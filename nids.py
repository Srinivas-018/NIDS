import argparse
import csv
import os
import signal
import sqlite3
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Dict, List, Optional, Set, Tuple

from scapy.all import ARP, ICMP, IP, PcapReader, TCP, UDP, sniff

try:
    import matplotlib.pyplot as plt
    from matplotlib.animation import FuncAnimation
except Exception:
    plt = None
    FuncAnimation = None


@dataclass
class AlertEvent:
    timestamp: str
    alert_type: str
    src_ip: str
    dst_ip: str
    details: str


class AlertLogger:
    def __init__(self, csv_path: Optional[str], sqlite_path: Optional[str]) -> None:
        self.csv_path = csv_path
        self.sqlite_path = sqlite_path
        self._lock = threading.Lock()
        self._csv_file = None
        self._csv_writer = None
        self._conn = None

        if self.csv_path:
            self._init_csv()
        if self.sqlite_path:
            self._init_sqlite()

    def _init_csv(self) -> None:
        file_exists = os.path.exists(self.csv_path)
        self._csv_file = open(self.csv_path, "a", newline="", encoding="utf-8")
        self._csv_writer = csv.writer(self._csv_file)
        if not file_exists:
            self._csv_writer.writerow(["timestamp", "alert_type", "src_ip", "dst_ip", "details"])
            self._csv_file.flush()

    def _init_sqlite(self) -> None:
        self._conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                details TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def log(self, event: AlertEvent) -> None:
        with self._lock:
            if self._csv_writer:
                self._csv_writer.writerow(
                    [event.timestamp, event.alert_type, event.src_ip, event.dst_ip, event.details]
                )
                self._csv_file.flush()

            if self._conn:
                self._conn.execute(
                    "INSERT INTO alerts (timestamp, alert_type, src_ip, dst_ip, details) VALUES (?, ?, ?, ?, ?)",
                    (event.timestamp, event.alert_type, event.src_ip, event.dst_ip, event.details),
                )
                self._conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._csv_file:
                self._csv_file.close()
                self._csv_file = None
            if self._conn:
                self._conn.close()
                self._conn = None


class NIDSDetector:
    def __init__(
        self,
        logger: AlertLogger,
        port_scan_threshold: int = 10,
        syn_threshold: int = 100,
        syn_window_seconds: float = 1.0,
        syn_ack_ratio_max: float = 0.2,
        alert_cooldown_seconds: float = 2.0,
    ) -> None:
        self.logger = logger
        self.port_scan_threshold = port_scan_threshold
        self.syn_threshold = syn_threshold
        self.syn_window_seconds = syn_window_seconds
        self.syn_ack_ratio_max = syn_ack_ratio_max
        self.alert_cooldown_seconds = alert_cooldown_seconds

        self.port_hits: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self.syn_events: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self.arp_table: Dict[str, str] = {}
        self.last_alert_time: Dict[Tuple[str, str], float] = {}

        self.packet_count = 0
        self.alert_count = 0
        self._packets_this_second = 0
        self._alerts_this_second = 0
        self._stats_lock = threading.Lock()

    def _now(self) -> float:
        return time.time()

    def _iso_now(self) -> str:
        return datetime.utcnow().isoformat(timespec="seconds") + "Z"

    def _can_alert(self, alert_type: str, key: str) -> bool:
        now = self._now()
        bucket = (alert_type, key)
        last = self.last_alert_time.get(bucket, 0.0)
        if now - last >= self.alert_cooldown_seconds:
            self.last_alert_time[bucket] = now
            return True
        return False

    def _emit_alert(self, alert_type: str, src_ip: str, dst_ip: str, details: str, key: str) -> None:
        if not self._can_alert(alert_type, key):
            return

        event = AlertEvent(
            timestamp=self._iso_now(),
            alert_type=alert_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            details=details,
        )
        self.logger.log(event)
        self.alert_count += 1
        with self._stats_lock:
            self._alerts_this_second += 1
        print(
            f"[ALERT] {event.timestamp} | {event.alert_type} | "
            f"src={event.src_ip} dst={event.dst_ip} | {event.details}"
        )

    def _protocol_name(self, pkt) -> str:
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(ARP):
            return "ARP"
        return "OTHER"

    def _print_packet_summary(self, pkt) -> None:
        src_ip = "N/A"
        dst_ip = "N/A"

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(ARP):
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst

        proto = self._protocol_name(pkt)
        print(f"SRC={src_ip:15} DST={dst_ip:15} PROTO={proto}")

    def _prune_port_hits(self, src_ip: str, now: float) -> None:
        window = self.port_hits[src_ip]
        while window and now - window[0][0] > 1.0:
            window.popleft()

    def _detect_port_scan(self, pkt) -> None:
        if not pkt.haslayer(IP) or not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport

        now = self._now()
        self.port_hits[src_ip].append((now, dport))
        self._prune_port_hits(src_ip, now)

        unique_ports: Set[int] = {port for _, port in self.port_hits[src_ip]}
        if len(unique_ports) >= self.port_scan_threshold:
            details = (
                f"{src_ip} hit {len(unique_ports)} unique ports in <1s "
                f"toward {dst_ip}"
            )
            self._emit_alert("Port Scan", src_ip, dst_ip, details, key=src_ip)

    def _prune_syn_events(self, src_ip: str, now: float) -> None:
        window = self.syn_events[src_ip]
        while window and now - window[0][0] > self.syn_window_seconds:
            window.popleft()

    def _detect_syn_flood(self, pkt) -> None:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        flags = pkt[TCP].flags
        now = self._now()

        is_syn = bool(flags & 0x02) and not bool(flags & 0x10)
        is_ack = bool(flags & 0x10)

        if is_syn:
            self.syn_events[src_ip].append((now, "SYN"))
        elif is_ack:
            self.syn_events[src_ip].append((now, "ACK"))
        else:
            return

        self._prune_syn_events(src_ip, now)
        events = self.syn_events[src_ip]
        syn_count = sum(1 for _, kind in events if kind == "SYN")
        ack_count = sum(1 for _, kind in events if kind == "ACK")

        if syn_count >= self.syn_threshold:
            ratio = (ack_count / syn_count) if syn_count else 0.0
            if ratio <= self.syn_ack_ratio_max:
                details = (
                    f"High SYN rate from {src_ip}: SYN={syn_count}, ACK={ack_count}, "
                    f"ACK/SYN={ratio:.2f} in {self.syn_window_seconds:.1f}s"
                )
                self._emit_alert("SYN Flood", src_ip, dst_ip, details, key=src_ip)

    def _detect_arp_spoofing(self, pkt) -> None:
        if not pkt.haslayer(ARP):
            return

        arp_layer = pkt[ARP]
        ip = arp_layer.psrc
        mac = arp_layer.hwsrc

        if not ip or not mac:
            return

        known_mac = self.arp_table.get(ip)
        if known_mac is None:
            self.arp_table[ip] = mac
            return

        if known_mac.lower() != mac.lower():
            details = f"IP {ip} changed MAC from {known_mac} to {mac}"
            self._emit_alert("ARP Spoofing", ip, arp_layer.pdst, details, key=ip)
            # Keep first-seen mapping to avoid accepting poisoned updates.

    def handle_packet(self, pkt) -> None:
        self.packet_count += 1
        with self._stats_lock:
            self._packets_this_second += 1
        self._print_packet_summary(pkt)
        self._detect_port_scan(pkt)
        self._detect_syn_flood(pkt)
        self._detect_arp_spoofing(pkt)

    def consume_second_stats(self) -> Tuple[int, int]:
        with self._stats_lock:
            packets = self._packets_this_second
            alerts = self._alerts_this_second
            self._packets_this_second = 0
            self._alerts_this_second = 0
        return packets, alerts


class SnifferApp:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self._apply_profile_defaults()
        self.logger = AlertLogger(csv_path=args.csv, sqlite_path=args.sqlite)
        self.detector = NIDSDetector(
            logger=self.logger,
            port_scan_threshold=args.port_scan_threshold,
            syn_threshold=args.syn_threshold,
            syn_window_seconds=args.syn_window_seconds,
            syn_ack_ratio_max=args.syn_ack_ratio_max,
            alert_cooldown_seconds=args.alert_cooldown_seconds,
        )
        self._stop = threading.Event()
        self._plot_thread = None

    def _apply_profile_defaults(self) -> None:
        # Presets help tune baseline behavior for quieter vs noisy networks.
        profile_defaults = {
            "balanced": {
                "port_scan_threshold": 10,
                "syn_threshold": 100,
                "syn_window_seconds": 1.0,
                "syn_ack_ratio_max": 0.2,
                "alert_cooldown_seconds": 2.0,
            },
            "sensitive": {
                "port_scan_threshold": 8,
                "syn_threshold": 70,
                "syn_window_seconds": 1.0,
                "syn_ack_ratio_max": 0.3,
                "alert_cooldown_seconds": 1.5,
            },
            "strict": {
                "port_scan_threshold": 15,
                "syn_threshold": 180,
                "syn_window_seconds": 1.0,
                "syn_ack_ratio_max": 0.15,
                "alert_cooldown_seconds": 3.0,
            },
        }

        selected = profile_defaults[self.args.profile]
        for key, value in selected.items():
            if getattr(self.args, key) is None:
                setattr(self.args, key, value)

    def _signal_handler(self, _signum, _frame) -> None:
        self._stop.set()

    def _plot_loop(self) -> None:
        if plt is None or FuncAnimation is None:
            print("[WARN] Matplotlib is unavailable; live graph is disabled.")
            return

        x_values: Deque[int] = deque(maxlen=60)
        packet_values: Deque[int] = deque(maxlen=60)
        alert_values: Deque[int] = deque(maxlen=60)
        elapsed = 0

        fig, ax = plt.subplots(figsize=(10, 4))
        packet_line, = ax.plot([], [], label="Packets/sec", color="tab:blue")
        alert_line, = ax.plot([], [], label="Alerts/sec", color="tab:red")
        ax.set_title("NIDS Live Traffic")
        ax.set_xlabel("Last 60 seconds")
        ax.set_ylabel("Count")
        ax.legend(loc="upper left")
        ax.grid(True, alpha=0.3)

        def update(_frame):
            nonlocal elapsed
            elapsed += 1
            packets, alerts = self.detector.consume_second_stats()
            x_values.append(elapsed)
            packet_values.append(packets)
            alert_values.append(alerts)

            packet_line.set_data(list(x_values), list(packet_values))
            alert_line.set_data(list(x_values), list(alert_values))

            if x_values:
                ax.set_xlim(min(x_values), max(x_values) + 1)
            max_y = max([1] + list(packet_values) + list(alert_values))
            ax.set_ylim(0, max_y + 2)
            return packet_line, alert_line

        animation = FuncAnimation(fig, update, interval=1000, blit=False, cache_frame_data=False)
        try:
            plt.tight_layout()
            plt.show()
        finally:
            # Keep a reference to avoid premature garbage collection while plotting.
            _ = animation
            self._stop.set()

    def run(self) -> None:
        mode = "PCAP replay" if self.args.pcap else "live sniffing"
        print(f"Starting NIDS ({mode})...")
        if self.args.pcap:
            print(f"PCAP file: {self.args.pcap}")
            print(f"Replay speed: {self.args.replay_speed}x")
        else:
            print(f"Interface: {self.args.iface or 'default'}")
        print(f"Profile: {self.args.profile}")
        print("Press Ctrl+C to stop.\n")

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        if self.args.plot:
            self._plot_thread = threading.Thread(target=self._plot_loop, daemon=True)
            self._plot_thread.start()

        try:
            if self.args.pcap:
                self._run_pcap_replay()
            else:
                while not self._stop.is_set():
                    try:
                        sniff(
                            iface=self.args.iface,
                            store=False,
                            filter=self.args.bpf_filter,
                            timeout=1,
                            prn=self.detector.handle_packet,
                        )
                    except RuntimeError as exc:
                        print(f"[ERROR] Live packet capture is unavailable: {exc}")
                        print("[HINT] On Windows, install Npcap to enable live sniffing, or use --pcap for offline replay.")
                        break
        finally:
            self.logger.close()
            print("\nStopped NIDS.")
            print(
                f"Packets processed: {self.detector.packet_count} | "
                f"Alerts generated: {self.detector.alert_count}"
            )

    def _run_pcap_replay(self) -> None:
        if not os.path.exists(self.args.pcap):
            raise FileNotFoundError(f"PCAP file not found: {self.args.pcap}")

        previous_packet_time = None
        speed = max(self.args.replay_speed, 0.01)

        with PcapReader(self.args.pcap) as reader:
            for pkt in reader:
                if self._stop.is_set():
                    break

                if self.args.replay_timing:
                    packet_time = float(getattr(pkt, "time", 0.0) or 0.0)
                    if previous_packet_time is not None and packet_time >= previous_packet_time:
                        delta = (packet_time - previous_packet_time) / speed
                        if delta > 0:
                            time.sleep(min(delta, 0.5))
                    previous_packet_time = packet_time

                self.detector.handle_packet(pkt)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Basic Network Intrusion Detection System (NIDS)")
    parser.add_argument("--iface", default=None, help="Network interface name")
    parser.add_argument("--pcap", default=None, help="Replay packets from a pcap file instead of live sniffing")
    parser.add_argument(
        "--replay-speed",
        type=float,
        default=1.0,
        help="Replay speed multiplier for pcap mode when --replay-timing is used",
    )
    parser.add_argument(
        "--replay-timing",
        action="store_true",
        help="In pcap mode, preserve packet timing (scaled by --replay-speed)",
    )
    parser.add_argument(
        "--profile",
        choices=["balanced", "sensitive", "strict"],
        default="balanced",
        help="Detection sensitivity profile",
    )
    parser.add_argument(
        "--bpf-filter",
        default="ip or arp",
        help="BPF capture filter (default: 'ip or arp')",
    )

    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        default=None,
        help="Unique destination ports in <1s to trigger port scan alert",
    )

    parser.add_argument(
        "--syn-threshold",
        type=int,
        default=None,
        help="SYN packets in window to trigger SYN flood evaluation",
    )

    parser.add_argument(
        "--syn-window-seconds",
        type=float,
        default=None,
        help="Rolling window for SYN flood logic",
    )

    parser.add_argument(
        "--syn-ack-ratio-max",
        type=float,
        default=None,
        help="Max ACK/SYN ratio to classify as SYN flood",
    )

    parser.add_argument(
        "--alert-cooldown-seconds",
        type=float,
        default=None,
        help="Minimum time between repeated same-source alerts",
    )

    parser.add_argument("--csv", default="alerts.csv", help="CSV alert log path")
    parser.add_argument("--sqlite", default="alerts.db", help="SQLite alert DB path")
    parser.add_argument(
        "--plot",
        action="store_true",
        help="Enable live matplotlib graph for packet/alert rate",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    app = SnifferApp(args)
    app.run()


if __name__ == "__main__":
    main()
