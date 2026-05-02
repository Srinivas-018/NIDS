import importlib
import os
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


class NIDSUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("NIDS Control Panel")
        self.root.geometry("1200x760")

        self.project_dir = Path(__file__).resolve().parent
        self.nids_script = self.project_dir / "nids.py"
        self.traffic_script = self.project_dir / "traffic_generator.py"
        self.all_alerts_pcap = self.project_dir / "all_alerts_test.pcap"

        self.proc: subprocess.Popen | None = None
        self.traffic_proc: subprocess.Popen | None = None
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.stop_reader = threading.Event()
        self.alert_rows: list[tuple[str, str, str, str, str]] = []

        self.mode_var = tk.StringVar(value="live")
        self.traffic_mode_var = tk.StringVar(value="all")
        self.all_alert_profile_var = tk.StringVar(value="sensitive")
        self.iface_var = tk.StringVar(value="")
        self.profile_var = tk.StringVar(value="balanced")
        self.pcap_var = tk.StringVar(value="")
        self.csv_var = tk.StringVar(value=str(self.project_dir / "alerts.csv"))
        self.sqlite_var = tk.StringVar(value=str(self.project_dir / "alerts.db"))
        self.port_scan_var = tk.StringVar(value="")
        self.syn_var = tk.StringVar(value="")
        self.filter_var = tk.StringVar(value="ip or arp")

        self._build_layout()
        self._load_interfaces()
        self._toggle_mode_widgets()
        self._append_log("UI ready. Configure options and click Start.")

        self.root.after(120, self._drain_log_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_layout(self) -> None:
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)

        run_box = ttk.LabelFrame(top, text="Run Settings", padding=10)
        run_box.pack(fill=tk.X)

        ttk.Label(run_box, text="Mode").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(run_box, text="Live", variable=self.mode_var, value="live", command=self._toggle_mode_widgets).grid(
            row=0, column=1, sticky="w"
        )
        ttk.Radiobutton(run_box, text="PCAP", variable=self.mode_var, value="pcap", command=self._toggle_mode_widgets).grid(
            row=0, column=2, sticky="w"
        )

        ttk.Label(run_box, text="Interface").grid(row=1, column=0, sticky="w")
        self.iface_combo = ttk.Combobox(run_box, textvariable=self.iface_var, width=60, state="readonly")
        self.iface_combo.grid(row=1, column=1, columnspan=3, sticky="ew", padx=(0, 6))
        ttk.Button(run_box, text="Refresh", command=self._load_interfaces).grid(row=1, column=4, sticky="w")

        ttk.Label(run_box, text="PCAP File").grid(row=2, column=0, sticky="w")
        self.pcap_entry = ttk.Entry(run_box, textvariable=self.pcap_var, width=70)
        self.pcap_entry.grid(row=2, column=1, columnspan=3, sticky="ew", padx=(0, 6))
        self.pcap_btn = ttk.Button(run_box, text="Browse", command=self._pick_pcap)
        self.pcap_btn.grid(row=2, column=4, sticky="w")

        ttk.Label(run_box, text="Profile").grid(row=3, column=0, sticky="w")
        ttk.Combobox(
            run_box,
            textvariable=self.profile_var,
            state="readonly",
            values=["balanced", "sensitive", "strict"],
            width=20,
        ).grid(row=3, column=1, sticky="w")

        ttk.Label(run_box, text="Port Scan Threshold").grid(row=3, column=2, sticky="e")
        ttk.Entry(run_box, textvariable=self.port_scan_var, width=10).grid(row=3, column=3, sticky="w")

        ttk.Label(run_box, text="SYN Threshold").grid(row=3, column=4, sticky="e")
        ttk.Entry(run_box, textvariable=self.syn_var, width=10).grid(row=3, column=5, sticky="w")

        ttk.Label(run_box, text="BPF Filter").grid(row=4, column=0, sticky="w")
        ttk.Entry(run_box, textvariable=self.filter_var, width=40).grid(row=4, column=1, sticky="w")

        ttk.Label(run_box, text="Traffic Mode").grid(row=4, column=2, sticky="e")
        ttk.Combobox(
            run_box,
            textvariable=self.traffic_mode_var,
            state="readonly",
            values=["all", "portscan", "synflood", "arpspoof"],
            width=14,
        ).grid(row=4, column=3, sticky="w")

        ttk.Label(run_box, text="CSV Path").grid(row=5, column=0, sticky="w")
        ttk.Entry(run_box, textvariable=self.csv_var, width=60).grid(row=5, column=1, columnspan=3, sticky="ew")

        ttk.Label(run_box, text="SQLite Path").grid(row=6, column=0, sticky="w")
        ttk.Entry(run_box, textvariable=self.sqlite_var, width=60).grid(row=6, column=1, columnspan=3, sticky="ew")

        btn_row = ttk.Frame(run_box)
        btn_row.grid(row=7, column=0, columnspan=6, sticky="ew", pady=(10, 0))
        self.start_btn = ttk.Button(btn_row, text="Start NIDS", command=self.start_nids)
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(btn_row, text="Stop NIDS", command=self.stop_nids, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_row, text="Run Test Traffic", command=self.run_test_traffic).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Replay All Alerts", command=self.replay_all_alerts).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Clear Logs", command=self._clear_logs).pack(side=tk.LEFT)

        run_box.columnconfigure(1, weight=1)
        run_box.columnconfigure(2, weight=1)
        run_box.columnconfigure(3, weight=1)

        middle = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        middle.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        log_frame = ttk.LabelFrame(middle, text="Live Output", padding=8)
        self.log_text = tk.Text(log_frame, height=18, wrap="none", bg="#111111", fg="#e8f5e9", insertbackground="#e8f5e9")
        y_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        x_scroll = ttk.Scrollbar(log_frame, orient=tk.HORIZONTAL, command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        alerts_frame = ttk.LabelFrame(middle, text="Recent Alerts", padding=8)
        columns = ("timestamp", "alert_type", "src_ip", "dst_ip", "details")
        self.alert_tree = ttk.Treeview(alerts_frame, columns=columns, show="headings", height=18)
        self.alert_tree.heading("timestamp", text="Time")
        self.alert_tree.heading("alert_type", text="Type")
        self.alert_tree.heading("src_ip", text="Source")
        self.alert_tree.heading("dst_ip", text="Destination")
        self.alert_tree.heading("details", text="Details")
        self.alert_tree.column("timestamp", width=140, anchor="w")
        self.alert_tree.column("alert_type", width=110, anchor="w")
        self.alert_tree.column("src_ip", width=130, anchor="w")
        self.alert_tree.column("dst_ip", width=130, anchor="w")
        self.alert_tree.column("details", width=420, anchor="w")

        alerts_scroll = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=alerts_scroll.set)
        self.alert_tree.grid(row=0, column=0, sticky="nsew")
        alerts_scroll.grid(row=0, column=1, sticky="ns")
        alerts_frame.columnconfigure(0, weight=1)
        alerts_frame.rowconfigure(0, weight=1)

        middle.add(log_frame, weight=1)
        middle.add(alerts_frame, weight=1)

    def _toggle_mode_widgets(self) -> None:
        live_mode = self.mode_var.get() == "live"
        if live_mode:
            self.iface_combo.configure(state="readonly")
            self.pcap_entry.configure(state="disabled")
            self.pcap_btn.configure(state="disabled")
        else:
            self.iface_combo.configure(state="disabled")
            self.pcap_entry.configure(state="normal")
            self.pcap_btn.configure(state="normal")

    def _load_interfaces(self) -> None:
        try:
            scapy_all = importlib.import_module("scapy.all")
            get_if_list = getattr(scapy_all, "get_if_list")
            interfaces = get_if_list()
            self.iface_combo["values"] = interfaces
            if interfaces and not self.iface_var.get():
                self.iface_var.set(interfaces[0])
            self._append_log(f"Loaded {len(interfaces)} interfaces.")
        except Exception as exc:
            self._append_log(f"[WARN] Could not load interfaces: {exc}")

    def _pick_pcap(self) -> None:
        path = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")],
        )
        if path:
            self.pcap_var.set(path)

    def _build_command(self) -> list[str]:
        cmd = [sys.executable, "-u", str(self.nids_script)]

        if self.mode_var.get() == "live":
            iface = self.iface_var.get().strip()
            if iface:
                cmd.extend(["--iface", iface])
        else:
            pcap = self.pcap_var.get().strip()
            if not pcap:
                raise ValueError("PCAP mode selected but no PCAP file provided.")
            cmd.extend(["--pcap", pcap])

        cmd.extend(["--profile", self.profile_var.get().strip()])

        bpf_filter = self.filter_var.get().strip()
        if bpf_filter:
            cmd.extend(["--bpf-filter", bpf_filter])

        csv_path = self.csv_var.get().strip()
        sqlite_path = self.sqlite_var.get().strip()
        if csv_path:
            cmd.extend(["--csv", csv_path])
        if sqlite_path:
            cmd.extend(["--sqlite", sqlite_path])

        port_scan = self.port_scan_var.get().strip()
        syn = self.syn_var.get().strip()
        if port_scan:
            cmd.extend(["--port-scan-threshold", port_scan])
        if syn:
            cmd.extend(["--syn-threshold", syn])

        return cmd

    def _build_traffic_command(self) -> list[str]:
        cmd = [sys.executable, "-u", str(self.traffic_script), "--mode", self.traffic_mode_var.get().strip()]

        iface = self.iface_var.get().strip()
        if self.mode_var.get() == "live" and iface:
            cmd.extend(["--iface", iface])

        cmd.extend(
            [
                "--target-ip",
                "127.0.0.1",
                "--target-port",
                "80",
                "--port-count",
                "20",
                "--syn-count",
                "250",
                "--arp-repeat",
                "10",
            ]
        )
        return cmd

    def _build_all_alerts_pcap(self) -> None:
        scapy_all = importlib.import_module("scapy.all")
        Ether = getattr(scapy_all, "Ether")
        IP = getattr(scapy_all, "IP")
        TCP = getattr(scapy_all, "TCP")
        ARP = getattr(scapy_all, "ARP")
        wrpcap = getattr(scapy_all, "wrpcap")

        packets = []
        for port in range(20, 40):
            packets.append(
                Ether(src="02:00:00:00:00:05", dst="02:00:00:00:00:01")
                / IP(src="10.10.10.5", dst="10.10.10.1")
                / TCP(dport=port, flags="S")
            )

        for index in range(250):
            packets.append(
                Ether(src="02:00:00:00:00:06", dst="02:00:00:00:00:01")
                / IP(src="10.10.10.6", dst="10.10.10.1")
                / TCP(sport=10000 + index, dport=80, flags="S")
            )

        packets.append(
            Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.10", hwsrc="00:11:22:33:44:55")
        )
        packets.append(
            Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:ff")
        )

        wrpcap(str(self.all_alerts_pcap), packets)

    def replay_all_alerts(self) -> None:
        if self.proc and self.proc.poll() is None:
            messagebox.showinfo("NIDS", "Stop NIDS before replaying a PCAP.")
            return

        try:
            self._append_log("Building all-alert test PCAP...")
            self._build_all_alerts_pcap()
        except Exception as exc:
            messagebox.showerror("Replay failed", f"Could not create PCAP: {exc}")
            self._append_log(f"[ERROR] Could not create all-alert PCAP: {exc}")
            return

        self.mode_var.set("pcap")
        self._toggle_mode_widgets()
        self.pcap_var.set(str(self.all_alerts_pcap))
        self.profile_var.set(self.all_alert_profile_var.get().strip() or "sensitive")

        self._append_log(f"Replaying all-alert PCAP: {self.all_alerts_pcap}")
        self.start_nids()

    def start_nids(self) -> None:
        if self.proc and self.proc.poll() is None:
            messagebox.showinfo("NIDS", "NIDS is already running.")
            return

        try:
            cmd = self._build_command()
        except ValueError as exc:
            messagebox.showerror("Invalid configuration", str(exc))
            return

        self.stop_reader.clear()
        self._append_log(f"Starting: {' '.join(cmd)}")

        try:
            self.proc = subprocess.Popen(
                cmd,
                cwd=str(self.project_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as exc:
            messagebox.showerror("Launch failed", str(exc))
            self._append_log(f"[ERROR] Failed to start: {exc}")
            return

        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        threading.Thread(target=self._read_process_output, daemon=True).start()

    def run_test_traffic(self) -> None:
        if self.traffic_proc and self.traffic_proc.poll() is None:
            messagebox.showinfo("Traffic Generator", "Traffic generator is already running.")
            return

        try:
            cmd = self._build_traffic_command()
        except ValueError as exc:
            messagebox.showerror("Invalid configuration", str(exc))
            return

        self._append_log(f"Starting traffic generator: {' '.join(cmd)}")

        try:
            self.traffic_proc = subprocess.Popen(
                cmd,
                cwd=str(self.project_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as exc:
            messagebox.showerror("Launch failed", str(exc))
            self._append_log(f"[ERROR] Failed to start traffic generator: {exc}")
            return

        threading.Thread(target=self._read_traffic_output, daemon=True).start()

    def _read_process_output(self) -> None:
        assert self.proc is not None

        try:
            if self.proc.stdout is None:
                return

            for line in self.proc.stdout:
                if self.stop_reader.is_set():
                    break
                self.log_queue.put(line.rstrip("\n"))
        finally:
            code = self.proc.poll()
            self.log_queue.put(f"[INFO] NIDS process exited with code: {code}")

    def _read_traffic_output(self) -> None:
        assert self.traffic_proc is not None

        try:
            if self.traffic_proc.stdout is None:
                return

            for line in self.traffic_proc.stdout:
                self.log_queue.put(f"[TRAFFIC] {line.rstrip(chr(10))}")
        finally:
            code = self.traffic_proc.poll()
            self.log_queue.put(f"[INFO] Traffic generator exited with code: {code}")

    def stop_nids(self) -> None:
        if not self.proc or self.proc.poll() is not None:
            self._append_log("NIDS is not running.")
            self.start_btn.configure(state=tk.NORMAL)
            self.stop_btn.configure(state=tk.DISABLED)
            return

        self._append_log("Stopping NIDS...")
        self.stop_reader.set()
        self.proc.terminate()

        for _ in range(20):
            if self.proc.poll() is not None:
                break
            time.sleep(0.1)

        if self.proc.poll() is None:
            self.proc.kill()
            self._append_log("NIDS force-killed.")

        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)

    def _drain_log_queue(self) -> None:
        while True:
            try:
                line = self.log_queue.get_nowait()
            except queue.Empty:
                break
            self._handle_output_line(line)

        if self.proc and self.proc.poll() is not None:
            self.start_btn.configure(state=tk.NORMAL)
            self.stop_btn.configure(state=tk.DISABLED)

        self.root.after(120, self._drain_log_queue)

    def _handle_output_line(self, line: str) -> None:
        self._append_log(line)
        alert_row = self._parse_alert_line(line)
        if alert_row is not None:
            self._append_alert_row(alert_row)

    def _append_log(self, text: str) -> None:
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)

    def _clear_logs(self) -> None:
        self.log_text.delete("1.0", tk.END)

    def _parse_alert_line(self, line: str) -> tuple[str, str, str, str, str] | None:
        if not line.startswith("[ALERT]"):
            return None

        pattern = re.compile(
            r"^\[ALERT\]\s+(?P<timestamp>[^|]+)\s+\|\s+(?P<alert_type>[^|]+)\s+\|\s+"
            r"src=(?P<src_ip>[^\s]+)\s+dst=(?P<dst_ip>[^|]+)\|\s+(?P<details>.*)$"
        )
        match = pattern.match(line)
        if not match:
            return None

        timestamp = match.group("timestamp").strip()
        alert_type = match.group("alert_type").strip()
        src_ip = match.group("src_ip").strip()
        dst_ip = match.group("dst_ip").strip()
        details = match.group("details").strip()
        return timestamp, alert_type, src_ip, dst_ip, details

    def _append_alert_row(self, row: tuple[str, str, str, str, str]) -> None:
        self.alert_rows.append(row)
        self.alert_tree.insert("", tk.END, values=row)
        self.alert_tree.yview_moveto(1.0)

    def _on_close(self) -> None:
        try:
            self.stop_nids()
        except Exception:
            pass
        try:
            if self.traffic_proc and self.traffic_proc.poll() is None:
                self.traffic_proc.terminate()
        except Exception:
            pass
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    app = NIDSUI(root)
    _ = app
    root.mainloop()


if __name__ == "__main__":
    main()
