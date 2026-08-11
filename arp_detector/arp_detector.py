#!/usr/bin/env python3
"""
ARP Spoofing & Poisoning Detector CLI
Defensive security tool to monitor local network ARP traffic and detect MITM/spoofing attacks.
"""

import sys
import os
import argparse
import signal
from typing import List

# Add parent directory to sys.path to allow execution directly as a script
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from arp_detector.config import DetectorConfig
from arp_detector.detector import ArpDetector
from arp_detector.alerts import AlertManager
from arp_detector.interface import print_interfaces_table, get_available_interfaces


def parse_args(args: List[str] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Passive ARP Spoofing & Poisoning Detector (Defensive Security Tool)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 arp_detector.py --list-interfaces
  sudo python3 arp_detector.py -i eth0
  sudo python3 arp_detector.py -i eth0 --known-gateway 192.168.1.1:AA:BB:CC:DD:EE:FF
  sudo python3 arp_detector.py -i wlan0 -w trusted_hosts.json --json-output alerts.json
"""
    )

    parser.add_argument(
        "-l", "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit."
    )
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to listen on (e.g., eth0, wlan0)."
    )
    parser.add_argument(
        "-g", "--known-gateway",
        action="append",
        metavar="IP:MAC",
        help="Pin a trusted IP:MAC pair (e.g., 192.168.1.1:AA:BB:CC:DD:EE:FF). Can be specified multiple times."
    )
    parser.add_argument(
        "-w", "--whitelist",
        type=str,
        default="whitelist.json",
        help="Path to JSON whitelist file containing trusted IP -> MAC mappings (default: whitelist.json)."
    )
    parser.add_argument(
        "-o", "--log-file",
        type=str,
        default="arp_detector.log",
        help="Path for security log file (default: arp_detector.log)."
    )
    parser.add_argument(
        "--json-output",
        type=str,
        default=None,
        help="Path to export alerts in structured JSON format."
    )
    parser.add_argument(
        "--anomaly-window",
        type=int,
        default=60,
        help="Time window in seconds to monitor for rapid ARP anomalies (default: 60)."
    )
    parser.add_argument(
        "--multi-ip-threshold",
        type=int,
        default=3,
        help="Threshold of distinct IPs claimed by a single MAC to trigger alert (default: 3)."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debugging console output."
    )

    return parser.parse_args(args)


def main():
    args = parse_args()

    # Handle interface listing request
    if args.list_interfaces:
        print_interfaces_table()
        sys.exit(0)

    # Validate interface argument
    if not args.interface:
        print("[!] Error: Network interface not specified. Use -i <interface> or --list-interfaces.")
        print("[*] Displaying available interfaces:")
        print_interfaces_table()
        sys.exit(1)

    # Initialize configuration
    config = DetectorConfig(
        interface=args.interface,
        log_file=args.log_file,
        export_json_path=args.json_output,
        whitelist_path=args.whitelist,
        anomaly_window=args.anomaly_window,
        multi_ip_threshold=args.multi_ip_threshold,
        verbose=args.verbose
    )

    # Parse pinned gateway/host arguments
    if args.known_gateway:
        for pair in args.known_gateway:
            if ":" in pair:
                parts = pair.split(":", 1)
                ip = parts[0].strip()
                mac = parts[1].strip()
                config.add_pinned_host(ip, mac)
                print(f"[*] Pinned trusted host: {ip} -> {config.normalize_mac(mac)}")

    alert_manager = AlertManager(config)
    detector = ArpDetector(config, alert_manager)

    print("\n" + "=" * 60)
    print(f"[*] Starting ARP Spoofing Detector on interface: '{config.interface}'")
    print(f"[*] Monitoring ARP traffic... (Press Ctrl+C to stop)")
    if config.pinned_hosts:
        print(f"[*] Active Pinned Hosts: {len(config.pinned_hosts)}")
    print("=" * 60 + "\n")

    # Import scapy
    try:
        from scapy.all import sniff
    except ImportError:
        print("[!] Error: Scapy library is not installed. Please run: pip install scapy")
        sys.exit(1)

    # Check root / administrative permissions on POSIX
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Warning: Root privileges required for raw packet sniffing.")
        print("[!] Please run with sudo: sudo python3 arp_detector.py -i " + str(config.interface))
        sys.exit(1)

    def signal_handler(sig, frame):
        print("\n[*] Stopping ARP capture engine...")
        alert_manager.print_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        sniff(
            iface=config.interface,
            filter="arp",
            store=0,
            prn=detector.handle_packet
        )
    except PermissionError:
        print("\n[!] Permission Error: Raw socket access denied.")
        print("[!] Please execute this tool as root/administrator (e.g., using sudo).")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during packet sniffing on '{config.interface}': {e}")
        if "No such device" in str(e) or "invalid" in str(e).lower():
            print("[*] Available interfaces:")
            print_interfaces_table()
        alert_manager.print_summary()
        sys.exit(1)


if __name__ == "__main__":
    main()
