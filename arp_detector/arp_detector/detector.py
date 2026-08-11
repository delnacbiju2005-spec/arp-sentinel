import time
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional, Any

from arp_detector.config import DetectorConfig
from arp_detector.alerts import AlertManager, AlertSeverity, ArpAlert


class ArpDetector:
    """
    Passive ARP Spoofing and Poisoning Detection Engine.
    Processes ARP packets from Scapy and evaluates them against security heuristics.
    """

    def __init__(self, config: Optional[DetectorConfig] = None, alert_manager: Optional[AlertManager] = None):
        self.config = config or DetectorConfig()
        self.alert_manager = alert_manager or AlertManager(self.config)

        # Active state tables
        self.ip_to_mac: Dict[str, str] = {}  # IP -> Current MAC
        self.mac_to_ips: Dict[str, List[Tuple[float, str]]] = defaultdict(list)  # MAC -> [(timestamp, IP)]
        self.gratuitous_history: Dict[str, List[float]] = defaultdict(list)  # MAC -> [timestamps]
        self.pending_requests: Dict[str, List[float]] = defaultdict(list)  # Requested IP -> [timestamps]

        # Load whitelisted/pinned hosts into internal state
        self.config.load_whitelist()

    def process_packet(self, packet: Any) -> Optional[ArpAlert]:
        """
        Scapy callback handler for sniffing ARP packets (`prn=detector.process_packet`).
        """
        self.alert_manager.total_packets_processed += 1

        # Check if packet contains ARP layer
        if not hasattr(packet, "haslayer") or not packet.haslayer("ARP"):
            return None

        arp = packet["ARP"]
        opcode = getattr(arp, "op", 1)  # 1: request, 2: reply
        src_ip = getattr(arp, "psrc", "").strip()
        src_mac = self.config.normalize_mac(getattr(arp, "hwsrc", ""))
        dst_ip = getattr(arp, "pdst", "").strip()
        dst_mac = self.config.normalize_mac(getattr(arp, "hwdst", ""))

        if not src_ip or not src_mac or src_mac == "00:00:00:00:00:00":
            return None

        current_time = time.time()
        alert = None

        # 1. Track Requests
        if opcode == 1:
            self.pending_requests[dst_ip].append(current_time)
            # Gratuitous ARP Request (sender IP == target IP)
            if src_ip == dst_ip:
                alert = self._check_gratuitous_flood(src_ip, src_mac, current_time)
            return alert

        # 2. Process Replies / Announcements (opcode == 2)
        # Check Pinned Host / Whitelist Violations FIRST
        alert = self._check_pinned_host_violation(src_ip, src_mac)
        if alert:
            return alert

        # Check IP-to-MAC Mapping Flap / Change
        flap_alert = self._check_mapping_change(src_ip, src_mac)
        if flap_alert and not alert:
            alert = flap_alert

        # Track MAC -> IP Claims (Multi-IP detection)
        multi_ip_alert = self._check_multi_ip_claim(src_ip, src_mac, current_time)
        if multi_ip_alert and not alert:
            alert = multi_ip_alert

        # Check Gratuitous ARP Reply (src_ip == dst_ip or unsolicited)
        if src_ip == dst_ip or not self._has_matching_request(src_ip, current_time):
            grat_alert = self._check_gratuitous_flood(src_ip, src_mac, current_time)
            if grat_alert and not alert:
                alert = grat_alert

        # Update current state table
        self.ip_to_mac[src_ip] = src_mac

        return alert

    def handle_packet(self, packet: Any) -> Optional[ArpAlert]:
        """Alias method for Scapy prn compatibility."""
        return self.process_packet(packet)

    def _check_pinned_host_violation(self, ip: str, mac: str) -> Optional[ArpAlert]:
        expected_mac = None
        if ip in self.config.pinned_hosts:
            expected_mac = self.config.pinned_hosts[ip]
        elif ip in self.config.whitelist:
            expected_mac = self.config.whitelist[ip]

        if expected_mac and mac != expected_mac:
            return self.alert_manager.trigger_alert(
                severity=AlertSeverity.CRITICAL,
                anomaly_type="PINNED_HOST_VIOLATION",
                ip=ip,
                mac=mac,
                old_mac=expected_mac,
                description=f"CRITICAL: Pinned host {ip} claimed by unauthorized MAC {mac} (Expected: {expected_mac})"
            )
        return None

    def _check_mapping_change(self, ip: str, mac: str) -> Optional[ArpAlert]:
        if ip in self.ip_to_mac:
            previous_mac = self.ip_to_mac[ip]
            if previous_mac != mac:
                return self.alert_manager.trigger_alert(
                    severity=AlertSeverity.HIGH,
                    anomaly_type="MAPPING_CHANGE",
                    ip=ip,
                    mac=mac,
                    old_mac=previous_mac,
                    description=f"IP-to-MAC mapping changed for {ip}: {previous_mac} -> {mac}"
                )
        return None

    def _check_multi_ip_claim(self, ip: str, mac: str, current_time: float) -> Optional[ArpAlert]:
        window = self.config.anomaly_window
        # Add claim
        self.mac_to_ips[mac].append((current_time, ip))

        # Prune old claims
        self.mac_to_ips[mac] = [
            (ts, claim_ip) for ts, claim_ip in self.mac_to_ips[mac]
            if current_time - ts <= window
        ]

        distinct_ips: Set[str] = {claim_ip for _, claim_ip in self.mac_to_ips[mac]}
        if len(distinct_ips) > self.config.multi_ip_threshold:
            return self.alert_manager.trigger_alert(
                severity=AlertSeverity.WARNING,
                anomaly_type="MULTI_IP_CLAIM",
                ip=ip,
                mac=mac,
                description=f"MAC {mac} claimed {len(distinct_ips)} distinct IPs in {window}s: {sorted(list(distinct_ips))}"
            )
        return None

    def _check_gratuitous_flood(self, ip: str, mac: str, current_time: float) -> Optional[ArpAlert]:
        window = self.config.anomaly_window
        self.gratuitous_history[mac].append(current_time)

        # Prune old entries
        self.gratuitous_history[mac] = [
            ts for ts in self.gratuitous_history[mac]
            if current_time - ts <= window
        ]

        count = len(self.gratuitous_history[mac])
        if count >= self.config.gratuitous_flood_threshold:
            return self.alert_manager.trigger_alert(
                severity=AlertSeverity.HIGH,
                anomaly_type="GRATUITOUS_FLOOD",
                ip=ip,
                mac=mac,
                description=f"Gratuitous ARP flood from MAC {mac} ({count} announcements in {window}s)"
            )
        return None

    def _has_matching_request(self, ip: str, current_time: float) -> bool:
        if ip not in self.pending_requests:
            return False

        window = self.config.request_timeout_window
        # Filter valid request timestamps
        valid = [ts for ts in self.pending_requests[ip] if current_time - ts <= window]
        self.pending_requests[ip] = valid
        return len(valid) > 0
