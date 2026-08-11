import unittest
import time
from unittest.mock import MagicMock

from arp_detector.config import DetectorConfig
from arp_detector.alerts import AlertManager, AlertSeverity
from arp_detector.detector import ArpDetector
from arp_detector.interface import get_available_interfaces


class MockArpPacket:
    """Mock class simulating Scapy ARP packet structure."""
    def __init__(self, psrc: str, hwsrc: str, pdst: str, hwdst: str, op: int = 2):
        self.psrc = psrc
        self.hwsrc = hwsrc
        self.pdst = pdst
        self.hwdst = hwdst
        self.op = op

    def haslayer(self, layer_name: str) -> bool:
        return layer_name.upper() == "ARP"

    def __getitem__(self, layer_name: str):
        if layer_name.upper() == "ARP":
            return self
        raise KeyError(f"Layer {layer_name} not found")


class TestArpDetector(unittest.TestCase):

    def setUp(self):
        self.config = DetectorConfig(
            anomaly_window=60,
            multi_ip_threshold=3,
            gratuitous_flood_threshold=4,
            enable_console_colors=False,
            log_file=None
        )
        self.alert_manager = AlertManager(self.config)
        self.detector = ArpDetector(self.config, self.alert_manager)

    def test_mapping_change_detection(self):
        """Test IP-to-MAC mapping change (flapping) detection."""
        ip = "192.168.1.50"
        mac1 = "aa:bb:cc:11:22:33"
        mac2 = "ff:ee:dd:44:55:66"

        # First normal reply
        pkt1 = MockArpPacket(psrc=ip, hwsrc=mac1, pdst="192.168.1.1", hwdst="00:11:22:33:44:55", op=2)
        alert1 = self.detector.process_packet(pkt1)
        self.assertIsNone(alert1)
        self.assertEqual(self.detector.ip_to_mac[ip], mac1)

        # Spoofed reply with different MAC for same IP
        pkt2 = MockArpPacket(psrc=ip, hwsrc=mac2, pdst="192.168.1.1", hwdst="00:11:22:33:44:55", op=2)
        alert2 = self.detector.process_packet(pkt2)

        self.assertIsNotNone(alert2)
        self.assertEqual(alert2.anomaly_type, "MAPPING_CHANGE")
        self.assertEqual(alert2.severity, AlertSeverity.HIGH)
        self.assertEqual(alert2.old_mac, mac1)
        self.assertEqual(alert2.mac, mac2)

    def test_pinned_host_violation(self):
        """Test trusted gateway / pinned host violation detection."""
        gateway_ip = "192.168.1.1"
        valid_mac = "11:22:33:44:55:66"
        attacker_mac = "aa:bb:cc:dd:ee:ff"

        self.config.add_pinned_host(gateway_ip, valid_mac)

        # Unauthorized ARP reply claiming to be gateway
        pkt = MockArpPacket(psrc=gateway_ip, hwsrc=attacker_mac, pdst="192.168.1.100", hwdst="00:11:22:33:44:55", op=2)
        alert = self.detector.process_packet(pkt)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.anomaly_type, "PINNED_HOST_VIOLATION")
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert.ip, gateway_ip)
        self.assertEqual(alert.mac, attacker_mac)

    def test_multi_ip_claim_detection(self):
        """Test single MAC claiming multiple distinct IPs."""
        mac = "aa:bb:cc:dd:ee:ff"
        ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]

        alerts = []
        for ip in ips:
            pkt = MockArpPacket(psrc=ip, hwsrc=mac, pdst="192.168.1.1", hwdst="00:11:22:33:44:55", op=2)
            a = self.detector.process_packet(pkt)
            if a:
                alerts.append(a)

        self.assertTrue(len(alerts) > 0)
        multi_ip_alerts = [a for a in alerts if a.anomaly_type == "MULTI_IP_CLAIM"]
        self.assertTrue(len(multi_ip_alerts) > 0)
        self.assertEqual(multi_ip_alerts[0].severity, AlertSeverity.WARNING)

    def test_gratuitous_arp_flood(self):
        """Test gratuitous ARP flood detection."""
        ip = "192.168.1.200"
        mac = "00:aa:bb:cc:dd:ee"

        alerts = []
        # Gratuitous ARP reply (psrc == pdst)
        for _ in range(5):
            pkt = MockArpPacket(psrc=ip, hwsrc=mac, pdst=ip, hwdst="ff:ff:ff:ff:ff:ff", op=2)
            a = self.detector.process_packet(pkt)
            if a:
                alerts.append(a)

        flood_alerts = [a for a in alerts if a.anomaly_type == "GRATUITOUS_FLOOD"]
        self.assertTrue(len(flood_alerts) > 0)
        self.assertEqual(flood_alerts[0].severity, AlertSeverity.HIGH)

    def test_interface_enumeration(self):
        """Test listing available interfaces helper."""
        ifaces = get_available_interfaces()
        self.assertIsInstance(ifaces, list)
        if len(ifaces) > 0:
            self.assertIn("name", ifaces[0])
            self.assertIn("mac", ifaces[0])


if __name__ == "__main__":
    unittest.main()
