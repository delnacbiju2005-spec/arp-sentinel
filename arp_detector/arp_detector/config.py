import os
import json
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class DetectorConfig:
    """Configuration settings for ARP Spoofing Detector daemon."""

    interface: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None

    # Thresholds & Windows (in seconds)
    anomaly_window: int = 60
    mac_flap_threshold: int = 3
    multi_ip_threshold: int = 3
    gratuitous_flood_threshold: int = 5
    request_timeout_window: int = 30

    # Logging & Alerts
    log_file: str = "arp_detector.log"
    export_json_path: Optional[str] = None
    export_csv_path: Optional[str] = None
    enable_desktop_alerts: bool = True
    enable_console_colors: bool = True
    verbose: bool = False

    # Active Defense / Whitelist & Pinned Hosts
    enable_auto_response: bool = False
    whitelist_path: str = "whitelist.json"
    whitelist: Dict[str, str] = field(default_factory=dict)
    pinned_hosts: Dict[str, str] = field(default_factory=dict)

    # Web Dashboard
    dashboard_enabled: bool = False
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5000

    def load_whitelist(self, filepath: Optional[str] = None) -> Dict[str, str]:
        """Loads trusted IP-to-MAC mappings from a JSON whitelist file."""
        target_path = filepath or self.whitelist_path
        if os.path.exists(target_path):
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        # Normalize MAC addresses to lower-case colons
                        normalized = {
                            ip.strip(): self.normalize_mac(mac)
                            for ip, mac in data.items()
                        }
                        self.whitelist.update(normalized)
                        return self.whitelist
            except Exception as e:
                print(f"[!] Warning: Failed to load whitelist from {target_path}: {e}")
        return self.whitelist

    def save_whitelist(self, filepath: Optional[str] = None) -> bool:
        """Saves current whitelist to a JSON file."""
        target_path = filepath or self.whitelist_path
        try:
            with open(target_path, "w", encoding="utf-8") as f:
                json.dump(self.whitelist, f, indent=2)
            return True
        except Exception as e:
            print(f"[!] Error saving whitelist to {target_path}: {e}")
            return False

    def add_pinned_host(self, ip: str, mac: str) -> None:
        """Pins a trusted IP:MAC address pair."""
        if ip and mac:
            self.pinned_hosts[ip.strip()] = self.normalize_mac(mac)

    @staticmethod
    def normalize_mac(mac: str) -> str:
        """Normalizes MAC address string to lower-case colon-separated format."""
        if not mac:
            return ""
        cleaned = mac.replace("-", "").replace(":", "").replace(".", "").lower()
        if len(cleaned) == 12:
            return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))
        return mac.lower().strip()

