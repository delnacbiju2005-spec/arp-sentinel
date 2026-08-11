import os
import json
import logging
import time
from enum import Enum
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
from arp_detector.config import DetectorConfig


class AlertSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ArpAlert:
    timestamp: str
    severity: AlertSeverity
    anomaly_type: str
    ip: str
    mac: str
    old_mac: Optional[str] = None
    description: str = ""
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


class AlertManager:
    """Handles logging, formatting, console printing, and exporting ARP security alerts."""

    # ANSI Color Codes
    COLOR_RESET = "\033[0m"
    COLOR_GREEN = "\033[92m"
    COLOR_YELLOW = "\033[93m"
    COLOR_RED = "\033[91m"
    COLOR_BOLD_RED = "\033[1;91m"
    COLOR_CRITICAL = "\033[1;41;97m"

    def __init__(self, config: Optional[DetectorConfig] = None):
        self.config = config or DetectorConfig()
        self.alerts: List[ArpAlert] = []
        self.total_packets_processed: int = 0

        # Setup standard python logger
        self.logger = logging.getLogger("ARPDetector")
        self.logger.setLevel(logging.DEBUG if self.config.verbose else logging.INFO)
        self.logger.handlers.clear()

        # File Handler
        if self.config.log_file:
            file_handler = logging.FileHandler(self.config.log_file, encoding="utf-8")
            file_formatter = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)

    def trigger_alert(
        self,
        severity: AlertSeverity,
        anomaly_type: str,
        ip: str,
        mac: str,
        old_mac: Optional[str] = None,
        description: str = "",
        details: Optional[Dict[str, Any]] = None
    ) -> ArpAlert:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        alert = ArpAlert(
            timestamp=timestamp,
            severity=severity,
            anomaly_type=anomaly_type,
            ip=ip,
            mac=mac,
            old_mac=old_mac,
            description=description,
            details=details
        )
        self.alerts.append(alert)

        # Log to file
        log_msg = f"[{alert.anomaly_type}] {alert.description} (IP: {ip}, MAC: {mac})"
        if old_mac:
            log_msg += f" [Previous MAC: {old_mac}]"

        if severity == AlertSeverity.CRITICAL:
            self.logger.critical(log_msg)
        elif severity == AlertSeverity.HIGH:
            self.logger.error(log_msg)
        elif severity == AlertSeverity.WARNING:
            self.logger.warning(log_msg)
        else:
            self.logger.info(log_msg)

        # Output to console
        self._print_console_alert(alert)

        # Export JSON if configured
        if self.config.export_json_path:
            self.export_json(self.config.export_json_path)

        return alert

    def _print_console_alert(self, alert: ArpAlert) -> None:
        if not self.config.enable_console_colors:
            print(f"[{alert.timestamp}] [{alert.severity.value}] [{alert.anomaly_type}] {alert.description}")
            return

        color = self.COLOR_RESET
        if alert.severity == AlertSeverity.CRITICAL:
            color = self.COLOR_CRITICAL
        elif alert.severity == AlertSeverity.HIGH:
            color = self.COLOR_BOLD_RED
        elif alert.severity == AlertSeverity.WARNING:
            color = self.COLOR_YELLOW
        elif alert.severity == AlertSeverity.INFO:
            color = self.COLOR_GREEN

        prefix = f"[{alert.timestamp}] [{alert.severity.value}]"
        print(f"{color}{prefix} [{alert.anomaly_type}] {alert.description}{self.COLOR_RESET}")

    def export_json(self, filepath: str) -> bool:
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump([a.to_dict() for a in self.alerts], f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Failed to export alerts to JSON ({filepath}): {e}")
            return False

    def print_summary(self) -> None:
        print("\n" + "=" * 60)
        print("          ARP SPOOFING DETECTOR SESSION SUMMARY          ")
        print("=" * 60)
        print(f"Total Packets Processed : {self.total_packets_processed}")
        print(f"Total Alerts Raised     : {len(self.alerts)}")

        counts: Dict[str, int] = {}
        for a in self.alerts:
            counts[a.severity.value] = counts.get(a.severity.value, 0) + 1

        print("Alerts Breakdown        :")
        for sev in [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.WARNING, AlertSeverity.INFO]:
            cnt = counts.get(sev.value, 0)
            if cnt > 0:
                print(f"  - {sev.value:<10}: {cnt}")

        if self.alerts:
            print("\nLatest Security Alerts:")
            for a in self.alerts[-5:]:
                print(f"  [{a.timestamp}] [{a.severity.value}] {a.anomaly_type}: IP {a.ip} -> MAC {a.mac}")
        print("=" * 60 + "\n")
