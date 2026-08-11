# 🛡️ ARP Detector (`arp-detector`)

`ARP Detector` is a passive Network Intrusion Detection System (NIDS) CLI tool written in Python. It monitors local network traffic in real-time to detect **ARP Spoofing, Poisoning, and Man-in-the-Middle (MITM) attacks**.

---

## ⚖️ Legal & Ethical Use Disclaimer

> **IMPORTANT**: This tool is provided strictly for defensive security monitoring, educational purposes, coursework demonstrations, and authorized security audits. Unauthorized interception, eavesdropping, or manipulation of network traffic without explicit permission from system owners is illegal. The author accepts no responsibility for misuse or unlawful activities.

---

## 🌟 Key Features

- **Passive Network Sniffing**: Uses Scapy to monitor ARP traffic with zero network footprint or active probes.
- **Trusted Gateway / Host Pinning**: Protects gateway addresses (`--known-gateway`) or static host definitions from unauthorized MAC spoofing.
- **Multi-Heuristic Anomaly Engine**:
  - **Pinned Host Violations** (`CRITICAL`): Unauthorized MAC address claiming a pinned host or gateway IP.
  - **IP-to-MAC Mapping Flapping** (`HIGH`): Detecting mid-session IP ownership changes.
  - **Multi-IP Claiming** (`WARNING`): Single MAC claiming multiple distinct IPs within a time window.
  - **Gratuitous ARP Flooding** (`HIGH`): Detecting high-frequency unsolicited ARP replies or announcements.
- **Whitelist Management**: Loads trusted static IP-to-MAC pairs from a customizable JSON file (`whitelist.json`).
- **Flexible Logging & Exports**: Supports real-time colorized terminal alerts, security log files (`arp_detector.log`), and structured JSON export (`--json-output alerts.json`).
- **Interface Enumeration**: Built-in utility (`--list-interfaces`) to enumerate active interfaces and MAC addresses.

---

## 📋 Prerequisites

- **OS**: Linux (Kali Linux, Ubuntu, Debian), macOS, or Windows (with Npcap).
- **Python**: Python 3.7 or higher.
- **Permissions**: Root / Administrator privileges are required for raw socket access and packet sniffing.

### Install Dependencies

```bash
pip install scapy
```

*Note on Linux (e.g. Kali):*
```bash
sudo apt update
sudo apt install python3-scapy -y
```

---

## 🚀 Quick Start & Usage

### 1. List Available Network Interfaces

```bash
sudo python3 arp_detector.py --list-interfaces
```

### 2. Basic Network Sniffing

Listen on an interface (e.g., `eth0` or `wlan0`):

```bash
sudo python3 arp_detector.py -i eth0
```

### 3. Protect Gateway Address (Pinned Gateway)

Specify known IP and MAC address pairs for your trusted gateway router:

```bash
sudo python3 arp_detector.py -i eth0 -g 192.168.1.1:AA:BB:CC:DD:EE:FF
```

### 4. Advanced Security Monitoring (JSON Export & Custom Whitelist)

```bash
sudo python3 arp_detector.py \
  -i eth0 \
  -g 192.168.1.1:00:11:22:33:44:55 \
  -w trusted_hosts.json \
  -o security_audit.log \
  --json-output alerts.json \
  -v
```

---

## 🛠️ CLI Options

| Flag | Long Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `-l` | `--list-interfaces` | List available network interfaces and exit | `False` |
| `-i` | `--interface` | Network interface to listen on (e.g. `eth0`) | `None` |
| `-g` | `--known-gateway` | Pin trusted `IP:MAC` pair (can be passed multiple times) | `None` |
| `-w` | `--whitelist` | Path to JSON whitelist file | `whitelist.json` |
| `-o` | `--log-file` | Path for security text log file | `arp_detector.log` |
| `--json-output` | `--json-output` | Export structured JSON alerts to specified file path | `None` |
| `--anomaly-window` | `--anomaly-window` | Time window (seconds) to track ARP anomalies | `60` |
| `--multi-ip-threshold` | `--multi-ip-threshold` | Number of distinct IPs per MAC before triggering alert | `3` |
| `-v` | `--verbose` | Enable verbose debugging console output | `False` |

---

## 🛡️ Detection Heuristics

| Anomaly Type | Severity | Description |
| :--- | :--- | :--- |
| `PINNED_HOST_VIOLATION` | 🔴 **CRITICAL** | An unauthorized MAC address claims an IP pinned via `-g` or present in `whitelist.json`. |
| `MAPPING_CHANGE` | 🟠 **HIGH** | An existing IP-to-MAC mapping changes to a new MAC during the active monitoring session. |
| `GRATUITOUS_FLOOD` | 🟠 **HIGH** | Excessive unsolicited ARP replies or broadcasts detected within `--anomaly-window`. |
| `MULTI_IP_CLAIM` | 🟡 **WARNING** | A single MAC address claims more IPs than `--multi-ip-threshold` within `--anomaly-window`. |

---

## 📄 Whitelist File Schema (`whitelist.json`)

You can create a `whitelist.json` file in the working directory to define known trusted devices:

```json
{
  "192.168.1.1": "00:11:22:33:44:55",
  "192.168.1.10": "AA:BB:CC:11:22:33",
  "192.168.1.50": "FF:EE:DD:44:55:66"
}
```

---

## 🧪 Running Unit Tests

Run the built-in test suite to verify detection logic using simulated packets:

```bash
python3 -m unittest discover -s tests
```

---

## 📁 Project Structure

```
arp_detector/
├── arp_detector.py      # CLI entrypoint
├── README.md            # Documentation
├── arp_detector/        # Core package module
│   ├── __init__.py
│   ├── alerts.py        # Alert manager & logging logic
│   ├── config.py        # Configuration management & CLI arguments parser
│   ├── detector.py      # Core Scapy packet handler & detection heuristics engine
│   └── interface.py     # Interface enumeration utilities
└── tests/
    └── test_detector.py # Unit tests for detection heuristics
```
