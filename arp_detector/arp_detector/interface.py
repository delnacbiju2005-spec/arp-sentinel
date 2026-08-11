import socket
from typing import List, Dict, Any


def get_available_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerates available network interfaces using Scapy's interface manager.
    Returns list of dicts containing name, ip, mac, and description.
    """
    interfaces = []
    try:
        from scapy.arch import get_working_ifaces
        for iface in get_working_ifaces():
            interfaces.append({
                "name": getattr(iface, "name", str(iface)),
                "description": getattr(iface, "description", getattr(iface, "name", "N/A")),
                "ip": getattr(iface, "ip", "0.0.0.0") or "0.0.0.0",
                "mac": getattr(iface, "mac", "00:00:00:00:00:00") or "00:00:00:00:00:00",
            })
    except Exception:
        # Fallback to scapy.all.IFACES if get_working_ifaces is unavailable
        try:
            from scapy.all import IFACES
            for name, iface in IFACES.items():
                interfaces.append({
                    "name": getattr(iface, "name", name),
                    "description": getattr(iface, "description", name),
                    "ip": getattr(iface, "ip", "0.0.0.0") or "0.0.0.0",
                    "mac": getattr(iface, "mac", "00:00:00:00:00:00") or "00:00:00:00:00:00",
                })
        except Exception:
            # Fallback mock/basic list
            interfaces.append({
                "name": "default",
                "description": "Default System Interface",
                "ip": "127.0.0.1",
                "mac": "00:00:00:00:00:00"
            })

    return interfaces


def print_interfaces_table() -> None:
    """Prints formatted table of all available network interfaces."""
    ifaces = get_available_interfaces()
    print("\n" + "=" * 70)
    print("                     AVAILABLE NETWORK INTERFACES                     ")
    print("=" * 70)
    print(f"{'INTERFACE NAME':<25} {'IP ADDRESS':<16} {'MAC ADDRESS':<18} DESCRIPTION")
    print("-" * 70)
    for iface in ifaces:
        name = str(iface['name'])[:24]
        ip = str(iface['ip'])[:15]
        mac = str(iface['mac'])[:17]
        desc = str(iface['description'])[:20]
        print(f"{name:<25} {ip:<16} {mac:<18} {desc}")
    print("=" * 70 + "\n")
