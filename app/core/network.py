"""Local subnet detection."""
from __future__ import annotations

import ipaddress
import socket

import psutil


def detect_subnet() -> dict:
    """Find the interface used for outbound traffic and derive its subnet.

    A UDP "connect" sends no packets; it just makes the OS pick the outbound interface.
    Subnets larger than /24 are narrowed to the /24 around our IP to keep scans quick.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))  # TEST-NET address, nothing is sent
        local_ip = sock.getsockname()[0]
    except OSError:
        raise RuntimeError("No active network connection found. Connect to Wi-Fi or Ethernet and retry.") from None
    finally:
        sock.close()

    net = ipaddress.ip_network(f"{local_ip}/24", strict=False)  # fallback
    iface = None
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and a.address == local_ip and a.netmask:
                net, iface = ipaddress.ip_network(f"{local_ip}/{a.netmask}", strict=False), name
    if net.prefixlen < 24:
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return {"local_ip": local_ip, "cidr": str(net), "interface": iface, "is_private": net.is_private}
