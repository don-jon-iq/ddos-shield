"""
VM network interface detection and monitoring.

Educational note:
  Virtual machines communicate through virtual network interfaces
  created by the hypervisor.  Common types include:

  - **virbr**  – libvirt virtual bridge (e.g. virbr0)
  - **veth**   – Virtual Ethernet pairs used by Docker / containers
  - **tap**    – TAP device used by QEMU/KVM for guest networking
  - **br-**    – Docker bridge networks
  - **docker0** – Default Docker bridge
  - **vnet**   – libvirt guest-facing end of a veth pair

  Monitoring these interfaces lets us see inter-VM traffic that
  never touches the physical NIC.
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass

from config import config


@dataclass(frozen=True)
class NetworkInterface:
    """Immutable snapshot of a network interface."""

    name: str
    is_virtual: bool
    mac_address: str
    status: str  # "UP" or "DOWN"


def detect_interfaces() -> list[NetworkInterface]:
    """
    Detect all network interfaces and classify them as physical or virtual.

    Returns:
        Sorted list of NetworkInterface objects (virtual first).

    Educational note:
      On Linux we parse /sys/class/net.  On macOS (common in labs)
      we fall back to `ifconfig` since /sys doesn't exist.
    """
    system = platform.system()
    if system == "Linux":
        return _detect_linux()
    if system == "Darwin":
        return _detect_macos()
    # Fallback: return empty list on unsupported platforms
    return []


def _detect_linux() -> list[NetworkInterface]:
    """Parse /sys/class/net for interface metadata."""
    import os

    interfaces: list[NetworkInterface] = []
    net_dir = "/sys/class/net"

    if not os.path.isdir(net_dir):
        return interfaces

    for name in sorted(os.listdir(net_dir)):
        mac = _read_file(f"{net_dir}/{name}/address").strip()
        operstate = _read_file(f"{net_dir}/{name}/operstate").strip()
        status = "UP" if operstate == "up" else "DOWN"
        is_virtual = _is_virtual_interface(name)
        interfaces.append(
            NetworkInterface(name=name, is_virtual=is_virtual, mac_address=mac, status=status)
        )

    return sorted(interfaces, key=lambda i: (not i.is_virtual, i.name))


def _detect_macos() -> list[NetworkInterface]:
    """Parse ifconfig output on macOS."""
    try:
        output = subprocess.check_output(["ifconfig"], text=True, timeout=5)
    except (subprocess.SubprocessError, FileNotFoundError):
        return []

    interfaces: list[NetworkInterface] = []
    current_name = ""
    current_mac = "00:00:00:00:00:00"
    current_status = "DOWN"

    for line in output.splitlines():
        if line and not line[0].isspace():
            # Save previous interface
            if current_name:
                interfaces.append(
                    NetworkInterface(
                        name=current_name,
                        is_virtual=_is_virtual_interface(current_name),
                        mac_address=current_mac,
                        status=current_status,
                    )
                )
            current_name = line.split(":")[0]
            current_mac = "00:00:00:00:00:00"
            current_status = "UP" if "UP" in line else "DOWN"
        elif "ether" in line:
            parts = line.strip().split()
            idx = parts.index("ether") if "ether" in parts else -1
            if idx >= 0 and idx + 1 < len(parts):
                current_mac = parts[idx + 1]

    # Don't forget the last interface
    if current_name:
        interfaces.append(
            NetworkInterface(
                name=current_name,
                is_virtual=_is_virtual_interface(current_name),
                mac_address=current_mac,
                status=current_status,
            )
        )

    return sorted(interfaces, key=lambda i: (not i.is_virtual, i.name))


def _is_virtual_interface(name: str) -> bool:
    """Check if an interface name matches known VM/container prefixes."""
    return any(name.startswith(prefix) for prefix in config.vm_interface_prefixes)


def _read_file(path: str) -> str:
    """Safely read a small sysfs file."""
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""
