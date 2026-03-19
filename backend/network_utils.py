"""
Network auto-detection utilities.

Provides functions to discover the active network interface, local IP,
subnet mask, and CIDR subnet — used by the sniffer and scanner to avoid
hardcoded values like 192.168.1.0/24.
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import socket
import struct
import subprocess

logger = logging.getLogger("ddos_shield.network_utils")


def get_active_interface() -> str | None:
    """
    Return the name of the primary network interface connected to the LAN.

    On macOS: parses `route get default` to find the interface, preferring
    en0/en1 over VM bridges.
    On Linux: parses `ip route` for the default route interface.
    Returns None if detection fails.
    """
    system = platform.system()

    try:
        if system == "Darwin":
            return _get_macos_default_interface()
        return _get_linux_default_interface()
    except Exception as exc:
        logger.warning("Failed to detect active interface: %s", exc)
        return None


def _find_cmd(name: str) -> str:
    """Find a system command, checking common sbin paths."""
    for prefix in ("/sbin/", "/usr/sbin/", "/usr/bin/", "/bin/", ""):
        path = f"{prefix}{name}"
        try:
            subprocess.check_output([path, "--help"], stderr=subprocess.DEVNULL, timeout=2)
            return path
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            # CalledProcessError is fine — it means the command exists
            if prefix:
                import os
                if os.path.isfile(path):
                    return path
    return name  # fallback to bare name


def _get_macos_default_interface() -> str | None:
    """Get the default route interface on macOS."""
    route_cmd = _find_cmd("route")
    try:
        output = subprocess.check_output(
            [route_cmd, "-n", "get", "default"],
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("interface:"):
                iface = line.split(":", 1)[1].strip()
                logger.info("macOS default route interface: %s", iface)
                return iface
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: try common macOS interfaces
    ifconfig_cmd = _find_cmd("ifconfig")
    for candidate in ("en0", "en1"):
        try:
            output = subprocess.check_output(
                [ifconfig_cmd, candidate],
                text=True,
                timeout=5,
                stderr=subprocess.DEVNULL,
            )
            if "status: active" in output and "inet " in output:
                logger.info("Fallback: found active interface %s", candidate)
                return candidate
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    return None


def _get_linux_default_interface() -> str | None:
    """Get the default route interface on Linux."""
    try:
        output = subprocess.check_output(
            [_find_cmd("ip"), "route", "show", "default"],
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
        # Format: "default via 192.168.1.1 dev eth0 ..."
        parts = output.strip().split()
        if "dev" in parts:
            idx = parts.index("dev")
            iface = parts[idx + 1]
            logger.info("Linux default route interface: %s", iface)
            return iface
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


def get_local_ip(interface: str | None = None) -> str | None:
    """
    Get the local IP address for the given interface (or the default route).

    Falls back to connecting a UDP socket to a public IP to determine
    the outgoing address.
    """
    if interface:
        ip = _get_ip_from_interface(interface)
        if ip:
            return ip

    # Fallback: UDP socket trick (does not actually send data)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            logger.info("Local IP (socket fallback): %s", ip)
            return ip
    except OSError:
        return None


def _get_ip_from_interface(interface: str) -> str | None:
    """Extract the IPv4 address assigned to a specific interface."""
    system = platform.system()

    try:
        if system == "Darwin":
            cmd = [_find_cmd("ifconfig"), interface]
        else:
            cmd = [_find_cmd("ip"), "addr", "show", interface]
        output = subprocess.check_output(
            cmd, text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None

    for line in output.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            # macOS: "inet 192.168.31.164 netmask 0xffffff00 broadcast ..."
            # Linux: "inet 192.168.31.164/24 brd ... scope global ..."
            parts = line.split()
            addr_part = parts[1]
            # Strip CIDR suffix if present
            return addr_part.split("/")[0]

    return None


def get_subnet_cidr(interface: str | None = None) -> str | None:
    """
    Calculate the subnet in CIDR notation for the given interface.

    Example: if the interface has IP 192.168.31.164/255.255.255.0,
    returns "192.168.31.0/24".
    """
    iface = interface or get_active_interface()
    if not iface:
        return None

    ip_str = _get_ip_from_interface(iface)
    if not ip_str:
        return None

    netmask_str = _get_netmask(iface)
    if not netmask_str:
        # Default to /24 if we can't determine the mask
        try:
            network = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
            subnet = str(network)
            logger.info("Subnet (default /24): %s", subnet)
            return subnet
        except ValueError:
            return None

    try:
        network = ipaddress.IPv4Network(f"{ip_str}/{netmask_str}", strict=False)
        subnet = str(network)
        logger.info("Detected subnet: %s (interface=%s)", subnet, iface)
        return subnet
    except ValueError as exc:
        logger.warning("Failed to compute subnet: %s", exc)
        return None


def _get_netmask(interface: str) -> str | None:
    """Get the subnet mask for an interface."""
    system = platform.system()

    try:
        if system == "Darwin":
            return _get_netmask_macos(interface)
        return _get_netmask_linux(interface)
    except Exception as exc:
        logger.warning("Failed to get netmask for %s: %s", interface, exc)
        return None


def _get_netmask_macos(interface: str) -> str | None:
    """Parse ifconfig output for the hex netmask on macOS."""
    output = subprocess.check_output(
        [_find_cmd("ifconfig"), interface], text=True, timeout=5, stderr=subprocess.DEVNULL,
    )
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("inet ") and "netmask" in line:
            parts = line.split()
            try:
                mask_idx = parts.index("netmask") + 1
                hex_mask = parts[mask_idx]
                # Convert hex like 0xffffff00 to dotted decimal
                mask_int = int(hex_mask, 16)
                return socket.inet_ntoa(struct.pack(">I", mask_int))
            except (ValueError, IndexError, struct.error):
                continue
    return None


def _get_netmask_linux(interface: str) -> str | None:
    """Parse ip addr output for the prefix length on Linux."""
    output = subprocess.check_output(
        [_find_cmd("ip"), "addr", "show", interface], text=True, timeout=5, stderr=subprocess.DEVNULL,
    )
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            # "inet 192.168.31.164/24 brd ..."
            parts = line.split()
            addr_cidr = parts[1]
            if "/" in addr_cidr:
                prefix_len = int(addr_cidr.split("/")[1])
                # Convert prefix length to dotted-decimal mask
                mask_int = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
                return socket.inet_ntoa(struct.pack(">I", mask_int))
    return None


def get_network_info() -> dict:
    """
    Return a dict with all detected network info.

    Keys: interface, ip_address, subnet, error
    """
    interface = get_active_interface()
    if not interface:
        return {
            "interface": None,
            "ip_address": None,
            "subnet": None,
            "error": "Could not detect active network interface",
        }

    ip_address = get_local_ip(interface)
    subnet = get_subnet_cidr(interface)

    return {
        "interface": interface,
        "ip_address": ip_address,
        "subnet": subnet,
        "error": None,
    }
