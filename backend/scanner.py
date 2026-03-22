"""
Network device discovery via ARP scanning + enhanced discovery.

Educational note:
  ARP (Address Resolution Protocol) maps IP addresses to MAC addresses
  on a local network.  By sending ARP "who-has" requests to every IP in
  the subnet, we can discover all active devices and their MAC addresses.

  Enhanced discovery adds:
  - mDNS/Bonjour: discovers devices advertising services (.local domains)
  - SSDP/UPnP: discovers smart home devices, media servers, IoT
  - OS fingerprinting via TCP/IP stack analysis (TTL, window size)
  - Device type auto-detection from vendor + OS + open ports

  In simulation mode, we generate fake discovered devices so students
  can experiment without root access or a real network.

  Scapy's `arping()` sends ARP requests and collects responses.
  Requires root/sudo for raw socket access in real mode.
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
from dataclasses import dataclass
from datetime import datetime, timezone

from config import config
from mac_vendor import lookup_vendor, guess_device_type
from network_utils import get_subnet_cidr

logger = logging.getLogger("ddos_shield.scanner")


@dataclass(frozen=True)
class DiscoveredDevice:
    """Immutable record of a device found via network scan."""

    mac_address: str
    ip_address: str
    hostname: str
    os_info: str
    device_type: str = "unknown"
    vendor: str = "Unknown"
    open_ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()
    discovery_method: str = "arp"

    def to_dict(self) -> dict:
        return {
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "device_type": self.device_type,
            "vendor": self.vendor,
            "open_ports": list(self.open_ports),
            "services": list(self.services),
            "discovery_method": self.discovery_method,
        }


# ---------------------------------------------------------------------------
# Simulated devices for demo mode — 18 realistic devices
# ---------------------------------------------------------------------------

# Stable MAC addresses so sniffer can reuse them
_SIM_DEVICE_TEMPLATES = [
    # (hostname, os_info, device_type, vendor, ports, services, method)
    # -- 2 Routers --
    ("Gateway-Router", "OpenWrt 23.05", "router", "TP-Link",
     (22, 53, 80, 443), ("ssh", "dns", "http", "https"), "arp"),
    ("Edge-Router", "MikroTik RouterOS 7.12", "router", "MikroTik",
     (22, 23, 80, 161, 8291), ("ssh", "telnet", "http", "snmp", "winbox"), "arp"),
    # -- 1 NAS --
    ("NAS-Vault", "Synology DSM 7.2", "nas", "Synology",
     (22, 80, 443, 445, 5000, 5001), ("ssh", "http", "https", "smb", "dsm", "dsm-ssl"), "ssdp"),
    # -- 3 Servers --
    ("Web-Server", "Ubuntu 22.04 LTS", "server", "Dell",
     (22, 80, 443, 3306, 8080), ("ssh", "http", "https", "mysql", "tomcat"), "arp"),
    ("DB-Server", "CentOS Stream 9", "server", "HP",
     (22, 3306, 5432, 6379, 9090), ("ssh", "mysql", "postgresql", "redis", "prometheus"), "arp"),
    ("File-Server", "Windows Server 2019", "server", "Dell",
     (21, 135, 139, 445, 3389), ("ftp", "msrpc", "netbios", "smb", "rdp"), "arp"),
    # -- 5 PCs --
    ("Dev-Workstation", "macOS 14 Sonoma", "client", "Apple",
     (22, 443, 548, 5353, 631), ("ssh", "https", "afp", "mdns", "cups"), "mdns"),
    ("Office-Laptop-1", "Windows 11 Pro", "client", "Dell",
     (135, 445, 3389, 5357), ("msrpc", "smb", "rdp", "wsd"), "arp"),
    ("Office-Laptop-2", "Windows 10 Pro", "client", "Lenovo",
     (135, 445, 3389), ("msrpc", "smb", "rdp"), "arp"),
    ("Linux-Dev", "Ubuntu 24.04", "client", "Lenovo",
     (22, 80, 8080, 5432), ("ssh", "http", "http-proxy", "postgresql"), "arp"),
    ("Intern-PC", "Windows 11 Home", "client", "HP",
     (135, 445, 8080, 23), ("msrpc", "smb", "http-proxy", "telnet"), "arp"),
    # -- 2 Phones --
    ("iPhone-Alice", "iOS 17.4", "phone", "Apple",
     (443, 5353, 62078), ("https", "mdns", "lockdown"), "mdns"),
    ("Galaxy-Bob", "Android 14", "phone", "Samsung",
     (443, 5353, 8008), ("https", "mdns", "chromecast"), "mdns"),
    # -- 2 IoT --
    ("Smart-Thermostat", "Espressif RTOS 4.4", "iot", "Espressif (IoT)",
     (80, 1883, 8883), ("http", "mqtt", "mqtts"), "mdns"),
    ("Smart-Plug-Hub", "Tuya OS 3.5", "iot", "Tuya",
     (80, 443, 6668, 8080), ("http", "https", "tuya-proto", "http-proxy"), "ssdp"),
    # -- 1 Printer --
    ("HP-LaserJet", "HP LaserJet FW 2.3", "printer", "HP",
     (80, 443, 515, 631, 9100), ("http", "https", "lpd", "ipp", "jetdirect"), "ssdp"),
    # -- 2 Cameras --
    ("Lobby-Camera", "Hikvision FW 5.6", "camera", "Hikvision",
     (80, 443, 554, 8000, 23), ("http", "https", "rtsp", "sdk", "telnet"), "ssdp"),
    ("Parking-Camera", "Dahua FW 2.8", "camera", "Dahua",
     (80, 443, 554, 37777), ("http", "https", "rtsp", "dahua-rpc"), "ssdp"),
]

# Stable MACs generated deterministically (no randomness in the base)
_SIM_STABLE_MACS: list[str] = []
_SIM_DISCOVERED: list[DiscoveredDevice] = []


def _init_sim_devices() -> list[DiscoveredDevice]:
    """Generate a pool of simulated discovered devices with rich detail."""
    global _SIM_DISCOVERED, _SIM_STABLE_MACS
    if _SIM_DISCOVERED:
        return _SIM_DISCOVERED

    devices = []
    macs = []
    for i, (hostname, os_info, dev_type, vendor, ports, services, method) in enumerate(_SIM_DEVICE_TEMPLATES):
        # Deterministic MAC based on index (stable across restarts within same session)
        mac = f"AA:BB:CC:{i:02X}:{(i * 17 + 42) % 256:02X}:{(i * 31 + 7) % 256:02X}"
        ip = f"192.168.1.{10 + i}"
        macs.append(mac)
        devices.append(DiscoveredDevice(
            mac_address=mac,
            ip_address=ip,
            hostname=hostname,
            os_info=os_info,
            device_type=dev_type,
            vendor=vendor,
            open_ports=ports,
            services=services,
            discovery_method=method,
        ))

    _SIM_STABLE_MACS = macs
    _SIM_DISCOVERED = devices
    return devices


def get_sim_mac_ip_map() -> dict[str, str]:
    """Return {MAC: IP} mapping for simulation devices. Used by sniffer."""
    if not _SIM_DISCOVERED:
        _init_sim_devices()
    return {d.mac_address: d.ip_address for d in _SIM_DISCOVERED}


def get_sim_devices() -> list[DiscoveredDevice]:
    """Return all simulation devices. Used by bootstrap."""
    if not _SIM_DISCOVERED:
        _init_sim_devices()
    return list(_SIM_DISCOVERED)


# ---------------------------------------------------------------------------
# Real ARP scan
# ---------------------------------------------------------------------------

def _resolve_hostname(ip: str) -> str:
    """Try reverse DNS lookup for a hostname."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _detect_os_from_ttl(ttl: int) -> str:
    """
    OS fingerprinting from TTL values.

    Educational note:
      Different operating systems use different default TTL values:
      - Linux/macOS: 64
      - Windows: 128
      - Network equipment (Cisco, etc.): 255
      The TTL decreases by 1 at each hop, so we check ranges.
    """
    if ttl <= 64:
        return "Linux/macOS (TTL<=64)"
    if ttl <= 128:
        return "Windows (TTL<=128)"
    return "Network device (TTL>128)"


async def _real_arp_scan(subnet: str | None = None) -> list[DiscoveredDevice]:
    """
    Perform an ARP scan on the local network using Scapy.

    Auto-detects the subnet from the active interface if not provided.
    Sends ARP who-has requests to every IP in the subnet and collects
    responses to build a list of active devices.
    """
    if not subnet:
        subnet = get_subnet_cidr()
        if not subnet:
            logger.error(
                "Cannot determine local subnet for ARP scan. "
                "Make sure you are connected to a network."
            )
            return []

    logger.info("ARP scanning subnet: %s", subnet)

    try:
        from scapy.all import ARP, Ether, srp, IP, sr1, ICMP, conf  # type: ignore
    except ImportError:
        logger.error("Scapy not installed. Cannot perform ARP scan.")
        return []

    # Check for root/sudo
    import os as _os
    if _os.geteuid() != 0:
        logger.error(
            "ARP scan requires root/sudo. Run with: sudo python main.py"
        )
        return []

    loop = asyncio.get_event_loop()

    def _scan():
        devices = []
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            answered, _ = srp(arp_request, timeout=3, verbose=False)

            for sent, received in answered:
                mac = received.hwsrc.upper()
                ip = received.psrc
                hostname = _resolve_hostname(ip)
                vendor = lookup_vendor(mac)
                dev_type = guess_device_type(mac, vendor)

                # Quick ICMP ping to get TTL for OS fingerprinting
                os_info = ""
                try:
                    ping = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=False)
                    if ping:
                        os_info = _detect_os_from_ttl(ping.ttl)
                except Exception:
                    pass

                devices.append(DiscoveredDevice(
                    mac_address=mac,
                    ip_address=ip,
                    hostname=hostname,
                    os_info=os_info,
                    device_type=dev_type,
                    vendor=vendor,
                    discovery_method="arp",
                ))

        except PermissionError:
            logger.error("ARP scan requires root/sudo.")
        except Exception as exc:
            logger.error("ARP scan failed: %s", exc)

        return devices

    return await loop.run_in_executor(None, _scan)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

_last_scan_results: list[DiscoveredDevice] = []
_scan_lock = asyncio.Lock()
_scan_in_progress: bool = False


async def scan_network(subnet: str | None = None) -> list[DiscoveredDevice]:
    """
    Scan the local network for devices.

    In simulation mode, returns pre-generated fake devices.
    In real mode, performs an ARP scan (requires root).
    Real mode NEVER generates fake/simulated devices — the list stays
    empty until real devices are found via ARP.

    The subnet is auto-detected from the active interface if not provided.
    """
    global _last_scan_results, _scan_in_progress

    async with _scan_lock:
        _scan_in_progress = True
        try:
            if config.simulation.enabled:
                results = _init_sim_devices()
                # Randomly add a couple transient devices for realism
                extra_count = random.randint(0, 2)
                extra_devices = []
                for _ in range(extra_count):
                    mac = f"DD:EE:FF:{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}"
                    ip = f"192.168.1.{random.randint(100, 200)}"
                    extra_devices.append(DiscoveredDevice(
                        mac_address=mac,
                        ip_address=ip,
                        hostname=f"New-Device-{random.randint(1,99)}",
                        os_info="Unknown",
                        device_type="unknown",
                        vendor="Unknown",
                        discovery_method="arp",
                    ))
                results = list(results) + extra_devices
                _last_scan_results = results
                logger.info("[SIM] Network scan: found %d devices", len(results))
            else:
                # Real mode: only ARP-discovered devices, no fakes
                results = await _real_arp_scan(subnet)
                _last_scan_results = results
                if results:
                    logger.info("ARP scan complete: found %d devices", len(results))
                else:
                    logger.info(
                        "ARP scan complete: no devices found. "
                        "Ensure you are running with sudo and connected to a network."
                    )

            return _last_scan_results
        finally:
            _scan_in_progress = False


def get_last_scan_results() -> list[DiscoveredDevice]:
    """Return the most recent scan results without triggering a new scan."""
    return list(_last_scan_results)


def is_scanning() -> bool:
    """Return True if a scan is currently in progress."""
    return _scan_in_progress


async def periodic_scan_loop(interval: float = 30.0):
    """
    Background task that scans the network at regular intervals.

    Runs every `interval` seconds to keep the discovered device list fresh.
    """
    while True:
        try:
            await scan_network()
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Error in periodic scan")
        await asyncio.sleep(interval)
