"""
Network device discovery via ARP scanning.

Educational note:
  ARP (Address Resolution Protocol) maps IP addresses to MAC addresses
  on a local network.  By sending ARP "who-has" requests to every IP in
  the subnet, we can discover all active devices and their MAC addresses.

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

logger = logging.getLogger("ddos_shield.scanner")


@dataclass(frozen=True)
class DiscoveredDevice:
    """Immutable record of a device found via ARP scan."""

    mac_address: str
    ip_address: str
    hostname: str
    os_info: str

    def to_dict(self) -> dict:
        return {
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "os_info": self.os_info,
        }


# ---------------------------------------------------------------------------
# Simulated devices for demo mode
# ---------------------------------------------------------------------------

_SIM_DISCOVERED: list[DiscoveredDevice] = []


def _init_sim_devices() -> list[DiscoveredDevice]:
    """Generate a pool of simulated discovered devices."""
    global _SIM_DISCOVERED
    if _SIM_DISCOVERED:
        return _SIM_DISCOVERED

    templates = [
        ("Windows Server", "Windows Server 2019"),
        ("File Server", "Windows Server 2022"),
        ("Web Server", "Ubuntu 22.04"),
        ("Workstation-A", "Windows 11"),
        ("Workstation-B", "Windows 10"),
        ("MacBook-Pro", "macOS 14"),
        ("Linux-Dev", "Ubuntu 24.04"),
        ("Printer", "Embedded Linux"),
        ("NAS-Storage", "Synology DSM 7"),
        ("Router", "OpenWrt 23"),
        ("IP-Camera", "Embedded ARM"),
        ("Smart-TV", "Tizen OS"),
    ]

    devices = []
    for i, (hostname, os_info) in enumerate(templates):
        mac = f"AA:BB:CC:{i:02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}"
        ip = f"192.168.1.{10 + i}"
        devices.append(DiscoveredDevice(
            mac_address=mac,
            ip_address=ip,
            hostname=hostname,
            os_info=os_info,
        ))

    _SIM_DISCOVERED = devices
    return devices


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
    """Basic OS fingerprinting from TTL values."""
    if ttl <= 64:
        return "Linux/macOS (TTL<=64)"
    if ttl <= 128:
        return "Windows (TTL<=128)"
    return "Network device (TTL>128)"


async def _real_arp_scan(subnet: str = "192.168.1.0/24") -> list[DiscoveredDevice]:
    """
    Perform an ARP scan on the local network using Scapy.

    Sends ARP who-has requests to every IP in the subnet and collects
    responses to build a list of active devices.
    """
    try:
        from scapy.all import ARP, Ether, srp, IP, sr1, ICMP, conf  # type: ignore
    except ImportError:
        logger.error("Scapy not installed. Cannot perform ARP scan.")
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


async def scan_network(subnet: str = "192.168.1.0/24") -> list[DiscoveredDevice]:
    """
    Scan the local network for devices.

    In simulation mode, returns pre-generated fake devices.
    In real mode, performs an ARP scan (requires root).
    """
    global _last_scan_results

    async with _scan_lock:
        if config.simulation.enabled:
            results = _init_sim_devices()
            # Randomly toggle a couple devices on/off for realism
            extra_count = random.randint(0, 2)
            for _ in range(extra_count):
                mac = f"DD:EE:FF:{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}"
                ip = f"192.168.1.{random.randint(100, 200)}"
                results = list(results) + [DiscoveredDevice(
                    mac_address=mac,
                    ip_address=ip,
                    hostname=f"New-Device-{random.randint(1,99)}",
                    os_info="Unknown",
                )]
            _last_scan_results = results
            logger.info("[SIM] Network scan: found %d devices", len(results))
        else:
            results = await _real_arp_scan(subnet)
            _last_scan_results = results
            logger.info("ARP scan complete: found %d devices", len(results))

        return _last_scan_results


def get_last_scan_results() -> list[DiscoveredDevice]:
    """Return the most recent scan results without triggering a new scan."""
    return list(_last_scan_results)


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
