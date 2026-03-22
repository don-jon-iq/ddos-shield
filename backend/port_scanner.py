"""
Port scanning engine for DDoS Shield.

Educational note:
  Port scanning is a fundamental network reconnaissance technique.
  By sending connection attempts to known port numbers, we discover
  which services a device is running. This information is critical
  for vulnerability assessment — you can't protect what you don't
  know about.

  Common port scanning techniques:
  - TCP Connect: Full 3-way handshake (what we use — most reliable)
  - SYN Scan: Half-open scan (faster, requires root)
  - UDP Scan: Slower, unreliable due to ICMP rate limiting

  In simulation mode, we generate realistic port scan results
  based on device type templates.
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
from dataclasses import dataclass
from datetime import datetime, timezone

from config import config

logger = logging.getLogger("ddos_shield.port_scanner")


# ---------------------------------------------------------------------------
# Well-known ports and their services (top 100 most common)
# ---------------------------------------------------------------------------

COMMON_PORTS: dict[int, tuple[str, str]] = {
    20: ("ftp-data", "FTP Data"),
    21: ("ftp", "FTP"),
    22: ("ssh", "SSH"),
    23: ("telnet", "Telnet"),
    25: ("smtp", "SMTP"),
    53: ("dns", "DNS"),
    67: ("dhcp", "DHCP Server"),
    68: ("dhcp-client", "DHCP Client"),
    69: ("tftp", "TFTP"),
    80: ("http", "HTTP"),
    88: ("kerberos", "Kerberos"),
    110: ("pop3", "POP3"),
    111: ("rpc", "RPC"),
    119: ("nntp", "NNTP"),
    123: ("ntp", "NTP"),
    135: ("msrpc", "Microsoft RPC"),
    137: ("netbios-ns", "NetBIOS Name"),
    138: ("netbios-dgm", "NetBIOS Datagram"),
    139: ("netbios-ssn", "NetBIOS Session"),
    143: ("imap", "IMAP"),
    161: ("snmp", "SNMP"),
    162: ("snmptrap", "SNMP Trap"),
    179: ("bgp", "BGP"),
    194: ("irc", "IRC"),
    389: ("ldap", "LDAP"),
    443: ("https", "HTTPS"),
    445: ("smb", "SMB/CIFS"),
    465: ("smtps", "SMTP over SSL"),
    500: ("isakmp", "IPSec IKE"),
    514: ("syslog", "Syslog"),
    515: ("lpd", "Line Printer"),
    520: ("rip", "RIP"),
    548: ("afp", "Apple Filing Protocol"),
    554: ("rtsp", "RTSP"),
    587: ("submission", "SMTP Submission"),
    631: ("ipp", "IPP/CUPS"),
    636: ("ldaps", "LDAP over SSL"),
    873: ("rsync", "Rsync"),
    902: ("vmware", "VMware Server"),
    993: ("imaps", "IMAP over SSL"),
    995: ("pop3s", "POP3 over SSL"),
    1080: ("socks", "SOCKS Proxy"),
    1194: ("openvpn", "OpenVPN"),
    1433: ("mssql", "Microsoft SQL Server"),
    1434: ("mssql-udp", "MS SQL Monitor"),
    1521: ("oracle", "Oracle DB"),
    1723: ("pptp", "PPTP VPN"),
    1883: ("mqtt", "MQTT"),
    2049: ("nfs", "NFS"),
    2082: ("cpanel", "cPanel"),
    2083: ("cpanels", "cPanel SSL"),
    3306: ("mysql", "MySQL"),
    3389: ("rdp", "Remote Desktop"),
    3478: ("stun", "STUN/TURN"),
    4443: ("https-alt", "HTTPS Alt"),
    5000: ("upnp", "UPnP"),
    5060: ("sip", "SIP"),
    5222: ("xmpp", "XMPP"),
    5353: ("mdns", "mDNS"),
    5432: ("postgresql", "PostgreSQL"),
    5900: ("vnc", "VNC"),
    5984: ("couchdb", "CouchDB"),
    6379: ("redis", "Redis"),
    6443: ("k8s-api", "Kubernetes API"),
    6667: ("irc", "IRC"),
    8000: ("http-alt", "HTTP Alt"),
    8008: ("http-alt2", "HTTP Alt"),
    8080: ("http-proxy", "HTTP Proxy"),
    8443: ("https-alt", "HTTPS Alt"),
    8888: ("http-alt3", "HTTP Alt"),
    9090: ("prometheus", "Prometheus"),
    9200: ("elasticsearch", "Elasticsearch"),
    9418: ("git", "Git"),
    9999: ("http-alt4", "HTTP Alt"),
    10000: ("webmin", "Webmin"),
    11211: ("memcached", "Memcached"),
    27017: ("mongodb", "MongoDB"),
    27018: ("mongodb-s", "MongoDB Shard"),
    49152: ("dynamic", "Dynamic Port"),
}

# Ports sorted by commonality for scanning
TOP_100_PORTS = sorted(COMMON_PORTS.keys())


# ---------------------------------------------------------------------------
# Port risk classification
# ---------------------------------------------------------------------------

# Ports that are inherently risky if open
HIGH_RISK_PORTS: set[int] = {23, 69, 135, 137, 138, 139, 161, 445, 514, 1433, 3389, 5900, 6667}
MEDIUM_RISK_PORTS: set[int] = {21, 25, 80, 110, 143, 389, 515, 1521, 2049, 3306, 5432, 8080}


def classify_port_risk(port: int, service: str) -> str:
    """
    Classify the risk level of an open port.

    Educational note:
      Some ports are inherently higher risk than others:
      - Telnet (23): Sends credentials in plaintext
      - RDP (3389): Common target for brute-force attacks
      - SMB (445): Frequently exploited (WannaCry, EternalBlue)
      - SNMP (161): Often misconfigured with default community strings
    """
    if port in HIGH_RISK_PORTS:
        return "HIGH"
    if port in MEDIUM_RISK_PORTS:
        return "MEDIUM"
    if port > 49151:
        return "LOW"
    return "LOW"


# ---------------------------------------------------------------------------
# Scan result dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PortScanResult:
    """Immutable record of a single port scan result."""
    ip_address: str
    mac_address: str
    port: int
    protocol: str
    state: str
    service_name: str
    service_version: str
    banner: str
    risk_level: str

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service_name": self.service_name,
            "service_version": self.service_version,
            "banner": self.banner,
            "risk_level": self.risk_level,
        }


# ---------------------------------------------------------------------------
# Real port scanning
# ---------------------------------------------------------------------------

async def _tcp_connect_scan(
    ip: str,
    port: int,
    timeout: float = 1.0,
) -> tuple[int, str, str, str]:
    """
    Attempt a TCP connection to determine if a port is open.

    Returns: (port, state, banner, service_version)
    """
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)

        # Try to grab a banner
        banner = ""
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
            banner = data.decode("utf-8", errors="replace").strip()[:256]
        except (asyncio.TimeoutError, Exception):
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        # Extract version from banner if possible
        version = ""
        if banner:
            # Common banner patterns
            for prefix in ("SSH-", "HTTP/", "220 ", "* OK"):
                if banner.startswith(prefix):
                    version = banner.split("\n")[0][:64]
                    break

        return (port, "OPEN", banner, version)

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return (port, "CLOSED", "", "")


async def scan_device_ports(
    ip: str,
    mac: str = "",
    ports: list[int] | None = None,
    timeout: float | None = None,
) -> list[PortScanResult]:
    """
    Scan ports on a specific device.

    In real mode, performs TCP connect scans on the specified ports.
    In simulation mode, generates realistic fake results.
    """
    if config.simulation.enabled:
        return _simulate_port_scan(ip, mac)

    scan_ports = ports or TOP_100_PORTS[:config.port_scan.top_ports]
    scan_timeout = timeout or config.port_scan.timeout

    # Scan ports concurrently in batches of 20 to avoid overwhelming the target
    results: list[PortScanResult] = []
    batch_size = 20

    for i in range(0, len(scan_ports), batch_size):
        batch = scan_ports[i:i + batch_size]
        tasks = [_tcp_connect_scan(ip, port, scan_timeout) for port in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in batch_results:
            if isinstance(result, Exception):
                continue
            port, state, banner, version = result
            if state == "OPEN":
                port_info = COMMON_PORTS.get(port, ("unknown", "Unknown"))
                results.append(PortScanResult(
                    ip_address=ip,
                    mac_address=mac,
                    port=port,
                    protocol="TCP",
                    state=state,
                    service_name=port_info[0],
                    service_version=version,
                    banner=banner,
                    risk_level=classify_port_risk(port, port_info[0]),
                ))

    logger.info("Port scan of %s complete: %d open ports", ip, len(results))
    return results


# ---------------------------------------------------------------------------
# Simulation mode port scanning
# ---------------------------------------------------------------------------

# Templates for common device type port profiles
_DEVICE_PORT_PROFILES: dict[str, list[tuple[int, str]]] = {
    "router": [(22, "OpenSSH 8.9"), (53, "dnsmasq 2.89"), (80, "nginx 1.24"), (443, "nginx 1.24"), (8080, "")],
    "server": [(22, "OpenSSH 9.3"), (80, "Apache 2.4.58"), (443, "Apache 2.4.58"), (3306, "MySQL 8.0"), (8080, "Tomcat 10")],
    "windows": [(135, ""), (139, ""), (445, ""), (3389, ""), (5357, "")],
    "linux": [(22, "OpenSSH 9.6"), (80, "nginx 1.26"), (443, ""), (8080, "")],
    "macos": [(22, "OpenSSH 9.4"), (443, ""), (548, ""), (5353, ""), (631, "CUPS 2.4")],
    "printer": [(80, "HP Embedded Web Server"), (443, ""), (515, ""), (631, "CUPS"), (9100, "")],
    "camera": [(80, "lighttpd"), (443, ""), (554, "RTSP/1.0"), (8080, "")],
    "nas": [(22, "OpenSSH 8.4"), (80, "nginx"), (443, "nginx"), (445, "Samba 4.18"), (5000, "Synology DSM"), (8080, "")],
    "iot": [(80, "GoAhead-Webs"), (443, ""), (1883, "Mosquitto 2.0"), (8883, "")],
    "smart_tv": [(8008, ""), (8443, ""), (9080, ""), (5353, "")],
}


def _simulate_port_scan(ip: str, mac: str) -> list[PortScanResult]:
    """Generate simulated port scan results based on device IP patterns."""
    # Determine device type from IP last octet
    last_octet = int(ip.split(".")[-1]) if "." in ip else 10
    idx = (last_octet - 10) % len(_DEVICE_PORT_PROFILES)
    profile_keys = list(_DEVICE_PORT_PROFILES.keys())
    profile_name = profile_keys[idx % len(profile_keys)]
    profile = _DEVICE_PORT_PROFILES[profile_name]

    results: list[PortScanResult] = []
    for port, version in profile:
        # Randomly skip some ports for realism
        if random.random() < 0.15:
            continue

        port_info = COMMON_PORTS.get(port, ("unknown", "Unknown"))
        results.append(PortScanResult(
            ip_address=ip,
            mac_address=mac,
            port=port,
            protocol="TCP",
            state="OPEN",
            service_name=port_info[0],
            service_version=version,
            banner=f"{port_info[1]} ready" if version else "",
            risk_level=classify_port_risk(port, port_info[0]),
        ))

    return results


# ---------------------------------------------------------------------------
# Scan state tracking
# ---------------------------------------------------------------------------

_scan_results_cache: dict[str, list[PortScanResult]] = {}
_scan_in_progress: set[str] = set()


async def get_device_ports(ip: str, mac: str = "") -> list[PortScanResult]:
    """Get cached port scan results for a device, or trigger a new scan."""
    if ip in _scan_results_cache:
        return _scan_results_cache[ip]

    if ip in _scan_in_progress:
        return []

    _scan_in_progress.add(ip)
    try:
        results = await scan_device_ports(ip, mac)
        _scan_results_cache[ip] = results
        return results
    finally:
        _scan_in_progress.discard(ip)


def get_cached_ports(ip: str) -> list[PortScanResult]:
    """Return cached port scan results without triggering a scan."""
    return list(_scan_results_cache.get(ip, []))


def get_all_cached_ports() -> dict[str, list[dict]]:
    """Return all cached port scan results."""
    return {
        ip: [p.to_dict() for p in ports]
        for ip, ports in _scan_results_cache.items()
    }


def clear_port_cache(ip: str | None = None) -> None:
    """Clear port scan cache for a specific IP or all IPs."""
    if ip:
        _scan_results_cache.pop(ip, None)
    else:
        _scan_results_cache.clear()
