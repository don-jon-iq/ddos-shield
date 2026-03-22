"""
Bandwidth tracking and monitoring for DDoS Shield.

Educational note:
  Bandwidth monitoring reveals how network resources are being consumed.
  By tracking per-device upload/download rates and protocol distribution,
  we can identify:
  - "Top talkers" consuming excessive bandwidth
  - Unusual data transfers that might indicate exfiltration
  - Protocol anomalies (e.g., unexpected SSH traffic from an IoT device)

  In simulation mode, we generate realistic bandwidth data that mimics
  typical enterprise network patterns.
"""

from __future__ import annotations

import logging
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from config import config

logger = logging.getLogger("ddos_shield.bandwidth")


# ---------------------------------------------------------------------------
# Per-device bandwidth accumulator
# ---------------------------------------------------------------------------

@dataclass
class DeviceBandwidth:
    """Mutable bandwidth counters for a single device."""
    mac_address: str = ""
    ip_address: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    # Protocol breakdown (bytes)
    http_bytes: int = 0
    https_bytes: int = 0
    dns_bytes: int = 0
    ssh_bytes: int = 0
    other_bytes: int = 0
    # Tracking
    last_update: float = field(default_factory=time.time)

    def reset(self) -> "DeviceBandwidth":
        """Return a new zeroed instance preserving identity fields."""
        return DeviceBandwidth(
            mac_address=self.mac_address,
            ip_address=self.ip_address,
            last_update=time.time(),
        )

    def to_dict(self) -> dict:
        elapsed = max(time.time() - self.last_update, 1.0)
        return {
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bps_sent": round(self.bytes_sent * 8 / elapsed),
            "bps_received": round(self.bytes_received * 8 / elapsed),
            "http_bytes": self.http_bytes,
            "https_bytes": self.https_bytes,
            "dns_bytes": self.dns_bytes,
            "ssh_bytes": self.ssh_bytes,
            "other_bytes": self.other_bytes,
        }


# ---------------------------------------------------------------------------
# Connection tracker
# ---------------------------------------------------------------------------

@dataclass
class ConnectionEntry:
    """Tracks a single source→destination connection pair."""
    src_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = "TCP"
    bytes_transferred: int = 0
    packet_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "src_mac": self.src_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "bytes_transferred": self.bytes_transferred,
            "packet_count": self.packet_count,
            "first_seen": datetime.fromtimestamp(self.first_seen, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen, tz=timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Bandwidth tracker singleton
# ---------------------------------------------------------------------------

class BandwidthTracker:
    """
    Tracks per-device bandwidth usage, protocol distribution,
    and connection pairs.

    Educational note:
      The tracker accumulates data between harvest intervals and
      produces snapshots for logging. This is the same "accumulate
      and harvest" pattern used by the packet sniffer.
    """

    def __init__(self) -> None:
        self._devices: dict[str, DeviceBandwidth] = {}
        self._connections: dict[str, ConnectionEntry] = {}
        self._dns_queries: list[dict] = []
        self._history: list[dict] = []
        self._max_history: int = 1000

    def record_packet(
        self,
        src_mac: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        pkt_len: int,
        is_outbound: bool = True,
    ) -> None:
        """Record a packet for bandwidth and connection tracking."""
        dev = self._devices.setdefault(src_mac, DeviceBandwidth(
            mac_address=src_mac, ip_address=src_ip,
        ))
        if not dev.ip_address and src_ip:
            dev.ip_address = src_ip

        if is_outbound:
            dev.bytes_sent += pkt_len
            dev.packets_sent += 1
        else:
            dev.bytes_received += pkt_len
            dev.packets_received += 1

        # Protocol classification by destination port
        if dst_port == 80:
            dev.http_bytes += pkt_len
        elif dst_port == 443:
            dev.https_bytes += pkt_len
        elif dst_port == 53:
            dev.dns_bytes += pkt_len
        elif dst_port == 22:
            dev.ssh_bytes += pkt_len
        else:
            dev.other_bytes += pkt_len

        # Connection tracking
        conn_key = f"{src_mac}:{src_ip}->{dst_ip}:{dst_port}"
        conn = self._connections.setdefault(conn_key, ConnectionEntry(
            src_mac=src_mac, src_ip=src_ip, dst_ip=dst_ip,
            dst_port=dst_port, protocol=protocol,
        ))
        conn.bytes_transferred += pkt_len
        conn.packet_count += 1
        conn.last_seen = time.time()

    def record_dns_query(self, mac: str, ip: str, domain: str, qtype: str = "A") -> None:
        """Record a DNS query for logging."""
        self._dns_queries.append({
            "mac_address": mac,
            "ip_address": ip,
            "domain": domain,
            "query_type": qtype,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        # Keep only last 500 queries in memory
        if len(self._dns_queries) > 500:
            self._dns_queries = self._dns_queries[-500:]

    def harvest(self) -> dict[str, DeviceBandwidth]:
        """
        Harvest current bandwidth data and reset counters.
        Returns a snapshot of all device bandwidth accumulators.
        """
        snapshot = dict(self._devices)
        # Reset counters but preserve identity
        self._devices = {
            mac: dev.reset() for mac, dev in self._devices.items()
        }

        # Store in history
        for mac, dev in snapshot.items():
            self._history.append({
                "mac_address": dev.mac_address,
                "ip_address": dev.ip_address,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "bytes_sent": dev.bytes_sent,
                "bytes_received": dev.bytes_received,
                "packets_sent": dev.packets_sent,
                "packets_received": dev.packets_received,
            })

        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        return snapshot

    def get_current_usage(self) -> list[dict]:
        """Get current bandwidth usage for all devices (non-destructive)."""
        return [dev.to_dict() for dev in self._devices.values()]

    def get_top_talkers(self, limit: int = 10) -> list[dict]:
        """Get top N devices by total bandwidth usage."""
        devices = sorted(
            self._devices.values(),
            key=lambda d: d.bytes_sent + d.bytes_received,
            reverse=True,
        )
        return [d.to_dict() for d in devices[:limit]]

    def get_connections(self, mac: str | None = None) -> list[dict]:
        """Get active connections, optionally filtered by source MAC."""
        connections = self._connections.values()
        if mac:
            connections = [c for c in connections if c.src_mac == mac]
        return [c.to_dict() for c in sorted(
            connections,
            key=lambda c: c.bytes_transferred,
            reverse=True,
        )]

    def get_dns_queries(self, mac: str | None = None, limit: int = 100) -> list[dict]:
        """Get recent DNS queries, optionally filtered by MAC."""
        queries = self._dns_queries
        if mac:
            queries = [q for q in queries if q["mac_address"] == mac]
        return queries[-limit:]

    def get_protocol_distribution(self, mac: str | None = None) -> dict:
        """Get protocol distribution (aggregate or per-device)."""
        if mac:
            dev = self._devices.get(mac)
            if not dev:
                return {}
            total = dev.http_bytes + dev.https_bytes + dev.dns_bytes + dev.ssh_bytes + dev.other_bytes
            if total == 0:
                return {}
            return {
                "HTTP": dev.http_bytes,
                "HTTPS": dev.https_bytes,
                "DNS": dev.dns_bytes,
                "SSH": dev.ssh_bytes,
                "Other": dev.other_bytes,
            }

        totals = {"HTTP": 0, "HTTPS": 0, "DNS": 0, "SSH": 0, "Other": 0}
        for dev in self._devices.values():
            totals["HTTP"] += dev.http_bytes
            totals["HTTPS"] += dev.https_bytes
            totals["DNS"] += dev.dns_bytes
            totals["SSH"] += dev.ssh_bytes
            totals["Other"] += dev.other_bytes
        return totals

    def get_history(self, mac: str | None = None, limit: int = 100) -> list[dict]:
        """Get bandwidth history, optionally filtered by MAC."""
        history = self._history
        if mac:
            history = [h for h in history if h["mac_address"] == mac]
        return history[-limit:]

    def clear_old_connections(self, max_age_seconds: int = 3600) -> None:
        """Remove connections older than max_age_seconds."""
        cutoff = time.time() - max_age_seconds
        self._connections = {
            key: conn for key, conn in self._connections.items()
            if conn.last_seen > cutoff
        }


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

_SIM_DOMAINS = [
    "google.com", "api.github.com", "cdn.cloudflare.com", "update.microsoft.com",
    "ads.doubleclick.net", "analytics.google.com", "s3.amazonaws.com",
    "registry.npmjs.org", "pypi.org", "hub.docker.com", "slack.com",
    "zoom.us", "teams.microsoft.com", "facebook.com", "twitter.com",
    "reddit.com", "netflix.com", "spotify.com", "icloud.com",
]


def simulate_bandwidth_tick(tracker: BandwidthTracker, device_macs: dict[str, str]) -> None:
    """
    Generate one tick of simulated bandwidth data.

    Educational note:
      Realistic bandwidth simulation mimics typical enterprise patterns:
      - Workstations generate moderate HTTPS traffic (web browsing)
      - Servers generate high HTTP/HTTPS traffic (serving requests)
      - IoT devices generate small bursts of MQTT/HTTP traffic
      - DNS queries are frequent but small
    """
    for mac, ip in device_macs.items():
        last_octet = int(ip.split(".")[-1]) if "." in ip else 10

        # Determine device profile based on IP
        if last_octet < 15:
            # Server-like: high bandwidth
            base_bytes = random.randint(5000, 50000)
            https_ratio = 0.6
            http_ratio = 0.2
        elif last_octet < 20:
            # Router/infrastructure: moderate
            base_bytes = random.randint(2000, 20000)
            https_ratio = 0.1
            http_ratio = 0.1
        else:
            # Workstation/IoT: variable
            base_bytes = random.randint(500, 15000)
            https_ratio = 0.5
            http_ratio = 0.1

        # Simulate outbound traffic
        common_ports = [80, 443, 53, 22, 8080, 3306]
        for _ in range(random.randint(1, 5)):
            dst_port = random.choice(common_ports)
            pkt_len = random.randint(64, 1500)
            dst_ip = f"10.0.{random.randint(0,10)}.{random.randint(1,254)}"
            tracker.record_packet(
                src_mac=mac, src_ip=ip, dst_ip=dst_ip,
                dst_port=dst_port, protocol="TCP",
                pkt_len=pkt_len, is_outbound=True,
            )

        # Simulate inbound traffic
        for _ in range(random.randint(1, 3)):
            pkt_len = random.randint(64, 1500)
            tracker.record_packet(
                src_mac=mac, src_ip=ip, dst_ip=ip,
                dst_port=random.choice([80, 443]),
                protocol="TCP", pkt_len=pkt_len, is_outbound=False,
            )

        # Occasional DNS query
        if random.random() < 0.3:
            domain = random.choice(_SIM_DOMAINS)
            tracker.record_dns_query(mac, ip, domain)


# Singleton
bandwidth_tracker = BandwidthTracker()
