"""
SQLAlchemy ORM models for DDoS Shield.

Tables:
  - devices:          Every MAC address seen on the network.
  - attack_logs:      Historical record of every detected attack.
  - blocked_macs:     Currently blocked MAC addresses.
  - managed_devices:  User-managed devices with protection toggle.
  - protection_logs:  Log of protection events (attacks blocked per device).
  - device_ports:     Open ports discovered on devices.
  - device_services:  Services running on discovered ports.
  - bandwidth_logs:   Per-device bandwidth usage over time.
  - alerts:           Smart alert system entries.
  - health_checks:    Network health monitoring records.
  - connection_logs:  Who-talks-to-whom connection tracking.
  - dns_queries:      DNS query logging per device.

Educational note:
  Each model maps to a SQLite table.  SQLAlchemy lets us interact with
  the database using Python objects instead of raw SQL, reducing the
  risk of SQL-injection vulnerabilities.
"""

from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import DateTime, Enum, Float, Integer, String, Text, Boolean, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all models."""


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AttackType(str, PyEnum):
    """
    Known DDoS / network attack categories.

    SYN_FLOOD  – Exploits TCP handshake by sending SYN packets without
                 completing the 3-way handshake, exhausting server resources.
    UDP_FLOOD  – Overwhelms a target with UDP datagrams on random ports,
                 forcing the target to reply with ICMP "port unreachable".
    ICMP_FLOOD – Sends massive ICMP Echo Requests (ping flood), consuming
                 bandwidth and CPU on the target.
    HTTP_FLOOD – Layer-7 attack that sends legitimate-looking HTTP requests
                 at a rate the web server cannot sustain.
    ARP_SPOOF  – Sends forged ARP replies to associate the attacker's MAC
                 with a legitimate IP, enabling man-in-the-middle attacks.
    PORT_SCAN  – One device scanning many ports on another device.
    DNS_TUNNEL – Unusually long or frequent DNS queries indicating data
                 exfiltration via DNS tunneling.
    DHCP_STARVE – Flooding DHCP requests to exhaust available IP leases.
    MAC_FLOOD  – Flooding switch CAM table with fake MAC addresses.
    LATERAL_MOVE – Device suddenly communicating with many internal hosts.
    ROGUE_DEVICE – Unknown/unauthorized device detected on the network.
    """
    SYN_FLOOD = "SYN_FLOOD"
    UDP_FLOOD = "UDP_FLOOD"
    ICMP_FLOOD = "ICMP_FLOOD"
    HTTP_FLOOD = "HTTP_FLOOD"
    ARP_SPOOF = "ARP_SPOOF"
    PORT_SCAN = "PORT_SCAN"
    DNS_TUNNEL = "DNS_TUNNEL"
    DHCP_STARVE = "DHCP_STARVE"
    MAC_FLOOD = "MAC_FLOOD"
    LATERAL_MOVE = "LATERAL_MOVE"
    ROGUE_DEVICE = "ROGUE_DEVICE"


class Severity(str, PyEnum):
    """Alert severity levels following standard SOC conventions."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DeviceStatus(str, PyEnum):
    """Operational status of a network device (by MAC)."""
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    BLOCKED = "BLOCKED"


class DeviceType(str, PyEnum):
    """Classification of managed network devices."""
    SERVER = "server"
    CLIENT = "client"
    ROUTER = "router"
    SWITCH = "switch"
    ACCESS_POINT = "access_point"
    PHONE = "phone"
    IOT = "iot"
    PRINTER = "printer"
    CAMERA = "camera"
    NAS = "nas"
    SMART_TV = "smart_tv"
    UNKNOWN = "unknown"


class AlertCategory(str, PyEnum):
    """Categories for the smart alert system."""
    SECURITY = "SECURITY"
    PERFORMANCE = "PERFORMANCE"
    NETWORK_CHANGE = "NETWORK_CHANGE"
    DEVICE_STATUS = "DEVICE_STATUS"


class AlertStatus(str, PyEnum):
    """Alert lifecycle status."""
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class PortProtocol(str, PyEnum):
    """Transport protocol for a discovered port."""
    TCP = "TCP"
    UDP = "UDP"


class PortState(str, PyEnum):
    """State of a scanned port."""
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

class Device(Base):
    """
    Represents a network device identified by MAC address.

    Educational note:
      We track devices by MAC rather than IP because MACs are (in theory)
      hardware-burned identifiers, whereas IPs can change via DHCP.
      In practice, MACs *can* be spoofed — that's exactly what ARP-spoof
      detection catches.
    """

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mac_address: Mapped[str] = mapped_column(String(17), unique=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), default="")
    vendor: Mapped[str] = mapped_column(String(128), default="Unknown")
    first_seen: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    total_packets: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[DeviceStatus] = mapped_column(
        Enum(DeviceStatus), default=DeviceStatus.NORMAL
    )
    is_vm: Mapped[bool] = mapped_column(Boolean, default=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "vendor": self.vendor,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "status": self.status.value,
            "is_vm": self.is_vm,
        }


class AttackLog(Base):
    """
    Immutable log entry for a detected attack event.

    Educational note:
      Attack logs are append-only — we never update or delete them so
      students can review the full history of every incident.
    """

    __tablename__ = "attack_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )
    mac_address: Mapped[str] = mapped_column(String(17), index=True)
    attack_type: Mapped[AttackType] = mapped_column(Enum(AttackType))
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    packets_per_second: Mapped[float] = mapped_column(Float, default=0.0)
    description: Mapped[str] = mapped_column(Text, default="")
    mitigated: Mapped[bool] = mapped_column(Boolean, default=False)
    z_score: Mapped[float] = mapped_column(Float, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "mac_address": self.mac_address,
            "attack_type": self.attack_type.value,
            "severity": self.severity.value,
            "packets_per_second": self.packets_per_second,
            "description": self.description,
            "mitigated": self.mitigated,
            "z_score": self.z_score,
        }


class BlockedMAC(Base):
    """
    Currently blocked MAC addresses.

    Educational note:
      Blocking at Layer 2 (MAC) is more robust than Layer 3 (IP) because
      an attacker can easily change their IP but changing a NIC's MAC
      requires more effort.  We use ebtables (Ethernet bridge tables)
      on Linux to enforce the block.
    """

    __tablename__ = "blocked_macs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mac_address: Mapped[str] = mapped_column(String(17), unique=True, index=True)
    blocked_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "mac_address": self.mac_address,
            "blocked_at": self.blocked_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "reason": self.reason,
        }


class ManagedDevice(Base):
    """
    A user-managed network device with optional protection mode.

    Devices can be discovered via ARP scan or added manually.
    When is_protected is True, the protection engine monitors all
    inbound traffic and auto-blocks attackers targeting this device.
    """

    __tablename__ = "managed_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    mac_address: Mapped[str] = mapped_column(String(17), unique=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), default="")
    device_type: Mapped[DeviceType] = mapped_column(
        Enum(DeviceType), default=DeviceType.UNKNOWN
    )
    hostname: Mapped[str] = mapped_column(String(256), default="")
    os_info: Mapped[str] = mapped_column(String(256), default="")
    is_protected: Mapped[bool] = mapped_column(Boolean, default=False)
    is_online: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    notes: Mapped[str] = mapped_column(Text, default="")
    attacks_blocked: Mapped[int] = mapped_column(Integer, default=0)
    uptime_checks: Mapped[int] = mapped_column(Integer, default=0)
    uptime_successes: Mapped[int] = mapped_column(Integer, default=0)
    last_attack_time: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    # New fields for enhanced discovery
    security_score: Mapped[int] = mapped_column(Integer, default=100)
    open_ports_count: Mapped[int] = mapped_column(Integer, default=0)
    is_whitelisted: Mapped[bool] = mapped_column(Boolean, default=False)

    def to_dict(self) -> dict:
        uptime_pct = (
            round(self.uptime_successes / self.uptime_checks * 100, 1)
            if self.uptime_checks > 0
            else 100.0
        )
        return {
            "id": self.id,
            "name": self.name,
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "device_type": self.device_type.value,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "is_protected": self.is_protected,
            "is_online": self.is_online,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "notes": self.notes,
            "attacks_blocked": self.attacks_blocked,
            "uptime_percent": uptime_pct,
            "last_attack_time": (
                self.last_attack_time.isoformat() if self.last_attack_time else None
            ),
            "security_score": self.security_score,
            "open_ports_count": self.open_ports_count,
            "is_whitelisted": self.is_whitelisted,
        }


class ProtectionLog(Base):
    """
    Log entry for a protection event — records each time the protection
    engine blocks an attacker targeting a protected device.
    """

    __tablename__ = "protection_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(Integer, ForeignKey("managed_devices.id"), index=True)
    attacker_mac: Mapped[str] = mapped_column(String(17), default="")
    attacker_ip: Mapped[str] = mapped_column(String(45), default="")
    attack_type: Mapped[str] = mapped_column(String(32), default="")
    action_taken: Mapped[str] = mapped_column(String(64), default="blocked")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "attacker_mac": self.attacker_mac,
            "attacker_ip": self.attacker_ip,
            "attack_type": self.attack_type,
            "action_taken": self.action_taken,
            "timestamp": self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# New tables for enhanced features
# ---------------------------------------------------------------------------

class DevicePort(Base):
    """
    Records an open port discovered on a device via port scanning.

    Educational note:
      Port scanning reveals which services a device is running.
      Open ports are potential attack surfaces — each open port is
      a door that an attacker might try to exploit.
    """

    __tablename__ = "device_ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mac_address: Mapped[str] = mapped_column(String(17), index=True)
    ip_address: Mapped[str] = mapped_column(String(45), default="")
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[PortProtocol] = mapped_column(Enum(PortProtocol), default=PortProtocol.TCP)
    state: Mapped[PortState] = mapped_column(Enum(PortState), default=PortState.OPEN)
    service_name: Mapped[str] = mapped_column(String(64), default="")
    service_version: Mapped[str] = mapped_column(String(128), default="")
    banner: Mapped[str] = mapped_column(Text, default="")
    risk_level: Mapped[str] = mapped_column(String(16), default="LOW")
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "port": self.port,
            "protocol": self.protocol.value,
            "state": self.state.value,
            "service_name": self.service_name,
            "service_version": self.service_version,
            "banner": self.banner,
            "risk_level": self.risk_level,
            "discovered_at": self.discovered_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


class BandwidthLog(Base):
    """
    Per-device bandwidth usage snapshot taken at regular intervals.

    Educational note:
      Tracking bandwidth per device helps identify "top talkers" —
      devices consuming the most network resources — and detect
      unusual data transfers that might indicate exfiltration.
    """

    __tablename__ = "bandwidth_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mac_address: Mapped[str] = mapped_column(String(17), index=True)
    ip_address: Mapped[str] = mapped_column(String(45), default="")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    bytes_received: Mapped[int] = mapped_column(Integer, default=0)
    packets_sent: Mapped[int] = mapped_column(Integer, default=0)
    packets_received: Mapped[int] = mapped_column(Integer, default=0)
    # Protocol distribution (bytes per protocol)
    http_bytes: Mapped[int] = mapped_column(Integer, default=0)
    https_bytes: Mapped[int] = mapped_column(Integer, default=0)
    dns_bytes: Mapped[int] = mapped_column(Integer, default=0)
    ssh_bytes: Mapped[int] = mapped_column(Integer, default=0)
    other_bytes: Mapped[int] = mapped_column(Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat(),
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "http_bytes": self.http_bytes,
            "https_bytes": self.https_bytes,
            "dns_bytes": self.dns_bytes,
            "ssh_bytes": self.ssh_bytes,
            "other_bytes": self.other_bytes,
        }


class ConnectionLog(Base):
    """
    Tracks source→destination communication pairs for connection analysis.

    Educational note:
      Connection tracking reveals which devices communicate with each
      other and how much data they exchange. This is essential for
      detecting lateral movement and data exfiltration.
    """

    __tablename__ = "connection_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    src_mac: Mapped[str] = mapped_column(String(17), index=True)
    src_ip: Mapped[str] = mapped_column(String(45), default="")
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(8), default="TCP")
    bytes_transferred: Mapped[int] = mapped_column(Integer, default=0)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "src_mac": self.src_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "bytes_transferred": self.bytes_transferred,
            "packet_count": self.packet_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


class DNSQueryLog(Base):
    """
    Logs DNS queries made by devices on the network.

    Educational note:
      DNS query logging reveals what domains devices are resolving.
      Unusually long domain names or high query rates can indicate
      DNS tunneling — a technique for exfiltrating data through DNS.
    """

    __tablename__ = "dns_queries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mac_address: Mapped[str] = mapped_column(String(17), index=True)
    ip_address: Mapped[str] = mapped_column(String(45), default="")
    domain: Mapped[str] = mapped_column(String(512), default="")
    query_type: Mapped[str] = mapped_column(String(8), default="A")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "domain": self.domain,
            "query_type": self.query_type,
            "timestamp": self.timestamp.isoformat(),
        }


class Alert(Base):
    """
    Smart alert with categories, severity, and acknowledgment workflow.

    Educational note:
      A well-designed alert system categorizes events by type and
      severity, allowing SOC analysts to prioritize their response.
      The acknowledge/resolve workflow prevents alert fatigue by
      letting analysts track which issues have been addressed.
    """

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )
    category: Mapped[AlertCategory] = mapped_column(Enum(AlertCategory))
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    title: Mapped[str] = mapped_column(String(256), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    source_mac: Mapped[str] = mapped_column(String(17), default="", index=True)
    source_ip: Mapped[str] = mapped_column(String(45), default="")
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus), default=AlertStatus.ACTIVE
    )
    resolved_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source_mac": self.source_mac,
            "source_ip": self.source_ip,
            "status": self.status.value,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "metadata_json": self.metadata_json,
        }


class HealthCheck(Base):
    """
    Network health monitoring records — gateway, DNS, and internet checks.

    Educational note:
      Regular health checks ensure the network infrastructure is
      functioning properly. Monitoring latency, packet loss, and
      connectivity helps detect issues before they affect users.
    """

    __tablename__ = "health_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )
    check_type: Mapped[str] = mapped_column(String(32), default="")
    target: Mapped[str] = mapped_column(String(128), default="")
    is_up: Mapped[bool] = mapped_column(Boolean, default=True)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    packet_loss_pct: Mapped[float] = mapped_column(Float, default=0.0)
    details: Mapped[str] = mapped_column(Text, default="")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "check_type": self.check_type,
            "target": self.target,
            "is_up": self.is_up,
            "latency_ms": self.latency_ms,
            "packet_loss_pct": self.packet_loss_pct,
            "details": self.details,
        }
