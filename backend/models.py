"""
SQLAlchemy ORM models for DDoS Shield.

Tables:
  - devices:          Every MAC address seen on the network.
  - attack_logs:      Historical record of every detected attack.
  - blocked_macs:     Currently blocked MAC addresses.
  - managed_devices:  User-managed devices with protection toggle.
  - protection_logs:  Log of protection events (attacks blocked per device).

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
    """
    SYN_FLOOD = "SYN_FLOOD"
    UDP_FLOOD = "UDP_FLOOD"
    ICMP_FLOOD = "ICMP_FLOOD"
    HTTP_FLOOD = "HTTP_FLOOD"
    ARP_SPOOF = "ARP_SPOOF"


class Severity(str, PyEnum):
    """Alert severity levels following standard SOC conventions."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


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
    UNKNOWN = "unknown"


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
