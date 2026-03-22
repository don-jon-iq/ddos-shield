"""
Smart alert system for DDoS Shield.

Educational note:
  A well-designed alert system is the backbone of any Security Operations
  Center (SOC). Alerts must be:
  - Categorized: Security vs Performance vs Network Change vs Device Status
  - Prioritized: Critical alerts need immediate attention; Info is FYI
  - Actionable: Each alert should tell the operator what to do
  - Manageable: Acknowledge/resolve workflow prevents alert fatigue

  This engine generates alerts from various detection subsystems and
  provides a unified interface for querying and managing them.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Sequence

from config import config
from models import (
    Alert, AlertCategory, AlertStatus, Severity,
    AttackType,
)

logger = logging.getLogger("ddos_shield.alert_engine")


# ---------------------------------------------------------------------------
# In-memory alert buffer (supplementing DB for real-time access)
# ---------------------------------------------------------------------------

_recent_alerts: list[dict] = []
_MAX_RECENT = 500

# Track known MACs for rogue device detection
_known_macs: set[str] = set()
_whitelisted_macs: set[str] = set()


def register_known_mac(mac: str) -> None:
    """Register a MAC address as known (seen before)."""
    _known_macs.add(mac.upper())


def whitelist_mac(mac: str) -> None:
    """Add a MAC to the whitelist (authorized devices)."""
    _whitelisted_macs.add(mac.upper())


def unwhitelist_mac(mac: str) -> None:
    """Remove a MAC from the whitelist."""
    _whitelisted_macs.discard(mac.upper())


def is_known_mac(mac: str) -> bool:
    """Check if a MAC has been seen before."""
    return mac.upper() in _known_macs


def is_whitelisted_mac(mac: str) -> bool:
    """Check if a MAC is in the whitelist."""
    return mac.upper() in _whitelisted_macs


# ---------------------------------------------------------------------------
# Alert creation helpers
# ---------------------------------------------------------------------------

def create_alert(
    category: AlertCategory,
    severity: Severity,
    title: str,
    description: str,
    source_mac: str = "",
    source_ip: str = "",
    metadata: dict | None = None,
) -> dict:
    """
    Create a new alert and add it to the in-memory buffer.

    Returns the alert dict for WebSocket broadcasting.
    """
    alert_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": category.value,
        "severity": severity.value,
        "title": title,
        "description": description,
        "source_mac": source_mac,
        "source_ip": source_ip,
        "status": AlertStatus.ACTIVE.value,
        "metadata_json": json.dumps(metadata or {}),
    }

    _recent_alerts.append(alert_data)
    if len(_recent_alerts) > _MAX_RECENT:
        _recent_alerts.pop(0)

    logger.info(
        "Alert [%s/%s]: %s — %s",
        category.value, severity.value, title, description[:80],
    )

    return alert_data


# ---------------------------------------------------------------------------
# Detection-to-alert converters
# ---------------------------------------------------------------------------

def alert_from_detection(
    mac: str,
    ip: str,
    attack_type: AttackType,
    severity: Severity,
    pps: float,
    description: str,
) -> dict:
    """Convert a detection result into a security alert."""
    return create_alert(
        category=AlertCategory.SECURITY,
        severity=severity,
        title=f"{attack_type.value} detected from {mac}",
        description=description,
        source_mac=mac,
        source_ip=ip,
        metadata={"attack_type": attack_type.value, "pps": pps},
    )


def alert_rogue_device(mac: str, ip: str, hostname: str = "") -> dict | None:
    """
    Generate an alert if a new/unknown device joins the network.

    Educational note:
      Rogue device detection is a first line of defense against
      unauthorized access. Any device not in the whitelist should
      be investigated — it could be an attacker's device or an
      employee's unauthorized personal device.
    """
    if not config.alert_engine.rogue_device_alerts:
        return None

    mac_upper = mac.upper()

    # Skip if already known or whitelisted
    if mac_upper in _known_macs or mac_upper in _whitelisted_macs:
        return None

    # Register as known to avoid repeat alerts
    _known_macs.add(mac_upper)

    device_desc = hostname or ip or "unknown"
    return create_alert(
        category=AlertCategory.NETWORK_CHANGE,
        severity=Severity.MEDIUM,
        title=f"New device detected: {device_desc}",
        description=f"Unknown device {mac} ({device_desc}) joined the network",
        source_mac=mac,
        source_ip=ip,
        metadata={"hostname": hostname, "event": "new_device"},
    )


def alert_device_offline(name: str, mac: str, ip: str) -> dict:
    """Generate an alert when a monitored device goes offline."""
    return create_alert(
        category=AlertCategory.DEVICE_STATUS,
        severity=Severity.HIGH,
        title=f"Device offline: {name}",
        description=f"{name} ({ip}) is no longer responding",
        source_mac=mac,
        source_ip=ip,
        metadata={"event": "device_offline"},
    )


def alert_device_online(name: str, mac: str, ip: str) -> dict:
    """Generate an alert when a monitored device comes back online."""
    return create_alert(
        category=AlertCategory.DEVICE_STATUS,
        severity=Severity.INFO,
        title=f"Device online: {name}",
        description=f"{name} ({ip}) is back online",
        source_mac=mac,
        source_ip=ip,
        metadata={"event": "device_online"},
    )


def alert_arp_spoof(mac: str, ip: str, expected_mac: str) -> dict:
    """Alert when ARP spoofing is detected (MAC-IP binding changed)."""
    return create_alert(
        category=AlertCategory.SECURITY,
        severity=Severity.CRITICAL,
        title=f"ARP spoofing detected for {ip}",
        description=(
            f"IP {ip} was bound to {expected_mac} but is now "
            f"claiming to be {mac} — possible ARP spoofing attack"
        ),
        source_mac=mac,
        source_ip=ip,
        metadata={"event": "arp_spoof", "expected_mac": expected_mac},
    )


def alert_port_scan_detected(src_mac: str, src_ip: str, target_ip: str, port_count: int) -> dict:
    """Alert when port scanning activity is detected."""
    return create_alert(
        category=AlertCategory.SECURITY,
        severity=Severity.HIGH,
        title=f"Port scan detected from {src_ip}",
        description=f"{src_ip} ({src_mac}) scanned {port_count} ports on {target_ip}",
        source_mac=src_mac,
        source_ip=src_ip,
        metadata={"event": "port_scan", "target": target_ip, "ports": port_count},
    )


def alert_lateral_movement(mac: str, ip: str, target_count: int) -> dict:
    """Alert when a device suddenly communicates with many internal hosts."""
    return create_alert(
        category=AlertCategory.SECURITY,
        severity=Severity.HIGH,
        title=f"Lateral movement detected: {ip}",
        description=(
            f"{ip} ({mac}) is communicating with {target_count} "
            f"internal hosts — possible lateral movement"
        ),
        source_mac=mac,
        source_ip=ip,
        metadata={"event": "lateral_movement", "targets": target_count},
    )


def alert_dns_tunneling(mac: str, ip: str, domain: str) -> dict:
    """Alert when DNS tunneling is suspected."""
    return create_alert(
        category=AlertCategory.SECURITY,
        severity=Severity.HIGH,
        title=f"DNS tunneling suspected from {ip}",
        description=f"Unusually long DNS query from {ip}: {domain[:60]}...",
        source_mac=mac,
        source_ip=ip,
        metadata={"event": "dns_tunnel", "domain": domain},
    )


def alert_health_issue(check_type: str, target: str, details: str) -> dict:
    """Alert when a health check fails."""
    return create_alert(
        category=AlertCategory.PERFORMANCE,
        severity=Severity.HIGH,
        title=f"{check_type} health check failed: {target}",
        description=details,
        metadata={"event": "health_failure", "check_type": check_type},
    )


def alert_high_bandwidth(mac: str, ip: str, bps: int) -> dict:
    """Alert when a device exceeds bandwidth threshold."""
    mbps = round(bps / 1_000_000, 1)
    return create_alert(
        category=AlertCategory.PERFORMANCE,
        severity=Severity.MEDIUM,
        title=f"High bandwidth usage: {ip}",
        description=f"{ip} ({mac}) is using {mbps} Mbps",
        source_mac=mac,
        source_ip=ip,
        metadata={"event": "high_bandwidth", "bps": bps},
    )


# ---------------------------------------------------------------------------
# Query interface
# ---------------------------------------------------------------------------

def get_recent_alerts(
    category: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Get recent alerts with optional filtering."""
    result = list(_recent_alerts)

    if category:
        result = [a for a in result if a["category"] == category]
    if severity:
        result = [a for a in result if a["severity"] == severity]
    if status:
        result = [a for a in result if a["status"] == status]

    # Most recent first
    result.reverse()
    return result[:limit]


def get_alert_counts() -> dict:
    """Get counts of active alerts by category and severity."""
    active = [a for a in _recent_alerts if a["status"] == AlertStatus.ACTIVE.value]

    by_category: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    for alert in active:
        by_category[alert["category"]] += 1
        by_severity[alert["severity"]] += 1

    return {
        "total_active": len(active),
        "by_category": dict(by_category),
        "by_severity": dict(by_severity),
    }


def acknowledge_alert_by_index(index: int) -> bool:
    """Acknowledge an alert by its index in the recent buffer."""
    if 0 <= index < len(_recent_alerts):
        _recent_alerts[index]["status"] = AlertStatus.ACKNOWLEDGED.value
        return True
    return False


def resolve_alert_by_index(index: int) -> bool:
    """Resolve an alert by its index in the recent buffer."""
    if 0 <= index < len(_recent_alerts):
        _recent_alerts[index]["status"] = AlertStatus.RESOLVED.value
        _recent_alerts[index]["resolved_at"] = datetime.now(timezone.utc).isoformat()
        return True
    return False
