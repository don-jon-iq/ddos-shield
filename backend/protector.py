"""
Protection engine — monitors traffic to protected devices and
auto-blocks attackers targeting them.

When a device has protection enabled, this engine:
  1. Monitors all traffic directed AT the protected device
  2. Detects attacks targeting the device (using the same threshold logic)
  3. Auto-blocks the attacker's MAC/IP via pfctl/iptables
  4. Logs the protection event
  5. Broadcasts a WebSocket alert

Educational note:
  This is the core of "active defense" — instead of just detecting
  and alerting, the system automatically takes action to keep the
  protected device online during an attack.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from config import config
from models import AttackType, ManagedDevice, ProtectionLog, Severity
from detector import TrafficSnapshot

logger = logging.getLogger("ddos_shield.protector")


# In-memory tracking of blocked attackers per protected device
_blocked_attackers: dict[int, set[str]] = {}  # device_id -> set of attacker MACs


def _detect_attack_on_target(
    snapshot: TrafficSnapshot, target_ip: str, target_mac: str
) -> tuple[str, float] | None:
    """
    Check if a traffic snapshot represents an attack targeting a specific device.

    Returns (attack_type, pps) if attack detected, else None.
    """
    cfg = config.detection

    # Check each protocol against thresholds
    checks = [
        (snapshot.syn_pps, cfg.syn_flood_pps, "SYN_FLOOD"),
        (snapshot.udp_pps, cfg.udp_flood_pps, "UDP_FLOOD"),
        (snapshot.icmp_pps, cfg.icmp_flood_pps, "ICMP_FLOOD"),
        (snapshot.http_pps, cfg.http_flood_pps, "HTTP_FLOOD"),
        (snapshot.arp_pps, cfg.arp_spoof_pps, "ARP_SPOOF"),
    ]

    for pps, threshold, attack_type in checks:
        if pps > threshold:
            return attack_type, pps

    return None


async def check_protection(
    snapshots: list[TrafficSnapshot],
    protected_devices: list[ManagedDevice],
    dest_map: dict[str, str],
    session,
    ws_manager,
    block_fn,
):
    """
    Main protection check — called every analysis window.

    Args:
        snapshots: Current window traffic snapshots (one per source MAC)
        protected_devices: Devices with protection enabled
        dest_map: Mapping of source MAC -> destination IP for current traffic
        session: Database session
        ws_manager: WebSocket manager for broadcasting alerts
        block_fn: Async function to block an attacker (mac, ip, reason)
    """
    if not protected_devices or not snapshots:
        return

    # Build a set of protected IPs and MACs for fast lookup
    protected_ips = {d.ip_address: d for d in protected_devices if d.ip_address}
    protected_macs = {d.mac_address: d for d in protected_devices if d.mac_address}

    protection_events = []

    for snap in snapshots:
        # Check if this source's traffic is targeting a protected device
        dest_ip = dest_map.get(snap.mac_address, "")

        target_device = protected_ips.get(dest_ip)
        if target_device is None:
            continue

        # Don't flag the device's own traffic
        if snap.mac_address == target_device.mac_address:
            continue

        # Check if this traffic constitutes an attack
        attack_result = _detect_attack_on_target(
            snap, target_device.ip_address, target_device.mac_address
        )
        if attack_result is None:
            continue

        attack_type, pps = attack_result
        attacker_mac = snap.mac_address
        attacker_ip = snap.ip_address

        # Check if already blocked
        device_blocked = _blocked_attackers.get(target_device.id, set())
        if attacker_mac in device_blocked:
            continue

        # AUTO-BLOCK the attacker
        reason = (
            f"Auto-blocked: {attack_type} attack ({pps:.0f} pps) "
            f"targeting protected device '{target_device.name}' ({target_device.ip_address})"
        )

        try:
            await block_fn(attacker_mac, attacker_ip, reason)
        except Exception as exc:
            logger.error("Failed to block attacker %s: %s", attacker_mac, exc)
            continue

        # Track blocked attacker
        if target_device.id not in _blocked_attackers:
            _blocked_attackers[target_device.id] = set()
        _blocked_attackers[target_device.id].add(attacker_mac)

        # Log protection event
        log_entry = ProtectionLog(
            device_id=target_device.id,
            attacker_mac=attacker_mac,
            attacker_ip=attacker_ip,
            attack_type=attack_type,
            action_taken="blocked",
            timestamp=datetime.now(timezone.utc),
        )
        session.add(log_entry)

        # Update device stats
        target_device.attacks_blocked += 1
        target_device.last_attack_time = datetime.now(timezone.utc)

        protection_events.append({
            "device_id": target_device.id,
            "device_name": target_device.name,
            "device_ip": target_device.ip_address,
            "attacker_mac": attacker_mac,
            "attacker_ip": attacker_ip,
            "attack_type": attack_type,
            "pps": round(pps, 1),
            "action": "blocked",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        logger.warning(
            "PROTECTION: Blocked %s (%s) attacking '%s' (%s) — %s at %.0f pps",
            attacker_mac, attacker_ip,
            target_device.name, target_device.ip_address,
            attack_type, pps,
        )

    if protection_events:
        await session.commit()

        # Broadcast protection alerts via WebSocket
        await ws_manager.broadcast({
            "type": "protection_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "events": protection_events,
        })


def get_blocked_attackers() -> dict[int, list[str]]:
    """Return the current set of blocked attackers per device ID."""
    return {
        device_id: sorted(macs)
        for device_id, macs in _blocked_attackers.items()
        if macs
    }


def clear_blocked_attacker(device_id: int, attacker_mac: str) -> bool:
    """Remove an attacker from the blocked set for a device."""
    if device_id in _blocked_attackers:
        _blocked_attackers[device_id].discard(attacker_mac)
        return True
    return False
