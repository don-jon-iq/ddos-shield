"""
Device management — CRUD operations for managed devices.

Handles adding, editing, deleting, and toggling protection on
network devices. Devices can be discovered via ARP scan or added
manually by the user.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import DeviceType, ManagedDevice

logger = logging.getLogger("ddos_shield.device_manager")


async def list_managed_devices(session: AsyncSession) -> list[dict]:
    """Return all managed devices ordered by last_seen."""
    result = await session.execute(
        select(ManagedDevice).order_by(ManagedDevice.last_seen.desc())
    )
    return [d.to_dict() for d in result.scalars().all()]


async def get_managed_device(device_id: int, session: AsyncSession) -> dict | None:
    """Get a single managed device by ID."""
    result = await session.execute(
        select(ManagedDevice).where(ManagedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()
    return device.to_dict() if device else None


async def add_device(
    session: AsyncSession,
    name: str,
    mac_address: str,
    ip_address: str = "",
    device_type: str = "unknown",
    hostname: str = "",
    os_info: str = "",
    notes: str = "",
) -> dict:
    """
    Add a new managed device (manually or from scan import).

    If a device with the same MAC already exists, updates it instead.
    """
    mac = mac_address.strip().upper()
    now = datetime.now(timezone.utc)

    result = await session.execute(
        select(ManagedDevice).where(ManagedDevice.mac_address == mac)
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.name = name or existing.name
        existing.ip_address = ip_address or existing.ip_address
        existing.device_type = DeviceType(device_type)
        existing.hostname = hostname or existing.hostname
        existing.os_info = os_info or existing.os_info
        existing.notes = notes or existing.notes
        existing.last_seen = now
        existing.is_online = True
        await session.commit()
        logger.info("Updated existing device: %s (%s)", mac, name)
        return existing.to_dict()

    device = ManagedDevice(
        name=name,
        mac_address=mac,
        ip_address=ip_address,
        device_type=DeviceType(device_type),
        hostname=hostname,
        os_info=os_info,
        is_protected=False,
        is_online=True,
        first_seen=now,
        last_seen=now,
        notes=notes,
        attacks_blocked=0,
        uptime_checks=0,
        uptime_successes=0,
    )
    session.add(device)
    await session.commit()
    logger.info("Added new device: %s (%s)", mac, name)
    return device.to_dict()


async def update_device(
    device_id: int,
    session: AsyncSession,
    name: str | None = None,
    ip_address: str | None = None,
    device_type: str | None = None,
    hostname: str | None = None,
    os_info: str | None = None,
    notes: str | None = None,
) -> dict | None:
    """Update fields on an existing managed device."""
    result = await session.execute(
        select(ManagedDevice).where(ManagedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()
    if device is None:
        return None

    if name is not None:
        device.name = name
    if ip_address is not None:
        device.ip_address = ip_address
    if device_type is not None:
        device.device_type = DeviceType(device_type)
    if hostname is not None:
        device.hostname = hostname
    if os_info is not None:
        device.os_info = os_info
    if notes is not None:
        device.notes = notes

    device.last_seen = datetime.now(timezone.utc)
    await session.commit()
    logger.info("Updated device id=%d: %s", device_id, device.name)
    return device.to_dict()


async def delete_device(device_id: int, session: AsyncSession) -> bool:
    """Delete a managed device. Returns True if deleted."""
    result = await session.execute(
        select(ManagedDevice).where(ManagedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()
    if device is None:
        return False

    await session.delete(device)
    await session.commit()
    logger.info("Deleted device id=%d: %s", device_id, device.mac_address)
    return True


async def toggle_protection(
    device_id: int, session: AsyncSession
) -> dict | None:
    """Toggle protection mode for a device. Returns updated device dict."""
    result = await session.execute(
        select(ManagedDevice).where(ManagedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()
    if device is None:
        return None

    device.is_protected = not device.is_protected
    device.last_seen = datetime.now(timezone.utc)
    await session.commit()

    status = "ENABLED" if device.is_protected else "DISABLED"
    logger.info("Protection %s for device %s (%s)", status, device.name, device.mac_address)
    return device.to_dict()


async def get_protected_devices(session: AsyncSession) -> list[ManagedDevice]:
    """Return all devices with protection enabled (as ORM objects)."""
    result = await session.execute(
        select(ManagedDevice).where(ManagedDevice.is_protected == True)  # noqa: E712
    )
    return list(result.scalars().all())


async def record_uptime_check(
    device_id: int, is_online: bool, session: AsyncSession
) -> None:
    """Record an uptime check result for a protected device."""
    result = await session.execute(
        select(ManagedDevice).where(ManagedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()
    if device is None:
        return

    device.uptime_checks += 1
    if is_online:
        device.uptime_successes += 1
    device.is_online = is_online
    device.last_seen = datetime.now(timezone.utc)
    await session.commit()
