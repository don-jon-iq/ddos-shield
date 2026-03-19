"""
Settings API for DDoS Shield.

Provides endpoints to read, update, and reset all configuration
from the dashboard UI. Changes persist to the .env file AND
update the running config in memory.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from auth import get_current_user
from config import DEFAULTS, config, reset_to_defaults, write_env
from vm_monitor import detect_interfaces

logger = logging.getLogger("ddos_shield.settings")

router = APIRouter(prefix="/api/settings", tags=["Settings"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class SettingsUpdate(BaseModel):
    """Partial settings update — only include fields you want to change."""

    # Simulation
    SIMULATION_MODE: bool | None = None
    SIM_DEVICE_COUNT: int | None = None
    SIM_ATTACK_PROB: float | None = None
    SIM_TICK_INTERVAL: float | None = None
    # Sniffer
    SNIFFER_INTERFACE: str | None = None
    SNIFFER_BPF_FILTER: str | None = None
    SNIFFER_WINDOW_SECONDS: int | None = None
    SNIFFER_MAX_BUFFER: int | None = None
    # Detection
    THRESH_SYN_PPS: int | None = None
    THRESH_UDP_PPS: int | None = None
    THRESH_ICMP_PPS: int | None = None
    THRESH_HTTP_PPS: int | None = None
    THRESH_ARP_PPS: int | None = None
    ZSCORE_THRESHOLD: float | None = None
    ZSCORE_MIN_SAMPLES: int | None = None
    # Mitigation
    AUTO_BLOCK: bool | None = None
    RATE_LIMIT_PPS: int | None = None
    BLOCK_DURATION: int | None = None
    # Auth
    TOKEN_EXPIRE_MINUTES: int | None = None
    # WebSocket
    WS_INTERVAL: float | None = None
    # Scanner
    SCAN_INTERVAL: int | None = None
    AUTO_SCAN: bool | None = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
async def get_settings(_user: str = Depends(get_current_user)):
    """Return all current settings."""
    return config.to_dict()


@router.put("")
async def update_settings(
    body: SettingsUpdate,
    _user: str = Depends(get_current_user),
):
    """
    Update settings — writes to .env and reloads runtime config.

    Only non-null fields in the request body are updated.
    """
    updates: dict[str, str] = {}

    for field_name, value in body.model_dump(exclude_none=True).items():
        if isinstance(value, bool):
            updates[field_name] = "true" if value else "false"
        else:
            updates[field_name] = str(value)

    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No settings provided",
        )

    write_env(updates)
    config.reload()

    logger.info("Settings updated: %s", list(updates.keys()))
    return {"updated": list(updates.keys()), "settings": config.to_dict()}


@router.get("/interfaces")
async def list_interfaces(_user: str = Depends(get_current_user)):
    """List available network interfaces for the sniffer dropdown."""
    interfaces = detect_interfaces()
    return [
        {
            "name": iface.name,
            "is_virtual": iface.is_virtual,
            "mac_address": iface.mac_address,
            "status": iface.status,
        }
        for iface in interfaces
    ]


@router.post("/reset")
async def reset_settings(_user: str = Depends(get_current_user)):
    """Reset all settings to factory defaults."""
    reset_to_defaults()
    config.reload()
    logger.info("Settings reset to defaults")
    return {"message": "Settings reset to defaults", "settings": config.to_dict()}


@router.get("/defaults")
async def get_defaults(_user: str = Depends(get_current_user)):
    """Return the default values for all settings."""
    return dict(DEFAULTS)


@router.post("/password")
async def change_password(
    body: PasswordChangeRequest,
    _user: str = Depends(get_current_user),
):
    """Change the default password."""
    from auth import verify_password, _hash_password, _default_password_hash
    import auth

    if not verify_password(body.current_password, auth._default_password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    write_env({"DEFAULT_PASS": body.new_password})
    # Update the in-memory hash so future logins work immediately
    auth._default_password_hash = _hash_password(body.new_password)
    config.reload()

    logger.info("Password changed successfully")
    return {"message": "Password changed successfully"}
