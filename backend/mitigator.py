"""
Auto-mitigation / rescue actions for detected attacks.

Educational note:
  Mitigation happens at Layer 2 using **ebtables** (Ethernet Bridge Tables)
  on Linux.  ebtables is the Ethernet equivalent of iptables — it filters
  frames by MAC address before they even reach the IP stack.

  Available actions:
  - **Block MAC**     — Drop all frames from the attacking MAC.
  - **Rate limit**    — Cap the attacker's throughput (uses iptables mark + tc).
  - **Isolate**       — Move the MAC to a quarantine VLAN (requires switch API).
  - **Unblock MAC**   — Remove a previous block.

  In simulation mode, commands are logged but NOT executed so students
  can safely experiment.

Security note:
  All shell commands use explicit arguments (never string interpolation)
  to prevent command injection.  MAC addresses are validated before use.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from datetime import datetime, timedelta, timezone

from config import config
from models import AttackType

logger = logging.getLogger("ddos_shield.mitigator")

# MAC address validation regex
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _validate_mac(mac: str) -> str:
    """Validate and normalise a MAC address. Raises ValueError if invalid."""
    mac = mac.strip().upper()
    if not _MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC address: {mac}")
    return mac


async def _run_command(args: list[str]) -> tuple[bool, str]:
    """
    Execute a system command asynchronously.

    In simulation mode, logs the command without executing it.
    Returns (success: bool, output: str).
    """
    if config.simulation.enabled:
        cmd_str = " ".join(args)
        logger.info("[SIMULATION] Would execute: %s", cmd_str)
        return True, f"[SIMULATION] {cmd_str}"

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        output = (stdout or b"").decode() + (stderr or b"").decode()
        success = proc.returncode == 0
        if not success:
            logger.warning("Command failed: %s → %s", args, output.strip())
        return success, output
    except FileNotFoundError:
        msg = f"Command not found: {args[0]}"
        logger.error(msg)
        return False, msg
    except Exception as exc:
        logger.error("Command error: %s", exc)
        return False, str(exc)


async def block_mac(mac: str, reason: str = "") -> dict:
    """
    Block all traffic from a MAC address using ebtables.

    Educational note:
      `ebtables -A INPUT -s <MAC> -j DROP` adds a rule to the INPUT
      chain that drops any Ethernet frame whose source MAC matches.
    """
    mac = _validate_mac(mac)

    # Try ebtables first (Layer 2), fall back to iptables (Layer 3)
    if shutil.which("ebtables"):
        success, output = await _run_command(
            ["ebtables", "-A", "INPUT", "-s", mac, "-j", "DROP"]
        )
    else:
        # iptables MAC match module as fallback
        success, output = await _run_command(
            ["iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"]
        )

    return {
        "action": "block",
        "mac_address": mac,
        "success": success,
        "output": output.strip(),
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def unblock_mac(mac: str) -> dict:
    """
    Remove the block rule for a MAC address.

    Educational note:
      `-D` (delete) mirrors the `-A` (append) rule exactly — ebtables
      matches on the full rule specification to find and remove it.
    """
    mac = _validate_mac(mac)

    if shutil.which("ebtables"):
        success, output = await _run_command(
            ["ebtables", "-D", "INPUT", "-s", mac, "-j", "DROP"]
        )
    else:
        success, output = await _run_command(
            ["iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"]
        )

    return {
        "action": "unblock",
        "mac_address": mac,
        "success": success,
        "output": output.strip(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def rate_limit_mac(mac: str, limit_pps: int | None = None) -> dict:
    """
    Apply rate limiting to a MAC address using iptables hashlimit.

    Educational note:
      `hashlimit` is an iptables module that tracks packet rates per
      source.  Packets exceeding the limit are dropped, while normal
      traffic flows through — a softer response than a full block.
    """
    mac = _validate_mac(mac)
    pps = limit_pps or config.mitigation.rate_limit_pps

    success, output = await _run_command([
        "iptables", "-A", "INPUT",
        "-m", "mac", "--mac-source", mac,
        "-m", "hashlimit",
        "--hashlimit-above", f"{pps}/sec",
        "--hashlimit-mode", "srcmac",
        "--hashlimit-name", f"ratelimit_{mac.replace(':', '')}",
        "-j", "DROP",
    ])

    return {
        "action": "rate_limit",
        "mac_address": mac,
        "limit_pps": pps,
        "success": success,
        "output": output.strip(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def isolate_mac(mac: str) -> dict:
    """
    Isolate a MAC by blocking both inbound and outbound traffic.

    Educational note:
      Full isolation prevents the device from communicating with ANY
      other device on the network.  This is the nuclear option —
      useful when a device is confirmed compromised.
    """
    mac = _validate_mac(mac)
    results: list[dict] = []

    for chain in ("INPUT", "OUTPUT", "FORWARD"):
        if shutil.which("ebtables"):
            success, output = await _run_command(
                ["ebtables", "-A", chain, "-s", mac, "-j", "DROP"]
            )
        else:
            success, output = await _run_command(
                ["iptables", "-A", chain, "-m", "mac", "--mac-source", mac, "-j", "DROP"]
            )
        results.append({"chain": chain, "success": success, "output": output.strip()})

    return {
        "action": "isolate",
        "mac_address": mac,
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def get_block_expiry() -> datetime | None:
    """Calculate block expiry time, or None for permanent blocks."""
    duration = config.mitigation.block_duration_seconds
    if duration <= 0:
        return None
    return datetime.now(timezone.utc) + timedelta(seconds=duration)


def suggested_action(attack_type: AttackType, pps: float) -> str:
    """
    Suggest a mitigation action based on attack type and severity.

    Educational note:
      Not all attacks warrant the same response.  ARP spoofing should
      be blocked immediately (it's a targeted attack), while a moderate
      UDP flood might only need rate limiting.
    """
    if attack_type == AttackType.ARP_SPOOF:
        return "isolate"  # ARP spoof is always serious
    if pps > 1000:
        return "block"
    if pps > 200:
        return "rate_limit"
    return "monitor"  # Low severity — just watch
