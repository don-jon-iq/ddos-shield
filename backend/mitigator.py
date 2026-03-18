"""
Auto-mitigation / rescue actions for detected attacks.

Educational note:
  Mitigation uses platform-specific firewalls:

  **macOS:** `pfctl` (Packet Filter) — the built-in macOS firewall.
    We maintain a pf table called "ddos_blocked" and add/remove IPs
    dynamically.  A pf anchor "ddos_shield" holds the blocking rules.

  **Linux:** `ebtables` (Layer 2) / `iptables` (Layer 3).
    ebtables filters frames by MAC address before they reach the IP stack.
    iptables provides Layer 3 blocking and rate limiting.

  Available actions:
  - **Block IP/MAC**  — Drop all traffic from the attacking source.
  - **Rate limit**    — Cap the attacker's throughput.
  - **Isolate**       — Full bidirectional block (quarantine).
  - **Unblock**       — Remove a previous block.
  - **Rescue**        — One-click emergency block (MAC + IP).

  In simulation mode, commands are logged but NOT executed so students
  can safely experiment.

Security note:
  All shell commands use explicit arguments (never string interpolation)
  to prevent command injection.  MAC/IP addresses are validated before use.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import re
import shutil
from datetime import datetime, timedelta, timezone

from config import config
from models import AttackType

logger = logging.getLogger("ddos_shield.mitigator")

# Validation regexes
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Track which IPs/MACs we've blocked (in-memory for pf table management)
_blocked_ips: set[str] = set()
_blocked_macs: set[str] = set()


def _validate_mac(mac: str) -> str:
    """Validate and normalise a MAC address. Raises ValueError if invalid."""
    mac = mac.strip().upper()
    if not _MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC address: {mac}")
    return mac


def _validate_ip(ip: str) -> str:
    """Validate an IPv4 address. Raises ValueError if invalid."""
    ip = ip.strip()
    if not _IP_RE.match(ip):
        raise ValueError(f"Invalid IP address: {ip}")
    return ip


def _is_macos() -> bool:
    """Check if running on macOS."""
    return platform.system() == "Darwin"


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


# ---------------------------------------------------------------------------
# macOS pfctl helpers
# ---------------------------------------------------------------------------

_PF_ANCHOR = "ddos_shield"
_PF_TABLE = "ddos_blocked"
_pf_initialized = False


async def _ensure_pf_anchor() -> bool:
    """
    Ensure the pf anchor and table exist for DDoS Shield.

    Creates a pf anchor with a persistent table that blocks traffic
    from listed IPs. This is idempotent — safe to call multiple times.
    """
    global _pf_initialized
    if _pf_initialized or config.simulation.enabled:
        _pf_initialized = True
        return True

    # Create anchor rules: block from table
    anchor_rules = (
        f'table <{_PF_TABLE}> persist\n'
        f'block drop in quick from <{_PF_TABLE}>\n'
        f'block drop out quick to <{_PF_TABLE}>\n'
    )

    # Load the anchor rules via stdin
    try:
        proc = await asyncio.create_subprocess_exec(
            "pfctl", "-a", _PF_ANCHOR, "-f", "-",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate(input=anchor_rules.encode())
        if proc.returncode != 0:
            logger.warning("pfctl anchor setup: %s", (stderr or b"").decode().strip())

        # Enable pf if not already enabled
        await _run_command(["pfctl", "-e"])

        _pf_initialized = True
        logger.info("pf anchor '%s' initialized", _PF_ANCHOR)
        return True
    except Exception as exc:
        logger.error("Failed to initialize pf anchor: %s", exc)
        return False


async def _pf_block_ip(ip: str) -> tuple[bool, str]:
    """Add an IP to the pf blocked table."""
    await _ensure_pf_anchor()
    success, output = await _run_command([
        "pfctl", "-a", _PF_ANCHOR, "-t", _PF_TABLE, "-T", "add", ip,
    ])
    if success:
        _blocked_ips.add(ip)
    return success, output


async def _pf_unblock_ip(ip: str) -> tuple[bool, str]:
    """Remove an IP from the pf blocked table."""
    success, output = await _run_command([
        "pfctl", "-a", _PF_ANCHOR, "-t", _PF_TABLE, "-T", "delete", ip,
    ])
    if success:
        _blocked_ips.discard(ip)
    return success, output


async def _pf_list_blocked() -> list[str]:
    """List all IPs in the pf blocked table."""
    success, output = await _run_command([
        "pfctl", "-a", _PF_ANCHOR, "-t", _PF_TABLE, "-T", "show",
    ])
    if success:
        return [line.strip() for line in output.splitlines() if line.strip()]
    return list(_blocked_ips)


# ---------------------------------------------------------------------------
# Cross-platform blocking functions
# ---------------------------------------------------------------------------

async def block_mac(mac: str, reason: str = "", ip: str = "") -> dict:
    """
    Block all traffic from a MAC address (and optionally IP).

    On macOS: uses pfctl to block the IP (pf doesn't filter by MAC).
    On Linux: uses ebtables (Layer 2) or iptables (Layer 3).
    """
    mac = _validate_mac(mac)
    results: list[str] = []
    overall_success = False

    if _is_macos():
        # macOS: pfctl blocks by IP
        if ip:
            ip = _validate_ip(ip)
            success, output = await _pf_block_ip(ip)
            results.append(f"pfctl block IP {ip}: {output.strip()}")
            overall_success = success
        else:
            results.append("No IP provided — cannot block by MAC only on macOS (pfctl is IP-based)")
            overall_success = False
    else:
        # Linux: ebtables (Layer 2) or iptables (Layer 3)
        if shutil.which("ebtables"):
            success, output = await _run_command(
                ["ebtables", "-A", "INPUT", "-s", mac, "-j", "DROP"]
            )
            results.append(f"ebtables: {output.strip()}")
            overall_success = success
        else:
            success, output = await _run_command(
                ["iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"]
            )
            results.append(f"iptables MAC: {output.strip()}")
            overall_success = success

        # Also block by IP on Linux if provided
        if ip:
            ip = _validate_ip(ip)
            success, output = await _run_command(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            )
            results.append(f"iptables IP: {output.strip()}")
            overall_success = overall_success or success

    _blocked_macs.add(mac)

    return {
        "action": "block",
        "mac_address": mac,
        "ip_address": ip,
        "success": overall_success,
        "output": " | ".join(results),
        "reason": reason,
        "platform": "macOS/pfctl" if _is_macos() else "Linux/iptables",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def unblock_mac(mac: str, ip: str = "") -> dict:
    """
    Remove the block rule for a MAC address (and optionally IP).

    On macOS: removes IP from pfctl table.
    On Linux: deletes ebtables/iptables rules.
    """
    mac = _validate_mac(mac)
    results: list[str] = []
    overall_success = False

    if _is_macos():
        if ip:
            ip = _validate_ip(ip)
            success, output = await _pf_unblock_ip(ip)
            results.append(f"pfctl unblock IP {ip}: {output.strip()}")
            overall_success = success
        else:
            results.append("No IP provided — check pfctl table manually")
            overall_success = False
    else:
        if shutil.which("ebtables"):
            success, output = await _run_command(
                ["ebtables", "-D", "INPUT", "-s", mac, "-j", "DROP"]
            )
            results.append(f"ebtables: {output.strip()}")
            overall_success = success
        else:
            success, output = await _run_command(
                ["iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"]
            )
            results.append(f"iptables MAC: {output.strip()}")
            overall_success = success

        if ip:
            ip = _validate_ip(ip)
            success, output = await _run_command(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            )
            results.append(f"iptables IP: {output.strip()}")

    _blocked_macs.discard(mac)

    return {
        "action": "unblock",
        "mac_address": mac,
        "ip_address": ip,
        "success": overall_success,
        "output": " | ".join(results),
        "platform": "macOS/pfctl" if _is_macos() else "Linux/iptables",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def block_ip(ip: str, reason: str = "") -> dict:
    """
    Block traffic from a specific IP address.

    On macOS: adds to pfctl table.
    On Linux: adds iptables rule.
    """
    ip = _validate_ip(ip)

    if _is_macos():
        success, output = await _pf_block_ip(ip)
    else:
        success, output = await _run_command(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        )

    return {
        "action": "block_ip",
        "ip_address": ip,
        "success": success,
        "output": output.strip(),
        "reason": reason,
        "platform": "macOS/pfctl" if _is_macos() else "Linux/iptables",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def unblock_ip(ip: str) -> dict:
    """Remove an IP block."""
    ip = _validate_ip(ip)

    if _is_macos():
        success, output = await _pf_unblock_ip(ip)
    else:
        success, output = await _run_command(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        )

    return {
        "action": "unblock_ip",
        "ip_address": ip,
        "success": success,
        "output": output.strip(),
        "platform": "macOS/pfctl" if _is_macos() else "Linux/iptables",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def rate_limit_mac(mac: str, limit_pps: int | None = None, ip: str = "") -> dict:
    """
    Apply rate limiting to a source.

    On macOS: pfctl doesn't support per-IP rate limiting natively,
    so we add to the block table if rate is exceeded (effective block).
    On Linux: uses iptables hashlimit module.
    """
    mac = _validate_mac(mac)
    pps = limit_pps or config.mitigation.rate_limit_pps

    if _is_macos() and ip:
        # macOS: pfctl doesn't have hashlimit — we log and suggest block
        ip = _validate_ip(ip)
        logger.info(
            "Rate limiting %s (%s) at %d pps — pfctl will block if exceeded",
            mac, ip, pps,
        )
        success, output = await _pf_block_ip(ip)
        return {
            "action": "rate_limit",
            "mac_address": mac,
            "ip_address": ip,
            "limit_pps": pps,
            "success": success,
            "output": f"macOS: added to pf block table (pfctl lacks per-IP rate limiting). {output.strip()}",
            "platform": "macOS/pfctl",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Linux: iptables hashlimit
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
        "platform": "Linux/iptables",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def isolate_mac(mac: str, ip: str = "") -> dict:
    """
    Isolate a device by blocking both inbound and outbound traffic.

    On macOS: blocks IP in both directions via pfctl table.
    On Linux: blocks in INPUT, OUTPUT, and FORWARD chains.
    """
    mac = _validate_mac(mac)
    results: list[dict] = []

    if _is_macos():
        if ip:
            ip = _validate_ip(ip)
            # pfctl table blocks both directions (configured in anchor)
            success, output = await _pf_block_ip(ip)
            results.append({
                "chain": "pf_table (in+out)",
                "success": success,
                "output": output.strip(),
            })
        else:
            results.append({
                "chain": "pf_table",
                "success": False,
                "output": "No IP provided — cannot isolate by MAC on macOS",
            })
    else:
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

    _blocked_macs.add(mac)

    return {
        "action": "isolate",
        "mac_address": mac,
        "ip_address": ip,
        "results": results,
        "platform": "macOS/pfctl" if _is_macos() else "Linux/iptables",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Rescue function — one-click emergency block
# ---------------------------------------------------------------------------

async def rescue_block(mac: str, ip: str = "", reason: str = "Emergency rescue") -> dict:
    """
    Emergency rescue: block an attacker by MAC and IP simultaneously.

    This is the "panic button" — it blocks the attacker using every
    available method on the current platform, logs the action, and
    returns a comprehensive result.

    Designed to be triggered from the dashboard with one click.
    """
    mac = _validate_mac(mac)
    actions_taken: list[dict] = []
    overall_success = True

    # Block by IP if available
    if ip:
        ip = _validate_ip(ip)
        ip_result = await block_ip(ip, reason=reason)
        actions_taken.append(ip_result)
        if not ip_result["success"]:
            overall_success = False

    # Block by MAC (which also blocks IP on Linux)
    mac_result = await block_mac(mac, reason=reason, ip=ip)
    actions_taken.append(mac_result)
    if not mac_result["success"]:
        overall_success = False

    logger.warning(
        "RESCUE: Blocked attacker MAC=%s IP=%s reason=%s success=%s",
        mac, ip, reason, overall_success,
    )

    return {
        "action": "rescue",
        "mac_address": mac,
        "ip_address": ip,
        "reason": reason,
        "success": overall_success,
        "actions": actions_taken,
        "platform": "macOS/pfctl" if _is_macos() else "Linux/iptables",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def get_block_expiry() -> datetime | None:
    """Calculate block expiry time, or None for permanent blocks."""
    duration = config.mitigation.block_duration_seconds
    if duration <= 0:
        return None
    return datetime.now(timezone.utc) + timedelta(seconds=duration)


async def list_blocked_ips() -> list[str]:
    """List all currently blocked IPs (platform-aware)."""
    if _is_macos():
        return await _pf_list_blocked()
    return list(_blocked_ips)


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
