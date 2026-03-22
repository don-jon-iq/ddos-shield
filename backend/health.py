"""
Network health monitoring for DDoS Shield.

Educational note:
  Network health monitoring continuously checks critical infrastructure
  components to detect issues before they impact users:
  - Gateway: Can we reach the default gateway? (Layer 2/3 connectivity)
  - DNS: Can we resolve domain names? (Name resolution)
  - Internet: Can we reach external hosts? (WAN connectivity)
  - Latency: How fast are responses? (Network performance)
  - Packet Loss: Are packets being dropped? (Network reliability)

  In simulation mode, we generate realistic health data with
  occasional degradation to demonstrate monitoring capabilities.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import random
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from config import config
from network_utils import get_network_info

logger = logging.getLogger("ddos_shield.health")


# ---------------------------------------------------------------------------
# Health check result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HealthResult:
    """Immutable result of a single health check."""
    check_type: str
    target: str
    is_up: bool
    latency_ms: float
    packet_loss_pct: float
    details: str
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "check_type": self.check_type,
            "target": self.target,
            "is_up": self.is_up,
            "latency_ms": round(self.latency_ms, 2),
            "packet_loss_pct": round(self.packet_loss_pct, 1),
            "details": self.details,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Health check implementations
# ---------------------------------------------------------------------------

async def _ping_host(host: str, count: int = 3, timeout: int = 2) -> tuple[bool, float, float]:
    """
    Ping a host and return (is_up, avg_latency_ms, packet_loss_pct).

    Educational note:
      ICMP ping is the simplest health check — it tests basic Layer 3
      reachability. However, some hosts block ICMP, so a failed ping
      doesn't always mean the host is down.
    """
    if config.simulation.enabled:
        return _sim_ping()

    try:
        # Build platform-appropriate ping command
        if platform.system() == "Darwin":
            cmd = ["ping", "-c", str(count), "-W", str(timeout * 1000), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout), host]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=count * timeout + 5)
        output = stdout.decode("utf-8", errors="replace")

        # Parse ping output
        is_up = proc.returncode == 0
        latency = 0.0
        loss = 100.0

        for line in output.split("\n"):
            if "avg" in line and "/" in line:
                # macOS/Linux: round-trip min/avg/max/stddev = 1.0/2.0/3.0/0.5 ms
                parts = line.split("=")
                if len(parts) >= 2:
                    vals = parts[-1].strip().split("/")
                    if len(vals) >= 2:
                        latency = float(vals[1])
            if "packet loss" in line:
                for part in line.split(","):
                    if "packet loss" in part:
                        loss_str = part.strip().split("%")[0].strip().split()[-1]
                        try:
                            loss = float(loss_str)
                        except ValueError:
                            pass

        return (is_up, latency, loss)

    except (asyncio.TimeoutError, FileNotFoundError, Exception) as exc:
        logger.debug("Ping to %s failed: %s", host, exc)
        return (False, 0.0, 100.0)


async def _dns_check(server: str = "8.8.8.8") -> tuple[bool, float]:
    """
    Check DNS resolution by resolving a known domain.

    Returns: (is_up, latency_ms)
    """
    if config.simulation.enabled:
        return _sim_dns()

    try:
        import socket
        loop = asyncio.get_event_loop()
        start = time.time()
        await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, "google.com"),
            timeout=5.0,
        )
        latency = (time.time() - start) * 1000
        return (True, latency)

    except Exception as exc:
        logger.debug("DNS check failed: %s", exc)
        return (False, 0.0)


async def _internet_check() -> tuple[bool, float]:
    """
    Check internet connectivity by attempting a TCP connection.

    Educational note:
      We test connectivity by trying to reach well-known public
      services. Using TCP port 443 (HTTPS) is more reliable than
      ICMP because fewer firewalls block it.
    """
    if config.simulation.enabled:
        return _sim_internet()

    targets = [("8.8.8.8", 53), ("1.1.1.1", 53), ("208.67.222.222", 53)]
    for host, port in targets:
        try:
            start = time.time()
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=3.0)
            latency = (time.time() - start) * 1000
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return (True, latency)
        except (asyncio.TimeoutError, OSError):
            continue

    return (False, 0.0)


# ---------------------------------------------------------------------------
# Simulation helpers
# ---------------------------------------------------------------------------

def _sim_ping() -> tuple[bool, float, float]:
    """Simulate a ping result with occasional degradation."""
    if random.random() < 0.05:
        return (False, 0.0, 100.0)
    if random.random() < 0.1:
        return (True, random.uniform(50, 200), random.uniform(5, 30))
    return (True, random.uniform(1, 15), 0.0)


def _sim_dns() -> tuple[bool, float]:
    """Simulate a DNS check result."""
    if random.random() < 0.03:
        return (False, 0.0)
    return (True, random.uniform(5, 50))


def _sim_internet() -> tuple[bool, float]:
    """Simulate an internet connectivity check."""
    if random.random() < 0.02:
        return (False, 0.0)
    return (True, random.uniform(10, 80))


# ---------------------------------------------------------------------------
# Composite health check
# ---------------------------------------------------------------------------

_last_health_results: list[HealthResult] = []
_health_history: list[dict] = []
_MAX_HISTORY = 500


async def run_health_checks() -> list[HealthResult]:
    """
    Run all health checks and return results.

    Checks: gateway ping, DNS resolution, internet connectivity.
    """
    global _last_health_results
    results: list[HealthResult] = []
    now = datetime.now(timezone.utc).isoformat()

    # Gateway check
    net_info = get_network_info()
    gateway_ip = config.health.gateway_ip or _detect_gateway()

    if gateway_ip:
        gw_up, gw_lat, gw_loss = await _ping_host(gateway_ip, count=3)
        results.append(HealthResult(
            check_type="gateway",
            target=gateway_ip,
            is_up=gw_up,
            latency_ms=gw_lat,
            packet_loss_pct=gw_loss,
            details="Gateway reachable" if gw_up else "Gateway unreachable",
            timestamp=now,
        ))

    # DNS check
    dns_up, dns_lat = await _dns_check(config.health.dns_server)
    results.append(HealthResult(
        check_type="dns",
        target=config.health.dns_server,
        is_up=dns_up,
        latency_ms=dns_lat,
        packet_loss_pct=0.0 if dns_up else 100.0,
        details="DNS resolution working" if dns_up else "DNS resolution failed",
        timestamp=now,
    ))

    # Internet check
    inet_up, inet_lat = await _internet_check()
    results.append(HealthResult(
        check_type="internet",
        target="public DNS (8.8.8.8, 1.1.1.1)",
        is_up=inet_up,
        latency_ms=inet_lat,
        packet_loss_pct=0.0 if inet_up else 100.0,
        details="Internet connectivity OK" if inet_up else "No internet connectivity",
        timestamp=now,
    ))

    _last_health_results = results

    # Store in history
    for r in results:
        _health_history.append(r.to_dict())
    if len(_health_history) > _MAX_HISTORY:
        _health_history[:] = _health_history[-_MAX_HISTORY:]

    return results


def get_last_health() -> list[dict]:
    """Get the most recent health check results."""
    return [r.to_dict() for r in _last_health_results]


def get_health_history(check_type: str | None = None, limit: int = 100) -> list[dict]:
    """Get health check history, optionally filtered by check type."""
    history = _health_history
    if check_type:
        history = [h for h in history if h["check_type"] == check_type]
    return history[-limit:]


def get_health_score() -> dict:
    """
    Calculate an overall network health score (0-100).

    Educational note:
      The health score aggregates multiple indicators:
      - All checks passing = 100
      - Gateway down = -40 (most critical)
      - DNS down = -30
      - Internet down = -20
      - High latency deducts points proportionally
    """
    if not _last_health_results:
        return {"score": 100, "status": "unknown", "checks": 0}

    score = 100.0
    for result in _last_health_results:
        if not result.is_up:
            if result.check_type == "gateway":
                score -= 40
            elif result.check_type == "dns":
                score -= 30
            elif result.check_type == "internet":
                score -= 20
        else:
            # Penalize for high latency
            if result.latency_ms > 100:
                score -= min(10, (result.latency_ms - 100) / 50)
            if result.packet_loss_pct > 0:
                score -= min(15, result.packet_loss_pct / 2)

    score = max(0, min(100, score))

    if score >= 90:
        status = "healthy"
    elif score >= 70:
        status = "degraded"
    elif score >= 40:
        status = "unhealthy"
    else:
        status = "critical"

    return {
        "score": round(score, 1),
        "status": status,
        "checks": len(_last_health_results),
        "all_up": all(r.is_up for r in _last_health_results),
    }


def _detect_gateway() -> str:
    """Try to detect the default gateway IP address."""
    if config.simulation.enabled:
        return "192.168.1.1"

    try:
        if platform.system() == "Darwin":
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.split("\n"):
                if "gateway:" in line:
                    return line.split(":")[-1].strip()
        else:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            parts = result.stdout.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass

    return ""


async def periodic_health_loop(interval: float | None = None) -> None:
    """Background task that runs health checks at regular intervals."""
    check_interval = interval or config.health.check_interval
    while True:
        try:
            await run_health_checks()
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Error in health check loop")
        await asyncio.sleep(check_interval)
