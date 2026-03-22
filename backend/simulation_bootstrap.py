"""
Simulation bootstrap — orchestrates realistic data generation on startup.

When simulation mode is enabled, this module:
1. Discovers all sim devices (via scanner)
2. Port-scans every device and caches results
3. Runs vulnerability assessment on each device
4. Populates the managed_devices table
5. Generates initial alerts (vulnerabilities, rogue devices, etc.)
6. Starts a periodic event generator for ongoing realism

This ensures the dashboard shows rich, realistic data immediately.
"""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import datetime, timezone

from config import config
from scanner import get_sim_devices, scan_network, DiscoveredDevice
from port_scanner import scan_device_ports, get_device_ports, PortScanResult, _scan_results_cache
from vulnerability import assess_device, calculate_network_grade, DeviceAssessment
from bandwidth import bandwidth_tracker
from alert_engine import (
    create_alert, alert_rogue_device, register_known_mac,
    alert_health_issue, alert_high_bandwidth,
)
from models import (
    AlertCategory, Severity, DeviceType, ManagedDevice,
)
from database import async_session_factory
from sqlalchemy import select

logger = logging.getLogger("ddos_shield.bootstrap")


# ---------------------------------------------------------------------------
# Simulation scenario presets
# ---------------------------------------------------------------------------

_SCENARIO_PRESETS = {
    "typical_office": {
        "name": "Typical Office",
        "description": "A regular office network with some issues — grade B-C",
    },
    "clean_network": {
        "name": "Clean Network",
        "description": "All devices patched and secure — grade A",
    },
    "compromised": {
        "name": "Compromised Network",
        "description": "Active attacks, rogue devices — grade D-F",
    },
    "iot_heavy": {
        "name": "IoT Heavy",
        "description": "Many IoT devices with poor security",
    },
}


def get_scenario_presets() -> dict:
    """Return available scenario presets."""
    return dict(_SCENARIO_PRESETS)


# ---------------------------------------------------------------------------
# Bootstrap orchestration
# ---------------------------------------------------------------------------

# Cache for assessments so they're available without re-scanning
_cached_assessments: list[DeviceAssessment] = []
_cached_grade: dict = {}


def get_cached_assessments() -> list[DeviceAssessment]:
    """Return cached security assessments from bootstrap."""
    return list(_cached_assessments)


def get_cached_grade() -> dict:
    """Return cached network grade from bootstrap."""
    return dict(_cached_grade) if _cached_grade else {}


async def run_bootstrap() -> None:
    """
    Full simulation bootstrap — call once at startup.

    Steps:
    1. Run network scan to discover sim devices
    2. Port scan all devices
    3. Run vulnerability assessment
    4. Populate managed_devices table
    5. Generate initial alerts
    """
    if not config.simulation.enabled:
        logger.info("Real mode — skipping simulation bootstrap")
        return

    logger.info("=== Simulation Bootstrap Starting ===")

    # Step 1: Discover devices
    devices = await scan_network()
    logger.info("Bootstrap: discovered %d devices", len(devices))

    # Step 2: Port scan all devices and cache results
    assessments: list[DeviceAssessment] = []
    for device in devices:
        if not device.ip_address:
            continue
        # Use get_device_ports which auto-caches results
        ports = await get_device_ports(device.ip_address, device.mac_address)

        # Step 3: Vulnerability assessment
        assessment = assess_device(device.ip_address, device.mac_address, ports)
        assessments.append(assessment)

    # Cache assessments and grade
    global _cached_assessments, _cached_grade
    _cached_assessments = assessments
    _cached_grade = calculate_network_grade(assessments)

    logger.info(
        "Bootstrap: security grade %s (score %.1f), %d vulnerabilities across %d devices",
        _cached_grade.get("grade", "?"),
        _cached_grade.get("score", 0),
        _cached_grade.get("total_vulnerabilities", 0),
        len(assessments),
    )

    # Step 4: Populate managed_devices table
    await _populate_managed_devices(devices, assessments)

    # Step 5: Generate initial alerts
    await _generate_initial_alerts(devices, assessments)

    logger.info("=== Simulation Bootstrap Complete ===")


async def _populate_managed_devices(
    devices: list[DiscoveredDevice],
    assessments: list[DeviceAssessment],
) -> None:
    """Add all discovered devices to the managed_devices table."""
    assessment_map = {a.ip_address: a for a in assessments}

    async with async_session_factory() as session:
        for device in devices:
            if not device.ip_address or not device.mac_address:
                continue

            mac = device.mac_address.upper()

            # Check if already exists
            result = await session.execute(
                select(ManagedDevice).where(ManagedDevice.mac_address == mac)
            )
            existing = result.scalar_one_or_none()
            if existing:
                # Update fields
                existing.ip_address = device.ip_address
                existing.hostname = device.hostname
                existing.os_info = device.os_info
                existing.is_online = True
                existing.last_seen = datetime.now(timezone.utc)
                assessment = assessment_map.get(device.ip_address)
                if assessment:
                    existing.security_score = assessment.security_score
                    existing.open_ports_count = assessment.open_ports
                continue

            # Map device_type string to DeviceType enum
            try:
                dev_type = DeviceType(device.device_type)
            except ValueError:
                dev_type = DeviceType.UNKNOWN

            now = datetime.now(timezone.utc)
            assessment = assessment_map.get(device.ip_address)

            managed = ManagedDevice(
                name=device.hostname or f"Device-{device.ip_address}",
                mac_address=mac,
                ip_address=device.ip_address,
                device_type=dev_type,
                hostname=device.hostname,
                os_info=device.os_info,
                is_protected=False,
                is_online=True,
                first_seen=now,
                last_seen=now,
                notes=f"Auto-discovered via {device.discovery_method}",
                attacks_blocked=0,
                uptime_checks=10,
                uptime_successes=10,
                security_score=assessment.security_score if assessment else 100,
                open_ports_count=assessment.open_ports if assessment else 0,
                is_whitelisted=True,
            )
            session.add(managed)
            register_known_mac(mac)

        await session.commit()

    logger.info("Bootstrap: populated managed_devices with %d devices", len(devices))


async def _generate_initial_alerts(
    devices: list[DiscoveredDevice],
    assessments: list[DeviceAssessment],
) -> None:
    """Generate realistic initial alerts from vulnerability findings."""
    # Alert for critical/high vulnerabilities found
    for assessment in assessments:
        for vuln in assessment.vulnerabilities:
            if vuln.risk_level in ("CRITICAL", "HIGH"):
                severity = Severity.CRITICAL if vuln.risk_level == "CRITICAL" else Severity.HIGH
                create_alert(
                    category=AlertCategory.SECURITY,
                    severity=severity,
                    title=f"Vulnerable service: {vuln.service} on port {vuln.port}",
                    description=(
                        f"Device {assessment.ip_address} has {vuln.service} "
                        f"exposed on port {vuln.port}: {vuln.description}"
                    ),
                    source_mac=assessment.mac_address,
                    source_ip=assessment.ip_address,
                    metadata={
                        "event": "vulnerability_found",
                        "port": vuln.port,
                        "service": vuln.service,
                        "risk_level": vuln.risk_level,
                    },
                )

    # Alert for devices with poor security scores
    for assessment in assessments:
        if assessment.security_score < 70:
            create_alert(
                category=AlertCategory.SECURITY,
                severity=Severity.MEDIUM,
                title=f"Poor security score: {assessment.ip_address}",
                description=(
                    f"Device {assessment.ip_address} scored {assessment.security_score}/100 "
                    f"with {len(assessment.vulnerabilities)} vulnerabilities"
                ),
                source_mac=assessment.mac_address,
                source_ip=assessment.ip_address,
                metadata={
                    "event": "low_security_score",
                    "score": assessment.security_score,
                },
            )

    # Simulate a couple of initial network events
    create_alert(
        category=AlertCategory.DEVICE_STATUS,
        severity=Severity.INFO,
        title="Network scan complete",
        description=f"Discovered {len(devices)} devices on the network",
        metadata={"event": "scan_complete", "device_count": len(devices)},
    )

    logger.info("Bootstrap: generated initial alerts")


# ---------------------------------------------------------------------------
# Periodic simulation events (runs after bootstrap)
# ---------------------------------------------------------------------------

async def periodic_sim_events_loop(interval: float = 45.0) -> None:
    """
    Generate periodic simulation events for a lively dashboard.

    Fires every `interval` seconds and randomly produces:
    - Bandwidth spike alerts
    - Health degradation events
    - New rogue device detections
    - Port scan activity alerts
    """
    if not config.simulation.enabled:
        return

    # Wait for bootstrap to complete
    await asyncio.sleep(10)

    while True:
        try:
            # Bandwidth spike (30% chance)
            if random.random() < 0.30:
                from scanner import get_sim_devices
                sim_devices = get_sim_devices()
                if sim_devices:
                    device = random.choice(sim_devices)
                    bps = random.randint(10_000_000, 80_000_000)  # 10-80 Mbps
                    alert_high_bandwidth(
                        device.mac_address, device.ip_address, bps
                    )

            # Rogue device detection (10% chance)
            if random.random() < 0.10:
                rogue_mac = f"EE:FF:{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}:{random.randint(0,255):02X}"
                rogue_ip = f"192.168.1.{random.randint(200, 250)}"
                alert_rogue_device(rogue_mac, rogue_ip, "unknown-device")

            # Service outage alert (5% chance)
            if random.random() < 0.05:
                create_alert(
                    category=AlertCategory.PERFORMANCE,
                    severity=Severity.HIGH,
                    title="Service latency spike detected",
                    description="DNS resolution latency exceeded 200ms threshold",
                    metadata={"event": "latency_spike", "latency_ms": random.randint(200, 500)},
                )

        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Error in periodic sim events")

        await asyncio.sleep(interval)
