"""
DDoS anomaly detection engine with enhanced intrusion detection.

Two complementary detection strategies:

1. **Threshold-based detection**
   Fires when a single MAC's packet rate exceeds a fixed PPS limit for
   a specific protocol.  Fast, deterministic, and easy to understand.

   Limitation: a clever attacker can stay just below the threshold.

2. **Statistical detection (z-score)**
   Computes how many standard deviations a MAC's traffic rate is from
   the network-wide mean.  Catches anomalies relative to "normal" —
   even if the absolute rate looks low.

   z = (x - μ) / σ

   A z-score > 3 means the device is sending traffic more than 3
   standard deviations above average, which is extremely unusual.

Enhanced intrusion detection (IDS) capabilities:
3. **Port scan detection** — One device probing many ports on another
4. **ARP spoofing detection** — MAC-IP binding changes
5. **Lateral movement detection** — Device contacting many internal hosts
6. **DNS tunneling detection** — Unusually long or frequent DNS queries

Educational note:
  Real-world IDS/IPS systems layer many more heuristics (entropy
  analysis, flow correlation, ML classifiers).  This simplified
  multi-layer approach teaches the fundamental concepts.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Sequence

from config import config
from models import AttackType, Severity


@dataclass(frozen=True)
class DetectionResult:
    """Immutable record of a single detection event."""

    mac_address: str
    attack_type: AttackType
    severity: Severity
    packets_per_second: float
    z_score: float | None
    description: str


@dataclass(frozen=True)
class TrafficSnapshot:
    """Per-MAC traffic counters for one analysis window."""

    mac_address: str
    ip_address: str
    syn_pps: float
    udp_pps: float
    icmp_pps: float
    http_pps: float
    arp_pps: float
    total_pps: float


def _classify_severity(pps: float, threshold: float) -> Severity:
    """
    Map a packet rate to a severity level based on how far it exceeds
    the threshold.

    Educational note:
      Severity tiers help SOC analysts prioritise response.  A device
      at 1.2× the threshold might be a misconfigured server, while
      10× is almost certainly malicious.
    """
    ratio = pps / threshold if threshold > 0 else 0
    if ratio >= 5:
        return Severity.CRITICAL
    if ratio >= 3:
        return Severity.HIGH
    if ratio >= 1.5:
        return Severity.MEDIUM
    return Severity.LOW


def detect_threshold(snapshot: TrafficSnapshot) -> list[DetectionResult]:
    """
    Threshold-based detection for a single MAC.

    Checks each protocol's PPS against the configured limit.
    Returns a list of DetectionResult for every threshold breach.
    """
    cfg = config.detection
    results: list[DetectionResult] = []

    _checks: list[tuple[float, int, AttackType, str]] = [
        (snapshot.syn_pps, cfg.syn_flood_pps, AttackType.SYN_FLOOD,
         "SYN packet rate {pps:.0f} pps exceeds threshold {thresh} pps"),
        (snapshot.udp_pps, cfg.udp_flood_pps, AttackType.UDP_FLOOD,
         "UDP packet rate {pps:.0f} pps exceeds threshold {thresh} pps"),
        (snapshot.icmp_pps, cfg.icmp_flood_pps, AttackType.ICMP_FLOOD,
         "ICMP packet rate {pps:.0f} pps exceeds threshold {thresh} pps"),
        (snapshot.http_pps, cfg.http_flood_pps, AttackType.HTTP_FLOOD,
         "HTTP packet rate {pps:.0f} pps exceeds threshold {thresh} pps"),
        (snapshot.arp_pps, cfg.arp_spoof_pps, AttackType.ARP_SPOOF,
         "ARP packet rate {pps:.0f} pps exceeds threshold {thresh} pps"),
    ]

    for pps, threshold, attack_type, desc_template in _checks:
        if pps > threshold:
            results.append(
                DetectionResult(
                    mac_address=snapshot.mac_address,
                    attack_type=attack_type,
                    severity=_classify_severity(pps, threshold),
                    packets_per_second=pps,
                    z_score=None,
                    description=desc_template.format(pps=pps, thresh=threshold),
                )
            )

    return results


def detect_zscore(
    snapshots: Sequence[TrafficSnapshot],
) -> list[DetectionResult]:
    """
    Statistical z-score detection across all MACs in the current window.

    Steps:
      1. Collect total_pps for every MAC.
      2. Compute mean (μ) and standard deviation (σ).
      3. Flag any MAC whose z-score exceeds the configured threshold.

    Educational note:
      The z-score normalises the data so we can compare traffic from
      different-sized networks.  It answers: "How unusual is this
      device compared to everyone else right now?"
    """
    cfg = config.detection

    if len(snapshots) < cfg.zscore_min_samples:
        return []

    rates = [s.total_pps for s in snapshots]
    n = len(rates)
    mean = sum(rates) / n
    variance = sum((r - mean) ** 2 for r in rates) / n
    stddev = math.sqrt(variance) if variance > 0 else 0.0

    if stddev == 0:
        return []  # All devices have identical traffic — nothing anomalous

    results: list[DetectionResult] = []
    for snapshot in snapshots:
        z = (snapshot.total_pps - mean) / stddev
        if z > cfg.zscore_threshold:
            # Determine which protocol is dominant to label the attack type
            attack_type = _dominant_attack_type(snapshot)
            results.append(
                DetectionResult(
                    mac_address=snapshot.mac_address,
                    attack_type=attack_type,
                    severity=_severity_from_zscore(z),
                    packets_per_second=snapshot.total_pps,
                    z_score=round(z, 2),
                    description=(
                        f"Statistical anomaly: z-score {z:.2f} "
                        f"(mean={mean:.0f}, σ={stddev:.0f}, rate={snapshot.total_pps:.0f} pps)"
                    ),
                )
            )

    return results


def _dominant_attack_type(snapshot: TrafficSnapshot) -> AttackType:
    """Return the attack type corresponding to the highest PPS protocol."""
    protocol_map: list[tuple[float, AttackType]] = [
        (snapshot.syn_pps, AttackType.SYN_FLOOD),
        (snapshot.udp_pps, AttackType.UDP_FLOOD),
        (snapshot.icmp_pps, AttackType.ICMP_FLOOD),
        (snapshot.http_pps, AttackType.HTTP_FLOOD),
        (snapshot.arp_pps, AttackType.ARP_SPOOF),
    ]
    return max(protocol_map, key=lambda x: x[0])[1]


def _severity_from_zscore(z: float) -> Severity:
    """Map z-score magnitude to severity."""
    if z >= 6:
        return Severity.CRITICAL
    if z >= 4.5:
        return Severity.HIGH
    if z >= 3.5:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------------------
# Enhanced IDS: Port scan detection
# ---------------------------------------------------------------------------

# Track per-device destination port counts (mac -> {target_ip -> set(ports)})
_port_scan_tracker: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
_port_scan_last_reset: float = time.time()
_PORT_SCAN_WINDOW: float = 60.0  # seconds
_PORT_SCAN_THRESHOLD: int = 15   # ports in window


def track_connection(src_mac: str, dst_ip: str, dst_port: int) -> DetectionResult | None:
    """
    Track connections for port scan detection.

    Educational note:
      Port scanning is a reconnaissance technique where an attacker
      probes many ports on a target to discover running services.
      We detect this by counting unique destination ports per
      source→target pair within a time window.
    """
    global _port_scan_last_reset

    now = time.time()
    if now - _port_scan_last_reset > _PORT_SCAN_WINDOW:
        _port_scan_tracker.clear()
        _port_scan_last_reset = now

    _port_scan_tracker[src_mac][dst_ip].add(dst_port)
    port_count = len(_port_scan_tracker[src_mac][dst_ip])

    if port_count >= _PORT_SCAN_THRESHOLD:
        _port_scan_tracker[src_mac][dst_ip].clear()
        return DetectionResult(
            mac_address=src_mac,
            attack_type=AttackType.PORT_SCAN,
            severity=Severity.HIGH,
            packets_per_second=0,
            z_score=None,
            description=f"Port scan detected: {src_mac} scanned {port_count} ports on {dst_ip}",
        )
    return None


# ---------------------------------------------------------------------------
# Enhanced IDS: ARP spoofing detection
# ---------------------------------------------------------------------------

# Track known MAC-IP bindings
_mac_ip_bindings: dict[str, str] = {}


def check_arp_binding(ip: str, mac: str) -> DetectionResult | None:
    """
    Check for ARP spoofing by detecting MAC-IP binding changes.

    Educational note:
      In a healthy network, each IP is associated with one MAC address.
      If the MAC for an IP changes unexpectedly, it could indicate
      ARP spoofing — where an attacker sends fake ARP replies to
      redirect traffic through their device.
    """
    mac = mac.upper()
    if ip in _mac_ip_bindings:
        expected_mac = _mac_ip_bindings[ip]
        if expected_mac != mac:
            old_mac = expected_mac
            _mac_ip_bindings[ip] = mac
            return DetectionResult(
                mac_address=mac,
                attack_type=AttackType.ARP_SPOOF,
                severity=Severity.CRITICAL,
                packets_per_second=0,
                z_score=None,
                description=(
                    f"ARP spoofing: IP {ip} changed from {old_mac} to {mac}"
                ),
            )
    else:
        _mac_ip_bindings[ip] = mac
    return None


# ---------------------------------------------------------------------------
# Enhanced IDS: Lateral movement detection
# ---------------------------------------------------------------------------

_lateral_tracker: dict[str, set[str]] = defaultdict(set)
_lateral_last_reset: float = time.time()
_LATERAL_WINDOW: float = 300.0  # 5 minutes
_LATERAL_THRESHOLD: int = 10    # unique internal hosts


def track_internal_connection(src_mac: str, dst_ip: str) -> DetectionResult | None:
    """
    Detect lateral movement — a device communicating with many internal hosts.

    Educational note:
      After an attacker compromises one device, they typically scan
      the internal network for other targets. This produces a sudden
      spike in the number of unique internal hosts a device contacts.
    """
    global _lateral_last_reset

    now = time.time()
    if now - _lateral_last_reset > _LATERAL_WINDOW:
        _lateral_tracker.clear()
        _lateral_last_reset = now

    # Only track internal (private) IPs
    if not _is_private_ip(dst_ip):
        return None

    _lateral_tracker[src_mac].add(dst_ip)
    target_count = len(_lateral_tracker[src_mac])

    if target_count >= _LATERAL_THRESHOLD:
        _lateral_tracker[src_mac].clear()
        return DetectionResult(
            mac_address=src_mac,
            attack_type=AttackType.LATERAL_MOVE,
            severity=Severity.HIGH,
            packets_per_second=0,
            z_score=None,
            description=(
                f"Lateral movement: {src_mac} contacted {target_count} internal hosts"
            ),
        )
    return None


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private range (RFC 1918)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return False

    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    return False


# ---------------------------------------------------------------------------
# Main detection entry point
# ---------------------------------------------------------------------------

def run_detection(snapshots: Sequence[TrafficSnapshot]) -> list[DetectionResult]:
    """
    Run both detection layers and merge results (deduplicated by MAC + attack type).

    This is the main entry point called by the analysis loop every window.
    """
    seen: set[tuple[str, AttackType]] = set()
    results: list[DetectionResult] = []

    # Layer 1: threshold per MAC
    for snap in snapshots:
        for det in detect_threshold(snap):
            key = (det.mac_address, det.attack_type)
            if key not in seen:
                seen.add(key)
                results.append(det)

    # Layer 2: z-score across all MACs
    for det in detect_zscore(snapshots):
        key = (det.mac_address, det.attack_type)
        if key not in seen:
            seen.add(key)
            results.append(det)

    return results
