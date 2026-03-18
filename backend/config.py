"""
Configuration for DDoS Shield.

All tunable parameters live here so students can experiment
with detection thresholds without touching detection logic.
"""

import os
from dataclasses import dataclass, field
from typing import FrozenSet


@dataclass(frozen=True)
class SnifferConfig:
    """Packet capture settings."""

    # Network interface to monitor (empty = auto-detect)
    interface: str = os.getenv("SNIFFER_INTERFACE", "")

    # BPF filter applied at capture time (empty = capture everything)
    bpf_filter: str = os.getenv("SNIFFER_BPF_FILTER", "")

    # How many seconds of traffic form one analysis window
    window_seconds: int = int(os.getenv("SNIFFER_WINDOW_SECONDS", "10"))

    # Maximum packets kept in the rolling buffer per window
    max_buffer_size: int = int(os.getenv("SNIFFER_MAX_BUFFER", "100000"))


@dataclass(frozen=True)
class DetectionConfig:
    """
    Thresholds for the anomaly-detection engine.

    Two detection layers:
      1. **Threshold-based** – fires when a MAC exceeds a fixed packet-per-second
         rate for a given protocol.  Simple but effective for obvious floods.
      2. **Statistical (z-score)** – compares each MAC's current rate against the
         rolling mean/stddev of all MACs.  Catches subtle anomalies.
    """

    # --- Threshold-based (packets per second) ---
    syn_flood_pps: int = int(os.getenv("THRESH_SYN_PPS", "100"))
    udp_flood_pps: int = int(os.getenv("THRESH_UDP_PPS", "500"))
    icmp_flood_pps: int = int(os.getenv("THRESH_ICMP_PPS", "200"))
    http_flood_pps: int = int(os.getenv("THRESH_HTTP_PPS", "150"))
    arp_spoof_pps: int = int(os.getenv("THRESH_ARP_PPS", "50"))

    # --- Z-score layer ---
    zscore_threshold: float = float(os.getenv("ZSCORE_THRESHOLD", "3.0"))

    # Minimum samples before z-score kicks in (avoids false positives on startup)
    zscore_min_samples: int = int(os.getenv("ZSCORE_MIN_SAMPLES", "30"))


@dataclass(frozen=True)
class MitigationConfig:
    """Auto-rescue / mitigation settings."""

    # Enable automatic blocking (disable for observe-only / educational mode)
    auto_block: bool = os.getenv("AUTO_BLOCK", "false").lower() == "true"

    # Rate-limit cap in packets/sec before hard block
    rate_limit_pps: int = int(os.getenv("RATE_LIMIT_PPS", "50"))

    # Seconds before an auto-block expires (0 = manual unblock only)
    block_duration_seconds: int = int(os.getenv("BLOCK_DURATION", "300"))


@dataclass(frozen=True)
class AuthConfig:
    """JWT authentication settings."""

    secret_key: str = os.getenv("JWT_SECRET", "change-me-in-production")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = int(os.getenv("TOKEN_EXPIRE_MINUTES", "60"))
    default_username: str = os.getenv("DEFAULT_USER", "admin")
    default_password: str = os.getenv("DEFAULT_PASS", "ddos-shield-2024")


@dataclass(frozen=True)
class SimulationConfig:
    """Demo / simulation mode for classroom use."""

    enabled: bool = os.getenv("SIMULATION_MODE", "true").lower() == "true"

    # How many fake devices to simulate
    device_count: int = int(os.getenv("SIM_DEVICE_COUNT", "8"))

    # Probability (0-1) that a simulated device becomes an attacker each tick
    attack_probability: float = float(os.getenv("SIM_ATTACK_PROB", "0.15"))

    # Tick interval in seconds
    tick_interval: float = float(os.getenv("SIM_TICK_INTERVAL", "2.0"))


@dataclass(frozen=True)
class AppConfig:
    """Top-level config aggregating all sub-configs."""

    sniffer: SnifferConfig = field(default_factory=SnifferConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    mitigation: MitigationConfig = field(default_factory=MitigationConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    simulation: SimulationConfig = field(default_factory=SimulationConfig)

    # Database
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./ddos_shield.db")

    # WebSocket broadcast interval (seconds)
    ws_broadcast_interval: float = float(os.getenv("WS_INTERVAL", "1.0"))

    # VM-specific network interface prefixes to auto-detect
    # Includes both Linux (virbr, veth, docker) and macOS (bridge, vmnet, vboxnet)
    vm_interface_prefixes: FrozenSet[str] = frozenset(
        {"virbr", "veth", "br-", "tap", "docker", "vnet",
         "bridge", "vmnet", "vboxnet", "utun"}
    )


# Singleton used throughout the application
config = AppConfig()
