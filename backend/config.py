"""
Configuration for DDoS Shield.

All tunable parameters live here so students can experiment
with detection thresholds without touching detection logic.

Runtime-mutable: settings can be changed via the Settings API
and persisted to the .env file.
"""

import os
from pathlib import Path
from threading import Lock

# Path to the .env file (project root)
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


# ---------------------------------------------------------------------------
# Default values (used for reset-to-defaults)
# ---------------------------------------------------------------------------

DEFAULTS: dict[str, str] = {
    # Simulation
    "SIMULATION_MODE": "true",
    "SIM_DEVICE_COUNT": "8",
    "SIM_ATTACK_PROB": "0.15",
    "SIM_TICK_INTERVAL": "2.0",
    # Sniffer
    "SNIFFER_INTERFACE": "",
    "SNIFFER_BPF_FILTER": "",
    "SNIFFER_WINDOW_SECONDS": "10",
    "SNIFFER_MAX_BUFFER": "100000",
    # Detection
    "THRESH_SYN_PPS": "100",
    "THRESH_UDP_PPS": "500",
    "THRESH_ICMP_PPS": "200",
    "THRESH_HTTP_PPS": "150",
    "THRESH_ARP_PPS": "50",
    "ZSCORE_THRESHOLD": "3.0",
    "ZSCORE_MIN_SAMPLES": "30",
    # Mitigation
    "AUTO_BLOCK": "false",
    "RATE_LIMIT_PPS": "50",
    "BLOCK_DURATION": "300",
    # Auth
    "JWT_SECRET": "change-me-in-production",
    "TOKEN_EXPIRE_MINUTES": "60",
    "DEFAULT_USER": "admin",
    "DEFAULT_PASS": "ddos-shield-2024",
    # Database
    "DATABASE_URL": "sqlite:///./ddos_shield.db",
    # WebSocket
    "WS_INTERVAL": "1.0",
    # Scanner
    "SCAN_INTERVAL": "30",
    "AUTO_SCAN": "true",
}


def _env(key: str) -> str:
    """Read an env var, falling back to DEFAULTS."""
    return os.getenv(key, DEFAULTS.get(key, ""))


# ---------------------------------------------------------------------------
# Mutable config classes
# ---------------------------------------------------------------------------

class SnifferConfig:
    """Packet capture settings."""

    def __init__(self) -> None:
        self.interface: str = _env("SNIFFER_INTERFACE")
        self.bpf_filter: str = _env("SNIFFER_BPF_FILTER")
        self.window_seconds: int = int(_env("SNIFFER_WINDOW_SECONDS"))
        self.max_buffer_size: int = int(_env("SNIFFER_MAX_BUFFER"))


class DetectionConfig:
    """Thresholds for the anomaly-detection engine."""

    def __init__(self) -> None:
        self.syn_flood_pps: int = int(_env("THRESH_SYN_PPS"))
        self.udp_flood_pps: int = int(_env("THRESH_UDP_PPS"))
        self.icmp_flood_pps: int = int(_env("THRESH_ICMP_PPS"))
        self.http_flood_pps: int = int(_env("THRESH_HTTP_PPS"))
        self.arp_spoof_pps: int = int(_env("THRESH_ARP_PPS"))
        self.zscore_threshold: float = float(_env("ZSCORE_THRESHOLD"))
        self.zscore_min_samples: int = int(_env("ZSCORE_MIN_SAMPLES"))


class MitigationConfig:
    """Auto-rescue / mitigation settings."""

    def __init__(self) -> None:
        self.auto_block: bool = _env("AUTO_BLOCK").lower() == "true"
        self.rate_limit_pps: int = int(_env("RATE_LIMIT_PPS"))
        self.block_duration_seconds: int = int(_env("BLOCK_DURATION"))


class AuthConfig:
    """JWT authentication settings."""

    def __init__(self) -> None:
        self.secret_key: str = _env("JWT_SECRET")
        self.algorithm: str = "HS256"
        self.access_token_expire_minutes: int = int(_env("TOKEN_EXPIRE_MINUTES"))
        self.default_username: str = _env("DEFAULT_USER")
        self.default_password: str = _env("DEFAULT_PASS")


class SimulationConfig:
    """Demo / simulation mode for classroom use."""

    def __init__(self) -> None:
        self.enabled: bool = _env("SIMULATION_MODE").lower() == "true"
        self.device_count: int = int(_env("SIM_DEVICE_COUNT"))
        self.attack_probability: float = float(_env("SIM_ATTACK_PROB"))
        self.tick_interval: float = float(_env("SIM_TICK_INTERVAL"))


class ScannerConfig:
    """Network scanner settings."""

    def __init__(self) -> None:
        self.scan_interval: int = int(_env("SCAN_INTERVAL"))
        self.auto_scan: bool = _env("AUTO_SCAN").lower() == "true"


class AppConfig:
    """Top-level config aggregating all sub-configs."""

    def __init__(self) -> None:
        self._lock = Lock()
        self.sniffer = SnifferConfig()
        self.detection = DetectionConfig()
        self.mitigation = MitigationConfig()
        self.auth = AuthConfig()
        self.simulation = SimulationConfig()
        self.scanner = ScannerConfig()
        self.database_url: str = _env("DATABASE_URL")
        self.ws_broadcast_interval: float = float(_env("WS_INTERVAL"))
        self.vm_interface_prefixes: frozenset[str] = frozenset(
            {"virbr", "veth", "br-", "tap", "docker", "vnet",
             "bridge", "vmnet", "vboxnet", "utun"}
        )

    def reload(self) -> None:
        """Re-read environment variables and rebuild all sub-configs."""
        with self._lock:
            self.sniffer = SnifferConfig()
            self.detection = DetectionConfig()
            self.mitigation = MitigationConfig()
            self.auth = AuthConfig()
            self.simulation = SimulationConfig()
            self.scanner = ScannerConfig()
            self.database_url = _env("DATABASE_URL")
            self.ws_broadcast_interval = float(_env("WS_INTERVAL"))

    def to_dict(self) -> dict:
        """Serialize all settings to a flat dict for the API."""
        return {
            # Simulation
            "SIMULATION_MODE": self.simulation.enabled,
            "SIM_DEVICE_COUNT": self.simulation.device_count,
            "SIM_ATTACK_PROB": self.simulation.attack_probability,
            "SIM_TICK_INTERVAL": self.simulation.tick_interval,
            # Sniffer
            "SNIFFER_INTERFACE": self.sniffer.interface,
            "SNIFFER_BPF_FILTER": self.sniffer.bpf_filter,
            "SNIFFER_WINDOW_SECONDS": self.sniffer.window_seconds,
            "SNIFFER_MAX_BUFFER": self.sniffer.max_buffer_size,
            # Detection
            "THRESH_SYN_PPS": self.detection.syn_flood_pps,
            "THRESH_UDP_PPS": self.detection.udp_flood_pps,
            "THRESH_ICMP_PPS": self.detection.icmp_flood_pps,
            "THRESH_HTTP_PPS": self.detection.http_flood_pps,
            "THRESH_ARP_PPS": self.detection.arp_spoof_pps,
            "ZSCORE_THRESHOLD": self.detection.zscore_threshold,
            "ZSCORE_MIN_SAMPLES": self.detection.zscore_min_samples,
            # Mitigation
            "AUTO_BLOCK": self.mitigation.auto_block,
            "RATE_LIMIT_PPS": self.mitigation.rate_limit_pps,
            "BLOCK_DURATION": self.mitigation.block_duration_seconds,
            # Auth
            "TOKEN_EXPIRE_MINUTES": self.auth.access_token_expire_minutes,
            # WebSocket
            "WS_INTERVAL": self.ws_broadcast_interval,
            # Scanner
            "SCAN_INTERVAL": self.scanner.scan_interval,
            "AUTO_SCAN": self.scanner.auto_scan,
        }


def write_env(updates: dict[str, str]) -> None:
    """
    Update the .env file with new key=value pairs.

    Reads the existing file, updates matching lines (or appends new ones),
    and writes back. Also updates os.environ so the process picks up changes.
    """
    # Update os.environ immediately
    for key, value in updates.items():
        os.environ[key] = str(value)

    # Read existing .env lines
    lines: list[str] = []
    if _ENV_PATH.exists():
        lines = _ENV_PATH.read_text().splitlines()

    updated_keys: set[str] = set()
    new_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        # Skip empty lines and comments — keep them as-is
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue

        # Parse KEY=VALUE
        if "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}")
                updated_keys.add(key)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    # Append any keys not already in the file
    for key, value in updates.items():
        if key not in updated_keys:
            new_lines.append(f"{key}={value}")

    _ENV_PATH.write_text("\n".join(new_lines) + "\n")


def reset_to_defaults() -> dict[str, str]:
    """Reset all settings to defaults, update .env and os.environ."""
    write_env(DEFAULTS)
    return dict(DEFAULTS)


# Singleton used throughout the application
config = AppConfig()
