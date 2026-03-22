"""
Packet sniffing and traffic analysis engine.

Educational note:
  This module captures raw network packets using Scapy and aggregates
  them into per-MAC traffic statistics.  The analysis runs in a
  background asyncio task, producing TrafficSnapshot objects every
  `window_seconds` for the detection engine.

  **How packet sniffing works:**
  1. The NIC is placed in promiscuous mode (sees ALL frames, not just
     those addressed to it).
  2. Scapy reads raw Ethernet frames from the interface.
  3. We parse each frame's source MAC and classify the payload:
     - TCP SYN flag set → SYN counter
     - UDP → UDP counter
     - ICMP → ICMP counter
     - TCP port 80/443 → HTTP counter
     - ARP → ARP counter
  4. Every `window_seconds` we compute packets-per-second rates and
     feed them to the detector.

  **Bandwidth tracking (NEW):**
  In addition to attack-focused counters, the sniffer now tracks:
  - Per-device upload/download bytes
  - Protocol distribution (HTTP, HTTPS, DNS, SSH, etc.)
  - Connection pairs (who talks to whom)
  - DNS queries (what domains devices resolve)

  **Simulation mode:**
  When SIMULATION_MODE=true, we skip real packet capture and instead
  generate synthetic traffic that mimics realistic network patterns,
  including periodic attack bursts.

  **Real mode on macOS:**
  Requires sudo for raw packet capture. Auto-detects VM bridge
  interfaces (bridge0, vmnet*, utun*) if SNIFFER_INTERFACE is empty.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import random
import time
from dataclasses import dataclass

from config import config
from detector import TrafficSnapshot
from network_utils import get_active_interface

logger = logging.getLogger("ddos_shield.sniffer")


# ---------------------------------------------------------------------------
# Packet counters (mutable accumulator, reset each window)
# ---------------------------------------------------------------------------

@dataclass
class _MacCounters:
    """Mutable counters for one MAC within a single analysis window."""

    syn: int = 0
    udp: int = 0
    icmp: int = 0
    http: int = 0
    arp: int = 0
    total_bytes: int = 0
    ip_address: str = ""
    dst_ip: str = ""
    # Enhanced bandwidth tracking
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    http_bytes: int = 0
    https_bytes: int = 0
    dns_bytes: int = 0
    ssh_bytes: int = 0
    other_bytes: int = 0

    @property
    def total(self) -> int:
        return self.syn + self.udp + self.icmp + self.http + self.arp


# ---------------------------------------------------------------------------
# Interface detection — prefer the real LAN interface (en0, eth0)
# ---------------------------------------------------------------------------


def auto_detect_interface() -> str | None:
    """
    Auto-detect the best network interface for packet capture.

    Priority:
      1. Configured SNIFFER_INTERFACE (if non-empty)
      2. Active LAN interface (en0 on macOS, eth0 on Linux) via
         default-route detection in network_utils.
    """
    configured = config.sniffer.interface.strip()
    if configured:
        logger.info("Using configured interface: %s", configured)
        return configured

    iface = get_active_interface()
    if iface:
        logger.info("Auto-detected LAN interface: %s", iface)
        return iface

    logger.warning("No suitable interface found — Scapy will use default")
    return None


# ---------------------------------------------------------------------------
# Real packet capture (requires root / CAP_NET_RAW)
# ---------------------------------------------------------------------------

# Reference to bandwidth tracker (set during start)
_bandwidth_tracker = None


def _start_real_capture(counters: dict[str, _MacCounters], stop_event: asyncio.Event):
    """
    Start Scapy packet sniffing in a background thread.

    Educational note:
      Scapy's `sniff()` blocks, so we run it in a thread and use
      `stop_filter` to check our asyncio stop event.
      On macOS, requires sudo. On Linux, requires root or CAP_NET_RAW.
    """
    try:
        from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, DNS, DNSQR, sniff, conf  # type: ignore
    except ImportError:
        logger.error(
            "Scapy not installed. Install with: pip install scapy  "
            "Or enable SIMULATION_MODE=true"
        )
        return

    def _process_packet(pkt):
        """
        Callback invoked for each captured packet.

        Educational note:
          We dissect the Ethernet frame layer by layer:
          Ether → IP → TCP/UDP/ICMP, incrementing the appropriate counter
          for the source MAC address.
        """
        if not pkt.haslayer(Ether):
            return

        src_mac = pkt[Ether].src.upper()
        c = counters.setdefault(src_mac, _MacCounters())
        pkt_len = len(pkt)
        c.total_bytes += pkt_len
        c.bytes_sent += pkt_len
        c.packets_sent += 1

        # Capture source and destination IP addresses
        dst_port = 0
        if pkt.haslayer(IP):
            if not c.ip_address:
                c.ip_address = pkt[IP].src
            c.dst_ip = pkt[IP].dst

        if pkt.haslayer(ARP):
            c.arp += 1
        elif pkt.haslayer(TCP):
            tcp = pkt[TCP]
            dst_port = tcp.dport
            # SYN flag = 0x02, check for SYN without ACK
            if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                c.syn += 1
            # HTTP on ports 80 or 443
            if tcp.dport in (80, 443) or tcp.sport in (80, 443):
                c.http += 1

            # Protocol byte tracking
            if tcp.dport == 80 or tcp.sport == 80:
                c.http_bytes += pkt_len
            elif tcp.dport == 443 or tcp.sport == 443:
                c.https_bytes += pkt_len
            elif tcp.dport == 22 or tcp.sport == 22:
                c.ssh_bytes += pkt_len
            else:
                c.other_bytes += pkt_len

        elif pkt.haslayer(UDP):
            c.udp += 1
            udp = pkt[UDP]
            dst_port = udp.dport
            if udp.dport == 53 or udp.sport == 53:
                c.dns_bytes += pkt_len
                # DNS query logging
                if pkt.haslayer(DNSQR) and _bandwidth_tracker:
                    try:
                        domain = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                        qtype = str(pkt[DNSQR].qtype)
                        _bandwidth_tracker.record_dns_query(src_mac, c.ip_address, domain, qtype)
                    except Exception:
                        pass
            else:
                c.other_bytes += pkt_len
        elif pkt.haslayer(ICMP):
            c.icmp += 1
            c.other_bytes += pkt_len

        # Record to bandwidth tracker if available
        if _bandwidth_tracker and c.ip_address and c.dst_ip:
            _bandwidth_tracker.record_packet(
                src_mac=src_mac,
                src_ip=c.ip_address,
                dst_ip=c.dst_ip,
                dst_port=dst_port,
                protocol="TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER",
                pkt_len=pkt_len,
                is_outbound=True,
            )

    iface = auto_detect_interface()
    bpf = config.sniffer.bpf_filter or None

    # On macOS, configure Scapy to use libpcap (default on Darwin)
    if platform.system() == "Darwin":
        conf.use_pcap = True

    logger.info("Starting real packet capture on interface=%s, filter=%s", iface, bpf)

    # Check for root/sudo before attempting capture
    import os as _os
    if _os.geteuid() != 0:
        logger.error(
            "\n"
            "============================================================\n"
            "  PERMISSION DENIED: Packet capture requires root/sudo.\n"
            "  Run with:  sudo python main.py\n"
            "  Or:        sudo uvicorn main:app --host 0.0.0.0 --port 8000\n"
            "============================================================\n"
        )
        return

    try:
        sniff(
            iface=iface,
            filter=bpf,
            prn=_process_packet,
            store=False,
            stop_filter=lambda _: stop_event.is_set(),
        )
    except PermissionError:
        logger.error(
            "Permission denied for packet capture. "
            "Run with sudo: sudo python main.py"
        )
    except OSError as exc:
        logger.error("Packet capture failed: %s", exc)


# ---------------------------------------------------------------------------
# Simulation engine
# ---------------------------------------------------------------------------

# Pre-generated fake MAC addresses and their IPs for simulation
# These are now sourced from scanner.py for consistency
_SIM_MACS: list[str] = []
_SIM_MAC_IPS: dict[str, str] = {}
_SIM_ATTACKERS: set[str] = set()


def _init_sim_macs():
    """Load simulated device MACs from the scanner module for consistency."""
    global _SIM_MACS, _SIM_MAC_IPS, _SIM_ATTACKERS
    from scanner import get_sim_mac_ip_map
    _SIM_MAC_IPS = get_sim_mac_ip_map()
    _SIM_MACS = list(_SIM_MAC_IPS.keys())
    _SIM_ATTACKERS = set()


def _simulate_tick(counters: dict[str, _MacCounters]):
    """
    Generate one tick of simulated traffic.

    Educational note:
      Normal devices produce ~10-50 pps.  An "attacker" device ramps
      up to 200-2000 pps on a single protocol — exactly the kind of
      spike the detector should catch.
    """
    if not _SIM_MACS:
        _init_sim_macs()

    # Randomly promote/demote attackers
    for mac in _SIM_MACS:
        if mac not in _SIM_ATTACKERS:
            if random.random() < config.simulation.attack_probability * 0.1:
                _SIM_ATTACKERS.add(mac)
                logger.info("[SIM] %s became an attacker", mac)
        else:
            if random.random() < 0.05:  # 5% chance to stop attacking
                _SIM_ATTACKERS.discard(mac)
                logger.info("[SIM] %s stopped attacking", mac)

    for mac in _SIM_MACS:
        c = counters.setdefault(mac, _MacCounters())
        if not c.ip_address:
            c.ip_address = _SIM_MAC_IPS.get(mac, "")

        if mac in _SIM_ATTACKERS:
            # Simulated attack — pick a random attack type
            # Target a random other device's IP (simulates attacking a specific device)
            other_ips = [_SIM_MAC_IPS[m] for m in _SIM_MACS if m != mac]
            if other_ips:
                c.dst_ip = random.choice(other_ips)
            attack = random.choice(["syn", "udp", "icmp", "http", "arp"])
            intensity = random.randint(200, 2000)
            setattr(c, attack, getattr(c, attack) + intensity)
            c.total_bytes += intensity * random.randint(40, 1500)
            c.bytes_sent += intensity * random.randint(40, 1500)
            c.packets_sent += intensity
        else:
            # Normal background traffic
            c.syn += random.randint(0, 5)
            c.udp += random.randint(5, 30)
            c.icmp += random.randint(0, 3)
            c.http += random.randint(2, 20)
            c.arp += random.randint(0, 2)
            normal_bytes = random.randint(500, 5000)
            c.total_bytes += normal_bytes
            c.bytes_sent += normal_bytes
            c.packets_sent += random.randint(10, 60)
            c.bytes_received += random.randint(500, 8000)
            c.packets_received += random.randint(10, 50)
            # Protocol distribution
            c.https_bytes += random.randint(200, 3000)
            c.http_bytes += random.randint(50, 500)
            c.dns_bytes += random.randint(20, 200)
            c.ssh_bytes += random.randint(0, 100)
            c.other_bytes += random.randint(50, 500)

        # Simulate bandwidth recording
        if _bandwidth_tracker and c.ip_address:
            dst_ip = c.dst_ip or f"10.0.0.{random.randint(1,254)}"
            dst_port = random.choice([80, 443, 53, 22, 8080])
            _bandwidth_tracker.record_packet(
                src_mac=mac, src_ip=c.ip_address,
                dst_ip=dst_ip, dst_port=dst_port,
                protocol="TCP", pkt_len=random.randint(64, 1500),
                is_outbound=True,
            )


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class PacketSniffer:
    """
    Manages packet capture (real or simulated) and produces
    TrafficSnapshot lists for each analysis window.
    """

    def __init__(self) -> None:
        self._counters: dict[str, _MacCounters] = {}
        self._stop_event = asyncio.Event()
        self._capture_task: asyncio.Task | None = None
        self._window_start: float = time.time()

    async def start(self, bw_tracker=None) -> None:
        """Begin capturing packets (real or simulated)."""
        global _bandwidth_tracker
        _bandwidth_tracker = bw_tracker
        self._window_start = time.time()

        if config.simulation.enabled:
            _init_sim_macs()
            logger.info(
                "Simulation mode: %d devices, attack_prob=%.2f",
                len(_SIM_MACS),
                config.simulation.attack_probability,
            )
            self._capture_task = asyncio.create_task(self._simulation_loop())
        else:
            loop = asyncio.get_event_loop()
            self._capture_task = asyncio.ensure_future(
                loop.run_in_executor(
                    None, _start_real_capture, self._counters, self._stop_event
                )
            )

    async def stop(self) -> None:
        """Stop packet capture."""
        self._stop_event.set()
        if self._capture_task:
            self._capture_task.cancel()
            try:
                await self._capture_task
            except asyncio.CancelledError:
                pass

    def harvest_snapshots(self) -> list[TrafficSnapshot]:
        """
        Collect current window's data and reset counters.

        Returns a list of TrafficSnapshot (one per MAC) with
        packets-per-second rates computed from elapsed time.

        Educational note:
          This is a "harvest and reset" pattern — we atomically grab
          the accumulated counters and start fresh.  This avoids the
          need for complex locking between the capture thread and the
          analysis loop.
        """
        elapsed = max(time.time() - self._window_start, 0.1)
        old_counters = self._counters
        self._counters = {}
        self._window_start = time.time()

        snapshots: list[TrafficSnapshot] = []
        for mac, c in old_counters.items():
            snapshots.append(
                TrafficSnapshot(
                    mac_address=mac,
                    ip_address=c.ip_address,
                    syn_pps=c.syn / elapsed,
                    udp_pps=c.udp / elapsed,
                    icmp_pps=c.icmp / elapsed,
                    http_pps=c.http / elapsed,
                    arp_pps=c.arp / elapsed,
                    total_pps=c.total / elapsed,
                )
            )

        return snapshots

    def get_raw_counters(self) -> dict[str, dict]:
        """Return a copy of current counters for the API (non-destructive)."""
        return {
            mac: {
                "syn": c.syn,
                "udp": c.udp,
                "icmp": c.icmp,
                "http": c.http,
                "arp": c.arp,
                "total": c.total,
                "total_bytes": c.total_bytes,
                "ip_address": c.ip_address,
            }
            for mac, c in self._counters.items()
        }

    def get_destination_map(self) -> dict[str, str]:
        """Return a mapping of source MAC -> destination IP from current counters."""
        return {
            mac: c.dst_ip
            for mac, c in self._counters.items()
            if c.dst_ip
        }

    async def _simulation_loop(self) -> None:
        """Generate simulated traffic at regular intervals."""
        while not self._stop_event.is_set():
            _simulate_tick(self._counters)
            await asyncio.sleep(config.simulation.tick_interval)
