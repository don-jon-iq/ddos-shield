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

  **Simulation mode:**
  When SIMULATION_MODE=true, we skip real packet capture and instead
  generate synthetic traffic that mimics realistic network patterns,
  including periodic attack bursts.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field

from config import config
from detector import TrafficSnapshot

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

    @property
    def total(self) -> int:
        return self.syn + self.udp + self.icmp + self.http + self.arp


# ---------------------------------------------------------------------------
# Real packet capture (requires root / CAP_NET_RAW)
# ---------------------------------------------------------------------------

def _start_real_capture(counters: dict[str, _MacCounters], stop_event: asyncio.Event):
    """
    Start Scapy packet sniffing in a background thread.

    Educational note:
      Scapy's `sniff()` blocks, so we run it in a thread and use
      `stop_filter` to check our asyncio stop event.
    """
    try:
        from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, sniff  # type: ignore
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

        # Capture source IP address if present
        if pkt.haslayer(IP) and not c.ip_address:
            c.ip_address = pkt[IP].src

        if pkt.haslayer(ARP):
            c.arp += 1
        elif pkt.haslayer(TCP):
            tcp = pkt[TCP]
            # SYN flag = 0x02, check for SYN without ACK
            if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                c.syn += 1
            # HTTP on ports 80 or 443
            if tcp.dport in (80, 443) or tcp.sport in (80, 443):
                c.http += 1
        elif pkt.haslayer(UDP):
            c.udp += 1
        elif pkt.haslayer(ICMP):
            c.icmp += 1

    iface = config.sniffer.interface or None
    bpf = config.sniffer.bpf_filter or None

    logger.info("Starting real packet capture on interface=%s, filter=%s", iface, bpf)

    sniff(
        iface=iface,
        filter=bpf,
        prn=_process_packet,
        store=False,
        stop_filter=lambda _: stop_event.is_set(),
    )


# ---------------------------------------------------------------------------
# Simulation engine
# ---------------------------------------------------------------------------

# Pre-generated fake MAC addresses and their IPs for simulation
_SIM_MACS: list[str] = []
_SIM_MAC_IPS: dict[str, str] = {}
_SIM_ATTACKERS: set[str] = set()


def _init_sim_macs():
    """Generate a pool of simulated device MACs with corresponding IPs."""
    global _SIM_MACS, _SIM_MAC_IPS, _SIM_ATTACKERS
    _SIM_MACS = [
        f"AA:BB:CC:{i:02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}"
        for i in range(config.simulation.device_count)
    ]
    _SIM_MAC_IPS = {
        mac: f"192.168.1.{10 + i}" for i, mac in enumerate(_SIM_MACS)
    }
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
            attack = random.choice(["syn", "udp", "icmp", "http", "arp"])
            intensity = random.randint(200, 2000)
            setattr(c, attack, getattr(c, attack) + intensity)
            c.total_bytes += intensity * random.randint(40, 1500)
        else:
            # Normal background traffic
            c.syn += random.randint(0, 5)
            c.udp += random.randint(5, 30)
            c.icmp += random.randint(0, 3)
            c.http += random.randint(2, 20)
            c.arp += random.randint(0, 2)
            c.total_bytes += random.randint(500, 5000)


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

    async def start(self) -> None:
        """Begin capturing packets (real or simulated)."""
        self._window_start = time.time()

        if config.simulation.enabled:
            _init_sim_macs()
            logger.info(
                "Simulation mode: %d devices, attack_prob=%.2f",
                config.simulation.device_count,
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

    async def _simulation_loop(self) -> None:
        """Generate simulated traffic at regular intervals."""
        while not self._stop_event.is_set():
            _simulate_tick(self._counters)
            await asyncio.sleep(config.simulation.tick_interval)
