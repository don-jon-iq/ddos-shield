"""
DDoS Shield — FastAPI application entry point.

Educational note:
  This is the main server that ties together all subsystems:
  - Packet sniffing (sniffer.py)
  - Anomaly detection (detector.py)
  - Auto-mitigation (mitigator.py)
  - WebSocket broadcasting (websocket_manager.py)
  - REST API for the dashboard

  Start the server:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

  Or in simulation mode (default):
    SIMULATION_MODE=true uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import select, func, desc

from auth import (
    LoginRequest,
    TokenResponse,
    authenticate_user,
    create_access_token,
    get_current_user,
)
from config import config
from database import async_session_factory, get_session, init_db
from detector import run_detection
from mac_vendor import is_vm_mac, lookup_vendor
from mitigator import (
    block_mac,
    get_block_expiry,
    isolate_mac,
    rate_limit_mac,
    suggested_action,
    unblock_mac,
)
from models import AttackLog, AttackType, BlockedMAC, Device, DeviceStatus, Severity
from sniffer import PacketSniffer
from vm_monitor import detect_interfaces
from websocket_manager import ws_manager

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ddos_shield")

# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------

sniffer = PacketSniffer()
_analysis_task: asyncio.Task | None = None


async def _analysis_loop():
    """
    Core analysis loop — runs every window_seconds.

    Steps each cycle:
      1. Harvest traffic snapshots from the sniffer.
      2. Update device records in the database.
      3. Run detection algorithms.
      4. Log any detected attacks.
      5. Apply auto-mitigation if enabled.
      6. Broadcast updates to WebSocket clients.
    """
    while True:
        try:
            await asyncio.sleep(config.sniffer.window_seconds)

            snapshots = sniffer.harvest_snapshots()
            if not snapshots:
                continue

            # --- Update devices ---
            async with async_session_factory() as session:
                for snap in snapshots:
                    result = await session.execute(
                        select(Device).where(Device.mac_address == snap.mac_address)
                    )
                    device = result.scalar_one_or_none()

                    now = datetime.now(timezone.utc)
                    vendor = lookup_vendor(snap.mac_address)
                    vm = is_vm_mac(snap.mac_address)

                    if device is None:
                        device = Device(
                            mac_address=snap.mac_address,
                            vendor=vendor,
                            first_seen=now,
                            last_seen=now,
                            total_packets=int(snap.total_pps * config.sniffer.window_seconds),
                            total_bytes=0,
                            status=DeviceStatus.NORMAL,
                            is_vm=vm,
                        )
                        session.add(device)
                    else:
                        device.last_seen = now
                        device.total_packets += int(snap.total_pps * config.sniffer.window_seconds)
                        device.vendor = vendor
                        device.is_vm = vm

                await session.commit()

            # --- Run detection ---
            detections = run_detection(snapshots)

            # --- Log attacks & mitigate ---
            if detections:
                async with async_session_factory() as session:
                    for det in detections:
                        attack_log = AttackLog(
                            mac_address=det.mac_address,
                            attack_type=det.attack_type,
                            severity=det.severity,
                            packets_per_second=det.packets_per_second,
                            description=det.description,
                            z_score=det.z_score,
                            mitigated=False,
                        )
                        session.add(attack_log)

                        # Update device status
                        dev_result = await session.execute(
                            select(Device).where(Device.mac_address == det.mac_address)
                        )
                        device = dev_result.scalar_one_or_none()
                        if device:
                            device.status = DeviceStatus.SUSPICIOUS

                        # Auto-mitigation
                        if config.mitigation.auto_block:
                            action = suggested_action(det.attack_type, det.packets_per_second)
                            if action == "block":
                                await block_mac(det.mac_address, reason=det.description)
                                attack_log.mitigated = True
                                if device:
                                    device.status = DeviceStatus.BLOCKED
                                # Record in blocked_macs table
                                blocked = BlockedMAC(
                                    mac_address=det.mac_address,
                                    expires_at=get_block_expiry(),
                                    reason=det.description,
                                )
                                session.add(blocked)
                            elif action == "rate_limit":
                                await rate_limit_mac(det.mac_address)
                                attack_log.mitigated = True

                    await session.commit()

                logger.warning(
                    "Detected %d attack(s): %s",
                    len(detections),
                    ", ".join(f"{d.mac_address}:{d.attack_type.value}" for d in detections),
                )

            # --- Broadcast to WebSocket clients ---
            traffic_data = []
            for snap in snapshots:
                traffic_data.append({
                    "mac_address": snap.mac_address,
                    "syn_pps": round(snap.syn_pps, 1),
                    "udp_pps": round(snap.udp_pps, 1),
                    "icmp_pps": round(snap.icmp_pps, 1),
                    "http_pps": round(snap.http_pps, 1),
                    "arp_pps": round(snap.arp_pps, 1),
                    "total_pps": round(snap.total_pps, 1),
                })

            alerts = [
                {
                    "mac_address": d.mac_address,
                    "attack_type": d.attack_type.value,
                    "severity": d.severity.value,
                    "pps": round(d.packets_per_second, 1),
                    "z_score": d.z_score,
                    "description": d.description,
                }
                for d in detections
            ]

            await ws_manager.broadcast({
                "type": "update",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "traffic": traffic_data,
                "alerts": alerts,
                "active_devices": len(snapshots),
                "ws_clients": ws_manager.client_count,
            })

        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Error in analysis loop")
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic."""
    global _analysis_task

    await init_db()
    await sniffer.start()
    _analysis_task = asyncio.create_task(_analysis_loop())
    logger.info(
        "DDoS Shield started (simulation=%s, window=%ds)",
        config.simulation.enabled,
        config.sniffer.window_seconds,
    )

    yield

    if _analysis_task:
        _analysis_task.cancel()
        try:
            await _analysis_task
        except asyncio.CancelledError:
            pass
    await sniffer.stop()
    logger.info("DDoS Shield stopped")


app = FastAPI(
    title="DDoS Shield",
    description="Educational DDoS Attack Monitoring System",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow the React dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------

class MACActionRequest(BaseModel):
    mac_address: str
    reason: str = ""


class StatusResponse(BaseModel):
    status: str
    simulation_mode: bool
    active_devices: int
    ws_clients: int
    uptime_seconds: float


_start_time = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/api/auth/login", response_model=TokenResponse, tags=["Auth"])
async def login(req: LoginRequest):
    """Authenticate and receive a JWT token."""
    user = authenticate_user(req.username, req.password)
    if user is None:
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    token = create_access_token(user)
    return TokenResponse(access_token=token)


# ---------------------------------------------------------------------------
# Dashboard endpoints
# ---------------------------------------------------------------------------

@app.get("/api/status", tags=["Dashboard"])
async def get_status():
    """System status overview."""
    elapsed = (datetime.now(timezone.utc) - _start_time).total_seconds()
    raw = sniffer.get_raw_counters()
    return {
        "status": "running",
        "simulation_mode": config.simulation.enabled,
        "active_devices": len(raw),
        "ws_clients": ws_manager.client_count,
        "uptime_seconds": round(elapsed, 1),
    }


@app.get("/api/devices", tags=["Devices"])
async def list_devices(session=Depends(get_session)):
    """List all known devices."""
    result = await session.execute(select(Device).order_by(desc(Device.last_seen)))
    devices = result.scalars().all()
    return [d.to_dict() for d in devices]


@app.get("/api/devices/{mac_address}", tags=["Devices"])
async def get_device(mac_address: str, session=Depends(get_session)):
    """Get details for a specific device."""
    result = await session.execute(
        select(Device).where(Device.mac_address == mac_address.upper())
    )
    device = result.scalar_one_or_none()
    if device is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Device not found")
    return device.to_dict()


@app.get("/api/traffic", tags=["Traffic"])
async def get_live_traffic():
    """Current traffic counters (non-destructive peek)."""
    return sniffer.get_raw_counters()


@app.get("/api/attacks", tags=["Attacks"])
async def list_attacks(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    mac_address: Optional[str] = None,
    session=Depends(get_session),
):
    """Query attack logs with optional filtering."""
    query = select(AttackLog).order_by(desc(AttackLog.timestamp))

    if severity:
        query = query.where(AttackLog.severity == Severity(severity.upper()))
    if attack_type:
        query = query.where(AttackLog.attack_type == AttackType(attack_type.upper()))
    if mac_address:
        query = query.where(AttackLog.mac_address == mac_address.upper())

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_query)).scalar()

    result = await session.execute(query.offset(offset).limit(limit))
    logs = result.scalars().all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "data": [log.to_dict() for log in logs],
    }


@app.get("/api/attacks/stats", tags=["Attacks"])
async def attack_stats(session=Depends(get_session)):
    """Aggregated attack statistics."""
    # Count by type
    type_query = select(
        AttackLog.attack_type, func.count().label("count")
    ).group_by(AttackLog.attack_type)
    type_result = await session.execute(type_query)
    by_type = {row.attack_type.value: row.count for row in type_result}

    # Count by severity
    sev_query = select(
        AttackLog.severity, func.count().label("count")
    ).group_by(AttackLog.severity)
    sev_result = await session.execute(sev_query)
    by_severity = {row.severity.value: row.count for row in sev_result}

    # Total
    total_result = await session.execute(select(func.count()).select_from(AttackLog))
    total = total_result.scalar()

    return {
        "total_attacks": total,
        "by_type": by_type,
        "by_severity": by_severity,
    }


# ---------------------------------------------------------------------------
# Mitigation endpoints (protected)
# ---------------------------------------------------------------------------

@app.post("/api/mitigate/block", tags=["Mitigation"])
async def api_block_mac(
    req: MACActionRequest,
    _user: str = Depends(get_current_user),
    session=Depends(get_session),
):
    """Block a MAC address."""
    result = await block_mac(req.mac_address, reason=req.reason)

    # Update DB
    mac = req.mac_address.upper()
    dev_result = await session.execute(select(Device).where(Device.mac_address == mac))
    device = dev_result.scalar_one_or_none()
    if device:
        device.status = DeviceStatus.BLOCKED

    blocked = BlockedMAC(
        mac_address=mac,
        expires_at=get_block_expiry(),
        reason=req.reason,
    )
    session.add(blocked)
    await session.commit()

    return result


@app.post("/api/mitigate/unblock", tags=["Mitigation"])
async def api_unblock_mac(
    req: MACActionRequest,
    _user: str = Depends(get_current_user),
    session=Depends(get_session),
):
    """Unblock a MAC address."""
    result = await unblock_mac(req.mac_address)

    mac = req.mac_address.upper()
    dev_result = await session.execute(select(Device).where(Device.mac_address == mac))
    device = dev_result.scalar_one_or_none()
    if device:
        device.status = DeviceStatus.NORMAL

    block_result = await session.execute(
        select(BlockedMAC).where(BlockedMAC.mac_address == mac)
    )
    blocked = block_result.scalar_one_or_none()
    if blocked:
        await session.delete(blocked)

    await session.commit()
    return result


@app.post("/api/mitigate/rate-limit", tags=["Mitigation"])
async def api_rate_limit(
    req: MACActionRequest,
    _user: str = Depends(get_current_user),
):
    """Apply rate limiting to a MAC address."""
    return await rate_limit_mac(req.mac_address)


@app.post("/api/mitigate/isolate", tags=["Mitigation"])
async def api_isolate(
    req: MACActionRequest,
    _user: str = Depends(get_current_user),
    session=Depends(get_session),
):
    """Fully isolate a MAC address."""
    result = await isolate_mac(req.mac_address)

    mac = req.mac_address.upper()
    dev_result = await session.execute(select(Device).where(Device.mac_address == mac))
    device = dev_result.scalar_one_or_none()
    if device:
        device.status = DeviceStatus.BLOCKED
    await session.commit()

    return result


@app.get("/api/blocked", tags=["Mitigation"])
async def list_blocked(session=Depends(get_session)):
    """List all currently blocked MACs."""
    result = await session.execute(select(BlockedMAC))
    blocked = result.scalars().all()
    return [b.to_dict() for b in blocked]


# ---------------------------------------------------------------------------
# Network interfaces
# ---------------------------------------------------------------------------

@app.get("/api/interfaces", tags=["Network"])
async def list_interfaces():
    """List detected network interfaces (physical and virtual)."""
    interfaces = detect_interfaces()
    return [
        {
            "name": i.name,
            "is_virtual": i.is_virtual,
            "mac_address": i.mac_address,
            "status": i.status,
        }
        for i in interfaces
    ]


# ---------------------------------------------------------------------------
# Educational content
# ---------------------------------------------------------------------------

ATTACK_EXPLANATIONS = {
    "SYN_FLOOD": {
        "name": "SYN Flood",
        "description": (
            "A SYN Flood exploits the TCP three-way handshake. The attacker sends "
            "a massive number of SYN (synchronize) packets to a target, but never "
            "completes the handshake by sending the final ACK. This fills the target's "
            "connection table with half-open connections, preventing legitimate users "
            "from connecting."
        ),
        "how_it_works": [
            "1. Attacker sends SYN packet to target",
            "2. Target responds with SYN-ACK and allocates resources",
            "3. Attacker never sends the final ACK",
            "4. Target's connection table fills up",
            "5. Legitimate connections are refused",
        ],
        "indicators": [
            "High rate of TCP SYN packets from a single source",
            "Many half-open connections on the target",
            "SYN-to-ACK ratio heavily skewed toward SYN",
        ],
        "mitigation": [
            "SYN cookies (stateless SYN handling)",
            "Reduce SYN-RECEIVED timeout",
            "Increase backlog queue size",
            "Rate-limit SYN packets per source",
            "Use a reverse proxy or CDN with DDoS protection",
        ],
        "severity": "HIGH",
        "layer": "Layer 4 (Transport)",
    },
    "UDP_FLOOD": {
        "name": "UDP Flood",
        "description": (
            "A UDP Flood overwhelms the target by sending a large volume of UDP "
            "datagrams to random ports. Since UDP is connectionless, the target must "
            "check for listening applications on each port and respond with ICMP "
            "'Destination Unreachable' when none is found — consuming bandwidth and CPU."
        ),
        "how_it_works": [
            "1. Attacker sends UDP packets to random ports on target",
            "2. Target checks each port for a listening application",
            "3. No application found → target sends ICMP port unreachable",
            "4. This consumes CPU, memory, and bandwidth",
            "5. Legitimate traffic is starved of resources",
        ],
        "indicators": [
            "Spike in UDP packets from one or few sources",
            "High volume of ICMP 'port unreachable' responses",
            "Bandwidth saturation",
        ],
        "mitigation": [
            "Rate-limit UDP traffic per source",
            "Block traffic on unused UDP ports",
            "Use deep packet inspection (DPI)",
            "Deploy upstream filtering (ISP-level)",
        ],
        "severity": "HIGH",
        "layer": "Layer 4 (Transport)",
    },
    "ICMP_FLOOD": {
        "name": "ICMP Flood (Ping Flood)",
        "description": (
            "An ICMP Flood sends an overwhelming number of ICMP Echo Request (ping) "
            "packets. The target must process each request and send an Echo Reply, "
            "consuming bandwidth in both directions. Variants include Ping of Death "
            "and Smurf attacks."
        ),
        "how_it_works": [
            "1. Attacker sends rapid ICMP Echo Requests to target",
            "2. Target replies to each with ICMP Echo Reply",
            "3. Both inbound and outbound bandwidth consumed",
            "4. CPU spent processing ICMP stack",
            "5. Network becomes congested or unresponsive",
        ],
        "indicators": [
            "Abnormally high ICMP traffic volume",
            "Ping response times spike across the network",
            "Bandwidth graphs show ICMP dominating",
        ],
        "mitigation": [
            "Rate-limit ICMP at the firewall",
            "Disable ICMP Echo Reply (if not needed)",
            "Use ingress filtering (BCP38)",
            "Configure routers to drop oversized ICMP packets",
        ],
        "severity": "MEDIUM",
        "layer": "Layer 3 (Network)",
    },
    "HTTP_FLOOD": {
        "name": "HTTP Flood",
        "description": (
            "An HTTP Flood is a Layer 7 attack that sends a large number of "
            "seemingly legitimate HTTP requests (GET or POST) to a web server. "
            "Because each request looks normal, it's harder to detect than "
            "volumetric attacks. The server exhausts CPU and memory processing "
            "each request."
        ),
        "how_it_works": [
            "1. Attacker uses bots to send valid HTTP requests",
            "2. Each request completes the full TCP handshake",
            "3. Server processes each request (database queries, page renders)",
            "4. Server resources (CPU, RAM, connections) are exhausted",
            "5. Legitimate users experience slow or no response",
        ],
        "indicators": [
            "Spike in HTTP requests per second",
            "Web server CPU/memory at 100%",
            "Many requests from few source MACs/IPs",
            "Unusual request patterns (same URL, no referrer)",
        ],
        "mitigation": [
            "Web Application Firewall (WAF)",
            "CAPTCHA challenges for suspicious traffic",
            "Rate limiting per source IP/MAC",
            "JavaScript challenges to filter bots",
            "CDN with DDoS protection (e.g., Cloudflare)",
        ],
        "severity": "HIGH",
        "layer": "Layer 7 (Application)",
    },
    "ARP_SPOOF": {
        "name": "ARP Spoofing",
        "description": (
            "ARP Spoofing sends forged ARP (Address Resolution Protocol) messages "
            "to link the attacker's MAC address with a legitimate IP address (often "
            "the gateway). This allows the attacker to intercept, modify, or stop "
            "traffic — a classic Man-in-the-Middle (MitM) attack."
        ),
        "how_it_works": [
            "1. Attacker sends fake ARP replies: 'Gateway IP is at MY MAC'",
            "2. Victim updates ARP cache with attacker's MAC",
            "3. Victim's traffic now flows through attacker",
            "4. Attacker can sniff, modify, or drop packets",
            "5. Can also cause denial of service by dropping all traffic",
        ],
        "indicators": [
            "Multiple MACs claiming the same IP (ARP cache conflicts)",
            "High rate of unsolicited ARP replies",
            "Gateway MAC address changes unexpectedly",
        ],
        "mitigation": [
            "Static ARP entries for critical devices (gateway)",
            "Dynamic ARP Inspection (DAI) on managed switches",
            "Use encrypted protocols (HTTPS, SSH) to prevent sniffing",
            "802.1X port authentication",
            "ARP monitoring tools (arpwatch)",
        ],
        "severity": "CRITICAL",
        "layer": "Layer 2 (Data Link)",
    },
}


@app.get("/api/educational/{attack_type}", tags=["Educational"])
async def get_attack_explanation(attack_type: str):
    """Get a detailed educational explanation of an attack type."""
    key = attack_type.upper()
    if key not in ATTACK_EXPLANATIONS:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Unknown attack type: {attack_type}")
    return ATTACK_EXPLANATIONS[key]


@app.get("/api/educational", tags=["Educational"])
async def list_attack_types():
    """List all attack types with brief descriptions."""
    return {
        key: {"name": val["name"], "layer": val["layer"], "severity": val["severity"]}
        for key, val in ATTACK_EXPLANATIONS.items()
    }


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time dashboard updates.

    Educational note:
      The client connects once and receives push updates every
      analysis window.  The message format is:
      {
        "type": "update",
        "timestamp": "...",
        "traffic": [...],
        "alerts": [...],
        "active_devices": N,
        "ws_clients": N
      }
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive — client can send pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
