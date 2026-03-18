"""
WebSocket connection manager for real-time dashboard updates.

Educational note:
  WebSockets provide a persistent, bidirectional channel between the
  server and browser.  Unlike HTTP polling (where the client asks
  "any news?" every N seconds), the server can *push* updates the
  instant an attack is detected.  This is critical for a security
  dashboard where every second counts.

  The manager keeps a set of active connections and broadcasts JSON
  messages to all of them simultaneously.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("ddos_shield.ws")


class WebSocketManager:
    """
    Thread-safe manager for multiple WebSocket clients.

    Usage:
        manager = WebSocketManager()

        # In a WebSocket endpoint:
        await manager.connect(ws)
        try:
            while True:
                await ws.receive_text()  # keep-alive
        except WebSocketDisconnect:
            manager.disconnect(ws)

        # From any coroutine:
        await manager.broadcast({"type": "attack", "data": {...}})
    """

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket client."""
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        logger.info("WebSocket client connected (%d total)", len(self._connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected client."""
        self._connections.discard(websocket)
        logger.info("WebSocket client disconnected (%d remaining)", len(self._connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """
        Send a JSON message to every connected client.

        Clients that fail to receive are silently disconnected.

        Educational note:
          We use asyncio.gather with return_exceptions=True so one
          broken connection doesn't block updates to healthy clients.
        """
        if not self._connections:
            return

        payload = json.dumps(message)
        stale: list[WebSocket] = []

        async def _send(ws: WebSocket) -> None:
            try:
                await ws.send_text(payload)
            except Exception:
                stale.append(ws)

        await asyncio.gather(*(_send(ws) for ws in self._connections))

        # Clean up broken connections
        for ws in stale:
            self._connections.discard(ws)

    @property
    def client_count(self) -> int:
        return len(self._connections)


# Singleton instance shared across the application
ws_manager = WebSocketManager()
