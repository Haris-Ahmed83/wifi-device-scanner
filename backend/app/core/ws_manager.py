from fastapi import WebSocket
import logging
from typing import Any

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self._connections: dict[str, set[WebSocket]] = {
            "scans": set(),
        }

    async def connect(self, websocket: WebSocket, channel: str = "scans"):
        await websocket.accept()
        self._connections[channel].add(websocket)

    def disconnect(self, websocket: WebSocket, channel: str = "scans"):
        self._connections[channel].discard(websocket)

    async def broadcast(self, channel: str, payload: dict[str, Any]):
        dead = []
        for ws in self._connections[channel]:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections[channel].discard(ws)

    @property
    def stats(self) -> dict:
        return {ch: len(conns) for ch, conns in self._connections.items()}


manager = ConnectionManager()
