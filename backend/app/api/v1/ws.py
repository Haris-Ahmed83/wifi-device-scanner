from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.app.core.ws_manager import manager

router = APIRouter()


@router.websocket("/ws/scans")
async def ws_scans(websocket: WebSocket):
    await manager.connect(websocket, "scans")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, "scans")
    except Exception:
        manager.disconnect(websocket, "scans")
