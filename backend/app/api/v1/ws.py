import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.app.core.ws_manager import manager

router = APIRouter()


@router.websocket("/ws/scans")
async def ws_scans(websocket: WebSocket):
    await manager.connect(websocket, "scans")
    try:
        async def heartbeat():
            while True:
                await asyncio.sleep(15)
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break

        hb = asyncio.create_task(heartbeat())
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        hb.cancel()
        manager.disconnect(websocket, "scans")
