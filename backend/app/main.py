import sys
import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from backend.app.config import get_settings
from backend.app.scanner.scheduler import ScanScheduler
from backend.app.api.v1 import devices as devices_router
from backend.app.api.v1 import ws as ws_router
from backend.app.api.v1 import network as network_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

scheduler: ScanScheduler | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global scheduler
    settings = get_settings()
    scheduler = ScanScheduler(interval=settings.scan_interval)
    await scheduler.start()
    devices_router.init(scheduler)
    yield
    if scheduler:
        await scheduler.stop()


app = FastAPI(
    title="WiFi Network Device Scanner",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api = FastAPI(title="API")
api.include_router(devices_router.router)
api.include_router(network_router.router)
api.include_router(ws_router.router)


@api.get("/health")
async def health():
    return {
        "status": "ok",
        "devices_count": len(scheduler.devices) if scheduler else 0,
        "ws_connections": scheduler._running if scheduler else False,
    }


@api.get("/scan")
async def trigger_scan():
    if scheduler:
        await scheduler.scan_once()
        return {"status": "started", "devices_count": len(scheduler.devices)}
    return {"status": "error", "message": "Scanner not initialized"}


app.mount("/api/v1", api)

frontend_dir = Path(__file__).parent.parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
