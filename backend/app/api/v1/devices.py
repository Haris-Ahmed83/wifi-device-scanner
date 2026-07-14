from fastapi import APIRouter, HTTPException
from backend.app.scanner.scheduler import ScanScheduler
from typing import Optional

router = APIRouter(prefix="/devices", tags=["devices"])

scheduler: Optional[ScanScheduler] = None


def init(sc: ScanScheduler):
    global scheduler
    scheduler = sc


@router.get("")
async def get_devices():
    if not scheduler:
        return []
    return scheduler.devices


@router.get("/{mac}")
async def get_device(mac: str):
    if not scheduler:
        raise HTTPException(404, "Scanner not initialized")
    dev = scheduler.get_device_by_mac(mac)
    if not dev:
        raise HTTPException(404, f"Device {mac} not found")
    return dev


@router.get("/summary/stats")
async def get_stats():
    if not scheduler:
        return {"total": 0, "by_type": {}, "by_vendor": {}}
    devices = scheduler.devices
    by_type = {}
    by_vendor = {}
    for d in devices:
        dt = d.get("device_type", "Unknown")
        by_type[dt] = by_type.get(dt, 0) + 1
        v = d.get("vendor", "Unknown")
        by_vendor[v] = by_vendor.get(v, 0) + 1
    return {
        "total": len(devices),
        "by_type": by_type,
        "by_vendor": by_vendor,
        "subnet": scheduler._subnet,
    }
