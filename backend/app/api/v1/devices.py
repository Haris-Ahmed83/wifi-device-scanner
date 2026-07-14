from fastapi import APIRouter, HTTPException
from backend.app.scanner.scheduler import ScanScheduler
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
from modules.blocker import block_device, unblock_device, get_blocked_devices

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
        "blocked": get_blocked_devices(),
    }


@router.post("/{ip}/block")
async def api_block_device(ip: str):
    if not scheduler:
        raise HTTPException(503, "Scanner not initialized")
    dev = None
    for d in scheduler.devices:
        if d.get("ip") == ip:
            dev = d
            break
    if not dev:
        raise HTTPException(404, f"Device {ip} not found")
    gw = scheduler._gateway or "192.168.1.1"
    result = await block_device(ip, dev["mac"], gw)
    return result


@router.post("/{ip}/unblock")
async def api_unblock_device(ip: str):
    if not scheduler:
        raise HTTPException(503, "Scanner not initialized")
    dev = None
    for d in scheduler.devices:
        if d.get("ip") == ip:
            dev = d
            break
    gw = scheduler._gateway or "192.168.1.1"
    mac = dev["mac"] if dev else ""
    result = await unblock_device(ip, mac, gw)
    return result
