import asyncio
import logging
import sys
import os
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from modules.network_scanner import arp_scan, get_local_network_info, resolve_hostname
from modules.fingerprinter import fingerprint_device
from backend.app.core.ws_manager import manager

logger = logging.getLogger(__name__)


class ScanScheduler:
    def __init__(self, interval: int = 60):
        self.interval = interval
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._devices: list[dict] = []
        self._subnet: Optional[str] = None
        self._gateway: Optional[str] = None

    async def start(self):
        net_info = get_local_network_info()
        if net_info and net_info["network"] != "unknown":
            self._subnet = net_info["network"]
            self._gateway = net_info["gateway"]
        else:
            logger.error("Could not detect network")
            return

        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info(f"Background scanner started on {self._subnet}")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    @property
    def devices(self) -> list[dict]:
        return self._devices

    async def scan_once(self) -> list[dict]:
        loop = asyncio.get_event_loop()
        raw_devices = await loop.run_in_executor(None, lambda: arp_scan(self._subnet))
        discovered = []

        for i, dev in enumerate(raw_devices):
            result = await loop.run_in_executor(
                None,
                lambda d=dev: fingerprint_device(d["ip"], d["mac"], self._gateway)
            )
            hostname = await loop.run_in_executor(None, lambda ip=dev["ip"]: resolve_hostname(ip))
            result["hostname"] = hostname
            result["last_seen"] = datetime.now(timezone.utc).isoformat()
            discovered.append(result)

            await manager.broadcast("scans", {
                "type": "device_discovered",
                "device": result,
            })

        self._devices = discovered
        await manager.broadcast("scans", {
            "type": "scan_complete",
            "summary": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "devices_found": len(discovered),
                "subnet": self._subnet,
            }
        })

        return discovered

    async def _loop(self):
        while self._running:
            try:
                await self.scan_once()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scan error: {e}")
            await asyncio.sleep(self.interval)

    def get_device_by_mac(self, mac: str) -> Optional[dict]:
        for d in self._devices:
            if d.get("mac") == mac:
                return d
        return None
