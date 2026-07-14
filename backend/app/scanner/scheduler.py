import asyncio
import logging
import sys
import os
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from modules.network_scanner import arp_scan, get_local_network_info, resolve_hostname
from modules.fingerprinter import get_ttl, classify_device_type
from modules.oui_lookup import lookup_vendor
from modules.port_scanner import quick_scan
from modules.discovery import discover_mdns, grab_http_title
from backend.app.core.ws_manager import manager

logger = logging.getLogger(__name__)


class ScanScheduler:
    def __init__(self, interval: int = 120):
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

    async def _fingerprint_one(self, loop, ip, mac, mdns_map, http_titles):
        ttl = await loop.run_in_executor(None, lambda: get_ttl(ip))
        vendor = lookup_vendor(mac)
        open_ports = await loop.run_in_executor(None, lambda: quick_scan(ip))
        is_gateway = (ip == self._gateway) if self._gateway else False
        classification = classify_device_type(ip, mac, vendor, ttl, open_ports, is_gateway)
        hostname = await loop.run_in_executor(None, lambda: resolve_hostname(ip))

        mdns = mdns_map.get(ip, {})
        mdns_name = mdns.get("mdns_name")
        mdns_type = mdns.get("mdns_type")
        http_title = http_titles.get(ip)

        final_hostname = mdns_name or hostname
        details = classification["details"]

        if mdns_name and mdns_name != hostname:
            details = [f"mDNS: {mdns_name}"] + details
        if http_title:
            details.append(f"Web title: {http_title}")
        if mdns_type:
            if classification["type"] in ("Unknown Device", f"{vendor} Device"):
                pass

        return {
            "ip": ip,
            "mac": mac,
            "hostname": final_hostname,
            "vendor": vendor,
            "ttl": ttl,
            "os": classification["os"],
            "device_type": classification["type"],
            "confidence": classification["confidence"],
            "details": details,
            "open_ports": open_ports,
            "mdns_name": mdns_name,
            "http_title": http_title,
            "last_seen": datetime.now(timezone.utc).isoformat(),
        }

    async def scan_once(self) -> list[dict]:
        loop = asyncio.get_event_loop()
        raw_devices = await loop.run_in_executor(None, lambda: arp_scan(self._subnet))

        if not raw_devices:
            self._devices = []
            await manager.broadcast("scans", {
                "type": "scan_complete",
                "summary": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "devices_found": 0,
                    "subnet": self._subnet,
                }
            })
            return []

        mdns_task = asyncio.create_task(discover_mdns(timeout=3))
        http_tasks = {}
        for d in raw_devices:
            http_tasks[d["ip"]] = asyncio.create_task(grab_http_title(d["ip"], 80, 1.5))

        mdns_map = await mdns_task
        http_titles = {}
        for ip, task in http_tasks.items():
            try:
                title = await task
                if title:
                    http_titles[ip] = title
            except Exception:
                pass

        tasks = [self._fingerprint_one(loop, d["ip"], d["mac"], mdns_map, http_titles) for d in raw_devices]
        discovered = await asyncio.gather(*tasks)

        for result in discovered:
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
        first = True
        while self._running:
            try:
                if not first:
                    await asyncio.sleep(self.interval)
                first = False
                await self.scan_once()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scan error: {e}")

    def get_device_by_mac(self, mac: str) -> Optional[dict]:
        for d in self._devices:
            if d.get("mac") == mac:
                return d
        return None
