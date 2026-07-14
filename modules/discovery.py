import asyncio
import socket
import re
from typing import Dict, List, Optional
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser
from zeroconf import Zeroconf, ServiceInfo
import logging

logger = logging.getLogger(__name__)


def _parse_mdns_name(name: str) -> str:
    clean = name.split(".")[0]
    clean = clean.replace("\\000", "").replace("\\", "")
    return clean


async def discover_mdns(timeout: int = 4) -> Dict[str, dict]:
    services: Dict[str, dict] = {}
    aiozc = None

    class MDNSListener:
        def add_service(self, zc: Zeroconf, type_: str, name: str):
            try:
                info = zc.get_service_info(type_, name)
                if info:
                    addrs = [str(a) for a in info.addresses if a]
                    parsed = _parse_mdns_name(name)
                    svc_type = type_.split(".")[0].lstrip("_")
                    for addr in addrs:
                        if addr not in services:
                            services[addr] = {
                                "mdns_name": parsed,
                                "mdns_type": svc_type,
                                "mdns_server": info.server.strip(".") if info.server else None,
                                "mdns_port": info.port,
                            }
                        else:
                            if not services[addr].get("mdns_name"):
                                services[addr]["mdns_name"] = parsed
            except Exception:
                pass

        def remove_service(self, zc: Zeroconf, type_: str, name: str):
            pass

        def update_service(self, zc: Zeroconf, type_: str, name: str):
            self.add_service(zc, type_, name)

    try:
        aiozc = AsyncZeroconf(ip_version=zeroconf.IPVersion.V4Only)
        listener = MDNSListener()
        browser = AsyncServiceBrowser(aiozc.zeroconf, "_services._dns-sd._udp.local.", listener)
        await asyncio.sleep(timeout)
        await browser.async_cancel()
    except Exception as e:
        logger.warning(f"mDNS error: {e}")
    finally:
        if aiozc:
            try:
                await aiozc.async_close()
            except Exception:
                pass

    return services


async def grab_http_title(ip: str, port: int = 80, timeout: float = 2) -> Optional[str]:
    try:
        import aiohttp
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(f"http://{ip}:{port}/", allow_redirects=False) as resp:
                text = await resp.text()
                match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                if match:
                    title = match.group(1).strip()[:80]
                    if title:
                        return title
                server = resp.headers.get("Server", "")
                if server:
                    return server[:60]
    except Exception:
        pass
    return None


async def discover_devices(subnet: str = None, gateway: str = None) -> Dict[str, dict]:
    results = {}

    mdns_info = await discover_mdns(timeout=3)
    for ip, info in mdns_info.items():
        results[ip] = info

    return results
