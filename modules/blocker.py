import asyncio
import logging
import platform
import subprocess
import sys
import os
import re
from typing import Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

logger = logging.getLogger(__name__)

_blocked: Dict[str, dict] = {}


async def block_device(ip: str, mac: str, gateway_ip: str, gateway_mac: Optional[str] = None) -> dict:
    if ip in _blocked:
        return {"ip": ip, "status": "already_blocked"}
    available = []
    results = {}

    result_scapy = await _try_scapy_block(ip, mac, gateway_ip, gateway_mac)
    results["scapy"] = result_scapy
    if result_scapy.get("success"):
        available.append("scapy")

    result_netsh = await _try_netsh_block(ip, mac)
    results["netsh"] = result_netsh
    if result_netsh.get("success"):
        available.append("netsh")

    if not available:
        results["message"] = ("Blocking requires Npcap (for ARP spoofing) or router admin access. "
                              f"Open http://{gateway_ip}/ in your browser, login, and block {mac} manually.")
        results["fallback_url"] = f"http://{gateway_ip}/"
        results["fallback_mac"] = mac
        results["success"] = False
        return results

    _blocked[ip] = {"ip": ip, "mac": mac, "methods": available}
    results["success"] = True
    return results


async def unblock_device(ip: str, mac: str, gateway_ip: str) -> dict:
    info = _blocked.pop(ip, None)
    results = {}

    if not info:
        results["warning"] = f"{ip} was not blocked by this app"

    result_netsh = await _try_netsh_unblock(ip)
    results["netsh"] = result_netsh

    result_scapy = await _try_scapy_unblock(ip, mac, gateway_ip)
    results["scapy"] = result_scapy

    results["success"] = True
    return results


def get_blocked_devices() -> list:
    return list(_blocked.values())


async def _try_scapy_block(ip: str, mac: str, gateway_ip: str, gateway_mac: Optional[str] = None) -> dict:
    try:
        from scapy.all import ARP, Ether, sendp, conf
        if not gateway_mac:
            gateway_result = await _resolve_mac(gateway_ip)
            if not gateway_result:
                return {"success": False, "error": "Could not resolve gateway MAC"}
            gateway_mac = gateway_result

        fake_mac = "00:00:00:00:00:01"

        pkt_to_device = Ether(dst=mac) / ARP(op=2, pdst=ip, hwdst=mac, psrc=gateway_ip, hwsrc=fake_mac)
        pkt_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=ip, hwsrc=fake_mac)

        for _ in range(5):
            sendp(pkt_to_device, verbose=False, timeout=0.1)
            sendp(pkt_to_gateway, verbose=False, timeout=0.1)
            await asyncio.sleep(0.5)

        return {"success": True, "method": "scapy_arp_spoof"}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def _try_scapy_unblock(ip: str, mac: str, gateway_ip: str) -> dict:
    try:
        from scapy.all import ARP, Ether, sendp
        gateway_mac = await _resolve_mac(gateway_ip)
        if not gateway_mac:
            return {"success": False, "error": "Could not resolve gateway MAC"}
        pkt_to_device = Ether(dst=mac) / ARP(op=2, pdst=ip, hwdst=mac, psrc=gateway_ip, hwsrc=gateway_mac)
        pkt_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=ip, hwsrc=mac)
        for _ in range(3):
            sendp(pkt_to_device, verbose=False, timeout=0.1)
            sendp(pkt_to_gateway, verbose=False, timeout=0.1)
            await asyncio.sleep(0.3)
        return {"success": True, "method": "scapy_arp_restore"}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def _resolve_mac(ip: str, timeout: float = 2) -> Optional[str]:
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=5)
            match = re.search(r"({})\s+([0-9a-fA-F-]{{17}})".format(re.escape(ip)), result.stdout)
            if match:
                return match.group(2).replace("-", ":").lower()
    except Exception:
        pass
    try:
        from scapy.all import ARP, Ether, srp
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans = srp(pkt, timeout=timeout, verbose=False)[0]
        if ans:
            return ans[0][1].hwsrc.lower()
    except Exception:
        pass
    return None


async def _try_netsh_block(ip: str, mac: str) -> dict:
    if platform.system().lower() != "windows":
        return {"success": False, "error": "netsh only available on Windows"}
    try:
        rule_name = f"Block_{ip.replace('.','_')}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=out", f"remoteip={ip}",
             "action=block", "enable=yes"],
            capture_output=True, text=True, timeout=10
        )
        return {"success": True, "method": "netsh_firewall",
                "note": f"Blocks outgoing traffic from THIS machine to {ip}. For network-wide block, use Router Admin."}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def _try_netsh_unblock(ip: str) -> dict:
    if platform.system().lower() != "windows":
        return {"success": False}
    try:
        rule_name = f"Block_{ip.replace('.','_')}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={rule_name}"],
            capture_output=True, text=True, timeout=10
        )
        return {"success": True, "method": "netsh_firewall"}
    except Exception as e:
        return {"success": False, "error": str(e)}
