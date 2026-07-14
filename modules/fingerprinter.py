import subprocess
import platform
import re
from typing import Dict, List, Optional
from modules.oui_lookup import lookup_vendor
from modules.port_scanner import quick_scan
from modules.network_scanner import resolve_hostname


def get_ttl(ip: str) -> Optional[int]:
    system = platform.system().lower()
    try:
        if system == "windows":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "2000", ip],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r"TTL=(\d+)", result.stdout, re.IGNORECASE)
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", ip],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)

        if match:
            return int(match.group(1))
    except Exception:
        pass
    return None


def estimate_os_from_ttl(ttl: int) -> str:
    if ttl is None:
        return "Unknown"
    if ttl <= 64 and ttl > 32:
        return "Linux/Unix/Android/iOS"
    elif ttl <= 128 and ttl > 64:
        return "Windows"
    elif ttl <= 255 and ttl > 128:
        return "Network Device (Router/Switch)"
    return "Unknown"


def _is_likely_gateway_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) == 4:
        last = parts[3]
        if last == "1" or last == "254":
            return True
    return False


def classify_device_type(
    ip: str,
    mac: str,
    vendor: str,
    ttl: Optional[int],
    open_ports: List[Dict],
    is_gateway: bool = False
) -> Dict:
    vendor_lower = vendor.lower()
    os_guess = estimate_os_from_ttl(ttl) if ttl else "Unknown"

    open_port_numbers = [p["port"] for p in open_ports]
    open_service_names = [p["service"].lower() for p in open_ports]

    device_type = "Unknown Device"
    confidence = "Low"
    details = []

    router_keywords = ["tp-link", "tplink", "d-link", "dlink", "netgear", "linksys",
                       "cisco", "zte", "zyxel", "arcadyan",
                       "sagemcom", "mikrotik", "ubiquiti", "broadcom"]
    phone_keywords = ["tecno", "infinix", "xiaomi", "redmi", "realme", "oppo",
                      "oneplus", "vivo", "honor", "samsung", "huawei", "htc",
                      "nokia", "motorola", "lg", "sony", "google"]
    laptop_keywords = ["dell", "hp", "hewlett", "lenovo", "apple", "asus",
                       "acer", "toshiba", "microsoft", "fujitsu", "msi"]
    printer_keywords = ["hp", "epson", "canon", "brother", "kyocera", "xerox",
                        "samsung", "oki", "printer"]
    camera_keywords = ["hikvision", "dahua", "axis", "geovision", "camera", "cctv"]
    tv_keywords = ["samsung", "lg", "sony", "tcl", "hisense", "panasonic",
                   "philips", "xiaomi", "vizio", "tv", "television"]

    has_rtsp = 554 in open_port_numbers
    has_ipp = 631 in open_port_numbers
    has_jetdirect = 9100 in open_port_numbers
    has_rdp = 3389 in open_port_numbers
    has_smb = 139 in open_port_numbers or 445 in open_port_numbers
    has_ssh = 22 in open_port_numbers
    has_http = 80 in open_port_numbers or 443 in open_port_numbers or 8080 in open_port_numbers
    has_upnp = 1900 in open_port_numbers
    has_dns = 53 in open_port_numbers
    has_dhcp = 67 in open_port_numbers or 68 in open_port_numbers
    is_router_ip = is_gateway or _is_likely_gateway_ip(ip)
    only_http = len(open_ports) == 1 and has_http

    if is_gateway or (is_router_ip and only_http):
        device_type = "Router/Network Device"
        confidence = "High" if is_gateway else "Medium"
        if is_gateway:
            details.append("Gateway IP address")
        else:
            details.append(f"Likely gateway (IP ends in .{ip.split('.')[-1]})")
        if has_http:
            details.append("Web interface detected (port 80/443)")
        if vendor != "Unknown":
            details.append(f"Vendor: {vendor}")
        return {"type": device_type, "os": os_guess, "confidence": confidence, "details": details}

    if has_rtsp and has_http and has_upnp:
        device_type = "IP Camera"
        confidence = "High"
        details.append("RTSP + HTTP + UPnP ports open")
    elif has_ipp or has_jetdirect:
        device_type = "Printer"
        confidence = "High"
        details.append("IPP/JetDirect port open")
    elif has_rtsp and has_upnp:
        if any(k in vendor_lower for k in tv_keywords):
            device_type = "Smart TV / Media Device"
            confidence = "Medium"
            details.append("RTSP + UPnP ports open")
        else:
            device_type = "IP Camera / Media Device"
            confidence = "Medium"
            details.append("RTSP + UPnP ports open")
    elif has_smb and has_rdp:
        device_type = "Windows Laptop/Desktop"
        confidence = "High"
        details.append("SMB + RDP ports open")
    elif has_smb:
        device_type = "Windows Device"
        confidence = "High"
        details.append("SMB port open")
    elif has_ssh and os_guess != "Windows":
        device_type = "Linux Device / Server"
        confidence = "High"
        details.append("SSH port open")
    elif has_rdp:
        device_type = "Windows Device"
        confidence = "Medium"
        details.append("RDP port open")
    elif only_http and (vendor == "Unknown" or any(k in vendor_lower for k in router_keywords)):
        device_type = "Router/Network Device"
        confidence = "Medium"
        details.append("Web interface only (likely router/network device)")
        if vendor != "Unknown":
            details.append(f"Vendor: {vendor}")
    elif has_http and ttl is not None and ttl > 64:
        device_type = "Network Device"
        confidence = "Low"
        details.append(f"HTTP port open, TTL suggests network device")

    if device_type == "Unknown Device":
        if vendor == "Unknown" and not open_ports:
            device_type = "Mobile Device / Unknown"
            confidence = "Low"
            details.append("No open ports detected, likely a mobile device")
        elif any(k in vendor_lower for k in phone_keywords):
            device_type = "Smartphone"
            confidence = "Medium"
            details.append(f"Vendor: {vendor}")
            if os_guess not in ("Unknown", "Windows"):
                details.append(f"Likely {os_guess}")
        elif any(k in vendor_lower for k in laptop_keywords):
            device_type = "Laptop/Desktop"
            confidence = "Medium"
            details.append(f"Vendor: {vendor}")
        elif any(k in vendor_lower for k in tv_keywords):
            device_type = "Smart TV"
            confidence = "Medium"
            details.append(f"Vendor: {vendor}")
        elif any(k in vendor_lower for k in router_keywords):
            device_type = "Router/Network Device"
            confidence = "High"
            details.append(f"Vendor: {vendor}")
        else:
            device_type = f"{vendor} Device"
            confidence = "Low"
            if vendor != "Unknown":
                details.append(f"Based on MAC vendor: {vendor}")
            elif open_ports:
                svc = ", ".join(f"port {p}" for p in open_port_numbers[:3])
                details.append(f"Open ports: {svc}")
                device_type = "Unknown Device"
            else:
                details.append("No identification data available")

    return {"type": device_type, "os": os_guess, "confidence": confidence, "details": details}


def fingerprint_device(ip: str, mac: str, gateway_ip: str = None) -> Dict:
    vendor = lookup_vendor(mac)
    ttl = get_ttl(ip)
    open_ports = quick_scan(ip)

    is_gateway = (ip == gateway_ip) if gateway_ip else False

    classification = classify_device_type(ip, mac, vendor, ttl, open_ports, is_gateway)

    hostname = resolve_hostname(ip)

    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": vendor,
        "ttl": ttl,
        "os": classification["os"],
        "device_type": classification["type"],
        "confidence": classification["confidence"],
        "details": classification["details"],
        "open_ports": open_ports,
    }
