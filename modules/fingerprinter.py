import subprocess
import platform
import re
from typing import Dict, List, Optional
from modules.oui_lookup import lookup_vendor
from modules.port_scanner import quick_scan


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

    if is_gateway:
        device_type = "Router/Gateway"
        confidence = "High"
        details.append("Gateway IP address")
        return {"type": device_type, "os": os_guess, "confidence": confidence, "details": details}

    router_keywords = ["tp-link", "tplink", "d-link", "dlink", "netgear", "linksys",
                       "asus", "cisco", "huawei", "zte", "zyxel", "arcadyan",
                       "sagemcom", "mikrotik", "ubiquiti", "router", "broadcom"]
    phone_keywords = ["tecno", "infinix", "xiaomi", "redmi", "realme", "oppo",
                      "oneplus", "vivo", "honor", "samsung", "huawei", "htc",
                      "nokia", "motorola", "lenovo", "lg", "sony", "google"]
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

    if has_rtsp and has_http and has_upnp:
        device_type = "IP Camera"
        confidence = "High"
        details.append("RTSP + HTTP + UPnP ports open")
    elif has_ipp or has_jetdirect:
        device_type = "Printer"
        confidence = "High"
        details.append("IPP/JetDirect port open")
    elif has_rtsp and has_upnp:
        if any(k in vendor_lower for k in tv_keywords) or os_guess == "Linux/Unix/Android/iOS":
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

    if device_type == "Unknown Device":
        if vendor == "Unknown" and not open_ports:
            device_type = "Mobile Device / Unknown"
            confidence = "Low"
            details.append("No open ports detected, likely a mobile device")
        elif any(k in vendor_lower for k in router_keywords):
            device_type = "Router/Network Device"
            confidence = "High"
            details.append(f"Vendor: {vendor}")
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
        else:
            device_type = f"{vendor} Device"
            confidence = "Low"
            details.append(f"Based on MAC vendor: {vendor}")

    return {"type": device_type, "os": os_guess, "confidence": confidence, "details": details}


def fingerprint_device(ip: str, mac: str, gateway_ip: str = None) -> Dict:
    vendor = lookup_vendor(mac)
    ttl = get_ttl(ip)
    open_ports = quick_scan(ip)

    is_gateway = (ip == gateway_ip) if gateway_ip else False

    classification = classify_device_type(ip, mac, vendor, ttl, open_ports, is_gateway)

    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "ttl": ttl,
        "os": classification["os"],
        "device_type": classification["type"],
        "confidence": classification["confidence"],
        "details": classification["details"],
        "open_ports": open_ports,
    }
