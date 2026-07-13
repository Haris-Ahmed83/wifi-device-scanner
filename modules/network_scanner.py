import socket
import subprocess
import re
import ipaddress
import platform
from typing import List, Dict, Optional, Tuple


def get_local_network_info() -> Optional[Dict]:
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        parts = local_ip.split(".")
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        gateway = f"{parts[0]}.{parts[1]}.{parts[2]}.1"

        return {
            "hostname": hostname,
            "local_ip": local_ip,
            "network": network,
            "gateway": gateway,
        }
    except Exception as e:
        return {"hostname": "unknown", "local_ip": "unknown", "network": "unknown", "gateway": "unknown"}


def get_arp_table() -> List[Dict]:
    devices = []
    system = platform.system().lower()

    try:
        if system == "windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split("\n")
            for line in lines:
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17,})", line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":")
                    if mac != "ff:ff:ff:ff:ff:ff" and ip:
                        devices.append({"ip": ip, "mac": mac.lower()})
        else:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split("\n")
            for line in lines:
                match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).lower()
                    if mac != "ff:ff:ff:ff:ff:ff":
                        devices.append({"ip": ip, "mac": mac})
    except Exception:
        pass

    return devices


def arp_scan(network: str = None) -> List[Dict]:
    devices = []

    if network is None or network == "unknown":
        net_info = get_local_network_info()
        if net_info and net_info["network"] != "unknown":
            network = net_info["network"]
        else:
            return get_arp_table()

    try:
        net = ipaddress.IPv4Network(network, strict=False)
        from scapy.all import ARP, Ether, srp

        arp_request = ARP(pdst=str(net))
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        answered = srp(packet, timeout=3, verbose=False)[0]

        for sent, received in answered:
            devices.append({"ip": received.psrc, "mac": received.hwsrc.lower()})
    except Exception:
        devices = get_arp_table()

    return devices
