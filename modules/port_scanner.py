import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    514: "Syslog",
    554: "RTSP",
    631: "IPP (Printer)",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1723: "PPTP",
    1883: "MQTT",
    1900: "UPnP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9100: "JetDirect (Printer)",
}


def scan_port(ip: str, port: int, timeout: float = 0.5) -> Dict:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect((ip, port))
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:50]
                sock.close()
            except Exception:
                banner = ""
            return {"port": port, "service": service, "open": True, "banner": banner}
    except Exception:
        pass
    return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "open": False, "banner": ""}


def scan_common_ports(ip: str, ports: List[int] = None) -> List[Dict]:
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)
        for result in results:
            if result["open"]:
                open_ports.append(result)

    return sorted(open_ports, key=lambda x: x["port"])


def quick_scan(ip: str) -> List[Dict]:
    quick_ports = [22, 80, 135, 139, 443, 445, 554, 631, 3389, 8080, 8443, 9100]
    return scan_common_ports(ip, quick_ports)
