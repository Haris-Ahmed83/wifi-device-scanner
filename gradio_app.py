import sys
import os
import platform
import time
import gradio as gr
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

IS_CLOUD = os.environ.get("SPACE_ID") is not None

if not IS_CLOUD:
    from modules.network_scanner import arp_scan, get_local_network_info
    from modules.fingerprinter import fingerprint_device
else:
    from modules.oui_lookup import lookup_vendor
    from modules.fingerprinter import estimate_os_from_ttl, classify_device_type


DEMO_DEVICES = [
    {"ip": "192.168.1.1", "mac": "00:1A:2B:33:44:55", "vendor": "TP-Link",
     "device_type": "Router/Gateway", "os": "Linux", "confidence": "High",
     "details": ["Gateway IP address"], "ttl": 255,
     "open_ports": [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]},
    {"ip": "192.168.1.2", "mac": "08:00:27:AB:CD:EF", "vendor": "Tecno Mobile",
     "device_type": "Smartphone", "os": "Linux/Unix/Android/iOS", "confidence": "Medium",
     "details": ["Vendor: Tecno Mobile", "Likely Linux/Unix/Android/iOS"], "ttl": 64,
     "open_ports": []},
    {"ip": "192.168.1.3", "mac": "3C:58:C2:11:22:33", "vendor": "Intel",
     "device_type": "Laptop/Desktop", "os": "Windows", "confidence": "High",
     "details": ["SMB + RDP ports open"], "ttl": 128,
     "open_ports": [{"port": 135, "service": "RPC"}, {"port": 139, "service": "NetBIOS"},
                    {"port": 445, "service": "SMB"}, {"port": 3389, "service": "RDP"}]},
    {"ip": "192.168.1.4", "mac": "9C:E1:72:44:55:66", "vendor": "Infinix",
     "device_type": "Smartphone", "os": "Linux/Unix/Android/iOS", "confidence": "Medium",
     "details": ["Vendor: Infinix", "Likely Linux/Unix/Android/iOS"], "ttl": 64,
     "open_ports": []},
    {"ip": "192.168.1.5", "mac": "58:8B:F3:77:88:99", "vendor": "Apple",
     "device_type": "Smart TV / Media Device", "os": "Linux/Unix/Android/iOS", "confidence": "Medium",
     "details": ["Vendor: Apple", "RTSP + UPnP ports open"], "ttl": 64,
     "open_ports": [{"port": 554, "service": "RTSP"}, {"port": 1900, "service": "UPnP"}]},
    {"ip": "192.168.1.6", "mac": "CC:CC:CC:AA:BB:CC", "vendor": "Xiaomi",
     "device_type": "IP Camera", "os": "Linux/Unix/Android/iOS", "confidence": "High",
     "details": ["RTSP + HTTP + UPnP ports open"], "ttl": 64,
     "open_ports": [{"port": 80, "service": "HTTP"}, {"port": 554, "service": "RTSP"},
                    {"port": 1900, "service": "UPnP"}]},
]


def do_scan(progress=gr.Progress()):
    if IS_CLOUD:
        progress(0.2, desc="Demo mode: Loading sample devices...")
        time.sleep(1)
        progress(0.8, desc="Fingerprinting devices...")
        time.sleep(0.5)
        progress(1.0, desc="Complete!")
        return DEMO_DEVICES, get_summary(DEMO_DEVICES)

    progress(0.1, desc="Getting network info...")
    net_info = get_local_network_info()
    network = net_info.get("network") if net_info else None

    progress(0.2, desc="Scanning network for devices...")
    scan_results = arp_scan(network)

    if not scan_results:
        return [], "No devices found. Try running as Administrator."

    total = len(scan_results)
    devices = []

    for i, device in enumerate(scan_results):
        progress((i + 1) / total, desc=f"Fingerprinting {device.get('ip', '?')} ({i+1}/{total})...")
        gateway_ip = net_info.get("gateway") if net_info else None
        result = fingerprint_device(device.get("ip"), device.get("mac"), gateway_ip)
        devices.append(result)

    summary = get_summary(devices)
    return devices, summary


def get_summary(devices: List[Dict]) -> str:
    if not devices:
        return "No devices found."

    device_types = {}
    for d in devices:
        dt = d.get("device_type", "Unknown")
        device_types[dt] = device_types.get(dt, 0) + 1

    summary_parts = [f"**{len(devices)} devices found**"]
    for dt, count in sorted(device_types.items(), key=lambda x: -x[1]):
        summary_parts.append(f"- {count}x {dt}")

    return "\n".join(summary_parts)


def devices_to_table(devices: List[Dict]) -> List[List]:
    table = []
    for d in devices:
        ports_str = ", ".join(str(p.get("port")) for p in d.get("open_ports", [])[:5])
        if len(d.get("open_ports", [])) > 5:
            ports_str += f" +{len(d['open_ports'])-5} more"

        details_str = " | ".join(d.get("details", []))[:100]

        table.append([
            d.get("ip", "?"),
            d.get("mac", "?"),
            d.get("vendor", "Unknown"),
            d.get("device_type", "Unknown"),
            d.get("os", "Unknown"),
            d.get("confidence", "Low"),
            details_str,
            ports_str if ports_str else "None",
        ])
    return table


def get_network_info():
    if IS_CLOUD:
        return "Running on Hugging Face Spaces (Demo Mode)\nShowing sample network data"
    net_info = get_local_network_info()
    if net_info:
        return (f"Host: {net_info.get('hostname', '?')}\n"
                f"Your IP: {net_info.get('local_ip', '?')}\n"
                f"Network: {net_info.get('network', '?')}\n"
                f"Gateway: {net_info.get('gateway', '?')}")
    return "Could not detect network info"


def build_app():
    with gr.Blocks(
        title="WiFi Network Scanner",
    ) as app:
        gr.Markdown(
            "# \U0001F6E1 WiFi Network Device Scanner\n"
            "Scan your local network and identify connected devices with detailed fingerprinting."
        )

        with gr.Row():
            with gr.Column(scale=3):
                net_info_box = gr.Textbox(
                    label="Network Information",
                    value=get_network_info(),
                    lines=4,
                    interactive=False,
                )
            with gr.Column(scale=1):
                scan_btn = gr.Button("\U0001F50D Scan Network", variant="primary", size="lg")

        if IS_CLOUD:
            gr.Info(
                "\U0001F30D Running on Hugging Face Spaces - showing demo data. "
                "Download and run locally for real network scanning.",
            )

        device_table = gr.Dataframe(
            headers=["IP", "MAC", "Vendor", "Device Type", "OS", "Confidence", "Details", "Open Ports"],
            datatype=["str", "str", "str", "str", "str", "str", "str", "str"],
            column_count=8,
            label="Discovered Devices",
            interactive=False,
        )

        summary_box = gr.Markdown("Click **Scan Network** to discover devices.")

        scan_event = scan_btn.click(
            fn=do_scan,
            outputs=[device_table, summary_box],
        )

        gr.Markdown(
            "---\n"
            "### \U0001F4CB How it works\n"
            "1. **ARP Scan** - Discovers all devices on your local network\n"
            "2. **MAC OUI Lookup** - Identifies vendor from MAC address (Tecno, Infinix, Samsung, etc.)\n"
            "3. **TTL Analysis** - Pings devices to estimate OS type\n"
            "4. **Port Scanning** - Checks common ports to identify device purpose\n"
            "5. **Classification** - Combines all data to determine device type\n\n"
            "### \U0001F6E1 Privacy\n"
            "All scanning is done locally on your machine. No data is sent anywhere."
        )

    return app


app = build_app()

if __name__ == "__main__":
    app.launch(
        theme=gr.themes.Soft(primary_hue="blue", neutral_hue="slate"),
    )
