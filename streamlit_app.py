import sys
import os
import time
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

IS_CLOUD = os.environ.get("SPACE_ID") is not None

if not IS_CLOUD:
    from modules.network_scanner import arp_scan, get_local_network_info
    from modules.fingerprinter import fingerprint_device
else:
    from modules.oui_lookup import lookup_vendor

from modules.port_scanner import COMMON_PORTS

DEMO_DEVICES = [
    {"ip": "192.168.1.1", "mac": "00:1A:2B:33:44:55", "vendor": "TP-Link",
     "device_type": "Router/Gateway", "os": "Linux", "confidence": "High",
     "ttl": 255, "open_ports": [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]},
    {"ip": "192.168.1.2", "mac": "08:00:27:AB:CD:EF", "vendor": "Tecno Mobile",
     "device_type": "Smartphone", "os": "Android", "confidence": "Medium",
     "ttl": 64, "open_ports": []},
    {"ip": "192.168.1.3", "mac": "3C:58:C2:11:22:33", "vendor": "Intel",
     "device_type": "Laptop/Desktop", "os": "Windows", "confidence": "High",
     "ttl": 128, "open_ports": [{"port": 135, "service": "RPC"}, {"port": 139, "service": "NetBIOS"},
                                {"port": 445, "service": "SMB"}, {"port": 3389, "service": "RDP"}]},
    {"ip": "192.168.1.4", "mac": "9C:E1:72:44:55:66", "vendor": "Infinix",
     "device_type": "Smartphone", "os": "Android", "confidence": "Medium",
     "ttl": 64, "open_ports": []},
    {"ip": "192.168.1.5", "mac": "58:8B:F3:77:88:99", "vendor": "Apple",
     "device_type": "Apple TV", "os": "tvOS", "confidence": "Medium",
     "ttl": 64, "open_ports": [{"port": 554, "service": "RTSP"}, {"port": 1900, "service": "UPnP"}]},
    {"ip": "192.168.1.6", "mac": "CC:CC:CC:AA:BB:CC", "vendor": "Xiaomi",
     "device_type": "IP Camera", "os": "Linux", "confidence": "High",
     "ttl": 64, "open_ports": [{"port": 80, "service": "HTTP"}, {"port": 554, "service": "RTSP"},
                               {"port": 1900, "service": "UPnP"}]},
]


def get_device_icon(device_type):
    dt = device_type.lower()
    if "router" in dt or "gateway" in dt:
        return "\U0001F3E1"
    if "phone" in dt or "smartphone" in dt or "mobile" in dt:
        return "\U0001F4F1"
    if "laptop" in dt or "desktop" in dt:
        return "\U0001F4BB"
    if "camera" in dt:
        return "\U0001F4F7"
    if "tv" in dt:
        return "\U0001F4FA"
    if "printer" in dt:
        return "\U0001F5A8"
    if "apple" in dt or "tv" in dt:
        return "\U0001F4FA"
    return "\U00002753"


st.set_page_config(
    page_title="WiFi Network Scanner",
    page_icon="\U0001F6E1",
    layout="wide",
)

st.markdown("""
<style>
.device-card {
    padding: 1rem;
    border-radius: 0.5rem;
    border: 1px solid #e0e0e0;
    margin-bottom: 0.5rem;
}
.conf-high { color: #2ECC71; font-weight: bold; }
.conf-med { color: #F1C40F; font-weight: bold; }
.conf-low { color: #E74C3C; font-weight: bold; }
.stButton > button { width: 100%; }
</style>
""", unsafe_allow_html=True)

st.title("\U0001F6E1 WiFi Network Device Scanner")
st.markdown("Scan your local network and identify connected devices with detailed fingerprinting.")

if IS_CLOUD:
    st.info("\U0001F30D Running on Hugging Face Spaces - showing demo data. Download and run locally for real network scanning.")
else:
    net_info = get_local_network_info()
    if net_info:
        col1, col2, col3 = st.columns(3)
        col1.metric("Hostname", net_info.get("hostname", "?"))
        col2.metric("Your IP", net_info.get("local_ip", "?"))
        col3.metric("Network", net_info.get("network", "?"))

if "devices" not in st.session_state:
    st.session_state.devices = []
if "scanned" not in st.session_state:
    st.session_state.scanned = False

col1, col2 = st.columns([1, 5])
with col1:
    scan_clicked = st.button("\U0001F50D Scan Network", type="primary", use_container_width=True)
with col2:
    if st.session_state.scanned:
        st.success(f"**{len(st.session_state.devices)} devices found**")

if scan_clicked:
    st.session_state.scanned = False
    st.session_state.devices = []

    with st.spinner("Discovering devices..."):
        if IS_CLOUD:
            time.sleep(1)
            devices = DEMO_DEVICES
        else:
            net_info = get_local_network_info()
            network = net_info.get("network") if net_info else None
            scan_results = arp_scan(network)
            gateway_ip = net_info.get("gateway") if net_info else None
            devices = []
            total = len(scan_results)
            progress_bar = st.progress(0, text="Starting...")
            for i, device in enumerate(scan_results):
                progress_bar.progress((i + 1) / total, text=f"Fingerprinting {device.get('ip', '?')} ({i+1}/{total})...")
                result = fingerprint_device(device.get("ip"), device.get("mac"), gateway_ip)
                devices.append(result)
            progress_bar.empty()

    st.session_state.devices = devices
    st.session_state.scanned = True
    st.rerun()

if st.session_state.devices:
    devices = st.session_state.devices

    device_types = {}
    for d in devices:
        dt = d.get("device_type", "Unknown")
        device_types[dt] = device_types.get(dt, 0) + 1

    st.subheader("\U0001F4CA Summary")
    cols = st.columns(len(device_types) if len(device_types) <= 6 else 4)
    for idx, (dt, count) in enumerate(sorted(device_types.items(), key=lambda x: -x[1])):
        with cols[idx % len(cols)]:
            st.metric(dt, count)

    st.subheader("\U0001F4CB Device Details")

    for d in devices:
        icon = get_device_icon(d.get("device_type", ""))
        conf = d.get("confidence", "Low")
        conf_class = f"conf-{conf.lower()}"

        ports_str = ", ".join(
            f"{p['port']} ({p['service']})"
            for p in d.get("open_ports", [])[:5]
        )
        if len(d.get("open_ports", [])) > 5:
            ports_str += f" +{len(d['open_ports'])-5} more"

        details_str = " | ".join(d.get("details", ["No details"])) if not IS_CLOUD else ""
        ttl_str = f", TTL: {d.get('ttl', '?')}" if d.get("ttl") else ""

        st.markdown(f"""
        <div class="device-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong style="font-size: 1.1rem;">{icon} {d.get("device_type", "Unknown")}</strong>
                    <span style="color: #666; margin-left: 1rem;">IP: {d.get("ip", "?")}</span>
                    <span style="color: #888; margin-left: 0.5rem;">MAC: {d.get("mac", "?")}</span>
                </div>
                <div>
                    <span class="{conf_class}">{conf}</span>
                </div>
            </div>
            <div style="margin-top: 0.3rem; color: #888; font-size: 0.9rem;">
                Vendor: <strong>{d.get("vendor", "Unknown")}</strong>
                | OS: {d.get("os", "Unknown")}{ttl_str}
                {f"| Ports: {ports_str}" if ports_str else "| Ports: None detected"}
                {f"| {details_str}" if details_str else ""}
            </div>
        </div>
        """, unsafe_allow_html=True)

    device_count = len(devices)
    csv_data = "IP,MAC,Vendor,Device Type,OS,Confidence,Open Ports\n"
    for d in devices:
        ports = "; ".join(f"{p['port']}" for p in d.get("open_ports", []))
        csv_data += f"{d.get('ip','')},{d.get('mac','')},{d.get('vendor','')},{d.get('device_type','')},{d.get('os','')},{d.get('confidence','')},{ports}\n"

    st.download_button(
        label="\U0001F4E5 Export as CSV",
        data=csv_data,
        file_name="wifi_devices.csv",
        mime="text/csv",
    )
else:
    st.info("\U0001F50D Click **Scan Network** to discover devices on your network.")
