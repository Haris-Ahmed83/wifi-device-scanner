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
    {"ip": "192.168.1.1", "mac": "c0:8b:05:1a:c3:4c", "vendor": "HUAWEI TECHNOLOGIES CO.,LTD",
     "hostname": "router", "device_type": "Router/Network Device", "os": "Linux/Unix/Android/iOS", "confidence": "High",
     "ttl": 64, "details": ["Gateway IP address", "Web interface detected (port 80/443)", "Vendor: HUAWEI TECHNOLOGIES CO.,LTD"],
     "open_ports": [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]},
    {"ip": "192.168.1.2", "mac": "2c:a7:ef:11:22:33", "vendor": "OnePlus Technology (Shenzhen) Co., Ltd",
     "hostname": "oneplus-phone", "device_type": "Smartphone", "os": "Linux/Unix/Android/iOS", "confidence": "Medium",
     "ttl": 64, "details": ["Vendor: OnePlus Technology (Shenzhen) Co., Ltd", "Likely Linux/Unix/Android/iOS"],
     "open_ports": []},
    {"ip": "192.168.1.3", "mac": "00:06:5b:11:22:33", "vendor": "Dell Inc.",
     "hostname": "DESKTOP-PC", "device_type": "Windows Laptop/Desktop", "os": "Windows", "confidence": "High",
     "ttl": 128, "details": ["SMB + RDP ports open"],
     "open_ports": [{"port": 135, "service": "RPC"}, {"port": 139, "service": "NetBIOS"},
                    {"port": 445, "service": "SMB"}, {"port": 3389, "service": "RDP"}]},
    {"ip": "192.168.1.4", "mac": "00:9e:c8:44:55:66", "vendor": "Xiaomi Communications Co Ltd",
     "hostname": "xiaomi-camera", "device_type": "IP Camera", "os": "Linux/Unix/Android/iOS", "confidence": "High",
     "ttl": 64, "details": ["RTSP + HTTP + UPnP ports open"],
     "open_ports": [{"port": 80, "service": "HTTP"}, {"port": 554, "service": "RTSP"},
                    {"port": 1900, "service": "UPnP"}]},
    {"ip": "192.168.1.5", "mac": "00:03:93:77:88:99", "vendor": "Apple, Inc.",
     "hostname": "apple-tv", "device_type": "Smart TV / Media Device", "os": "Linux/Unix/Android/iOS", "confidence": "Medium",
     "ttl": 64, "details": ["RTSP + UPnP ports open"],
     "open_ports": [{"port": 554, "service": "RTSP"}, {"port": 1900, "service": "UPnP"}]},
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
    if "tv" in dt or "media" in dt:
        return "\U0001F4FA"
    if "printer" in dt:
        return "\U0001F5A8"
    if "apple" in dt:
        return "\U0001F4FA"
    if "unknown" in dt:
        return "\U00002753"
    return "\U0001F4E1"


def device_card(d, idx):
    icon = get_device_icon(d.get("device_type", ""))
    conf = d.get("confidence", "Low")
    conf_colors = {"High": "#2ECC71", "Medium": "#F1C40F", "Low": "#E74C3C"}
    hostname = d.get("hostname") or d.get("ip", "?")

    with st.expander(f"{icon} {hostname} — {d.get('device_type', 'Unknown')}    {d.get('ip', '?')}  {conf}", expanded=False):
        col1, col2 = st.columns([1, 1])
        with col1:
            st.markdown(f"**MAC Address:** `{d.get('mac', '?')}`")
            st.markdown(f"**Vendor:** {d.get('vendor', 'Unknown')}")
            st.markdown(f"**TTL:** {d.get('ttl', '?')}")
        with col2:
            st.markdown(f"**OS:** {d.get('os', 'Unknown')}")
            st.markdown(f"**Confidence:** :{conf_colors.get(conf, '#888')}[{conf}]")
            st.markdown(f"**Hostname:** {hostname}")

        st.markdown("---")
        ports = d.get("open_ports", [])
        if ports:
            st.markdown("**Open Ports:**")
            pcols = st.columns(4)
            for i, p in enumerate(ports):
                with pcols[i % 4]:
                    st.code(f"{p['port']} ({p['service']})")
        else:
            st.markdown("**Open Ports:** None detected")

        details = d.get("details", [])
        if details:
            st.markdown("**Details:**")
            for det in details:
                st.markdown(f"- {det}")


st.set_page_config(
    page_title="WiFi Network Scanner",
    page_icon="\U0001F6E1",
    layout="wide",
)

st.markdown("""
<style>
.stExpander {
    border: 1px solid #e0e0e0;
    border-radius: 0.5rem;
    margin-bottom: 0.3rem;
}
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
    st.markdown("Click on a device to expand and see full details.")

    for idx, d in enumerate(devices):
        device_card(d, idx)

    csv_data = "IP,MAC,Hostname,Vendor,Device Type,OS,Confidence,TTL,Open Ports\n"
    for d in devices:
        ports = "; ".join(f"{p['port']}" for p in d.get("open_ports", []))
        csv_data += f"{d.get('ip','')},{d.get('mac','')},{d.get('hostname','')},{d.get('vendor','')},{d.get('device_type','')},{d.get('os','')},{d.get('confidence','')},{d.get('ttl','')},{ports}\n"

    st.download_button(
        label="\U0001F4E5 Export as CSV",
        data=csv_data,
        file_name="wifi_devices.csv",
        mime="text/csv",
    )
else:
    if not scan_clicked:
        st.info("\U0001F50D Click **Scan Network** to discover devices on your network.")
