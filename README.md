---
title: WiFi Network Device Scanner
emoji: "\U0001F6E1"
colorFrom: blue
colorTo: indigo
sdk: streamlit
sdk_version: 1.59.2
app_file: streamlit_app.py
pinned: false
license: mit
---

# WiFi Network Device Scanner

Scan your local network and identify connected devices with detailed fingerprinting.

## Features
- ARP scan to discover all devices on your network
- MAC OUI lookup to identify vendors (Tecno, Infinix, Samsung, Apple, etc.)
- TTL analysis to estimate OS type (Windows/Linux/Android/iOS)
- Port scanning to identify device purpose (cameras, printers, routers, etc.)
- Combined classification for accurate device type detection
- Desktop GUI (CustomTkinter) + Web UI (Streamlit)

## How to Run Locally

### Desktop App
```bash
pip install -r requirements.txt
python main.py
```

### Streamlit Web App
```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

**Note:** Run as Administrator for full ARP scanning capabilities.

## Deploy on Streamlit Cloud

1. Go to https://share.streamlit.io
2. Sign in with GitHub
3. Click "New app"
4. Select: `Haris-Ahmed83/wifi-device-scanner`
5. Branch: `main`, File: `streamlit_app.py`
6. Click Deploy!

## One-Click Deploy

[![Deploy to Streamlit](https://img.shields.io/badge/Deploy%20to-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit)](https://share.streamlit.io/deploy?repository=https://github.com/Haris-Ahmed83/wifi-device-scanner)

## License
MIT
