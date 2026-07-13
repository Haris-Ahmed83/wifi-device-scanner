---
title: WiFi Network Device Scanner
emoji: "\U0001F6E1"
colorFrom: blue
colorTo: indigo
sdk: streamlit
sdk_version: 1.59.2
app_file: streamlit_app.py
pinned: true
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

## How to Run Locally

### Desktop App (CustomTkinter)
```bash
cd "E:\wifi project"
python main.py
```

### Web App (Gradio)
```bash
cd "E:\wifi project"
python gradio_app.py
```

> Note: For real network scanning, run as Administrator. 
> On Hugging Face Spaces, demo data is shown.

## Deployment

This Space is configured for Gradio. The app automatically detects 
whether it's running in the cloud (demo mode) or locally (real scanning).
