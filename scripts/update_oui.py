"""Download official OUI list and regenerate oui_lookup.py"""

import subprocess
import re
import os
import sys
import json
import tempfile

OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
OUTPUT = os.path.join(os.path.dirname(__file__), "..", "modules", "oui_lookup.py")


def download(url):
    print(f"Downloading {url}...")
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        with urllib.request.urlopen(req, timeout=30) as f:
            return f.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"urllib failed: {e}, trying curl.exe...")
        tmp = os.path.join(tempfile.gettempdir(), "oui.txt")
        result = subprocess.run(
            ["curl.exe", "-sL", url, "-o", tmp],
            capture_output=True, timeout=30
        )
        if result.returncode == 0 and os.path.exists(tmp):
            with open(tmp, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        raise


def parse_oui(text):
    entries = {}
    hex_pattern = re.compile(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$", re.MULTILINE)

    for match in hex_pattern.finditer(text):
        oui_hex = match.group(1).replace("-", ":").lower()
        vendor = match.group(2).strip().strip('"')
        vendor = re.sub(r"\s+", " ", vendor)

        if oui_hex not in entries:
            entries[oui_hex] = vendor
        else:
            existing = entries[oui_hex]
            if vendor not in existing and existing not in vendor:
                entries[oui_hex] = f"{existing} / {vendor}"

    return entries


def generate_module(entries):
    quoted = json.dumps(dict(sorted(entries.items())), ensure_ascii=False, indent=4)
    code = f"""OUI_DATABASE = {quoted}


OUI_ALIASES = {{}}


def lookup_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return "Unknown"
    prefix = mac[:8].lower()
    return OUI_DATABASE.get(prefix, "Unknown")
"""
    return code


if __name__ == "__main__":
    text = download(OUI_URL)
    entries = parse_oui(text)
    print(f"Found {len(entries)} OUI entries")
    code = generate_module(entries)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(code)
    print(f"Written to {OUTPUT}")
    print(f"File size: {os.path.getsize(OUTPUT):,} bytes")
