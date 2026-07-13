import socket
import subprocess
import sys


def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    lan_ip = get_lan_ip()
    print(f"Starting WiFi Device Scanner...")
    print(f"Access from any device on your network at:")
    print(f"  http://{lan_ip}:8501")
    print(f"  http://localhost:8501 (local only)")
    print()

    subprocess.run([
        sys.executable, "-m", "streamlit", "run", "streamlit_app.py",
        "--server.address", "0.0.0.0",
        "--server.port", "8501",
    ])
