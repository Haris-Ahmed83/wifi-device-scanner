import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"Starting WiFi Device Scanner API...")
    print(f"Access from any device on your network at:")
    print(f"  http://{host}:{port}")
    print(f"  http://localhost:{port}")
    uvicorn.run(
        "backend.app.main:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
        timeout_keep_alive=120,
        ws_ping_interval=20,
        ws_ping_timeout=10,
    )
