import os
from functools import lru_cache


class Settings:
    app_name: str = "WiFi Network Scanner"
    version: str = "2.0.0"
    scan_subnet: str = os.environ.get("SCAN_SUBNET", "")
    scan_interval: int = int(os.environ.get("SCAN_INTERVAL", "60"))
    scan_ports: list[int] = [22, 80, 443, 554, 631, 8080, 9100, 3389, 139, 445]
    database_url: str = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///data/scanner.db")
    cors_origins: list[str] = ["*"]
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")


@lru_cache
def get_settings() -> Settings:
    return Settings()
