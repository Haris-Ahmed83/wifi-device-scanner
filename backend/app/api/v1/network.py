from fastapi import APIRouter
from modules.network_scanner import get_local_network_info, resolve_hostname

router = APIRouter(prefix="/network", tags=["network"])


@router.get("/info")
async def network_info():
    return get_local_network_info() or {"error": "Could not detect network"}


@router.get("/resolve")
async def resolve(ip: str):
    name = resolve_hostname(ip)
    return {"ip": ip, "hostname": name}
