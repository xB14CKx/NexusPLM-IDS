from fastapi import APIRouter, Depends
from app.modules.core.auth import require_api_key
from app.modules.blacklist.model import BlacklistResponse, BlacklistListResponse
from app.modules.blacklist import service

router = APIRouter(prefix="/ips/blacklist", tags=["Blacklist"])


@router.get("", response_model=BlacklistListResponse, dependencies=[Depends(require_api_key)])
async def get_blacklist() -> BlacklistListResponse:
    """List all currently blacklisted IPs (Redis-backed, survives restarts)."""
    return await service.list_all()


@router.post("", response_model=BlacklistResponse, dependencies=[Depends(require_api_key)])
async def add_to_blacklist(ip: str) -> BlacklistResponse:
    """Add an IP to the blacklist (persisted to Redis)."""
    return await service.add(ip)


@router.delete("", response_model=BlacklistResponse, dependencies=[Depends(require_api_key)])
async def remove_from_blacklist(ip: str) -> BlacklistResponse:
    """Remove an IP from the blacklist (removed from Redis)."""
    return await service.remove(ip)
