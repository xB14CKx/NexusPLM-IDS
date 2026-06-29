from fastapi import APIRouter, Depends
from app.modules.core.auth import require_api_key
from app.modules.ips.model import IpsBlockRequest, IpsBlockResponse, IpsBlockListResponse
from app.modules.ips import service

router = APIRouter(prefix="/ips/blocks", tags=["IPS"])


@router.get("", response_model=IpsBlockListResponse, dependencies=[Depends(require_api_key)])
async def get_blocks() -> IpsBlockListResponse:
    """List all IPS-managed blocks (active, non-expired)."""
    return await service.list_blocks()


@router.post("", response_model=IpsBlockResponse, dependencies=[Depends(require_api_key)])
async def block_ip(req: IpsBlockRequest) -> IpsBlockResponse:
    """Manually block an IP. ttl (seconds) is optional; omit for permanent block."""
    return await service.block_ip(req.ip, reason=req.reason, ttl=req.ttl)


@router.delete("/{ip}", response_model=IpsBlockResponse, dependencies=[Depends(require_api_key)])
async def unblock_ip(ip: str) -> IpsBlockResponse:
    """Remove an IP from the IPS block list."""
    return await service.unblock_ip(ip)


@router.get("/{ip}/check", dependencies=[Depends(require_api_key)])
async def check_ip(ip: str) -> dict:
    """Fast check: is this IP currently IPS-blocked?"""
    blocked = await service.is_blocked(ip)
    return {"ip": ip, "blocked": blocked}
