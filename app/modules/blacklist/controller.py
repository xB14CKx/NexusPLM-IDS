from fastapi import APIRouter, Depends
from app.modules.core.auth import require_api_key
from app.modules.blacklist.model import BlacklistResponse, BlacklistListResponse
from app.modules.blacklist import service

router = APIRouter(prefix="/ips/blacklist", tags=["Blacklist"])


@router.get("", response_model=BlacklistListResponse, dependencies=[Depends(require_api_key)])
def get_blacklist() -> BlacklistListResponse:
    """List all currently blacklisted IPs."""
    return service.list_all()


@router.post("", response_model=BlacklistResponse, dependencies=[Depends(require_api_key)])
def add_to_blacklist(ip: str) -> BlacklistResponse:
    """Add an IP to the blacklist."""
    return service.add(ip)


@router.delete("", response_model=BlacklistResponse, dependencies=[Depends(require_api_key)])
def remove_from_blacklist(ip: str) -> BlacklistResponse:
    """Remove an IP from the blacklist."""
    return service.remove(ip)
