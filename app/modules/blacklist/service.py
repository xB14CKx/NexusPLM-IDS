from app.modules.detection.signatures import add_ip, remove_ip, list_ips
from app.modules.blacklist.model import BlacklistResponse, BlacklistListResponse


def add(ip: str) -> BlacklistResponse:
    add_ip(ip)
    return BlacklistResponse(ip=ip, action="added")


def remove(ip: str) -> BlacklistResponse:
    remove_ip(ip)
    return BlacklistResponse(ip=ip, action="removed")


def list_all() -> BlacklistListResponse:
    ips = list_ips()
    return BlacklistListResponse(ips=ips, total=len(ips))
