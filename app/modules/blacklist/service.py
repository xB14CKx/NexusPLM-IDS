from app.modules.detection.signatures import add_ip, remove_ip, list_ips
from app.modules.blacklist.model import BlacklistResponse, BlacklistListResponse
from app.modules.core.redis import get_redis

_BLACKLIST_KEY = "ids:blacklist"


async def _redis_add(ip: str) -> None:
    r = await get_redis()
    if r is not None:
        await r.sadd(_BLACKLIST_KEY, ip)


async def _redis_remove(ip: str) -> None:
    r = await get_redis()
    if r is not None:
        await r.srem(_BLACKLIST_KEY, ip)


async def _redis_list() -> list[str]:
    r = await get_redis()
    if r is None:
        return []
    members = await r.smembers(_BLACKLIST_KEY)
    return sorted(members)


async def add(ip: str) -> BlacklistResponse:
    add_ip(ip)           # keep in-memory set in sync
    await _redis_add(ip) # persist to Redis
    return BlacklistResponse(ip=ip, action="added")


async def remove(ip: str) -> BlacklistResponse:
    remove_ip(ip)           # keep in-memory set in sync
    await _redis_remove(ip) # remove from Redis
    return BlacklistResponse(ip=ip, action="removed")


async def list_all() -> BlacklistListResponse:
    # Prefer Redis (survives restarts); fall back to in-memory set
    ips = await _redis_list()
    if not ips:
        ips = list_ips()
    return BlacklistListResponse(ips=ips, total=len(ips))
