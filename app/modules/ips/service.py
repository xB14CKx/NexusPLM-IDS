"""IPS service: Redis-backed auto-block/unblock with optional TTL."""
from __future__ import annotations
import json
import logging
from datetime import datetime, timedelta, timezone
from app.modules.core.redis import get_redis
from app.modules.core.config import get_settings
from app.modules.ips.model import IpsBlock, IpsBlockResponse, IpsBlockListResponse

_BLOCK_KEY = "ips:blocks"         # Redis hash  ip → json(IpsBlock)
logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def is_blocked(ip: str) -> bool:
    """Fast pre-flight check used in the middleware path."""
    r = await get_redis()
    if r is None:
        return False
    raw = await r.hget(_BLOCK_KEY, ip)
    if raw is None:
        return False
    block = IpsBlock(**json.loads(raw))
    if block.expires_at and block.expires_at <= _now():
        await r.hdel(_BLOCK_KEY, ip)  # lazy expiry cleanup
        return False
    return True


async def block_ip(ip: str, reason: str = "auto", ttl: int | None = None) -> IpsBlockResponse:
    """Add an IP to the IPS block list. ttl=None means permanent."""
    s = get_settings()
    effective_ttl = ttl if ttl is not None else s.ips_auto_block_ttl
    now = _now()
    expires_at = now + timedelta(seconds=effective_ttl) if effective_ttl else None

    block = IpsBlock(ip=ip, reason=reason, blocked_at=now, expires_at=expires_at)
    r = await get_redis()
    if r is not None:
        payload = block.model_dump_json()
        if effective_ttl:
            pipe = r.pipeline()
            await pipe.hset(_BLOCK_KEY, ip, payload)
            # Use a separate key with Redis TTL for auto-expiry
            await pipe.setex(f"ips:ttl:{ip}", effective_ttl, "1")
            await pipe.execute()
        else:
            await r.hset(_BLOCK_KEY, ip, payload)
    return IpsBlockResponse(ip=ip, action="blocked", expires_at=expires_at)


async def unblock_ip(ip: str) -> IpsBlockResponse:
    r = await get_redis()
    if r is not None:
        await r.hdel(_BLOCK_KEY, ip)
        await r.delete(f"ips:ttl:{ip}")
    return IpsBlockResponse(ip=ip, action="unblocked")


async def list_blocks() -> IpsBlockListResponse:
    r = await get_redis()
    if r is None:
        return IpsBlockListResponse(blocks=[], total=0)
    raw = await r.hgetall(_BLOCK_KEY)
    blocks: list[IpsBlock] = []
    expired: list[str] = []
    now = _now()
    for ip, data in raw.items():
        b = IpsBlock(**json.loads(data))
        if b.expires_at and b.expires_at <= now:
            expired.append(ip)
        else:
            blocks.append(b)
    if expired:
        await r.hdel(_BLOCK_KEY, *expired)
    blocks.sort(key=lambda b: b.blocked_at, reverse=True)
    return IpsBlockListResponse(blocks=blocks, total=len(blocks))


async def auto_block(ip: str, reason: str) -> None:
    """Called automatically when the IDS decides BLOCK. Respects ips_enabled setting.
    Private, loopback, and link-local IPs are never auto-blocked — blocking them
    would lock out everyone sharing that internal address (e.g. entire LAN behind NAT).
    """
    if not get_settings().ips_enabled:
        logger.warning("auto_block skipped for %s — IPS_ENABLED is false", ip)
        return
    from app.modules.core.ip_utils import is_private_ip
    if is_private_ip(ip):
        logger.warning("auto_block skipped for %s — IP is private/reserved", ip)
        return
    logger.info("auto_block: blocking %s reason=%s", ip, reason)
    await block_ip(ip, reason=reason)
    logger.info("auto_block: %s successfully added to block list", ip)
