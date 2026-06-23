"""Shared async Redis client. Returns None if Redis is unreachable so callers degrade gracefully."""
from __future__ import annotations
import redis.asyncio as aioredis
from app.modules.core.config import get_settings

_client: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis | None:
    global _client
    if _client is None:
        _client = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    return _client


async def incr_window(r: aioredis.Redis, key: str, window: int) -> int:
    """Increment a counter and set TTL on first write."""
    count = await r.incr(key)
    if count == 1:
        await r.expire(key, window)
    return count
