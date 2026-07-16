"""Shared async Redis client. Returns None if Redis is unreachable so callers degrade gracefully."""
from __future__ import annotations
import logging
import redis.asyncio as aioredis
from app.modules.core.config import get_settings

_client: aioredis.Redis | None = None
logger = logging.getLogger(__name__)


async def get_redis() -> aioredis.Redis | None:
    global _client
    if _client is None:
        url = get_settings().redis_url
        try:
            _client = aioredis.from_url(url, decode_responses=True)
            # Ping to verify the connection is actually reachable
            await _client.ping()
            logger.info("Redis connected: %s", url)
        except Exception as exc:
            logger.error("Redis connection failed (%s): %s — IPS/behavioral detection disabled", url, exc)
            _client = None
    return _client


async def incr_window(r: aioredis.Redis, key: str, window: int) -> int:
    """Increment a counter and set TTL on first write."""
    count = await r.incr(key)
    if count == 1:
        await r.expire(key, window)
    return count
