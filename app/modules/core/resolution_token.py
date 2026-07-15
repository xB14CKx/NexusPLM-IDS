"""
Signed JWT tokens for email-based alert resolution.

Each token encodes:
  - ip:     the IP address the action applies to
  - action: "unblock" | "block_permanent"
  - jti:    unique token ID (stored in Redis on issue, deleted on use → single-use)
  - exp:    expiry timestamp

The secret is ids_api_key from settings — no extra secret needed.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timedelta, timezone

import jwt

from app.modules.core.config import get_settings
from app.modules.core.redis import get_redis

_JTI_PREFIX = "res:jti:"


def _secret() -> str:
    return get_settings().ids_api_key


def _ttl() -> int:
    return get_settings().resolution_token_ttl


async def create_token(ip: str, action: str) -> str:
    """
    Issue a signed, single-use JWT for the given IP and action.
    action must be "unblock" or "block_permanent".
    """
    jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    payload = {
        "ip": ip,
        "action": action,
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(seconds=_ttl()),
    }
    token = jwt.encode(payload, _secret(), algorithm="HS256")

    # Store jti in Redis with same TTL so we can burn it on use
    r = await get_redis()
    if r is not None:
        await r.setex(f"{_JTI_PREFIX}{jti}", _ttl(), "1")

    return token


async def consume_token(token: str) -> dict:
    """
    Validate and consume a resolution token.
    Returns the decoded payload on success.
    Raises ValueError with a human-readable reason on any failure.
    """
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise ValueError("This resolution link has expired.")
    except jwt.InvalidTokenError as exc:
        raise ValueError(f"Invalid resolution token: {exc}")

    jti = payload.get("jti")
    if not jti:
        raise ValueError("Token missing jti claim.")

    r = await get_redis()
    if r is not None:
        key = f"{_JTI_PREFIX}{jti}"
        # GETDEL atomically returns the value and deletes it
        existing = await r.getdel(key)
        if existing is None:
            raise ValueError("This resolution link has already been used or has expired.")

    action = payload.get("action")
    if action not in ("unblock", "block_permanent"):
        raise ValueError(f"Unknown action in token: {action!r}")

    return payload
