"""Behavioral detection: rate limiting, brute-force, off-hours login, geo-jump."""
from __future__ import annotations
from datetime import datetime, timezone
from app.modules.core.models import ThreatEvent, Severity
from app.modules.core.config import get_settings
from app.modules.core.redis import get_redis, incr_window
from app.modules.core.geoip import lookup_country


async def check_rate_limit(request_id: str | None, ip: str, user_id: str | None) -> list[ThreatEvent]:
    s = get_settings()
    r = await get_redis()
    if r is None:
        return []
    key = f"rl:{ip}:{datetime.utcnow().strftime('%Y%m%d%H%M')}"
    count = await incr_window(r, key, s.rate_limit_window)
    if count > s.rate_limit_max_requests:
        return [ThreatEvent(
            request_id=request_id, ip=ip, user_id=user_id,
            threat_type="RATE_LIMIT_EXCEEDED", severity=Severity.MEDIUM,
            detail=f"{count} requests in {s.rate_limit_window}s (max {s.rate_limit_max_requests})",
            score=50,
        )]
    return []


async def check_brute_force(event_id: str, ip: str, user_id: str, action: str) -> list[ThreatEvent]:
    if action != "LOGIN_FAILED":
        return []
    s = get_settings()
    r = await get_redis()
    if r is None:
        return []
    key = f"bf:{ip}:{user_id}"
    count = await incr_window(r, key, s.brute_force_window)
    if count >= s.brute_force_max:
        return [ThreatEvent(
            event_id=event_id, ip=ip, user_id=user_id,
            threat_type="BRUTE_FORCE", severity=Severity.HIGH,
            detail=f"{count} failed logins in {s.brute_force_window}s",
            score=75,
        )]
    return []


def check_login_time(event_id: str, ip: str, user_id: str, action: str, timestamp: datetime) -> list[ThreatEvent]:
    if action not in ("LOGIN", "LOGIN_SUCCESS"):
        return []
    hour = timestamp.astimezone(timezone.utc).hour
    if hour < 6 or hour >= 22:
        return [ThreatEvent(
            event_id=event_id, ip=ip, user_id=user_id,
            threat_type="UNUSUAL_LOGIN_TIME", severity=Severity.LOW,
            detail=f"Login at off-hours UTC {hour:02d}:xx",
            score=25,
        )]
    return []


async def check_geo_jump(event_id: str, ip: str, user_id: str, action: str) -> list[ThreatEvent]:
    if action not in ("LOGIN", "LOGIN_SUCCESS"):
        return []
    country = lookup_country(ip)
    if country is None:
        return []
    r = await get_redis()
    if r is None:
        return []
    key = f"geo:{user_id}"
    prev = await r.get(key)
    await r.setex(key, 3600, country)
    if prev and prev != country:
        return [ThreatEvent(
            event_id=event_id, ip=ip, user_id=user_id,
            threat_type="GEO_JUMP", severity=Severity.HIGH,
            detail=f"Country changed {prev} → {country} within 1 hour",
            score=70,
        )]
    return []
