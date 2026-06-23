"""Aggregates threat scores → RiskScore, fires optional webhook alert."""
from __future__ import annotations
import httpx
from app.modules.core.models import ThreatEvent, RiskScore
from app.modules.core.config import get_settings


def aggregate(ip: str, user_id: str | None, threats: list[ThreatEvent]) -> RiskScore:
    s = get_settings()
    total = min(sum(t.score for t in threats), 100)
    if total >= s.risk_block_threshold:
        action = "BLOCK"
    elif total >= s.risk_alert_threshold:
        action = "ALERT"
    else:
        action = "ALLOW"
    return RiskScore(ip=ip, user_id=user_id, total_score=total, threats=threats, action=action)


async def maybe_alert(risk: RiskScore) -> None:
    url = get_settings().alert_webhook_url
    if not url or risk.action == "ALLOW":
        return
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(url, json=risk.model_dump(mode="json"))
    except Exception:
        pass
