"""Sequence engine: detects suspicious action chains stored in Redis per user."""
from __future__ import annotations
import json
from datetime import datetime
from app.modules.core.models import ThreatEvent, Severity
from app.modules.core.redis import get_redis

_SEQ_TTL = 600  # 10 min buffer per user

# (ordered actions, max_window_seconds, score, description)
RULES: list[tuple[list[str], int, int, str]] = [
    (["LOGIN", "EXPORT_BOM", "LOGOUT"],                     30,  85, "Login→ExportBOM→Logout in ≤30s"),
    (["LOGIN", "EXPORT_BOM", "EXPORT_BOM", "EXPORT_BOM"],  120,  75, "Mass BOM export after login"),
    (["LOGIN", "DELETE_PART", "LOGOUT"],                    60,  80, "Delete immediately after login"),
    (["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN", "EXPORT_BOM"], 300, 90, "Export after repeated failures"),
    (["LOGIN", "ADMIN_CHANGE", "LOGOUT"],                   60,  80, "Admin change immediately after login"),
]


async def push_and_score(event_id: str, ip: str, user_id: str, action: str, timestamp: datetime) -> list[ThreatEvent]:
    r = await get_redis()
    if r is None:
        return []

    key = f"seq:{user_id}"
    await r.rpush(key, json.dumps({"action": action, "ts": timestamp.isoformat(), "event_id": event_id}))
    await r.expire(key, _SEQ_TTL)

    events = [json.loads(x) for x in await r.lrange(key, -20, -1)]

    threats: list[ThreatEvent] = []
    for actions, window, score, desc in RULES:
        if t := _match(event_id, ip, user_id, events, actions, window, score, desc):
            threats.append(t)
    return threats


def _match(event_id, ip, user_id, events, actions, window, score, desc) -> ThreatEvent | None:
    for i in range(len(events)):
        if events[i]["action"] != actions[0]:
            continue
        matched = [events[i]]
        for action in actions[1:]:
            hit = next((e for e in events[i + len(matched):] if e["action"] == action), None)
            if hit is None:
                break
            matched.append(hit)
        else:
            t0 = datetime.fromisoformat(matched[0]["ts"])
            t1 = datetime.fromisoformat(matched[-1]["ts"])
            if (t1 - t0).total_seconds() <= window:
                return ThreatEvent(
                    event_id=event_id, ip=ip, user_id=user_id,
                    threat_type="SUSPICIOUS_SEQUENCE", severity=Severity.CRITICAL,
                    detail=desc, score=score,
                )
    return None
