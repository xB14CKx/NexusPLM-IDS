import json
from fastapi import APIRouter, Depends, Query
from app.modules.core.auth import require_api_key
from app.modules.core.models import ThreatEvent
from app.modules.core.redis import get_redis

router = APIRouter(prefix="/ids", tags=["IDS"])

_THREATS_KEY = "ids:threats"
_MAX_STORED = 500


async def store_threat(threat: ThreatEvent) -> None:
    """Push a threat event to the Redis list (called by analyze/audit services)."""
    r = await get_redis()
    if r is None:
        return
    await r.lpush(_THREATS_KEY, threat.model_dump_json())
    await r.ltrim(_THREATS_KEY, 0, _MAX_STORED - 1)


@router.get("/threats", response_model=list[ThreatEvent], dependencies=[Depends(require_api_key)])
async def get_threats(limit: int = Query(100, ge=1, le=500)) -> list[ThreatEvent]:
    """Return the most recent threat events (newest first)."""
    r = await get_redis()
    if r is None:
        return []
    raw = await r.lrange(_THREATS_KEY, 0, limit - 1)
    return [ThreatEvent(**json.loads(item)) for item in raw]
