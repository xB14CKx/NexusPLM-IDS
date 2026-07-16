from app.modules.analyze.model import AnalyzeRequest
from app.modules.core.models import RiskScore
from app.modules.core.alert import aggregate, maybe_alert
from app.modules.detection import signatures, behavioral
from app.modules.ids.controller import store_threat
from app.modules.ips.service import auto_block
import asyncio


async def analyze(req: AnalyzeRequest) -> RiskScore:
    threats = signatures.scan(
        request_id=req.request_id, ip=req.ip, user_id=req.user_id,
        user_agent=req.user_agent, path=req.path,
        query=req.query_string, body=req.body,
    )
    threats += await behavioral.check_rate_limit(req.request_id, req.ip, req.user_id)

    risk = aggregate(req.ip, req.user_id, threats)
    for t in risk.threats:
        await store_threat(t)

    # Block first — never let email delay the IPS action
    if risk.action == "BLOCK":
        reason = risk.threats[0].threat_type if risk.threats else "high_risk_score"
        await auto_block(risk.ip, reason=reason)

    # Fire alert in the background so slow SMTP never blocks the response
    asyncio.ensure_future(maybe_alert(risk))

    return risk
