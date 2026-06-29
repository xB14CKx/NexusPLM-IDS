from app.modules.audit.model import AuditEntry
from app.modules.core.models import RiskScore
from app.modules.core.alert import aggregate, maybe_alert
from app.modules.detection import behavioral, sequences
from app.modules.ids.controller import store_threat
from app.modules.ips.service import auto_block


async def ingest(entry: AuditEntry) -> RiskScore:
    threats = await behavioral.check_brute_force(entry.event_id, entry.ip, entry.user_id, entry.action)
    threats += behavioral.check_login_time(entry.event_id, entry.ip, entry.user_id, entry.action, entry.timestamp)
    threats += await behavioral.check_geo_jump(entry.event_id, entry.ip, entry.user_id, entry.action)
    threats += await sequences.push_and_score(entry.event_id, entry.ip, entry.user_id, entry.action, entry.timestamp)

    risk = aggregate(entry.ip, entry.user_id, threats)
    for t in risk.threats:
        await store_threat(t)
    await maybe_alert(risk)
    if risk.action == "BLOCK":
        reason = risk.threats[0].threat_type if risk.threats else "high_risk_score"
        await auto_block(risk.ip, reason=reason)
    return risk
