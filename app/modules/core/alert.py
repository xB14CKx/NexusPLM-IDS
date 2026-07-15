"""Aggregates threat scores → RiskScore, fires optional webhook alert and email notification."""
from __future__ import annotations
import httpx
from email.mime.text import MIMEText
import aiosmtplib
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
    if risk.action == "ALLOW":
        return
    s = get_settings()

    # Webhook
    if s.alert_webhook_url:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(s.alert_webhook_url, json=risk.model_dump(mode="json"))
        except Exception:
            pass

    # Email
    await _send_email(risk)


async def _send_email(risk: RiskScore) -> None:
    s = get_settings()
    if not all([s.smtp_host, s.smtp_user, s.smtp_password, s.smtp_from, s.alert_email_to]):
        return

    top = risk.threats[0] if risk.threats else None
    threat_lines = "\n".join(
        f"  - [{t.severity.upper()}] {t.threat_type}: {t.detail}" for t in risk.threats
    )
    body = (
        f"NexusPLM IDS Alert\n"
        f"{'=' * 40}\n"
        f"Action  : {risk.action}\n"
        f"IP      : {risk.ip}\n"
        f"User    : {risk.user_id or 'anonymous'}\n"
        f"Score   : {risk.total_score}/100\n"
        f"Time    : {risk.evaluated_at.isoformat()}\n\n"
        f"Threats detected:\n{threat_lines or '  (none)'}\n"
    )

    msg = MIMEText(body)
    msg["Subject"] = f"[NexusPLM IDS] {risk.action} — {risk.ip} (score {risk.total_score})"
    msg["From"] = s.smtp_from
    msg["To"] = s.alert_email_to

    try:
        await aiosmtplib.send(
            msg,
            hostname=s.smtp_host,
            port=s.smtp_port,
            username=s.smtp_user,
            password=s.smtp_password,
            start_tls=True,
        )
    except Exception:
        pass
