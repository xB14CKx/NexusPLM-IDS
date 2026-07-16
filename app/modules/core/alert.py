"""Aggregates threat scores → RiskScore, fires optional webhook alert and email notification."""
from __future__ import annotations
import httpx
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import aiosmtplib
from app.modules.core.models import ThreatEvent, RiskScore
from app.modules.core.config import get_settings

logger = logging.getLogger(__name__)


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
    logger.info("Firing alert: action=%s ip=%s score=%s", risk.action, risk.ip, risk.total_score)

    # Webhook
    if s.alert_webhook_url:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(s.alert_webhook_url, json=risk.model_dump(mode="json"))
            logger.info("Webhook delivered to %s", s.alert_webhook_url)
        except Exception as exc:
            logger.warning("Webhook delivery failed: %s", exc)

    # Email
    await _send_email(risk)


async def _send_email(risk: RiskScore) -> None:
    s = get_settings()

    # Need at minimum a sender and recipient regardless of transport
    missing_base = [k for k, v in {
        "SMTP_FROM": s.smtp_from,
        "ALERT_EMAIL_TO": s.alert_email_to,
    }.items() if not v]
    if missing_base:
        logger.warning("Email alert skipped — missing config: %s", ", ".join(missing_base))
        return

    # Generate signed single-use action tokens
    from app.modules.core.resolution_token import create_token
    unblock_token = await create_token(risk.ip, "unblock")
    permanent_token = await create_token(risk.ip, "block_permanent")
    base = s.resolution_base_url.rstrip("/")
    unblock_url = f"{base}/ips/resolve?token={unblock_token}"
    permanent_url = f"{base}/ips/resolve?token={permanent_token}"

    threat_lines_txt = "\n".join(
        f"  [{t.severity.upper()}] {t.threat_type}: {t.detail}" for t in risk.threats
    ) or "  (none)"
    threat_rows_html = "".join(
        f"<tr><td style='padding:4px 8px'>{t.severity.upper()}</td>"
        f"<td style='padding:4px 8px'>{t.threat_type}</td>"
        f"<td style='padding:4px 8px'>{t.detail}</td></tr>"
        for t in risk.threats
    ) or "<tr><td colspan='3' style='padding:4px 8px'>(none)</td></tr>"

    action_color = "#b5111b" if risk.action == "BLOCK" else "#d97706"

    # ── Plain-text part ──────────────────────────────────────────────────────
    plain = (
        f"NexusPLM IDS Alert\n"
        f"{'=' * 40}\n"
        f"Action  : {risk.action}\n"
        f"IP      : {risk.ip}\n"
        f"User    : {risk.user_id or 'anonymous'}\n"
        f"Score   : {risk.total_score}/100\n"
        f"Time    : {risk.evaluated_at.isoformat()}\n\n"
        f"Threats:\n{threat_lines_txt}\n\n"
        f"--- Actions (links expire in {s.resolution_token_ttl // 3600}h, single-use) ---\n\n"
        f"RESOLVE & UNBLOCK:\n{unblock_url}\n\n"
        f"BLOCK PERMANENTLY:\n{permanent_url}\n"
    )

    # ── HTML part ────────────────────────────────────────────────────────────
    html = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:system-ui,sans-serif;background:#f4f4f4;margin:0;padding:24px">
  <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;
              box-shadow:0 2px 8px rgba(0,0,0,.1);overflow:hidden">

    <!-- Header -->
    <div style="background:{action_color};padding:20px 28px">
      <h1 style="margin:0;color:#fff;font-size:1.2rem;letter-spacing:.5px">
        NexusPLM IDS &mdash; {risk.action}
      </h1>
    </div>

    <!-- Summary -->
    <div style="padding:24px 28px">
      <table style="border-collapse:collapse;width:100%;font-size:.95rem">
        <tr><td style="padding:4px 0;color:#666;width:90px">IP</td>
            <td style="padding:4px 0;font-weight:600">{risk.ip}</td></tr>
        <tr><td style="padding:4px 0;color:#666">User</td>
            <td style="padding:4px 0">{risk.user_id or 'anonymous'}</td></tr>
        <tr><td style="padding:4px 0;color:#666">Score</td>
            <td style="padding:4px 0;font-weight:600">{risk.total_score}/100</td></tr>
        <tr><td style="padding:4px 0;color:#666">Time</td>
            <td style="padding:4px 0">{risk.evaluated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
      </table>

      <!-- Threats -->
      <h2 style="font-size:1rem;margin:20px 0 8px">Threats Detected</h2>
      <table style="border-collapse:collapse;width:100%;font-size:.875rem;border:1px solid #e5e7eb;border-radius:4px">
        <thead>
          <tr style="background:#f9fafb">
            <th style="padding:6px 8px;text-align:left;color:#555">Severity</th>
            <th style="padding:6px 8px;text-align:left;color:#555">Type</th>
            <th style="padding:6px 8px;text-align:left;color:#555">Detail</th>
          </tr>
        </thead>
        <tbody>{threat_rows_html}</tbody>
      </table>

      <!-- Action buttons -->
      <h2 style="font-size:1rem;margin:24px 0 12px">Actions</h2>
      <p style="font-size:.8rem;color:#888;margin:0 0 16px">
        Links expire in {s.resolution_token_ttl // 3600} hour(s) and are single-use.
      </p>
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <a href="{unblock_url}"
           style="display:inline-block;padding:12px 24px;background:#2d6a4f;color:#fff;
                  text-decoration:none;border-radius:6px;font-weight:600;font-size:.95rem">
          ✅ Resolve &amp; Unblock
        </a>
        <a href="{permanent_url}"
           style="display:inline-block;padding:12px 24px;background:#b5111b;color:#fff;
                  text-decoration:none;border-radius:6px;font-weight:600;font-size:.95rem">
          🔒 Block Permanently
        </a>
      </div>
    </div>

    <div style="padding:12px 28px;background:#f9fafb;border-top:1px solid #e5e7eb;
                font-size:.75rem;color:#aaa;text-align:center">
      NexusPLM IDS/IPS &mdash; automated security alert
    </div>
  </div>
</body>
</html>"""

    subject = f"[NexusPLM IDS] {risk.action} — {risk.ip} (score {risk.total_score})"

    if s.resend_api_key:
        await _send_via_resend(s, subject, plain, html)
    else:
        await _send_via_smtp(s, subject, plain, html)


async def _send_via_resend(s, subject: str, plain: str, html: str) -> None:
    payload = {
        "from": s.smtp_from,
        "to": [s.alert_email_to],
        "subject": subject,
        "text": plain,
        "html": html,
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {s.resend_api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
        logger.info("Alert email sent via Resend to %s", s.alert_email_to)
    except Exception as exc:
        logger.error("Failed to send alert email via Resend: %s", exc)


async def _send_via_smtp(s, subject: str, plain: str, html: str) -> None:
    missing = [k for k, v in {
        "SMTP_HOST": s.smtp_host, "SMTP_USER": s.smtp_user,
        "SMTP_PASSWORD": s.smtp_password,
    }.items() if not v]
    if missing:
        logger.warning("SMTP email skipped — missing config: %s", ", ".join(missing))
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = s.smtp_from
    msg["To"] = s.alert_email_to
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        await aiosmtplib.send(
            msg,
            hostname=s.smtp_host,
            port=s.smtp_port,
            username=s.smtp_user,
            password=s.smtp_password,
            start_tls=True,
            timeout=10,
        )
        logger.info("Alert email sent via SMTP to %s", s.alert_email_to)
    except Exception as exc:
        logger.error("Failed to send alert email via SMTP to %s: %s", s.alert_email_to, exc)
