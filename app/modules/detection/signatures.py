"""Signature-based detection: SQLi, XSS, path traversal, bad IP/UA."""
import re
from app.modules.core.models import ThreatEvent, Severity

_SQLI = re.compile(
    r"('|\")\s*(or|and)\s+['\"0-9]|"
    r"(union\s+(all\s+)?select|drop\s+table|insert\s+into|"
    r"exec\s*\(|xp_cmdshell|benchmark\s*\(|sleep\s*\()",
    re.IGNORECASE,
)
_XSS = re.compile(
    r"<\s*script[\s>]|javascript\s*:|on\w+\s*=|<\s*iframe[\s>]|<\s*img[^>]+onerror",
    re.IGNORECASE,
)
_PATH_TRAVERSAL = re.compile(r"\.\./|\.\.\\", re.IGNORECASE)

_BAD_UA: set[str] = {
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
    "gobuster", "hydra", "metasploit", "havij", "acunetix",
}
_BLACKLISTED_IPS: set[str] = set()


def scan(request_id: str | None, ip: str, user_id: str | None,
         user_agent: str, path: str, query: str, body: str) -> list[ThreatEvent]:
    threats: list[ThreatEvent] = []
    payload = f"{path} {query} {body}"

    if _SQLI.search(payload):
        threats.append(ThreatEvent(
            request_id=request_id, ip=ip, user_id=user_id,
            threat_type="SQL_INJECTION", severity=Severity.CRITICAL,
            detail=f"SQLi pattern detected: {payload[:120]}", score=90,
        ))
    if _XSS.search(payload):
        threats.append(ThreatEvent(
            request_id=request_id, ip=ip, user_id=user_id,
            threat_type="XSS", severity=Severity.HIGH,
            detail=f"XSS pattern detected: {payload[:120]}", score=70,
        ))
    if _PATH_TRAVERSAL.search(payload):
        threats.append(ThreatEvent(
            request_id=request_id, ip=ip, user_id=user_id,
            threat_type="PATH_TRAVERSAL", severity=Severity.HIGH,
            detail="Path traversal attempt", score=65,
        ))
    if any(bad in user_agent.lower() for bad in _BAD_UA):
        threats.append(ThreatEvent(
            request_id=request_id, ip=ip, user_id=user_id,
            threat_type="MALICIOUS_UA", severity=Severity.HIGH,
            detail=f"Known attack tool user-agent: {user_agent}", score=80,
        ))
    if ip in _BLACKLISTED_IPS:
        threats.append(ThreatEvent(
            request_id=request_id, ip=ip, user_id=user_id,
            threat_type="BLACKLISTED_IP", severity=Severity.CRITICAL,
            detail=f"IP {ip} is blacklisted", score=95,
        ))
    return threats


def add_ip(ip: str) -> None:
    _BLACKLISTED_IPS.add(ip)


def remove_ip(ip: str) -> None:
    _BLACKLISTED_IPS.discard(ip)


def list_ips() -> list[str]:
    return sorted(_BLACKLISTED_IPS)
