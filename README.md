# NexusPLM IDS/IPS

FastAPI intrusion detection **and prevention** service that sits alongside your C# + React NexusPLM application.

## Features

| Layer | What it detects / does |
|---|---|
| **Signature** | SQL injection, XSS, path traversal, known-bad IPs / attack-tool user-agents |
| **Behavioral** | Rate limiting, brute-force login, unusual login hours (off UTC 06–22) |
| **Geo-jump** | Country change within 1 hour for the same user |
| **Sequence** | Suspicious audit chains — e.g. Login → ExportBOM → Logout in ≤30 s |
| **IPS** | Auto-blocks offending IPs on BLOCK decision; TTL-based expiry; manual block/unblock |
| **Email alerts** | Sends an email on every ALERT or BLOCK event via SMTP |

## Quick start

```bash
cp .env.example .env          # edit IDS_API_KEY, SMTP credentials, and thresholds
docker compose up --build
```

The service is now listening on **http://localhost:8000**.

> **GeoIP (optional):** download `GeoLite2-City.mmdb` from MaxMind and place it in the project root. Without it, geo-jump detection is silently skipped.

---

## How IPS works

When the IDS scores a request or audit event as `BLOCK`, the offending IP is **automatically added to the IPS block list** in Redis. All subsequent requests from that IP are rejected immediately — before any scoring — via a single Redis lookup.

Blocks expire after `IPS_AUTO_BLOCK_TTL` seconds (default 1 hour). Set to `0` for permanent blocks.

The C# middleware performs a **two-stage check**:
1. Fast IPS pre-check (`GET /ips/blocks/{ip}/check`) — single Redis lookup, no scoring
2. Full IDS analysis (`POST /analyze`) — only runs if the IP is not already blocked

---

## C# integration

### 1. Analyze an incoming request

```csharp
// POST https://ids-host:8000/analyze
// Header: X-IDS-API-Key: <your key>

var payload = new {
    request_id  = Guid.NewGuid().ToString(),
    user_id     = currentUserId,
    ip          = remoteIp,
    user_agent  = request.Headers["User-Agent"].ToString(),
    method      = request.Method,
    path        = request.Path.Value,
    query_string= request.QueryString.Value,
    body        = await ReadBodyAsync(request),
    timestamp   = DateTimeOffset.UtcNow
};

var risk = await _idsClient.PostAsJsonAsync<RiskScore>("/analyze", payload);
if (risk.action == "BLOCK")
    return Results.StatusCode(403);
```

### 2. Push an audit event

```csharp
// POST https://ids-host:8000/audit/ingest

var entry = new {
    event_id  = Guid.NewGuid().ToString(),
    user_id   = currentUserId,
    action    = "EXPORT_BOM",
    resource  = $"BOM/{bomId}",
    ip        = remoteIp,
    timestamp = DateTimeOffset.UtcNow,
    meta      = new { bom_id = bomId }
};

var risk = await _idsClient.PostAsJsonAsync<RiskScore>("/audit/ingest", entry);
if (risk.action == "BLOCK")
    ForcefullyEndSession(userId);
```

### Action vocabulary (recommended)

`LOGIN` · `LOGIN_FAILED` · `LOGIN_SUCCESS` · `LOGOUT`  
`EXPORT_BOM` · `VIEW_PART` · `DELETE_PART` · `MODIFY_PART`  
`EXPORT_REPORT` · `ADMIN_CHANGE`

### RiskScore response

```json
{
  "ip": "1.2.3.4",
  "user_id": "u-123",
  "total_score": 85,
  "action": "BLOCK",
  "threats": [
    {
      "threat_type": "SUSPICIOUS_SEQUENCE",
      "severity": "critical",
      "detail": "Login→ExportBOM→Logout in ≤30s",
      "score": 85
    }
  ],
  "evaluated_at": "2026-06-22T13:44:54Z"
}
```

---

## API reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/analyze` | Analyze a forwarded HTTP request (IPS pre-check included) |
| `POST` | `/audit/ingest` | Ingest an audit log entry |
| `GET` | `/ids/threats` | List recent threat events |
| `GET` | `/ips/blocks` | List all active IPS blocks |
| `POST` | `/ips/blocks` | Manually block an IP (`{ "ip", "reason", "ttl" }`) |
| `DELETE` | `/ips/blocks/{ip}` | Unblock an IP |
| `GET` | `/ips/blocks/{ip}/check` | Fast check: is this IP currently blocked? |
| `GET` | `/ips/blacklist` | List signature-based blacklisted IPs |
| `POST` | `/ips/blacklist` | Add IP to signature blacklist |
| `DELETE` | `/ips/blacklist` | Remove IP from signature blacklist |
| `GET` | `/health` | Health check |

All endpoints (except `/health`) require `X-IDS-API-Key` header.

Interactive docs: **http://localhost:8000/docs**

---

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `IDS_API_KEY` | `change-me-secret` | Shared secret with C# backend |
| `REDIS_URL` | `redis://localhost:6379` | Redis for counters, sequence buffers & IPS blocks |
| `GEOIP_DB_PATH` | `./GeoLite2-City.mmdb` | MaxMind DB path |
| `RISK_BLOCK_THRESHOLD` | `80` | Score ≥ this → BLOCK |
| `RISK_ALERT_THRESHOLD` | `50` | Score ≥ this → ALERT |
| `ALERT_WEBHOOK_URL` | _(empty)_ | Webhook URL for ALERT/BLOCK events |
| `RATE_LIMIT_MAX_REQUESTS` | `100` | Requests per `RATE_LIMIT_WINDOW` seconds |
| `BRUTE_FORCE_MAX` | `5` | Failed logins before brute-force flag |
| `IPS_ENABLED` | `true` | Enable/disable automatic IP blocking |
| `IPS_AUTO_BLOCK_TTL` | `3600` | Block duration in seconds (`0` = permanent) |
| `SMTP_HOST` | _(empty)_ | SMTP server hostname (e.g. `smtp.gmail.com`) |
| `SMTP_PORT` | `587` | SMTP port (STARTTLS) |
| `SMTP_USER` | _(empty)_ | SMTP login username |
| `SMTP_PASSWORD` | _(empty)_ | SMTP password / app password |
| `SMTP_FROM` | _(empty)_ | Sender address |
| `ALERT_EMAIL_TO` | _(empty)_ | Recipient address for alert emails |

> **Gmail users:** generate an [App Password](https://myaccount.google.com/apppasswords) and use it as `SMTP_PASSWORD`. Do not use your regular Gmail password.
