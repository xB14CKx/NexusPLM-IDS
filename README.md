# NexusPLM IDS

FastAPI intrusion detection service that sits alongside your C# + React NexusPLM application.

## Features

| Layer | What it detects |
|---|---|
| **Signature** | SQL injection, XSS, path traversal, known-bad IPs / attack-tool user-agents |
| **Behavioral** | Rate limiting, brute-force login, unusual login hours (off UTC 06–22) |
| **Geo-jump** | Country change within 1 hour for the same user |
| **Sequence** | Suspicious audit chains — e.g. Login → ExportBOM → Logout in ≤30 s |

## Quick start

```bash
cp .env.example .env          # edit IDS_API_KEY and thresholds
docker compose up --build
```

The service is now listening on **http://localhost:8000**.

> **GeoIP (optional):** download `GeoLite2-City.mmdb` from MaxMind and place it in the project root. Without it, geo-jump detection is silently skipped.

---

## C# integration

Add a typed HTTP client in your C# backend and call the IDS on every request and every audit event.

### 1. Analyze an incoming request

```csharp
// POST https://ids-host:8000/analyze
// Header: X-IDS-API-Key: <your key>

var payload = new {
    request_id  = Guid.NewGuid().ToString(),
    user_id     = currentUserId,       // null if anonymous
    session_id  = httpContext.Session.Id,
    ip          = remoteIp,
    user_agent  = request.Headers["User-Agent"].ToString(),
    method      = request.Method,
    path        = request.Path.Value,
    query_string= request.QueryString.Value,
    body        = await ReadBodyAsync(request),  // string
    headers     = request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
    timestamp   = DateTimeOffset.UtcNow
};

var risk = await _idsClient.PostAsJsonAsync<RiskScore>("/analyze", payload);
if (risk.action == "BLOCK")
    return Results.StatusCode(403);
```

### 2. Push an audit event

```csharp
// POST https://ids-host:8000/audit/ingest
// Call this whenever a significant action occurs (login, export, delete, etc.)

var entry = new {
    event_id  = Guid.NewGuid().ToString(),
    user_id   = currentUserId,
    action    = "EXPORT_BOM",        // see action vocabulary below
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
  "action": "BLOCK",          // ALLOW | ALERT | BLOCK
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
| `POST` | `/analyze` | Analyze a forwarded HTTP request |
| `POST` | `/audit/ingest` | Ingest an audit log entry |
| `POST` | `/ips/blacklist?ip=1.2.3.4` | Add IP to in-memory blacklist |
| `DELETE` | `/ips/blacklist?ip=1.2.3.4` | Remove IP from blacklist |
| `GET` | `/health` | Health check |

All write endpoints require `X-IDS-API-Key` header.

Interactive docs: **http://localhost:8000/docs**

---

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `IDS_API_KEY` | `change-me-secret` | Shared secret with C# backend |
| `REDIS_URL` | `redis://localhost:6379` | Redis for counters & sequence buffers |
| `GEOIP_DB_PATH` | `./GeoLite2-City.mmdb` | MaxMind DB path |
| `RISK_BLOCK_THRESHOLD` | `80` | Score ≥ this → BLOCK |
| `RISK_ALERT_THRESHOLD` | `50` | Score ≥ this → ALERT + webhook |
| `ALERT_WEBHOOK_URL` | _(empty)_ | Webhook for ALERT/BLOCK events |
| `RATE_LIMIT_MAX_REQUESTS` | `100` | Requests per `RATE_LIMIT_WINDOW` seconds |
| `BRUTE_FORCE_MAX` | `5` | Failed logins before brute-force flag |
