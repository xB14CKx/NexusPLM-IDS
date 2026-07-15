from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from app.modules.core.auth import require_api_key
from app.modules.core.resolution_token import consume_token
from app.modules.ips.model import IpsBlockRequest, IpsBlockResponse, IpsBlockListResponse
from app.modules.ips import service

router = APIRouter(prefix="/ips", tags=["IPS"])


@router.get("/blocks", response_model=IpsBlockListResponse, dependencies=[Depends(require_api_key)])
async def get_blocks() -> IpsBlockListResponse:
    """List all IPS-managed blocks (active, non-expired)."""
    return await service.list_blocks()


@router.post("/blocks", response_model=IpsBlockResponse, dependencies=[Depends(require_api_key)])
async def block_ip(req: IpsBlockRequest) -> IpsBlockResponse:
    """Manually block an IP. ttl (seconds) is optional; omit for permanent block."""
    return await service.block_ip(req.ip, reason=req.reason, ttl=req.ttl)


@router.delete("/blocks/{ip}", response_model=IpsBlockResponse, dependencies=[Depends(require_api_key)])
async def unblock_ip(ip: str) -> IpsBlockResponse:
    """Remove an IP from the IPS block list."""
    return await service.unblock_ip(ip)


@router.get("/blocks/{ip}/check", dependencies=[Depends(require_api_key)])
async def check_ip(ip: str) -> dict:
    """Fast check: is this IP currently IPS-blocked?"""
    blocked = await service.is_blocked(ip)
    return {"ip": ip, "blocked": blocked}


@router.get("/resolve", response_class=HTMLResponse, tags=["IPS"])
async def resolve_alert(token: str = Query(...)) -> HTMLResponse:
    """
    Email action link handler. No API key required — the signed JWT is the auth.
    Accepts:  GET /ips/resolve?token=<jwt>
    Actions encoded in the token:
      unblock         — removes the IP from the IPS block list
      block_permanent — re-blocks the IP with no TTL (permanent)
    """
    try:
        payload = await consume_token(token)
    except ValueError as exc:
        return _page("❌ Action Failed", str(exc), success=False)

    ip: str = payload["ip"]
    action: str = payload["action"]

    if action == "unblock":
        await service.unblock_ip(ip)
        return _page(
            "✅ IP Unblocked",
            f"<strong>{ip}</strong> has been removed from the block list.",
            success=True,
        )
    else:  # block_permanent
        await service.block_ip(ip, reason="manual:permanent_via_email", ttl=0)
        return _page(
            "🔒 IP Permanently Blocked",
            f"<strong>{ip}</strong> has been permanently blocked.",
            success=True,
        )


def _page(title: str, message: str, *, success: bool) -> HTMLResponse:
    color = "#2d6a4f" if success else "#b5111b"
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NexusPLM IDS — {title}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #f4f4f4;
            display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
    .card {{ background: #fff; border-radius: 8px; padding: 2.5rem 3rem;
             box-shadow: 0 2px 12px rgba(0,0,0,.1); max-width: 480px; text-align: center; }}
    h1 {{ color: {color}; font-size: 1.5rem; margin-bottom: .75rem; }}
    p {{ color: #444; line-height: 1.6; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{title}</h1>
    <p>{message}</p>
    <p style="margin-top:1.5rem;font-size:.85rem;color:#999;">NexusPLM IDS/IPS</p>
  </div>
</body>
</html>"""
    status = 200 if success else 400
    return HTMLResponse(content=html, status_code=status)

