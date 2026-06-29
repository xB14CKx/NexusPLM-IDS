from fastapi import APIRouter, Depends
from app.modules.core.auth import require_api_key
from app.modules.core.models import RiskScore
from app.modules.analyze.model import AnalyzeRequest
from app.modules.analyze.service import analyze
from app.modules.ips.service import is_blocked

router = APIRouter(prefix="/analyze", tags=["Analyze"])

_BLOCK_RISK = RiskScore(ip="", total_score=100, threats=[], action="BLOCK")


@router.post("", response_model=RiskScore, dependencies=[Depends(require_api_key)])
async def analyze_request(req: AnalyzeRequest) -> RiskScore:
    """
    C# backend forwards every incoming HTTP request here.
    Returns RiskScore — block the user if action == 'BLOCK'.
    IPS-blocked IPs are rejected immediately without full analysis.
    """
    if await is_blocked(req.ip):
        return _BLOCK_RISK.model_copy(update={"ip": req.ip})
    return await analyze(req)
