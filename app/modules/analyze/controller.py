from fastapi import APIRouter, Depends
from app.modules.core.auth import require_api_key
from app.modules.core.models import RiskScore
from app.modules.analyze.model import AnalyzeRequest
from app.modules.analyze.service import analyze

router = APIRouter(prefix="/analyze", tags=["Analyze"])


@router.post("", response_model=RiskScore, dependencies=[Depends(require_api_key)])
async def analyze_request(req: AnalyzeRequest) -> RiskScore:
    """
    C# backend forwards every incoming HTTP request here.
    Returns RiskScore — block the user if action == 'BLOCK'.
    """
    return await analyze(req)
