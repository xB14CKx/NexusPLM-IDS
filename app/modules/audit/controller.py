from fastapi import APIRouter, Depends
from app.modules.core.auth import require_api_key
from app.modules.core.models import RiskScore
from app.modules.audit.model import AuditEntry
from app.modules.audit.service import ingest

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.post("/ingest", response_model=RiskScore, dependencies=[Depends(require_api_key)])
async def ingest_audit(entry: AuditEntry) -> RiskScore:
    """
    C# backend pushes audit events here (login, export, delete, etc.).
    Runs behavioral + sequence checks and returns a RiskScore.
    """
    return await ingest(entry)
