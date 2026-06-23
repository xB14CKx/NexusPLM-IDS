from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from app.modules.core.config import get_settings

_header = APIKeyHeader(name="X-IDS-API-Key")


async def require_api_key(key: str = Security(_header)) -> str:
    if key != get_settings().ids_api_key:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API key")
    return key
