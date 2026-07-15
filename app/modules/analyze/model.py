from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
from app.modules.core.ip_utils import is_valid_ip, normalize_ip


class AnalyzeRequest(BaseModel):
    """HTTP request forwarded from C# backend for real-time threat analysis."""
    request_id: str
    user_id: str | None = None
    session_id: str | None = None
    ip: str
    user_agent: str = ""
    method: str
    path: str
    query_string: str = ""
    body: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("ip", mode="before")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        normalized = normalize_ip(str(v))
        if not is_valid_ip(normalized):
            raise ValueError(f"Invalid IP address: {v!r}")
        return normalized
