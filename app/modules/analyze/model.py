from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, Field


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
