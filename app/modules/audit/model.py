from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field, field_validator
from app.modules.core.ip_utils import is_valid_ip, normalize_ip


class AuditEntry(BaseModel):
    """Audit event pushed from C# backend (login, export, delete, etc.)."""
    event_id: str
    user_id: str
    action: str   # LOGIN | LOGIN_FAILED | LOGIN_SUCCESS | LOGOUT | EXPORT_BOM | DELETE_PART | ...
    resource: str = ""
    ip: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    meta: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ip", mode="before")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        normalized = normalize_ip(str(v))
        if not is_valid_ip(normalized):
            raise ValueError(f"Invalid IP address: {v!r}")
        return normalized
