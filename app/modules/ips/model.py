from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel


class IpsBlock(BaseModel):
    ip: str
    reason: str
    blocked_at: datetime
    expires_at: datetime | None  # None = permanent


class IpsBlockRequest(BaseModel):
    ip: str
    reason: str = "manual"
    ttl: int | None = None  # seconds; None = permanent


class IpsBlockResponse(BaseModel):
    ip: str
    action: str       # blocked | unblocked
    expires_at: datetime | None = None


class IpsBlockListResponse(BaseModel):
    blocks: list[IpsBlock]
    total: int
