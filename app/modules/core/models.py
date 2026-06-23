"""Shared Pydantic models used across all modules."""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatEvent(BaseModel):
    request_id: str | None = None
    event_id: str | None = None
    user_id: str | None = None
    ip: str
    threat_type: str
    severity: Severity
    detail: str
    score: int  # 0–100 contribution
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class RiskScore(BaseModel):
    ip: str
    user_id: str | None = None
    total_score: int
    threats: list[ThreatEvent]
    action: str  # ALLOW | ALERT | BLOCK
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
