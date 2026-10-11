from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Objective(BaseModel):
    """Authorized task. Must not be writable by the agent."""

    model_config = ConfigDict(frozen=True)

    task_id: str
    text: str
    allowed_scopes: tuple[str, ...]
    created_at: datetime = Field(default_factory=utcnow)


class Event(BaseModel):
    schema_version: str = SCHEMA_VERSION
    timestamp: datetime = Field(default_factory=utcnow)
    agent_id: str
    task_id: str
    step: int
    tool: str
    action: str
    target: str
    args_redacted: dict[str, Any]
    permissions: list[str]
    data_sensitivity: Literal["low", "medium", "high"]
    network_destination: str | None
    prev_tool: str | None
    result_redacted: str | None = None
    decision: str | None = None
    risk: float | None = None


class IntentJudgement(BaseModel):
    intent_alignment: float
    risk_reason: str
    confidence: float
    recommended_action: Literal["ALLOW", "MONITOR", "ESCALATE", "BLOCK"]
