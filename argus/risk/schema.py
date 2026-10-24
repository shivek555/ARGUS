"""R3 decision record (versioned). Emitted for every judged call; explanations are
mandatory for HIGH/CRITICAL (ARGUS_PROMPT.md §4 component 11)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RISK_SCHEMA_VERSION = "risk-v1"
Level = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Decision = Literal["ALLOW", "MONITOR", "ESCALATE", "BLOCK"]
LEVEL_DECISION: dict[str, str] = {"LOW": "ALLOW", "MEDIUM": "MONITOR", "HIGH": "ESCALATE", "CRITICAL": "BLOCK"}


class Contribution(BaseModel):
    model_config = ConfigDict(frozen=True)
    signal: str
    label: str
    points: float


class RiskDecision(BaseModel):
    schema_version: str = RISK_SCHEMA_VERSION
    step: int
    tool: str
    level: Level
    decision: Decision
    risk_points: float                     # additive score: baseline + sum(contributions)
    probability: float = Field(ge=0.0, le=1.0)  # Platt-calibrated, monotone in risk_points
    baseline_points: float
    contributions: list[Contribution]      # sorted by |points|, largest first
    policy_rule: str | None = None
    llm_reason: str | None = None          # model rationale from untrusted-input analysis
    signal_errors: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)   # why this level (threshold, policy, fail-closed)
    recommended_response: str
