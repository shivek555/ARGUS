from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# Request bounds. The playground is driven by a human in a browser; these keep a
# malformed or hostile client from growing server memory without limit.
MAX_ARGS = 8
MAX_ARG_CHARS = 10_000
MAX_OBJECTIVE_CHARS = 2_000
MAX_SCOPES = 10

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_SCOPE = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")

ArgValue = str | int | float | bool | None


class ToolCallRequest(BaseModel):
    """One agent tool call. Unknown tool names are allowed through on purpose:
    the gateway must fail closed on them, and the playground demonstrates that."""

    tool: str = Field(min_length=1, max_length=64)
    args: dict[str, ArgValue] = Field(default_factory=dict)

    @field_validator("tool")
    @classmethod
    def _tool_ident(cls, v: str) -> str:
        if not _IDENT.match(v):
            raise ValueError("tool must be an identifier")
        return v

    @field_validator("args")
    @classmethod
    def _bounded_args(cls, v: dict[str, ArgValue]) -> dict[str, ArgValue]:
        if len(v) > MAX_ARGS:
            raise ValueError(f"at most {MAX_ARGS} args")
        for key, value in v.items():
            if not _IDENT.match(key):
                raise ValueError(f"arg name {key!r} must be an identifier")
            if isinstance(value, str) and len(value) > MAX_ARG_CHARS:
                raise ValueError(f"arg {key!r} exceeds {MAX_ARG_CHARS} chars")
        return v


class CreateSessionRequest(BaseModel):
    """Either a free-form objective, or a scenario id whose objective and
    scripted agent are copied into the session."""

    scenario_id: str | None = Field(default=None, max_length=64)
    objective_text: str | None = Field(default=None, max_length=MAX_OBJECTIVE_CHARS)
    allowed_scopes: list[str] = Field(default_factory=list)

    @field_validator("allowed_scopes")
    @classmethod
    def _scopes(cls, v: list[str]) -> list[str]:
        if len(v) > MAX_SCOPES:
            raise ValueError(f"at most {MAX_SCOPES} scopes")
        for scope in v:
            if not _SCOPE.match(scope):
                raise ValueError(f"invalid scope {scope!r}")
        return list(dict.fromkeys(v))

    @model_validator(mode="after")
    def _one_source(self) -> CreateSessionRequest:
        if self.scenario_id is None:
            if not self.objective_text or not self.objective_text.strip():
                raise ValueError("objective_text is required without scenario_id")
        elif self.objective_text is not None or self.allowed_scopes:
            raise ValueError("scenario_id cannot be combined with a custom objective")
        return self


class PolicyExplain(BaseModel):
    decision: str
    rule: str
    reason: str
    source: Literal["policy", "gateway"]


class IntentView(BaseModel):
    intent_alignment: float
    risk_reason: str
    confidence: float
    recommended_action: str


class AnomalyView(BaseModel):
    score: float
    threshold: float
    above_threshold: bool


class StepView(BaseModel):
    step: int
    timestamp: str
    tool: str
    action: str
    target: str
    args_redacted: dict[str, Any]
    data_sensitivity: str
    network_destination: str | None
    prev_tool: str | None
    result_redacted: str | None
    executed: bool
    decision: str
    policy: PolicyExplain
    intent: IntentView
    anomaly: AnomalyView
    label: Literal["safe", "unsafe"] | None
