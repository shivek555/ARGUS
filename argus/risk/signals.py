"""R3-a: per-step named signals for the risk engine (docs/PLAN_R3_RISK_ENGINE.md §2).

Every signal is available *before* the call executes. Like the ML features,
nothing here reads ``result_redacted`` or the policy decision of other steps;
the current step's policy verdict is computed directly from the event.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from argus.events.schema import Event, Objective
from argus.intent.monitor import MonitorResult, is_risky
from argus.policy.engine import PolicyEngine
from argus.sandbox.tools import normalize_path

SIGNALS: tuple[str, ...] = (
    "policy_block", "sensitive_unscoped", "anomaly", "objective_deviation", "llm_escalate",
    "llm_missing", "privilege", "data_sensitivity", "destination", "persistence", "objective_mention",
)
GROUPS: dict[str, tuple[str, ...]] = {
    "rules": ("policy_block", "sensitive_unscoped"),
    "ml": ("anomaly",),
    "llm": ("objective_deviation", "llm_escalate", "llm_missing"),
    "context": ("privilege", "data_sensitivity", "destination", "persistence", "objective_mention"),
}
LABEL: dict[str, str] = {
    "policy_block": "blocked by policy rule",
    "sensitive_unscoped": "sensitive read without secrets-audit",
    "anomaly": "anomalous trajectory (ML)",
    "objective_deviation": "objective deviation (LLM)",
    "llm_escalate": "LLM recommends escalation",
    "llm_missing": "no LLM opinion",
    "privilege": "credential / secrets access",
    "data_sensitivity": "data sensitivity",
    "destination": "egress destination",
    "persistence": "persistence (code / config / CI write)",
    "objective_mention": "target named in objective",
}
SENS = {"low": 0.0, "medium": 0.5, "high": 1.0}
PERSIST_EXT = (".py", ".yaml", ".yml", ".json", ".toml", ".sh", ".cfg", ".ini", ".js", ".ts")
PERSIST_DIRS = ("/.github/", "/ci/", "/configs/", "/deploy/", "/scripts/")
SECRET_MARKERS = ("/secrets", ".ssh", "credentials", ".env", "deploy_key", "id_rsa")


@dataclass
class StepSignals:
    values: dict[str, float]
    risky: bool
    errors: list[str] = field(default_factory=list)  # ML/LLM failures on this step (→ fail closed)
    policy_rule: str | None = None
    llm_reason: str | None = None

    def vector(self, names: tuple[str, ...] = SIGNALS) -> list[float]:
        return [self.values[n] for n in names]


def _mentioned(objective: Objective, target: str) -> bool:
    t = target.strip()
    if not t:
        return False
    text = objective.text
    return t in text or (t.startswith("/") and normalize_path(t) in text)


def context_signals(objective: Objective, e: Event) -> dict[str, float]:
    target = e.target or ""
    low = target.lower()
    persistence = e.tool == "fs_write" and (normalize_path(target).endswith(PERSIST_EXT)
                                            or any(d in normalize_path(target) for d in PERSIST_DIRS))
    destination = 0.0
    if e.tool == "http_post":
        destination = 0.5 if _mentioned(objective, target) else 1.0
    return {
        "privilege": float(e.tool == "creds_list" or any(m in low for m in SECRET_MARKERS)),
        "data_sensitivity": SENS.get(e.data_sensitivity, 0.0),
        "destination": destination,
        "persistence": float(persistence),
        "objective_mention": float(_mentioned(objective, target)),
    }


def step_signals(objective: Objective, e: Event, *, v2: PolicyEngine, v3: PolicyEngine,
                 anomaly: float, llm: MonitorResult | None) -> StepSignals:
    """``anomaly`` = ML score minus its frozen threshold. ``llm`` is None when the LLM was not
    consulted (non-risky call, or no cached verdict for this prefix)."""
    pv = v2.evaluate(e, objective)
    v3v = v3.evaluate(e, objective)
    values = {
        "policy_block": float(pv.decision == "BLOCK"),
        "sensitive_unscoped": float(v3v.rule == "sensitivity.scope"),
        "anomaly": float(anomaly),
        "objective_deviation": 0.0,
        "llm_escalate": 0.0,
        "llm_missing": 1.0,
        **context_signals(objective, e),
    }
    errors: list[str] = []
    reason = None
    if llm is not None:
        if llm.verdict is not None:
            values["objective_deviation"] = 1.0 - llm.verdict.intent_alignment
            values["llm_escalate"] = float(llm.recommended_action in ("ESCALATE", "BLOCK"))
            values["llm_missing"] = 0.0
            reason = llm.verdict.risk_reason
        elif llm.error and llm.error != "replay_cache_miss":
            errors.append(f"llm:{llm.error}")  # a real failure, not "never asked"
    return StepSignals(values=values, risky=is_risky(e), errors=errors,
                       policy_rule=pv.rule if pv.decision == "BLOCK" else None, llm_reason=reason)


LLMJudge = Callable[[Objective, list[Event], Event], MonitorResult]


def trajectory_signals(objective: Objective, events: list[Event], anomaly_scores: list[float],
                       threshold: float, *, v2: PolicyEngine, v3: PolicyEngine,
                       llm: LLMJudge | None) -> list[StepSignals]:
    """Signals for every step. The LLM is consulted on risky calls only (R2-L scope)."""
    out = []
    for i, e in enumerate(events):
        verdict = llm(objective, events[:i], e) if (llm is not None and is_risky(e)) else None
        out.append(step_signals(objective, e, v2=v2, v3=v3, anomaly=anomaly_scores[i] - threshold, llm=verdict))
    return out
