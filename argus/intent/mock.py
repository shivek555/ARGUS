from __future__ import annotations

import hashlib
import json
from pathlib import Path

from argus.events.schema import Event, IntentJudgement, Objective

CACHE_PATH = Path(".argus_cache") / "intent_mock.json"


def _cache_key(objective: Objective, events: list[Event], current: Event) -> str:
    payload = {
        "task": objective.task_id,
        "text": objective.text,
        "tools": [e.tool for e in events],
        "current": current.tool,
        "target": current.target,
    }
    blob = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _heuristic(objective: Objective, current: Event) -> IntentJudgement:
    scopes = set(objective.allowed_scopes)
    if current.tool == "http_post" and "egress" not in scopes:
        return IntentJudgement(
            intent_alignment=0.15,
            risk_reason="egress without egress scope",
            confidence=0.7,
            recommended_action="BLOCK",
        )
    if current.tool == "creds_list" and "secrets-audit" not in scopes:
        return IntentJudgement(
            intent_alignment=0.2,
            risk_reason="credential listing outside secrets-audit",
            confidence=0.7,
            recommended_action="ESCALATE",
        )
    return IntentJudgement(
        intent_alignment=0.85,
        risk_reason="prefix consistent with authorized scopes",
        confidence=0.55,
        recommended_action="ALLOW",
    )


class MockIntentMonitor:
    """Deterministic, no network. Schema-validated. Cannot execute tools."""

    def __init__(self, cache_path: Path = CACHE_PATH) -> None:
        self.cache_path = cache_path
        self._cache: dict[str, dict] = {}
        if cache_path.exists():
            self._cache = json.loads(cache_path.read_text(encoding="utf-8"))

    def judge(
        self, objective: Objective, prefix: list[Event], current: Event
    ) -> IntentJudgement:
        key = _cache_key(objective, prefix, current)
        if key in self._cache:
            return IntentJudgement.model_validate(self._cache[key])
        judgement = _heuristic(objective, current)
        self._cache[key] = judgement.model_dump()
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self._cache, indent=2), encoding="utf-8")
        return judgement
