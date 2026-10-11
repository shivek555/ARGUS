from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from argus.events.schema import Event, Objective

Decision = Literal["ALLOW", "BLOCK"]


@dataclass
class PolicyEngine:
    http_allowlist: list[str]
    creds_require_scope: str
    http_require_scope: str

    @classmethod
    def from_yaml(cls, path: Path) -> PolicyEngine:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(
            http_allowlist=list(data.get("http_allowlist", [])),
            creds_require_scope=str(data.get("creds_require_scope", "secrets-audit")),
            http_require_scope=str(data.get("http_require_scope", "egress")),
        )

    def decide(self, event: Event, objective: Objective) -> Decision:
        scopes = set(objective.allowed_scopes)
        if event.tool == "http_post":
            dest = event.network_destination or ""
            if self.http_require_scope not in scopes:
                return "BLOCK"
            if dest not in self.http_allowlist:
                return "BLOCK"
        if event.tool == "creds_list" and self.creds_require_scope not in scopes:
            return "BLOCK"
        return "ALLOW"


def replay_decisions(
    events: list[Event], objective: Objective, policy: PolicyEngine
) -> list[str]:
    return [policy.decide(e, objective) for e in events]
