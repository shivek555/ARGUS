from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from argus.events.schema import Event, Objective
from argus.sandbox.tools import normalize_path

FS_TOOLS = frozenset({"fs_read", "fs_write", "fs_list"})

Decision = Literal["ALLOW", "BLOCK"]


@dataclass(frozen=True)
class PolicyVerdict:
    decision: Decision
    rule: str
    reason: str


@dataclass
class PolicyEngine:
    http_allowlist: list[str]
    creds_require_scope: str
    http_require_scope: str
    # None disables confinement (policy v1 / poc.yaml behaviour is unchanged).
    workspace_root: str | None = None
    # Policy v3 (B2+, ADR-0006): fs_read of a high-sensitivity target needs this
    # scope. None disables it (policy v1/v2 behaviour unchanged).
    sensitive_read_scope: str | None = None

    @classmethod
    def from_yaml(cls, path: Path) -> PolicyEngine:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(
            http_allowlist=list(data.get("http_allowlist", [])),
            creds_require_scope=str(data.get("creds_require_scope", "secrets-audit")),
            http_require_scope=str(data.get("http_require_scope", "egress")),
            workspace_root=(
                normalize_path(str(data["workspace_root"]))
                if data.get("workspace_root") else None
            ),
            sensitive_read_scope=(
                str(data["sensitive_read_scope"]) if data.get("sensitive_read_scope") else None
            ),
        )

    def _inside_workspace(self, path: str) -> bool:
        assert self.workspace_root is not None
        p = normalize_path(path)
        return p == self.workspace_root or p.startswith(self.workspace_root.rstrip("/") + "/")

    def evaluate(self, event: Event, objective: Objective) -> PolicyVerdict:
        """Decision plus the rule that produced it (for explainability)."""
        scopes = set(objective.allowed_scopes)
        if (self.workspace_root is not None and event.tool in FS_TOOLS
                and not self._inside_workspace(event.target)):
            return PolicyVerdict(
                "BLOCK",
                "workspace.confinement",
                f"'{event.target}' is outside {self.workspace_root}",
            )
        if (self.sensitive_read_scope is not None and event.tool == "fs_read"
                and event.data_sensitivity == "high" and self.sensitive_read_scope not in scopes):
            return PolicyVerdict(
                "BLOCK",
                "sensitivity.scope",
                f"reading high-sensitivity '{event.target}' requires scope '{self.sensitive_read_scope}'",
            )
        if event.tool == "http_post":
            dest = event.network_destination or ""
            if self.http_require_scope not in scopes:
                return PolicyVerdict(
                    "BLOCK",
                    "egress.scope",
                    f"http_post requires scope '{self.http_require_scope}'",
                )
            if dest not in self.http_allowlist:
                return PolicyVerdict(
                    "BLOCK", "egress.allowlist", f"destination '{dest}' not in allowlist"
                )
        if event.tool == "creds_list" and self.creds_require_scope not in scopes:
            return PolicyVerdict(
                "BLOCK",
                "credentials.scope",
                f"creds_list requires scope '{self.creds_require_scope}'",
            )
        return PolicyVerdict("ALLOW", "default.allow", "no policy rule matched")

    def decide(self, event: Event, objective: Objective) -> Decision:
        return self.evaluate(event, objective).decision


def replay_decisions(
    events: list[Event], objective: Objective, policy: PolicyEngine
) -> list[str]:
    return [policy.decide(e, objective) for e in events]
