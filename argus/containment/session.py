"""R3-e: a gateway session that enforces risk levels.

    LOW / MEDIUM → the call goes through the (authoritative) policy gateway
    HIGH         → held in the approval queue; runs only if a *human* approves in time
    CRITICAL     → quarantine: tools revoked (incl. egress), every later call blocked,
                   forensic snapshot written once with a sha256

Nothing in ARGUS can approve a held call: ``ApprovalQueue.decide`` rejects
reserved actor names, and an unanswered request is denied when it expires.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import BaseModel

from argus.events.builders import build_pre_event, redact_result
from argus.events.schema import Event, Objective
from argus.gateway.core import Gateway
from argus.policy.engine import PolicyEngine
from argus.risk.engine import RiskEngine
from argus.risk.schema import RiskDecision
from argus.risk.signals import StepSignals
from argus.sandbox.tools import FakeWorld, make_tools
from argus.telemetry.log import MemoryLogger

RESERVED_ACTORS = frozenset({"argus", "agent", "monitor", "risk_engine", "gateway", "llm", "ml"})
DEFAULT_APPROVAL_TIMEOUT_S = 300.0
Status = Literal["pending", "approved", "denied", "expired"]


# ------------------------------------------------------------- approvals

@dataclass
class PendingCall:
    id: str
    session_id: str
    step: int
    tool: str
    args_redacted: dict[str, Any]
    decision: dict[str, Any]
    created: float
    status: Status = "pending"
    actor: str | None = None


class ApprovalQueue:
    """Held HIGH-risk calls. Append-only JSONL log when ``path`` is given."""

    def __init__(self, path: Path | None = None, timeout_s: float = DEFAULT_APPROVAL_TIMEOUT_S,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.path, self.timeout_s, self._clock = path, timeout_s, clock
        self.items: dict[str, PendingCall] = {}

    def _log(self, kind: str, item: PendingCall) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps({"event": kind, **item.__dict__}, sort_keys=True, default=str) + "\n")

    def submit(self, session_id: str, step: int, tool: str, args_redacted: dict[str, Any],
               decision: RiskDecision) -> str:
        item = PendingCall(uuid.uuid4().hex, session_id, step, tool, args_redacted,
                           decision.model_dump(mode="json"), self._clock())
        self.items[item.id] = item
        self._log("submitted", item)
        return item.id

    def expire(self) -> list[str]:
        now, gone = self._clock(), []
        for item in self.items.values():
            if item.status == "pending" and now - item.created > self.timeout_s:
                item.status, item.actor = "expired", "timeout"
                self._log("expired", item)
                gone.append(item.id)
        return gone

    def decide(self, item_id: str, approve: bool, actor: str) -> Status:
        if not actor or actor.lower() in RESERVED_ACTORS:
            raise PermissionError(f"actor {actor!r} cannot decide approvals (no self-approval)")
        self.expire()
        item = self.items[item_id]
        if item.status != "pending":
            return item.status
        item.status, item.actor = ("approved" if approve else "denied"), actor
        self._log(item.status, item)
        return item.status

    def pending(self) -> list[PendingCall]:
        self.expire()
        return [i for i in self.items.values() if i.status == "pending"]


# -------------------------------------------------------------- snapshot

class ForensicSnapshot(BaseModel):
    session_id: str
    created_at: str
    agent_id: str
    objective: dict[str, Any]
    trigger: dict[str, Any]
    events: list[dict[str, Any]]
    decisions: list[dict[str, Any]]
    files_written: dict[str, str]          # path → redacted content (agent writes since start)
    egress: list[dict[str, Any]]           # redacted
    network_cut: bool
    capabilities_revoked: bool
    sha256: str = ""

    def body_hash(self) -> str:
        body = self.model_dump(mode="json", exclude={"sha256"})
        return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()


def verify_snapshot(path: Path) -> bool:
    snap = ForensicSnapshot.model_validate_json(path.read_text(encoding="utf-8"))
    return snap.sha256 == snap.body_hash()


# --------------------------------------------------------------- session

SignalFn = Callable[[Objective, list[Event], Event], StepSignals]


@dataclass
class ContainedSession:
    objective: Objective
    world: FakeWorld
    policy: PolicyEngine
    engine: RiskEngine
    signals: SignalFn
    queue: ApprovalQueue
    snapshot_dir: Path
    agent_id: str = "agent"
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def __post_init__(self) -> None:
        self._tools = make_tools(self.world)       # we own this dict; quarantine clears it
        self._initial_files = dict(self.world.files)
        self.gateway = Gateway(tools=self._tools, policy=self.policy, logger=MemoryLogger(),
                               objective=self.objective, agent_id=self.agent_id, mode="enforce")
        self.history: list[Event] = []
        self.decisions: list[RiskDecision] = []
        self.held: dict[str, tuple[str, dict[str, Any]]] = {}
        self.quarantined = False
        self.snapshot_path: Path | None = None
        self.executed: list[int] = []              # our step numbers that actually ran

    def request(self, tool: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        args = dict(args or {})
        step = len(self.history) + 1
        pre = build_pre_event(objective=self.objective, agent_id=self.agent_id, step=step, tool=tool, args=args,
                              prev_tool=self.history[-1].tool if self.history else None)
        if self.quarantined:
            self.history.append(pre)
            return {"step": step, "status": "blocked", "reason": "agent quarantined"}
        decision = self.engine.decide(self.signals(self.objective, self.history, pre), step, tool)
        self.history.append(pre)
        self.decisions.append(decision)
        if decision.level == "CRITICAL":
            self._quarantine(decision)
            return {"step": step, "status": "blocked", "level": "CRITICAL", "snapshot": str(self.snapshot_path)}
        if decision.level == "HIGH":
            qid = self.queue.submit(self.session_id, step, tool, pre.args_redacted, decision)
            self.held[qid] = (tool, args)
            return {"step": step, "status": "held", "level": "HIGH", "approval_id": qid}
        result = self.gateway.invoke(tool, args)
        if result.decision == "ALLOW":
            self.executed.append(step)
        return {"step": step, "status": "executed" if result.decision == "ALLOW" else "blocked",
                "level": decision.level}

    def resolve(self, approval_id: str, approve: bool, actor: str) -> dict[str, Any]:
        status = self.queue.decide(approval_id, approve, actor)
        tool, args = self.held.pop(approval_id)
        step = self.queue.items[approval_id].step
        if status != "approved" or self.quarantined:
            return {"step": step, "status": "denied" if status != "approved" else "blocked", "queue": status}
        result = self.gateway.invoke(tool, args)       # policy still applies after approval
        if result.decision == "ALLOW":
            self.executed.append(step)
        return {"step": step, "status": "executed" if result.decision == "ALLOW" else "blocked", "queue": status}

    def _quarantine(self, trigger: RiskDecision) -> None:
        self.quarantined = True
        self._tools.clear()                           # revoke every capability, egress included
        written = {p: redact_result(c) or "" for p, c in self.world.files.items()
                   if self._initial_files.get(p) != c}
        snap = ForensicSnapshot(
            session_id=self.session_id, created_at=datetime.now(timezone.utc).isoformat(), agent_id=self.agent_id,
            objective={"task_id": self.objective.task_id, "text": self.objective.text,
                       "allowed_scopes": list(self.objective.allowed_scopes)},
            trigger=trigger.model_dump(mode="json"),
            events=[e.model_dump(mode="json") for e in self.history],
            decisions=[d.model_dump(mode="json") for d in self.decisions],
            files_written=written,
            egress=[{"url": str(h.get("url")), "body": redact_result(h.get("body"))} for h in self.world.http_sink],
            network_cut=True, capabilities_revoked=True,
        )
        snap.sha256 = snap.body_hash()
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        path = self.snapshot_dir / f"{self.session_id}.json"
        with path.open("x", encoding="utf-8") as fh:   # write-once: never overwrite evidence
            fh.write(snap.model_dump_json(indent=2))
        self.snapshot_path = path
