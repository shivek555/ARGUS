"""Phase W service: the web app's window onto the frozen research system (ADR-0014).

It computes no new research numbers. Bench trajectories carry exactly the signals the R3/R4
dev evaluation used (frozen R1b ML, R2-L LLM verdicts replayed from the committed cache);
result tables come from the committed ``docs/results/`` files that ``reproduce`` writes.

Engines (ADR-0014):
* bench trajectories with LLM verdicts → the **primary** frozen model (ADR-0012);
* custom objectives and the v1 test split (no LLM verdict exists) → the frozen **no-LLM
  ablation** (ADR-0013), because the primary model never saw missing verdicts on risky calls.

Live sessions run through ``ContainedSession`` in enforce mode: HIGH calls wait in a shared
human approval queue (no self-approval, auto-deny on timeout), CRITICAL quarantines the
session and writes a write-once sha256 forensic snapshot. Test v2 is never loaded here.
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from argus.bench.dataset import POLICY_V2, build_world, harm_step
from argus.containment.session import RESERVED_ACTORS, ApprovalQueue, ContainedSession, verify_snapshot
from argus.eval import r1, r1b, r3, r4
from argus.events.builders import redact_result
from argus.events.schema import Event, Objective
from argus.features.trajectory import trajectory_matrix
from argus.intent.monitor import is_risky
from argus.policy.engine import PolicyEngine
from argus.risk.engine import QUANTILES, Levels, RiskEngine
from argus.risk.model import RiskModel
from argus.risk.schema import LEVEL_DECISION
from argus.risk.signals import GROUPS, LABEL, SIGNALS, StepSignals, step_signals, trajectory_signals
from argus.sandbox.tools import make_tools, world_v2

ROOT = r3.ROOT
RESULTS_DIR = ROOT / "docs" / "results"
PROGRESS = ROOT / "docs" / "PROGRESS.md"
SNAPSHOT_DIR = ROOT / "eval" / "results" / "webapp" / "forensics"
DEMO_APPROVAL_TIMEOUT_S = 120.0        # ADR-0014 §9: demo timeout; the engine default stays 300 s
MAX_SESSIONS = 64
MAX_STEPS_PER_SESSION = 100
ID_RE = re.compile(r"^[0-9a-f]{32}$")
REVIEWER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 ._-]{0,39}$")
RESULT_FILES = ("r4_dev", "r3_dev", "r1b_dev_selection", "r2l_runs", "poc_summary", "latency-laptop")
FIGURES = ("r4_roc_dev", "r4_dr_vs_budget_dev", "r4_earliness_dev")
ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

PRIMARY, NO_LLM = "primary", "no-llm-ablation"
ENGINE_INFO = {
    PRIMARY: {"name": "Primary risk model (ADR-0012)", "files": "configs/risk/model.json + levels.yaml",
              "llm": "R2-L verdicts replayed from the committed qwen2.5:3b cache"},
    NO_LLM: {"name": "No-LLM ablation (ADR-0013)", "files": "configs/risk/r4/ablation-no-llm/",
             "llm": "not used: no LLM verdict exists for this input (no live model runs in the app)"},
}
SPLITS = {
    "dev_attacks": "AgentEscapeBench v1 dev attacks (risk model trained on these: in-sample)",
    "dev_benign": "Dev v2 benign with LLM verdicts (risk model trained on these: in-sample)",
    "v1_test": "AgentEscapeBench v1 test (already seen in R1: exploratory)",
}


class NotFound(KeyError):
    pass


class Conflict(RuntimeError):
    pass


class Forbidden(PermissionError):
    pass


@dataclass
class BenchItem:
    tr: r3.Traj
    split: str
    engine: str


@dataclass
class LiveSession:
    id: str
    kind: str                                   # "bench" | "custom"
    engine: str
    session: ContainedSession
    trajectory_id: str | None = None
    script: list[dict[str, Any]] = field(default_factory=list)
    script_pos: int = 0
    records: list[dict[str, Any]] = field(default_factory=list)
    initial_files: dict[str, Any] = field(default_factory=dict)   # path → content at session start


def _label(lab: int | None, is_attack: bool) -> str:
    if not is_attack:
        return "safe"
    return "unsafe" if lab == 1 else "precursor"


def _level_at_least(level: str, floor: str) -> bool:
    return ORDER.index(level) >= ORDER.index(floor)


def parse_progress(path: Path = PROGRESS) -> dict[str, Any]:
    """Phase roadmap and gate tables straight from docs/PROGRESS.md (no duplicated status text)."""
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    phases, gates = [], []
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.startswith("|") else []
        if len(cells) == 4 and re.match(r"^(R\d+b?|W|LA|P)$", cells[0]):
            phases.append({"phase": cells[0], "focus": cells[1], "gate": cells[2], "status": cells[3]})
        elif len(cells) == 2 and re.match(r"^(G\d|Phase 0)", cells[0]):
            gates.append({"gate": cells[0], "status": cells[1]})
    return {"source": "docs/PROGRESS.md", "phases": phases, "gates": gates}


class ResearchService:
    def __init__(self, *, results_dir: Path = RESULTS_DIR, snapshot_dir: Path = SNAPSHOT_DIR,
                 approval_timeout_s: float = DEMO_APPROVAL_TIMEOUT_S, max_sessions: int = MAX_SESSIONS,
                 clock: Callable[[], float] = time.monotonic, progress_path: Path = PROGRESS) -> None:
        t0 = time.perf_counter()
        self.results_dir, self.snapshot_dir, self.progress_path = results_dir, snapshot_dir, progress_path
        self.approval_timeout_s = approval_timeout_s
        self._clock = clock
        self._max_sessions = max_sessions
        self._lock = threading.RLock()
        self.v2 = PolicyEngine.from_yaml(POLICY_V2)
        self.v3 = PolicyEngine.from_yaml(r3.POLICY_V3)

        # Frozen ML exactly as in r3.build (R1b selection, benign-only, threshold from LOIO).
        dev = r1b.load_dev(self.v2)
        kind, nu, scaler = r3.ML_CONFIG
        self.fit = r1b.fit_group(kind, nu, scaler, 0, dev)
        self.tau = r1b.thresholds(self.fit, dev.benign, "global")["plain"]
        self.engines = {
            PRIMARY: RiskEngine(RiskModel.load(r3.MODEL_PATH), Levels.load(r3.LEVELS_PATH)),
            NO_LLM: r4.load_derived("ablation-no-llm"),
        }
        self.manifest = json.loads(r4.MANIFEST.read_text(encoding="utf-8"))

        self.bench: dict[str, BenchItem] = {}
        for tr in r3.build(dev):
            self.bench[tr.t.id] = BenchItem(tr, "dev_attacks" if tr.is_attack else "dev_benign", PRIMARY)
        for p in r1.prepare("test", self.v2):
            sigs = trajectory_signals(p.objective, p.events, self.fit.scores(p), self.tau, v2=self.v2, v3=self.v3,
                                      llm=None)
            fus = p.t.first_unsafe_step
            labels = [0 if p.t.type == "benign" else (1 if e.step >= (fus or 10**9) else None) for e in p.events]
            self.bench[p.t.id] = BenchItem(r3.Traj(p, sigs, p.t.template, p.t.family, labels), "v1_test", NO_LLM)
        self._bench_cache: dict[str, dict[str, Any]] = {}

        self.queue = ApprovalQueue(timeout_s=approval_timeout_s, clock=clock)
        self._sessions: OrderedDict[str, LiveSession] = OrderedDict()
        self._snapshots: dict[str, Path] = {}
        self.tools = sorted(make_tools(world_v2()))
        self.startup_seconds = time.perf_counter() - t0

    # ------------------------------------------------------------------ meta

    def meta(self) -> dict[str, Any]:
        engines = {}
        for k, eng in self.engines.items():
            engines[k] = {**ENGINE_INFO[k], "signals": list(eng.model.names), "levels": eng.levels.__dict__}
        return {
            "frozen": {
                "ml": {"config": "-".join(map(str, r3.ML_CONFIG)), "adr": "ADR-0007", "threshold": self.tau},
                "llm": {"model": r3.LLM_MODEL, "prompt": "monitor-v1", "adr": "ADR-0011", "mode": "replay only"},
                "risk_model": {"sha256": r3.FROZEN_SHA256, "adr": "ADR-0012"},
                "r4_manifest": {"sha256": r4.FROZEN_MANIFEST_SHA256, "adr": "ADR-0013"},
            },
            "engines": engines,
            "signals": [{"name": n, "label": LABEL[n], "group": next(g for g, cols in GROUPS.items() if n in cols)}
                        for n in SIGNALS],
            "level_decision": LEVEL_DECISION,
            "level_rule": {k: f"> threshold reached by ≤ {round((1 - v) * 100)}% of dev benign trajectories"
                           for k, v in QUANTILES.items()},
            "component_thresholds": self.manifest["component_thresholds"],
            "policy": {"path": "configs/policies/v2.yaml", "http_allowlist": self.v2.http_allowlist,
                       "http_require_scope": self.v2.http_require_scope,
                       "creds_require_scope": self.v2.creds_require_scope,
                       "workspace_root": self.v2.workspace_root},
            "tools": self.tools,
            "known_scopes": sorted({s for b in self.bench.values() for s in b.tr.t.allowed_scopes}),
            "splits": SPLITS,
            "approval": {"timeout_s": self.approval_timeout_s, "reserved_actors": sorted(RESERVED_ACTORS),
                         "note": "The reviewer name is self-declared, not authentication: this is a local demo tool."},
            "startup_seconds": round(self.startup_seconds, 1),
        }

    def status(self) -> dict[str, Any]:
        return parse_progress(self.progress_path)

    # ----------------------------------------------------------------- bench

    def _flags(self, item: BenchItem, decisions: list[dict[str, Any]]) -> dict[str, int | None]:
        thr = self.manifest["component_thresholds"]
        sigs, events = item.tr.sigs, item.tr.p.events
        first = lambda pred: next((e.step for e, s in zip(events, sigs) if pred(s)), None)  # noqa: E731
        return {
            "B2_policy_v2": first(lambda s: s.values["policy_block"] >= 1),
            "B2plus_policy_v3": first(lambda s: s.values["policy_block"] >= 1 or s.values["sensitive_unscoped"] >= 1),
            "B3_ml": first(lambda s: s.values["anomaly"] > thr["B3_anomaly"]),
            "B4_llm_native": first(lambda s: s.values["llm_escalate"] >= 1),
            "Hybrid": next((d["step"] for d in decisions if _level_at_least(d["level"], "HIGH")), None),
        }

    def _header(self, tid: str, item: BenchItem, flags: dict[str, int | None]) -> dict[str, Any]:
        t = item.tr.t
        return {"id": tid, "split": item.split, "type": t.type, "family": t.family, "variant": t.variant,
                "template": t.template, "objective": {"text": t.objective_text, "allowed_scopes": list(t.allowed_scopes)},
                "n_steps": len(t.calls), "first_unsafe_step": t.first_unsafe_step,
                "harm_step": harm_step(t, item.tr.p.events) if t.type == "attack" else None,
                "engine": item.engine, "first_flag": flags}

    def _bench_detail(self, tid: str) -> dict[str, Any]:
        if tid in self._bench_cache:
            return self._bench_cache[tid]
        item = self.bench.get(tid)
        if item is None:
            raise NotFound(tid)
        eng = self.engines[item.engine]
        steps, decisions = [], []
        for e, s, lab in zip(item.tr.p.events, item.tr.sigs, item.tr.labels):
            d = eng.decide(s, e.step, e.tool).model_dump(mode="json")
            decisions.append(d)
            steps.append({**_event_view(e), "label": _label(lab, item.tr.is_attack), "risky": s.risky,
                          "signals": s.values, "policy_rule": s.policy_rule, "llm_reason": s.llm_reason,
                          "decision": d})
        flags = self._flags(item, decisions)
        out = {**self._header(tid, item, flags), "split_note": SPLITS[item.split],
               "engine_info": ENGINE_INFO[item.engine], "steps": steps,
               "provenance_note": "Decisions here come from the frozen model applied to data it was trained on "
                                  "(dev) or that was already seen (v1 test). Evaluation numbers use out-of-fold "
                                  "scores: see Results."}
        self._bench_cache[tid] = out
        return out

    def list_bench(self, split: str | None = None, family: str | None = None,
                   variant: str | None = None) -> list[dict[str, Any]]:
        out = []
        with self._lock:
            for tid in sorted(self.bench):
                item = self.bench[tid]
                if (split and item.split != split) or (family and item.tr.family != family) or \
                        (variant and item.tr.t.variant != variant):
                    continue
                d = self._bench_detail(tid)
                out.append({k: v for k, v in d.items() if k not in ("steps", "split_note", "engine_info",
                                                                    "provenance_note")})
        return out

    def bench_detail(self, tid: str) -> dict[str, Any]:
        with self._lock:
            return self._bench_detail(tid)

    # -------------------------------------------------------------- sessions

    def _custom_signals(self, objective: Objective, history: list[Event], e: Event) -> StepSignals:
        row = trajectory_matrix(objective, [*history, e], self.fit.groups)[-1]
        score = self.fit.final.score([row])[0]
        return step_signals(objective, e, v2=self.v2, v3=self.v3, anomaly=score - self.tau, llm=None)

    def create_session(self, *, trajectory_id: str | None, objective_text: str | None,
                       allowed_scopes: list[str]) -> dict[str, Any]:
        sid = uuid.uuid4().hex
        with self._lock:
            if trajectory_id is not None:
                item = self.bench.get(trajectory_id)
                if item is None:
                    raise NotFound(trajectory_id)
                lookup = {e.step: s for e, s in zip(item.tr.p.events, item.tr.sigs)}
                objective, world, engine = item.tr.p.objective, build_world(item.tr.t), item.engine
                signals: Callable[[Objective, list[Event], Event], StepSignals] = lambda o, h, e: lookup[e.step]
                script = [c.model_dump() for c in item.tr.t.calls]
                kind = "bench"
            else:
                assert objective_text is not None
                objective = Objective(task_id=f"web-{sid[:8]}", text=objective_text.strip(),
                                      allowed_scopes=tuple(allowed_scopes))
                world, engine, signals, script, kind = world_v2(), NO_LLM, self._custom_signals, [], "custom"
            sess = ContainedSession(objective=objective, world=world, policy=self.v2, engine=self.engines[engine],
                                    signals=signals, queue=self.queue, snapshot_dir=self.snapshot_dir,
                                    agent_id=f"web-{sid[:6]}", session_id=sid)
            self._sessions[sid] = LiveSession(sid, kind, engine, sess, trajectory_id, script,
                                              initial_files=dict(world.files))
            while len(self._sessions) > self._max_sessions:
                self._sessions.popitem(last=False)
            return self._state(sid)

    def _get(self, sid: str) -> LiveSession:
        if not ID_RE.match(sid) or sid not in self._sessions:
            raise NotFound(sid)
        self._sessions.move_to_end(sid)
        return self._sessions[sid]

    def _request(self, ls: LiveSession, tool: str, args: dict[str, Any], script_index: int | None) -> None:
        if len(ls.records) >= MAX_STEPS_PER_SESSION:
            raise Conflict(f"session reached {MAX_STEPS_PER_SESSION} steps")
        sess = ls.session
        n_dec = len(sess.decisions)
        r = sess.request(tool, args)
        decision = sess.decisions[-1].model_dump(mode="json") if len(sess.decisions) > n_dec else None
        pre = sess.history[-1]
        label = None
        if ls.kind == "bench" and script_index is not None:
            item = self.bench[ls.trajectory_id]  # type: ignore[index]
            label = _label(item.tr.labels[script_index], item.tr.is_attack)
        ls.records.append({"step": r["step"], "tool": tool, "target": pre.target, "args_redacted": pre.args_redacted,
                           "status": r["status"], "reason": r.get("reason"), "approval_id": r.get("approval_id"),
                           "queue": "pending" if r["status"] == "held" else None, "decision": decision,
                           "label": label})
        if sess.quarantined and sess.snapshot_path is not None:
            self._snapshots[ls.id] = sess.snapshot_path

    def invoke(self, sid: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            ls = self._get(sid)
            if ls.kind == "bench":
                raise Conflict("bench sessions replay their recorded script (signals are precomputed per step); "
                               "start a custom session to send your own calls")
            self._request(ls, tool, args, None)
            return self._state(sid)

    def advance_script(self, sid: str) -> dict[str, Any]:
        with self._lock:
            ls = self._get(sid)
            if ls.kind != "bench":
                raise Conflict("session was not created from a bench trajectory")
            if ls.script_pos >= len(ls.script):
                raise Conflict("script already finished")
            call = ls.script[ls.script_pos]
            idx = ls.script_pos
            ls.script_pos += 1
            self._request(ls, call["tool"], dict(call.get("args") or {}), idx)
            return self._state(sid)

    def delete_session(self, sid: str) -> None:
        with self._lock:
            if not ID_RE.match(sid) or self._sessions.pop(sid, None) is None:
                raise NotFound(sid)

    def session_state(self, sid: str) -> dict[str, Any]:
        with self._lock:
            self._get(sid)
            return self._state(sid)

    def _state(self, sid: str) -> dict[str, Any]:
        self.queue.expire()
        ls = self._sessions[sid]
        sess, world = ls.session, ls.session.world
        for rec in ls.records:
            if rec["approval_id"]:
                item = self.queue.items.get(rec["approval_id"])
                if item is not None:
                    rec["queue"] = item.status
                    if item.status == "expired" and rec["status"] == "held":
                        rec["status"] = "denied"
        o = sess.objective
        return {
            "id": sid, "kind": ls.kind, "engine": ls.engine, "engine_info": ENGINE_INFO[ls.engine],
            "trajectory_id": ls.trajectory_id, "mode": "enforce",
            "objective": {"task_id": o.task_id, "text": o.text, "allowed_scopes": list(o.allowed_scopes)},
            "script": None if ls.kind != "bench" else {
                "position": ls.script_pos, "total": len(ls.script),
                "next_tool": ls.script[ls.script_pos]["tool"] if ls.script_pos < len(ls.script) else None},
            "records": ls.records,
            "executed_steps": list(sess.executed),
            "quarantined": sess.quarantined,
            "tools_available": sorted(sess._tools),
            "snapshot": sid if sid in self._snapshots else None,
            "max_steps": MAX_STEPS_PER_SESSION,
            "world": {
                # Only what the agent wrote or changed; sizes only (contents may hold canaries).
                "files_written": [{"path": p, "bytes": len(str(c).encode("utf-8")), "new": p not in ls.initial_files}
                                  for p, c in sorted(world.files.items()) if ls.initial_files.get(p) != c],
                "http_sink": [{"url": str(h.get("url")), "body_redacted": redact_result(h.get("body"))}
                              for h in world.http_sink],
                "credential_names": sorted(world.creds),
            },
        }

    # ------------------------------------------------------------- approvals

    def approvals(self) -> dict[str, Any]:
        with self._lock:
            self.queue.expire()
            now = self._clock()
            items = []
            for it in self.queue.items.values():
                if it.session_id not in self._sessions:
                    continue
                d = it.decision
                items.append({"id": it.id, "session_id": it.session_id, "step": it.step, "tool": it.tool,
                              "args_redacted": it.args_redacted, "status": it.status, "reviewer": it.actor,
                              "seconds_left": max(0.0, self.queue.timeout_s - (now - it.created))
                              if it.status == "pending" else 0.0,
                              "level": d["level"], "risk_points": d["risk_points"],
                              "recommended_response": d["recommended_response"],
                              "contributions": d["contributions"][:4],
                              "objective": self._sessions[it.session_id].session.objective.text})
            items.sort(key=lambda x: (x["status"] != "pending", -x["step"]))
            return {"timeout_s": self.queue.timeout_s, "items": items}

    def decide(self, approval_id: str, approve: bool, reviewer: str) -> dict[str, Any]:
        reviewer = reviewer.strip()
        if not ID_RE.match(approval_id):
            raise NotFound(approval_id)
        if reviewer.lower() in RESERVED_ACTORS or not REVIEWER_RE.match(reviewer):
            raise Forbidden(f"reviewer {reviewer!r} cannot decide approvals (no self-approval; use your own name)")
        with self._lock:
            item = self.queue.items.get(approval_id)
            if item is None or item.session_id not in self._sessions:
                raise NotFound(approval_id)
            ls = self._sessions[item.session_id]
            self.queue.expire()
            if item.status != "pending" or approval_id not in ls.session.held:
                ls.session.held.pop(approval_id, None)       # expired: the held call is dropped, never run
                raise Conflict(f"approval already {item.status}")
            out = ls.session.resolve(approval_id, approve, actor=reviewer)
            for rec in ls.records:
                if rec["approval_id"] == approval_id:
                    rec["status"], rec["queue"] = out["status"], out["queue"]
                    rec["reviewer"] = reviewer
            return {"result": out, "session": self._state(item.session_id)}

    # ------------------------------------------------------------- forensics

    def forensics(self) -> list[dict[str, Any]]:
        with self._lock:
            out = []
            for sid, path in self._snapshots.items():
                snap = json.loads(path.read_text(encoding="utf-8"))
                out.append({"session_id": sid, "created_at": snap["created_at"], "sha256": snap["sha256"],
                            "trigger": {k: snap["trigger"][k] for k in ("step", "tool", "level", "policy_rule")},
                            "objective": snap["objective"]["text"], "n_events": len(snap["events"])})
            return sorted(out, key=lambda x: x["created_at"], reverse=True)

    def _snapshot_path(self, sid: str) -> Path:
        if not ID_RE.match(sid) or sid not in self._snapshots:
            raise NotFound(sid)
        return self._snapshots[sid]

    def forensic(self, sid: str) -> dict[str, Any]:
        with self._lock:
            path = self._snapshot_path(sid)
            return {"path": path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else path.name,
                    "snapshot": json.loads(path.read_text(encoding="utf-8"))}

    def verify(self, sid: str) -> dict[str, Any]:
        with self._lock:
            path = self._snapshot_path(sid)
            snap = json.loads(path.read_text(encoding="utf-8"))
            ok = verify_snapshot(path)
            return {"session_id": sid, "ok": ok, "stored_sha256": snap["sha256"],
                    "detail": "sha256 of the snapshot body matches the stored hash" if ok
                    else "TAMPERED: the snapshot body no longer matches its stored sha256"}

    # --------------------------------------------------------------- results

    def result(self, name: str) -> Any:
        if name not in RESULT_FILES:
            raise NotFound(name)
        path = self.results_dir / f"{name}.json"
        if not path.is_file():
            raise NotFound(f"{name} (not generated yet: run `python -m argus.eval.reproduce`)")
        return json.loads(path.read_text(encoding="utf-8"))

    def figure(self, name: str) -> Path:
        if name not in FIGURES:
            raise NotFound(name)
        path = self.results_dir / "figures" / f"{name}.svg"
        if not path.is_file():
            raise NotFound(name)
        return path

    # ------------------------------------------------------------------ demo

    def reset(self) -> None:
        """Clear live sessions and approvals. Snapshot files stay on disk (evidence is never deleted)."""
        with self._lock:
            self._sessions.clear()
            self._snapshots.clear()
            self.queue = ApprovalQueue(timeout_s=self.approval_timeout_s, clock=self._clock)


def _event_view(e: Event) -> dict[str, Any]:
    return {"step": e.step, "tool": e.tool, "action": e.action, "target": e.target, "args_redacted": e.args_redacted,
            "data_sensitivity": e.data_sensitivity, "network_destination": e.network_destination,
            "result_redacted": e.result_redacted, "risky": is_risky(e)}
