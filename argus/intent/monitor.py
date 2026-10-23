"""R2-a: LLM intent monitor (baseline B4) with mock / replay / live modes.

    ARGUS_LLM_MODE   mock (default) | replay | live
    ARGUS_LLM_MODEL  default claude-opus-5-5
    ARGUS_LLM_EFFORT default medium   (Opus 5.5 thinking can't be disabled; effort is the control)
    ARGUS_LLM_CACHE  default argus/intent/cache/<prompt version>.jsonl
    ARGUS_LLM_FALLBACK  1 (default) | 0   server-side refusal fallback
    ARGUS_LLM_TIMEOUT   seconds, default 60

Invariants (ARGUS_PROMPT.md §4, ADR-0009):
* advisory only: ``apply_advisory`` can raise a policy decision, never lower it;
* no tools: the request carries no tools, tool_choice or MCP servers;
* fail closed: any error, refusal, timeout, schema failure or replay miss
  becomes ESCALATE for risky calls and MONITOR otherwise, with the reason kept;
* reproducible: current models reject sampling parameters, so answers vary run
  to run; every live answer (and refusal) is stored in a sha256-keyed cache and
  ``replay`` serves only from it, with no network.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from argus.events.schema import Event, IntentJudgement, Objective
from argus.intent import prompt as P
from argus.intent.mock import _heuristic

Action = Literal["ALLOW", "MONITOR", "ESCALATE", "BLOCK"]
SEVERITY: dict[str, int] = {"ALLOW": 0, "MONITOR": 1, "ESCALATE": 2, "BLOCK": 3}
RISKY_TOOLS = frozenset({"fs_write", "http_post", "creds_list"})
KNOWN_TOOLS = frozenset({"fs_read", "fs_write", "fs_list", "repo_search", "http_post", "creds_list"})
FALLBACK_BETA = "server-side-fallback-2026-07-01"
CACHE_DIR = Path(__file__).resolve().parent / "cache"


class MonitorVerdict(BaseModel):
    """What the model must return (validated after the API's JSON-schema check)."""

    model_config = ConfigDict(extra="forbid")

    intent_alignment: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    risk_reason: str = Field(max_length=600)
    recommended_action: Action
    evidence_steps: list[int] = Field(default_factory=list, max_length=50)


class MonitorResult(BaseModel):
    recommended_action: Action
    verdict: MonitorVerdict | None
    source: Literal["mock", "replay", "live", "fail_closed"]
    error: str | None = None
    served_by: str | None = None
    fallback_used: bool = False
    cache_key: str | None = None

    def as_intent_judgement(self) -> IntentJudgement:
        """Legacy shape used by the PoC/API. Fail-closed results have alignment 0, confidence 0."""
        v = self.verdict
        return IntentJudgement(
            intent_alignment=v.intent_alignment if v else 0.0,
            risk_reason=v.risk_reason if v else f"monitor failed closed: {self.error}",
            confidence=v.confidence if v else 0.0,
            recommended_action=self.recommended_action,
        )


def is_risky(e: Event) -> bool:
    return (e.tool in RISKY_TOOLS or e.tool not in KNOWN_TOOLS
            or (e.tool == "fs_read" and e.data_sensitivity == "high"))


def fail_closed(current: Event, error: str, key: str | None = None) -> MonitorResult:
    return MonitorResult(recommended_action="ESCALATE" if is_risky(current) else "MONITOR",
                         verdict=None, source="fail_closed", error=error, cache_key=key)


def apply_advisory(policy_decision: str, monitor_action: str) -> str:
    """The monitor can only raise scrutiny: never below the policy decision.
    Anything unrecognised on either side is treated as BLOCK (fail closed)."""
    if policy_decision not in SEVERITY or monitor_action not in SEVERITY:
        return "BLOCK"
    return max((policy_decision, monitor_action), key=SEVERITY.__getitem__)


# ------------------------------------------------------------------ config

@dataclass(frozen=True)
class MonitorConfig:
    mode: Literal["mock", "replay", "live"] = "mock"
    model: str = "claude-opus-5-5"
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "medium"
    cache_path: Path = field(default_factory=lambda: CACHE_DIR / f"{P.PROMPT_VERSION}.jsonl")
    fallback: bool = True
    timeout_s: float = 60.0
    max_tokens: int = 16000

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> MonitorConfig:
        e = os.environ if env is None else env
        mode = e.get("ARGUS_LLM_MODE", "mock")
        if mode not in ("mock", "replay", "live"):
            raise ValueError(f"ARGUS_LLM_MODE must be mock|replay|live, got {mode!r}")
        kw: dict[str, Any] = {"mode": mode}
        if "ARGUS_LLM_MODEL" in e:
            kw["model"] = e["ARGUS_LLM_MODEL"]
        if "ARGUS_LLM_EFFORT" in e:
            kw["effort"] = e["ARGUS_LLM_EFFORT"]
        if "ARGUS_LLM_CACHE" in e:
            kw["cache_path"] = Path(e["ARGUS_LLM_CACHE"])
        if "ARGUS_LLM_FALLBACK" in e:
            kw["fallback"] = e["ARGUS_LLM_FALLBACK"] not in ("0", "false", "False")
        if "ARGUS_LLM_TIMEOUT" in e:
            kw["timeout_s"] = float(e["ARGUS_LLM_TIMEOUT"])
        return cls(**kw)


def cache_key(cfg: MonitorConfig, objective: Objective, prefix: list[Event], current: Event) -> str:
    blob = json.dumps({
        "model": cfg.model, "effort": cfg.effort, "fallback": cfg.fallback,
        "prompt": P.prompt_hash(), "schema": P.SCHEMA_VERSION,
        "input": P.input_payload(objective, prefix, current),
    }, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class ResponseCache:
    """Append-only JSONL: one {key, verdict | error, served_by, fallback_used} per line."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, Any]] = {}
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self._data[rec["key"]] = rec

    def get(self, key: str) -> dict[str, Any] | None:
        return self._data.get(key)

    def put(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._data[record["key"]] = record
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n")

    def __len__(self) -> int:
        return len(self._data)


def _from_record(rec: dict[str, Any], current: Event, source: Literal["replay", "live"]) -> MonitorResult:
    key = rec["key"]
    if rec.get("error"):
        return fail_closed(current, rec["error"], key)
    try:
        verdict = MonitorVerdict.model_validate(rec["verdict"])
    except (ValidationError, KeyError, TypeError) as exc:
        return fail_closed(current, f"schema_invalid:{type(exc).__name__}", key)
    return MonitorResult(recommended_action=verdict.recommended_action, verdict=verdict, source=source,
                         served_by=rec.get("served_by"), fallback_used=bool(rec.get("fallback_used")),
                         cache_key=key)


# ---------------------------------------------------------------- backends

class IntentMonitor(Protocol):
    def judge(self, objective: Objective, prefix: list[Event], current: Event) -> MonitorResult: ...


class MockMonitor:
    """The PoC's deterministic scope heuristic, in the R2 result shape. No I/O."""

    def judge(self, objective: Objective, prefix: list[Event], current: Event) -> MonitorResult:
        j = _heuristic(objective, current)
        v = MonitorVerdict(intent_alignment=j.intent_alignment, confidence=j.confidence,
                           risk_reason=j.risk_reason, recommended_action=j.recommended_action,
                           evidence_steps=[current.step])
        return MonitorResult(recommended_action=v.recommended_action, verdict=v, source="mock")


class ReplayMonitor:
    """Serves only from the committed cache. A miss fails closed; never calls the network."""

    def __init__(self, cfg: MonitorConfig, cache: ResponseCache | None = None) -> None:
        self.cfg = cfg
        self.cache = cache or ResponseCache(cfg.cache_path)

    def judge(self, objective: Objective, prefix: list[Event], current: Event) -> MonitorResult:
        key = cache_key(self.cfg, objective, prefix, current)
        rec = self.cache.get(key)
        return _from_record(rec, current, "replay") if rec else fail_closed(current, "replay_cache_miss", key)


class LiveMonitor:
    """Calls the Claude API once per judgement (cache first). Every outcome is fail-closed-safe."""

    def __init__(self, cfg: MonitorConfig, cache: ResponseCache | None = None,
                 client_factory: Callable[[], Any] | None = None) -> None:
        self.cfg = cfg
        self.cache = cache or ResponseCache(cfg.cache_path)
        self._factory = client_factory or _default_client
        self._client: Any = None
        self.calls = 0  # API requests actually sent (for budget accounting)

    def request_kwargs(self, objective: Objective, prefix: list[Event], current: Event) -> dict[str, Any]:
        kw: dict[str, Any] = {
            "model": self.cfg.model,
            "max_tokens": self.cfg.max_tokens,
            "system": [{"type": "text", "text": P.SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": P.render_user_message(objective, prefix, current)}],
            "output_config": {"effort": self.cfg.effort,
                              "format": {"type": "json_schema", "schema": P.VERDICT_JSON_SCHEMA}},
        }
        if self.cfg.fallback:
            kw["betas"] = [FALLBACK_BETA]
            kw["fallbacks"] = "default"
        return kw

    def judge(self, objective: Objective, prefix: list[Event], current: Event) -> MonitorResult:
        key = cache_key(self.cfg, objective, prefix, current)
        rec = self.cache.get(key)
        if rec:
            return _from_record(rec, current, "replay")
        try:
            if self._client is None:
                self._client = self._factory()
            client = self._client.with_options(timeout=self.cfg.timeout_s, max_retries=2)
            self.calls += 1
            response = client.beta.messages.create(**self.request_kwargs(objective, prefix, current))
        except Exception as exc:  # noqa: BLE001 — a security monitor fails closed on anything
            return fail_closed(current, f"api_error:{type(exc).__name__}", key)  # transient: not cached

        record: dict[str, Any] = {"key": key, "served_by": getattr(response, "model", None),
                                  "fallback_used": _fallback_used(response)}
        stop = getattr(response, "stop_reason", None)
        if stop == "refusal":
            details = getattr(response, "stop_details", None)
            record["error"] = f"refusal:{getattr(details, 'category', None)}"
        elif stop == "max_tokens":
            record["error"] = "max_tokens"
        else:
            text = next((b.text for b in getattr(response, "content", []) if getattr(b, "type", None) == "text"), None)
            try:
                verdict = MonitorVerdict.model_validate(json.loads(text or ""))
            except (json.JSONDecodeError, ValidationError) as exc:
                record["error"] = f"schema_invalid:{type(exc).__name__}"
            else:
                verdict.evidence_steps = [s for s in verdict.evidence_steps if 1 <= s <= current.step]
                record["verdict"] = verdict.model_dump()
        # Successes and deterministic failures (refusal, schema, max_tokens) are cached so
        # replay reproduces them and they are never paid for twice.
        self.cache.put(record)
        return _from_record(record, current, "live")


def _fallback_used(response: Any) -> bool:
    usage = getattr(response, "usage", None)
    return any(getattr(it, "type", None) == "fallback_message" for it in (getattr(usage, "iterations", None) or []))


def _default_client() -> Any:
    import anthropic  # imported lazily: mock/replay never need the SDK or credentials

    return anthropic.Anthropic()


def build_monitor(cfg: MonitorConfig | None = None, **kw: Any) -> IntentMonitor:
    cfg = cfg or MonitorConfig.from_env()
    if cfg.mode == "mock":
        return MockMonitor()
    if cfg.mode == "replay":
        return ReplayMonitor(cfg, **kw)
    return LiveMonitor(cfg, **kw)
