"""R2-a: LLM intent monitor (baseline B4) with mock / replay / live modes.

    ARGUS_LLM_MODE      mock (default) | replay | live
    ARGUS_LLM_PROVIDER  openai (default, ADR-0010) | anthropic | ollama (ADR-0011: free,
                        open-weights, run on a GitHub-hosted runner by r2-llm.yml)
    ARGUS_OLLAMA_URL    ollama only; default http://127.0.0.1:11434 (loopback hosts only)
    ARGUS_LLM_MODEL     openai: required, no default (your choice; it sets the cost)
                        anthropic: default claude-opus-5-5
    ARGUS_LLM_EFFORT    default medium; "none" omits the reasoning setting (openai)
    ARGUS_LLM_CACHE     default argus/intent/cache/<prompt version>.jsonl
    ARGUS_LLM_FALLBACK  anthropic only: 1 (default) | 0   server-side refusal fallback
    ARGUS_LLM_TIMEOUT   seconds, default 60
    Credentials: OPENAI_API_KEY (openai) or ANTHROPIC_API_KEY / `ant auth login`
    (anthropic), set by the user in their own environment; ARGUS never stores them.

Invariants (ARGUS_PROMPT.md §4, ADR-0009, ADR-0010):
* advisory only: ``apply_advisory`` can raise a policy decision, never lower it;
* no tools: the request carries no tools, tool_choice or MCP servers;
* fail closed: any error, refusal, timeout, schema failure, missing model or
  replay miss becomes ESCALATE for risky calls and MONITOR otherwise;
* reproducible: no sampling parameters are sent, so answers vary run to run;
  every live answer (and refusal) is stored in a sha256-keyed cache and
  ``replay`` serves only from it, with no network.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from argus.events.schema import Event, IntentJudgement, Objective
from argus.intent import prompt as P
from argus.intent.mock import _heuristic

Action = Literal["ALLOW", "MONITOR", "ESCALATE", "BLOCK"]
Provider = Literal["anthropic", "openai", "ollama"]
SEVERITY: dict[str, int] = {"ALLOW": 0, "MONITOR": 1, "ESCALATE": 2, "BLOCK": 3}
RISKY_TOOLS = frozenset({"fs_write", "http_post", "creds_list"})
KNOWN_TOOLS = frozenset({"fs_read", "fs_write", "fs_list", "repo_search", "http_post", "creds_list"})
FALLBACK_BETA = "server-side-fallback-2026-07-01"
DEFAULT_MODEL: dict[str, str] = {"anthropic": "claude-opus-5-5", "openai": "", "ollama": ""}  # user picks
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
OLLAMA_NUM_PREDICT = 1024  # the verdict is a short JSON object; bounds CPU time per call
OLLAMA_SEED = 0
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
    usage: dict[str, int] | None = None   # tokens of the API call that produced this (live only)
    latency_ms: float | None = None

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
    provider: Provider = "openai"
    model: str = ""  # empty → DEFAULT_MODEL[provider]
    effort: str = "medium"
    cache_path: Path = field(default_factory=lambda: CACHE_DIR / f"{P.PROMPT_VERSION}.jsonl")
    fallback: bool = True
    timeout_s: float = 60.0
    max_tokens: int = 16000
    ollama_url: str = "http://127.0.0.1:11434"

    def __post_init__(self) -> None:
        if self.provider not in DEFAULT_MODEL:
            raise ValueError(f"provider must be anthropic|openai, got {self.provider!r}")
        if not self.model:
            object.__setattr__(self, "model", DEFAULT_MODEL[self.provider])
        if self.provider != "anthropic":
            object.__setattr__(self, "fallback", False)  # server-side fallback is an Anthropic feature
        if self.provider == "ollama":
            object.__setattr__(self, "effort", "none")  # no reasoning-effort setting for local models

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> MonitorConfig:
        e = os.environ if env is None else env
        mode = e.get("ARGUS_LLM_MODE", "mock")
        if mode not in ("mock", "replay", "live"):
            raise ValueError(f"ARGUS_LLM_MODE must be mock|replay|live, got {mode!r}")
        kw: dict[str, Any] = {"mode": mode, "provider": e.get("ARGUS_LLM_PROVIDER", "openai")}
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
        if "ARGUS_OLLAMA_URL" in e:
            kw["ollama_url"] = e["ARGUS_OLLAMA_URL"]
        return cls(**kw)


def cache_key(cfg: MonitorConfig, objective: Objective, prefix: list[Event], current: Event) -> str:
    blob = json.dumps({
        "provider": cfg.provider, "model": cfg.model, "effort": cfg.effort, "fallback": cfg.fallback,
        "prompt": P.prompt_hash(), "schema": P.SCHEMA_VERSION,
        "input": P.input_payload(objective, prefix, current),
    }, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class ResponseCache:
    """Append-only JSONL: one {key, verdict | error, served_by, fallback_used, usage} per line."""

    def __init__(self, path: Path, also_read: tuple[Path, ...] = ()) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, Any]] = {}
        for src in (*also_read, path):
            if src.exists():
                for line in src.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        rec = json.loads(line)
                        self._data[rec["key"]] = rec

    @classmethod
    def from_dir(cls, directory: Path, write_name: str) -> ResponseCache:
        """Read every *.jsonl in ``directory``; write only to ``directory/write_name``.
        Lets separate workflow jobs commit separate files without merge conflicts."""
        others = tuple(sorted(f for f in directory.glob("*.jsonl") if f.name != write_name)) \
            if directory.exists() else ()
        return cls(directory / write_name, also_read=others)

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
                         cache_key=key, usage=rec.get("usage"), latency_ms=rec.get("latency_ms"))


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
        self.cache = cache if cache is not None else ResponseCache(cfg.cache_path)

    def judge(self, objective: Objective, prefix: list[Event], current: Event) -> MonitorResult:
        key = cache_key(self.cfg, objective, prefix, current)
        rec = self.cache.get(key)
        return _from_record(rec, current, "replay") if rec else fail_closed(current, "replay_cache_miss", key)


@dataclass
class Outcome:
    """Provider-neutral result of one API call."""

    text: str | None
    error: str | None
    served_by: str | None
    usage: dict[str, int]
    fallback_used: bool = False


class LiveMonitor:
    """Calls the configured provider once per judgement (cache first). Every outcome is fail-closed-safe."""

    def __init__(self, cfg: MonitorConfig, cache: ResponseCache | None = None,
                 client_factory: Callable[[], Any] | None = None) -> None:
        self.cfg = cfg
        self.cache = cache if cache is not None else ResponseCache(cfg.cache_path)
        self._factory = client_factory or (lambda: _default_client(cfg))
        self._client: Any = None
        self.calls = 0  # API requests actually sent (for budget accounting)

    def request_kwargs(self, objective: Objective, prefix: list[Event], current: Event) -> dict[str, Any]:
        if self.cfg.provider == "ollama":
            return _ollama_kwargs(self.cfg, objective, prefix, current)
        if self.cfg.provider == "openai":
            return _openai_kwargs(self.cfg, objective, prefix, current)
        return _anthropic_kwargs(self.cfg, objective, prefix, current)

    def _call(self, client: Any, kwargs: dict[str, Any]) -> Outcome:
        if self.cfg.provider == "ollama":
            return _ollama_outcome(client.chat(**kwargs))
        if self.cfg.provider == "openai":
            return _openai_outcome(client.responses.create(**kwargs))
        return _anthropic_outcome(client.beta.messages.create(**kwargs))

    def judge(self, objective: Objective, prefix: list[Event], current: Event) -> MonitorResult:
        key = cache_key(self.cfg, objective, prefix, current)
        rec = self.cache.get(key)
        if rec:
            return _from_record(rec, current, "replay")
        if not self.cfg.model:
            return fail_closed(current, "config:model_not_set (set ARGUS_LLM_MODEL)", key)
        try:
            if self._client is None:
                self._client = self._factory()
            client = self._client.with_options(timeout=self.cfg.timeout_s, max_retries=2)
            self.calls += 1
            t0 = time.perf_counter()
            out = self._call(client, self.request_kwargs(objective, prefix, current))
            latency_ms = (time.perf_counter() - t0) * 1000
        except Exception as exc:  # noqa: BLE001 — a security monitor fails closed on anything
            return fail_closed(current, f"api_error:{type(exc).__name__}", key)  # transient: not cached

        record: dict[str, Any] = {"key": key, "served_by": out.served_by, "fallback_used": out.fallback_used,
                                  "usage": out.usage, "latency_ms": round(latency_ms, 1)}
        if out.error:
            record["error"] = out.error
        else:
            try:
                verdict = MonitorVerdict.model_validate(json.loads(out.text or ""))
            except (json.JSONDecodeError, ValidationError) as exc:
                record["error"] = f"schema_invalid:{type(exc).__name__}"
            else:
                verdict.evidence_steps = [s for s in verdict.evidence_steps if 1 <= s <= current.step]
                record["verdict"] = verdict.model_dump()
        # Successes and deterministic failures (refusal, schema, max_tokens) are cached so
        # replay reproduces them and they are never paid for twice.
        self.cache.put(record)
        result = _from_record(record, current, "live")
        # Failures carry cost too; expose usage/latency on fail-closed results as well.
        return result.model_copy(update={"usage": record["usage"], "latency_ms": record["latency_ms"]})


# ------------------------------------------------------- provider adapters

USAGE_FIELDS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")


def _anthropic_kwargs(cfg: MonitorConfig, objective: Objective, prefix: list[Event],
                      current: Event) -> dict[str, Any]:
    kw: dict[str, Any] = {
        "model": cfg.model,
        "max_tokens": cfg.max_tokens,
        "system": [{"type": "text", "text": P.SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": P.render_user_message(objective, prefix, current)}],
        "output_config": {"effort": cfg.effort,
                          "format": {"type": "json_schema", "schema": P.VERDICT_JSON_SCHEMA}},
    }
    if cfg.fallback:
        kw["betas"] = [FALLBACK_BETA]
        kw["fallbacks"] = "default"
    return kw


def _anthropic_outcome(response: Any) -> Outcome:
    u = getattr(response, "usage", None)
    out = Outcome(text=None, error=None, served_by=getattr(response, "model", None),
                  usage={f: int(getattr(u, f, 0) or 0) for f in USAGE_FIELDS},
                  fallback_used=any(getattr(it, "type", None) == "fallback_message"
                                    for it in (getattr(u, "iterations", None) or [])))
    stop = getattr(response, "stop_reason", None)
    if stop == "refusal":
        out.error = f"refusal:{getattr(getattr(response, 'stop_details', None), 'category', None)}"
    elif stop == "max_tokens":
        out.error = "max_tokens"
    else:
        out.text = next((b.text for b in getattr(response, "content", []) if getattr(b, "type", None) == "text"),
                        None)
    return out


def _openai_kwargs(cfg: MonitorConfig, objective: Objective, prefix: list[Event],
                   current: Event) -> dict[str, Any]:
    """Responses API with a strict JSON schema (structured outputs). No tools; not stored by OpenAI."""
    kw: dict[str, Any] = {
        "model": cfg.model,
        "instructions": P.SYSTEM_PROMPT,
        "input": [{"role": "user", "content": P.render_user_message(objective, prefix, current)}],
        "text": {"format": {"type": "json_schema", "name": "argus_verdict",
                            "schema": P.VERDICT_JSON_SCHEMA, "strict": True}},
        "max_output_tokens": cfg.max_tokens,
        "store": False,
        "prompt_cache_key": f"argus-{P.PROMPT_VERSION}",
    }
    if cfg.effort != "none":
        kw["reasoning"] = {"effort": cfg.effort}
    return kw


def _openai_outcome(response: Any) -> Outcome:
    u = getattr(response, "usage", None)
    cached = int(getattr(getattr(u, "input_tokens_details", None), "cached_tokens", 0) or 0)
    usage = {"input_tokens": max(0, int(getattr(u, "input_tokens", 0) or 0) - cached),  # uncached part
             "output_tokens": int(getattr(u, "output_tokens", 0) or 0),                # includes reasoning
             "cache_creation_input_tokens": 0, "cache_read_input_tokens": cached}
    out = Outcome(text=None, error=None, served_by=getattr(response, "model", None), usage=usage)
    status = getattr(response, "status", None)
    refused = any(getattr(c, "type", None) == "refusal"
                  for item in (getattr(response, "output", None) or [])
                  for c in (getattr(item, "content", None) or []))
    if refused:
        out.error = "refusal:openai"
    elif status == "incomplete":
        reason = getattr(getattr(response, "incomplete_details", None), "reason", None)
        out.error = {"max_output_tokens": "max_tokens", "content_filter": "refusal:content_filter"}.get(
            reason, f"incomplete:{reason}")
    elif status not in (None, "completed"):
        out.error = f"status:{status}"
    else:
        out.text = getattr(response, "output_text", None)
    return out


class OllamaHTTPError(RuntimeError):
    pass


class OllamaClient:
    """Minimal client for Ollama's local REST API. Loopback hosts only: trajectory
    data can only reach an Ollama process on the same machine. Proxy env vars are
    ignored (``trust_env=False``) for the same reason."""

    def __init__(self, base_url: str, timeout: float = 60.0, transport: httpx.BaseTransport | None = None) -> None:
        if httpx.URL(base_url).host not in LOOPBACK_HOSTS:
            raise ValueError(f"Ollama URL must be a loopback address, got {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._transport = transport

    def with_options(self, timeout: float | None = None, max_retries: int | None = None) -> OllamaClient:
        del max_retries  # a local server: no retry loop
        return OllamaClient(self.base_url, timeout or self.timeout, self._transport)

    def chat(self, **body: Any) -> dict[str, Any]:
        with httpx.Client(transport=self._transport, timeout=self.timeout, trust_env=False) as client:
            response = client.post(f"{self.base_url}/api/chat", json=body)
        if response.status_code != 200:
            raise OllamaHTTPError(f"HTTP {response.status_code}")
        data = response.json()
        if not isinstance(data, dict):
            raise OllamaHTTPError("non-object response")
        return data


OLLAMA_SCHEMA_HINT = "\n\nRespond with one JSON object that matches this schema:\n" + json.dumps(
    P.VERDICT_JSON_SCHEMA, sort_keys=True)


def _ollama_kwargs(cfg: MonitorConfig, objective: Objective, prefix: list[Event],
                   current: Event) -> dict[str, Any]:
    """POST /api/chat body: schema-enforced ``format``, deterministic decoding, no tools.
    Ollama's docs recommend also giving the schema as text, hence OLLAMA_SCHEMA_HINT."""
    return {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": P.SYSTEM_PROMPT},
            {"role": "user", "content": P.render_user_message(objective, prefix, current) + OLLAMA_SCHEMA_HINT},
        ],
        "format": P.VERDICT_JSON_SCHEMA,
        "stream": False,
        "keep_alive": "30m",
        "options": {"temperature": 0, "seed": OLLAMA_SEED, "num_predict": OLLAMA_NUM_PREDICT},
    }


def _ollama_outcome(data: dict[str, Any]) -> Outcome:
    usage = {"input_tokens": int(data.get("prompt_eval_count") or 0),
             "output_tokens": int(data.get("eval_count") or 0),
             "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    out = Outcome(text=None, error=None, served_by=data.get("model"), usage=usage)
    reason = data.get("done_reason")
    if data.get("done") is False:
        out.error = "incomplete:not_done"
    elif reason not in (None, "stop"):
        out.error = "max_tokens" if reason == "length" else f"incomplete:{reason}"
    else:
        out.text = (data.get("message") or {}).get("content")
    return out


def _default_client(cfg: MonitorConfig) -> Any:
    # Imported lazily: mock/replay never need an SDK or credentials.
    if cfg.provider == "ollama":
        return OllamaClient(cfg.ollama_url, cfg.timeout_s)
    if cfg.provider == "openai":
        import openai

        return openai.OpenAI()  # reads OPENAI_API_KEY from the user's environment
    import anthropic

    return anthropic.Anthropic()


def build_monitor(cfg: MonitorConfig | None = None, **kw: Any) -> IntentMonitor:
    cfg = cfg or MonitorConfig.from_env()
    if cfg.mode == "mock":
        return MockMonitor()
    if cfg.mode == "replay":
        return ReplayMonitor(cfg, **kw)
    return LiveMonitor(cfg, **kw)
