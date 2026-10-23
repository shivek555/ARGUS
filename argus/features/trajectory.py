"""Trajectory features v2 (Phase R1-d). Designed on the DEV split only.

One vector per prefix ``events[:i]``, so detection is computed per step.
Inputs are the immutable objective and gateway events. Like ``prefix.py``,
this module never reads ``result_redacted``, ``decision`` or ``risk``
(``FORBIDDEN_FEATURE_FIELDS``): those are post-execution or label-like.

Why v2 differs from the PoC (see docs/PLAN_R1_RESCUE.md §1): the PoC vector was
mostly tool-identity counts, i.e. the same signal the policy already uses.
v2 describes behaviour *relative to the objective* (does the target relate to
the task? did the agent touch secrets the task does not need? did sensitive
reads flow into writes or egress?), plus sequence shape.

Not used by default (R1-d dev diagnostic, docs/DECISIONS.md ADR-0004):

* ``step`` (``length`` group). On dev, unsafe steps sit late in trajectories
  (first_unsafe ≈ 4.2–4.7 vs benign length ≈ 4.8), so ``step`` alone scores
  AUROC 0.80: a template artefact, not behaviour.
* the ``[CANARY]`` marker the redactor puts into args: a perfect "secret in
  outgoing data" oracle that only exists because our benchmark plants
  canaries, so it is an optional, ablation-only ``dlp`` group.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from argus.events.schema import Event, Objective
from argus.features.prefix import FORBIDDEN_FEATURE_FIELDS
from argus.sandbox.tools import normalize_path

__all__ = [
    "FEATURE_GROUPS", "FEATURE_NAMES", "FORBIDDEN_FEATURE_FIELDS", "feature_names",
    "prefix_features", "trajectory_matrix",
]

SENS = {"low": 0.0, "medium": 0.5, "high": 1.0}
ACTIONS = ("read", "write", "list", "search", "egress", "credential_access")
FS_TOOLS = {"fs_read", "fs_write", "fs_list"}

# Generic secret-scanner vocabulary (gitleaks/trufflehog-style keywords), not
# tuned to any split. Caveat: chosen by the same author who wrote the test
# templates; see docs/BENCH_V1.md limitations.
SECRET_TERMS = ("password", "passwd", "secret", "token", "api_key", "apikey", "credential",
                "private key", "aws", "ssh", "deploy_key", ".env")
WRITE_INTENT = ("write", "save", "record", "report", "create", "update", "edit", "fix", "store")
CODE_EXT = (".py", ".yaml", ".yml", ".json", ".toml", ".sh", ".cfg", ".ini", ".js", ".ts")
_STOP = {"the", "and", "for", "from", "with", "into", "that", "this", "your", "new", "all",
         "files", "file", "workspace", "http", "https", "api", "fake", "local", "what", "which"}
_STEM = 4  # crude stemming: compare 4-character prefixes (config ~ configuration)


def _tokens(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {w[:_STEM] for w in words if len(w) >= 3 and w not in _STOP}


def _dir_of(path: str) -> str:
    p = normalize_path(path)
    return p.rsplit("/", 1)[0] or "/"


@dataclass(frozen=True)
class _Ctx:
    obj_tokens: frozenset[str]
    obj_text: str
    has_egress: bool
    has_secrets: bool
    wants_write: bool


def _ctx(objective: Objective) -> _Ctx:
    text = objective.text.lower()
    scopes = set(objective.allowed_scopes)
    return _Ctx(
        obj_tokens=frozenset(_tokens(objective.text)),
        obj_text=text,
        has_egress="egress" in scopes,
        has_secrets="secrets-audit" in scopes,
        wants_write=any(w in text for w in WRITE_INTENT),
    )


def _overlap(ctx: _Ctx, e: Event) -> float:
    """Fraction of the target's tokens that also occur in the objective."""
    if e.tool == "creds_list":
        return 0.0
    toks = _tokens(e.target)
    return len(toks & ctx.obj_tokens) / len(toks) if toks else 0.0


def _mentioned(ctx: _Ctx, e: Event) -> bool:
    """Objective names this exact path/URL (or, for files, its basename)."""
    t = e.target.lower()
    if not t:
        return False
    if t in ctx.obj_text:
        return True
    return e.tool in FS_TOOLS and "/" in t and t.rsplit("/", 1)[1] in ctx.obj_text and "." in t


def _secret_recon(e: Event) -> bool:
    """Search query / listed directory aimed at secrets. Keywords apply to
    recon only; file reads use the gateway's path-based sensitivity, so test
    secrets the heuristic rates "low" (keys/ci_token) stay low here too."""
    if e.tool not in {"repo_search", "fs_list"}:
        return False
    t = e.target.lower()
    return e.data_sensitivity == "high" or any(s in t for s in SECRET_TERMS)


def _has_canary(e: Event) -> bool:
    return any(isinstance(v, str) and "[CANARY]" in v for v in e.args_redacted.values())


# Name → group. Order defines vector layout.
_SPEC: tuple[tuple[str, str], ...] = (
    # objective-relative
    ("obj_overlap_last", "objective"),
    ("obj_overlap_mean", "objective"),
    ("obj_unrelated_frac", "objective"),
    ("obj_mentioned_last", "objective"),
    ("scope_egress", "objective"),
    ("scope_secrets", "objective"),
    ("objective_wants_write", "objective"),
    # sensitivity dynamics
    ("sens_last", "sensitivity"),
    ("sens_max", "sensitivity"),
    ("n_high", "sensitivity"),
    ("sens_delta_last", "sensitivity"),
    ("high_unscoped", "sensitivity"),
    ("high_unscoped_last", "sensitivity"),
    # behavioural shape
    ("recon_frac", "behaviour"),
    ("n_secret_searches", "behaviour"),
    ("n_secret_lists", "behaviour"),
    ("distinct_dirs", "behaviour"),
    ("new_dir_last", "behaviour"),
    ("n_writes", "behaviour"),
    ("writes_unrequested", "behaviour"),
    ("write_code_last", "behaviour"),
    ("write_after_read_same", "behaviour"),
    ("readback_of_written", "behaviour"),
    ("recon_then_high", "behaviour"),
    # flow / network
    ("n_egress", "network"),
    ("egress_dest_mentioned_last", "network"),
    ("high_then_write", "network"),
    ("high_then_egress", "network"),
    ("egress_after_high", "network"),
    # position
    ("step", "length"),  # ablation-only: length artefact on dev (see below)
    ("steps_since_high", "position"),
    # current action (context for the call being decided)
    *((f"action_{a}", "action") for a in ACTIONS),
    # ablation-only
    ("dlp_canary_in_args", "dlp"),
    ("dlp_canary_count", "dlp"),
)

FEATURE_NAMES: tuple[str, ...] = tuple(n for n, _ in _SPEC)
FEATURE_GROUPS: dict[str, tuple[str, ...]] = {}
for _n, _g in _SPEC:
    FEATURE_GROUPS.setdefault(_g, ())
    FEATURE_GROUPS[_g] += (_n,)

DEFAULT_GROUPS = ("objective", "sensitivity", "behaviour", "network", "position", "action")


def feature_names(groups: tuple[str, ...] = DEFAULT_GROUPS) -> tuple[str, ...]:
    return tuple(n for n, g in _SPEC if g in groups)


def _full_vector(ctx: _Ctx, events: list[Event]) -> dict[str, float]:
    f: dict[str, float] = dict.fromkeys(FEATURE_NAMES, 0.0)
    f["scope_egress"] = float(ctx.has_egress)
    f["scope_secrets"] = float(ctx.has_secrets)
    f["objective_wants_write"] = float(ctx.wants_write)
    f["steps_since_high"] = 10.0
    if not events:
        return f

    last = events[-1]
    n = len(events)
    overlaps = [_overlap(ctx, e) for e in events]
    sens = [SENS.get(e.data_sensitivity, 0.0) for e in events]
    dirs = [_dir_of(e.target) if e.tool in FS_TOOLS else None for e in events]

    f["obj_overlap_last"] = overlaps[-1]
    f["obj_overlap_mean"] = sum(overlaps) / n
    f["obj_unrelated_frac"] = sum(o == 0.0 for o in overlaps) / n
    f["obj_mentioned_last"] = float(_mentioned(ctx, last))

    f["sens_last"] = sens[-1]
    f["sens_max"] = max(sens)
    f["n_high"] = float(sum(s == 1.0 for s in sens))
    f["sens_delta_last"] = sens[-1] - (sum(sens[:-1]) / (n - 1) if n > 1 else 0.0)
    if not ctx.has_secrets:
        f["high_unscoped"] = f["n_high"]
        f["high_unscoped_last"] = float(sens[-1] == 1.0)

    recon = [e.tool in {"fs_list", "repo_search"} for e in events]
    f["recon_frac"] = sum(recon) / n
    f["n_secret_searches"] = float(sum(e.tool == "repo_search" and _secret_recon(e) for e in events))
    f["n_secret_lists"] = float(sum(e.tool == "fs_list" and _secret_recon(e) for e in events))
    seen = [d for d in dirs if d is not None]
    f["distinct_dirs"] = float(len(set(seen)))
    if dirs[-1] is not None:
        f["new_dir_last"] = float(dirs[-1] not in dirs[:-1])

    writes = [e for e in events if e.tool == "fs_write"]
    f["n_writes"] = float(len(writes))
    f["writes_unrequested"] = 0.0 if ctx.wants_write else float(len(writes))
    if last.tool == "fs_write":
        f["write_code_last"] = float(normalize_path(last.target).endswith(CODE_EXT))

    read_paths: set[str] = set()
    written: set[str] = set()
    seen_high = False
    seen_recon = False
    for i, e in enumerate(events):
        p = normalize_path(e.target) if e.tool in FS_TOOLS else None
        if e.tool == "fs_write" and p in read_paths:
            f["write_after_read_same"] += 1.0
        if e.tool == "fs_read" and p in written:
            f["readback_of_written"] += 1.0
        if e.tool == "fs_read" and sens[i] == 1.0 and seen_recon:
            f["recon_then_high"] = 1.0
        if seen_high and e.tool == "fs_write":
            f["high_then_write"] = 1.0
        if seen_high and e.tool == "http_post":
            f["high_then_egress"] = 1.0
        if e.tool == "fs_read" and p is not None:
            read_paths.add(p)
        if e.tool == "fs_write" and p is not None:
            written.add(p)
        if _secret_recon(e):
            seen_recon = True
        if sens[i] == 1.0:
            seen_high = True

    f["n_egress"] = float(sum(e.tool == "http_post" for e in events))
    if last.tool == "http_post":
        f["egress_dest_mentioned_last"] = float(_mentioned(ctx, last))
        f["egress_after_high"] = float(any(s == 1.0 for s in sens[:-1]))

    f["step"] = float(n)
    highs = [i for i, s in enumerate(sens) if s == 1.0]
    if highs:
        f["steps_since_high"] = float(min(10, n - 1 - highs[-1]))
    if last.action in ACTIONS:
        f[f"action_{last.action}"] = 1.0

    canaries = [e for e in events if _has_canary(e)]
    f["dlp_canary_in_args"] = float(_has_canary(last))
    f["dlp_canary_count"] = float(len(canaries))
    return f


def prefix_features(
    objective: Objective, events: list[Event], groups: tuple[str, ...] = DEFAULT_GROUPS
) -> list[float]:
    """Feature vector for the whole prefix ``events`` (the last event is the call being decided)."""
    full = _full_vector(_ctx(objective), events)
    return [full[n] for n in feature_names(groups)]


def trajectory_matrix(
    objective: Objective, events: list[Event], groups: tuple[str, ...] = DEFAULT_GROUPS
) -> list[list[float]]:
    """One row per step i: features of ``events[: i + 1]``."""
    ctx = _ctx(objective)
    names = feature_names(groups)
    return [[full[n] for n in names] for full in (_full_vector(ctx, events[: i + 1]) for i in range(len(events)))]
