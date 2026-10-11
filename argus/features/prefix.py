from __future__ import annotations

from typing import Any

from argus.events.schema import Event

# Fields detectors must never use (label / post-condition leakage).
FORBIDDEN_FEATURE_FIELDS = frozenset({"result_redacted", "decision", "risk"})
ALLOWED_TOOLS = ("fs_read", "fs_write", "http_post", "creds_list", "repo_search")
SENSITIVITY = {"low": 0.0, "medium": 0.5, "high": 1.0}


def _tool_index(name: str) -> int:
    try:
        return ALLOWED_TOOLS.index(name)
    except ValueError:
        return -1


def prefix_vector(events: list[Event]) -> list[float]:
    """Bag-of-tools + last-bigram + sensitivity on the prefix only.

    Ignores result_redacted, decision, and risk even if those fields are populated.
    """
    counts = [0.0] * len(ALLOWED_TOOLS)
    high_n = 0.0
    http_n = 0.0
    creds_n = 0.0
    for event in events:
        idx = _tool_index(event.tool)
        if idx >= 0:
            counts[idx] += 1.0
        if event.data_sensitivity == "high":
            high_n += 1.0
        if event.tool == "http_post":
            http_n += 1.0
        if event.tool == "creds_list":
            creds_n += 1.0
    last_tool = _tool_index(events[-1].tool) if events else -1.0
    prev_tool = _tool_index(events[-1].prev_tool or "") if events else -1.0
    last_sens = SENSITIVITY.get(events[-1].data_sensitivity, 0.0) if events else 0.0
    step = float(events[-1].step) if events else 0.0
    return counts + [high_n, http_n, creds_n, last_tool, prev_tool, last_sens, step]


def prefix_matrix(events: list[Event]) -> list[list[float]]:
    return [prefix_vector(events[: i + 1]) for i in range(len(events))]


def vectors_ignore_forbidden_fields(events: list[Event]) -> bool:
    """True if mutating forbidden fields does not change the vector."""
    if not events:
        return True
    base = prefix_vector(events)
    cloned: list[Event] = []
    for event in events:
        dumped: dict[str, Any] = event.model_dump()
        dumped["result_redacted"] = "LEAK"
        dumped["decision"] = "BLOCK"
        dumped["risk"] = 99.0
        cloned.append(Event.model_validate(dumped))
    return prefix_vector(cloned) == base
