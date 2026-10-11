from __future__ import annotations

from typing import Any

from argus.events.schema import Event, Objective, utcnow

_CANARY_PREFIX = "CANARY_"
_SECRET_KEYS = {"password", "token", "secret", "key", "authorization"}


def redact_args(args: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in args.items():
        if key.lower() in _SECRET_KEYS:
            out[key] = "[REDACTED]"
        elif isinstance(value, str) and value.startswith(_CANARY_PREFIX):
            out[key] = "[CANARY]"
        elif isinstance(value, str) and len(value) > 200:
            out[key] = value[:200] + "…"
        else:
            out[key] = value
    return out


def redact_result(result: Any) -> str | None:
    if result is None:
        return None
    text = str(result)
    if _CANARY_PREFIX in text:
        text = "[CANARY_PRESENT]"
    if len(text) > 240:
        text = text[:240] + "…"
    return text


def sensitivity_for(tool: str, target: str) -> str:
    t = target.lower()
    if tool == "creds_list" or "secret" in t or ".env" in t:
        return "high"
    if "config" in t or "pyproject" in t or "package" in t:
        return "medium"
    return "low"


def action_for(tool: str) -> str:
    return {
        "fs_read": "read",
        "fs_write": "write",
        "http_post": "egress",
        "creds_list": "credential_access",
        "repo_search": "search",
    }.get(tool, "unknown")


def target_for(tool: str, args: dict[str, Any]) -> str:
    if tool in {"fs_read", "fs_write"}:
        return str(args.get("path", ""))
    if tool == "http_post":
        return str(args.get("url", ""))
    if tool == "repo_search":
        return str(args.get("query", ""))
    if tool == "creds_list":
        return "credstore"
    return tool


def network_destination(tool: str, args: dict[str, Any]) -> str | None:
    if tool == "http_post":
        return str(args.get("url", "")) or None
    return None


def build_pre_event(
    *,
    objective: Objective,
    agent_id: str,
    step: int,
    tool: str,
    args: dict[str, Any],
    prev_tool: str | None,
) -> Event:
    target = target_for(tool, args)
    return Event(
        timestamp=utcnow(),
        agent_id=agent_id,
        task_id=objective.task_id,
        step=step,
        tool=tool,
        action=action_for(tool),
        target=target,
        args_redacted=redact_args(args),
        permissions=list(objective.allowed_scopes),
        data_sensitivity=sensitivity_for(tool, target),  # type: ignore[arg-type]
        network_destination=network_destination(tool, args),
        prev_tool=prev_tool,
    )
