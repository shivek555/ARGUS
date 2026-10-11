from __future__ import annotations

from typing import Any

from argus.events.schema import Objective
from argus.gateway.core import Gateway, ToolResult


def run_scripted(
    gateway: Gateway,
    objective: Objective,
    calls: list[dict[str, Any]],
) -> list[ToolResult]:
    """Explicit loop. `objective` is not given to the agent to mutate."""
    _ = objective  # stored on the gateway only
    results: list[ToolResult] = []
    for call in calls:
        results.append(gateway.invoke(call["tool"], dict(call.get("args") or {})))
    return results
