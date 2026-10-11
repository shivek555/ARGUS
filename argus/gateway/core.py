from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from argus.events.builders import build_pre_event, redact_result
from argus.events.schema import Event, Objective
from argus.policy.engine import PolicyEngine
from argus.sandbox.tools import ToolFn
from argus.telemetry.log import JsonlLogger

Mode = Literal["enforce", "record"]


@dataclass
class ToolResult:
    decision: str
    result: Any
    event: Event


class Gateway:
    """Sole execution path. Agents receive this object, not tool callables."""

    def __init__(
        self,
        *,
        tools: dict[str, ToolFn],
        policy: PolicyEngine,
        logger: JsonlLogger,
        objective: Objective,
        agent_id: str,
        mode: Mode = "enforce",
    ) -> None:
        self._tools = tools
        self._policy = policy
        self._logger = logger
        self._objective = objective
        self._agent_id = agent_id
        self._mode = mode
        self._step = 0
        self._prev_tool: str | None = None

    def invoke(self, tool: str, args: dict[str, Any] | None = None) -> ToolResult:
        args = args or {}
        self._step += 1
        decision = "BLOCK"
        event: Event | None = None
        try:
            event = build_pre_event(
                objective=self._objective,
                agent_id=self._agent_id,
                step=self._step,
                tool=tool,
                args=args,
                prev_tool=self._prev_tool,
            )
            if tool not in self._tools:
                decision = "BLOCK"
            else:
                decision = self._policy.decide(event, self._objective)
        except Exception:
            decision = "BLOCK"
            if event is None:
                event = build_pre_event(
                    objective=self._objective,
                    agent_id=self._agent_id,
                    step=self._step,
                    tool=tool,
                    args={"_error": "event_build_failed"},
                    prev_tool=self._prev_tool,
                )

        execute = tool in self._tools and (
            decision == "ALLOW" or self._mode == "record"
        )
        result: Any = None
        if execute:
            try:
                result = self._tools[tool](**args)
            except Exception as exc:
                result = f"tool_error:{type(exc).__name__}"
                if self._mode == "enforce":
                    decision = "BLOCK"

        event.decision = decision
        event.result_redacted = redact_result(result)
        self._logger.append(event)
        self._prev_tool = tool
        return ToolResult(decision=decision, result=result, event=event)
