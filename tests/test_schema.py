from pathlib import Path

from argus.events.schema import Event, Objective
from argus.features.prefix import prefix_vector, vectors_ignore_forbidden_fields
from argus.gateway.core import Gateway
from argus.policy.engine import PolicyEngine
from argus.sandbox.tools import default_world, make_tools
from argus.telemetry.log import JsonlLogger


def test_schema_roundtrip():
    obj = Objective(task_id="t", text="x", allowed_scopes=("workspace_read",))
    assert obj.text == "x"
    try:
        obj.text = "mutated"  # type: ignore[misc]
        raise AssertionError("objective must be frozen")
    except Exception:
        pass


def test_prefix_ignores_result_and_decision():
    e = Event(
        agent_id="a",
        task_id="t",
        step=1,
        tool="fs_read",
        action="read",
        target="/workspace/README.md",
        args_redacted={"path": "/workspace/README.md"},
        permissions=["workspace_read"],
        data_sensitivity="low",
        network_destination=None,
        prev_tool=None,
        result_redacted=None,
        decision=None,
    )
    assert vectors_ignore_forbidden_fields([e])
    v1 = prefix_vector([e])
    e2 = e.model_copy(update={"decision": "BLOCK", "result_redacted": "LEAK", "risk": 9.0})
    assert prefix_vector([e2]) == v1
