from argus.features.prefix import FORBIDDEN_FEATURE_FIELDS, prefix_vector
from argus.events.schema import Event


def test_forbidden_fields_are_documented():
    assert "decision" in FORBIDDEN_FEATURE_FIELDS
    assert "result_redacted" in FORBIDDEN_FEATURE_FIELDS


def test_vector_length_stable():
    e = Event(
        agent_id="a",
        task_id="t",
        step=1,
        tool="fs_read",
        action="read",
        target="/workspace/README.md",
        args_redacted={},
        permissions=["workspace_read"],
        data_sensitivity="low",
        network_destination=None,
        prev_tool=None,
    )
    assert len(prefix_vector([e])) == 12
