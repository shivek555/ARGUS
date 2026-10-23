"""Benign task catalog: coverage, benign contract, never blocked, deterministic."""

import json
from collections import Counter
from pathlib import Path

import pytest

from argus.bench import benign_catalog as bc
from argus.bench.dataset import replay
from argus.policy.engine import PolicyEngine
from argus.sandbox.tools import normalize_path

POL = Path(__file__).resolve().parents[1] / "configs" / "policies"
V2 = PolicyEngine.from_yaml(POL / "v2.yaml")
V3 = PolicyEngine.from_yaml(POL / "v3.yaml")
CATALOG = bc.generate()


def test_coverage():
    assert len(bc.CATEGORIES) >= 25
    counts = Counter(t.template for t in CATALOG)
    assert set(counts) == set(bc.CATEGORIES) and set(counts.values()) == {bc.PER_CATEGORY}
    groups = {g for g, _ in bc.CATEGORIES.values()}
    assert groups == {"code", "docs", "data", "devops", "project", "legit_security", "publishing"}
    assert {bc.context_of(t.allowed_scopes) for t in CATALOG} == {"plain", "secrets", "egress"}


def test_deterministic_and_unique():
    again = bc.generate()
    assert [json.dumps(t.model_dump(mode="json"), sort_keys=True) for t in CATALOG] == \
           [json.dumps(t.model_dump(mode="json"), sort_keys=True) for t in again]
    assert len({t.id for t in CATALOG}) == len({t.seed for t in CATALOG}) == len(CATALOG)
    assert all(t.type == "benign" and t.first_unsafe_step is None for t in CATALOG)


@pytest.mark.parametrize("t", CATALOG, ids=lambda t: t.id)
def test_benign_contract_and_policy(t):
    ctx = bc.context_of(t.allowed_scopes)
    for policy in (V2, V3):
        events, _ = replay(t, policy)
        assert not [e for e in events if e.decision == "BLOCK"]
        assert not [e for e in events if (e.result_redacted or "").startswith("tool_error")]
    for e, c in zip(events, t.calls):
        if e.tool == "fs_read" and e.data_sensitivity == "high":
            assert ctx == "secrets"
        if e.tool == "creds_list":
            assert ctx == "secrets"
        if e.tool == "fs_write":
            assert normalize_path(c.args["path"]) in t.objective_text
        if e.tool == "http_post":
            assert ctx == "egress" and c.args["url"] == bc.ALLOWED_HOST


def test_writes_and_posts_come_last():
    for t in CATALOG:
        tools = [c.tool for c in t.calls]
        first_out = next((i for i, x in enumerate(tools) if x in {"fs_write", "http_post"}), len(tools))
        assert all(x in {"fs_write", "http_post"} for x in tools[first_out:]), t.id
