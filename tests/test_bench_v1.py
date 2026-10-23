"""R1-b/c: AgentEscapeBench v1 generator, labels, freeze and leakage guards."""

import json
import shutil

import pytest

from argus.bench import generate
from argus.bench.dataset import IntegrityError, V1_DIR, harm_step, load_split, replay
from argus.events.schema import Event
from argus.policy.engine import PolicyEngine
from argus.bench.dataset import POLICY_V2

# Recorded in docs/EXPERIMENTS.md when the test split was frozen (2026-10-23).
# Changing either requires a new ADR (test) or an EXPERIMENTS.md row (dev).
FROZEN_TEST_SHA256 = "91a2b73738b4d10efeb98efbc3476c7099e88a6bdf47e55d703030b95987d652"
DEV_SHA256 = "6e6c4cb3779aa7064080391186ff0fe500253e2497d7023b20f538264b64e742"

POLICY = PolicyEngine.from_yaml(POLICY_V2)
DEV = load_split("dev")
TEST = load_split("test")
ALL = DEV + TEST


def _seq(t):
    return tuple((c.tool, c.args.get("path") or c.args.get("url") or c.args.get("query") or "") for c in t.calls)


# ------------------------------------------------------------------- freeze

def test_frozen_hashes():
    manifest = json.loads((V1_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["splits"]["test"]["sha256"] == FROZEN_TEST_SHA256
    assert manifest["splits"]["dev"]["sha256"] == DEV_SHA256


def test_generator_is_deterministic():
    for split in ("dev", "test"):
        assert generate.serialize(generate.generate_split(split)) == (V1_DIR / f"{split}.jsonl").read_bytes()


def test_check_mode_passes():
    assert generate.main(["--check"]) == 0


def test_generator_refuses_to_overwrite_changed_test(tmp_path):
    assert generate.main(["--out", str(tmp_path)]) == 0
    test_file = tmp_path / "test.jsonl"
    test_file.write_bytes(test_file.read_bytes().replace(b"paste.fake", b"other.fake"))
    assert generate.main(["--out", str(tmp_path)]) == 2
    assert b"other.fake" in test_file.read_bytes()  # untouched


def test_loader_rejects_tampered_split(tmp_path):
    for name in ("dev.jsonl", "test.jsonl", "manifest.json"):
        shutil.copy(V1_DIR / name, tmp_path / name)
    (tmp_path / "test.jsonl").write_bytes((tmp_path / "test.jsonl").read_bytes() + b"\n")
    with pytest.raises(IntegrityError):
        load_split("test", tmp_path)


# ------------------------------------------------------------------- shape

def test_sizes_and_balance():
    assert len(DEV) == 240 and len(TEST) == 180
    for split in (DEV, TEST):
        assert sum(t.type == "benign" for t in split) == len(split) // 2
        assert {t.family for t in split} == {"benign", "goal_hijack", "credential_discovery", "exfiltration"}
        assert {t.variant for t in split} == {"benign", "policy_visible", "policy_compliant"}


def test_seed_ranges_disjoint():
    assert {t.seed for t in DEV}.isdisjoint({t.seed for t in TEST})
    assert len({t.seed for t in ALL}) == len(ALL)
    assert len({t.id for t in ALL}) == len(ALL)


def test_template_sets_disjoint_for_benign():
    assert {t.template for t in DEV if t.type == "benign"}.isdisjoint(
        {t.template for t in TEST if t.type == "benign"})


# ----------------------------------------------------------------- leakage

def test_no_trajectory_shared_across_splits():
    assert not ({_seq(t) for t in DEV} & {_seq(t) for t in TEST})


def test_unsafe_targets_mostly_disjoint_across_splits():
    def unsafe_targets(split):
        out = set()
        for t in split:
            if t.type == "attack":
                c = t.calls[t.first_unsafe_step - 1]
                out.add(c.args.get("path") or c.args.get("url") or c.tool)
        return out

    assert unsafe_targets(DEV) & unsafe_targets(TEST) == {"creds_list"}


def test_labels_and_roles_never_reach_events():
    forbidden = {"roles", "first_unsafe_step", "variant", "family", "harm", "template", "severity"}
    assert forbidden.isdisjoint(Event.model_fields)


# ---------------------------------------------------- labels vs real policy

@pytest.mark.parametrize("t", ALL, ids=lambda t: t.id)
def test_labels_agree_with_policy_v2(t):
    events, _ = replay(t, POLICY)
    blocks = [e.step for e in events if e.decision == "BLOCK"]
    assert not [e for e in events if (e.result_redacted or "").startswith("tool_error")]
    if t.variant == "benign":
        assert blocks == []
    elif t.variant == "policy_visible":
        assert blocks and blocks[0] == t.first_unsafe_step
    else:  # policy_compliant: every rule passes, harm still completes
        assert blocks == []
    if t.type == "attack":
        assert harm_step(t, events) is not None


def test_enforce_mode_stops_visible_harm_but_not_compliant_harm():
    for t in ALL:
        if t.type != "attack":
            continue
        events, world = replay(t, POLICY, mode="enforce")
        done = harm_step(t, events)
        if t.variant == "policy_visible":
            assert done is None, t.id
        else:
            assert done is not None, t.id


def test_no_raw_canary_in_events():
    for t in ALL[::7]:
        events, _ = replay(t, POLICY)
        blob = json.dumps([e.model_dump(mode="json") for e in events])
        stripped = blob.replace("[CANARY_PRESENT]", "").replace("[CANARY]", "")
        assert "CANARY_" not in stripped, t.id
