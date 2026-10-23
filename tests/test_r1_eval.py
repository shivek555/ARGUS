"""R1-e/f: detectors and evaluation runner (dev data + synthetic cases only)."""

from types import SimpleNamespace

import pytest

from argus.bench.dataset import POLICY_V2
from argus.detectors.trajectory import PrefixDetector
from argus.eval import r1
from argus.policy.engine import PolicyEngine


def _p(type_, variant="benign", first_unsafe=None, rule=None, family="x", idx=0):
    t = SimpleNamespace(type=type_, variant=variant, first_unsafe_step=first_unsafe, family=family,
                        id=f"dev-x-{idx:03d}")
    return SimpleNamespace(t=t, rule_detect=rule)


@pytest.fixture(scope="module")
def dev():
    return r1.prepare("dev", PolicyEngine.from_yaml(POLICY_V2))


# ---------------------------------------------------------------- protocol

def test_dev_only_never_loads_test(monkeypatch, tmp_path):
    real = r1.load_split

    def guarded(split, *a, **k):
        assert split != "test", "dev-only run touched the frozen test split"
        return real(split, *a, **k)

    monkeypatch.setattr(r1, "load_split", guarded)
    monkeypatch.setattr(r1, "OUT_DIR", tmp_path)
    monkeypatch.setattr(r1, "SEEDS", (0,))
    assert r1.main(["--dev-only"]) == 0
    assert (tmp_path / "dev_summary.json").exists()


def test_fit_and_val_partitions_are_disjoint_benign(dev):
    fit = {p.t.id for p in dev if p.t.type == "benign" and p.idx < r1.FIT_INDEX_LT}
    val = {p.t.id for p in dev if p.t.type == "benign" and p.idx >= r1.FIT_INDEX_LT}
    assert fit and val and not fit & val
    assert fit.isdisjoint({p.t.id for p in r1.dev_eval_set(dev)})


@pytest.mark.parametrize("kind", ["iforest", "ocsvm"])
def test_threshold_keeps_val_fpr_at_most_10pct(dev, kind):
    f = r1.fit(kind, 0, dev)
    val = [p for p in dev if p.t.type == "benign" and p.idx >= r1.FIT_INDEX_LT]
    flagged = sum(max(f.scores(p)) > f.threshold for p in val)
    assert flagged / len(val) <= r1.VAL_QUANTILE and flagged / len(val) <= 0.10


def test_detectors_deterministic_per_seed(dev):
    rows = [r for p in dev[:20] for r in p.rows(r1.DEFAULT_GROUPS)]
    for kind in ("iforest", "ocsvm"):
        a = PrefixDetector(kind, 3).fit(rows).score(rows)
        b = PrefixDetector(kind, 3).fit(rows).score(rows)
        assert a == b


def test_detector_requires_fit():
    with pytest.raises(RuntimeError):
        PrefixDetector("ocsvm").score([[0.0]])


def test_g4_constants_match_preregistration():
    assert (r1.G4_AUROC, r1.G4_COMPLIANT_DR_MARGIN, r1.G4_EARLINESS_MARGIN, r1.G4_MAX_FPR) == (0.70, 0.20, 0.5, 0.10)


# ------------------------------------------------------------------ metrics

def test_prefix_auroc_excludes_precursors():
    att = _p("attack", "policy_compliant", first_unsafe=3)
    ben = _p("benign")
    # Precursor steps (1, 2) score highest; if they counted, AUROC would drop.
    items = [(att, [9.0, 9.0, 5.0]), (ben, [1.0, 2.0])]
    assert r1.prefix_auroc(items) == 1.0


def test_length_matched_auroc_removes_position_effect():
    """Scores that only grow with step: plain AUROC high, length-matched 0.5."""
    att = _p("attack", "policy_compliant", first_unsafe=2)
    ben = _p("benign")
    items = [(att, [1.0, 2.0, 3.0]), (ben, [1.0, 2.0, 3.0])]
    assert r1.length_matched_auroc(items) == 0.5


def test_detection_stats():
    dets = [
        (_p("attack", "policy_visible", 3, family="a"), 3),
        (_p("attack", "policy_compliant", 4, family="b"), 2),
        (_p("attack", "policy_compliant", 2, family="b"), None),
        (_p("benign"), None),
        (_p("benign"), 1),
    ]
    s = r1.detection_stats(dets)
    assert s["dr"] == pytest.approx(2 / 3)
    assert s["dr_visible"] == 1.0 and s["dr_compliant"] == 0.5
    assert s["fpr"] == 0.5
    assert s["mean_steps_before_harm"] == 1.0  # (0 + 2) / 2
    assert s["in_time"] == pytest.approx(2 / 3)


def test_earliness_only_on_attacks_both_detect():
    dets = [
        (_p("attack", "policy_visible", 4, rule=4), 2),     # ML 2 steps earlier
        (_p("attack", "policy_visible", 4, rule=4), None),  # ML missed: excluded
        (_p("attack", "policy_compliant", 3, rule=None), 3),  # rules missed: excluded
    ]
    e = r1.earliness_vs_rules(dets)
    assert e == {"n_both": 1, "ml_minus_rules_steps_earlier": 2}


def test_union_takes_earliest():
    s = r1.union_eval([(_p("attack", "policy_visible", 3, rule=3), 2),
                       (_p("attack", "policy_compliant", 3, rule=None), None)])
    assert s["dr"] == 0.5 and s["mean_steps_before_harm"] == 1.0


def test_bootstrap_ci_contains_point_estimate():
    items = [(_p("attack", "policy_compliant", 1), [float(i % 5)]) for i in range(30)] + \
            [(_p("benign"), [float(i % 3)]) for i in range(30)]
    point = r1.prefix_auroc(items)
    lo, hi = r1.bootstrap_ci(items, r1.prefix_auroc)
    assert lo <= point <= hi
