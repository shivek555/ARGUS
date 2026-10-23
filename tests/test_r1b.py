"""R1b-3/4: grid, LOIO calibration, nested FPR, selection rule, final-runner plumbing."""

import hashlib
import json
from types import SimpleNamespace

import pytest

from argus.bench.dataset import load_split
from argus.bench.steps import as_record
from argus.eval import r1, r1b, r1b_final


# ------------------------------------------------------------------ grid

def test_grid_is_the_preregistered_16():
    names = [c.name for c in r1b.GRID]
    assert len(names) == len(set(names)) == 16
    assert sum(c.kind == "iforest" and not c.control for c in r1b.GRID) == 4
    assert sum(c.kind == "ocsvm" and not c.control for c in r1b.GRID) == 8
    controls = [c for c in r1b.GRID if c.control]
    assert len(controls) == 4 and all(c.scaler == "standard" and c.nu == 0.05 for c in controls)
    assert {c.nu for c in r1b.GRID if c.kind == "ocsvm"} == {0.05, 0.10}
    assert {c.threshold for c in r1b.GRID} == {"global", "context"}


def test_preregistered_constants():
    assert (r1b.QUANTILE, r1b.MAX_NESTED_FPR, r1b.MIN_CONTEXT_N) == (0.90, 0.10, 30)
    assert (r1b_final.G4R2_AUROC, r1b_final.G4R2_MAX_FPR, r1b_final.G4R2_DR_MARGIN,
            r1b_final.G4R2_EARLINESS) == (0.70, 0.10, 0.20, 0.5)


# ------------------------------------------------------- synthetic benign

def _b(intent, i, scopes=("workspace_read",)):
    return SimpleNamespace(t=SimpleNamespace(id=f"{intent}-{i}", template=intent, allowed_scopes=scopes,
                                             type="benign"))


def _fit(scores):
    return r1b.Fit(final=None, loio=scores, groups=(), drop=())


def test_loio_folds_hold_out_whole_intents():
    benign = [_b(k, i) for k in "ABC" for i in range(3)]
    folds = r1b.loio_folds(benign)
    assert [k for k, _, _ in folds] == ["A", "B", "C"]
    for k, train, held in folds:
        assert {p.t.template for p in held} == {k}
        assert k not in {p.t.template for p in train}
        assert len(train) + len(held) == len(benign)


def test_nested_fpr_exposes_novel_intent():
    """Intent C behaves unlike A/B. Naive (non-nested) FPR stays ~10%; nested says 100% for C."""
    benign = [_b(k, i) for k in "AB" for i in range(40)] + [_b("C", i) for i in range(40)]
    scores = {p.t.id: [float(i % 10) / 10] for k in "AB" for i, p in
              enumerate(x for x in benign if x.t.template == k)}
    scores.update({p.t.id: [5.0] for p in benign if p.t.template == "C"})
    fit = _fit(scores)
    nested = r1b.nested_fpr(fit, benign, "global")
    assert nested["by_intent"]["C"] == 1.0
    naive_thr = r1b.thresholds(fit, benign, "global")["plain"]
    naive = sum(max(scores[p.t.id]) > naive_thr for p in benign) / len(benign)
    assert naive <= 0.10 < nested["fpr"]


def test_context_thresholds_and_fallback():
    plain = [_b("A", i) for i in range(40)]
    secrets = [_b("S", i, ("workspace_read", "secrets-audit")) for i in range(40)]
    egress = [_b("E", i, ("workspace_read", "egress")) for i in range(5)]  # < 30 → global fallback
    benign = plain + secrets + egress
    scores = {p.t.id: [0.1] for p in plain} | {p.t.id: [0.9] for p in secrets} | {p.t.id: [0.5] for p in egress}
    thr = r1b.thresholds(_fit(scores), benign, "context")
    glob = r1b.thresholds(_fit(scores), benign, "global")["plain"]
    assert thr["plain"] == 0.1 and thr["secrets"] == 0.9 and thr["egress"] == glob


# ------------------------------------------------------------- selection

def _res(**kw):
    return {"agg": {k: (None if v is None else {"mean": v, "std": 0.0}) for k, v in kw.items()}}


def test_selection_rule():
    results = {
        "a": _res(nested_fpr=0.20, dr_compliant=1.0, auroc=0.99),   # best DR but too many FPs
        "b": _res(nested_fpr=0.08, dr_compliant=0.6, auroc=0.90),
        "c": _res(nested_fpr=0.09, dr_compliant=0.6, auroc=0.95),   # ties b on DR, wins on AUROC
    }
    assert r1b.select(results)["selected"] == "c"
    none = {"x": _res(nested_fpr=0.3, dr_compliant=1.0, auroc=0.9),
            "y": _res(nested_fpr=0.2, dr_compliant=0.1, auroc=0.5)}
    s = r1b.select(none)
    assert s["selected"] == "y" and "unlikely" in s["reason"]


def test_verdict_logic():
    rules = {"dr_compliant": 0.0}
    early = [{"earliness": {"ml_minus_rules_steps_earlier": 0.0}}]
    ok = {"auroc": {"mean": 0.9}, "fpr": {"mean": 0.08}, "dr_compliant": {"mean": 0.5}}
    assert r1b_final.verdict(ok, early, rules)["G4-R2"] == "PASS"
    hi_fpr = {**ok, "fpr": {"mean": 0.2}}
    assert r1b_final.verdict(hi_fpr, early, rules)["G4-R2"] == "FAIL"
    low_auc = {**ok, "auroc": {"mean": 0.6}}
    assert r1b_final.verdict(low_auc, early, rules)["G4-R2"] == "FAIL"


# --------------------------------------------------------------- real dev

@pytest.fixture(scope="module")
def dev(monkeypatch_module):
    real = r1.load_split

    def guarded(split, *a, **k):
        assert split != "test", "R1b dev code loaded the test split"
        return real(split, *a, **k)

    monkeypatch_module.setattr(r1, "load_split", guarded)
    return r1b.load_dev()


@pytest.fixture(scope="module")
def monkeypatch_module():
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


def test_dev_data_shape(dev):
    assert len(dev.benign) == 420 and len(dev.attacks) == 120
    assert {r1b.context_of(p) for p in dev.benign} == {"plain", "secrets", "egress"}


def test_dev_grid_runs_and_loio_is_out_of_sample(dev):
    cfgs = tuple(c for c in r1b.GRID if c.name in {"ocsvm-nu0.05-standard_floor-context",
                                                    "control-ocsvm-standard-global"})
    res = r1b.run_grid(dev, cfgs)
    for r in res.values():
        a = r["agg"]
        assert 0.0 <= a["nested_fpr"]["mean"] <= 1.0
        assert a["auroc"] is not None and set(r["seeds"][0]["thresholds"]) == set(r1b.CONTEXTS)
    fit = r1b.fit_group("ocsvm", 0.05, "standard_floor", 0, dev)
    assert set(fit.loio) == {p.t.id for p in dev.benign}


# ------------------------------------------------------- final runner

def _fake_test_dir(tmp_path):
    """Stand-in for test v2 built from DEV v1 data only (plumbing test; no test data is read)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    trajs = load_split("dev")[::8]
    blob = ("\n".join(json.dumps(as_record(t), sort_keys=True) for t in trajs) + "\n").encode()
    (tmp_path / "test.jsonl").write_bytes(blob)
    (tmp_path / "manifest.json").write_text(json.dumps({"sha256": hashlib.sha256(blob).hexdigest()}))
    return tmp_path


def test_final_loader_integrity(tmp_path):
    d = _fake_test_dir(tmp_path)
    trajs, sha = r1b_final.load_test_v2(d)
    assert trajs and len(sha) == 64
    (d / "test.jsonl").write_bytes((d / "test.jsonl").read_bytes() + b"\n")
    with pytest.raises(r1b_final.IntegrityError):
        r1b_final.load_test_v2(d)
    with pytest.raises(FileNotFoundError):
        r1b_final.load_test_v2(tmp_path / "missing")


def test_final_runner_plumbing(tmp_path, monkeypatch):
    d = _fake_test_dir(tmp_path / "t")
    monkeypatch.setattr(r1b, "SEEDS", (0,))
    grid = tuple(c for c in r1b.GRID if c.name in {"ocsvm-nu0.05-standard_floor-context",
                                                    "control-ocsvm-standard-global"})
    out = tmp_path / "summary.json"
    assert r1b_final.main([], test_dir=d, out=out, grid=grid, ablations=False, exploratory_v1=False) == 0
    s = json.loads(out.read_text())
    assert s["G4-R2"]["G4-R2"] in {"PASS", "FAIL"}
    assert "rules_v3_b2plus" in s["test_v2"] and s["selected"]["config"]["name"] in {c.name for c in grid}
