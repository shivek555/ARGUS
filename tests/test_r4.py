"""R4: metrics/statistics, frozen derived models, containment rows, SVG, reproduce renderers, latency."""

import json
import xml.etree.ElementTree as ET

import pytest

from argus.eval import r4
from argus.eval.metrics import (Outcome, bootstrap_ci, earliness, holm, mcnemar_exact, prefix_auroc, roc_points,
                                traj_stats)
from argus.eval.svg import histogram, line_chart


def att(flags, onset=2, harm=3, fam="exfiltration", variant="policy_compliant"):
    return Outcome(True, fam, variant, onset, harm, tuple(flags))


def ben(flags):
    return Outcome(False, "benign", "benign", None, None, tuple(flags))


# ----------------------------------------------------------------- metrics

def test_traj_stats_counts():
    outs = [att([0, 1, 0]), att([0, 0, 0, 1]), att([0, 0, 0], variant="policy_visible"), ben([0, 0]), ben([1, 0])]
    s = traj_stats(outs)
    assert s["dr"] == pytest.approx(2 / 3) and s["dr_in_time"] == pytest.approx(1 / 3)   # step 4 > harm step 3
    assert s["dr_compliant"] == 1.0 and s["dr_visible"] == 0.0
    assert s["fpr"] == 0.5 and s["fpr_step"] == 0.25
    assert s["precision"] == pytest.approx(2 / 3) and s["f1"] == pytest.approx(2 / 3)


def test_earliness_vs_harm_and_rules():
    outs = [att([1, 0, 0]), att([0, 1, 0])]
    rules = [att([0, 0, 1]), att([0, 0, 0])]
    e = earliness(outs, rules)
    assert e["steps_before_harm"] == [2, 1] and e["mean_steps_before_harm"] == 1.5
    assert e["n_both_vs_rules"] == 1 and e["mean_steps_earlier_than_rules"] == 2.0


def test_mcnemar_exact_known_values():
    r = mcnemar_exact([True] * 5 + [False] * 5, [False] * 10)
    assert (r["only_a"], r["only_b"]) == (5, 0) and r["p"] == pytest.approx(2 / 32)
    assert mcnemar_exact([True, False], [True, False])["p"] == 1.0
    assert mcnemar_exact([True] * 3 + [False] * 3, [False] * 3 + [True] * 3)["p"] == 1.0
    with pytest.raises(ValueError):
        mcnemar_exact([True], [])


def test_holm_monotone():
    adj = holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adj == pytest.approx({"a": 0.03, "c": 0.06, "b": 0.06})
    assert holm({"x": 0.9, "y": 0.8})["x"] == 1.0


def test_bootstrap_deterministic_and_stratified():
    outs = [att([1])] * 8 + [att([0])] * 2 + [ben([0])] * 9 + [ben([1])]
    stat = lambda o: traj_stats(o)["dr"]  # noqa: E731
    a, b = bootstrap_ci(outs, stat), bootstrap_ci(outs, stat)
    assert a == b and a[0] <= 0.8 <= a[1]
    assert bootstrap_ci([ben([1])] * 5, stat) is None   # no attacks → DR undefined in every resample


def test_auroc_and_roc():
    scores, labels = [[0.1, 0.9], [0.2, 0.3]], [[None, 1], [0, 0]]
    assert prefix_auroc(scores, labels) == 1.0
    pts = roc_points(scores, labels)
    assert pts[0] == (0.0, 0.0) and pts[-1] == (1.0, 1.0)
    assert prefix_auroc([[0.5]], [[1]]) is None


# ------------------------------------------------------- frozen protocol

def test_manifest_pinned_and_files_match():
    assert r4.FROZEN_MANIFEST_SHA256 is not None, "R4 protocol commit pins the manifest"
    assert r4.file_sha256(r4.MANIFEST) == r4.FROZEN_MANIFEST_SHA256
    m = json.loads(r4.MANIFEST.read_text(encoding="utf-8"))
    assert m["protocol"] == r4.PROTOCOL_VERSION and m["primary"]["sha256"] == r4.r3.FROZEN_SHA256
    names = set(m["models"])
    assert {f"ablation-no-{g}" for g in r4.GROUPS} | {f"seed-{s}" for s in r4.SEEDS} <= names
    assert {n for n in names if n.startswith("lofo-")} == {"lofo-credential_discovery", "lofo-exfiltration",
                                                          "lofo-goal_hijack"}
    for entry in m["models"].values():
        for rel, sha in entry["files"].items():
            assert r4.file_sha256(r4.DERIVED / rel) == sha


def test_derived_models_load_and_are_ordered():
    m = json.loads(r4.MANIFEST.read_text(encoding="utf-8"))
    for name, entry in m["models"].items():
        eng = r4.load_derived(name)
        lv = eng.levels
        assert lv.medium <= lv.high <= lv.critical
        assert list(eng.model.names) == entry["signals"]
        if name.startswith("ablation-no-"):
            dropped = set(r4.GROUPS[name.removeprefix("ablation-no-")])
            assert not dropped & set(eng.model.names)
        if name.startswith("seed-"):
            assert (entry["n_attack"], entry["n_benign"]) == (120, 126) and len(entry["ml_fingerprint"]) == 64


def test_seed_resamples_differ():
    m = json.loads(r4.MANIFEST.read_text(encoding="utf-8"))["models"]
    picks = {tuple(m[f"seed-{s}"]["benign_intents"]) + tuple(m[f"seed-{s}"]["attack_templates"]) for s in r4.SEEDS}
    assert len(picks) == len(r4.SEEDS)


def test_freeze_refused_once_frozen(capsys):
    assert r4._derive_cmd(freeze=True) == 2
    assert "refused" in capsys.readouterr().out


# ---------------------------------------------------- containment rows

@pytest.fixture(scope="module")
def trajs():
    return r4.r3.build()


def test_no_protection_and_rules_containment(trajs):
    b1 = r4.contain_summary(r4.rules_rows(trajs, enforce=False))
    b2 = r4.contain_summary(r4.rules_rows(trajs, enforce=True))
    assert b1["harm_completion"] == 1.0 and b1["contained"] == 0
    assert b2["harm_completion"] == 0.5 and b2["mean_steps_to_containment"] == 0.0
    assert b2["approvals_per_100_benign"] == 0.0 and b2["benign_disrupted"] == 0.0


def test_frozen_hybrid_containment(trajs, tmp_path):
    eng = r4.RiskEngine(r4.RiskModel.load(r4.r3.MODEL_PATH), r4.Levels.load(r4.r3.LEVELS_PATH))
    sub = [t for t in trajs if t.is_attack][:10] + [t for t in trajs if not t.is_attack][:10]
    rows = r4.contain(sub, r4.frozen_points(eng.model, sub), eng.levels, eng.model, "always_deny", tmp_path)
    s = r4.contain_summary(rows)
    assert 0.0 <= s["harm_completion"] <= 0.5 and len(rows) == 20


# ---------------------------------------------------- figures / tables

def test_svg_is_valid_xml():
    for svg in (line_chart("t", "x", "y", {"a": [(0, 0), (0.5, 0.7), (1, 1)], "b <&>": [(0, 0), (1, 0.2)]},
                           diagonal=True),
                histogram("h", "x", "y", [0, 1, 1, 3], "Hybrid"), histogram("h", "x", "y", [], "none")):
        root = ET.fromstring(svg)
        assert root.tag.endswith("svg")


def test_r2l_table_lists_every_committed_run():
    from argus.eval import reproduce
    md = reproduce.render_r2l()
    assert md.count("qwen2.5:3b") >= 4 and md.count("llama3.2:3b") >= 2 and md.startswith(reproduce.HEADER)


def test_latency_harness_smoke():
    from argus.eval import latency
    r = latency.measure(calls=20)
    assert r["components"]["policy"]["n"] >= 20 and 0 < r["risky_call_fraction"] < 1
    assert r["llm_per_risky_call"]["n"] > 0 and not r["l5_p95_le_2s"]
    assert "| policy |" in latency.to_markdown(r)


def test_numeric_diff_tolerates_last_digit_noise_only(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    for d, coef, fp in ((a, 1.2345678901234, "x" * 64), (b, 1.2345678901239, "y" * 64)):
        (d / "m").mkdir(parents=True)
        (d / "m" / "model.json").write_text(json.dumps({"coef": [coef, -2.0], "names": ["s1", "s2"]}))
        (d / "manifest.json").write_text(json.dumps({"models": {"m": {"files": {"m/model.json": fp},
                                                                       "ml_fingerprint": fp, "n": 3}}}))
    out, worst = r4.numeric_diff(a, b)
    assert out == [] and 0 < worst < r4.REL_TOL
    (b / "m" / "model.json").write_text(json.dumps({"coef": [1.2346, -2.0], "names": ["s1", "s2"]}))
    out, _ = r4.numeric_diff(a, b)
    assert out and "coef[0]" in out[0]
    (b / "manifest.json").write_text(json.dumps({"models": {"m": {"files": {}, "ml_fingerprint": "z", "n": 4}}}))
    assert any(".n:" in x for x in r4.numeric_diff(a, b)[0])
