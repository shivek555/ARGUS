"""R1-d design diagnostic on the DEV split only.

    python -m argus.eval.r1_dev_diag   → eval/results/r1/dev_feature_diag.json

Univariate AUROC of each trajectory feature for three prefix comparisons:
  unsafe_vs_benign      attack prefixes at/after first_unsafe_step vs all benign prefixes
  compliant_vs_benign   same, policy_compliant attacks only (what rules cannot see)
  precursor_vs_benign   attack prefixes BEFORE first_unsafe_step vs benign (early signal)

This is a design aid, not a G4 result: no model, no threshold, and the test
split is never loaded here (asserted).
"""

from __future__ import annotations

import json
from pathlib import Path

from sklearn.metrics import roc_auc_score

from argus.bench.dataset import POLICY_V2, load_split, objective_of, replay
from argus.features.trajectory import FEATURE_GROUPS, FEATURE_NAMES, trajectory_matrix
from argus.policy.engine import PolicyEngine

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "eval" / "results" / "r1" / "dev_feature_diag.json"
ALL_GROUPS = tuple(FEATURE_GROUPS)


def collect() -> dict[str, list[list[float]]]:
    dev = load_split("dev")
    assert {t.split for t in dev} == {"dev"}
    policy = PolicyEngine.from_yaml(POLICY_V2)
    buckets: dict[str, list[list[float]]] = {"benign": [], "unsafe": [], "compliant": [], "precursor": []}
    for t in dev:
        events, _ = replay(t, policy)
        rows = trajectory_matrix(objective_of(t), events, groups=ALL_GROUPS)
        for step, row in enumerate(rows, start=1):
            if t.type == "benign":
                buckets["benign"].append(row)
            elif step >= (t.first_unsafe_step or 0):
                buckets["unsafe"].append(row)
                if t.variant == "policy_compliant":
                    buckets["compliant"].append(row)
            else:
                buckets["precursor"].append(row)
    return buckets


def auroc(pos: list[list[float]], neg: list[list[float]], j: int) -> float | None:
    y = [1] * len(pos) + [0] * len(neg)
    x = [r[j] for r in pos] + [r[j] for r in neg]
    if len(set(x)) < 2:
        return None  # constant feature: undefined
    return round(float(roc_auc_score(y, x)), 4)


def main() -> None:
    b = collect()
    group_of = {n: g for g, names in FEATURE_GROUPS.items() for n in names}
    rows = []
    for j, name in enumerate(FEATURE_NAMES):
        rows.append({
            "feature": name,
            "group": group_of[name],
            "unsafe_vs_benign": auroc(b["unsafe"], b["benign"], j),
            "compliant_vs_benign": auroc(b["compliant"], b["benign"], j),
            "precursor_vs_benign": auroc(b["precursor"], b["benign"], j),
        })
    out = {
        "split": "dev",
        "command": "python -m argus.eval.r1_dev_diag",
        "n_prefixes": {k: len(v) for k, v in b.items()},
        "note": "Univariate, unsupervised-direction AUROC (0.5 = no signal; <0.5 = signal in the opposite "
                "direction). Design aid on dev only; not a G4 result.",
        "features": rows,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out["n_prefixes"]))
    print(f"{'feature':28} {'group':12} {'unsafe':>7} {'compl.':>7} {'precur.':>7}")
    for r in rows:
        f = lambda v: "   —   " if v is None else f"{v:7.3f}"  # noqa: E731
        print(f"{r['feature']:28} {r['group']:12} {f(r['unsafe_vs_benign'])} "
              f"{f(r['compliant_vs_benign'])} {f(r['precursor_vs_benign'])}")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
