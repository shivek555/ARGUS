"""Check every benign catalog task against ARGUS (exploratory false-alarm stress test).

    python -m argus.eval.catalog_check   → eval/results/catalog/summary.json

For each of the 27 task categories × 8 variants (``argus.bench.benign_catalog``):
  * policy v2 and v3 (B2+) must never BLOCK (a block here = policy false positive);
  * the R1b-selected detector and the R1 control detector, fit and calibrated
    exactly as in R1b (dev v2 benign, LOIO thresholds), raise an alarm if any
    prefix score exceeds the threshold for the objective's context.

Exploratory only: it does not change the R1b selection, grid or G4-R2 analysis
(all committed in f1e83b1) and contains no attacks.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from argus.bench import benign_catalog
from argus.bench.dataset import POLICY_V2, objective_of, replay
from argus.eval import r1b
from argus.eval.r1 import Prepared
from argus.policy.engine import PolicyEngine

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "eval" / "results" / "catalog" / "summary.json"
POLICY_V3 = ROOT / "configs" / "policies" / "v3.yaml"
SELECTED = "ocsvm-nu0.10-quantile-global"     # ADR-0007
COMPARE = ("control-ocsvm-standard-global",)  # the R1 detector, recalibrated as in R1b


def _check_selected_matches_dev_run() -> None:
    path = r1b.OUT_DIR / "dev_selection.json"
    if path.exists():
        recorded = json.loads(path.read_text(encoding="utf-8"))["selection"]["selected"]
        if recorded != SELECTED:
            raise RuntimeError(f"dev_selection.json selected {recorded}, expected {SELECTED} (ADR-0007)")


def run(out: Path = OUT) -> dict[str, Any]:
    _check_selected_matches_dev_run()
    v2, v3 = PolicyEngine.from_yaml(POLICY_V2), PolicyEngine.from_yaml(POLICY_V3)
    catalog: list[Prepared] = []
    policy_blocks: list[dict[str, Any]] = []
    for t in benign_catalog.generate():
        events, _ = replay(t, v2)
        catalog.append(Prepared(t, objective_of(t), events, None))
        for name, pol in (("v2", v2), ("v3", v3)):
            evs = events if name == "v2" else replay(t, pol)[0]
            for e in evs:
                if e.decision == "BLOCK":
                    policy_blocks.append({"id": t.id, "policy": name, "step": e.step, "tool": e.tool})

    dev = r1b.load_dev(v2)
    by_name = {c.name: c for c in r1b.GRID}
    detectors: dict[str, Any] = {}
    for cname in (SELECTED, *COMPARE):
        cfg = by_name[cname]
        fit = r1b.fit_group(cfg.kind, cfg.nu, cfg.scaler, 0, dev)  # OC-SVM: deterministic
        thr = r1b.thresholds(fit, dev.benign, cfg.threshold)
        rows = []
        for p in catalog:
            scores = fit.scores(p)
            step = r1b.first_over(scores, thr[r1b.context_of(p)])
            first = p.events[step - 1] if step else None
            rows.append({"id": p.t.id, "category": p.t.template, "group": benign_catalog.CATEGORIES[p.t.template][0],
                         "context": r1b.context_of(p), "flagged_at": step,
                         "first_flag": None if first is None else f"{first.tool} {first.target}",
                         "max_score": max(scores)})
        detectors[cname] = {"thresholds": thr, "rows": rows, **_rates(rows)}

    summary = {
        "command": "python -m argus.eval.catalog_check",
        "n": len(catalog), "categories": len(benign_catalog.CATEGORIES),
        "per_category": benign_catalog.PER_CATEGORY,
        "policy_blocks": policy_blocks,
        "detectors": detectors,
        "note": "Exploratory benign-only stress test; not part of G4/G4-R2.",
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _rates(rows: list[dict[str, Any]]) -> dict[str, Any]:
    def rate(rs: list[dict[str, Any]]) -> float:
        return sum(r["flagged_at"] is not None for r in rs) / len(rs)

    keys = lambda k: sorted({r[k] for r in rows})  # noqa: E731
    return {
        "fpr": rate(rows),
        "fpr_by_group": {g: rate([r for r in rows if r["group"] == g]) for g in keys("group")},
        "fpr_by_context": {c: rate([r for r in rows if r["context"] == c]) for c in keys("context")},
        "fpr_by_category": {c: rate([r for r in rows if r["category"] == c]) for c in keys("category")},
        "first_flag_tools": dict(Counter(r["first_flag"].split()[0] for r in rows if r["first_flag"])),
    }


def main() -> int:
    s = run()
    print(f"{s['n']} tasks, {s['categories']} categories; policy blocks: {len(s['policy_blocks'])}")
    names = list(s["detectors"])
    print(f"{'category':26} {'group':15} " + " ".join(f"{n[:22]:>23}" for n in names))
    first = s["detectors"][names[0]]
    for cat in first["fpr_by_category"]:
        group = benign_catalog.CATEGORIES[cat][0]
        vals = " ".join(f"{100 * s['detectors'][n]['fpr_by_category'][cat]:22.0f}%" for n in names)
        print(f"{cat:26} {group:15} {vals}")
    for n in names:
        d = s["detectors"][n]
        print(f"{n}: overall FPR {100 * d['fpr']:.1f}% | by context "
              + ", ".join(f"{k} {100 * v:.0f}%" for k, v in d["fpr_by_context"].items())
              + f" | first-flag tools {d['first_flag_tools']}")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
