"""R4-c: per-call overhead of each ARGUS component (RQ5, docs/PLAN_R4_FULL_EVAL.md §7).

    python -m argus.eval.latency [--calls 2000] [--doc docs/results/latency-laptop.md]

Times, on this machine, per tool call of the dev trajectories (warm-up discarded):
* policy check (v2);
* feature extraction + ML score (frozen R1b config, fitted on dev benign);
* risk engine: signals + score + level (frozen ADR-0012 model; LLM excluded);
* gateway + containment bookkeeping (ContainedSession.request, incl. the risk decision);
LLM latency is not measured here: it is read from the live timings the GitHub runner recorded
in the committed qwen2.5:3b cache (CPU, no GPU), and applies to risky calls only.
Output depends on the machine, so it is never part of `reproduce --check`.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

import numpy as np

from argus.bench.dataset import POLICY_V2, build_world
from argus.containment.session import ApprovalQueue, ContainedSession
from argus.detectors.trajectory import PrefixDetector
from argus.eval import r1b, r3
from argus.eval.r2_local import CACHE_ROOT
from argus.features.trajectory import DEFAULT_GROUPS, trajectory_matrix
from argus.intent.monitor import is_risky
from argus.policy.engine import PolicyEngine
from argus.risk.engine import Levels, RiskEngine
from argus.risk.model import RiskModel
from argus.risk.signals import step_signals

WARMUP = 200
OUT_DIR = r3.ROOT / "eval" / "results" / "r4"


def _pct(xs: list[float]) -> dict[str, float]:
    return {"p50_ms": float(np.percentile(xs, 50)), "p95_ms": float(np.percentile(xs, 95)),
            "mean_ms": float(np.mean(xs)), "n": len(xs)}


def _time(fn: Callable[[], Any]) -> float:
    t0 = time.perf_counter()
    fn()
    return (time.perf_counter() - t0) * 1000


def llm_cache_latency(model_dir: Path = CACHE_ROOT / "qwen2.5_3b") -> dict[str, Any]:
    ms = []
    for f in sorted(model_dir.glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("latency_ms") is not None:
                ms.append(float(row["latency_ms"]))
    return {**_pct(ms), "source": f"{model_dir.relative_to(r3.ROOT).as_posix()} (live, GitHub runner CPU)"}


def measure(calls: int = 2000) -> dict[str, Any]:
    v2, v3 = PolicyEngine.from_yaml(POLICY_V2), PolicyEngine.from_yaml(r3.POLICY_V3)
    dev = r1b.load_dev(v2)
    kind, nu, scaler = r3.ML_CONFIG
    det = PrefixDetector(kind, 0, nu, scaler).fit([r for p in dev.benign for r in p.rows(DEFAULT_GROUPS)])
    engine = RiskEngine(RiskModel.load(r3.MODEL_PATH), Levels.load(r3.LEVELS_PATH))
    trajs = dev.attacks + [p for p in dev.benign if p.idx < r3.DEV_BENIGN_PER_INTENT]

    times: dict[str, list[float]] = {"policy": [], "features_ml": [], "risk_engine": [], "gateway_containment": []}
    seen = 0
    risky = steps = 0
    snaps = Path(tempfile.mkdtemp(prefix="argus-latency-"))
    while seen < calls + WARMUP:
        for p in trajs:
            sigs = []
            for i, e in enumerate(p.events):
                t_pol = _time(lambda: v2.evaluate(e, p.objective))
                score: list[float] = []
                t_ml = _time(lambda: score.extend(det.score([trajectory_matrix(p.objective, p.events[: i + 1])[-1]])))
                t0 = time.perf_counter()
                s = step_signals(p.objective, e, v2=v2, v3=v3, anomaly=score[0], llm=None)
                engine.decide(s, e.step, e.tool)
                t_risk = (time.perf_counter() - t0) * 1000
                sigs.append(s)
                if seen >= WARMUP:
                    times["policy"].append(t_pol)
                    times["features_ml"].append(t_ml)
                    times["risk_engine"].append(t_risk)
                    risky += is_risky(e)
                    steps += 1
                seen += 1
            lookup = {e.step: s for e, s in zip(p.events, sigs)}
            sess = ContainedSession(objective=p.objective, world=build_world(p.t), policy=v2, engine=engine,
                                    signals=lambda o, h, ev: lookup[ev.step], queue=ApprovalQueue(),
                                    snapshot_dir=snaps, agent_id="latency")
            for c in p.t.calls:
                if sess.quarantined:
                    break
                t_gw = _time(lambda: sess.request(c.tool, dict(c.args)))
                if seen >= WARMUP:
                    times["gateway_containment"].append(t_gw)
            if seen >= calls + WARMUP:
                break

    per = {k: _pct(v) for k, v in times.items()}
    no_llm = [a + b + c for a, b, c in zip(times["policy"], times["features_ml"], times["risk_engine"])]
    llm = llm_cache_latency()
    risky_frac = risky / steps
    steps_per_traj = sum(len(p.events) for p in trajs) / len(trajs)
    return {
        "host": {"platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
                 "cpu_count": os.cpu_count(), "python": sys.version.split()[0],
                 "ci": bool(os.environ.get("GITHUB_ACTIONS"))},
        "components": per,
        "argus_without_llm_per_call": _pct(no_llm),
        "llm_per_risky_call": llm,
        "risky_call_fraction": risky_frac,
        "expected_llm_seconds_per_trajectory": risky_frac * steps_per_traj * llm["p50_ms"] / 1000,
        "steps_per_trajectory": steps_per_traj,
        "time_to_containment_note": "containment acts at the flagged call itself, so its added latency is one "
                                    "decision (argus_without_llm_per_call, plus the LLM on risky calls)",
        "l5_p95_le_2s": llm["p95_ms"] <= 2000,
    }


def to_markdown(r: dict[str, Any]) -> str:
    h = r["host"]
    lines = [f"# Latency (R4-c, RQ5): {h['platform']}", "",
             f"Host: {h['machine']}, {h['cpu_count']} CPUs, Python {h['python']}; CI: {h['ci']}. "
             "Generated by `python -m argus.eval.latency`; machine-dependent, not part of `reproduce --check`.", "",
             "| Component (per call) | p50 ms | p95 ms | n |", "|---|---|---|---|"]
    for k, v in {**r["components"], "ARGUS without LLM (policy + features/ML + risk)": r["argus_without_llm_per_call"],
                 "LLM, risky calls only (recorded on GitHub runner)": r["llm_per_risky_call"]}.items():
        lines.append(f"| {k} | {v['p50_ms']:.2f} | {v['p95_ms']:.2f} | {v['n']} |")
    lines += ["", f"Risky calls: {100 * r['risky_call_fraction']:.1f}% of calls; "
              f"{r['steps_per_trajectory']:.1f} calls per trajectory; expected LLM time "
              f"≈ {r['expected_llm_seconds_per_trajectory']:.1f} s per trajectory.",
              f"L5 (LLM p95 ≤ 2 s): {'PASS' if r['l5_p95_le_2s'] else 'FAIL'}.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--calls", type=int, default=2000)
    ap.add_argument("--doc", type=Path, help="also write a Markdown table here")
    args = ap.parse_args(argv)
    r = measure(args.calls)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "latency.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
    md = to_markdown(r)
    if args.doc:
        args.doc.parent.mkdir(parents=True, exist_ok=True)
        args.doc.write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
