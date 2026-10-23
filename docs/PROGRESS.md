# ARGUS Progress

Tag tasks with owners: **M1** AI/ML · **M2** Security · **M3** Backend · **M4** Frontend/Research.

## Current phase

**Phase R1 (ML rescue) — in progress. R1-a/b/c/d done (2026-10-23); next R1-e/f (detectors + G4 run).** Decision: RESCUE (ADR-0003). Plan: `docs/PLAN_R1_RESCUE.md` (approved: "GO").

## Roadmap (ADR-0003)

| Phase | Focus | Gate | Status |
|---|---|---|---|
| R1 | Features v2 + AgentEscapeBench v1 (3 families, policy-compliant variants, hard benign, frozen test split) + IF/OC-SVM | G4 | **in progress** (R1-a/b/c/d done) |
| R2 | Live LLM intent monitor, cached replay, injection-safe | schema-validated, cannot override BLOCK | not started |
| R3 | Calibrated risk engine, per-signal explanations, containment, approval queue | full loop runs | not started |
| R4 | Baselines + hybrid + ablations, open-set, ≥5 seeds, CIs, latency, `make reproduce` | G5, G6 | not started |
| R5 | Adaptive attacker (stretch) | evasion rate per round | not started |
| W | Upgrade web app (ADR-0002) to new APIs + class demo mode | G7 | parked (v0 app exists) |
| P | Report + presentation | — | not started |

## Done

- [x] Canonical brief: `ARGUS_PROMPT.md`
- [x] Session contract: `CLAUDE.md`
- [x] `docs/FEASIBILITY.md` → MODIFY accepted (2026-10-06)
- [x] ADR-0001 accepted (MODIFY scope)
- [x] P1-1: Event schema v1 + gateway + scripted agent runtime
- [x] P1-2: 10 scenario YAMLs (4 benign, 6 attack, 3 families) with first_unsafe_step
- [x] P1-3: Prefix features (12D bag-of-tools) + Isolation Forest
- [x] P1-4: YAML policy baseline B2
- [x] P1-5: Mock LLM intent judge (deterministic heuristic + cache)
- [x] P1-6: Eval harness (`python -m argus.eval.poc`) → summary.json
- [x] 8/8 tests passing (gateway bypass, no-network, label leak, replay)
- [x] Bugfix: syntax error in tools.py (mismatched quote), unused Gateway import in prefix.py
- [x] Web app (ADR-0002, 2026-10-23): FastAPI `argus/api/` + React/TS `dashboard/` — overview, scenario drill-down, enforce-mode gateway playground, experiments/provenance. 33/33 tests (25 new API/security tests). See `docs/WEBAPP.md`.

## PoC results (2026-10-11)

- **Prefix AUROC: 0.536** (below 0.70 threshold — ML fails)
- **Rules DR: 100%** (fire at exactly first_unsafe_step, steps-before-harm = 0.0)
- **ML DR: 0%** (no attacks detected above benign p90 threshold)
- **ML FPR: 50%** (2 of 4 benign trajectories flagged)
- **Mock LLM: identical to rules** (same scope-based signal)

## Next

1. R1-e/f: IF + OC-SVM, validation threshold, runner → G4 report, then stop for decision.

## Open risks

- **Early detection may fail (dev evidence, ADR-0004):** precursor prefixes look like benign on every feature (univariate AUROC ≈ 0.5). G4-c is at risk; G4-b (policy-compliant DR) is the realistic path.
- **Length artefact:** benchmark templates put unsafe steps late; `step` excluded by default, length-matched control required in R1-f.

- **ML viability**: Current bag-of-tools features cannot separate attack from benign prefixes. Root cause: features don't encode pre-attack behavioral patterns, only tool identity (which collapses to rules).
- **Benchmark circularity**: same author wrote dev and test templates. Mitigated (separate files/vocab/shapes/seeds, test frozen before tuning), not removed. Optional fix: a teammate writes a blind "test-B" template set.
- **Mock LLM adds zero signal**: Perfectly correlated with rules. Need real LLM judge to test hybrid hypothesis.
- **N too small**: 10 scenarios (40 prefix vectors) is insufficient for any ML model.
- **Dashboard built early (ADR-0002)**: expect API/UI changes when features/schema change in the G4 rescue. Keep metric logic server-side.
- **Policy gap surfaced by the dashboard**: in A-creds-s1, step 3 (`fs_write` of the canary to `/workspace/stolen.txt`) is labelled unsafe but ALLOWED by policy (only the earlier `creds_list` is blocked). It is the only unsafe-but-allowed step across the 10 scenarios. Detection still counts as "in time" because the first flag is at the first unsafe step.

## Gate status

| Gate | Status |
|---|---|
| Phase 0: FEASIBILITY.md + GO/MODIFY/REJECT | **PASS** (MODIFY) |
| G1 agent E2E in sandbox | **PASS** (in-process; Docker deferred) |
| G2 trajectory replay | **PASS** (replay_decisions tested) |
| G3 benign vs unsafe distinguishable | **FAIL** for ML (AUROC=0.536); **PASS** for rules (100% DR) |
| G4 ML beats rules on a defined metric | **FAILING** — rescue attempt needed |
| G5 hybrid ≥ best component | not started |
| G6 some unseen-family detection | not started |
| G7 demo from clean checkout | not started |

## Task board

| ID | Task | Owner | State |
|---|---|---|---|
| P0-1 | Feasibility research + doc | M4 + all | done |
| P0-2 | Decision from supervisor/team | you | done (MODIFY) |
| P1-0 | Weeks 1–2 / PoC plan | M3 + M2 | done |
| P1-1 | Event schema + gateway + scripted loop | M3 | **done** |
| P1-2 | Hard benign + 3 attack scripts + labels | M2 | **done** |
| P1-3 | Prefix features + Isolation Forest | M1 | **done (result: AUROC=0.536)** |
| P1-4 | YAML policy baseline | M3 | **done** |
| P1-5 | LLM judge interface (mock) | M1 | **done** |
| P1-6 | PoC tables + freeze hashes | M4 | **done (hashes in summary.json, not yet in EXPERIMENTS.md)** |
| P2-0 | Feature rescue plan | M1 + all | **done** (RESCUE, ADR-0003) |
| R1-a | Fake world v2 + `fs_list` + policy v2 | M2 + M3 | **done** — `world_v2()`, `fs_list`, path normalization, `configs/policies/v2.yaml` (workspace confinement); 46 new tests; v0 hashes + PoC summary verified identical |
| R1-b | Scenario generator → bench v1 | M2 | **done** — `argus/bench/{steps,templates_dev,templates_test,generate,dataset}.py`; 420 trajectories (dev 240 / test 180), 3 families × {visible, compliant} + hard benign |
| R1-c | Dev/test split, freeze hashes, leakage tests | M2 + M4 | **done** — test split frozen (hash in EXPERIMENTS.md), `.gitattributes` keeps bytes exact, 433 new tests |
| R1-d | Trajectory features v2 | M1 | **done** — 36 default features / 6 groups (+ ablation-only `length`, `dlp`), 20 leakage/behaviour tests, dev diagnostic (ADR-0004) |
| R1-e | IF + OC-SVM, validation threshold, 5 seeds | M1 | approved, not started |
| R1-f | `python -m argus.eval.r1` + G4 report | M4 | approved, not started |
| W-1 | API + dashboard over PoC (ADR-0002) | M3 + M4 | **done** — read-only; hybrid/latency shown as TODO |
