# ARGUS Progress

Tag tasks with owners: **M1** AI/ML · **M2** Security · **M3** Backend · **M4** Frontend/Research.

## Current phase

**PoC complete — ML branch failed (AUROC=0.536). Awaiting RESCUE/PIVOT decision.**

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

## PoC results (2026-10-11)

- **Prefix AUROC: 0.536** (below 0.70 threshold — ML fails)
- **Rules DR: 100%** (fire at exactly first_unsafe_step, steps-before-harm = 0.0)
- **ML DR: 0%** (no attacks detected above benign p90 threshold)
- **ML FPR: 50%** (2 of 4 benign trajectories flagged)
- **Mock LLM: identical to rules** (same scope-based signal)

## Next

1. **Decision needed**: RESCUE (richer features + more scenarios) or PIVOT (Alt A comparison project)
2. If RESCUE: expand features to ~30D, add ≥20 scenarios, re-run IF + OC-SVM
3. If AUROC ≥ 0.70 after rescue: proceed to risk engine + containment (weeks 5–8)
4. If AUROC < 0.70 after rescue: declare ML not needed (G4 fail), pivot to evaluation-focused project

## Open risks

- **ML viability**: Current bag-of-tools features cannot separate attack from benign prefixes. Root cause: features don't encode pre-attack behavioral patterns, only tool identity (which collapses to rules).
- **Benchmark circularity**: Same team writes attacks and detector. Need hash freeze before tuning.
- **Mock LLM adds zero signal**: Perfectly correlated with rules. Need real LLM judge to test hybrid hypothesis.
- **N too small**: 10 scenarios (40 prefix vectors) is insufficient for any ML model.

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
| P2-0 | Feature rescue plan | M1 + all | **waiting your decision** |
