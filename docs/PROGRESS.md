# ARGUS Progress

Tag tasks with owners: **M1** AI/ML · **M2** Security · **M3** Backend · **M4** Frontend/Research.

## Current phase

**2026-10-24: R1b, R2-L, R3 and R4 are done on dev and frozen; Phase W (web app + class demo) built, at the W-f rehearsal checkpoint. Everything official (G4-R2, R2 test, G5, G6) waits on the blind test v2 the project owner is writing (ADR-0008).** History: Phase R1 complete — G4 FAILED (pre-registered), 2026-10-23. Signal is strong (OC-SVM AUROC 0.990, catches 100% of rule-invisible attacks ~1 step earlier) but FPR on unseen benign task shapes is 32.2% (> 10%). Decision: RESCUE (ADR-0003). Plan: `docs/PLAN_R1_RESCUE.md` (approved: "GO").

## Roadmap (ADR-0003)

| Phase | Focus | Gate | Status |
|---|---|---|---|
| R1 | Features v2 + AgentEscapeBench v1 (3 families, policy-compliant variants, hard benign, frozen test split) + IF/OC-SVM | G4 | **FAIL** — AUROC passes, FPR 32% blocks G4-b/c |
| R1b | RESCUE-2: compositional benign, per-context LOIO calibration, B2+ rules, blind test v2 | G4-R2 | **dev done** (R1b-3 selected `ocsvm-nu0.10-quantile-global`, ADR-0007); **G4-R2 waits on test v2** (`templates_test_v2.py`, you) |
| R2 | Live LLM intent monitor, cached replay, injection-safe | L1–L6 (ADR-0009) | **dev done ($0)**: qwen2.5:3b frozen (ADR-0011); dev AUROC 0.677, benign FPR 36.5%, p95 9.6 s; test-v2 run waits on test v2 |
| R3 | Calibrated risk engine, per-signal explanations, containment, approval queue | G5 (ADR-0012) | **dev done, frozen 2026-10-24** (`docs/R3_DEV_REPORT.md`, ADR-0012 accepted): hybrid DR 0.975 / FPR 0.095 vs B2+ 0.833 (G5 dev preview pass); R3-c workload 27/100 fails ≤ 15 (recorded finding). Official G5 waits on test v2 |
| R4 | Baselines + hybrid + ablations, open-set, ≥5 seeds, CIs, latency, `make reproduce` | G5, G6 | **R4-a..e built, protocol frozen** (ADR-0013 accepted; tables `docs/results/r4_dev.md`): dev G5 preview pass, G6 preview 3/3, seed DR 0.71 ± 0.22 (recorded finding: detection depends strongly on training templates). **Checkpoint accepted 2026-10-24**; R4-f (test v2) blocked on `templates_test_v2.py` |
| R5 | Adaptive attacker (stretch) | evasion rate per round | not started |
| W | Upgrade web app (ADR-0002) to new APIs + class demo mode | G7 | **W-a..e built** (ADR-0014 accepted; `docs/WEBAPP.md`, `docs/DEMO_SCRIPT.md`); G7 check passes locally, CI job `demo`. **Next: W-f rehearsal (you run `make serve` and walk the demo)** |
| LA | Real LLM agent + live LLM monitor, end to end on GitHub runners (exploratory) | — (ADR-0015) | **on hold, not built** (ADR-0015): implementation stopped during LA-a; partial code reverted; plan kept as a record |
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
- [x] Benign task catalog check (2026-10-23, exploratory): 27 categories × 8 legit agent tasks; 0 policy blocks; R1b-selected detector false alarms 6% vs R1 detector 34%; residual alarms = requested file edits. `docs/BENIGN_CATALOG.md`.
- [x] R2L-a (2026-10-23, ADR-0011): free open-weights monitor via Ollama on a GitHub-hosted runner — loopback-only adapter, sharded/resumable runner with time cap, manual `r2-llm.yml` (no secrets, Ollama 0.40.2 pinned), 27 offline tests; fixed empty-cache bug.
- [x] R2 provider switch (2026-10-23, ADR-0010): OpenAI adapter (Responses API, strict structured output, store=False), provider-aware pilot preflight and OpenAI prices in the cost cap; Claude adapter kept; `openai==3.37.0` pinned; 11 new offline tests.
- [x] R2-a/b/c (2026-10-23): LLM intent monitor with mock/replay/live modes, sha256 response cache, fail-closed mapping, advisory-only combination, injection-escaped renderer; 46 security tests (no network); `anthropic==2.1.0` pinned.
- [x] Dependencies pinned (2026-10-23): exact pins in `requirements.txt`, full transitive lock in `constraints.txt` (26 packages, Python 3.11.9); CI installs the lock on Python 3.11.9; `tests/test_dependency_lock.py` keeps files consistent and checks the numerics stack matches.
- [x] CI (2026-10-23): `.github/workflows/ci.yml` — pytest (mock LLM mode), byte-identical regeneration checks for bench v1 / dev v2 / test v2 (once frozen), dashboard typecheck + build + npm audit. **First GitHub run green** (2026-10-23, commit `64eea66`, run 39919602781): all 701 tests pass on Linux and every frozen benchmark regenerates byte-identically there, so the bench files are reproducible across OSes.
- [x] Web app (ADR-0002, 2026-10-23): FastAPI `argus/api/` + React/TS `dashboard/` — overview, scenario drill-down, enforce-mode gateway playground, experiments/provenance. 33/33 tests (25 new API/security tests). See `docs/WEBAPP.md`.

## PoC results (2026-10-11)

- **Prefix AUROC: 0.536** (below 0.70 threshold — ML fails)
- **Rules DR: 100%** (fire at exactly first_unsafe_step, steps-before-harm = 0.0)
- **ML DR: 0%** (no attacks detected above benign p90 threshold)
- **ML FPR: 50%** (2 of 4 benign trajectories flagged)
- **Mock LLM: identical to rules** (same scope-based signal)

## Next

1. R1b-1 (**user**, ADR-0008): test v2 per `docs/TEST_V2_AUTHORING.md` with composition fixed in ADR-0008 → `test-v2 freeze:` commit, **after** the R1b analysis commit.
2. R1b-2 **done**: dev v2 benign (420, 14 intents), policy v3, `--split test_v2` generator mode, blindness guard. Checkpoint: review `docs/DEV_V2.md`.
3. R1b-3 **built + run on dev**: selected `ocsvm-nu0.10-quantile-global` (nested FPR 9.5%). Protocol committed before test v2 is written (ADR-0008).
4. R1b-4: `python -m argus.eval.r1b_final` once → G4-R2 verdict + `docs/R1B_RESULTS.md`.
5. R2-a/b/c **done**: monitor (`argus/intent/monitor.py`), prompt `monitor-v1` (`argus/intent/prompt.py`), 46 security tests. **R2-L pilot done (2026-10-24):** both candidates ran on GitHub's runners at $0; the pre-registered rule selected **`qwen2.5:3b`** (see EXPERIMENTS.md). Early signal (dev, n = 20, exploratory): it flags every attack trajectory but also 7/11 benign ones, and per-call latency is ~6.5 s on CPU, so L1/L2/L5 are at risk. Model + prompt **frozen** (ADR-0011). **R2L-d done (2026-10-24):** dev AUROC 0.677, benign FPR 36.5%, policy-compliant DR 98%; catalog 26.4% of legitimate tasks flagged (ML: 5.6%). Only the test-v2 run (R2L-e) remains, after G4-R2. The OpenAI key pasted in chat was not used and must be revoked (2026-10-23). Runner ready: `python -m argus.eval.r2_pilot --smoke`, then `python -m argus.eval.r2_pilot` (fixed 20 dev trajectories, spend tracked from API token usage, stops before crossing the cap, stops on credential/first-call failure; preflight made 0 calls, $0).
2. Note: the v1 test split is spent for confirmatory use; any re-test needs a fresh (ideally blind-written) test split.

## Open risks

- **GitHub runner images change under us:** `ubuntu-latest` moved to 26.04 (no Python 3.11.9) on 2026-10-19 and broke a run; both workflows are now pinned to `ubuntu-24.04`. Pinned images are eventually retired too, so revisit before the final runs.

- **Small local LLM over-flags benign work (confirmed on dev + catalog):** dev benign FPR 36.5%, catalog 26.4% (worse than the ML detector's 5.6%); legit secret work and requested edits flagged almost always. Earlier pilot note: qwen2.5:3b escalated at least one step in 7/11 benign pilot trajectories (steps: 19/88) while catching 9/9 attacks; prefix AUROC 0.638 (< L1's 0.70). Expect L1/L2 to fail on dev unless the dev-scale numbers differ.

- **G4-R2 likely to fail on the FPR condition (ADR-0007, predicted before test v2):** selected config's nested FPR is 0% for plain/egress tasks but 66.7% for unseen legitimate secrets tasks; margin to the 10% bar is 0.5 pp.

- **Test v2 is only partially blind (ADR-0008):** written by the project owner, who has seen high-level detector results. Analysis was fixed first, but author bias in scenario design is uncontrolled; report G4-R2 as an author-aware sealed test.
- **Repo is public** (https://github.com/shivek555/ARGUS): only synthetic canaries are committed, but teammate-authored test v2 will be readable by anyone, including the detector side; blindness rests on discipline + `tests/test_blindness.py`.

- **B2+ closes much of the gap (dev evidence):** policy v3 blocks all dev credential/exfil policy-compliant attacks; ML's distinct value vs B2+ may be limited to objective-relative tampering. Will be reported as the secondary comparison in R1b.

- **One-class calibration does not transfer to unseen benign task shapes** (R1: dev val FPR 5.6% → test 32.2%; `key_rotation_check` flagged 15/15). Any ML-in-the-loop design must handle legitimate-but-novel behaviour.
- **Rules baseline may be a straw man:** part of what OC-SVM catches (unscoped high-sensitivity reads) could be a policy rule. Add a stronger B2+ rules baseline in R4.

- **Earliness prediction was wrong (ADR-0004 said unlikely):** on test, OC-SVM flagged attacks 0.96 steps earlier than rules on attacks both caught (blocked from counting only by the FPR condition). Univariate dev diagnostics underestimated the multivariate signal.
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
| G4 ML beats rules on a defined metric | **FAIL (R1, pre-registered)**: AUROC 0.990 ≥ 0.70 but FPR 32% > 10% |
| G5 hybrid ≥ best component | **dev preview pass** (0.975 vs B2+ 0.833, out-of-fold); official verdict on test v2 (R4) |
| G6 some unseen-family detection | criterion pre-registered (ADR-0013 accepted); **dev preview pass** 3/3 families (compliant DR 1.00 / 1.00 / 0.85); official on test v2 |
| G7 demo from clean checkout | **local PASS**; CI job `demo` on a clean ubuntu-24.04 checkout; laptop rehearsal (W-f) pending |

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
| R1-e | IF + OC-SVM, validation threshold, 5 seeds | M1 | **done** — `argus/detectors/trajectory.py`; protocol ADR-0005 committed before test |
| R1-f | `python -m argus.eval.r1` + G4 report | M4 | **done** — G4 FAIL; `docs/R1_RESULTS.md` |
| W-1 | API + dashboard over PoC (ADR-0002) | M3 + M4 | **done** — read-only; hybrid/latency shown as TODO |
