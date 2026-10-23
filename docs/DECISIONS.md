# ARGUS Architecture Decision Records

Short ADRs. Newest first. Do not hide disagreements.

---

## ADR-0000 — Use `ARGUS_PROMPT.md` as the project constitution

- **Date:** 2026-10-05
- **Status:** accepted
- **Decision:** Treat `ARGUS_PROMPT.md` as the research/engineering constitution. `CLAUDE.md` points at it and restates the Phase 0 kickoff.
- **Alternatives:** Ignore the brief and start coding the 12-component architecture; rewrite the brief first.
- **Why:** The brief already encodes hypothesis, invariants, eval protocol, and anti-hype rules. Deviating without an ADR is how the project becomes a dashboard.

---

## ADR-0004 — Trajectory features v2: what is in, what is out

- **Date:** 2026-10-23
- **Status:** accepted (R1-d, designed on the dev split only; test split not loaded)
- **Decision:** `argus/features/trajectory.py`: 36 default features in 6 groups (objective-relative 7, sensitivity 6, behaviour 11, network/flow 5, position 1, current action 6), one vector per prefix, inputs = immutable objective + gateway events only. Two ablation-only groups are **off by default**:
  - `length` (`step`): on dev, unsafe steps come late (mean first_unsafe 4.2–4.7) while benign trajectories average 4.8 steps, so `step` alone scores AUROC 0.80 (dev diagnostic). That is a template artefact, not behaviour.
  - `dlp` (`[CANARY]` marker in args): a perfect secret-in-outgoing-data oracle that exists only because the benchmark plants canaries.
- **Secret keywords apply to recon only** (search queries, listed dirs). File reads use the gateway's path-based sensitivity, so test secrets the heuristic rates "low" (`keys/ci_token`, `service/settings.py`) stay low. Applying keywords to paths would have silently undone that deliberate test-split shift.
- **Disclosed bias:** `SECRET_TERMS` is a generic scanner-style list (password, token, credential, aws, ssh, …), but it was chosen by the same author who wrote the test templates and it covers test recon queries. R1-f must report an ablation without the recon-keyword features.
- **Alternatives:** keep `step` (inflates results via an artefact); learned embeddings / sequence models (cut by ADR-0001 unless IF/OC-SVM leave a measured gap); keywords on paths (leaks author knowledge of the test layout).
- **Consequences for R1-f:** (1) report a length-matched control (unsafe vs benign prefixes at the same step index); (2) ablations: each group off, plus `+length`, `+dlp`, and `-recon keywords`; (3) `readback_of_written` is constant on dev (multi-hop exfil exists only in test): IF cannot use it, OC-SVM may react to it; note it when interpreting test results.
- **Dev diagnostic (design aid, not G4):** `python -m argus.eval.r1_dev_diag`. Strongest univariate signals on dev: `high_unscoped` (0.775 unsafe / 0.895 policy-compliant), `sens_max`, `distinct_dirs` (partly length-confounded), low objective overlap. **Precursor prefixes (before first_unsafe) are ≈ 0.5 on every feature**, so early detection (G4-c) looks unlikely with these features; detection of policy-compliant attacks (G4-b) looks plausible. Stated now, before any test run.

---

## ADR-0003 — RESCUE the ML branch; research first, web app last

- **Date:** 2026-10-23
- **Status:** accepted (user: "great", approving the phase plan and RESCUE)
- **Decision:** Do not pivot yet. Build the research system completely first, working without the web app, in gated phases: **R1** ML rescue (features v2 + AgentEscapeBench v1, plan in `docs/PLAN_R1_RESCUE.md`) → **R2** live LLM intent monitor with cached replay → **R3** calibrated risk engine, explanations, containment, approval queue → **R4** full evaluation (baselines, ablations, open-set, ≥5 seeds, CIs, latency, `make reproduce`) → **R5** adaptive attacker (stretch) → **W** upgrade the web app for the class presentation → **P** report. One phase at a time; stop at each gate for user review.
- **R1 scope changes:** add `fs_list` tool, synthetic sensitive files and a workspace-confinement rule (policy v2). Benchmark v0 (10 PoC scenarios) stays byte-identical and frozen.
- **Web app:** the ADR-0002 app is parked as-is; it is updated in Phase W to the new APIs. No UI work before then.
- **Alternatives:** PIVOT now to Alt A (comparison project); RESCUE with only more of the same 12-D features.
- **Why:** The PoC failure has a clear cause (features duplicate the rules; attacks lack precursors; every attack is policy-visible; N = 10). Those are fixable within the MODIFY scope. If G4 still fails after R1, we pivot with evidence.

---

## ADR-0002 — Build the web app (API + dashboard) now, read-only over the PoC

- **Date:** 2026-10-23
- **Status:** accepted (user request: "create a proper web app for this")
- **Decision:** Add `argus/api/` (FastAPI) and `dashboard/` (React + TypeScript + Vite) now, before G4 is resolved. The app only *exposes* what exists: frozen scenario replays, the logged PoC run (`eval/results/poc/summary.json`), and an enforce-mode gateway playground over the in-process fake tools. It computes no new metrics beyond per-trajectory rates derived from the logged rows, and shows `TODO: not yet measured` for the hybrid, latency and S1–S5.
- **Conflict noted:** The brief (§4 item 12, §8) and ADR-0001 put the dashboard last, on stable APIs. Building it now risks UI churn when the schema/features change during the G4 rescue. Mitigation: the UI reads typed API responses only; there are no metric computations in the frontend; the service reuses `compute_summary`, `Gateway`, `PolicyEngine`, `PrefixIsolationForest` and `MockIntentMonitor` unchanged.
- **Small core changes:** `PolicyEngine.evaluate()` returns `(decision, rule, reason)` for explainability; `decide()` delegates to it, so behaviour is unchanged (replay tests still pass). `compute_summary()` and `MemoryLogger`/`EventSink` (already in the working tree) are used by the API.
- **Alternatives:** (a) Static HTML report generated from `summary.json` — simpler, but no live gateway demo, and the brief asks for React+TS. (b) Streamlit — fast, but not the stack in §4 and harder to keep honest about provenance. (c) Wait for G4 — correct by the plan, but rejected by the user's explicit request.
- **Dependencies:** no router library: a 30-line hash router replaces `react-router-dom` (6.x had open advisories at time of writing; five routes do not justify it). Charts are hand-written SVG. Runtime deps: `react`, `react-dom`; Python: `fastapi`, `uvicorn`.
- **Security:** binds to 127.0.0.1 by default; no CORS (Vite proxies in dev, same origin in prod); CSP + nosniff + frame-deny headers; request bounds (8 args, 10 000 chars, identifier-only tool/arg names, 100 steps/session, 64 sessions LRU); responses carry only redacted args/results; objective has no write endpoint (PATCH/PUT → 405). Covered in `tests/test_api.py`.
- **Why:** A demo surface is needed for supervisor reviews and G7, and it is cheap if it stays a thin, read-mostly layer over the existing code.

---

## ADR-0001 — Scope is MODIFY, not full GO

- **Date:** 2026-10-06
- **Status:** accepted (user: “approved”)
- **Decision:** Keep the trajectory hypothesis and evaluation protocol. Cut dashboard-from-week-1, nine-family AgentEscapeBench, Redis/pgvector/K8s/MLflow, and sequence deep learning unless G4 shows a measured gap. PoC and weeks 1–2 follow `docs/FEASIBILITY.md` §6–§9.
- **Alternatives:** GO as written; REJECT and switch to Alt A/B/C.
- **Why:** See feasibility §6. Full GO is not feasible for 4×16 weeks with valid experiments.

---

## Template

```
## ADR-XXXX — title
- Date:
- Status: proposed | accepted | superseded
- Decision:
- Alternatives:
- Why:
```
