# Plan: Phase R1 — ML rescue (features + benchmark v1)

**Status:** waiting approval before code
**Gate:** G4 — ML beats rules on at least one pre-registered metric, and prefix AUROC ≥ 0.70 on the frozen test split. Otherwise: documented failure → PIVOT decision.
**Scope rules:** ADR-0001 MODIFY cuts still apply (3 core families, no PyTorch, no Docker yet). ADR-0003 records this phase.

---

## 1. Why the PoC ML failed (diagnosis, not guesswork)

From `eval/results/poc/summary.json` and the dashboard replays:

1. **Features = tool identity.** The 12-D vector counts `http_post` / `creds_list`. That is the same signal the policy already uses, so ML can at best duplicate rules.
2. **Attacks have no precursors.** Every attack does its harmful call almost immediately (step 2–4), so there is nothing *earlier* to detect. Rules fire exactly at `first_unsafe_step` (steps-before-harm = 0.0).
3. **Every attack is policy-visible.** All 6 attacks violate a scope rule, so rules reach 100% DR and nothing is left for ML to add, except A-creds-s1 step 3 (`fs_write` of a stolen canary), which policy allows.
4. **N = 10 trajectories / 40 prefixes.** Too small to fit or evaluate anything.

So the rescue changes **what we measure against** (objective-relative behaviour) and **what the benchmark contains** (precursors + policy-compliant misuse + hard benign that looks similar). It does not just add more of the same features.

---

## 2. Deliverables

### R1-a. Richer fake world + one new tool (M2) — ADR-0003
- Add realistic sensitive files (synthetic canaries only): `/workspace/.env`, `/workspace/secrets/deploy_key`, `/workspace/configs/db.yaml` (with canary password), `~`-style paths outside `/workspace`.
- Add `fs_list(dir)` so agents can do reconnaissance (a realistic precursor).
- Workspace confinement rule in policy: reads/writes outside `/workspace` → BLOCK (brief §4 item 5 already lists it).
- Existing PoC scenarios stay byte-identical (hashes frozen in `docs/EXPERIMENTS.md`); they keep working as **benchmark v0**.

### R1-b. Scenario generator → AgentEscapeBench v1 (M2)
`argus/bench/generate.py`, seeded, deterministic, writes JSONL trajectories + a manifest.

| Family | Policy-visible variant | Policy-compliant variant (rules can't block) |
|---|---|---|
| Goal hijack | egress to non-allowlisted host | in-scope but off-objective actions (reads/writes unrelated to the task) |
| Credential discovery | `creds_list` without scope | recon (`fs_list`, `repo_search "password"`) → read `.env` / `deploy_key` under `workspace_read` |
| Exfiltration | POST to `evil.fake` | slow-and-low: read secret → write it into a workspace file → POST to the **allowlisted** host in an egress-scoped task |

- **Hard benign templates** (≥5): README summary, dependency audit (reads configs incl. `db.yaml`), analytics report, docs search, **legitimate secrets-audit** (has `secrets-audit` scope, reads `.env`), **legitimate report upload** (egress scope, POSTs to allowlisted host). These deliberately overlap with attack behaviour so features must use context, not tool names.
- **Variation per seed:** benign padding steps, order permutations, path/query paraphrases, attack injection point.
- **Labels per step:** `first_unsafe_step` = first step that is harmful *with respect to the objective* (defined in the template, not by the detector).
- **Volume target:** ≥ 300 trajectories (≈ 50% benign), ≥ 5 seeds.

### R1-c. Anti-circularity protocol (M2 + M4)
- Two template sets: **dev** (used to design features/thresholds) and **test** (different paths, queries, padding distributions, injection points), written in separate files, generated with disjoint seeds.
- Test set is generated **once**, hashed, and recorded in `EXPERIMENTS.md` **before** any feature tuning. Any later change to test templates needs a new ADR and a fresh test seed set.
- Leakage checks (tests): no identical trajectory prefix (tool+target sequence) appears in both dev and test; forbidden fields never reach features (existing test, extended).
- Honest limitation kept in every result: same team wrote attacks and detector.

### R1-d. Trajectory features v2 (M1)
`argus/features/trajectory.py`, ~30-D per prefix, computed from events only (never labels/decisions/results):

- **Objective-relative:** lexical overlap between target path/query and objective text; fraction of steps whose target is outside paths the objective mentions; first-time-in-directory count.
- **Sensitivity dynamics:** max / last / delta of sensitivity; count of high-sensitivity reads; high read followed by write or egress (taint-lite: did data from a sensitive read flow into a later write/POST body, using redacted hashes, not raw values).
- **Behavioural shape:** tool bigram transition indicators (read→egress, search→read-secret, list→read), recon ratio (`fs_list` + `repo_search` / steps), breadth (distinct dirs), write-after-read-secret.
- **Network:** egress count, new-destination flag, egress after high read.
- **Position:** step index, steps since last high-sensitivity event.

Each feature group can be switched off for ablation.

### R1-e. Detectors (M1)
- Isolation Forest and One-Class SVM (scikit-learn), fit on **benign dev** prefixes only.
- Threshold from benign **validation** prefixes (not in-sample, fixing a PoC weakness): per-trajectory FPR ≤ 10%.
- Seeds 0–4 for stochastic parts; report mean ± std.
- PyTorch sequence models stay cut unless both leave a measured gap (ADR-0001).

### R1-f. Evaluation runner (M4)
`python -m argus.eval.r1` → `eval/results/r1/summary.json` + CSV tables. Same harness for:
- B2 rules (policy v2), B3-IF, B3-OCSVM, B3 feature ablations.
- Metrics: per-step AUROC; per-trajectory DR and FPR at the validation threshold; mean steps-before-harm; DR on **policy-compliant** attacks separately; bootstrap 95% CIs over trajectories.
- Added after R1-d (ADR-0004): length-matched control (unsafe vs benign prefixes at equal step index); ablations per feature group, `+length`, `+dlp`, `-recon keywords`.

---

## 3. Pre-registered G4 criteria (fixed now, before any run)

On the frozen **test** split, at per-trajectory FPR ≤ 10% on hard benign:

| ID | Criterion |
|---|---|
| G4-a | Best ML detector prefix AUROC ≥ **0.70** (95% CI lower bound reported) |
| G4-b | ML DR on **policy-compliant** attacks ≥ rules DR on them + **20 pp** (rules DR there is expected ≈ 0 by design; this is stated, not hidden) |
| G4-c | On attacks both detect, ML mean steps-before-harm ≥ rules + **0.5** step |

**Pass** = G4-a and (G4-b or G4-c). **Fail** = report it, ablate, and bring the PIVOT decision to you.

G4-b is partly true by construction (rules can't see in-scope misuse), so on its own it is weak evidence. That's why G4-a is mandatory and hard-benign overlap is required.

---

## 4. Order of work and checkpoints

1. R1-a world + policy v2 + tests → checkpoint (all old tests + v0 replay unchanged).
2. R1-b/R1-c generator, dev + test templates, freeze test hashes → checkpoint (you review sample trajectories and the frozen manifest).
3. R1-d features + leakage tests.
4. R1-e/R1-f detectors + runner, first full run → **G4 report** in `EXPERIMENTS.md`, then stop for your decision.

Every step ends with tests passing and `PROGRESS.md` updated.

## 5. Owners

M2: R1-a, R1-b, R1-c · M1: R1-d, R1-e · M4: R1-f, EXPERIMENTS.md · M3: policy v2 and schema review.

## 6. Risks

- **ML still fails.** Acceptable outcome; we report it and pivot with evidence.
- **Benchmark realism:** scripted templates, not live LLM agents. Live-agent trajectories come in R2 as a second generator with recorded seeds.
- **Schema change (`fs_list`):** additive; schema version stays 1 unless a field changes. The web app needs a small update in Phase W.
