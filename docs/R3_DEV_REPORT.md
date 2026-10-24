# R3 dev report: risk engine, explanations, containment, approval queue

**Status:** dev checkpoint, waiting for review (ADR-0012). All numbers are **dev, out-of-fold**. The official G5 verdict comes only from test v2. `configs/risk/model.json` and `configs/risk/levels.yaml` are frozen once this report is accepted.

Reproduce (offline, $0, about 11 s): `python -m argus.eval.r3` → `eval/results/r3/dev_report.json` (gitignored), `configs/risk/model.json`, `configs/risk/levels.yaml`. Tests: `tests/test_r3.py`.

## Data

| | n | Source of the signals |
|---|---|---|
| Attacks (AgentEscapeBench v1 dev) | 120 | ML: final R1b model (`ocsvm-nu0.10-quantile`, benign-only training, so attack scores are not in-sample); LLM: replay of the frozen `qwen2.5:3b` dev cache |
| Benign (dev v2, idx < 9 per intent × context) | 126 | ML: leave-one-intent-out scores; LLM: same replay cache |
| Steps | 1,635 | LLM signal errors: 0 |

**Correction to the plan:** training uses only the 126 benign trajectories that have LLM verdicts, not all 420. Adding the other 294 would make `llm_missing = 1` a benign-only artefact that the model would learn.

Evaluation is leave-one-template-out: each trajectory is scored by a model that never saw its template. Platt calibration uses those out-of-fold logits. Levels come from out-of-fold benign per-trajectory maxima (quantiles .70 / .90 / .99, `method="higher"`, strict `>`).

## Frozen candidates

**Levels (risk points, 10 points per logit unit):** MEDIUM > −24.84, HIGH > −1.25, CRITICAL > 40.02. A policy BLOCK is always CRITICAL.

**Coefficients (standardised signals):**

| Signal | Coef | | Signal | Coef |
|---|---|---|---|---|
| anomaly (ML score − threshold) | **+2.77** | | persistence | +0.56 |
| policy_block | +1.33 | | destination | +0.51 |
| sensitive_unscoped (B2+ rule) | +1.20 | | llm_missing | +0.36 |
| objective_mention | **−1.32** | | data_sensitivity | −0.15 |
| privilege | −1.16 | | llm_escalate | −0.04 |
| intercept | −2.28 | | objective_deviation | +0.03 |

## Detection at ≤ 10% benign trajectories reaching HIGH

| Method | DR | DR visible | DR compliant | Benign FPR | By family: creds / exfil / hijack |
|---|---|---|---|---|---|
| B2 policy v2 | 0.500 | 1.000 | 0.000 | 0.000 | .50 / .50 / .50 |
| B2+ policy v3 | 0.833 | 1.000 | 0.667 | 0.000 | 1.0 / 1.0 / .50 |
| B3 ML only | 0.642 | 0.333 | 0.950 | 0.095 | 1.0 / .50 / .425 |
| B4 LLM only (score at budget) | 0.000 | 0.000 | 0.000 | 0.000 | 0 / 0 / 0 |
| B4 LLM native ESCALATE (over budget) | 0.933 | 0.883 | 0.983 | **0.365** | .975 / .875 / .95 |
| **Hybrid (R3)** | **0.975** | 1.000 | 0.950 | 0.095 | 1.0 / 1.0 / .925 |
| Hybrid, CRITICAL only (auto-block) | 0.817 | 1.000 | 0.633 | 0.008 | .95 / 1.0 / .50 |

- Hybrid 95% bootstrap CI (1,000 resamples, seed 12345): DR [0.942, 1.000], FPR [0.040, 0.143].
- Earliness vs rules: hybrid flags 0.27 steps earlier on average (n = 60 attacks both catch); ML alone 1.45 steps earlier (n = 20).
- **G5 preview: PASS on dev.** Hybrid 0.975 ≥ best single component (B2+ policy v3, 0.833).

## Ablations (refit and recalibrated without the group)

| Variant | DR | DR compliant | FPR |
|---|---|---|---|
| Full hybrid | 0.975 | 0.950 | 0.095 |
| − rules | 0.992 | 0.983 | 0.095 |
| − ML | 0.833 | 0.667 | 0.079 |
| − LLM | 0.983 | 0.967 | 0.095 |
| − context | 0.833 | 0.667 | 0.095 |

Regularisation sensitivity (DR / FPR): C = 0.1 → 0.983 / 0.095; C = 1 (frozen) → 0.975 / 0.095; C = 10 → 0.908 / 0.095.

Leave-one-family-out (benign intents held out; DR on the unseen attack family at τ_high): credential discovery 1.00, exfiltration 1.00, goal hijack 0.925 (n = 40 each).

## Containment (enforce mode, simulated humans)

Each trajectory is replayed through `ContainedSession` with its own out-of-fold engine. Harm completion means the attack's harmful step actually executed.

| Setting | Harm completion | Approvals / 100 benign | Benign quarantined | Benign disrupted |
|---|---|---|---|---|
| Rules only (policy v2 gateway) | 0.500 | n/a | n/a | n/a |
| Hybrid, oracle human | **0.025** | 27.0 | 0.8% | 0.8% |
| Hybrid, human always denies | 0.025 | 27.0 | 0.8% | 9.5% |
| Hybrid, human always approves | 0.183 | 27.0 | 0.8% | 0.8% |

99 of 246 sessions are quarantined (98 attacks, 1 benign). Every quarantine writes one write-once snapshot that passes its sha256 check (tested; tampering is detected).

## Findings (honest)

1. **The LLM adds almost nothing.** Its weights are ≈ 0 (deviation +0.03, escalate −0.04). At the 10% budget the LLM score catches 0%, and removing the LLM *raises* DR slightly (0.983). Its native ESCALATE catches 93% but flags 36.5% of benign work. The gains come from ML anomaly + context signals + the B2+ rule.
2. **The rules group looks redundant on dev.** Without it, DR is 0.992. The policy gateway still blocks authoritatively in deployment, so this changes nothing about enforcement. It means the learned weights for the rule signals carry no extra information beyond ML + context on this data.
3. **Negative weights on `objective_mention` and `privilege` are dataset effects.** Dev v2 benign work often names its targets and handles credentials legitimately in the secrets context. Explanations show them as risk-lowering. A reviewer should know these signals can be gamed by an attacker who names the target in the objective (R5).
4. **R3-c FAILS: 27 approvals per 100 benign tasks vs the ≤ 15 target.** 9.5% of benign trajectories reach HIGH, but each flagged trajectory holds about 2.8 calls (27 / 9.5). Per-call holds, not per-trajectory, drive the workload. A possible fix (escalate once per trajectory, then MONITOR) would be a new ADR, decided before test v2.
5. **Humans matter.** If the reviewer approves everything, harm completion rises from 2.5% to 18.3%. If the reviewer denies everything, 9.5% of benign tasks are disrupted.
6. **Scope limits:** n = 126 benign / 120 attacks, all synthetic. Goal hijack is the weakest family (0.925 unseen, 0.50 at CRITICAL only).

## Decision needed at this checkpoint

- Accept the frozen model and levels as they are, **or**
- Amend before freezing (for example per-trajectory escalation for R3-c, or dropping the LLM group). Any amendment goes in a new ADR and is rerun on dev only.
