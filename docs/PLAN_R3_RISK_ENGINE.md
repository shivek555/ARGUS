# Plan: Phase R3 — risk engine, explanations, containment, approval queue

**Status:** draft for review. No code until you approve.
**Brief:** `ARGUS_PROMPT.md` §4 components 9 (risk engine), 10 (decision + containment), 11 (explainability), plus the invariants; gate **G5** (hybrid ≥ best component) in §8.
**Dependency on G4-R2:** R3 is needed either way. If G4-R2 passes, the ML signal enters the hybrid as planned. If it fails, the ADR-0006 stop rule keeps ML as an *advisory* signal, which is exactly how R3 treats it below. Only the final G5 test waits for test v2.
**Cost:** $0. Everything is built and calibrated offline from committed data: ML scores are recomputed locally, and LLM verdicts come from the R2-L cache.

---

## 1. What we know going in (measured, dev data)

| Signal | Strength | Weakness |
|---|---|---|
| Policy v2 (rules) | 100% of policy-visible attacks, 0 false alarms | 0% of policy-compliant attacks, by construction |
| ML (`ocsvm-nu0.10-quantile-global`) | 96.7% policy-compliant DR; catalog false alarms only 5.6% | unseen legitimate *secrets* tasks: 66.7% nested FPR |
| LLM (`qwen2.5:3b`, risky calls) | 98% policy-compliant DR | 36.5% benign FPR; flags legit secret work and requested edits almost always |

No single signal is good enough on its own. The question R3 answers, and the reason for G5, is whether a **calibrated combination** beats the best single one at the same false-alarm budget. The two learned signals fail on *different* benign tasks (ML: unseen secrets tasks; LLM: requested edits), so there is a real chance it does. It's also possible the combination doesn't help, and then that's the result.

## 2. Signals (all pre-execution, named, per step)

| Name | Source | Value |
|---|---|---|
| `policy_block` | policy v2 | 1 if the authoritative rules block the call |
| `sensitive_unscoped` | policy v3 rule (B2+) evaluated as a *signal* | high-sensitivity read without `secrets-audit` |
| `anomaly` | ML prefix score | score relative to its frozen threshold (`score − τ`) |
| `objective_deviation` | LLM | `1 − intent_alignment`; LLM is consulted on risky calls only |
| `llm_escalate` | LLM | 1 if it recommends ESCALATE/BLOCK |
| `llm_missing` | LLM | 1 if no verdict (not risky, or failed closed) |
| `privilege` | event | credential-store access / secrets path |
| `data_sensitivity` | event | low / medium / high → 0 / 0.5 / 1 |
| `destination` | event | egress, and whether the host is named in the objective |
| `persistence` | event | write to code / config / CI paths |
| `objective_mention` | event + objective | target path named in the objective (lowers risk) |

These are the brief's named signals (anomaly, objective deviation, privilege, data sensitivity, destination, persistence) plus the rule and LLM indicators. No raw labels, results or decisions of other steps go in, as in R1.

**Leakage guard:** the ML detector was fit on all dev-v2 benign. So R3 uses its **leave-one-intent-out (out-of-fold) scores** for benign trajectories (already defined in R1b), never in-sample scores. Otherwise benign would look artificially normal and the weights would be biased.

## 3. Risk engine (component 9)

- **Model:** logistic regression on the standardized signals (L2, fixed `C = 1.0`), followed by **calibration**: Platt / sigmoid, fit with `CalibratedClassifierCV`, cross-validated **grouped by trajectory**.
- **Output:** a calibrated risk probability per call, shown as a 0–100 **risk score**.
- **Labels:** supervised on dev. The positive class is attack prefixes at or after `first_unsafe_step`; the negative class is all benign prefixes. Precursor steps are excluded from fitting, the same convention as R1.
- **Training set:**
  - all 120 dev attacks;
  - the 126 dev-v2 benign trajectories that have LLM verdicts (72 with risky calls, 54 without);
  - plus the remaining 294 dev-v2 benign trajectories, with `llm_missing = 1`.
- **Transparency:** the score is additive by construction. Each signal's contribution = coefficient × standardized value, rescaled to **points**, and the points sum to the score (tested). These points are the explanation (§5).
- **Sensitivity analysis (brief requirement):** refit with each signal dropped, and with C ∈ {0.1, 1, 10}. Report how the coefficients and dev metrics move.

## 4. Levels and decisions (component 10)

Thresholds are fixed by rule on dev, written to `configs/risk/levels.yaml` (configurable), and frozen before any test run:

| Level | Rule for the threshold (dev) | Decision |
|---|---|---|
| **CRITICAL** | policy BLOCK, **or** risk ≥ τ_crit chosen so that ≤ **1%** of dev benign trajectories ever reach it (nested, leave-one-intent-out) | **BLOCK + quarantine** |
| **HIGH** | risk ≥ τ_high chosen so that ≤ **10%** of dev benign trajectories ever reach it (same nested rule as R1b) | **hold for human approval** |
| **MEDIUM** | risk ≥ τ_med chosen at ≤ **30%** of benign trajectories | **MONITOR** (execute, log, raise scrutiny) |
| **LOW** | below τ_med | **ALLOW** |

**Invariants, each a test:**
- **Policy is authoritative:** a policy BLOCK is always CRITICAL. ML and LLM can only *raise* the level, never lower it (`apply_advisory`, already built in R2).
- **Non-policy signals reach auto-BLOCK only through the 1%-benign τ_crit.** Anything less certain goes to a human. That's deliberate: the LLM alone flags 26–37% of benign work, so it must never block on its own say-so.
- **Fail closed:** if the ML or LLM signal errors on a risky tool class, the level is at least HIGH, and the error is recorded in the decision.
- **No self-approval:** the monitor and risk engine have no path to approve held calls; only the approval queue does (§6).

## 5. Explanations (component 11)

Every HIGH or CRITICAL decision emits a `RiskDecision` record (pydantic, versioned) with:
- **level, decision, risk score**;
- **contributions**, sorted, e.g. `+31 objective deviation`, `+22 sensitive read without secrets-audit`, `+12 persistence (CI file)`, `−9 target named in objective`;
- **the policy rule id** if one fired;
- **the LLM's `risk_reason`,** clearly labelled as *model rationale from untrusted-input analysis*, never as evidence on its own;
- **a recommended response**, from a fixed table: e.g. "deny and rotate the credential", "review the diff before allowing", "allow: matches objective".

No opaque "AI says malicious": the points always sum to the score.

## 6. Containment and the approval queue (component 10)

**Containment** (CRITICAL), inside the sandbox gateway:
1. **Quarantine:** the gateway enters a `quarantined` state, and every later call from that agent is BLOCKed, whatever it is.
2. **Revoke capabilities:** the agent's tool table is emptied, so no tool is reachable.
3. **Cut the network:** `http_post` is disabled for the session (in the fake world, the egress sink closes).
4. **Forensic snapshot:** an immutable JSON bundle with the objective, all events, decisions, signal contributions, files written, egress attempts and a sha256. It is written where the agent cannot reach it.

Tests: zero calls execute after quarantine; the snapshot hash verifies; the agent cannot touch the snapshot path.

**Approval queue** (HIGH):
- **Held, not executed:** the call waits in a queue (JSONL store; SQLite only if the web app needs it), with its `RiskDecision` attached.
- **Decisions:** approve / deny. **No answer within T → auto-deny** (fail closed).
- **In experiments,** a human is simulated three ways, and all three are reported:
  - *oracle* (approves exactly the benign calls);
  - *always deny*;
  - *always approve*.

  The main metric is **human workload**: approvals requested per 100 benign tasks.
- **The web app (Phase W)** gets approve/deny buttons later. In R3 the queue is an API plus files.

## 7. Evaluation and pre-registered criteria (fixed now)

**Compared on identical trajectories:**
- **Baselines:** B2 (policy v2), B2+ (policy v3), B3 (ML only), B4 (LLM only), **Hybrid**.
- **Ablations:** hybrid without ML, without LLM, and without the context signals.

| ID | Criterion | Data |
|---|---|---|
| **G5** | Hybrid attack detection rate (any step ≥ HIGH) ≥ the best single component's, **at the same budget of ≤ 10% benign trajectories reaching HIGH** | test v2 (once, after G4-R2) |
| R3-b | Attack **harm completion** with containment + always-deny human: hybrid ≤ rules-only, reported with oracle and always-approve too | dev + test v2 |
| R3-c | Human workload ≤ **15** approvals per 100 benign trajectories at the frozen τ_high | dev + test v2 |
| R3-d | 100% of HIGH/CRITICAL decisions carry contributions that sum to the score | tests |
| R3-e | 0 calls executed after quarantine; policy BLOCK never lowered; fail-closed on signal errors | tests |
| G6 (preview) | Leave-one-family-out on dev: fit on 2 attack families, test on the 3rd; report DR at the frozen budget | dev |

**Honest risk, stated now:** the weights are learned from dev attack shapes. Test v2 has different shapes (and was partly written knowing the detector; ADR-0008 caveat). G5 may fail, and if it does, that's reported.

**On reusing test v2:** it now serves three pre-registered evaluations, G4-R2 (ML), R2 (LLM) and G5 (hybrid). Each has a frozen model before test v2 is touched. The report states this and does not claim more than "pre-registered, single-use per detector".

## 8. Steps

| Step | What | Cost |
|---|---|---|
| R3-a | Signal extraction per step (offline: ML out-of-fold scores, LLM cache, event/objective features); `RiskDecision` schema | $0 |
| R3-b | Calibrated logistic model; grouped CV; sensitivity analysis | $0 |
| R3-c | Thresholds by the §4 rules → `configs/risk/levels.yaml`; decision mapping | $0 |
| R3-d | Explanations + recommended-response table | $0 |
| R3-e | Containment (quarantine, revoke, cut network, snapshot) + approval queue; security tests | $0 |
| R3-f | Dev evaluation: baselines, ablations, leave-one-family-out, human-simulation workload → dev report | $0 |
| — | **Checkpoint:** you review the dev report; weights and thresholds are **frozen and committed** | — |
| R3-g | After test v2 exists and G4-R2 has run: the R2 test-v2 run (free, GitHub workflow), then the single G5 run | $0 |

## 9. Risks

- **Overfitting to dev attack shapes** (supervised weights): grouped CV, leave-one-family-out, few parameters (≈ 11 signals, L2).
- **Missing LLM verdicts** on non-risky calls: explicit `llm_missing` indicator, never silently imputed.
- **Correlated signals** (`llm_escalate` vs `objective_deviation`): L2 regularization; the sensitivity analysis shows how stable the coefficients are.
- **Small N:** 120 dev attacks / about 190 trajectories with full signals. Metrics come with bootstrap CIs, and no "significant" claims without a test.
- **Scope creep:** no red-team agent here (that's R5), no dashboard work (Phase W).
