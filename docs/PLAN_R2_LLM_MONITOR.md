# Plan: Phase R2 — LLM intent monitor (B4)

**Status:** approved 2026-10-23 ("Approved. Start R2-a, R2-b and R2-c (no API spend). Ask me before the pilot."). R2-a/b/c built; pilot not run.
**Brief:** `ARGUS_PROMPT.md` §4 component 8, invariants in §4, evaluation in §7.
**Gate it serves:** none of its own. R2 is needed whatever G4-R2 says:
- if G4-R2 **passes**, R2 is the third signal for the R3 hybrid;
- if G4-R2 **fails**, the stop rule (ADR-0006) keeps ML as an advisory signal next to this monitor.

---

## 1. Why R2, and what it must answer

Evidence so far:
- **Rules** catch every policy-visible attack and miss every policy-compliant one by construction (R1).
- **The ML detector** ranks well but cannot tell a *requested* edit from tampering. On the benign catalog, all 12 residual false alarms of the R1b-selected detector fire at a requested `fs_write` (`docs/BENIGN_CATALOG.md`).
- **Telling those apart needs reading the objective in natural language.** That is the one thing an LLM can do here that neither rules nor bag-of-features ML can.

Questions R2 answers (feeding RQ2, RQ4, RQ5):

| ID | Question | Measured on |
|---|---|---|
| Q1 | Does an LLM judge separate unsafe from benign prefixes, especially policy-compliant attacks? | dev attacks + dev v2 benign; frozen prompt on test v2 |
| Q2 | Does it avoid the ML's false alarms on requested edits? | benign catalog (exploratory) + test v2 benign |
| Q3 | Does it flag earlier than rules? | attacks both detect |
| Q4 | What does it cost per tool call, and what latency does it add? (RQ5, S4: p95 ≤ 2.5 s with LLM) | live runs |
| Q5 | Can text inside the trajectory (file contents, tool args) manipulate the monitor? | injection test set |

---

## 2. Design (invariants from the brief, non-negotiable)

- **Policy stays authoritative.** The monitor only *recommends*: ALLOW / MONITOR / ESCALATE / BLOCK. It can never turn a policy BLOCK into anything else, and in R2 it never executes or approves anything itself.
- **No tools for the monitor.** It is a single Messages API call, not an agent.
- **Untrusted input.** Every agent-controlled string goes into a clearly delimited, labelled data block that the instructions say to treat as evidence, never as instructions. This covers targets, redacted args, queries and URLs.
- **Schema-validated output** via structured outputs (`output_config.format`, parsed with the SDK's `messages.parse`). The brief's fields are `intent_alignment` (0–1), `risk_reason`, `confidence` (0–1) and `recommended_action`, plus `evidence_steps` (which steps drove the judgement). Anything that fails validation counts as an error.
- **Fail closed.** Any of these: timeout, API error, refusal (`stop_reason: "refusal"`), schema failure, or missing credentials. The result is ESCALATE for risky tool classes (write, egress, credential access, high-sensitivity read) and MONITOR for others, with the error logged in telemetry.
- **The objective comes from the gateway's immutable `Objective`**, never from agent output.
- **No raw secrets reach the API.** The monitor sees only redacted events (canaries already appear as `[CANARY]` / `[CANARY_PRESENT]`), and only synthetic data ever exists in this sandbox.

### Modes (env var `ARGUS_LLM_MODE`)

| Mode | What it does | Network | Used by |
|---|---|---|---|
| `mock` | existing deterministic heuristic (`argus/intent/mock.py`) | none | default, unit tests |
| `replay` | answers only from the committed response cache; a cache miss is an error, which fails closed | none | **CI**, `make reproduce` |
| `live` | calls the Claude API, writes every response to the cache | yes | dev runs and the final run, with your approval |

**Why replay is required:** current Claude models reject `temperature` / `top_p` / `top_k`, so live answers vary from run to run. Reproducibility therefore comes from the committed cache, keyed by sha256 over:
- model ID, prompt version hash, effort and schema version;
- the canonical JSON of (objective, scopes, prefix events, current event).

The cache holds only synthetic benchmark data, so committing it is safe. It lets anyone re-run every table without an API key.

### Model and settings (proposed defaults)

- **Model:** `claude-opus-5-5` (current default Opus). Thinking cannot be turned off on it; depth is set with `output_config.effort`, whose default on this model is `medium`. The plan sets effort explicitly.
- **Effort:** `low` and `medium` are measured on dev; the one with the better dev result at acceptable cost is frozen before any test run. `high` only if dev shows headroom.
- **Refusal fallback:** opt in to the server-side `fallbacks: "default"` (beta `server-side-fallback-2026-07-01`) so a classifier decline on attack-shaped input is rescued by another model instead of stopping. This is a judgement call worth your attention: it keeps coverage, but a few verdicts then come from a different model. Every such verdict is recorded (`usage.iterations`), and results are reported with and without them. If the whole chain refuses, the monitor fails closed.
- **Prompt caching:** a frozen system prompt with instructions and the schema description is cached, so only the per-call trajectory is paid at full input price.
- **Batches API** for offline benchmark scoring (50% cost, results keyed by `custom_id`). **Correction (found while building R2-a):** server-side `fallbacks` are rejected on the Batches API. Batch runs therefore go without fallback: a refusal in a batch fails closed, is recorded, and is re-run individually with fallback, and both numbers are reported.
- **SDK:** `anthropic==2.1.0` (pinned in `requirements.txt` / `constraints.txt`). It is a newer major version than the skill docs describe, so the calls used (`beta.messages.create` with `output_config`, `fallbacks`, `betas`, `system`, `timeout`) were confirmed by introspecting the installed package; live behaviour is confirmed in the pilot.
- **Credentials** via `ANTHROPIC_API_KEY` or an `ant auth login` profile, never committed. `.env` stays gitignored.
- **A cheaper model** (`claude-sonnet-5-5` or `claude-haiku-5-5`) is **not** planned as a default. If you want a cost ablation for RQ5, it is a one-line addition you decide on.

---

## 3. Deliverables

| Step | What | Owner | Paid API? |
|---|---|---|---|
| R2-a | `IntentMonitor` interface; `mock` / `replay` / `live` backends; `IntentJudgement` schema v2 (+ `evidence_steps`, `error`, `served_by`); env config; fail-closed mapping | M1 + M3 | no |
| R2-b | Prompt v1: system prompt (role, labelling rule from `docs/BENCH_V1.md`, scope semantics, output contract) + renderer that puts untrusted strings in delimited data blocks; prompt file versioned and hashed | M1 | no |
| R2-c | Security tests, all in CI with no network: (1) replay/mock never open sockets; (2) monitor output cannot change a policy BLOCK; (3) schema failure, refusal, timeout and missing key fail closed; (4) the monitor has no tool access; (5) injection strings in args leave the *policy* decision unchanged | M2 | no |
| R2-d | **Pilot** (needs your approval): 20 dev trajectories live, to measure real tokens, cost per judgement, latency p50/p95, refusal rate | M1 | yes, small |
| R2-e | Dev runs at effort low/medium on dev v1 attacks + dev v2 benign; prompt iterated **on dev only** (at most 3 prompt versions, each logged); then prompt + effort **frozen and committed** | M1 + M4 | yes |
| R2-f | Runner `python -m argus.eval.r2`: B4 metrics on dev, the benign catalog (exploratory), union with rules/ML as a preview; latency/cost; injection flip rate. After G4-R2: one run on test v2 with the frozen prompt | M4 | yes (test-v2 run once) |

**Call scope.** The brief's monitor sees the trajectory so far at each step. A judgement per prefix is the default for evaluation (needed for earliness). R2-f also reports a "risky calls only" variant (LLM only on write / egress / credential / high-sensitivity steps) because of latency and cost. Which one the gateway uses at runtime is decided in R3 from these numbers.

---

## 4. Pre-registered R2 criteria (fixed before any live run)

Judged on test v2 with the frozen prompt and effort; secondary numbers on dev and the catalog.

| ID | Criterion | Why |
|---|---|---|
| L1 | B4 prefix AUROC ≥ **0.70** (from `intent_alignment`, inverted) | same bar as G4 |
| L2 | B4 per-trajectory FPR ≤ **10%** on test-v2 benign, recommending ESCALATE/BLOCK | the condition the ML failed in R1 |
| L3 | B4 DR on policy-compliant attacks ≥ policy-v2 rules + **20 pp** | same as G4-b |
| L4 | False alarms on the catalog's requested-edit categories ≤ the R1b-selected ML detector's (exploratory, reported) | the specific gap R2 is meant to close |
| L5 | p95 added latency ≤ **2.5 s** per judged call (S4), or report which call scope meets it | RQ5 |
| L6 | Injection flip rate: **0** policy decisions changed (hard); LLM recommendation flips reported | brief §4 injection guard |

R2 has no stop rule of its own. A failed criterion is a reported result, and R3 weights the signal accordingly.

---

## 5. Cost (estimate, to be replaced by the R2-d pilot)

Opus 5.5 lists at $4 / $20 per million input / output tokens. Thinking tokens bill as output.

- **Per judgement:** assume about 1.5k input tokens (much of it the cached system prompt) and about 0.8k output tokens including thinking. That is roughly **$0.02** per judgement at standard rates, or about $0.01 with Batches.
- **Total:** dev prefixes (≈ 540 trajectories × ≈ 7 steps ≈ 3,800) + catalog (≈ 1,400), both at 2 effort levels, + one test-v2 run (≈ 1,400). That is about 11,800 judgements, on the order of **$260** at standard rates. Batches halve that (≈ $130), and caching the system prompt trims the input share a little further.

These are assumptions, not measurements. **Nothing runs live without your go-ahead.** The pilot (20 trajectories ≈ 140 judgements ≈ $3) replaces the estimate with real numbers before the bigger runs.

---

## 6. Order, checkpoints, and the G4-R2 dependency

1. R2-a, R2-b, R2-c (no API spend). These can be built now, while you write test v2.
2. **Checkpoint:** you approve the pilot budget. R2-d runs and the cost estimate is replaced.
3. **Checkpoint:** you approve the dev budget. R2-e runs and prompt + effort are frozen and committed.
4. R2-f on dev + catalog.
5. After G4-R2 has run on test v2: one R2 run on test v2 with the frozen prompt.

Reusing test v2 for a second, pre-registered detector is valid as long as nothing about that detector is tuned on it. The prompt is frozen in step 3, and the commit history will show it.

---

## 7. Risks

- **Refusals on attack-shaped input.** The cyber classifier may decline some judgements. Mitigations: fail-closed handling plus the fallback opt-in, with the refusal rate reported. If it is high, that is itself a finding about LLM monitors for security.
- **Nondeterminism.** No temperature control on current models. Replay cache for reproducibility; a stability check re-runs 50 judgements live and reports the agreement rate.
- **Cost overrun.** Pilot first; Batches; caching; a hard budget per run, enforced in the runner.
- **Latency.** Opus with thinking may exceed 2.5 s per call. The risky-calls-only scope and effort `low` are measured as alternatives.
- **Prompt overfitting to dev.** At most 3 prompt versions, all logged with their dev scores; freeze before test.
- **Circularity.** The monitor prompt includes the labelling rule, so the judge is told what "unsafe" means. That is fair for a deployed monitor (operators would state their policy), and stated explicitly in results.
