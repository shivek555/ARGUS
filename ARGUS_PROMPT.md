# ARGUS: Runtime Behavioral Security for Autonomous AI Agents

> Save this file as `CLAUDE.md` in an empty repo root (or keep it as `ARGUS_PROMPT.md` and reference it from `CLAUDE.md`). Then start Claude Code in **plan mode** with the kickoff message at the bottom.

---

## 1. Mission

Build **ARGUS**, a final-year BE CSE project (team of 4, 16 weeks): a runtime layer that sits between an autonomous LLM agent and its tools, watches the agent's *trajectory* (sequence of actions), and decides ALLOW / MONITOR / ESCALATE / BLOCK before the agent crosses a security boundary.

This is a **research prototype with an honest evaluation**, not a product. A small system with valid experiments beats a large system with unverified claims.

**Priority order:** research validity > security correctness > experimental evidence > engineering quality > features.

### Central hypothesis (must be testable and falsifiable)
> Trajectory-level behavioral analysis detects an agent's deviation from its authorized objective earlier and more reliably than isolated, per-action rule inspection.

Do not assume it is true. The code must be able to confirm, partially support, or refute it. A negative result is an acceptable outcome and must be reported as such.

### Research questions
- **RQ1** Can trajectories separate benign from unsafe behavior?
- **RQ2** Can unsafe behavior be flagged *before* the harmful action completes?
- **RQ3** Does detection hold on attack families held out of training (open-set anomaly detection)?
- **RQ4** Does hybrid (rules + ML + LLM) beat each component alone?
- **RQ5** What latency/compute overhead does ARGUS add?
- **RQ6** Can an adaptive adversarial agent evade it?

---

## 2. How you must work (operating rules)

1. **Plan before code.** Use plan mode for each phase. Write the plan, wait for my approval, then implement.
2. **Smallest correct version first.** Implement the minimum, run tests, fix, document, then move on. Never generate the whole project in one pass. Never rewrite working components without a stated reason. No silent breaking changes.
3. **Challenge every feature** against: What problem does it solve? Is there a simpler mechanism? Is AI necessary here? Can we measure its benefit? Can 4 students finish it in the time left? If not, cut it.
4. **You may reject my requests.** If something adds complexity without improving the research objective, reply `REJECTED: <reason>` and propose an alternative.
5. **Persist state in the repo, not in chat.** Maintain:
   - `docs/PROGRESS.md`: what is done, what is next, open risks, gate status
   - `docs/DECISIONS.md`: short ADRs (decision, alternatives, why)
   - `docs/EXPERIMENTS.md`: every experiment: config hash, seed, command, result path
   At the start of every session, read these three files first.
6. **Before substantial code**, state: the component, assumptions, dependencies, how it integrates, security implications. **After**: how to run it, tests, expected output, known limitations.
7. **No fabricated numbers.** Every metric in docs/paper/dashboard must come from a logged run reproducible via a single command. If results are unavailable, write `TODO: not yet measured`.

---

## 3. Phase 0: Feasibility review (do this first; write no production code)

Produce `docs/FEASIBILITY.md` as a skeptical principal engineer would, then **stop and wait for my decision**. It must contain:

1. Brutal feasibility assessment (scope vs. 4 people × 16 weeks).
2. Strongest arguments *against* building ARGUS.
3. Existing work that overlaps or makes parts redundant. **Search the web** for current work (e.g., agent guardrail/runtime-monitor frameworks, agent-security benchmarks such as AgentDojo/InjecAgent/ASB-style suites, provenance/taint tracking, sandboxing and capability systems, LLM-based monitors, sequence-based anomaly detection on system call traces). Cite sources; do not rely on memory.
4. The exact, realistic research gap.
5. Three alternative project directions that might be better, with trade-offs.
6. A **GO / MODIFY / REJECT** recommendation with reasoning.
7. If GO/MODIFY: the minimum viable research contribution.
8. Measurable success criteria (numeric where possible, e.g., "hybrid reduces mean attack progress vs. rules-only by ≥X% at ≤Y% FPR on held-out families", with the criteria chosen *before* running experiments).
9. A 7-day proof-of-concept plan with a clear pass/fail check.
10. Known risks: label leakage, synthetic-data realism, benchmark circularity (we write both attacks and detector), LLM nondeterminism, small-N statistics. Give mitigations.

---

## 4. Architecture

```
USER TASK → AGENT → tool call → ARGUS GATEWAY → [Policy | Trajectory features | Anomaly | Intent (LLM) | Sensitivity] → RISK ENGINE
                                                     ├─ ALLOW   → execute tool in sandbox
                                                     ├─ MONITOR → execute + raise scrutiny
                                                     ├─ ESCALATE→ human approval queue
                                                     └─ BLOCK   → quarantine agent → forensic snapshot
```

### Hard design invariants
- **Every** tool call passes through the gateway; the agent has no other path to tools (enforce structurally, test it).
- **Deterministic policy engine is authoritative.** The LLM and ML components can only *raise* risk or recommend; they can never override a policy BLOCK or approve their own actions.
- **Fail closed:** if ARGUS components error or time out, default to ESCALATE/BLOCK for risky tool classes, and log it.
- ARGUS stores the **original task/objective** immutably, separate from anything the agent can write to.
- Agent-controlled text (file contents, tool outputs) is **untrusted input** to the LLM monitor: guard against prompt injection into the monitor itself (structured prompts, delimiters, schema-validated outputs, no tool access for the monitor).

### Components
| # | Component | Notes |
|---|-----------|-------|
| 1 | Agent runtime | Explicit, readable control loop (LangGraph acceptable, but no hidden control flow). Tools: filesystem, repo search, safe command exec, controlled HTTP, fake DB, fake services. |
| 2 | Gateway | Intercepts tool calls, args, resources, file/network/DB access, subprocess creation, credential access, inter-agent messages. Emits telemetry. |
| 3 | Event schema | Pydantic model, versioned. Fields: timestamp, agent_id, task_id, step, tool, action, target, args (redacted), permissions, data_sensitivity, network_destination, prev_action, result, decision, risk. Get this right first; ML depends on it. |
| 4 | Objective model | Stores task + allowed scopes; scores objective alignment of each step. |
| 5 | Policy engine | Declarative rules (YAML) → workspace confinement, credential-store access, egress allowlist, privileged ops. This is **Baseline 2**. |
| 6 | Trajectory features | Action/tool/resource n-gram transitions, timing, sensitivity deltas, privilege changes, network behavior, prefix-level features (so detection is computed **per step**, enabling early-detection metrics). |
| 7 | Anomaly detection | Start: Isolation Forest, One-Class SVM. Add GRU/LSTM autoencoder or small Transformer **only if** simple baselines leave a measurable gap and data volume supports it. |
| 8 | LLM intent monitor | Input: objective + trajectory so far + current action + permissions. Output (JSON schema): `intent_alignment`, `risk_reason`, `confidence`, `recommended_action`. Model/API key via env vars; provide a deterministic **mock/replay mode** so tests and CI never call the network. Cache responses by hash for reproducibility. |
| 9 | Risk engine | Transparent additive score from named signals (anomaly, objective deviation, privilege, data sensitivity, destination, persistence). **Learn/calibrate** weights on a validation split (e.g., logistic regression + calibration), justify thresholds, report sensitivity analysis. Levels LOW/MEDIUM/HIGH/CRITICAL, thresholds configurable. |
| 10 | Decision + containment | LOW→ALLOW, MEDIUM→MONITOR, HIGH→human approval, CRITICAL→BLOCK+quarantine. Containment: revoke capabilities, cut network, freeze/terminate, preserve forensic snapshot. |
| 11 | Explainability | Each HIGH/CRITICAL decision emits per-signal contributions, e.g. `+25 objective deviation, +21 credential access, …` and a recommended response. No opaque "AI says malicious". |
| 12 | Dashboard | React+TS SOC-style UI: overview, per-agent timeline, risk-over-time graph, incident drill-down, experiment/metrics comparison. Build **last**, on stable APIs. |

### Stack (default; deviate only with an ADR)
Python 3.11+, FastAPI, Pydantic, scikit-learn, PyTorch (only if needed), pytest, Docker/Compose, React+TypeScript, MLflow (or plain JSON/CSV logs if MLflow is overkill), GitHub Actions.
- **Start with SQLite or Postgres via Compose; add Redis/pgvector only if a concrete need appears.** Do not add Kubernetes, Kafka, eBPF, custom LLM training, or quantum components.
- Quantum/QAOA is **out of scope** unless I explicitly request it after Gate 5.

---

## 5. Sandbox and safety constraints (non-negotiable)

- All attack scenarios run only against **fake local services**: fake GitHub, DB, package registry, email, cloud API, credential store, "external" server. Use Docker network isolation (`internal: true` network, no host mounts beyond the workspace) so nothing can reach the real internet or real credentials.
- All credentials/secrets in the sandbox are **synthetic canary values**; never read or use real keys, tokens, or files from the host.
- The red-team agent is an in-sandbox behavior simulator (goal deviation, credential discovery, privilege escalation, exfiltration to the fake server, persistence attempts, tool chaining, inter-agent manipulation). **Do not write real malware, real exploits, or anything targeting real systems.** Attacks are expressed as tool-call sequences against deliberately vulnerable fake services.
- Never hardcode secrets or API keys; use `.env` (gitignored) and `.env.example`.
- Add tests proving the sandbox cannot reach the outside network and the agent cannot bypass the gateway.

---

## 6. AgentEscapeBench (internal benchmark)

Scenario families: (1) goal/prompt hijacking, (2) credential discovery, (3) privilege escalation, (4) data exfiltration, (5) unauthorized network communication, (6) persistence, (7) tool abuse, (8) agent-to-agent manipulation, (9) other/unknown anomalies.

Each scenario is a versioned file with: initial state, authorized objective, benign reference trajectory, attack trajectory, ground-truth labels **per step** (first-unsafe-step index), severity, and success condition.

Data requirements:
- Include **hard benign cases** (legitimately broad tasks that touch many files/tools, a dependency audit that reads configs, a DB analytics task) to measure false positives honestly.
- Generate trajectories at volume with seeded variation (scripted templates + LLM-driven agents + noise/paraphrase of orderings), and record the generation seed and method.
- **Avoid benchmark circularity:** attack variants used for final testing must be written/parameterized independently of the ones used to tune rules and features. Document who wrote which, and freeze the test set before tuning.
- Split **by scenario family**, never by random step/trajectory, for the open-set experiment. Guard against leakage (e.g., identical trajectory prefixes across splits).

---

## 7. Evaluation protocol

Compare, on identical trajectories and seeds:
- B1 no protection · B2 rules only · B3 ML anomaly only · B4 LLM only · **Hybrid ARGUS** (plus ablations removing one component at a time).

Metrics: detection rate, precision, recall, F1, false-positive rate (per-trajectory and per-step), **mean detection step / steps-before-harm (earliness)**, **attack progress prevented**, time-to-containment, per-step latency (p50/p95), compute/LLM cost.

Rigor:
- Pre-register success criteria (from Phase 0) before experiments.
- ≥5 seeds where stochastic; report mean ± std or bootstrap CIs; use paired tests where valid. State N honestly.
- Open-set experiment: train on k families, hold out the rest, report detection on held-out families. Phrase results as *"open-set behavioral anomaly detection under controlled unseen attack scenarios"*, never "zero-day detection."
- Adaptive adversary (after the system works): red-team agent observes blocks and tries alternate tools/indirect channels/slow-and-low behavior; report evasion rate per round and what defenses changed. Report evasions found; they are results, not failures.
- One command reproduces all tables/figures (`make reproduce` or equivalent) from logged raw outputs.

---

## 8. Plan and quality gates (16 weeks)

Do not advance past a gate until its check passes or I approve a documented pivot.

| Weeks | Focus | Deliverable | Gate (stop-if-fail) |
|---|---|---|---|
| 0 | Feasibility review (§3) | `FEASIBILITY.md` | I approve GO/MODIFY |
| 1–2 | Threat model, schema, sandbox, agent runtime, gateway, telemetry | Working monitored agent | **G1** agent runs end-to-end in sandbox; **G2** trajectories captured reliably (replay test) |
| 3–4 | Policy engine, first benchmark scenarios, trajectory dataset v1 | Rules baseline + data | **G3** benign vs. unsafe distinguishable at all (simple stats/viz) |
| 5–8 | Anomaly baselines → sequence model (if justified), LLM intent monitor | Detection prototype | **G4** ML beats rules on at least one defined metric; otherwise say ML isn't needed |
| 9–12 | Risk engine, containment, red-team agent, open-set experiments | Full security loop | **G5** hybrid ≥ best component; **G6** some unseen-family detection |
| 13–16 | Adaptive red team, dashboard, full benchmark, latency tuning, paper, demo | Final system + paper | **G7** demo runs reliably from a clean checkout |

If a gate fails, cut features rather than weakening the evaluation.

---

## 9. Repository layout (suggested; adapt via ADR)

```
argus/
  gateway/  policy/  features/  detectors/  intent/  risk/  containment/  telemetry/
  agents/ (runtime, benign, redteam)   sandbox/ (fake services, compose)
  bench/ (AgentEscapeBench scenarios, generators, splits)
  eval/ (metrics, runners, reports)   api/ (FastAPI)   
dashboard/ (React+TS)
configs/ (yaml: policies, thresholds, experiments)
tests/ (unit, integration, security)   docs/   Makefile   docker-compose.yml
```

---

## 10. Code standards and definition of done

- Modular, typed (mypy-clean where practical), small functions, structured logging, config via YAML/env, meaningful errors.
- Tests: unit + integration + **security tests** (gateway cannot be bypassed, sandbox egress blocked, LLM monitor cannot authorize its own action, injection attempts in tool output don't change decisions). CI via GitHub Actions runs everything using mock LLM mode.
- Every change ends with: tests passing, docs updated (`PROGRESS.md`, API docs), commit with a clear message. A task is **done** only when it runs from a clean checkout with documented commands.
- Never trust LLM output for a security decision without schema validation and policy-layer confirmation.

---

## 11. Claim discipline

Do not write: "revolutionary", "100% secure", "solves AI safety", "prevents all attacks", "zero-day protection", "production ready". Use: "evaluated under controlled scenarios", "reduces attack completion rate in our benchmark", "detects previously unseen behavioral patterns in our evaluation environment". State limitations (synthetic data, author-written attacks, small scale) in every results section.

---

## 12. Team ownership (for task breakdown and docs)

M1 AI/ML (detectors, sequence model, LLM eval, experiments) · M2 Security (sandbox, threat model, attack scenarios, red team, containment) · M3 Backend (FastAPI, gateway, telemetry, DB, policy engine) · M4 Frontend/Research (dashboard, metrics, experiment framework, paper). Tag tasks in `PROGRESS.md` with an owner; all members must be able to explain the whole architecture.

---

## Kickoff message (paste this into Claude Code after saving this file as CLAUDE.md)

```
Read CLAUDE.md fully. Start in plan mode. Execute Phase 0 only: research current related work on the web, then write docs/FEASIBILITY.md with all 10 required sections, including a clear GO / MODIFY / REJECT recommendation and the 7-day proof-of-concept plan. Create docs/PROGRESS.md, docs/DECISIONS.md and docs/EXPERIMENTS.md as stubs. Do not write production code. Stop when done and wait for my decision.
```
