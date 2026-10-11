# ARGUS Phase 0: Feasibility Review

**Date:** 2026-10-05  
**Status:** **MODIFY accepted** (2026-10-06)  
**Scope of this document:** skeptical review. Implementation follows §6–§9, not the full 12-component brief.

This review treats ARGUS as a 16-week BE CSE research prototype for four students, not as a product pitch. Priority order from the brief is respected: research validity > security correctness > experimental evidence > engineering quality > features.

---

## 1. Brutal feasibility assessment (4 people × 16 weeks)

The brief specifies **12 components**, an internal 9-family benchmark with per-step labels, six RQs (including open-set detection and an adaptive adversary), a hybrid detector, containment, a React+TS SOC dashboard, Docker isolation, CI, and a paper. That is a small research lab’s year, not a BE capstone.

A realistic capacity estimate (after classes, exams, integration tax, and a ~30% slip buffer):

| Workstream | Honest fit in 16 weeks |
|---|---|
| Threat model, event schema, gateway, scripted agent, fake services | Yes (weeks 1–3) |
| YAML policy baseline + 2–3 scenario families with per-step labels | Yes (weeks 3–5) |
| Isolation Forest / One-Class SVM on prefix features + eval harness | Yes (weeks 5–8) |
| LLM monitor in **mock/replay** mode + one live API path | Tight but yes |
| Calibrated additive risk + ablations B1–B5 | Yes if dashboard is last |
| Open-set split + one adaptive-evasion round | Tight; do only after G4 |
| React SOC dashboard, MLflow, Postgres, Redis/pgvector, sequence Transformer | **No**, unless something else is cut |
| Nine attack families at publication quality, live LLM red-team at volume | **No** |

**What will actually happen if you implement the brief as written:** weeks 1–8 disappear into scaffolding (Compose, FastAPI, dashboard, fake GitHub, fake DB). Experiments start late, N stays small, and the paper becomes a system description with `TODO: not yet measured`.

**What can finish:** a *narrow* runtime gate, a *small* labeled trajectory corpus, and a *pre-registered* comparison of rules vs trajectory ML vs LLM vs hybrid, with earliness and open-set reported honestly.

Team split (M1–M4) is workable **only if** M4’s dashboard is delayed until APIs freeze, and M2 does not write nine families of original attacks.

---

## 2. Strongest arguments against building ARGUS

1. **The product-shaped architecture is not the research contribution.** Gateway + ALLOW/MONITOR/ESCALATE/BLOCK is now a standard pattern (OpenAI Agents SDK tool guardrails, AgentSpec, Progent, LlamaFirewall, NVIDIA OpenShell). Building another one does not create a thesis.

2. **The central hypothesis may already be the default LLM-monitor design.** LlamaFirewall AlignmentCheck and InferAct already reason over traces / trajectories vs the user objective. If “trajectory beats per-action rules” is shown only against a weak YAML baseline that you wrote, reviewers will call it a straw man.

3. **Benchmark circularity is structural.** The same team writing fake services, attack scripts, features, and rules will overfit. AgentDojo / ASB / InjecAgent exist so you *don’t* invent AgentEscapeBench from scratch. A private 9-family suite looks like busywork unless it adds something those suites lack (per-step first-unsafe-step labels and prefix-level scoring).

4. **Hybrid systems are easy to claim and hard to evaluate.** Without frozen test sets, calibrated FPR, and component ablations on identical trajectories, “hybrid wins” is an engineering anecdote. Four students rarely have the discipline to pre-register and not peek.

5. **LLM-in-the-loop destroys reproducibility and budget.** Nondeterminism, cost, and prompt-injection into the *monitor* (which the brief correctly flags) can dominate the project. If the LLM is required for the headline result, one API outage or one prompt tweak can invalidate tables.

6. **Safety theater vs OS isolation.** NVIDIA OpenShell / IsolateGPT-style process, filesystem, and egress policy already *prevents* many of the harms ARGUS wants to *detect*. Detection of sandbox-internal fake attacks is a weaker claim than “we contain real agents.”

7. **Open-set / “unseen family” language is easy to overclaim.** Holding out one of nine families you designed is not zero-day detection. The brief forbids that wording; reviewers will still ask why the held-out family shares tools, prefixes, and authors with the train set.

8. **Opportunity cost.** A cleaner project would take CaMeL or LlamaFirewall, add per-step earliness metrics, and run AgentDojo. That is more publishable than a greenfield SOC clone.

---

## 3. Existing work (searched, not recalled)

Sources accessed 2026-10-05. This is not a complete literature review; it is enough to locate ARGUS relative to 2024–2025 systems.

### 3.1 Runtime intercept / policy enforcement

| Work | What it already does | Overlap with ARGUS |
|---|---|---|
| [AgentSpec](https://arxiv.org/abs/2503.18666) (Wang, Poskitt, Sun, 2025) | DSL: trigger + predicate + enforcement; hooks LangChain before action execution; stop / user inspection / corrective action / LLM self-examine | Gateway + policy + ESCALATE/BLOCK |
| [Progent](https://arxiv.org/abs/2504.11703) | Least-privilege policies over tool names/args; SMT comparison so LLM-proposed policy *expansions* cannot sneak through | Deterministic policy is authoritative |
| [OpenAI Agents SDK guardrails](https://openai.github.io/openai-agents-js/guides/guardrails/) | Input / output / **tool** guardrails; allow / reject / tripwire before tool exec | Structural intercept |
| [NVIDIA NeMo Guardrails](https://docs.nvidia.com/nemo/guardrails/integration-with-third-party-libraries/langchain/agent-middleware) | Agent middleware before/after model calls | **Documented gap:** default rails inspect message `content`, not `tool_calls` args; tool *results* bypass input rails |
| [LlamaFirewall](https://arxiv.org/abs/2505.03574) (Meta, 2025) | Production-oriented scanners: PromptGuard 2, AlignmentCheck (CoT/goal auditor), CodeShield | LLM intent monitor + layered defense |
| [GuardAgent](https://arxiv.org/abs/2406.09187) / [PMLR](https://proceedings.mlr.press/v267/xiang25a.html) | Guardrail *agent* compiles safety requests to executable code | LLM monitor, but code-exec rather than risk score |
| AgentGuard (e.g. [WhitzardAgent/AgentGuard](https://github.com/WhitzardAgent/AgentGuard), [hidearmoon/agentguard](https://github.com/hidearmoon/agentguard)) | Before/after tool hooks, risk scores, audit traces | Entire gateway narrative |

### 3.2 Isolation, capabilities, taint / IFC

| Work | What it already does | Overlap |
|---|---|---|
| [IsolateGPT](https://arxiv.org/html/2403.04960v2) | Hub-and-spoke execution isolation; per-app sandboxes | Sandbox / inter-agent channel |
| [CaMeL](https://arxiv.org/abs/2503.18813) ([code](https://github.com/google-research/camel-prompt-injection)) | Dual-LLM; capabilities on values; custom interpreter; **77% tasks with provable security vs 84% undefended on AgentDojo** | Stronger *guarantee* story than ARGUS detection |
| [NVIDIA OpenShell](https://docs.nvidia.com/openshell/about/overview) / [Sentry](https://nvidianews.nvidia.com/news/open-agent-safety-platform) | YAML policy: FS, process, network, credentials; supervisor is the local security boundary | Sandbox + fail-closed containment |

### 3.3 Trajectory / intent monitors (closest scientific cousins)

| Work | What it already does | Overlap |
|---|---|---|
| LlamaFirewall **AlignmentCheck** | Few-shot CoT auditor over reasoning/trace vs user goal; AgentDojo combined PG+AC: ASR 17.6% → 1.75%, utility 47.7% → 42.7% | RQ1/RQ2 LLM branch |
| [InferAct](https://aclanthology.org/2025.emnlp-main.12/) (Fang, Zhu, Gurevych, EMNLP 2025) | Infer intent from **action trajectory**, compare to user instruction; trigger before *critical* actions; up to ~20% Macro-F1 | Central hypothesis, LLM-only |
| [STeCa](https://aclanthology.org/2025.findings-acl.604.pdf) | Step-level deviation via MC step rewards (learning, not security) | Prefix/step scoring idea |
| [BRT-Align](https://arxiv.org/abs/2509.21528) | Early unsafe-completion forecast in latent space (token-level, not tools) | Earliness as a metric, different layer |

### 3.4 Sequence anomaly detection (classic HIDS, not agents)

Isolation Forest and One-Class SVM on syscall / window features are standard HIDS tools, including recent container work ([graph + Isolation Forest](https://arxiv.org/html/2306.14750); [CWE-level OC-SVM / IF](https://arxiv.org/html/2606.22581)). LSTM/autoencoders on syscall sequences are also well studied. **Applying them to agent tool-call n-grams is transfer, not a new algorithm.**

### 3.5 Benchmarks you would be compared against

| Benchmark | Focus | Why it matters |
|---|---|---|
| [AgentDojo](https://arxiv.org/abs/2406.13352) (NeurIPS 2024) | Dynamic multi-tool tasks; 97 tasks / 629 security cases; prompt injection in tool outputs | Default external testbed |
| [InjecAgent](https://arxiv.org/abs/2403.02691) (ACL 2024) | Indirect injection, mostly single-turn tool output | Too narrow to be ARGUS’s only bench |
| [ASB](https://luckfort.github.io/ASBench/) (ICLR 2025) | 10 scenarios, 400+ tools, DPI/IPI/memory/PoT/mixed; high ASR, weak defenses | Broader attack taxonomy |
| [AgentHarm](https://arxiv.org/abs/2410.09024) (ICLR 2025) | Explicitly malicious multi-step *user* requests | Different threat model (malicious user vs hijacked agent) |
| ToolEmu | LLM-simulated tools | Circular if the same LLM judges attacks |

**Implication:** AgentEscapeBench should not try to replace these. If it exists, it should exist *only* to add **per-step first-unsafe-step labels** and **hard benign** trajectories that public suites do not provide cleanly.

---

## 4. The exact, realistic research gap

Strip marketing. The remaining gap is **narrow and measurable**:

> Public agent defenses are mostly (a) per-action policies / capabilities, (b) prompt-injection classifiers, or (c) LLM judges over the current step or CoT. Public agent *benchmarks* mostly score **task success vs attack success**, not **which prefix first became unsafe**. Classic HIDS sequence models were not evaluated on agent tool-call vocabularies with open-set family splits.

ARGUS is justified **only** if it treats that as the contribution:

1. A versioned event schema and prefix-level feature vector for tool-call trajectories.
2. Per-step ground truth (first-unsafe-step index) so **earliness** is a first-class metric.
3. A comparison, on identical frozen trajectories: rules-only vs unsupervised trajectory anomaly vs LLM-intent vs hybrid, with the LLM **unable to override policy BLOCK**.
4. An open-set protocol: train/tune on some families, test on held-out families, phrased as *open-set behavioral anomaly detection under controlled unseen attack scenarios*.
5. Honest negative result allowed.

It is **not** a gap to “build a SOC for agents,” “prevent all attacks,” or “replace OpenShell.”

If the 7-day PoC cannot show *any* prefix-level separation of hard-benign vs attack (simple stats), the gap is not exploitable by this team and the project should pivot (see §5).

---

## 5. Three alternative directions that might be better

### Alt A — Evaluate existing defenses with a better metric (lowest risk)

**Do:** Fork AgentDojo (and optionally LlamaFirewall / CaMeL). Add first-unsafe-step labels to a subset. Report earliness, FPR on hard benign, and open-set family holdout. Maybe add Isolation Forest on logged traces as *one* extra baseline.

**Trade-off:** Less “we built a system” demo; more paper-shaped; depends on labeling effort and AgentDojo’s environment. Stronger external validity.

### Alt B — Policy + IFC, not ML (stronger security story)

**Do:** Implement a CaMeL/Progent-style capability or taint policy for a coding/tool agent in a fake sandbox. Prove (or test) that exfil/egress cannot happen even under injection.

**Trade-off:** Better engineering/security thesis, weaker ML story. The central *detection* hypothesis is abandoned. Examiners who wanted “AI/ML project” may be unhappy; examiners who wanted security may prefer this.

### Alt C — Monitor robustness (attack the defender)

**Do:** Study prompt injection *into LLM monitors* (AlignmentCheck/InferAct-style). Measure how tool-output delimiters, schema validation, and “no tools for the monitor” change evasion. Small system, sharp RQ.

**Trade-off:** Very timely; smaller code; may look like a paper replication plus one attack family. Less dashboard, less “full ARGUS.”

**Relative to original ARGUS:** A is the most publishable; B is the most correct-as-security; C is the most original-if-you-can-land-an-attack. Original ARGUS is a union of A+B+C plus a UI, which is why it does not fit 16 weeks.

---

## 6. Recommendation: **MODIFY** (not GO, not REJECT)

**REJECT** would be appropriate if the team insists on: React SOC, nine families, GRU/Transformer, live adaptive multi-agent red team, and “production-like” Compose/MLflow all as must-haves. That will not yield a valid experiment.

**GO as written** would commit you to a system that existing papers and open-source already sketch, with high risk of an empty eval.

**MODIFY** means: keep the hypothesis and evaluation protocol; cut the product.

Reasoning:

- The hypothesis is **falsifiable** and not fully settled: InferAct/AlignmentCheck are LLM judges; they do not answer whether *cheap sequence features* detect earlier than rules, or whether hybrid beats each part on **held-out families**.
- NeMo’s documented failure to inspect tool-call arguments is a real operational hole; a mandatory gateway that sees `tool`, `args` (redacted), `target`, and prefix features is a legitimate *experimental platform*, not a novel product.
- CaMeL already offers stronger *guarantees* on AgentDojo. ARGUS must not claim to beat information-flow enforcement; it claims to *detect behavioral deviation* when policy cannot encode the whole task.

Conditions of MODIFY (non-negotiable):

1. Dashboard is week 15–16 or Streamlit; not on the critical path.
2. No PyTorch sequence model unless Isolation Forest / OC-SVM leave a **measured** gap after G4.
3. AgentEscapeBench v1 = **3 families** (hijack, credential discovery, exfil) + **2 hard benign** templates. Other families are optional stretch.
4. Primary agent for experiments is **scripted / replayable**; live LLM agents are a secondary generator with recorded seeds.
5. External comparison: at least report against a reimplemented **rules** baseline and an **LLM-judge** baseline in the *same* harness (AlignmentCheck-style prompt, mockable). Optional: run AgentDojo *offline traces* if time.
6. Policy remains fail-closed and authoritative. LLM/ML never override BLOCK.

---

## 7. Minimum viable research contribution (if MODIFY)

A paper-shaped artifact with this claim language (and no stronger):

> We evaluate a runtime tool-call gateway that scores **prefixes** of agent trajectories using a deterministic policy engine, unsupervised sequence features, and an optional schema-constrained LLM judge. Under a small, frozen, author-written benchmark with **per-step** labels, we measure whether hybrid scoring detects unsafe continuations **earlier** than rules-only, and whether detection **transfers** to attack families held out of tuning. Limitations: synthetic tools, author-written attacks, small N.

Deliverables that define “contribution exists”:

- Immutable objective store + single tool gateway (tested: no bypass).
- Versioned event schema (Pydantic).
- Replayable trajectories with first-unsafe-step.
- B2/B3/B4/hybrid on the same files; one `make reproduce` (or `python -m eval.reproduce`).
- Tables: detection, FPR, earliness, latency; CIs or mean±std over ≥5 seeds where stochastic.
- Negative results reported.

---

## 8. Measurable success criteria (pre-registered; do not tune to hit these)

Chosen **before** experiments. If missed, report miss; do not silently lower the bar.

**Primary (must all be defined even if we fail them):**

| ID | Criterion | Notes |
|---|---|---|
| S1 | At FPR ≤ **10%** (per-trajectory, hard-benign included), hybrid **detection rate** on *held-out families* is ≥ **10 percentage points** above rules-only **or** rules-only already saturates (≥90% DR) and hybrid does not *increase* FPR by >3pp | RQ4 + RQ3 |
| S2 | On detected attacks, hybrid **mean steps-before-harm** is ≥ **1.0 step** better than rules-only, or mean first-detection index is earlier by ≥1.0 with 95% bootstrap CI excluding 0 | RQ2 |
| S3 | Open-set: train/tune on 2 families, test on the held-out family. Report DR and FPR. Success if held-out DR ≥ **50%** at FPR ≤ 10%. Phrase as controlled unseen-family detection | RQ3 |
| S4 | Gate overhead without LLM: p95 ≤ **100 ms** per tool call on laptop-class hardware. With LLM judge: p95 ≤ **2.5 s** (or mock/replay in CI) | RQ5 |
| S5 | Security tests: gateway bypass = 0; sandbox egress to public net = 0 in CI | correctness |

**Secondary:**

- S6: Isolation Forest / OC-SVM beats rules on **at least one** of {held-out DR, earliness} at the same FPR target; else **declare ML not needed** (G4).
- S7: Adaptive round (stretch): evasion rate after observing BLOCK, one round, reported not optimized away.

**Explicit non-criteria:** production readiness, 100% DR, “zero-day,” dashboard completeness.

---

## 9. 7-day proof-of-concept plan (pass/fail)

**Goal:** test whether prefix features can separate *anything* before we invest in FastAPI/React.

| Day | Work | Output |
|---|---|---|
| 1 | Event schema (Pydantic) + in-process gateway wrapping 4 fake tools: `fs_read`, `fs_write`, `http_post` (fake), `creds_list` (synthetic canaries). Scripted agent loop. No Docker required yet | `events.jsonl` |
| 2 | Immutable task/objective record. Two **hard benign** scripts (repo audit reading many files; analytics reading fake DB-like JSON). Three **attack** scripts: (i) hijack → extra `http_post` to fake sink; (ii) creds_list + write; (iii) gradual: search → read → post | Labeled trajectories, first-unsafe-step |
| 3 | Prefix n-gram / transition features + Isolation Forest trained on **benign prefixes only**. Plot anomaly score vs step | Notebook or `eval/poc_plot.py` |
| 4 | YAML rules: block `http_post` outside allowlist; block `creds_list` if objective scope ≠ secrets-audit | B2 decisions on same traces |
| 5 | Dummy LLM judge (deterministic heuristic or recorded JSON) so the hybrid *interface* exists without API keys | Interface freeze |
| 6 | Tables: per-step AUROC, FPR on hard benign, first detection step vs first-unsafe-step | `docs/EXPERIMENTS.md` first row |
| 7 | Write PoC result + recommend continue / pivot. Freeze test traces (hashes) | Gate review |

**Pass:** (a) ≥8 trajectories (4 benign-like, 4 attack-like) with valid first-unsafe-step; (b) **prefix AUROC ≥ 0.70** on at least one attack family vs hard benign **or** a documented failure with plots; (c) rules-only either misses a slow-and-low path that features catch, or features add **nothing**—both are acceptable PoC outcomes; (d) no real network, no real secrets.

**Fail:** cannot log a closed loop; labels don’t map to steps; AUROC ~0.5 and rules also fail with no insight. Then pivot to Alt A or B.

---

## 10. Known risks and mitigations

| Risk | Why it kills the project | Mitigation |
|---|---|---|
| **Label leakage** | Features include the label, the tool name that *is* the attack, or post-harm fields | Prefix features only; no `result`/`decision` in the detector input; code review of feature functions; tests |
| **Synthetic-data realism** | Fake GitHub/DB trajectories do not look like real agents | State limitation in every results section; optional later: replay AgentDojo traces; keep live LLM generation as *secondary* with seeds |
| **Benchmark circularity** | Same authors write attacks and detector | Freeze test hashes before tuning (document in EXPERIMENTS.md); different person writes holdout family if possible; do not add rules that name the test attack |
| **LLM nondeterminism** | Tables move between runs | Mock/replay by hash in CI; ≥5 seeds for live calls; cache |
| **Small-N statistics** | 12 trajectories, huge claims | Pre-register S1–S5; bootstrap CIs; refuse “significant” without a test; prefer paired comparison on identical traces |
| **Prompt injection into the monitor** | Tool output jailbreaks ARGUS | Delimiters, JSON schema, no tools for monitor, untrusted-input framing; security tests with injected tool output |
| **Policy vs ML credit assignment** | Hybrid “wins” because BLOCK rules fire | Ablations; report rules-only and ML-only; LLM cannot override BLOCK |
| **Scope creep (dashboard/K8s)** | Eval never runs | MODIFY cuts; reject extra infra via ADR |
| **Adaptive adversary too early** | Moves goalposts before baseline exists | Only after G4 |
| **Ethical/legal** | Real exploits, real creds | Fake services, canary secrets, no host mounts, `internal: true` network when Compose exists |

---

## Decision requested

Reply with one of:

- **MODIFY** — accept §6–§9 (recommended)
- **GO** — override and keep the full 12-component brief (high fail risk)
- **REJECT** — stop ARGUS; pick Alt A / B / C
- **MODIFY + notes** — accept MODIFY but change families, metrics, or PoC days

No production code will be written until that reply.
