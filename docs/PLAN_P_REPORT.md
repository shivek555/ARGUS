# Plan: Phase P — final-year report and class presentation

**Status:** draft for review (ADR-0016 proposed). Outline only; no chapters or slides written yet.
**Inputs already in the repo:** ADR-0000..0015, `FEASIBILITY.md` (searched related work, gap, pre-registered criteria), `THREAT_MODEL.md`, `BENCH_V1.md`, `DEV_V2.md`, `BENIGN_CATALOG.md`, `R1_RESULTS.md`, `R3_DEV_REPORT.md`, `docs/results/` (every table and figure, CI-checked), `WEBAPP.md`, `DEMO_SCRIPT.md`, `EXPERIMENTS.md`.

---

## 1. Rules for every page (from the brief)

1. **No fabricated numbers.** Every number cites a file in `docs/results/` (or a committed run log) and the command that regenerates it. Anything not measured says `TODO: not yet measured`.
2. **Numbers ledger:** an appendix table listing every number in the report and deck with its source file and field. The ledger is generated from `docs/results/*.json`, not typed by hand, and a check fails if the text quotes a number that is not in the ledger.
3. **Labels on every result:** *dev out-of-fold*, *dev in-sample*, *exploratory*, or *blind test v2*. Test-v2 results get placeholders until the single run happens.
4. **Wording:** never "revolutionary", "100% secure", "zero-day", "prevents all attacks", "production ready". Instead: "evaluated under controlled scenarios", "reduces attack completion in our benchmark", "open-set behavioral anomaly detection under controlled unseen attack scenarios".
5. **Every results section ends with its limitations** (synthetic data, author-written attacks, small N).
6. **Negative results are results:** G3 and G4 failed; the LLM adds almost nothing; the approval workload misses its target; seed variance is large; LA is on hold. Each is reported, with what it taught us.

## 2. Report outline (about 60–80 pages; adjusted to your college template)

| # | Chapter | Content | Main sources | ~pages |
|---|---|---|---|---|
| – | Front matter | Certificate, declaration, acknowledgements, abstract, contents, lists of figures/tables, abbreviations | college template | 6–8 |
| 1 | Introduction | Problem (autonomous agents with tools), motivation, hypothesis, RQ1–RQ6, contributions, what is *not* claimed | brief §1–2, FEASIBILITY §4, §7 | 5 |
| 2 | Background and related work | LLM agents and tool use; prompt injection; guardrails and policy enforcement; runtime monitoring; anomaly detection on traces; LLM-as-judge; agent security benchmarks; the gap | FEASIBILITY §3–4 (**citations re-verified on the web and dated before final**) | 8–10 |
| 3 | Threat model | Assets, actors, trust boundaries, attack families, policy-visible vs policy-compliant, out of scope | THREAT_MODEL.md | 4 |
| 4 | System design | Gateway as the sole path; policy engine (v2/v3); trajectory features v2; ML detector; LLM intent monitor (untrusted-data handling, fail-closed, advisory only); risk engine (calibrated additive points, levels, explanations); containment (quarantine, revocation, forensic snapshot); human approval queue; security invariants and how each is tested | ADR-0004..0014, code, tests | 12–14 |
| 5 | Benchmark and data | AgentEscapeBench v1 (3 families × 2 variants), labelling rule, dev v2 compositional benign, benign catalogue, frozen splits and hashes, blind test v2 protocol | BENCH_V1, DEV_V2, BENIGN_CATALOG, TEST_V2_AUTHORING | 6 |
| 6 | Methodology | Pre-registration and gates; leakage controls (blindness tests, LOIO/LOTO, out-of-fold); budgets; metrics definitions; statistics (bootstrap CIs, exact McNemar + Holm); seeds; reproducibility (`make reproduce`, CI checks, cross-OS correction) | PLAN_R4, ADR-0006/0013, `argus/eval/metrics.py` | 6 |
| 7 | Results | 7.1 PoC and G3 fail; 7.2 R1 and G4 fail; 7.3 R1b selection; 7.4 R2-L LLM monitor; 7.5 R3 risk engine (dev); 7.6 R4 all methods, ablations, open-set, seeds, containment (dev); 7.7 overhead (RQ5); **7.8 blind test v2: G4-R2, G5, G6 (placeholders until run)** | `docs/results/*` | 14–16 |
| 8 | Discussion | Answers to RQ1–RQ6 with evidence level; what the hybrid gains and from where (ML + context, not the LLM); the cost (false holds, workload); seed sensitivity; gameable signals; threats to validity | R3/R4 findings, ADRs | 5 |
| 9 | Limitations and ethics | Synthetic, author-written data; small N; CPU 3B LLM; scripted agents only (LA on hold); no adaptive attacker (R5); no auth in the demo app; responsible use and disclosure of AI assistance | ADR-0015, brief §186 | 3 |
| 10 | Conclusion and future work | Summary; test v2; R5 adaptive attacker; LA live agent; larger monitors; per-trajectory escalation | — | 2 |
| A–F | Appendices | A ADR index; B reproduction guide; C web app and demo guide; D gate table; E test-v2 authoring protocol; F numbers ledger | repo docs | as needed |

### Figures and tables

- **Existing (CI-checked SVG):** step-level ROC, detection vs budget, steps before harm.
- **To make:**
  - architecture diagram (gateway → signals → risk engine → decision/containment);
  - risk-explanation example (screenshot of the waterfall);
  - containment and approval flow;
  - project timeline (phases and gates);
  - dataset composition chart.
- **Tables:** methods comparison, CIs, paired tests, containment, open-set, seeds, R1b grid, R2-L runs, latency (all from `docs/results/`).

## 3. Presentation deck (about 15 slides for a 20-minute slot, 9 of which is the live demo)

| # | Slide | Point |
|---|---|---|
| 1 | Title | ARGUS, team, guide |
| 2 | The problem | Agents act through tools; one injected instruction can make them leak or tamper |
| 3 | Why existing defences fall short | Static rules miss policy-compliant attacks; LLM judges over-flag; no explanation |
| 4 | Hypothesis and RQs | Trajectory behaviour + calibrated fusion + containment |
| 5 | Architecture | One gateway, three signals, one explained score, containment |
| 6 | How we kept it honest | Pre-registered gates, blind test split, failed gates reported |
| 7 | Benchmark | Families, visible vs compliant, benign shapes |
| 8 | **Live demo** (transition) | The 7 beats from DEMO_SCRIPT, with fallback screenshots |
| 9 | Results (dev) | Hybrid vs components with CIs, labelled dev |
| 10 | What we learned the hard way | G3/G4 failures, LLM adds ≈ nothing, seed variance, workload miss |
| 11 | Overhead | ms without the LLM vs seconds with it |
| 12 | Limitations | Synthetic, author-written, small N, scripted agent |
| 13 | What decides it | Blind test v2 (status), then R5/LA |
| 14 | Team contributions | M1–M4 roles (your names) |
| 15 | Q&A | — |
| B1–B4 | Backup | Statistics, threat model, risk-score maths, ADR highlights |

Speaker notes come from `DEMO_SCRIPT.md` and the chapter summaries. Every number on a slide is in the ledger.

## 4. Steps and checkpoints

| Step | Work | Checkpoint |
|---|---|---|
| P-a | Fit this outline to your template and decisions (§6); generate the numbers ledger from `docs/results/` | your OK on the outline |
| P-b | Draft chapters in this order: 4 → 5 → 6 → 3 → 7 (dev) → 8 → 9 → 1 → 2 → 10. Design first, introduction last. Related work is re-checked on the web (dated) before chapter 2. | review after chapters 4–6, then after 7–10 |
| P-c | Figures (diagrams, screenshots from the running app) | — |
| P-d | Deck + speaker notes | your rehearsal |
| P-e | After the test-v2 run: fill 7.8, update the abstract, discussion, deck slides 9/13 and the ledger | — |
| P-f | Final pass: ledger check, wording check (banned words), citation check, consistency with the repo | your sign-off |

## 5. Risks

- **College rules on AI-assisted writing:** check your department's policy before drafting. The plan assumes AI help is allowed **and disclosed** (acknowledgements and the ethics chapter), and that the team reviews and can explain every section, as the brief requires ("all members must be able to explain the whole architecture").
- **Test v2 timing:** if it is not ready before submission, chapter 7.8 stays a clearly marked placeholder, and the conclusion says the confirmatory test is pending. Dev results are never presented as the verdict.
- **Citation drift:** related work was searched in Phase 0; papers move. It is re-verified before final.
- **Length vs honesty:** cutting to a page limit must not drop the limitations or negative results.

## 6. Decisions for you

1. **Template:** does your college prescribe a format (chapter headings, page limit, citation style such as IEEE or APA, front-matter pages)? Please share it or its rules.
2. **Report format:** a Word file (.docx), Google Docs, or LaTeX?
3. **Deck format and slot:** PowerPoint (.pptx) or Google Slides, and how long is your presentation slot?
4. **Team:** names and M1–M4 roles for the contributions slide and the declaration.
5. **Submission timing:** wait for test v2 before the final, or submit with marked placeholders if the deadline comes first?
