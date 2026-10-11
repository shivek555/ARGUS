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
