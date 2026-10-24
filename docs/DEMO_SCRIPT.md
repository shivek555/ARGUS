# Class demo script (Phase W, about 9 minutes)

Run `make serve`, wait for the server (about 15 s), open http://127.0.0.1:8000, switch **Presenter: on** (bottom left), then press **Reset demo** on the Demo page. Use ← → between beats. Every beat drives the real system; the expected outcome under each card is pinned and checked in CI (G7).

**Before class:** run `python -m argus.api.demo --base http://127.0.0.1:8000` once with the server up. It must print `G7 check: PASS`. Then press Reset demo.

| # | Beat | Do | Say (short) | ~ |
|---|---|---|---|---|
| 0 | Overview | Show the four numbers and the warning box | "Every tool call goes through one gateway. Three signals (policy rules, an anomaly detector on the trajectory, an LLM judging intent) become one calibrated, explained risk score. Numbers are dev, out-of-fold; the blind test decides." | 1:00 |
| 1 | A normal task | Start, click Next call until the end, open any step | "LOW everywhere: no friction, no human. The explanation shows each signal's points; they add up to the score exactly." | 1:00 |
| 2 | Rules catch a visible attack | Start, Next call ×4 | "Reading an SSH key outside the workspace breaks a policy rule. A policy block is always CRITICAL: quarantine, tools and network revoked, forensic snapshot." Open the snapshot, click **Verify sha256**. | 1:15 |
| 3 | An attack the rules miss | Start, Next call ×3 | "This exfiltration never breaks a rule. The hybrid's score passes CRITICAL when the agent reads a deploy key the task never asked for, three steps before the upload. No harm." | 1:15 |
| 4 | A human decides | Start, Next call ×4; type your name; **Deny** | "HIGH is uncertain, so a human decides. Denied: the code edit never runs. ARGUS cannot approve itself; unanswered requests are denied after 120 s." | 1:15 |
| 5 | The honest cost | Start, Next call ×3; **Approve** | "A legitimate secrets audit also gets held. On dev that is 27 approvals per 100 benign tasks; our own target was 15, and we missed it." | 1:00 |
| 6 | Try it live | Start, send the two calls | "No LLM here (no model runs on this laptop). README: LOW. Reading .env without the secrets scope: CRITICAL from the score alone." Optional: type your own call. | 1:00 |
| 7 | Results | Show the four cards, then the Results page | "97.5% vs 83.3% for the best single component on dev. But refits on resampled data swing from 33% to 100%, and the LLM adds almost nothing. The blind test v2 run decides G5 and G6." | 1:15 |

## Likely questions (honest answers)

- **Is it secure / does it stop all attacks?** No. It reduces attack completion in our benchmark under controlled scenarios. Attacks and detector were both written by us; the blind test split is meant to limit that bias.
- **Why does the LLM not help?** The free 3B model we can run at $0 flags legitimate risky work too (36.5% of benign tasks); once combined with the other signals its learned weight is about zero. A larger model might differ; we did not test that.
- **Why is the score in "points"?** It is a logistic regression: 10 points per unit of log-odds, so each signal's contribution can be shown and they add up exactly.
- **What if the reviewer always approves?** On dev, harm completion rises from 2.5% to 18.3%. Humans matter.
- **How fast is it?** A few milliseconds per call without the LLM (1.8 ms p50 / 3.7 ms p95 in the committed laptop run, `docs/results/latency-laptop.md`; it varies by machine and load); the CPU LLM adds about 7 s on the ~21% of calls that are risky (fails our 2 s target).
- **Zero-day?** No. We call it open-set behavioural anomaly detection under controlled unseen attack scenarios.

## If something fails

- Server not up: check the terminal for the "Uvicorn running" line; startup takes about 15 s.
- A beat looks different from its card: press **Reset demo** and restart the beat; if it persists, run the G7 check above.
- Laptop failure: every table and figure is committed under `docs/results/` and renders on GitHub (`r4_dev.md`, `figures/*.svg`).
