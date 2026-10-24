# ARGUS web app (API + dashboard), Phase W

A local console over the **frozen research system** (ADR-0014): AgentEscapeBench replays with the frozen R3 risk decisions and their explanations, live enforce-mode containment sessions, the human approval queue, forensic snapshots, and the committed R4 results. It computes no new research numbers. The v0 PoC is kept read-only under **Archive**.

## Run it

Requirements: Python 3.11.9 and Node 22 (both already used by the project). Nothing is downloaded at demo time: no model, no API key, no network.

```bash
pip install -r requirements.txt -c constraints.txt
npm --prefix dashboard ci
make serve          # builds dashboard/dist, serves UI + API on http://127.0.0.1:8000
```

The server needs about 15 s to start: it fits the frozen ML detector and loads the bench and LLM replay cache before it listens. Development: `make api` and `make dashboard-dev` in two terminals, then open http://127.0.0.1:5173. OpenAPI: http://127.0.0.1:8000/docs.

**G7 check** (the same one CI runs on a clean checkout): with the server running, `python -m argus.api.demo --base http://127.0.0.1:8000` prints `G7 check: PASS`.

## Pages

| Page | What it shows | Source |
|---|---|---|
| Overview | Research questions, gate and phase board, headline dev numbers with their labels, frozen artefacts with hashes, overhead | `/api/status` (parsed from `docs/PROGRESS.md`), `docs/results/*.json` |
| Demo | 7 guided beats, each driving the real API; ← → to move; pinned expected outcomes | `argus/api/demo.py` |
| Benchmark | Dev attacks / dev benign / v1 test with each method's first flag vs the harm step | frozen signals + engines |
| Trajectory | Risk-over-steps chart with level thresholds, per-step table, **explanation**: baseline + per-signal points = risk score, the reasons for the level, recommended response | frozen engine |
| Live session | Replay a bench trajectory or type your own calls through `ContainedSession` (enforce mode) | live |
| Approvals | Held HIGH-risk calls with a countdown; approve/deny with a reviewer name | shared `ApprovalQueue` |
| Forensics | Snapshots (trigger, events, decisions, files written, egress, all redacted) and server-side sha256 verification | `eval/results/webapp/forensics/` (gitignored) |
| Results | R4 methods table, CIs, McNemar/Holm, containment, open-set, seeds, figures, R1b, R2-L, latency, provenance | `docs/results/` |
| Archive | v0 PoC scenarios and experiment (failed G3), read-only | `docs/results/poc_summary.json` |

## Which engine a session uses (ADR-0014)

| Session | Signals | Engine |
|---|---|---|
| Bench trajectory (dev) | Precomputed exactly as the dev evaluation: frozen ML, LLM verdicts replayed from the committed qwen2.5:3b cache | **Primary** model (ADR-0012) |
| v1 test, custom objective | Live policy + ML + context signals, **no LLM** (no verdict exists; no model runs in the app) | **No-LLM ablation** (ADR-0013) |

Bench sessions replay their recorded calls only, because their signals are precomputed per step; custom sessions accept hand-typed calls. On dev, decisions are **in-sample** (the model was fitted on that data): every per-trajectory view says so and points to the out-of-fold numbers on Results.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health`, `/api/meta`, `/api/status` | frozen artefacts + hashes, engines, signals, levels, policy, tools; gate/phase board |
| GET | `/api/bench?split=&family=&variant=` · `/api/bench/{id}` | headers with first-flag per method · per-step decisions with contributions |
| POST | `/api/sessions` | `{trajectory_id}` or `{objective_text, allowed_scopes}` (not both) |
| GET/DELETE | `/api/sessions/{id}` | state: records (status, decision, approval), quarantine, snapshot, world |
| POST | `/api/sessions/{id}/calls` · `/script/next` | custom call · next recorded call |
| GET · POST | `/api/approvals` · `/api/approvals/{id}` | queue with seconds left · `{approve, reviewer}` |
| GET · POST | `/api/forensics[/{id}]` · `/api/forensics/{id}/verify` | snapshot list/detail · sha256 check |
| GET | `/api/results/{name}` · `/api/results/figures/{name}.svg` | whitelisted committed files |
| GET · POST | `/api/demo` · `/api/demo/reset` | beats · clear sessions/approvals (snapshot files stay on disk) |
| GET | `/api/archive/{meta,scenarios,scenarios/{id},experiment}` | v0 PoC, read-only |

Retired in Phase W: `POST /api/experiments/poc/run` and the PoC playground sessions.

## Security properties (tested in `tests/test_api.py`)

- Binds to 127.0.0.1 by default; no CORS; CSP, `nosniff`, `X-Frame-Options: DENY`, `no-referrer`.
- Tools are the in-process fake world only; unknown tools and tool errors fail closed.
- HIGH-risk calls never run without a human decision; reserved names (`argus`, `agent`, `monitor`, `risk_engine`, `gateway`, `llm`, `ml`) are refused (403); unanswered requests expire after 120 s and are denied; a decided or expired request cannot be decided again (409).
- CRITICAL quarantines the session: every tool, including egress, is revoked; the snapshot is written once (`open("x")`) and tampering is detected.
- Session, approval and snapshot ids must be 32-hex; results and figure names are whitelisted; `../` paths never reach files.
- Canary secrets never appear in any response (bench details, session state, snapshots): results pass through `redact_result`, credential names only.
- Objective is immutable (PATCH/PUT → 405). Bounded inputs (≤ 8 identifier-named scalar args, ≤ 10 000 chars, ≤ 100 calls/session, ≤ 64 sessions LRU).
- The reviewer name is self-declared, not authentication. Do not bind this to a public interface.
- Test v2 is never loaded (`tests/test_blindness.py` covers `argus/api/`).

## Known limitations

- Dev decisions shown per trajectory are in-sample; out-of-fold numbers are on Results.
- Custom sessions have no LLM signal (no live model in the app).
- Sessions and approvals are in memory and vanish on restart; snapshot files persist under `eval/results/webapp/forensics/`.
- Startup takes about 15 s.
