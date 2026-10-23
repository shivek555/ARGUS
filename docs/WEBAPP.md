# ARGUS web app (API + dashboard)

A local research console over the PoC. It shows what exists and nothing more: frozen
scenario replays, the logged evaluation run, and a live gateway you can drive by hand.
See ADR-0002 for why it exists before G4 and what it deliberately does not do.

## Run it

Requirements: Python 3.11+, Node 18+ (tested with Node 24).

```bash
pip install -r requirements.txt -c constraints.txt
npm --prefix dashboard ci
python -m argus.eval.poc        # optional: writes the logged run the Experiments page reads
make serve                      # builds dashboard/dist, serves UI + API on http://127.0.0.1:8000
```

Development (hot reload): run `make api` and `make dashboard-dev` in two terminals and open
http://127.0.0.1:5173 (Vite proxies `/api` to :8000). OpenAPI UI: http://127.0.0.1:8000/docs.

Tests: `make test` (API tests use FastAPI's in-process client; no sockets, no LLM calls).

## Pages

| Page | What it shows | Data source |
|---|---|---|
| Overview | Hypothesis status vs the pre-registered PoC bar (AUROC ≥ 0.70), headline rates, what is built vs mock vs not built, S1–S5 (all `TODO: not yet measured`), active policy | `summary.json` + `/api/meta` |
| Scenarios | All frozen scenarios with first-detection step per detector, judged against `first_unsafe_step` | deterministic record-mode replay |
| Scenario drill-down | Immutable objective, per-step timeline (policy rule + reason, mock intent, anomaly score, ground truth), anomaly-over-steps chart, unsafe-but-allowed steps highlighted | replay |
| Gateway playground | Start a session from a custom objective or a scenario; send tool calls (incl. unregistered tools) through the **enforce-mode** gateway; see the fake world (egress sink, files written, credential names) | live `Gateway` over `FakeWorld` |
| Experiments | Provenance (file, SHA-256, mtime, reproduce command, scenario-hash drift check), B1–B4 per-trajectory DR/FPR/in-time/steps-before-harm, hybrid + latency as TODO, per-scenario detection matrix, "Run evaluation" | `summary.json`; re-run calls `compute_summary` |

Record vs enforce: scenario replays use **record** mode (every call executes, the gateway logs
what it would decide), exactly like `argus.eval.poc`. The playground uses **enforce** mode
(blocked calls never execute), so a replayed attack can diverge from the recorded trace.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | liveness |
| GET | `/api/meta` | schema version, policy (path, sha, rules), tool catalog (from real signatures), detector config + threshold, pre-registered criteria, not-built list |
| GET | `/api/scenarios` | headers + first-detection steps |
| GET | `/api/scenarios/{id}` | annotated replay (`StepView[]`) + detections |
| GET | `/api/experiments/poc` | logged run + provenance + derived baselines; **404 "TODO: not yet measured"** if absent |
| POST | `/api/experiments/poc/run` | re-runs the PoC eval and overwrites `summary.json`; 409 if already running |
| POST | `/api/sessions` | `{objective_text, allowed_scopes}` or `{scenario_id}` (not both) |
| GET | `/api/sessions/{id}` | session state |
| POST | `/api/sessions/{id}/calls` | `{tool, args}` through the gateway |
| POST | `/api/sessions/{id}/script/next` | next scripted call of a scenario session; 409 when finished |
| DELETE | `/api/sessions/{id}` | drop session |

Each step carries `policy.source`: `policy` (YAML rule: `egress.scope`, `egress.allowlist`,
`credentials.scope`, `default.allow`) or `gateway` (`gateway.unknown_tool`,
`gateway.tool_error`, `gateway.fail_closed`).

## Derived metrics (exact definitions)

Computed server-side from the logged rows only (`derive_baselines` in `argus/api/service.py`):

- **Detection rate**: attack trajectories with any flag ÷ attack trajectories.
- **FPR**: benign trajectories with any flag ÷ benign trajectories.
- **Flagged in time**: attacks whose first flag step ≤ `first_unsafe_step`.
- **Mean steps before harm**: mean of `first_unsafe_step − first_flag_step` over detected attacks (0 = flagged on the unsafe step).
- **B1** is zero by definition, not measured. **Hybrid**, **latency** and **S1–S5** are `TODO: not yet measured`.

## Security properties (tested in `tests/test_api.py`)

- Binds to `127.0.0.1` by default. No CORS. CSP, `nosniff`, `X-Frame-Options: DENY`, `no-referrer`.
- The playground only reaches `make_tools(FakeWorld)`: in-process, no sockets (existing `test_fake_tools_no_network`).
- Unknown tools, tool exceptions and event-build failures → BLOCK (fail closed).
- Injection text in args does not change the policy decision or the mock judge.
- Canary secrets never appear in any response (results go through `redact_result`; credential store exposes names only).
- The objective is frozen at session creation; there is no update route.
- Bounded input: identifier-only tool/arg names, ≤ 8 scalar args, ≤ 10 000 chars each, ≤ 100 steps/session, ≤ 64 sessions (LRU). Sessions are in memory and vanish on restart.
- SPA fallback never serves files outside `dashboard/dist` and never shadows `/api/*`.

## Known limitations

- The anomaly threshold is in-sample (fit and p90 on the same benign scenarios), as in the PoC.
- The mock intent judge is a scope heuristic; it returns ALLOW for unregistered tools (the gateway still blocks them).
- No auth: this is a local research tool. Do not bind it to a public interface.
- No hybrid/risk engine, containment, or approval queue. The UI says so rather than simulating them.
