# Plan: Phase R2-L — free open-weights LLM monitor, run on GitHub Actions

**Status:** approved 2026-10-23 ("Approved. Build R2L-a … I'll click Run workflow for the smoke test."). R2L-a built: adapter, runner, workflow, offline tests.
**Your constraints:**
- **Free:** paid APIs (OpenAI, Claude) charge per token, so they are out.
- **Nothing downloaded on your PC:** so no local Ollama on the laptop.

**Solution:** run a small open-weights model with Ollama **on a GitHub-hosted runner**, inside a manual GitHub Actions workflow in this repo. Ollama and the model download onto GitHub's machine; nothing is installed or downloaded on your laptop, and no API key or account is needed beyond GitHub.

**Replaces for live runs:** the OpenAI default of ADR-0010. The OpenAI and Claude adapters stay in the code for anyone with a key, but R2 results come from this setup.

---

## 1. What stays the same (from ADR-0009)

- Prompt `monitor-v1`: the trusted objective and the untrusted, escaped trajectory data.
- The verdict schema and its pydantic validation.
- Fail-closed mapping, advisory-only `apply_advisory`, no tools.
- The sha256 response cache: replay in normal CI and on your laptop, never compute twice.
- The pre-registered criteria L1–L6 and the rule that test v2 is used once, with a frozen prompt and model.

## 2. Where it runs (checked in GitHub's docs, 2026-10-23)

| Item | Value | Source |
|---|---|---|
| Machine | `ubuntu-latest`, **public repo: 4 CPU, 16 GB RAM, 14 GB SSD** | GitHub-hosted runners reference |
| Cost | "free and unlimited on public repositories" | same page |
| Time limit | **6 hours per job** ("terminated and marked as failed" after that) | GitHub Actions limits |
| GPU | none, so inference is CPU-only | — |

Consequences:
- **Models:** small models (about 3B parameters, a few GB) fit comfortably. `gpt-oss:20b` (OpenAI's free open-weight model, 14 GB download, needs ~16 GB memory) does **not** fit: the 14 GB disk also holds the OS and Python packages.
- **Speed:** CPU-only, so expect seconds per judgement. The pilot measures it.
- **Job length:** each job stops itself before the 6 h limit (default cap **5 h 20 min**). Long runs are split into several jobs and resume from the cache.
- **Public logs:** the repo is public, so workflow logs are public. The monitor only ever sees **synthetic** benchmark data with fake `CANARY_*` values, and the workflow uses **no secrets**, so nothing sensitive can appear.

## 3. Design

### 3a. Ollama adapter (R2L-a)
- **Provider:** `ARGUS_LLM_PROVIDER=ollama`; model via `ARGUS_LLM_MODEL`.
- **Transport:** `POST http://localhost:11434/api/chat` on the runner itself (Ollama's documented default), sent with `httpx`, which is already in the lock. **No new Python dependency.**
- **Localhost only:** the adapter refuses any non-loopback host. This is enforced by a test, so trajectory data never goes anywhere except the Ollama process on the same machine.
- **Request:**
  - `messages` = [system prompt, user message];
  - `format` = the verdict JSON schema (Ollama enforces it);
  - `stream: false`;
  - `options: {temperature: 0}`.

  Following Ollama's guidance, the schema is also appended to the user message as text. That is a provider-specific prompt variant, recorded in the cache key and in results.
- **Determinism:** `temperature: 0`, so answers repeat, unlike the paid APIs. Checked by re-running 30 judgements and reporting agreement.
- **Verify before coding, from Ollama's API reference:**
  1. whether `options.seed` exists;
  2. the response fields for the answer text, token counts and timings.

  Nothing is guessed.
- **Fail closed:** Ollama not running, model missing, timeout or invalid JSON all become ESCALATE (risky calls) or MONITOR (others).

### 3b. The workflow (R2L-a): `.github/workflows/r2-llm.yml`
- **Manual only (`workflow_dispatch`).** It never runs on push or on pull requests from forks. You start it from the repo's **Actions** tab with **Run workflow**.
- **Inputs:** `model` (one of the pre-registered candidates), `run` (`smoke` | `pilot` | `dev` | `catalog` | `test_v2`), `shard` (for splitting long runs).
- **Steps:**
  1. checkout;
  2. Python 3.11.9 + the locked requirements;
  3. install Ollama on the runner with Ollama's official Linux install method, a **pinned version**; I verify the exact command and version from Ollama's docs before writing it;
  4. start `ollama serve`, then `ollama pull <model>`;
  5. run the R2-L runner with the time cap;
  6. **commit the response cache and the run summary back to the branch.**

  Step 6 means every judgement lands in the repo, and replay works everywhere, including your laptop, without Ollama.
- **Permissions:** `contents: write` only in this workflow, which is needed for step 6. No repository secrets are used. Normal CI stays read-only and keeps running in replay/mock mode.

### 3c. Runner changes
- **Time cap instead of the dollar cap.** Spend is $0; the runner stops before the job limit.
- **Resumable:** finished judgements are in the cache, so a new job skips them.
- **Risky-call scope** (§5), and sharding so each job stays under its cap.

## 4. Candidate models (pre-registered now)

Both about 3B and both in Ollama's library (checked 2026-10-23):

| Candidate | Why |
|---|---|
| `llama3.2:3b` | most-pulled small instruct model; tools label |
| `qwen2.5:3b` | strong small model for structured output; tools label |

Not chosen:
- **"Thinking" models** (`qwen3:4b`, `deepseek-r1:1.5b`): reasoning tokens are much slower on CPU.
- **Models under 1.5B:** likely too weak to read intent.
- **`gpt-oss:20b`:** does not fit the runner's 14 GB disk (§2).

`phi4-mini:3.8b` is the reserve if a candidate fails to load.

**Selection rule (fixed now, applied on the pilot, i.e. dev only):** among candidates with a **valid-JSON rate ≥ 95%**, pick the higher **AUROC on the pilot's prefix judgements** (unsafe vs benign; inverted `intent_alignment`). Ties go to the lower p50 latency. If neither reaches 95% valid JSON, R2-L stops and is reported as "small open-weights models cannot follow the monitor's output contract on CPU". That is a result in itself.

## 5. Reduced scope (fits free CPU runners)

| Run | Data | Calls judged | Approx. judgements |
|---|---|---|---|
| Pilot (each candidate) | the fixed 20 dev trajectories from `r2_pilot.py` | every step | **141** per model (measured) |
| Dev | all 120 v1 dev attacks + 126 dev-v2 benign (9 per intent) | **risky calls only** | **307** (measured) |
| Catalog (exploratory) | 216 legitimate tasks | risky calls only | **174** (measured) |
| Test v2 (once, after G4-R2) | full test v2 | risky calls only | ≈ 400–600 |

**Risky calls only** means writes, uploads, credential-store access, high-sensitivity reads and unknown tools. Other calls count as "no LLM opinion".

The cost of this cut: earliness on reconnaissance steps isn't measured by the LLM. That is stated in the results. The pilot replaces these counts with measured ones, and the measured speed decides how many shards each run needs.

## 6. Criteria

L1–L6 from ADR-0009 are kept unchanged and evaluated on the risky-call scope. Expected honest outcomes, written now:
- **L5 (p95 ≤ 2.5 s):** likely **fails** on a CPU runner. Reported with measured p50/p95, plus the observation that a CPU-hosted small model would run as an asynchronous, advisory monitor rather than an inline gate.
- **L1–L3:** unknown; small models may fall short. Any result is reported.

## 7. Steps and checkpoints

| Step | What | Who | Cost |
|---|---|---|---|
| R2L-a ✅ | Verify the Ollama API + install docs (done: chat fields, `options.seed`, `OLLAMA_VERSION` pinning; pinned **0.40.2**, released 2026-10-08); write the `ollama` adapter, localhost guard, time cap, resumable/sharded runner, risky-call scope, and `r2-llm.yml`; offline tests (fake HTTP transport). Commit + push | Claude | $0 |
| R2L-b | In GitHub → **Actions** → *R2 LLM* → **Run workflow**, `run = smoke`, for each candidate (one call each) | **you (two clicks)** | $0, nothing on your PC |
| R2L-c | If both smokes pass: run `pilot` for each candidate; the workflow commits the cache and summary | you click, Claude reads the results | $0 |
| — | **Checkpoint:** you see latency, valid-JSON rate and the selected model | you | — |
| R2L-d | Freeze model + prompt variant; `dev` and `catalog` runs (sharded if needed) | you click, Claude analyses | $0 |
| R2L-e | After G4-R2: one `test_v2` run; `docs/R2_RESULTS.md` | you click, Claude analyses | $0 |

Starting the workflow needs a click from you, because I have no GitHub access token here, and I won't ask for one.

## 8. Risks

- **Quality of small models:** may fail L1/L3. Mitigation: two candidates, and an honest report.
- **Speed on 4 CPUs:** mitigated by the risky-call scope, sharding and resumable runs. If even that is too slow, scope drops to the pilot + dev attacks, and that is reported.
- **Runner changes:** GitHub may change runner specs. The workflow prints CPU/RAM/disk at the start of every run, and results record them.
- **Comparability:** results describe a *small open-weights* LLM monitor on CPU, not frontier models. The paper says so, and anyone with an API key can re-run with the OpenAI or Claude adapters.
- **Bot commits:** the workflow pushes to `r1-rescue`. Pull before working locally; the committed cache only ever grows (append-only JSONL).
