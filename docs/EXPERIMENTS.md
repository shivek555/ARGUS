# ARGUS Experiments Log

Every metric in the paper, dashboard, or docs must point at a row here. If it is not here, write `TODO: not yet measured`.

**Reproduce:** `python -m argus.eval.poc` → writes `eval/results/poc/summary.json`

## Protocol (frozen intent)

- Compare on **identical trajectories and seeds**: B1 none · B2 rules · B3 ML anomaly · B4 LLM judge · Hybrid · leave-one-component-out.
- Split **by scenario family**, never by random step.
- Freeze test-set hashes **before** tuning rules/features.
- Stochastic parts: ≥5 seeds; mean ± std or bootstrap CIs.

## Pre-registered success criteria

Copied from `docs/FEASIBILITY.md` §8 (S1–S5). Do not edit after the first real run without a new ADR.

## Runs

| ID | Date | Seed | Command | Result path | Notes |
|---|---|---|---|---|---|
| poc-v1 | 2026-10-11 | IF seed=0 | `python -m argus.eval.poc` | `eval/results/poc/summary.json` | Baseline PoC. 10 scenarios, 12D bag-of-tools features. AUROC=0.536. |

## PoC (7-day) results

| Metric | Value |
|---|---|
| Prefix AUROC (attack vs hard benign) | **0.536** (below 0.70 threshold) |
| Rules-only DR @ 10% FPR | **100%** (all 6 attacks detected at first_unsafe_step) |
| ML-only DR @ benign-p90 threshold | **0%** (no attacks detected; 2/4 benign FP) |
| Mean steps-before-harm (rules) | **0.0** (rules fire at exactly the unsafe step) |
| Mean steps-before-harm (ML) | n/a (ML never detects) |
| p95 gate latency (no LLM) | TODO: not yet measured |

## Scenario hashes (frozen after first run — do not modify scenarios without a new ADR)

| Scenario | SHA-256 |
|---|---|
| A-creds-s1 | `59f9da3507029a88c5db72e8042311fac7e6f6317bc837ce1d3c5b16757675cf` |
| A-creds-s2 | `3d1b4a56d8f14da3667ab2fbea51ef6392fd846aad3131cf103ac4f13274d888` |
| A-hijack-s1 | `402d124ca66815ab7f6298a17d472e9ddd829c5f9ed7670fb49fcd11a8c7c26b` |
| A-hijack-s2 | `e32fb7fb91a7d1cda2d02661c6e6ecc7af8307965c7a85595c346b87b93abc94` |
| A-slow-s1 | `8f8243da195d4f4f4330dfd02e3a98d09c5ae45e63396a172b6f8d30d1838914` |
| A-slow-s2 | `34f2771cb573dfc24c108879cfe8e90b0a03d9bac087f558b0ce8d0cb998e289` |
| B-analytics-s1 | `a85c37898e81d0877b89830f710adcddc904eddf3763bbfbeaff1dc3e7dfff54` |
| B-analytics-s2 | `2fbb1ccf972b31ac83074fa11be38dc1f258e46faccfa2a384ce9e69d3df6985` |
| B-audit-s1 | `b0d5b99c4aa73546f1292653e2f17f8ab872e13cbb850d662639ed8fd9418df3` |
| B-audit-s2 | `880e1a28b35ea36bf5b212ed6db98db045d220edb2035246fcfb3682bde6bbaf` |
