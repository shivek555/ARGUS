# ARGUS threat model (v0, PoC)

**Status:** working draft for weeks 1–2. Not a complete STRIDE of a production agent platform.

## Assets

- User **objective** (immutable): authorized task + scopes.
- **Synthetic** workspace files and fake DB JSON inside the process.
- **Canary credentials** (`CANARY_*`) in the fake cred store.
- Trajectory logs (forensics, eval). Not real host secrets.

## Actors

- **Benign agent:** tries to complete the authorized objective.
- **Hijacked / goal-deviant agent:** same tools, extra or substituted calls (scripted in PoC).
- **Untrusted tool output:** later; PoC tools return inert strings.
- **ARGUS itself:** must not be bypassed; LLM judge (when added) is untrusted for BLOCK override.

## In-scope attack families (PoC)

1. Goal hijack → unauthorized `http_post` to fake sink.
2. Credential discovery → `creds_list` outside `secrets-audit` scope.
3. Slow-and-low: allowed reads then unauthorized egress.

Out of scope for PoC: real malware, real network, host credential theft, model-weight attacks, adaptive multi-round evasion.

## Trust boundaries

- Agent code never holds tool callables.
- Only `Gateway.invoke` can execute a registered fake tool.
- Policy errors → **BLOCK** (fail closed).
- Detector vectors are **prefixes** (no result/decision).

## Out of scope (host)

PoC is in-process. Docker egress lock (`internal: true`) is deferred until after PoC pass. Do not treat in-process fakes as OS isolation.
