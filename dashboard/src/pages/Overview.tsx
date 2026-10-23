import { api, ApiError } from "../api";
import { useAsync } from "../hooks";
import { Callout, Card, ErrorState, Loading, Stat, Todo, fixed, pct, relTime } from "../components/ui";

const PIPELINE = [
  { name: "Agent runtime", state: "built", note: "Scripted loop; receives only the gateway" },
  { name: "Gateway", state: "built", note: "Sole tool path; fail-closed on unknown tools/errors" },
  { name: "Policy engine (B2)", state: "built", note: "YAML: egress scope + allowlist, credential scope" },
  { name: "Prefix features + IForest (B3)", state: "built", note: "12-D bag-of-tools prefix features" },
  { name: "Intent monitor (B4)", state: "mock", note: "Deterministic heuristic, no LLM call" },
  { name: "Risk engine / hybrid", state: "not built", note: "Blocked on G4" },
  { name: "Containment + approval queue", state: "not built", note: "" },
];

export function Overview() {
  const meta = useAsync(() => api.meta(), []);
  const exp = useAsync(() => api.experiment(), []);

  const missing = exp.error instanceof ApiError && exp.error.status === 404;
  const auroc = exp.data?.summary.prefix_auroc_unsafe_vs_benign;
  const bar = meta.data?.preregistered.poc_auroc_threshold;
  const b = Object.fromEntries((exp.data?.baselines ?? []).map((x) => [x.id, x]));
  const attacks = exp.data?.rows.filter((r) => r.type === "attack") ?? [];
  const families = new Set(attacks.map((r) => r.family));

  return (
    <div className="stack">
      <header className="page-head">
        <div>
          <h1>Overview</h1>
          <p>
            ARGUS sits between an LLM agent and its tools and decides, per call, whether to allow it. The research
            question is whether the <em>trajectory</em> of calls flags unsafe behaviour earlier and more reliably than
            per-action rules. Every number below comes from the logged PoC run or a deterministic replay.
          </p>
        </div>
      </header>

      {exp.loading && <Loading rows={2} />}
      {missing && (
        <Callout tone="warning" icon="▲" title="No logged evaluation run">
          TODO: not yet measured. Run <code>python -m argus.eval.poc</code> or use{" "}
          <a href="#/experiments">Experiments → Run evaluation</a>.
        </Callout>
      )}
      {exp.error && !missing && <ErrorState error={exp.error} onRetry={exp.reload} />}

      {exp.data && (
        <>
          {typeof auroc === "number" && bar !== undefined && (
            <Callout
              tone={auroc >= bar ? "info" : "critical"}
              icon={auroc >= bar ? "✓" : "✕"}
              title={
                auroc >= bar
                  ? `ML signal passes the PoC bar: prefix AUROC ${auroc.toFixed(3)} ≥ ${bar.toFixed(2)}`
                  : `Hypothesis not supported yet: prefix AUROC ${auroc.toFixed(3)} < ${bar.toFixed(2)} pre-registered bar`
              }
            >
              {auroc >= bar
                ? "Trajectory features separate unsafe prefixes from hard-benign ones in this run."
                : `With the current 12-D bag-of-tools features the anomaly detector does not separate unsafe prefixes from hard-benign ones. ${
                    b.B2
                      ? `Rules flag ${b.B2.detected_attacks}/${b.B2.n_attack} attacks with mean steps-before-harm ${
                          b.B2.mean_steps_before_harm === null ? "n/a" : b.B2.mean_steps_before_harm.toFixed(1)
                        } (0 = flagged exactly at the unsafe step), so there is no early-detection gain over rules to report. `
                      : ""
                  }See docs/PROGRESS.md for the gate status and the rescue/pivot decision.`}
            </Callout>
          )}

          <div className="grid cols-4">
            <Stat
              label="Scenarios (frozen)"
              value={exp.data.summary.n_scenarios}
              sub={`${attacks.length} attack · ${exp.data.rows.length - attacks.length} benign · ${families.size} attack families`}
            />
            <Stat
              label="Prefix AUROC (unsafe vs benign)"
              value={typeof auroc === "number" ? fixed(auroc) : <Todo />}
              sub={bar !== undefined ? `PoC pass bar ≥ ${bar.toFixed(2)}` : undefined}
            />
            <Stat
              label="Rules (B2) detection rate"
              value={pct(b.B2?.detection_rate) ?? <Todo />}
              sub={b.B2 ? `${b.B2.detected_attacks}/${b.B2.n_attack} attacks · FPR ${pct(b.B2.fpr)}` : undefined}
            />
            <Stat
              label="ML (B3) false-positive rate"
              value={pct(b.B3?.fpr) ?? <Todo />}
              sub={b.B3 ? `${b.B3.flagged_benign}/${b.B3.n_benign} benign flagged · DR ${pct(b.B3.detection_rate)}` : undefined}
            />
          </div>
          <p className="small muted">
            From <code>{exp.data.provenance.path}</code>, written {relTime(exp.data.provenance.modified_at)}. N is tiny
            (per-trajectory rates over {attacks.length} attacks and {exp.data.rows.length - attacks.length} benign runs),
            scenarios are author-written, and no confidence intervals are computed yet.
          </p>
        </>
      )}

      <div className="grid cols-2">
        <Card title="Pipeline status" hint="what exists in code today">
          <ul className="list" style={{ margin: "0 -16px -16px" }}>
            {PIPELINE.map((p) => (
              <li key={p.name}>
                <span
                  className={`badge ${p.state === "built" ? "ALLOW" : p.state === "mock" ? "MONITOR" : "neutral"}`}
                  style={{ minWidth: 86, justifyContent: "center" }}
                >
                  {p.state}
                </span>
                <span className="grow wrap">
                  <strong style={{ fontWeight: 560 }}>{p.name}</strong>
                  {p.note && <span className="muted"> · {p.note}</span>}
                </span>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Pre-registered success criteria" hint={meta.data?.preregistered.source}>
          {meta.loading && <Loading />}
          {meta.error && <ErrorState error={meta.error} onRetry={meta.reload} />}
          {meta.data && (
            <ul className="list" style={{ margin: "0 -16px -16px" }}>
              {meta.data.preregistered.criteria.map((c) => (
                <li key={c.id} style={{ alignItems: "flex-start" }}>
                  <span className="chip mono" style={{ marginTop: 1 }}>
                    {c.id}
                  </span>
                  <span style={{ flex: 1 }}>
                    {c.text}
                    <div className="small todo">TODO: not yet measured</div>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {meta.data && (
        <Card title="Authoritative policy" hint={`${meta.data.policy.path} · sha ${meta.data.policy.sha256.slice(0, 10)}`}>
          <dl className="kv">
            <dt>Egress</dt>
            <dd>
              <code>http_post</code> requires scope <span className="chip mono">{meta.data.policy.http_require_scope}</span>{" "}
              and a destination in{" "}
              {meta.data.policy.http_allowlist.map((u) => (
                <span key={u} className="chip mono">
                  {u}
                </span>
              ))}
            </dd>
            <dt>Credentials</dt>
            <dd>
              <code>creds_list</code> requires scope{" "}
              <span className="chip mono">{meta.data.policy.creds_require_scope}</span>
            </dd>
            <dt>Gateway</dt>
            <dd>Unknown tools, event-build failures and tool errors (enforce mode) are blocked: fail closed.</dd>
            <dt>Advisory signals</dt>
            <dd>
              ML and the intent monitor can only raise risk; they never override a policy BLOCK. The hybrid risk engine
              that would combine them is not built yet.
            </dd>
          </dl>
        </Card>
      )}
    </div>
  );
}
