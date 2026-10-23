import { useState } from "react";
import { api, ApiError } from "../api";
import { useAsync } from "../hooks";
import { Callout, Card, ErrorState, Loading, Todo, TypeChip, fixed, pct, relTime, shortSha } from "../components/ui";
import { DetectionCell } from "./Scenarios";
import type { Baseline } from "../types";

function Rate({ value, n, of }: { value: number | null; n: number; of: number }) {
  if (value === null) return <Todo />;
  return (
    <div className="meter" title={`${n} of ${of}`}>
      <div className="meter-track">
        <div className="meter-fill" style={{ width: `${value * 100}%` }} />
      </div>
      <span className="num small">
        {pct(value)} <span className="muted">({n}/{of})</span>
      </span>
    </div>
  );
}

function BaselineRow({ b }: { b: Baseline }) {
  return (
    <tr>
      <td>
        <div className="cell-title">
          <span className="chip mono">{b.id}</span> {b.label}
        </div>
        <div className="cell-sub">{b.note}</div>
      </td>
      <td>
        <Rate value={b.detection_rate} n={b.detected_attacks} of={b.n_attack} />
      </td>
      <td>
        <Rate value={b.fpr} n={b.flagged_benign} of={b.n_benign} />
      </td>
      <td className="num">
        {b.prevented_attacks}/{b.n_attack}
      </td>
      <td className="num">{b.mean_steps_before_harm === null ? <span className="muted">n/a</span> : b.mean_steps_before_harm.toFixed(2)}</td>
    </tr>
  );
}

export function Experiments() {
  const exp = useAsync(() => api.experiment(), []);
  const [running, setRunning] = useState(false);
  const [runErr, setRunErr] = useState<Error | null>(null);

  const rerun = async () => {
    setRunning(true);
    setRunErr(null);
    try {
      exp.setData(await api.runExperiment());
    } catch (e) {
      setRunErr(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setRunning(false);
    }
  };

  const missing = exp.error instanceof ApiError && exp.error.status === 404;
  const d = exp.data;

  return (
    <div className="stack">
      <header className="page-head">
        <div>
          <h1>Experiments</h1>
          <p>
            Baseline comparison on identical trajectories, read from the logged PoC run. Re-running executes the same
            code path as <code>python -m argus.eval.poc</code> and overwrites the logged summary.
          </p>
        </div>
        <button className="btn primary" onClick={() => void rerun()} disabled={running}>
          {running ? "Running…" : "↻ Run evaluation"}
        </button>
      </header>

      {runErr && <ErrorState error={runErr} />}
      {exp.loading && <Loading rows={5} />}
      {missing && (
        <Callout tone="warning" icon="▲" title="TODO: not yet measured">
          No logged run at <code>eval/results/poc/summary.json</code>. Use “Run evaluation” or{" "}
          <code>python -m argus.eval.poc</code>.
        </Callout>
      )}
      {exp.error && !missing && <ErrorState error={exp.error} onRetry={exp.reload} />}

      {d && (
        <>
          <Card title="Provenance" hint="every metric on this page traces to this file">
            <dl className="kv">
              <dt>Result file</dt>
              <dd className="mono small">{d.provenance.path}</dd>
              <dt>SHA-256</dt>
              <dd className="mono small" title={d.provenance.sha256}>
                {d.provenance.sha256}
              </dd>
              <dt>Written</dt>
              <dd>
                {new Date(d.provenance.modified_at).toLocaleString()} <span className="muted">({relTime(d.provenance.modified_at)})</span>
              </dd>
              <dt>Reproduce</dt>
              <dd>
                <code>{d.provenance.command}</code>
              </dd>
              <dt>Scenario hashes</dt>
              <dd>
                {d.provenance.stale.length === 0 ? (
                  <span className="badge ALLOW">
                    <span className="glyph">✓</span>match frozen files
                  </span>
                ) : (
                  <span className="badge BLOCK">
                    <span className="glyph">✕</span>
                    {d.provenance.stale.length} mismatch(es): {d.provenance.stale.map((x) => `${x.id} (${x.issue})`).join(", ")}
                  </span>
                )}
              </dd>
            </dl>
          </Card>

          <Card title="Baseline comparison" hint="per-trajectory · B1 to B4 · hybrid not built" flush>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Configuration</th>
                    <th>Detection rate</th>
                    <th>False-positive rate</th>
                    <th className="num">Flagged in time</th>
                    <th className="num">Mean steps before harm</th>
                  </tr>
                </thead>
                <tbody>
                  {d.baselines.map((b) => (
                    <BaselineRow key={b.id} b={b} />
                  ))}
                  <tr>
                    <td>
                      <div className="cell-title">
                        <span className="chip mono">H</span> Hybrid ARGUS (rules + ML + LLM)
                      </div>
                      <div className="cell-sub">Risk engine not built; blocked on gate G4.</div>
                    </td>
                    <td>
                      <Todo />
                    </td>
                    <td>
                      <Todo />
                    </td>
                    <td className="num">
                      <Todo>—</Todo>
                    </td>
                    <td className="num">
                      <Todo>—</Todo>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="small muted" style={{ padding: "10px 16px 14px", borderTop: "1px solid var(--border)" }}>
              "Flagged in time" = first flag at or before the labelled first unsafe step. Steps before harm = first unsafe
              step minus first flag (0 = flagged on the unsafe step itself; positive = earlier). Derived server-side from the
              logged rows. No CIs: N = {d.baselines[0]?.n_attack ?? 0} attacks / {d.baselines[0]?.n_benign ?? 0} benign.
            </p>
          </Card>

          <div className="grid cols-3">
            <Card title="Prefix AUROC">
              <div className="stat-value" style={{ marginTop: 0 }}>
                {typeof d.summary.prefix_auroc_unsafe_vs_benign === "number" ? (
                  fixed(d.summary.prefix_auroc_unsafe_vs_benign)
                ) : (
                  <Todo>{d.summary.prefix_auroc_unsafe_vs_benign}</Todo>
                )}
              </div>
              <p className="small muted">Unsafe-labelled attack prefixes vs all hard-benign prefixes; 0.5 = chance.</p>
            </Card>
            <Card title="ML threshold">
              <div className="stat-value" style={{ marginTop: 0 }}>
                {fixed(d.summary.ml_threshold_benign_p90)}
              </div>
              <p className="small muted">90th percentile of benign prefix scores (in-sample: fit and threshold use the same data).</p>
            </Card>
            <Card title="p95 gate latency">
              <div className="stat-value" style={{ marginTop: 0 }}>
                <Todo />
              </div>
              <p className="small muted">Pre-registered S4 target: ≤ 100 ms per call without LLM.</p>
            </Card>
          </div>

          <Card title="Per-scenario first detection" hint="step index where each detector first flags" flush>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Scenario</th>
                    <th>Type</th>
                    <th className="num">First unsafe</th>
                    <th>Rules (B2)</th>
                    <th>ML (B3)</th>
                    <th>Mock LLM (B4)</th>
                    <th>SHA</th>
                  </tr>
                </thead>
                <tbody>
                  {d.rows.map((r) => (
                    <tr key={r.id}>
                      <td>
                        <a href={`#/scenarios/${encodeURIComponent(r.id)}`}>{r.id}</a>
                        <div className="cell-sub mono">{r.family}</div>
                      </td>
                      <td>
                        <TypeChip type={r.type} />
                      </td>
                      <td className="num">{r.first_unsafe_step ?? "—"}</td>
                      <td>
                        <DetectionCell at={r.detect_rules} firstUnsafe={r.first_unsafe_step} type={r.type} />
                      </td>
                      <td>
                        <DetectionCell at={r.detect_ml} firstUnsafe={r.first_unsafe_step} type={r.type} />
                      </td>
                      <td>
                        <DetectionCell at={r.detect_llm_mock} firstUnsafe={r.first_unsafe_step} type={r.type} />
                      </td>
                      <td className="mono small muted" title={r.sha256}>
                        {shortSha(r.sha256)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Callout icon="ⓘ" title="Limitations recorded with this run">
            {d.summary.note}
          </Callout>
        </>
      )}
    </div>
  );
}
