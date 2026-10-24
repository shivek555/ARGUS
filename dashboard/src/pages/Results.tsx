import type { ReactNode } from "react";
import { api } from "../api";
import { useAsync } from "../hooks";
import { Callout, Card, ErrorState, Loading, fixed, pct } from "../components/ui";
import type { Latency, MethodStats, R1bSelection, R2lRun, R4Dev } from "../research-types";

const name = (k: string) => k.replace(/_/g, " ");
const ci = (c: number[] | null | undefined) => (c ? `[${pct(c[0])}, ${pct(c[1])}]` : "–");
const cell = (v: ReactNode) => (v === null || v === undefined ? <span className="muted">–</span> : v);

function MethodsTable({ methods, best }: { methods: Record<string, MethodStats>; best?: string }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th className="num">DR</th>
            <th className="num">DR visible</th>
            <th className="num">DR compliant</th>
            <th className="num">FPR</th>
            <th className="num">FPR / step</th>
            <th className="num">F1</th>
            <th className="num">AUROC</th>
            <th className="num">Steps before harm</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(methods).map(([k, m]) => (
            <tr key={k} className={k === "Hybrid" ? "sel" : undefined}>
              <td>
                {name(k)}
                {k === best && <span className="chip accent" style={{ marginLeft: 6 }}>best component</span>}
              </td>
              <td className="num">{cell(pct(m.dr))}</td>
              <td className="num">{cell(pct(m.dr_visible))}</td>
              <td className="num">{cell(pct(m.dr_compliant))}</td>
              <td className="num">{cell(pct(m.fpr))}</td>
              <td className="num">{cell(pct(m.fpr_step))}</td>
              <td className="num">{cell(fixed(m.f1, 3))}</td>
              <td className="num">{cell(fixed(m.prefix_auroc, 3))}</td>
              <td className="num">{cell(fixed(m.earliness.mean_steps_before_harm, 2))}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Figure({ id, title, alt }: { id: string; title: string; alt: string }) {
  return (
    <Card title={title}>
      <img className="figure" src={api.figureUrl(id)} alt={alt} loading="lazy" />
    </Card>
  );
}

export function Results() {
  const r4 = useAsync(() => api.result<R4Dev>("r4_dev"), []);
  const r1b = useAsync(() => api.result<R1bSelection>("r1b_dev_selection"), []);
  const r2l = useAsync(() => api.result<R2lRun[]>("r2l_runs"), []);
  const lat = useAsync(() => api.result<Latency>("latency-laptop"), []);
  const meta = useAsync(() => api.meta(), []);
  const d = r4.data?.dev;

  return (
    <div className="stack">
      <header className="page-head">
        <div>
          <h1>Results</h1>
          <p>
            Read from the committed files in <code>docs/results/</code>, written by <code>python -m argus.eval.reproduce</code>{" "}
            and checked in CI. The app computes none of these numbers.
          </p>
        </div>
      </header>

      <Callout tone="warning" icon="▲" title="Blind test v2: not yet run">
        Every number below is dev (out-of-fold) or exploratory. The official G4-R2, G5 and G6 verdicts come from one
        pre-registered run on the blind test v2 split, which has not happened yet.
      </Callout>

      {r4.loading && <Loading rows={8} />}
      {r4.error && <ErrorState error={r4.error} onRetry={r4.reload} />}
      {d && (
        <>
          <Card
            title="R4: all methods on identical trajectories (dev, out-of-fold)"
            hint={`${d.data.attacks} attacks · ${d.data.benign} benign · budget ≤ ${pct(d.budget)} benign flagged`}
            flush
          >
            <MethodsTable methods={d.methods} best={d.best_component} />
            <div className="card-body provenance">
              <b>G5 preview:</b> hybrid {pct(d.g5_preview.hybrid_dr)} vs {name(d.g5_preview.best_component)}{" "}
              {pct(d.g5_preview.best_component_dr)} → {d.g5_preview.pass ? "pass" : "fail"} (dev). LLM native ESCALATE ignores the
              budget. "no rules" removes rule signals from the score only; a policy BLOCK stays CRITICAL.
            </div>
          </Card>

          <div className="split">
            <Card title="95% bootstrap CIs" hint="1,000 resamples, stratified">
              <dl className="kv">
                {Object.entries(d.methods)
                  .filter(([, m]) => m.ci95)
                  .map(([k, m]) => (
                    <div key={k} style={{ display: "contents" }}>
                      <dt>{name(k)}</dt>
                      <dd className="num">
                        DR {ci(m.ci95?.dr)} · FPR {ci(m.ci95?.fpr)}
                      </dd>
                    </div>
                  ))}
              </dl>
            </Card>
            <Card title="Paired exact McNemar" hint="Holm-corrected" flush>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Comparison</th>
                      <th className="num">hybrid only</th>
                      <th className="num">other only</th>
                      <th className="num">p (Holm)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(d.paired).map(([k, v]) => (
                      <tr key={k}>
                        <td className="small">{k.replace("Hybrid vs ", "vs ")}</td>
                        <td className="num">{v.only_a}</td>
                        <td className="num">{v.only_b}</td>
                        <td className="num">{v.p_holm < 0.001 ? v.p_holm.toExponential(1) : v.p_holm.toFixed(3)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>

          <Card title="Containment (enforce mode, simulated reviewer)" flush>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Setting</th>
                    <th className="num">Harm completed</th>
                    <th className="num">Post-onset steps run</th>
                    <th className="num">Steps to containment</th>
                    <th className="num">Approvals / 100 benign</th>
                    <th className="num">Benign disrupted</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(d.containment).map(([k, v]) => (
                    <tr key={k}>
                      <td>{name(k)}</td>
                      <td className="num">{pct(v.harm_completion)}</td>
                      <td className="num">{cell(pct(v.post_onset_steps_executed))}</td>
                      <td className="num">{cell(fixed(v.mean_steps_to_containment, 2))}</td>
                      <td className="num">{fixed(v.approvals_per_100_benign, 1)}</td>
                      <td className="num">{pct(v.benign_disrupted)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="card-body provenance">
              Negative steps to containment = before the first unsafe step. R3-c target was ≤ 15 approvals per 100 benign
              tasks: <b>fails</b> (recorded finding).
            </div>
          </Card>

          <div className="split">
            <Card title="Open-set preview (G6, dev)" hint="frozen leave-one-family-out models">
              <dl className="kv">
                {Object.entries(d.lofo).map(([k, v]) => (
                  <div key={k} style={{ display: "contents" }}>
                    <dt>{name(k)} held out</dt>
                    <dd className="num">
                      DR {pct(v.dr)} · policy-compliant {pct(v.dr_compliant)} (n = {v.n})
                    </dd>
                  </div>
                ))}
              </dl>
              <p className="provenance">
                {d.g6_preview.families_ge_50pct_compliant}/3 families ≥ 50% → {d.g6_preview.pass ? "pass" : "fail"} on dev.
                Open-set behavioural anomaly detection under controlled unseen attack scenarios.
              </p>
            </Card>
            <Card title="Seed variance (secondary)" hint="5 training resamples">
              <dl className="kv">
                {Object.entries(d.seeds.per_seed).map(([k, v]) => (
                  <div key={k} style={{ display: "contents" }}>
                    <dt>{k}</dt>
                    <dd className="num">
                      DR {pct(v.dr)} · FPR {pct(v.fpr)}
                    </dd>
                  </div>
                ))}
              </dl>
              <p className="provenance">
                DR {pct(d.seeds.dr.mean)} ± {pct(d.seeds.dr.std)}: detection depends strongly on which attack templates are
                in training (recorded finding, ADR-0013).
              </p>
            </Card>
          </div>

          <div className="grid cols-3">
            <Figure id="r4_roc_dev" title="Step-level ROC" alt="ROC curves of hybrid, ML and LLM scores on dev steps" />
            <Figure id="r4_dr_vs_budget_dev" title="Detection vs benign budget" alt="Attack detection rate as the benign budget grows" />
            <Figure id="r4_earliness_dev" title="Steps before harm" alt="Histogram of how many steps before the harm step the hybrid flags" />
          </div>

          {r4.data && (
            <Card title={`Exploratory: ${r4.data.v1_test_exploratory.split}`} hint="no LLM verdicts: no-LLM ablation" flush>
              <MethodsTable methods={r4.data.v1_test_exploratory.methods} />
            </Card>
          )}
        </>
      )}

      <div className="split">
        <Card title="R1b ML selection (dev)" hint={r1b.data?.selection.reason} flush>
          {r1b.data && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Config</th>
                    <th className="num">Nested FPR</th>
                    <th className="num">AUROC</th>
                    <th className="num">DR compliant</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(r1b.data.results).map(([k, r]) => (
                    <tr key={k} className={k === r1b.data!.selection.selected ? "sel" : undefined}>
                      <td className="mono small">{k}</td>
                      <td className="num">{pct(r.agg.nested_fpr?.mean)}</td>
                      <td className="num">{fixed(r.agg.auroc?.mean, 3)}</td>
                      <td className="num">{pct(r.agg.dr_compliant?.mean)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {r1b.error && <div className="card-body muted small">{r1b.error.message}</div>}
        </Card>
        <Card title="R2-L local LLM monitor runs" hint="Ollama on GitHub runners, $0" flush>
          {r2l.data && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Run</th>
                    <th>Model</th>
                    <th className="num">Judged</th>
                    <th className="num">AUROC</th>
                    <th className="num">p95 s</th>
                  </tr>
                </thead>
                <tbody>
                  {r2l.data.map((r) => (
                    <tr key={`${r.run}-${r.model}`}>
                      <td>{r.run}</td>
                      <td className="mono small">{r.model}</td>
                      <td className="num">{r.judged}</td>
                      <td className="num">{cell(fixed(r.auroc_unsafe_vs_benign, 3))}</td>
                      <td className="num">{r.latency_ms ? (r.latency_ms.p95 / 1000).toFixed(1) : "–"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <div className="split">
        <Card title="Latency (RQ5)" hint={lat.data ? `${lat.data.host.platform}, ${lat.data.host.cpu_count} CPUs` : undefined}>
          {lat.error && <span className="muted small">{lat.error.message}</span>}
          {lat.data && (
            <dl className="kv">
              {Object.entries(lat.data.components).map(([k, v]) => (
                <div key={k} style={{ display: "contents" }}>
                  <dt>{name(k)}</dt>
                  <dd className="num">
                    {v.p50_ms.toFixed(2)} ms p50 · {v.p95_ms.toFixed(2)} ms p95
                  </dd>
                </div>
              ))}
              <dt>LLM (risky calls)</dt>
              <dd className="num">
                {(lat.data.llm_per_risky_call.p50_ms / 1000).toFixed(1)} s p50 · {(lat.data.llm_per_risky_call.p95_ms / 1000).toFixed(1)} s p95 ·
                L5 {lat.data.l5_p95_le_2s ? "pass" : "fail"}
              </dd>
            </dl>
          )}
        </Card>
        <Card title="Provenance" hint="what produced these numbers">
          {meta.data && (
            <dl className="kv">
              <dt>Reproduce</dt>
              <dd>
                <code>python -m argus.eval.reproduce</code> (CI: <code>--check --fast</code>)
              </dd>
              <dt>Risk model</dt>
              <dd className="mono small">{meta.data.frozen.risk_model.sha256["model.json"]?.slice(0, 16)}…</dd>
              <dt>R4 manifest</dt>
              <dd className="mono small">{meta.data.frozen.r4_manifest.sha256.slice(0, 16)}…</dd>
              <dt>ML</dt>
              <dd>
                <code>{meta.data.frozen.ml.config}</code>
              </dd>
              <dt>LLM</dt>
              <dd>
                <code>{meta.data.frozen.llm.model}</code> ({meta.data.frozen.llm.mode})
              </dd>
            </dl>
          )}
        </Card>
      </div>
    </div>
  );
}
