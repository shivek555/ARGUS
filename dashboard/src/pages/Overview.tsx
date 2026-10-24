import { api } from "../api";
import { useAsync } from "../hooks";
import { Callout, Card, ErrorState, Loading, Stat, pct, shortSha } from "../components/ui";
import type { Latency, R4Dev } from "../research-types";

const RQ = [
  ["RQ1", "Can trajectories separate benign from unsafe behaviour?"],
  ["RQ2", "Can unsafe behaviour be flagged before the harmful action completes?"],
  ["RQ3", "Does detection hold on attack families held out of training (open-set)?"],
  ["RQ4", "Does the hybrid (rules + ML + LLM) beat each component alone?"],
  ["RQ5", "What latency and compute overhead does ARGUS add?"],
  ["RQ6", "Can an adaptive adversarial agent evade it? (R5, not started)"],
];

const plain = (s: string) => s.replace(/\*\*/g, "").replace(/`/g, "");

function tone(status: string): string {
  const s = status.toLowerCase();
  if (s.includes("fail")) return "BLOCK";
  if (s.includes("pass") || s.includes("done") || s.includes("frozen")) return "ALLOW";
  if (s.includes("not started") || s.includes("pending")) return "neutral";
  return "MONITOR";
}

export function Overview() {
  const meta = useAsync(() => api.meta(), []);
  const status = useAsync(() => api.status(), []);
  const r4 = useAsync(() => api.result<R4Dev>("r4_dev"), []);
  const lat = useAsync(() => api.result<Latency>("latency-laptop"), []);
  const d = r4.data?.dev;
  const hy = d?.methods["Hybrid"];
  const best = d ? d.methods[d.best_component] : undefined;

  return (
    <div className="stack">
      <header className="page-head">
        <div>
          <h1>ARGUS: runtime behavioural security for AI agents</h1>
          <p>
            Every tool call an agent makes passes one gateway. ARGUS scores it with policy rules, a trajectory anomaly
            detector and an LLM intent monitor, combines them into one calibrated, explained risk score, and contains
            the agent when the risk is high. Evaluated under controlled scenarios with synthetic, author-written attacks
            and fake tools.
          </p>
        </div>
        <a className="btn primary" href="#/demo">
          ▶ Start the demo
        </a>
      </header>

      {r4.error && <ErrorState error={r4.error} onRetry={r4.reload} />}
      {d && hy && best && (
        <>
          <div className="grid cols-4">
            <Stat label="Hybrid detection (dev)" value={pct(hy.dr)} sub={`attacks flagged ≥ HIGH · ${hy.n_attack} attacks`} />
            <Stat label="Benign false alarms (dev)" value={pct(hy.fpr)} sub={`budget ≤ ${pct(d.budget)} · ${hy.n_benign} benign`} />
            <Stat label={`Best single component`} value={pct(best.dr)} sub={d.best_component.replace(/_/g, " ")} />
            <Stat
              label="Seed variance (dev)"
              value={`${pct(d.seeds.dr.mean)} ± ${pct(d.seeds.dr.std)}`}
              sub="hybrid DR over 5 training resamples"
            />
          </div>
          <Callout tone="warning" icon="▲" title="Read these numbers with their label">
            Dev data, out-of-fold, exploratory. The risk weights were learned on dev attack shapes, refits on resampled
            data vary from 33% to 100%, and the official G5/G6 verdicts come only from the single blind test-v2 run
            (not yet run).
          </Callout>
        </>
      )}

      <div className="split">
        <Card title="Research questions">
          <ul className="list">
            {RQ.map(([id, q]) => (
              <li key={id}>
                <span className="chip mono">{id}</span>
                <span className="grow wrap">{q}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Gates" hint={status.data ? `from ${status.data.source}` : undefined}>
          {status.loading && <Loading />}
          {status.error && <ErrorState error={status.error} />}
          {status.data && (
            <ul className="list">
              {status.data.gates.map((g) => (
                <li key={g.gate}>
                  <span className={`badge ${tone(g.status)}`}>{g.gate.split(" ")[0]}</span>
                  <span className="grow wrap small">
                    <b>{plain(g.gate)}</b> · {plain(g.status)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Phases" hint="roadmap (ADR-0003)" flush>
        {status.data && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Phase</th>
                  <th>Focus</th>
                  <th>Gate</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {status.data.phases.map((p) => (
                  <tr key={p.phase}>
                    <td className="mono">{p.phase}</td>
                    <td className="small">{plain(p.focus)}</td>
                    <td className="small">{plain(p.gate)}</td>
                    <td className="small">{plain(p.status)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="split">
        <Card title="What is frozen" hint="nothing below changes before the test-v2 run">
          {meta.data && (
            <dl className="kv">
              <dt>ML detector</dt>
              <dd>
                <code>{meta.data.frozen.ml.config}</code> ({meta.data.frozen.ml.adr})
              </dd>
              <dt>LLM monitor</dt>
              <dd>
                <code>{meta.data.frozen.llm.model}</code>, prompt {meta.data.frozen.llm.prompt} ({meta.data.frozen.llm.adr}),{" "}
                {meta.data.frozen.llm.mode}
              </dd>
              <dt>Risk model</dt>
              <dd className="mono small">
                model.json {shortSha(meta.data.frozen.risk_model.sha256["model.json"] ?? "")} · levels.yaml{" "}
                {shortSha(meta.data.frozen.risk_model.sha256["levels.yaml"] ?? "")}
              </dd>
              <dt>R4 protocol</dt>
              <dd className="mono small">manifest {shortSha(meta.data.frozen.r4_manifest.sha256)}</dd>
              <dt>Policy</dt>
              <dd>
                <code>{meta.data.policy.path}</code>
              </dd>
            </dl>
          )}
        </Card>
        <Card title="Overhead (RQ5)" hint={lat.data ? lat.data.host.platform : undefined}>
          {lat.error && <span className="muted small">No latency file yet: run python -m argus.eval.latency --doc docs/results/latency-laptop.md</span>}
          {lat.data && (
            <dl className="kv">
              <dt>ARGUS without LLM</dt>
              <dd className="num">
                {lat.data.argus_without_llm_per_call.p50_ms.toFixed(1)} ms p50 · {lat.data.argus_without_llm_per_call.p95_ms.toFixed(1)} ms p95
                per call
              </dd>
              <dt>LLM monitor (CPU)</dt>
              <dd className="num">
                {(lat.data.llm_per_risky_call.p50_ms / 1000).toFixed(1)} s p50 · {(lat.data.llm_per_risky_call.p95_ms / 1000).toFixed(1)} s p95
                on {pct(lat.data.risky_call_fraction)} of calls (risky only)
              </dd>
              <dt>L5 (LLM p95 ≤ 2 s)</dt>
              <dd>{lat.data.l5_p95_le_2s ? "pass" : "fail (reported, not hidden)"}</dd>
            </dl>
          )}
        </Card>
      </div>
    </div>
  );
}
