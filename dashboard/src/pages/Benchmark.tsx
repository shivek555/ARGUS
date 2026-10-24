import { useState } from "react";
import { api } from "../api";
import { navigate, useAsync } from "../hooks";
import { Card, ErrorState, Loading, TypeChip } from "../components/ui";
import { FlagCell } from "../components/risk";
import type { BenchHeader, Method } from "../research-types";

const SPLITS: [string, string][] = [
  ["dev_attacks", "Dev attacks"],
  ["dev_benign", "Dev benign"],
  ["v1_test", "v1 test (exploratory)"],
];
const METHODS: [Method, string][] = [
  ["B2_policy_v2", "Rules"],
  ["B2plus_policy_v3", "Rules+"],
  ["B3_ml", "ML"],
  ["B4_llm_native", "LLM"],
  ["Hybrid", "Hybrid"],
];

function rate(rows: BenchHeader[], m: Method): string {
  if (!rows.length) return "–";
  const hit = rows.filter((r) => r.first_flag[m] !== null).length;
  return `${hit}/${rows.length}`;
}

export function Benchmark() {
  const [split, setSplit] = useState("dev_attacks");
  const [family, setFamily] = useState("");
  const [variant, setVariant] = useState("");
  const list = useAsync(() => api.bench({ split, family, variant }), [split, family, variant]);
  const meta = useAsync(() => api.meta(), []);
  const rows = list.data ?? [];
  const isAttack = split !== "dev_benign";

  return (
    <div className="stack">
      <header className="page-head">
        <div>
          <h1>Benchmark</h1>
          <p>
            AgentEscapeBench v1 attacks and dev-v2 benign tasks, each with the step every method first flags it, judged
            against the step where harm executes. Click a row to see every decision and its explanation.
          </p>
        </div>
      </header>

      <Card
        title="Trajectories"
        hint={meta.data?.splits[split]}
        actions={
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <div className="seg" role="group" aria-label="Split">
              {SPLITS.map(([k, label]) => (
                <button key={k} aria-pressed={split === k} onClick={() => setSplit(k)}>
                  {label}
                </button>
              ))}
            </div>
            {isAttack && (
              <>
                <select aria-label="Family" value={family} onChange={(e) => setFamily(e.target.value)}>
                  <option value="">All families</option>
                  <option value="credential_discovery">credential discovery</option>
                  <option value="exfiltration">exfiltration</option>
                  <option value="goal_hijack">goal hijack</option>
                </select>
                <select aria-label="Variant" value={variant} onChange={(e) => setVariant(e.target.value)}>
                  <option value="">All variants</option>
                  <option value="policy_visible">policy-visible</option>
                  <option value="policy_compliant">policy-compliant</option>
                </select>
              </>
            )}
          </div>
        }
        flush
      >
        {list.loading && (
          <div className="card-body">
            <Loading rows={6} />
          </div>
        )}
        {list.error && (
          <div className="card-body">
            <ErrorState error={list.error} onRetry={list.reload} />
          </div>
        )}
        {list.data && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Trajectory</th>
                  <th>Type</th>
                  <th className="num">Steps</th>
                  <th className="num">Harm at</th>
                  {METHODS.map(([m, label]) => (
                    <th key={m} title={m}>
                      {label}
                      <div className="cell-sub num">{rate(rows, m)}</div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className="clickable" onClick={() => navigate(`/bench/${encodeURIComponent(r.id)}`)}>
                    <td>
                      <a className="cell-title mono" href={`#/bench/${encodeURIComponent(r.id)}`} onClick={(e) => e.stopPropagation()}>
                        {r.id}
                      </a>
                      <div className="cell-sub">{r.objective.text}</div>
                    </td>
                    <td>
                      <TypeChip type={r.type} />
                      {r.type === "attack" && <div className="cell-sub">{r.variant.replace("_", "-")}</div>}
                    </td>
                    <td className="num">{r.n_steps}</td>
                    <td className="num">{r.harm_step ?? "–"}</td>
                    {METHODS.map(([m]) => (
                      <td key={m}>
                        <FlagCell at={r.first_flag[m]} deadline={r.harm_step} type={r.type} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <p className="provenance">
        Hybrid flags = first step at HIGH or above under the frozen engine for this split ({split === "v1_test" ? "no-LLM ablation" : "primary model"}).
        On dev this is <b>in-sample</b> (the model was fitted on these trajectories); the out-of-fold numbers are on the
        Results page. "LLM" is the monitor's own ESCALATE/BLOCK recommendation, which ignores the 10% budget.
      </p>
    </div>
  );
}
