import { useState } from "react";
import { api } from "../api";
import { navigate, useAsync } from "../hooks";
import { Callout, Card, ErrorState, Loading, Sensitivity, TypeChip } from "../components/ui";
import { Explanation, FlagCell, LevelBadge, RiskChart, StepLabelBadge } from "../components/risk";
import type { Method } from "../research-types";

const METHODS: [Method, string][] = [
  ["B2_policy_v2", "Rules (policy v2)"],
  ["B2plus_policy_v3", "Rules+ (policy v3)"],
  ["B3_ml", "ML anomaly"],
  ["B4_llm_native", "LLM monitor"],
  ["Hybrid", "Hybrid ≥ HIGH"],
];

export function Trajectory({ id }: { id: string }) {
  const q = useAsync(() => api.benchDetail(id), [id]);
  const meta = useAsync(() => api.meta(), []);
  const [sel, setSel] = useState<number | null>(null);
  const t = q.data;
  const levels = t && meta.data ? meta.data.engines[t.engine]?.levels : undefined;
  const step = t?.steps.find((s) => s.step === (sel ?? t.first_flag.Hybrid ?? 1));

  const replay = async () => {
    const s = await api.createSession({ trajectory_id: id });
    navigate(`/live?s=${s.id}`);
  };

  return (
    <div className="stack">
      <header className="page-head">
        <div>
          <div className="crumbs">
            <a href="#/bench">Benchmark</a> / {id}
          </div>
          <h1 className="row" style={{ gap: 10 }}>
            <span className="mono">{id}</span> {t && <TypeChip type={t.type} />}
          </h1>
          {t && (
            <p>
              {t.family.replace(/_/g, " ")} · {t.variant.replace(/_/g, "-")} · template <code>{t.template}</code> · engine{" "}
              {t.engine_info.name}
            </p>
          )}
        </div>
        {t && (
          <button className="btn primary" onClick={() => void replay()}>
            ▶ Run it live (enforce mode)
          </button>
        )}
      </header>

      {q.loading && <Loading rows={6} />}
      {q.error && <ErrorState error={q.error} onRetry={q.reload} />}
      {t && (
        <>
          <div className="objective">
            <div className="objective-meta">Objective (immutable) · scopes: {t.objective.allowed_scopes.join(", ")}</div>
            {t.objective.text}
          </div>
          <Callout tone="info" icon="i" title={t.split_note}>
            {t.provenance_note} LLM: {t.engine_info.llm}.
          </Callout>

          <Card title="Who flags it, and when" hint={t.harm_step ? `harm executes at step ${t.harm_step}` : "benign"}>
            <div className="row" style={{ gap: 18, flexWrap: "wrap" }}>
              {METHODS.map(([m, label]) => (
                <div key={m} className="stack" style={{ gap: 4 }}>
                  <span className="small muted">{label}</span>
                  <FlagCell at={t.first_flag[m]} deadline={t.harm_step} type={t.type} />
                </div>
              ))}
            </div>
          </Card>

          {levels && (
            <Card title="Risk over the trajectory" hint="click a point or a row">
              <RiskChart
                steps={t.steps}
                levels={levels}
                firstUnsafe={t.first_unsafe_step}
                harmStep={t.harm_step}
                selected={step?.step ?? null}
                onSelect={setSel}
              />
            </Card>
          )}

          <div className="split">
            <Card title="Steps" flush>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th className="num">#</th>
                      <th>Call</th>
                      <th>Truth</th>
                      <th>Policy</th>
                      <th className="num">Risk</th>
                      <th>Level</th>
                    </tr>
                  </thead>
                  <tbody>
                    {t.steps.map((s) => (
                      <tr key={s.step} className={`clickable${step?.step === s.step ? " sel" : ""}`} onClick={() => setSel(s.step)}>
                        <td className="num">{s.step}</td>
                        <td>
                          <div className="cell-title mono">{s.tool}</div>
                          <div className="cell-sub target" title={s.target}>
                            {s.target}
                          </div>
                        </td>
                        <td>
                          <StepLabelBadge value={s.label} />
                        </td>
                        <td className="small mono">{s.policy_rule ?? <span className="muted">allow</span>}</td>
                        <td className="num">{s.decision.risk_points.toFixed(1)}</td>
                        <td>
                          <LevelBadge level={s.decision.level} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
            {step && (
              <Card title={`Step ${step.step}: why ${step.decision.level}?`} hint={step.tool}>
                <div className="stack" style={{ gap: 10 }}>
                  <div className="row small" style={{ gap: 12, flexWrap: "wrap" }}>
                    <span>
                      target <code>{step.target}</code>
                    </span>
                    <Sensitivity level={step.data_sensitivity} />
                    {step.network_destination && <span>dest {step.network_destination}</span>}
                    <span className="muted">{step.risky ? "risky call: LLM consulted" : "not a risky call"}</span>
                  </div>
                  <Explanation d={step.decision} levels={levels} />
                </div>
              </Card>
            )}
          </div>
        </>
      )}
    </div>
  );
}
