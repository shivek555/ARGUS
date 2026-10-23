import { api } from "../api";
import { navigate, useAsync } from "../hooks";
import { AnomalyChart } from "../components/AnomalyChart";
import { StepTable } from "../components/StepTable";
import { Callout, Card, ErrorState, Loading, TypeChip } from "../components/ui";
import { DetectionCell } from "./Scenarios";

export function ScenarioView({ id }: { id: string }) {
  const q = useAsync(() => api.scenario(id), [id]);
  const s = q.data;
  const threshold = s?.steps[0]?.anomaly.threshold;
  const missedUnsafe = s?.steps.filter((x) => x.label === "unsafe" && x.decision === "ALLOW") ?? [];

  return (
    <div className="stack">
      <header className="page-head">
        <div>
          <div className="crumbs">
            <a href="#/scenarios">Scenarios</a> / {id}
          </div>
          <h1 className="row">
            {id} {s && <TypeChip type={s.type} />}
          </h1>
          {s && (
            <p>
              Family <code>{s.family}</code> · {s.method ?? "unknown"} generation, seed {s.seed ?? "—"} · sha{" "}
              <code title={s.sha256}>{s.sha256.slice(0, 16)}…</code>
            </p>
          )}
        </div>
        {s && (
          <button className="btn primary" onClick={() => navigate(`/playground?scenario=${encodeURIComponent(s.id)}`)}>
            ▶ Replay in enforce mode
          </button>
        )}
      </header>

      {q.loading && <Loading rows={6} />}
      {q.error && <ErrorState error={q.error} onRetry={q.reload} />}

      {s && (
        <>
          <div className="split">
            <Card title="Authorised objective" hint="immutable · stored by the gateway, not the agent">
              <div className="objective">{s.objective.text}</div>
              <div className="objective-meta">
                <span className="small muted">Scopes</span>
                {s.objective.allowed_scopes.map((x) => (
                  <span key={x} className="chip mono accent">
                    {x}
                  </span>
                ))}
              </div>
            </Card>
            <Card title="First detection" hint="vs ground truth">
              <dl className="kv">
                <dt>First unsafe step</dt>
                <dd>{s.first_unsafe_step ?? "none (benign)"}</dd>
                <dt>Rules (B2)</dt>
                <dd>
                  <DetectionCell at={s.detections.rules} firstUnsafe={s.first_unsafe_step} type={s.type} />
                </dd>
                <dt>ML (B3)</dt>
                <dd>
                  <DetectionCell at={s.detections.ml} firstUnsafe={s.first_unsafe_step} type={s.type} />
                </dd>
                <dt>Mock LLM (B4)</dt>
                <dd>
                  <DetectionCell at={s.detections.llm_mock} firstUnsafe={s.first_unsafe_step} type={s.type} />
                </dd>
              </dl>
            </Card>
          </div>

          {missedUnsafe.length > 0 && (
            <Callout tone="warning" icon="▲" title={`${missedUnsafe.length} labelled-unsafe step(s) allowed by the gateway`}>
              Step{missedUnsafe.length > 1 ? "s" : ""} {missedUnsafe.map((x) => x.step).join(", ")} (
              {missedUnsafe.map((x) => x.tool).join(", ")}) passed every policy rule. Trajectory-level detection is
              meant to catch exactly this kind of follow-on action.
            </Callout>
          )}

          <Card title="Anomaly score over the trajectory" hint="Isolation Forest on prefix features · advisory only">
            {threshold !== undefined ? (
              <AnomalyChart steps={s.steps} firstUnsafe={s.first_unsafe_step} threshold={threshold} />
            ) : (
              <div className="empty">No steps.</div>
            )}
          </Card>

          <Card title="Step timeline" hint={s.mode_note} flush>
            <StepTable steps={s.steps} labelled mode="record" />
          </Card>
        </>
      )}
    </div>
  );
}
