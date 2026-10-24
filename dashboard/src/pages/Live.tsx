import { useState } from "react";
import { api } from "../api";
import { navigate, useAsync } from "../hooks";
import { Callout, Card, ErrorState, Loading } from "../components/ui";
import { Explanation, LevelBadge, StatusBadge, StepLabelBadge } from "../components/risk";
import { DecideButtons, ReviewerField, useReviewer } from "./Approvals";
import type { LiveSession } from "../research-types";

const TOOL_ARGS: Record<string, string[]> = {
  fs_read: ["path"],
  fs_list: ["path"],
  fs_write: ["path", "content"],
  http_post: ["url", "body"],
  repo_search: ["query"],
  creds_list: [],
};
const DEFAULTS: Record<string, string> = {
  path: "/workspace/README.md",
  content: "notes",
  url: "https://fake.local/api",
  body: "summary",
  query: "TODO",
};

function NewSession() {
  const meta = useAsync(() => api.meta(), []);
  const demo = useAsync(() => api.demo(), []);
  const [tid, setTid] = useState("");
  const [text, setText] = useState("Summarize /workspace/README.md for a new team member.");
  const [scopes, setScopes] = useState<string[]>(["workspace_read"]);
  const [err, setErr] = useState<string | null>(null);
  const start = async (body: Parameters<typeof api.createSession>[0]) => {
    setErr(null);
    try {
      const s = await api.createSession(body);
      navigate(`/live?s=${s.id}`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };
  const examples = (demo.data?.beats ?? []).filter((b) => b.trajectory_id);
  return (
    <div className="split">
      <Card title="Replay a benchmark trajectory" hint="primary model, LLM verdicts replayed">
        <div className="stack" style={{ gap: 10 }}>
          <p className="small ink2">
            The recorded agent's calls are sent one by one through the enforce-mode gateway. Signals are the precomputed
            ones from the evaluation, so you cannot add your own calls to these sessions.
          </p>
          <input list="traj-examples" value={tid} onChange={(e) => setTid(e.target.value)} placeholder="trajectory id, e.g. dev-exfil_compliant-000" />
          <datalist id="traj-examples">
            {examples.map((b) => (
              <option key={b.id} value={b.trajectory_id}>
                {b.title}
              </option>
            ))}
          </datalist>
          <div>
            <button className="btn primary" disabled={!tid.trim()} onClick={() => void start({ trajectory_id: tid.trim() })}>
              ▶ Start replay
            </button>
          </div>
        </div>
      </Card>
      <Card title="Custom session" hint="your own calls · no-LLM model">
        <div className="stack" style={{ gap: 10 }}>
          <p className="small ink2">
            Type an objective, then send tool calls by hand. No LLM verdict exists for new input (and no model runs in the
            app), so this uses the frozen no-LLM ablation.
          </p>
          <textarea rows={2} value={text} onChange={(e) => setText(e.target.value)} maxLength={2000} />
          <div className="checks">
            {(meta.data?.known_scopes ?? ["workspace_read", "egress", "secrets-audit"]).map((s) => (
              <label key={s} className="check">
                <input
                  type="checkbox"
                  checked={scopes.includes(s)}
                  onChange={(e) => setScopes(e.target.checked ? [...scopes, s] : scopes.filter((x) => x !== s))}
                />
                {s}
              </label>
            ))}
          </div>
          <div>
            <button className="btn primary" disabled={!text.trim()} onClick={() => void start({ objective_text: text, allowed_scopes: scopes })}>
              ▶ Start custom session
            </button>
          </div>
        </div>
      </Card>
      {err && <ErrorState error={new Error(err)} />}
    </div>
  );
}

function CallForm({ s, onState }: { s: LiveSession; onState: (s: LiveSession) => void }) {
  const [tool, setTool] = useState("fs_read");
  const [args, setArgs] = useState<Record<string, string>>({ path: DEFAULTS.path! });
  const [err, setErr] = useState<string | null>(null);
  const pick = (t: string) => {
    setTool(t);
    setArgs(Object.fromEntries((TOOL_ARGS[t] ?? []).map((a) => [a, DEFAULTS[a] ?? ""])));
  };
  const send = async () => {
    setErr(null);
    try {
      onState(await api.call(s.id, tool, args));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };
  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <select value={tool} onChange={(e) => pick(e.target.value)} aria-label="Tool">
          {Object.keys(TOOL_ARGS).map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
        {(TOOL_ARGS[tool] ?? []).map((a) => (
          <input key={a} aria-label={a} placeholder={a} value={args[a] ?? ""} onChange={(e) => setArgs({ ...args, [a]: e.target.value })} style={{ minWidth: 220 }} />
        ))}
        <button className="btn primary" onClick={() => void send()}>
          Send call
        </button>
      </div>
      {err && <span className="form-error">{err}</span>}
    </div>
  );
}

export function SessionView({ s, onState, compact }: { s: LiveSession; onState: (s: LiveSession) => void; compact?: boolean }) {
  const [sel, setSel] = useState<number | null>(null);
  const [reviewer, setReviewer] = useReviewer();
  const [err, setErr] = useState<string | null>(null);
  const meta = useAsync(() => api.meta(), []);
  const levels = meta.data?.engines[s.engine]?.levels;
  const rec = s.records.find((r) => r.step === sel) ?? [...s.records].reverse().find((r) => r.decision);
  const next = async () => {
    setErr(null);
    try {
      onState(await api.scriptNext(s.id));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };
  const held = s.records.filter((r) => r.status === "held" && r.queue === "pending");
  return (
    <div className="stack">
      {s.quarantined && (
        <Callout tone="critical" icon="✕" title="Agent quarantined">
          Every tool, including the network, is revoked; later calls are blocked.{" "}
          {s.snapshot && <a href={`#/forensics/${s.snapshot}`}>Open the forensic snapshot →</a>}
        </Callout>
      )}
      <div className="objective">
        <div className="objective-meta">
          {s.kind === "bench" ? `Replay of ${s.trajectory_id}` : "Custom session"} · {s.engine_info.name} · scopes:{" "}
          {s.objective.allowed_scopes.join(", ") || "none"}
        </div>
        {s.objective.text}
      </div>
      {held.length > 0 && (
        <Card title="Waiting for a human" hint="the call has not run">
          <div className="stack" style={{ gap: 8 }}>
            <ReviewerField name={reviewer} setName={setReviewer} />
            {held.map((r) => (
              <div key={r.step} className="row" style={{ gap: 10, flexWrap: "wrap" }}>
                <span className="mono">
                  step {r.step}: {r.tool} {r.target}
                </span>
                <DecideButtons item={{ id: r.approval_id! }} reviewer={reviewer} onDone={onState} />
              </div>
            ))}
          </div>
        </Card>
      )}
      <Card
        title="Calls"
        hint={s.script ? `${s.script.position}/${s.script.total} scripted calls sent` : `${s.records.length} calls`}
        actions={
          s.kind === "bench" ? (
            <button className="btn primary" disabled={!s.script?.next_tool || s.quarantined || held.length > 0} onClick={() => void next()}>
              {s.script?.next_tool ? `▶ Next call (${s.script.next_tool})` : "Script finished"}
            </button>
          ) : undefined
        }
        flush
      >
        {s.kind === "custom" && !s.quarantined && (
          <div className="card-body">
            <CallForm s={s} onState={onState} />
          </div>
        )}
        {err && (
          <div className="card-body">
            <span className="form-error">{err}</span>
          </div>
        )}
        {s.records.length === 0 ? (
          <div className="card-body muted small">No calls yet.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th className="num">#</th>
                  <th>Call</th>
                  {s.kind === "bench" && <th>Truth</th>}
                  <th className="num">Risk</th>
                  <th>Level</th>
                  <th>Outcome</th>
                </tr>
              </thead>
              <tbody>
                {s.records.map((r) => (
                  <tr key={r.step} className={`clickable${rec?.step === r.step ? " sel" : ""}`} onClick={() => setSel(r.step)}>
                    <td className="num">{r.step}</td>
                    <td>
                      <div className="cell-title mono">{r.tool}</div>
                      <div className="cell-sub target">{r.target}</div>
                    </td>
                    {s.kind === "bench" && (
                      <td>
                        <StepLabelBadge value={r.label} />
                      </td>
                    )}
                    <td className="num">{r.decision ? r.decision.risk_points.toFixed(1) : "–"}</td>
                    <td>{r.decision ? <LevelBadge level={r.decision.level} /> : <span className="muted small">—</span>}</td>
                    <td>
                      <StatusBadge status={r.status} />
                      {r.reason && <div className="cell-sub">{r.reason}</div>}
                      {r.queue && r.queue !== "pending" && (
                        <div className="cell-sub">
                          human: {r.queue}
                          {r.reviewer ? ` (${r.reviewer})` : ""}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {rec?.decision && (
        <Card title={`Step ${rec.step}: why ${rec.decision.level}?`} hint={rec.tool}>
          <Explanation d={rec.decision} levels={levels} />
        </Card>
      )}
      {!compact && (
        <Card title="Fake world" hint="in-process only; no real network">
          <dl className="kv">
            <dt>Uploads (egress sink)</dt>
            <dd>{s.world.http_sink.length === 0 ? <span className="muted">none</span> : s.world.http_sink.map((h) => h.url).join(", ")}</dd>
            <dt>Files written</dt>
            <dd>{s.world.files_written.length === 0 ? <span className="muted">none</span> : s.world.files_written.map((f) => f.path).join(", ")}</dd>
            <dt>Tools still available</dt>
            <dd>{s.tools_available.length === 0 ? <b>none (revoked)</b> : s.tools_available.join(", ")}</dd>
          </dl>
        </Card>
      )}
    </div>
  );
}

export function Live({ sessionId }: { sessionId: string | null }) {
  const q = useAsync(() => (sessionId ? api.session(sessionId) : Promise.resolve(null)), [sessionId]);
  return (
    <div className="stack">
      <header className="page-head">
        <div>
          <h1>Live session</h1>
          <p>
            Calls go through <code>ContainedSession</code> in enforce mode: LOW and MEDIUM run (if the policy allows), HIGH
            waits for a human, CRITICAL quarantines the agent and writes a forensic snapshot.
          </p>
        </div>
        {sessionId && (
          <a className="btn" href="#/live">
            + New session
          </a>
        )}
      </header>
      {!sessionId && <NewSession />}
      {sessionId && q.loading && !q.data && <Loading rows={5} />}
      {q.error && <ErrorState error={q.error} />}
      {q.data && <SessionView s={q.data} onState={q.setData} />}
    </div>
  );
}
