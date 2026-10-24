import { useState } from "react";
import { api } from "../api";
import { useAsync } from "../hooks";
import { Callout, Card, ErrorState, Loading, relTime, shortSha } from "../components/ui";
import { Explanation, LevelBadge } from "../components/risk";
import type { VerifyResult } from "../research-types";

function Detail({ id }: { id: string }) {
  const q = useAsync(() => api.forensic(id), [id]);
  const [v, setV] = useState<VerifyResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const verify = async () => {
    setErr(null);
    try {
      setV(await api.verify(id));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };
  if (q.loading) return <Loading rows={6} />;
  if (q.error) return <ErrorState error={q.error} />;
  const s = q.data!.snapshot;
  return (
    <div className="stack">
      <Card
        title="Forensic snapshot"
        hint={q.data!.path}
        actions={
          <button className="btn primary" onClick={() => void verify()}>
            Verify sha256
          </button>
        }
      >
        <div className="stack" style={{ gap: 10 }}>
          {v && (
            <Callout tone={v.ok ? "info" : "critical"} icon={v.ok ? "✓" : "✕"} title={v.ok ? "Integrity verified" : "Tampered"}>
              {v.detail}. Stored <code>{shortSha(v.stored_sha256)}…</code>
            </Callout>
          )}
          {err && <span className="form-error">{err}</span>}
          <dl className="kv">
            <dt>Session</dt>
            <dd className="mono small">{s.session_id}</dd>
            <dt>Written</dt>
            <dd>
              {new Date(s.created_at).toLocaleString()} ({relTime(s.created_at)}), once (write-once file)
            </dd>
            <dt>sha256</dt>
            <dd className="mono small">{s.sha256}</dd>
            <dt>Objective</dt>
            <dd>{s.objective.text}</dd>
            <dt>Containment</dt>
            <dd>
              network cut: {s.network_cut ? "yes" : "no"} · capabilities revoked: {s.capabilities_revoked ? "yes" : "no"}
            </dd>
            <dt>Files the agent wrote</dt>
            <dd>{Object.keys(s.files_written).length === 0 ? <span className="muted">none</span> : Object.keys(s.files_written).join(", ")}</dd>
            <dt>Egress (redacted)</dt>
            <dd>{s.egress.length === 0 ? <span className="muted">none</span> : s.egress.map((e) => e.url).join(", ")}</dd>
          </dl>
        </div>
      </Card>
      <div className="split">
        <Card title={`Trigger: step ${s.trigger.step}`} hint={s.trigger.tool}>
          <Explanation d={s.trigger} />
        </Card>
        <Card title="Events before quarantine" flush>
          <ul className="list">
            {s.events.map((e) => {
              const d = s.decisions.find((x) => x.step === e.step);
              return (
                <li key={e.step}>
                  <span className="num">{e.step}</span>
                  <span className="mono">{e.tool}</span>
                  <span className="grow target small">{e.target}</span>
                  {d ? <LevelBadge level={d.level} /> : <span className="small muted">blocked</span>}
                </li>
              );
            })}
          </ul>
        </Card>
      </div>
    </div>
  );
}

export function Forensics({ id }: { id: string | null }) {
  const list = useAsync(() => api.forensics(), []);
  return (
    <div className="stack">
      <header className="page-head">
        <div>
          {id && (
            <div className="crumbs">
              <a href="#/forensics">Forensics</a> / {id.slice(0, 8)}
            </div>
          )}
          <h1>Forensics</h1>
          <p>
            Each quarantine writes one snapshot (events, decisions, files written, egress; secrets redacted) with a sha256
            over its body. The file is created write-once and is never overwritten; verification recomputes the hash on the
            server.
          </p>
        </div>
      </header>
      {id ? (
        <Detail id={id} />
      ) : (
        <Card title="Snapshots from this server's sessions" flush>
          {list.loading && (
            <div className="card-body">
              <Loading />
            </div>
          )}
          {list.error && (
            <div className="card-body">
              <ErrorState error={list.error} />
            </div>
          )}
          {list.data && list.data.length === 0 && <div className="card-body muted small">No quarantines yet.</div>}
          {list.data && list.data.length > 0 && (
            <ul className="list">
              {list.data.map((f) => (
                <li key={f.session_id}>
                  <LevelBadge level={f.trigger.level} />
                  <a className="mono" href={`#/forensics/${f.session_id}`}>
                    {f.session_id.slice(0, 8)}
                  </a>
                  <span className="grow wrap small">
                    step {f.trigger.step} {f.trigger.tool}
                    {f.trigger.policy_rule ? ` · policy ${f.trigger.policy_rule}` : " · risk score"} · {f.objective}
                  </span>
                  <span className="small muted">{relTime(f.created_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
    </div>
  );
}
