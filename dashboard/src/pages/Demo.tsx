import { useEffect, useState } from "react";
import { api } from "../api";
import { navigate, useAsync } from "../hooks";
import { Callout, Card, ErrorState, Loading, pct } from "../components/ui";
import { SessionView } from "./Live";
import type { DemoBeat, LiveSession, R4Dev } from "../research-types";

const EXPECT_TEXT: Record<string, (v: unknown) => string> = {
  quarantined: (v) => (v ? "agent quarantined" : "no quarantine"),
  quarantine_step: (v) => `quarantined at step ${String(v)}`,
  held: (v) => ((v as number[]).length ? `held for a human at step ${(v as number[]).join(", ")}` : "nothing held"),
  all_executed: () => "every call runs",
  harm_executed: (v) => (v ? "harm executes" : "harm never executes"),
  harm_step: (v) => `harm would execute at step ${String(v)}`,
  snapshot_ok: () => "forensic snapshot verifies",
  trigger_rule: (v) => `triggered by policy rule ${String(v)}`,
  rules_first_flag: (v) => (v === null ? "policy v2 never fires" : `policy fires at step ${String(v)}`),
  statuses: (v) => `outcomes: ${(v as string[]).join(" → ")}`,
  results: () => "results load from docs/results",
};

function ResultsBeat() {
  const r4 = useAsync(() => api.result<R4Dev>("r4_dev"), []);
  const d = r4.data?.dev;
  if (r4.error) return <ErrorState error={r4.error} />;
  if (!d) return <Loading />;
  const hy = d.methods["Hybrid"]!;
  const best = d.methods[d.best_component]!;
  return (
    <div className="grid cols-4">
      <div className="card stat">
        <div className="stat-label">Hybrid detection</div>
        <div className="stat-value">{pct(hy.dr)}</div>
        <div className="stat-sub">at {pct(hy.fpr)} benign false alarms</div>
      </div>
      <div className="card stat">
        <div className="stat-label">Best single component</div>
        <div className="stat-value">{pct(best.dr)}</div>
        <div className="stat-sub">{d.best_component.replace(/_/g, " ")}</div>
      </div>
      <div className="card stat">
        <div className="stat-label">Seed refits</div>
        <div className="stat-value">
          {pct(d.seeds.dr.mean)} ± {pct(d.seeds.dr.std)}
        </div>
        <div className="stat-sub">depends on training templates</div>
      </div>
      <div className="card stat">
        <div className="stat-label">Without the LLM</div>
        <div className="stat-value">{pct(d.methods["Hybrid-no-llm"]?.dr)}</div>
        <div className="stat-sub">the LLM adds ≈ nothing</div>
      </div>
    </div>
  );
}

function BeatRunner({ beat }: { beat: DemoBeat }) {
  const [s, setS] = useState<LiveSession | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [callIdx, setCallIdx] = useState(0);
  useEffect(() => {
    setS(null);
    setCallIdx(0);
    setErr(null);
  }, [beat.id]);

  const start = async () => {
    setErr(null);
    try {
      setS(
        await api.createSession(
          beat.kind === "bench"
            ? { trajectory_id: beat.trajectory_id! }
            : { objective_text: beat.objective_text!, allowed_scopes: beat.allowed_scopes ?? [] },
        ),
      );
      setCallIdx(0);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };
  const sendScripted = async () => {
    const c = beat.calls?.[callIdx];
    if (!s || !c) return;
    try {
      setS(await api.call(s.id, c.tool, c.args));
      setCallIdx(callIdx + 1);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  if (beat.kind === "results") return <ResultsBeat />;
  return (
    <div className="stack">
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <button className="btn primary" onClick={() => void start()}>
          {s ? "↻ Restart this beat" : "▶ Start"}
        </button>
        {beat.kind === "custom" && s && beat.calls && callIdx < beat.calls.length && !s.quarantined && (
          <button className="btn" onClick={() => void sendScripted()}>
            Send <code>{beat.calls[callIdx]!.tool} {Object.values(beat.calls[callIdx]!.args).join(" ")}</code>
          </button>
        )}
        {beat.trajectory_id && (
          <a className="btn ghost" href={`#/bench/${beat.trajectory_id}`}>
            Inspect {beat.trajectory_id}
          </a>
        )}
        {s?.snapshot && (
          <a className="btn ghost" href={`#/forensics/${s.snapshot}`}>
            Open snapshot · verify sha256
          </a>
        )}
      </div>
      {err && <span className="form-error">{err}</span>}
      {s && <SessionView s={s} onState={setS} compact />}
    </div>
  );
}

export function Demo({ index }: { index: number }) {
  const q = useAsync(() => api.demo(), []);
  const beats = q.data?.beats ?? [];
  const i = Math.min(Math.max(index, 0), Math.max(beats.length - 1, 0));
  const beat = beats[i];
  const go = (k: number) => navigate(`/demo?b=${k}`, true);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName ?? "";
      if (["INPUT", "TEXTAREA", "SELECT"].includes(tag)) return;
      if (e.key === "ArrowRight" && i < beats.length - 1) go(i + 1);
      if (e.key === "ArrowLeft" && i > 0) go(i - 1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [i, beats.length]);

  const reset = async () => {
    await api.demoReset();
    go(0);
  };

  return (
    <div className="stack">
      <header className="page-head">
        <div>
          <h1>Demo</h1>
          <p>
            A guided tour that drives the real system: every beat runs live through the gateway, the risk engine and the
            approval queue. Use ← → to move. Dev data only; the blind test split is never loaded.
          </p>
        </div>
        <button className="btn" onClick={() => void reset()} title="Clears live sessions and approvals; snapshot files stay on disk">
          Reset demo
        </button>
      </header>
      {q.loading && <Loading />}
      {q.error && <ErrorState error={q.error} onRetry={q.reload} />}
      {beats.length > 0 && (
        <nav className="beat-nav" aria-label="Demo beats">
          {beats.map((b, k) => (
            <button key={b.id} className="btn sm" aria-current={k === i ? "step" : undefined} onClick={() => go(k)}>
              {k + 1}
            </button>
          ))}
        </nav>
      )}
      {beat && (
        <>
          <Card title={beat.title} hint={`${i + 1} / ${beats.length}`}>
            <div className="stack" style={{ gap: 10 }}>
              <p className="demo-say">{beat.say}</p>
              <p className="small muted">
                Expected (pinned, checked in CI):{" "}
                {Object.entries(beat.expect)
                  .map(([k, v]) => (EXPECT_TEXT[k] ? EXPECT_TEXT[k]!(v) : `${k} = ${JSON.stringify(v)}`))
                  .join(" · ")}
              </p>
            </div>
          </Card>
          <BeatRunner beat={beat} />
          {beat.human && (
            <Callout tone="info" icon="i" title={`Your move: ${beat.human === "deny" ? "deny" : "approve"} the held call`}>
              When the call is held, type your name as reviewer and {beat.human === "deny" ? "deny" : "approve"} it. Approval
              requests left unanswered for {q.data?.approval_timeout_s ?? 120} s are denied automatically.
            </Callout>
          )}
          <div className="row" style={{ gap: 8 }}>
            <button className="btn" disabled={i === 0} onClick={() => go(i - 1)}>
              ← Previous
            </button>
            <button className="btn primary" disabled={i >= beats.length - 1} onClick={() => go(i + 1)}>
              Next beat →
            </button>
          </div>
        </>
      )}
    </div>
  );
}
