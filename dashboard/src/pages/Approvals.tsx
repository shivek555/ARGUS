import { useEffect, useState } from "react";
import { api } from "../api";
import { useAsync } from "../hooks";
import { Callout, Card, ErrorState, Loading } from "../components/ui";
import { LevelBadge } from "../components/risk";
import type { ApprovalItem, LiveSession } from "../research-types";

// The reviewer name is a per-viewer convenience: local storage, wrapped (may be unavailable).
export function useReviewer(): [string, (v: string) => void] {
  const [name, setName] = useState<string>(() => {
    try {
      return window.localStorage.getItem("argus.reviewer") ?? "";
    } catch {
      return "";
    }
  });
  const set = (v: string) => {
    setName(v);
    try {
      window.localStorage.setItem("argus.reviewer", v);
    } catch {
      /* non-persistent is fine */
    }
  };
  return [name, set];
}

export function ReviewerField({ name, setName }: { name: string; setName: (v: string) => void }) {
  return (
    <label className="row small" style={{ gap: 6 }}>
      Reviewer
      <input value={name} onChange={(e) => setName(e.target.value)} placeholder="your name" maxLength={40} style={{ width: 140 }} />
    </label>
  );
}

/** Approve/deny one held call. Errors (e.g. a reserved name like "argus") are shown, not hidden. */
export function DecideButtons({
  item,
  reviewer,
  onDone,
}: {
  item: { id: string };
  reviewer: string;
  onDone: (s: LiveSession) => void;
}) {
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const go = async (approve: boolean) => {
    setBusy(true);
    setErr(null);
    try {
      onDone((await api.decide(item.id, approve, reviewer || "")).session);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <span className="row" style={{ gap: 6, flexWrap: "wrap" }}>
      <button className="btn sm" disabled={busy} onClick={() => void go(false)}>
        ✕ Deny
      </button>
      <button className="btn sm primary" disabled={busy} onClick={() => void go(true)}>
        ✓ Approve
      </button>
      {err && <span className="form-error">{err}</span>}
    </span>
  );
}

function Countdown({ item }: { item: ApprovalItem }) {
  return item.status === "pending" ? (
    <span className="countdown" title="Unanswered requests are denied automatically">
      {Math.ceil(item.seconds_left)} s
    </span>
  ) : (
    <span className="small muted">
      {item.status}
      {item.reviewer ? ` by ${item.reviewer}` : ""}
    </span>
  );
}

export function Approvals() {
  const q = useAsync(() => api.approvals(), []);
  const [reviewer, setReviewer] = useReviewer();
  useEffect(() => {
    const t = window.setInterval(() => q.reload(), 1000);
    return () => window.clearInterval(t);
  }, [q.reload]);
  const items = q.data?.items ?? [];
  const pending = items.filter((i) => i.status === "pending");

  return (
    <div className="stack">
      <header className="page-head">
        <div>
          <h1>Approvals</h1>
          <p>
            HIGH-risk calls wait here for a human. Nothing in ARGUS can approve its own escalation (reserved names such as
            "argus" or "agent" are refused), and a request nobody answers within {q.data?.timeout_s ?? 120} s is denied.
            An approved call still goes through the policy gateway.
          </p>
        </div>
        <ReviewerField name={reviewer} setName={setReviewer} />
      </header>
      {q.loading && !q.data && <Loading />}
      {q.error && <ErrorState error={q.error} onRetry={q.reload} />}
      {q.data && pending.length === 0 && (
        <Callout tone="neutral" icon="✓" title="Nothing waiting">
          Start a session on the Live page or in the demo; HIGH-risk calls will appear here.
        </Callout>
      )}
      {items.length > 0 && (
        <Card title="Queue" hint={`${pending.length} pending`} flush>
          <ul className="list">
            {items.map((i) => (
              <li key={i.id} style={{ alignItems: "flex-start" }}>
                <LevelBadge level={i.level} />
                <div className="grow wrap stack" style={{ gap: 4 }}>
                  <div>
                    <b className="mono">{i.tool}</b> <span className="mono small">{JSON.stringify(i.args_redacted)}</span>
                  </div>
                  <div className="small muted">
                    step {i.step} · risk {i.risk_points.toFixed(1)} · task: {i.objective} ·{" "}
                    <a href={`#/live?s=${i.session_id}`}>open session</a>
                  </div>
                  <div className="small">
                    Top signals:{" "}
                    {i.contributions
                      .filter((c) => c.points > 0)
                      .map((c) => `${c.label} (+${c.points.toFixed(1)})`)
                      .join(", ") || "none positive"}
                  </div>
                  <div className="small">
                    <b>Recommended:</b> {i.recommended_response}
                  </div>
                </div>
                <div className="stack" style={{ gap: 6, alignItems: "flex-end" }}>
                  <Countdown item={i} />
                  {i.status === "pending" && <DecideButtons item={i} reviewer={reviewer} onDone={() => q.reload()} />}
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
      <p className="provenance">The reviewer name is self-declared, not authentication: this is a local demo tool.</p>
    </div>
  );
}
