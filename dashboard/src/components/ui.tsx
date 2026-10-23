import type { ReactNode } from "react";
import type { Decision } from "../types";

// Status colour never carries meaning alone: every decision has a glyph + word.
const GLYPH: Record<Decision, string> = {
  ALLOW: "✓",
  MONITOR: "◐",
  ESCALATE: "▲",
  BLOCK: "✕",
};

export function DecisionBadge({ value, title }: { value: Decision; title?: string }) {
  return (
    <span className={`badge ${value}`} title={title}>
      <span className="glyph" aria-hidden>
        {GLYPH[value]}
      </span>
      {value}
    </span>
  );
}

export function LabelBadge({ value }: { value: "safe" | "unsafe" | null }) {
  if (value === null) return <span className="muted small">unlabelled</span>;
  return (
    <span className={`badge ${value}`}>
      <span className="glyph" aria-hidden>
        {value === "unsafe" ? "!" : "·"}
      </span>
      {value}
    </span>
  );
}

export function TypeChip({ type }: { type: "attack" | "benign" }) {
  return (
    <span className={`badge ${type === "attack" ? "unsafe" : "safe"}`}>
      <span className="glyph" aria-hidden>
        {type === "attack" ? "⚑" : "○"}
      </span>
      {type}
    </span>
  );
}

export function Sensitivity({ level }: { level: "low" | "medium" | "high" }) {
  return (
    <span className="row" style={{ gap: 6 }}>
      <span className={`sens ${level}`} aria-hidden>
        <i />
        <i />
        <i />
      </span>
      <span className="small ink2">{level}</span>
    </span>
  );
}

export function Card({
  title,
  hint,
  actions,
  children,
  flush,
}: {
  title?: ReactNode;
  hint?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  flush?: boolean;
}) {
  return (
    <section className="card">
      {(title || actions) && (
        <div className="card-head">
          {title && <h2>{title}</h2>}
          {hint && <span className="hint">{hint}</span>}
          {actions && (
            <>
              <span className="spacer" />
              {actions}
            </>
          )}
        </div>
      )}
      <div className={`card-body${flush ? " flush" : ""}`}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="card stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export function Callout({
  tone = "neutral",
  icon,
  title,
  children,
}: {
  tone?: "neutral" | "critical" | "warning" | "info";
  icon: string;
  title: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className={`callout ${tone}`} role={tone === "critical" ? "alert" : undefined}>
      <span className="icon" aria-hidden>
        {icon}
      </span>
      <div>
        <h3>{title}</h3>
        {children && <p>{children}</p>}
      </div>
    </div>
  );
}

export function Loading({ rows = 3 }: { rows?: number }) {
  return (
    <div className="stack" style={{ gap: 10 }} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skeleton" style={{ width: `${90 - i * 12}%` }} />
      ))}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  return (
    <Callout tone="critical" icon="✕" title="Request failed">
      {error.message}{" "}
      {onRetry && (
        <button className="btn sm" onClick={onRetry} style={{ marginLeft: 6 }}>
          Retry
        </button>
      )}
    </Callout>
  );
}

export function Todo({ children = "TODO: not yet measured" }: { children?: ReactNode }) {
  return <span className="todo">{children}</span>;
}

export const pct = (v: number | null | undefined) =>
  v === null || v === undefined ? null : `${Math.round(v * 1000) / 10}%`;

export const fixed = (v: number | null | undefined, d = 3) =>
  v === null || v === undefined ? null : v.toFixed(d);

export const shortSha = (sha: string) => sha.slice(0, 10);

export function relTime(iso: string): string {
  const t = new Date(iso).getTime();
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
