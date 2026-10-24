import { DecisionBadge } from "./ui";
import type { CallStatus, Contribution, Level, Levels, RiskDecision, StepLabel } from "../research-types";
import { LEVEL_DECISION } from "../research-types";

const LEVEL_GLYPH: Record<Level, string> = { LOW: "✓", MEDIUM: "◐", HIGH: "▲", CRITICAL: "✕" };

/** Risk level: colour of its decision, plus glyph + word (colour never carries meaning alone). */
export function LevelBadge({ level, title }: { level: Level; title?: string }) {
  return (
    <span className={`badge ${LEVEL_DECISION[level]}`} title={title}>
      <span className="glyph" aria-hidden>
        {LEVEL_GLYPH[level]}
      </span>
      {level}
    </span>
  );
}

const STATUS: Record<CallStatus, { cls: string; glyph: string; text: string }> = {
  executed: { cls: "ALLOW", glyph: "✓", text: "executed" },
  held: { cls: "ESCALATE", glyph: "⏸", text: "held for a human" },
  blocked: { cls: "BLOCK", glyph: "✕", text: "blocked" },
  denied: { cls: "BLOCK", glyph: "✕", text: "denied" },
};

export function StatusBadge({ status }: { status: CallStatus }) {
  const s = STATUS[status];
  return (
    <span className={`badge ${s.cls}`}>
      <span className="glyph" aria-hidden>
        {s.glyph}
      </span>
      {s.text}
    </span>
  );
}

export function StepLabelBadge({ value }: { value: StepLabel | null }) {
  if (value === null) return <span className="muted small">unlabelled</span>;
  const cls = value === "unsafe" ? "unsafe" : "safe";
  const glyph = value === "unsafe" ? "!" : value === "precursor" ? "…" : "·";
  return (
    <span className={`badge ${cls}`} title="Ground truth from the benchmark labelling rule">
      <span className="glyph" aria-hidden>
        {glyph}
      </span>
      {value}
    </span>
  );
}

const pts = (v: number) => `${v >= 0 ? "+" : "−"}${Math.abs(v).toFixed(1)}`;

/** Additive explanation: baseline + each signal's points = the risk score (exact, ADR-0012). */
export function Explanation({ d, levels }: { d: RiskDecision; levels?: Levels }) {
  const shown: Contribution[] = d.contributions.filter((c) => Math.abs(c.points) >= 0.5);
  const rest = d.contributions.filter((c) => Math.abs(c.points) < 0.5);
  const restSum = rest.reduce((a, c) => a + c.points, 0);
  const max = Math.max(1, ...shown.map((c) => Math.abs(c.points)), Math.abs(restSum));
  const Bar = ({ v }: { v: number }) => (
    <span className="wf-track" aria-hidden>
      <span
        className={`wf-bar ${v >= 0 ? "up" : "down"}`}
        style={{
          width: `${(50 * Math.abs(v)) / max}%`,
          left: v >= 0 ? "50%" : `${50 - (50 * Math.abs(v)) / max}%`,
        }}
      />
    </span>
  );
  return (
    <div className="stack" style={{ gap: 12 }}>
      <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
        <LevelBadge level={d.level} />
        <DecisionBadge value={d.decision} />
        <span className="num">
          risk <b>{d.risk_points.toFixed(1)}</b> points
        </span>
        <span className="muted small">calibrated probability {(100 * d.probability).toFixed(1)}%</span>
      </div>
      <ul className="wf" aria-label="Risk score breakdown">
        <li>
          <span className="wf-label muted">Baseline (an average call)</span>
          <span />
          <span className="num muted">{d.baseline_points.toFixed(1)}</span>
        </li>
        {shown.map((c) => (
          <li key={c.signal}>
            <span className="wf-label">{c.label}</span>
            <Bar v={c.points} />
            <span className={`num ${c.points >= 0 ? "wf-up" : "wf-down"}`}>{pts(c.points)}</span>
          </li>
        ))}
        {rest.length > 0 && (
          <li>
            <span className="wf-label muted">{rest.length} other signals</span>
            <Bar v={restSum} />
            <span className="num muted">{pts(restSum)}</span>
          </li>
        )}
        <li className="wf-total">
          <span className="wf-label">Risk score</span>
          <span />
          <span className="num">{d.risk_points.toFixed(1)}</span>
        </li>
      </ul>
      {levels && (
        <p className="small muted">
          Levels: MEDIUM &gt; {levels.medium.toFixed(1)}, HIGH &gt; {levels.high.toFixed(1)}, CRITICAL &gt;{" "}
          {levels.critical.toFixed(1)} points. A policy BLOCK is always CRITICAL.
        </p>
      )}
      {d.reasons.length > 0 && (
        <ul className="list small">
          {d.reasons.map((r) => (
            <li key={r}>
              <span className="grow wrap">Why this level: {r}</span>
            </li>
          ))}
        </ul>
      )}
      {d.llm_reason && (
        <p className="small">
          <b>LLM monitor said</b> (untrusted model output, advisory): <span className="ink2">{d.llm_reason}</span>
        </p>
      )}
      <p className="small">
        <b>Recommended response:</b> {d.recommended_response}
      </p>
    </div>
  );
}

const LEVEL_Y: Level[] = ["MEDIUM", "HIGH", "CRITICAL"];

/** Risk points per step, with the level thresholds and the unsafe region. */
export function RiskChart({
  steps,
  levels,
  firstUnsafe,
  harmStep,
  selected,
  onSelect,
}: {
  steps: { step: number; decision: RiskDecision }[];
  levels: Levels;
  firstUnsafe: number | null;
  harmStep: number | null;
  selected: number | null;
  onSelect: (step: number) => void;
}) {
  const W = 720;
  const H = 240;
  const m = { l: 48, r: 92, t: 16, b: 32 };
  const pw = W - m.l - m.r;
  const ph = H - m.t - m.b;
  const ys = steps.map((s) => s.decision.risk_points);
  const lo = Math.min(levels.medium - 10, ...ys);
  const hi = Math.max(levels.critical + 10, ...ys);
  const n = Math.max(steps.length, 1);
  const x = (i: number) => m.l + (n === 1 ? pw / 2 : (pw * (i - 1)) / (n - 1));
  const y = (v: number) => m.t + ph - (ph * (v - lo)) / (hi - lo);
  const thr: Record<string, number> = { MEDIUM: levels.medium, HIGH: levels.high, CRITICAL: levels.critical };
  return (
    <div className="chart" role="img" aria-label="Risk points per step with level thresholds">
      <svg viewBox={`0 0 ${W} ${H}`}>
        {firstUnsafe !== null && (
          <>
            <rect className="unsafe-band" x={x(firstUnsafe) - pw / n / 2} y={m.t} width={W - m.r - x(firstUnsafe) + pw / n / 2} height={ph} />
            <text className="unsafe-label" x={x(firstUnsafe) - pw / n / 2 + 4} y={m.t + 12}>
              unsafe from step {firstUnsafe}
            </text>
          </>
        )}
        {LEVEL_Y.map((k) => (
          <g key={k}>
            <line className="threshold" x1={m.l} x2={W - m.r} y1={y(thr[k]!)} y2={y(thr[k]!)} />
            <text className="threshold-label" x={W - m.r + 6} y={y(thr[k]!) + 4}>
              {k} &gt; {thr[k]!.toFixed(0)}
            </text>
          </g>
        ))}
        <line className="axis" x1={m.l} x2={m.l} y1={m.t} y2={m.t + ph} />
        {steps.map((s) => (
          <text key={`t${s.step}`} className="tick" x={x(s.step)} y={H - 12} textAnchor="middle">
            {s.step}
            {harmStep === s.step ? " (harm)" : ""}
          </text>
        ))}
        <polyline className="series" fill="none" points={steps.map((s) => `${x(s.step)},${y(s.decision.risk_points)}`).join(" ")} />
        {steps.map((s) => (
          <g key={s.step} className="hit" onClick={() => onSelect(s.step)} style={{ cursor: "pointer" }}>
            <circle
              className={`dot lvl-${s.decision.level}${selected === s.step ? " sel" : ""}`}
              cx={x(s.step)}
              cy={y(s.decision.risk_points)}
              r={selected === s.step ? 7 : 5}
            >
              <title>
                step {s.step} · {s.decision.level} · {s.decision.risk_points.toFixed(1)} points
              </title>
            </circle>
          </g>
        ))}
        <text className="tick" x={14} y={m.t + ph / 2} transform={`rotate(-90 14 ${m.t + ph / 2})`} textAnchor="middle">
          risk points
        </text>
      </svg>
    </div>
  );
}

export function FlagCell({ at, deadline, type }: { at: number | null; deadline: number | null; type: string }) {
  if (type === "benign") {
    return at === null ? (
      <span className="det-tag clear">clear</span>
    ) : (
      <span className="det-cell">
        <span className="mono">@{at}</span>
        <span className="det-tag fp">false alarm</span>
      </span>
    );
  }
  if (at === null) return <span className="det-tag missed">missed</span>;
  const inTime = deadline === null || at <= deadline;
  return (
    <span className="det-cell">
      <span className="mono">@{at}</span>
      <span className={`det-tag ${inTime ? "prevented" : "late"}`}>{inTime ? "before harm" : "late"}</span>
    </span>
  );
}
