import { useEffect, useMemo, useRef, useState } from "react";
import type { Step } from "../types";
import { DecisionBadge, fixed } from "./ui";

// Single-series line: Isolation Forest prefix anomaly score per step.
// Threshold (benign p90) as a dashed rule, ground-truth unsafe region as a band,
// gateway decision as a glyph row under the axis. Hover = crosshair + tooltip.

// Drawn at the container's pixel width (not a scaled viewBox) so text stays 11px.
const H = 240;
const M = { top: 18, right: 76, bottom: 52, left: 48 };

export function AnomalyChart({
  steps,
  firstUnsafe,
  threshold,
}: {
  steps: Step[];
  firstUnsafe: number | null;
  threshold: number;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const [W, setW] = useState(720);
  const empty = steps.length === 0;

  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      if (entry) setW(Math.max(300, Math.round(entry.contentRect.width)));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [empty]); // the wrapper only mounts once there are steps

  const geo = useMemo(() => {
    const n = steps.length;
    const vals = steps.map((s) => s.anomaly.score).concat(threshold);
    const lo = Math.min(...vals);
    const hi = Math.max(...vals);
    // Round tick step (≈4 intervals), domain snapped to whole steps.
    const raw = Math.max((hi - lo) * 1.4, 0.02) / 4;
    const tickStep = [0.005, 0.01, 0.02, 0.025, 0.05, 0.1, 0.2, 0.25, 0.5, 1].find((c) => c >= raw) ?? 1;
    const y0 = Math.floor((lo - tickStep / 2) / tickStep) * tickStep;
    const y1 = Math.ceil((hi + tickStep / 2) / tickStep) * tickStep;
    const iw = W - M.left - M.right;
    const ih = H - M.top - M.bottom;
    const inset = 24; // keep first/last points clear of the axis labels
    const band = n > 1 ? (iw - 2 * inset) / (n - 1) : iw;
    const x = (i: number) => M.left + (n > 1 ? inset + i * band : iw / 2);
    const y = (v: number) => M.top + ih - ((v - y0) / (y1 - y0)) * ih;
    const ticks: number[] = [];
    for (let k = 0; y0 + k * tickStep <= y1 + 1e-9; k++) ticks.push(y0 + k * tickStep);
    const digits = tickStep < 0.01 ? 3 : 2;
    return { n, x, y, ticks, digits, ih, band };
  }, [steps, threshold, W]);

  if (empty) {
    return <div className="empty">No steps yet. Anomaly scores appear after the first tool call.</div>;
  }

  const { n, x, y, ticks, digits, ih, band } = geo;
  const path = steps.map((s, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(s.anomaly.score).toFixed(1)}`).join("");
  const unsafeIdx = firstUnsafe === null ? -1 : steps.findIndex((s) => s.step >= firstUnsafe);
  const half = n > 1 ? band / 2 : 30;
  const bandX = unsafeIdx <= 0 ? M.left : Math.max(M.left, x(unsafeIdx) - half);
  const hovered = hover === null ? null : steps[hover];

  const tipLeft =
    hover === null || !wrap.current
      ? 0
      : Math.max(0, Math.min(x(hover) + 14, W - 230));

  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="legend" aria-hidden>
        <span>
          <i className="sw-line" /> anomaly score (higher = more anomalous)
        </span>
        <span>
          <i className="sw-dash" /> threshold: benign p90 = {threshold.toFixed(3)}
        </span>
        {unsafeIdx >= 0 && (
          <span>
            <i className="sw-band" /> labelled unsafe (ground truth)
          </span>
        )}
      </div>
      <div className="chart" ref={wrap} onMouseLeave={() => setHover(null)}>
        <svg
          viewBox={`0 0 ${W} ${H}`}
          role="img"
          aria-label={`Anomaly score over ${n} steps. ${steps
            .map((s) => `step ${s.step}: ${s.anomaly.score.toFixed(3)}, ${s.decision}`)
            .join("; ")}.`}
        >
          {unsafeIdx >= 0 && (
            <g>
              <rect className="unsafe-band" x={bandX} y={M.top} width={W - M.right - bandX} height={ih} />
              <text className="unsafe-label" x={bandX + 6} y={M.top + 13}>
                unsafe from step {firstUnsafe}
              </text>
            </g>
          )}
          {ticks.map((t) => (
            <g key={t}>
              <line className="gridline" x1={M.left} x2={W - M.right} y1={y(t)} y2={y(t)} />
              <text className="tick" x={M.left - 8} y={y(t) + 4} textAnchor="end">
                {t.toFixed(digits)}
              </text>
            </g>
          ))}
          <line className="axis" x1={M.left} x2={W - M.right} y1={M.top + ih} y2={M.top + ih} />
          <line className="threshold" x1={M.left} x2={W - M.right} y1={y(threshold)} y2={y(threshold)} />
          <text className="threshold-label" x={W - M.right + 6} y={y(threshold) + 4}>
            p90 {threshold.toFixed(3)}
          </text>
          {hover !== null && <line className="crosshair" x1={x(hover)} x2={x(hover)} y1={M.top} y2={M.top + ih} />}
          <path className="series" d={path} />
          {steps.map((s, i) => (
            <g key={s.step}>
              <circle className={`dot${hover === i ? " hot" : ""}`} cx={x(i)} cy={y(s.anomaly.score)} r={hover === i ? 5.5 : 4} />
              <text className="tick" x={x(i)} y={M.top + ih + 16} textAnchor="middle">
                {s.step}
              </text>
              <text className={`decision-glyph ${s.decision}`} x={x(i)} y={M.top + ih + 34}>
                {s.decision === "BLOCK" ? "✕" : "✓"}
              </text>
            </g>
          ))}
          <text className="tick" x={M.left - 8} y={M.top + ih + 16} textAnchor="end">
            step
          </text>
          <text className="tick" x={M.left - 8} y={M.top + ih + 34} textAnchor="end">
            gate
          </text>
          {steps.map((s, i) => (
            <rect
              key={`hit-${s.step}`}
              className="hit"
              x={x(i) - half}
              y={M.top}
              width={half * 2}
              height={ih + 40}
              onMouseEnter={() => setHover(i)}
              onFocus={() => setHover(i)}
              onBlur={() => setHover(null)}
              tabIndex={0}
              aria-label={`Step ${s.step}`}
            />
          ))}
        </svg>
        {hovered && (
          <div className="tooltip" style={{ left: tipLeft, top: 8 }}>
            <div className="tt-head">
              Step {hovered.step} · <span className="mono">{hovered.tool}</span>
            </div>
            <dl>
              <dt>anomaly score</dt>
              <dd>{fixed(hovered.anomaly.score)}</dd>
              <dt>vs threshold</dt>
              <dd>{hovered.anomaly.above_threshold ? "above" : "below"}</dd>
              <dt>gateway</dt>
              <dd>
                <DecisionBadge value={hovered.decision} />
              </dd>
              <dt>mock intent</dt>
              <dd>{hovered.intent.recommended_action}</dd>
              {hovered.label && (
                <>
                  <dt>label</dt>
                  <dd>{hovered.label}</dd>
                </>
              )}
            </dl>
          </div>
        )}
      </div>
    </div>
  );
}
