import { Fragment, useState } from "react";
import type { Step } from "../types";
import { DecisionBadge, LabelBadge, Sensitivity, fixed } from "./ui";

/** Per-step forensic timeline: what the agent did, what each signal said. */
export function StepTable({ steps, labelled, mode }: { steps: Step[]; labelled: boolean; mode: "record" | "enforce" }) {
  const [open, setOpen] = useState<number | null>(null);

  if (steps.length === 0) {
    return <div className="empty">No tool calls yet.</div>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th className="num">#</th>
            <th>Tool call</th>
            <th>Data</th>
            {labelled && <th>Ground truth</th>}
            <th>Gateway (authoritative)</th>
            <th>Mock intent (advisory)</th>
            <th className="num">Anomaly</th>
          </tr>
        </thead>
        <tbody>
          {steps.map((s) => {
            const missed = s.label === "unsafe" && s.decision === "ALLOW";
            const isOpen = open === s.step;
            return (
              <Fragment key={s.step}>
                <tr
                  className={`clickable${s.label === "unsafe" ? " unsafe" : ""}${missed ? " miss" : ""}`}
                  onClick={() => setOpen(isOpen ? null : s.step)}
                  aria-expanded={isOpen}
                >
                  <td className="num">{s.step}</td>
                  <td>
                    <div className="cell-title mono">{s.tool}</div>
                    <div className="target">{s.target || "—"}</div>
                  </td>
                  <td>
                    <Sensitivity level={s.data_sensitivity} />
                    {s.network_destination && <div className="cell-sub">egress</div>}
                  </td>
                  {labelled && (
                    <td>
                      <LabelBadge value={s.label} />
                      {missed && <div className="cell-sub" style={{ color: "var(--critical-ink)" }}>unsafe, allowed</div>}
                    </td>
                  )}
                  <td>
                    <DecisionBadge value={s.decision} />
                    <div className="cell-sub">
                      <span className="mono">{s.policy.rule}</span>
                    </div>
                    <div className="cell-sub">
                      {mode === "enforce" ? (s.executed ? "executed" : "not executed") : "executed (record mode)"}
                    </div>
                  </td>
                  <td>
                    <DecisionBadge value={s.intent.recommended_action} />
                    <div className="cell-sub">{s.intent.risk_reason}</div>
                  </td>
                  <td className="num">
                    <span className="mono">{fixed(s.anomaly.score)}</span>
                    <div className="cell-sub">{s.anomaly.above_threshold ? "▲ above p90" : "below p90"}</div>
                  </td>
                </tr>
                {isOpen && (
                  <tr>
                    <td />
                    <td colSpan={labelled ? 6 : 5}>
                      <dl className="kv">
                        <dt>Policy reason</dt>
                        <dd>
                          {s.policy.reason} <span className="muted">({s.policy.source})</span>
                        </dd>
                        <dt>Intent alignment</dt>
                        <dd>
                          {fixed(s.intent.intent_alignment, 2)} · confidence {fixed(s.intent.confidence, 2)}
                        </dd>
                        <dt>Action</dt>
                        <dd>
                          {s.action} · prev tool <span className="mono">{s.prev_tool ?? "—"}</span>
                        </dd>
                        <dt>Args (redacted)</dt>
                        <dd>
                          <pre className="json">{JSON.stringify(s.args_redacted, null, 2)}</pre>
                        </dd>
                        <dt>Result (redacted)</dt>
                        <dd>
                          <pre className="json">{s.result_redacted ?? "— (not executed)"}</pre>
                        </dd>
                        <dt>Timestamp</dt>
                        <dd className="mono small">{s.timestamp}</dd>
                      </dl>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
