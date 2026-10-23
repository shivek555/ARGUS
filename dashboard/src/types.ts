// Mirrors argus/api/models.py and argus/api/service.py response shapes.

export type Decision = "ALLOW" | "MONITOR" | "ESCALATE" | "BLOCK";

export interface ToolParam {
  name: string;
  required: boolean;
  default: string | null;
}

export interface ToolSpec {
  name: string;
  params: ToolParam[];
}

export interface Meta {
  schema_version: string;
  policy: {
    path: string;
    sha256: string;
    http_allowlist: string[];
    http_require_scope: string;
    creds_require_scope: string;
  };
  tools: ToolSpec[];
  known_scopes: string[];
  detector: {
    model: string;
    features: string;
    seed: number;
    fit_on: string;
    threshold: number;
    threshold_rule: string;
  };
  intent_monitor: { mode: string; description: string };
  preregistered: {
    source: string;
    poc_auroc_threshold: number;
    criteria: { id: string; text: string }[];
  };
  not_built: string[];
}

export interface Detections {
  rules: number | null;
  ml: number | null;
  llm_mock: number | null;
}

export interface ScenarioHeader {
  id: string;
  type: "attack" | "benign";
  family: string;
  seed: number | null;
  method: string | null;
  sha256: string;
  objective: { text: string; allowed_scopes: string[] };
  first_unsafe_step: number | null;
  n_steps: number;
  detections?: Detections;
}

export interface Step {
  step: number;
  timestamp: string;
  tool: string;
  action: string;
  target: string;
  args_redacted: Record<string, unknown>;
  data_sensitivity: "low" | "medium" | "high";
  network_destination: string | null;
  prev_tool: string | null;
  result_redacted: string | null;
  executed: boolean;
  decision: Decision;
  policy: { decision: Decision; rule: string; reason: string; source: "policy" | "gateway" };
  intent: {
    intent_alignment: number;
    risk_reason: string;
    confidence: number;
    recommended_action: Decision;
  };
  anomaly: { score: number; threshold: number; above_threshold: boolean };
  label: "safe" | "unsafe" | null;
}

export interface ScenarioDetail extends ScenarioHeader {
  mode: "record";
  mode_note: string;
  steps: Step[];
  detections: Detections;
}

export interface Baseline {
  id: string;
  label: string;
  note: string;
  n_attack: number;
  n_benign: number;
  detected_attacks: number;
  flagged_benign: number;
  prevented_attacks: number;
  detection_rate: number | null;
  fpr: number | null;
  mean_steps_before_harm: number | null;
}

export interface ExperimentRow {
  id: string;
  family: string;
  type: "attack" | "benign";
  sha256: string;
  first_unsafe_step: number | null;
  detect_rules: number | null;
  detect_ml: number | null;
  detect_llm_mock: number | null;
  steps_before_harm_rules: number | null;
  steps_before_harm_ml: number | null;
}

export interface Experiment {
  provenance: {
    path: string;
    sha256: string;
    modified_at: string;
    command: string;
    stale: { id: string; issue: string }[];
  };
  summary: {
    n_scenarios: number;
    prefix_auroc_unsafe_vs_benign: number | string;
    ml_threshold_benign_p90: number;
    mean_steps_before_harm_rules: number | string;
    mean_steps_before_harm_ml: number | string;
    note: string;
  };
  rows: ExperimentRow[];
  baselines: Baseline[];
}

export interface SessionState {
  id: string;
  created_at: string;
  agent_id: string;
  mode: "enforce";
  objective: { task_id: string; text: string; allowed_scopes: string[]; created_at: string };
  scenario_id: string | null;
  script: { position: number; total: number; next_tool: string | null } | null;
  max_steps: number;
  steps: Step[];
  world: {
    files: { path: string; bytes: number; created_by_agent: boolean }[];
    http_sink: { url: string; body_redacted: string | null }[];
    credential_names: string[];
  };
}
