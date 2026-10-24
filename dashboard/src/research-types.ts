// Phase W (ADR-0014): types for the research API. The v0 PoC types stay in types.ts (Archive).
import type { Decision } from "./types";

export type Level = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export const LEVEL_DECISION: Record<Level, Decision> = {
  LOW: "ALLOW",
  MEDIUM: "MONITOR",
  HIGH: "ESCALATE",
  CRITICAL: "BLOCK",
};

export interface Contribution {
  signal: string;
  label: string;
  points: number;
}

export interface RiskDecision {
  schema_version: string;
  step: number;
  tool: string;
  level: Level;
  decision: Decision;
  risk_points: number;
  probability: number;
  baseline_points: number;
  contributions: Contribution[];
  policy_rule: string | null;
  llm_reason: string | null;
  signal_errors: string[];
  reasons: string[];
  recommended_response: string;
}

export interface Levels {
  medium: number;
  high: number;
  critical: number;
}

export interface EngineInfo {
  name: string;
  files: string;
  llm: string;
}

export interface ResearchMeta {
  frozen: {
    ml: { config: string; adr: string; threshold: number };
    llm: { model: string; prompt: string; adr: string; mode: string };
    risk_model: { sha256: Record<string, string>; adr: string };
    r4_manifest: { sha256: string; adr: string };
  };
  engines: Record<string, EngineInfo & { signals: string[]; levels: Levels }>;
  signals: { name: string; label: string; group: string }[];
  level_decision: Record<Level, Decision>;
  level_rule: Record<string, string>;
  component_thresholds: Record<string, number | string>;
  policy: {
    path: string;
    http_allowlist: string[];
    http_require_scope: string;
    creds_require_scope: string;
    workspace_root: string | null;
  };
  tools: string[];
  known_scopes: string[];
  splits: Record<string, string>;
  approval: { timeout_s: number; reserved_actors: string[]; note: string };
  startup_seconds: number;
}

export interface Status {
  source: string;
  phases: { phase: string; focus: string; gate: string; status: string }[];
  gates: { gate: string; status: string }[];
}

export type Method = "B2_policy_v2" | "B2plus_policy_v3" | "B3_ml" | "B4_llm_native" | "Hybrid";
export type FirstFlag = Record<Method, number | null>;

export interface BenchHeader {
  id: string;
  split: string;
  type: "attack" | "benign";
  family: string;
  variant: string;
  template: string;
  objective: { text: string; allowed_scopes: string[] };
  n_steps: number;
  first_unsafe_step: number | null;
  harm_step: number | null;
  engine: string;
  first_flag: FirstFlag;
}

export type StepLabel = "safe" | "unsafe" | "precursor";

export interface BenchStep {
  step: number;
  tool: string;
  action: string;
  target: string;
  args_redacted: Record<string, unknown>;
  data_sensitivity: "low" | "medium" | "high";
  network_destination: string | null;
  result_redacted: string | null;
  risky: boolean;
  label: StepLabel;
  signals: Record<string, number>;
  policy_rule: string | null;
  llm_reason: string | null;
  decision: RiskDecision;
}

export interface BenchDetail extends BenchHeader {
  split_note: string;
  engine_info: EngineInfo;
  provenance_note: string;
  steps: BenchStep[];
}

export type CallStatus = "executed" | "held" | "blocked" | "denied";

export interface SessionRecord {
  step: number;
  tool: string;
  target: string;
  args_redacted: Record<string, unknown>;
  status: CallStatus;
  reason: string | null;
  approval_id: string | null;
  queue: "pending" | "approved" | "denied" | "expired" | null;
  decision: RiskDecision | null;
  label: StepLabel | null;
  reviewer?: string;
}

export interface LiveSession {
  id: string;
  kind: "bench" | "custom";
  engine: string;
  engine_info: EngineInfo;
  trajectory_id: string | null;
  mode: "enforce";
  objective: { task_id: string; text: string; allowed_scopes: string[] };
  script: { position: number; total: number; next_tool: string | null } | null;
  records: SessionRecord[];
  executed_steps: number[];
  quarantined: boolean;
  tools_available: string[];
  snapshot: string | null;
  max_steps: number;
  world: {
    files_written: { path: string; bytes: number; new: boolean }[];
    http_sink: { url: string; body_redacted: string | null }[];
    credential_names: string[];
  };
}

export interface ApprovalItem {
  id: string;
  session_id: string;
  step: number;
  tool: string;
  args_redacted: Record<string, unknown>;
  status: "pending" | "approved" | "denied" | "expired";
  reviewer: string | null;
  seconds_left: number;
  level: Level;
  risk_points: number;
  recommended_response: string;
  contributions: Contribution[];
  objective: string;
}

export interface Approvals {
  timeout_s: number;
  items: ApprovalItem[];
}

export interface ForensicSummary {
  session_id: string;
  created_at: string;
  sha256: string;
  trigger: { step: number; tool: string; level: Level; policy_rule: string | null };
  objective: string;
  n_events: number;
}

export interface ForensicDetail {
  path: string;
  snapshot: {
    session_id: string;
    created_at: string;
    agent_id: string;
    objective: { task_id: string; text: string; allowed_scopes: string[] };
    trigger: RiskDecision;
    events: { step: number; tool: string; target: string; args_redacted: Record<string, unknown> }[];
    decisions: RiskDecision[];
    files_written: Record<string, string>;
    egress: { url: string; body: string | null }[];
    network_cut: boolean;
    capabilities_revoked: boolean;
    sha256: string;
  };
}

export interface VerifyResult {
  session_id: string;
  ok: boolean;
  stored_sha256: string;
  detail: string;
}

export interface DemoBeat {
  id: string;
  title: string;
  kind: "bench" | "custom" | "results";
  trajectory_id?: string;
  human?: "approve" | "deny" | null;
  objective_text?: string;
  allowed_scopes?: string[];
  calls?: { tool: string; args: Record<string, string> }[];
  say: string;
  expect: Record<string, unknown>;
}

// Results files: only the fields the UI reads are typed.
export interface MethodStats {
  dr: number | null;
  dr_in_time: number | null;
  dr_visible: number | null;
  dr_compliant: number | null;
  fpr: number | null;
  fpr_step: number | null;
  precision: number | null;
  f1: number | null;
  prefix_auroc?: number | null;
  by_family: Record<string, number | null>;
  earliness: { mean_steps_before_harm: number | null; mean_steps_earlier_than_rules?: number | null };
  ci95?: { dr: number[] | null; fpr: number[] | null };
  n_attack: number;
  n_benign: number;
}

export interface R4Dev {
  dev: {
    split: string;
    data: { attacks: number; benign: number; steps: number };
    budget: number;
    levels: Levels;
    methods: Record<string, MethodStats>;
    best_component: string;
    g5_preview: { hybrid_dr: number; best_component: string; best_component_dr: number; pass: boolean };
    paired: Record<string, { only_a: number; only_b: number; n: number; p: number; p_holm: number }>;
    containment: Record<string, Record<string, number | null>>;
    lofo: Record<string, { dr: number; dr_compliant: number; dr_visible: number; n: number }>;
    g6_preview: { families_ge_50pct_compliant: number; pass: boolean; note: string };
    seeds: {
      per_seed: Record<string, { dr: number; fpr: number }>;
      dr: { mean: number; std: number };
      fpr: { mean: number; std: number };
    };
  };
  v1_test_exploratory: { split: string; data: { attacks: number; benign: number }; methods: Record<string, MethodStats> };
}

export interface R1bSelection {
  selection: { selected: string; reason: string };
  results: Record<string, { config: { name: string }; agg: Record<string, { mean: number | null; std: number | null }> }>;
}

export interface R2lRun {
  run: string;
  model: string;
  judged: number;
  valid_json_rate: number | null;
  auroc_unsafe_vs_benign: number | null;
  escalate_or_block: Record<string, string> | null;
  latency_ms: { p50: number; p95: number } | null;
}

export interface Latency {
  host: { platform: string; machine: string; cpu_count: number; python: string; ci: boolean };
  components: Record<string, { p50_ms: number; p95_ms: number; n: number }>;
  argus_without_llm_per_call: { p50_ms: number; p95_ms: number; n: number };
  llm_per_risky_call: { p50_ms: number; p95_ms: number; n: number; source: string };
  risky_call_fraction: number;
  expected_llm_seconds_per_trajectory: number;
  l5_p95_le_2s: boolean;
}
