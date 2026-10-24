import type { Experiment, Meta, ScenarioDetail, ScenarioHeader } from "./types";
import type {
  Approvals,
  BenchDetail,
  BenchHeader,
  DemoBeat,
  ForensicDetail,
  ForensicSummary,
  LiveSession,
  ResearchMeta,
  Status,
  VerifyResult,
} from "./research-types";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

function detailText(detail: unknown): string {
  if (typeof detail === "string") return detail;
  // FastAPI 422: [{loc, msg, ...}]
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        const item = d as { loc?: unknown[]; msg?: string };
        const loc = (item.loc ?? []).filter((x) => x !== "body").join(".");
        return loc ? `${loc}: ${item.msg}` : String(item.msg);
      })
      .join("; ");
  }
  return "request failed";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    throw new ApiError(0, "Cannot reach the ARGUS API. Is `python -m argus.api` running?");
  }
  if (res.status === 204) return undefined as T;
  const body: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const detail = (body as { detail?: unknown } | null)?.detail;
    throw new ApiError(res.status, detail ? detailText(detail) : `${res.status} ${res.statusText}`);
  }
  return body as T;
}

const enc = encodeURIComponent;
const post = <T,>(path: string, body?: unknown) =>
  request<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

export type NewSession = { trajectory_id: string } | { objective_text: string; allowed_scopes: string[] };

export const api = {
  meta: () => request<ResearchMeta>("/api/meta"),
  status: () => request<Status>("/api/status"),
  bench: (q: { split?: string; family?: string; variant?: string } = {}) => {
    const pairs = Object.entries(q).filter((kv): kv is [string, string] => Boolean(kv[1]));
    const qs = new URLSearchParams(pairs).toString();
    return request<BenchHeader[]>(`/api/bench${qs ? `?${qs}` : ""}`);
  },
  benchDetail: (id: string) => request<BenchDetail>(`/api/bench/${enc(id)}`),
  createSession: (body: NewSession) => post<LiveSession>("/api/sessions", body),
  session: (id: string) => request<LiveSession>(`/api/sessions/${enc(id)}`),
  call: (id: string, tool: string, args: Record<string, string>) =>
    post<LiveSession>(`/api/sessions/${enc(id)}/calls`, { tool, args }),
  scriptNext: (id: string) => post<LiveSession>(`/api/sessions/${enc(id)}/script/next`),
  approvals: () => request<Approvals>("/api/approvals"),
  decide: (id: string, approve: boolean, reviewer: string) =>
    post<{ result: { status: string; queue: string }; session: LiveSession }>(`/api/approvals/${enc(id)}`, {
      approve,
      reviewer,
    }),
  forensics: () => request<ForensicSummary[]>("/api/forensics"),
  forensic: (id: string) => request<ForensicDetail>(`/api/forensics/${enc(id)}`),
  verify: (id: string) => post<VerifyResult>(`/api/forensics/${enc(id)}/verify`),
  result: <T,>(name: string) => request<T>(`/api/results/${enc(name)}`),
  figureUrl: (name: string) => `/api/results/figures/${enc(name)}.svg`,
  demo: () => request<{ beats: DemoBeat[]; approval_timeout_s: number }>("/api/demo"),
  demoReset: () => post<{ status: string }>("/api/demo/reset"),
  archiveMeta: () => request<Meta>("/api/archive/meta"),
  archiveScenarios: () => request<ScenarioHeader[]>("/api/archive/scenarios"),
  archiveScenario: (id: string) => request<ScenarioDetail>(`/api/archive/scenarios/${enc(id)}`),
  archiveExperiment: () => request<Experiment>("/api/archive/experiment"),
};
