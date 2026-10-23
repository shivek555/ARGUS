import type { Experiment, Meta, ScenarioDetail, ScenarioHeader, SessionState } from "./types";

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

export const api = {
  meta: () => request<Meta>("/api/meta"),
  scenarios: () => request<ScenarioHeader[]>("/api/scenarios"),
  scenario: (id: string) => request<ScenarioDetail>(`/api/scenarios/${encodeURIComponent(id)}`),
  experiment: () => request<Experiment>("/api/experiments/poc"),
  runExperiment: () => request<Experiment>("/api/experiments/poc/run", { method: "POST" }),
  createSession: (
    body: { scenario_id: string } | { objective_text: string; allowed_scopes: string[] },
  ) => request<SessionState>("/api/sessions", { method: "POST", body: JSON.stringify(body) }),
  session: (id: string) => request<SessionState>(`/api/sessions/${encodeURIComponent(id)}`),
  call: (id: string, tool: string, args: Record<string, string>) =>
    request<SessionState>(`/api/sessions/${encodeURIComponent(id)}/calls`, {
      method: "POST",
      body: JSON.stringify({ tool, args }),
    }),
  scriptNext: (id: string) =>
    request<SessionState>(`/api/sessions/${encodeURIComponent(id)}/script/next`, {
      method: "POST",
    }),
  deleteSession: (id: string) =>
    request<void>(`/api/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }),
};
