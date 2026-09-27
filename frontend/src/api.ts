import type { EngagementRow, StateSummary } from "./types";

async function getJson<T>(path: string): Promise<T> {
  const resp = await fetch(path);
  if (!resp.ok) throw new Error(`${resp.status} ${path}`);
  return resp.json();
}

export function listEngagements(): Promise<EngagementRow[]> {
  return getJson("/api/engagements");
}

export function fetchState(id: string): Promise<StateSummary> {
  return getJson(`/api/engagements/${id}/state`);
}

export function fetchRoe(id: string): Promise<Record<string, unknown>> {
  return getJson(`/api/engagements/${id}/roe`);
}

export async function resolveHitl(
  id: string, gateId: string, approved: boolean,
): Promise<void> {
  const resp = await fetch(
    `/api/engagements/${id}/hitl/${gateId}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approved }),
    },
  );
  if (resp.status === 409) throw new Error("already-resolved");
  if (!resp.ok) throw new Error(`${resp.status}`);
}
