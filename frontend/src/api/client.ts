export type StageStatus = "pending" | "running" | "needs_input" | "complete" | "failed";
export type RunStatus = "queued" | "running" | "needs_input" | "complete" | "failed";

export interface RunStage {
  id: string;
  sequence_index: number;
  name: string;
  status: StageStatus;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
}

export interface Run {
  id: string;
  status: RunStatus;
  parent_run_id: string | null;
  project_name: string | null;
  created_at: string;
  updated_at: string;
  stages: RunStage[];
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { "content-type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${detail}`);
  }
  return response.json() as Promise<T>;
}

export function createRun(stageNames: string[], projectName?: string): Promise<Run> {
  return request<Run>("/runs", {
    method: "POST",
    body: JSON.stringify({ stage_names: stageNames, project_name: projectName ?? null }),
  });
}

export function getRun(runId: string): Promise<Run> {
  return request<Run>(`/runs/${runId}`);
}

export function subscribeRunEvents(
  runId: string,
  onEvent: (event: Record<string, unknown>) => void,
): () => void {
  const source = new EventSource(`${API_BASE_URL}/runs/${runId}/events`);
  const handler = (message: MessageEvent<string>) => onEvent(JSON.parse(message.data));
  source.addEventListener("run_status", handler);
  source.addEventListener("stage_status", handler);
  return () => source.close();
}
