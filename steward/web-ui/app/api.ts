import type { IntegrationDetail, PlannerRunArtifact, PlannerRunSummary, StewardState, TaskDetail } from "./types";

export type PlannerRunsPage = {
  runs: PlannerRunSummary[];
  total: number;
  limit: number;
  offset: number;
};

export async function getState(): Promise<StewardState> {
  const response = await fetch("/api/state", { cache: "no-store" });
  if (!response.ok) throw new Error(`state request failed: ${response.status}`);
  return response.json();
}

export async function getTask(taskId: string): Promise<TaskDetail> {
  const response = await fetch(`/api/tasks/${encodeURIComponent(taskId)}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`task request failed: ${response.status}`);
  return response.json();
}

export async function getIntegration(integrationId: string): Promise<IntegrationDetail> {
  const response = await fetch(`/api/integrations/${encodeURIComponent(integrationId)}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`integration request failed: ${response.status}`);
  return response.json();
}

export async function getTaskFile(taskId: string, name: string): Promise<string> {
  const response = await fetch(`/api/tasks/${encodeURIComponent(taskId)}/files/${encodeURIComponent(name)}`, {
    cache: "no-store",
  });
  if (!response.ok) return "";
  return response.text();
}

export async function getRunTranscript(taskId: string, runName: string): Promise<string> {
  const response = await fetch(
    `/api/tasks/${encodeURIComponent(taskId)}/runs/${encodeURIComponent(runName)}/transcript`,
    { cache: "no-store" },
  );
  if (!response.ok) return "";
  return response.text();
}

export async function getValidationLog(taskId: string, index: number): Promise<string> {
  const response = await fetch(`/api/tasks/${encodeURIComponent(taskId)}/validations/${index}`, {
    cache: "no-store",
  });
  if (!response.ok) return "";
  return response.text();
}

export async function getIterationPatch(taskId: string, iteration: number): Promise<string> {
  const response = await fetch(
    `/api/tasks/${encodeURIComponent(taskId)}/iterations/${iteration}/patch`,
    { cache: "no-store" },
  );
  if (!response.ok) return "";
  return response.text();
}

export async function getPlannerRuns(options: { limit?: number; offset?: number } = {}): Promise<PlannerRunsPage> {
  const params = new URLSearchParams();
  if (options.limit !== undefined) params.set("limit", String(options.limit));
  if (options.offset !== undefined) params.set("offset", String(options.offset));
  const query = params.toString();
  const response = await fetch(`/api/planner/runs${query ? `?${query}` : ""}`, { cache: "no-store" });
  if (!response.ok) {
    return { runs: [], total: 0, limit: options.limit ?? 0, offset: options.offset ?? 0 };
  }
  const payload = (await response.json()) as {
    runs?: PlannerRunSummary[];
    total?: number;
    limit?: number;
    offset?: number;
  };
  const runs = payload.runs ?? [];
  return {
    runs,
    total: typeof payload.total === "number" ? payload.total : runs.length,
    limit: typeof payload.limit === "number" ? payload.limit : options.limit ?? runs.length,
    offset: typeof payload.offset === "number" ? payload.offset : options.offset ?? 0,
  };
}

export async function getPlannerRun(runId: string): Promise<PlannerRunArtifact | null> {
  const response = await fetch(`/api/planner/runs/${encodeURIComponent(runId)}`, { cache: "no-store" });
  if (!response.ok) return null;
  return response.json();
}

export async function requestSchedulerTick(payload: {
  plan?: boolean;
  dispatch?: boolean;
  max_dispatch?: number | null;
} = {}): Promise<void> {
  const response = await fetch("/api/actions/tick", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(await response.text());
}

export async function requestSignalFetch(providers: string[]): Promise<void> {
  const response = await fetch("/api/actions/fetch-signals", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ providers }),
  });
  if (!response.ok) throw new Error(await response.text());
}

export async function createTask(payload: {
  title: string;
  prompt: string;
  kind: string;
  worker: string;
}): Promise<void> {
  const response = await fetch("/api/tasks", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(await response.text());
}

export async function runTask(taskId: string): Promise<void> {
  const response = await fetch(`/api/tasks/${encodeURIComponent(taskId)}/run`, { method: "POST" });
  if (!response.ok) throw new Error(await response.text());
}
