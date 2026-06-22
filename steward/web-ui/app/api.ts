import type { IntegrationDetail, PlannerRunArtifact, PlannerRunSummary, StewardState, TaskDetail } from "./types";

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

export async function getPlannerRuns(): Promise<PlannerRunSummary[]> {
  const response = await fetch("/api/planner/runs", { cache: "no-store" });
  if (!response.ok) return [];
  const payload = (await response.json()) as { runs?: PlannerRunSummary[] };
  return payload.runs ?? [];
}

export async function getPlannerRun(runId: string): Promise<PlannerRunArtifact | null> {
  const response = await fetch(`/api/planner/runs/${encodeURIComponent(runId)}`, { cache: "no-store" });
  if (!response.ok) return null;
  return response.json();
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
