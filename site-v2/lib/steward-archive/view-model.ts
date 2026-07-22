import { readFile } from "node:fs/promises";
import type { StewardArchiveRepository } from "./repository";
import { isRecord } from "./schema";

type TranscriptItem = {
  id: string;
  attempt: number;
  kind: string;
  label: string;
  timestamp?: string;
  text?: string;
  command?: string;
  output?: string;
  outputTruncated?: boolean;
  exitCode?: number | null;
  outputBytes?: number;
  changes?: Array<{ path: string; kind: string }>;
};

function durationSeconds(start: string, end: string | null) {
  if (!end) return null;
  const value = Math.max(0, Math.floor((Date.parse(end) - Date.parse(start)) / 1000));
  return Number.isFinite(value) ? value : null;
}
function titleCase(value: string) { return value.replace(/([A-Z])/g, " $1").replace(/[._-]/g, " ").replace(/^./, (letter) => letter.toUpperCase()); }

async function transcriptFor(repository: StewardArchiveRepository, taskId: string, run: Record<string, unknown>, attempt: number): Promise<TranscriptItem[]> {
  const artifacts = isRecord(run.artifacts) ? run.artifacts : {};
  const codex = isRecord(artifacts.codex) ? artifacts.codex : null;
  const path = codex && typeof codex.path === "string" ? codex.path : null;
  if (!path) return [];
  const items: TranscriptItem[] = [];
  let cursor: string | null = null;
  for (let page = 0; page < 100; page += 1) {
    let chunk;
    try { chunk = await repository.readTranscriptChunk(taskId, String(run.runId), path, cursor, 100); } catch { break; }
    for (const record of chunk.data.records as Array<{ ordinal: number; timestamp: string | null; value: unknown }>) {
      const value = isRecord(record.value) ? record.value : {};
      const type = typeof value.record_type === "string" ? value.record_type : typeof value.type === "string" ? value.type : "record";
      const text = typeof value.text === "string" ? value.text : typeof value.message === "string" ? value.message : null;
      const command = typeof value.command === "string" ? value.command : null;
      const kind = type.includes("tool") || command ? "tool" : type.includes("file") ? "file" : "assistant";
      items.push({ id: `${String(run.runId)}-${record.ordinal}`, attempt, kind, label: command ? command.slice(0, 120) : text ? text.slice(0, 120) : titleCase(type), timestamp: record.timestamp ?? undefined, text: text ?? undefined, command: command ?? undefined, output: typeof value.output === "string" ? value.output : undefined, exitCode: typeof value.exit_code === "number" ? value.exit_code : undefined });
    }
    if (!chunk.data.nextCursor) break;
    cursor = chunk.data.nextCursor;
  }
  return items;
}

export async function loadArchiveTaskView(repository: StewardArchiveRepository, taskId: string) {
  const response = await repository.loadTaskDetail(taskId);
  if (!response) return null;
  const task = response.data.task as Record<string, unknown>;
  const pipelines = response.data.pipelines as Array<Record<string, unknown>>;
  const attempts: Array<Record<string, unknown>> = [];
  const transcript: TranscriptItem[] = [];
  const planRuns: Array<Record<string, unknown>> = [];
  const validations: Array<Record<string, unknown>> = [];
  const reviews: Array<Record<string, unknown>> = [];
  let attemptNumber = 0;
  for (const group of pipelines) {
    const pipeline = group.pipeline as Record<string, unknown>;
    const runs = (group.runs as Array<Record<string, unknown>>) ?? [];
    const worker = runs.find((run) => run.role === "implementation") ?? runs.find((run) => run.role !== "planning") ?? runs[0];
    if (worker) {
      const items = await transcriptFor(repository, taskId, worker, attemptNumber);
      transcript.push(...items);
      const workerArtifacts = isRecord(worker.artifacts) ? worker.artifacts : {};
      const workerCodex = isRecord(workerArtifacts.codex) && typeof workerArtifacts.codex.path === "string" ? workerArtifacts.codex.path : null;
      attempts.push({ number: attemptNumber, label: titleCase(String(worker.role ?? "run")), status: worker.state, startedAt: worker.startedAt, completedAt: worker.completedAt ?? null, summary: isRecord(worker.result) && typeof worker.result.summary === "string" ? worker.result.summary : "Archive run evidence.", workerRun: { name: worker.runId, transcriptPath: workerCodex, model: worker.model ?? null, reasoningEffort: worker.reasoning ?? null, events: items.length, exitCode: isRecord(worker.exit) && typeof worker.exit.code === "number" ? worker.exit.code : null, status: worker.state }, reviewerRun: null, artifacts: { transcriptBytes: 0, patchBytes: 0, lastMessageBytes: 0, transcriptTruncated: false } });
      attemptNumber += 1;
    }
    for (const run of runs) {
      if (run.role !== "planning") continue;
      const items = await transcriptFor(repository, taskId, run, planRuns.length);
      planRuns.push({ number: planRuns.length, name: String(run.runId), status: run.state, startedAt: run.startedAt, completedAt: run.completedAt ?? null, durationSeconds: durationSeconds(String(run.startedAt), typeof run.completedAt === "string" ? run.completedAt : null), model: run.model ?? null, reasoningEffort: run.reasoning ?? null, eventCount: items.length, exitCode: isRecord(run.exit) && typeof run.exit.code === "number" ? run.exit.code : null, summary: isRecord(run.result) && typeof run.result.summary === "string" ? run.result.summary : "Planning run evidence.", transcript: { availability: items.length ? "available" : "missing", mode: "archive", sizeBytes: 0, originalSizeBytes: 0, truncated: false, text: items.map((item) => item.text ?? item.command ?? item.label).join("\n") } });
    }
    for (const validation of (group.validations as Array<Record<string, unknown>>) ?? []) validations.push({ id: validation.validationId, attempt: Math.max(0, attemptNumber - 1), command: validation.command, status: validation.result, exitCode: null, durationSeconds: durationSeconds(String(validation.startedAt), typeof validation.completedAt === "string" ? validation.completedAt : null) ?? 0, summary: validation.state === "running" ? "Validation is still running." : "Validation result recorded in the archive.", summaryTruncated: false });
    for (const review of (group.reviews as Array<Record<string, unknown>>) ?? []) reviews.push({ attempt: Math.max(0, attemptNumber - 1), verdict: review.verdict, summary: `${titleCase(String(review.kind))} review evidence.`, findings: Array.isArray(review.findings) ? review.findings.map((finding) => ({ severity: "info", title: String(finding), file: "Archive review", line: null, detail: String(finding), recommendation: "See the owning review artifact." })) : [], validationGaps: [], remainingRisk: "Review evidence remains attached to its pipeline." });
  }
  const stages = ["plan", "implementation", "validation", "review", "integration"].map((id) => {
    const present = pipelines.some((group) => String((group.pipeline as Record<string, unknown>).phase) === id || (id === "implementation" && (group.runs as Array<Record<string, unknown>>).some((run) => run.role === "implementation")));
    return { id, label: titleCase(id), state: present ? "complete" : "pending", detail: present ? "Indexed archive evidence" : "No evidence indexed" };
  });
  const eventsPath = typeof task.eventsPath === "string" ? task.eventsPath : null;
  const timeline: Array<Record<string, unknown>> = [];
  if (eventsPath) {
    try {
      const eventArtifact = await repository.readArtifact(taskId, eventsPath);
      for (const [index, line] of eventArtifact.bytes.toString("utf8").split("\n").entries()) {
        if (!line.trim()) continue;
        try { const event = JSON.parse(line) as Record<string, unknown>; timeline.push({ id: String(event.eventId ?? `event-${index}`), stage: "execution", kind: event.kind ?? "event", timestamp: event.at ?? new Date().toISOString(), title: titleCase(String(event.kind ?? "Archive event")), detail: typeof event.status === "string" ? titleCase(event.status) : "Indexed archive event" }); } catch { /* opaque event */ }
      }
    } catch { /* events can arrive after metadata */ }
  }
  return {
    task: { id: String(task.taskId), title: isRecord(task.summary) ? String(task.summary.title) : String(task.taskId), kind: "archive", workflow: "Steward 2.0", worker: "Steward archive", priority: "published", risk: "observed", status: String(task.status), summary: isRecord(task.summary) ? String(task.summary.text) : "Archive task evidence.", createdAt: String(task.createdAt), updatedAt: String(task.updatedAt), sourceSignalIds: [], issueUrl: null, plannerRunId: "", commit: null, commitUrl: null },
    pipeline: { stages, transitions: [{ from: "plan", to: "implementation", count: attempts.length ? 1 : 0, label: "Plan to implementation", attempts: [], causes: [] }, { from: "implementation", to: "validation", count: validations.length, label: "Implementation to validation", attempts: [], causes: [] }, { from: "validation", to: "review", count: reviews.length, label: "Validation to review", attempts: [], causes: [] }, { from: "review", to: "integration", count: pipelines.some((group) => (group.pipeline as Record<string, unknown>).phase === "complete") ? 1 : 0, label: "Review to integration", attempts: [], causes: [] }] },
    plan: { objective: isRecord(task.summary) ? String(task.summary.text) : "Archive task objective", sourceContext: "Canonical Steward 2.0 task archive.", constraints: [], validationCommands: validations.map((item) => String(item.command)), completeness: "archive" },
    planRuns: planRuns.length ? planRuns : undefined,
    attempts,
    transcript,
    patches: [],
    validations,
    reviews,
    timeline,
    completeness: { state: String(response.data.archiveState), transcript: transcript.length ? "available" : "missing", warnings: response.data.importLag ? [String((response.data.importLag as Record<string, unknown>).reason)] : [] },
  };
}
