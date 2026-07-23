import type { StewardArchiveRepository } from "./repository";
import { isRecord } from "./schema";

export type TranscriptItem = {
  id: string; ordinal: number; attempt: number; kind: string; label: string; timestamp?: string;
  text?: string; command?: string; output?: string; exitCode?: number | null;
};

function durationSeconds(start: string, end: string | null) {
  if (!end) return null;
  const value = Math.max(0, Math.floor((Date.parse(end) - Date.parse(start)) / 1000));
  return Number.isFinite(value) ? value : null;
}
function titleCase(value: string) { return value.replace(/([A-Z])/g, " $1").replace(/[._-]/g, " ").replace(/^./, (letter) => letter.toUpperCase()); }

function transcriptPath(run: Record<string, unknown>) {
  const artifacts = isRecord(run.artifacts) ? run.artifacts : {};
  const codex = isRecord(artifacts.codex) ? artifacts.codex : null;
  return codex && typeof codex.path === "string" ? codex.path : null;
}

function mapTranscriptRecord(runId: string, attempt: number, record: { ordinal: number; timestamp: string | null; value: unknown }): TranscriptItem {
  const value = isRecord(record.value) ? record.value : {};
  const type = typeof value.record_type === "string" ? value.record_type : typeof value.type === "string" ? value.type : "record";
  const text = typeof value.text === "string" ? value.text : typeof value.message === "string" ? value.message : null;
  const command = typeof value.command === "string" ? value.command : null;
  const kind = type.includes("tool") || command ? "tool" : type.includes("file") ? "file" : value.opaque === true ? "opaque" : "assistant";
  return { id: `${runId}-${record.ordinal}`, ordinal: record.ordinal, attempt, kind, label: command ? command.slice(0, 120) : text ? text.slice(0, 120) : titleCase(type), timestamp: record.timestamp ?? undefined, text: text ?? (value.opaque === true ? "Opaque complete archive record" : undefined), command: command ?? undefined, output: typeof value.output === "string" ? value.output : undefined, exitCode: typeof value.exit_code === "number" ? value.exit_code : undefined };
}

export async function loadInitialTranscript(repository: StewardArchiveRepository, taskId: string, runId: string, path: string, attempt: number, limit = 50) {
  const chunk = await repository.readTranscriptChunk(taskId, runId, path, null, limit);
  return { items: chunk.data.records.map((record) => mapTranscriptRecord(runId, attempt, { ordinal: Number(record.ordinal), timestamp: typeof record.timestamp === "string" ? record.timestamp : null, value: record.value })), nextCursor: chunk.data.nextCursor, hasMore: chunk.data.hasMore, completeRecords: chunk.data.file.completeRecords, fileRevision: chunk.data.file.fileRevision };
}

export async function loadArchiveTaskView(repository: StewardArchiveRepository, taskId: string) {
  const response = await repository.loadTaskDetail(taskId);
  if (!response) return null;
  const task = response.data.task as Record<string, unknown>;
  const pipelines = response.data.pipelines as Array<Record<string, unknown>>;
  const attempts: Array<Record<string, unknown>> = [];
  const planRuns: Array<Record<string, unknown>> = [];
  const validations: Array<Record<string, unknown>> = [];
  const reviews: Array<Record<string, unknown>> = [];
  const patches: Array<Record<string, unknown>> = [];
  const timeline: Array<Record<string, unknown>> = [];
  const pipelineAttempt = new Map<string, number>();

  for (const group of pipelines) {
    const pipeline = group.pipeline as Record<string, unknown>;
    const pipelineId = String(pipeline.pipelineId);
    const runs = (group.runs as Array<Record<string, unknown>>) ?? [];
    const nonPlanning = runs.filter((run) => run.role !== "planning");
    const number = attempts.length;
    pipelineAttempt.set(pipelineId, number);
    const runEvidence: Array<Record<string, unknown>> = [];
    for (const run of runs) {
      const path = transcriptPath(run);
      const indexedFiles = Array.isArray(run.indexedFiles) ? run.indexedFiles as Array<Record<string, unknown>> : [];
      const transcriptFile = indexedFiles.find((file) => file.relative_path === path);
      runEvidence.push({
        runId: String(run.runId), role: String(run.role), roleOrdinal: Number(run.roleOrdinal), state: String(run.state),
        sessionId: String(run.sessionId), resumeOfRunId: run.resumeOfRunId ?? null, parentRunId: run.parentRunId ?? null,
        retryOfRunId: run.retryOfRunId ?? null, startedAt: String(run.startedAt), completedAt: run.completedAt ?? null,
        model: run.model ?? null, reasoning: run.reasoning ?? null, result: run.result, usage: run.usage, cost: run.cost,
        transcriptPath: path, completeRecords: Number(transcriptFile?.complete_records ?? 0),
        exitCode: isRecord(run.exit) && typeof run.exit.code === "number" ? run.exit.code : null,
      });
      if (run.role === "planning") {
        const planNumber = planRuns.length;
        planRuns.push({ number: planNumber, name: String(run.runId), status: run.state, startedAt: run.startedAt, completedAt: run.completedAt ?? null, durationSeconds: durationSeconds(String(run.startedAt), typeof run.completedAt === "string" ? run.completedAt : null), model: run.model ?? null, reasoningEffort: run.reasoning ?? null, eventCount: Number(transcriptFile?.complete_records ?? 0), exitCode: isRecord(run.exit) && typeof run.exit.code === "number" ? run.exit.code : null, summary: isRecord(run.result) && typeof run.result.summary === "string" ? run.result.summary : "Planning run evidence.", transcriptPath: path, transcript: { availability: path ? "available" : "missing", mode: "archive", sizeBytes: Number(transcriptFile?.actual_size ?? 0), originalSizeBytes: Number(transcriptFile?.actual_size ?? 0), truncated: false, text: "" } });
      }
    }
    const primary = [...nonPlanning].reverse().find((run) => transcriptPath(run)) ?? nonPlanning.at(-1) ?? runs.at(-1);
    const primaryPath = primary ? transcriptPath(primary) : null;
    const primaryFiles = primary && Array.isArray(primary.indexedFiles) ? primary.indexedFiles as Array<Record<string, unknown>> : [];
    const primaryTranscript = primaryFiles.find((file) => file.relative_path === primaryPath);
    attempts.push({
      number, pipelineId, pipelineOrdinal: pipeline.ordinal, pipelineTrigger: pipeline.trigger, parentPipelineId: pipeline.parentPipelineId ?? null,
      label: `Pipeline ${String(pipeline.ordinal).padStart(2, "0")} · ${titleCase(String(pipeline.trigger))}`, status: pipeline.state,
      startedAt: pipeline.startedAt, completedAt: pipeline.completedAt ?? null,
      summary: `${runs.length} owned run${runs.length === 1 ? "" : "s"}; ${String(pipeline.phase)} phase.`, runs: runEvidence,
      integration: pipeline.integration,
      workerRun: { name: primary?.runId, sessionId: primary?.sessionId, resumeOfRunId: primary?.resumeOfRunId ?? null, parentRunId: primary?.parentRunId ?? null, retryOfRunId: primary?.retryOfRunId ?? null, transcriptPath: primaryPath, model: primary?.model ?? null, reasoningEffort: primary?.reasoning ?? null, events: Number(primaryTranscript?.complete_records ?? 0), exitCode: primary && isRecord(primary.exit) && typeof primary.exit.code === "number" ? primary.exit.code : null, status: String(primary?.state ?? pipeline.state), initialCursor: null, hasMore: false },
      reviewerRun: null,
      artifacts: { transcriptBytes: Number(primaryTranscript?.actual_size ?? 0), patchBytes: 0, lastMessageBytes: 0, transcriptTruncated: false },
    });
    for (const validation of (group.validations as Array<Record<string, unknown>>) ?? []) validations.push({ id: validation.validationId, pipelineId, attempt: number, command: validation.command, status: validation.result, exitCode: null, durationSeconds: durationSeconds(String(validation.startedAt), typeof validation.completedAt === "string" ? validation.completedAt : null) ?? 0, summary: validation.state === "running" ? "Validation is still running." : "Validation result recorded in the archive.", summaryTruncated: false, outputPath: validation.outputPath, outputUrl: `/api/steward/tasks/${encodeURIComponent(taskId)}/artifact?path=${encodeURIComponent(String(validation.outputPath))}` });
    for (const review of (group.reviews as Array<Record<string, unknown>>) ?? []) reviews.push({ id: review.reviewId, pipelineId, attempt: number, kind: review.kind, role: review.role, verdict: review.verdict, summary: `${titleCase(String(review.kind))} review by ${String(review.role)}.`, findings: Array.isArray(review.findings) ? review.findings.map((finding) => ({ severity: review.kind === "effective" ? "warning" : "info", title: String(finding), file: String(isRecord(review.artifact) ? review.artifact.path : "Archive review"), line: null, detail: String(finding), recommendation: "See the owning review artifact and its formality decision." })) : [], validationGaps: [], remainingRisk: review.kind === "effective" ? "Effective findings retain formality exclusions from the raw review." : "Raw findings remain distinct from effective findings.", artifactPath: isRecord(review.artifact) ? review.artifact.path : null });
    if (Array.isArray(pipeline.patches)) for (const descriptor of pipeline.patches as Array<Record<string, unknown>>) patches.push({ attempt: number, pipelineId, filesChanged: 0, additions: 0, deletions: 0, rawUrl: `/api/steward/tasks/${encodeURIComponent(taskId)}/artifact?path=${encodeURIComponent(String(descriptor.path))}`, descriptor, files: [] });
    timeline.push({ id: `pipeline-${pipelineId}`, stage: String(pipeline.phase), kind: String(pipeline.trigger), timestamp: String(pipeline.updatedAt), title: `${titleCase(String(pipeline.trigger))} pipeline`, detail: `${nonPlanning.length} non-planning runs · ${String(pipeline.state)}` });
    if (isRecord(pipeline.integration) && pipeline.integration.state !== "pending") timeline.push({ id: `integration-${pipelineId}`, stage: "integration", kind: "integration", timestamp: String(pipeline.integration.completedAt ?? pipeline.updatedAt), title: `Integration ${titleCase(String(pipeline.integration.state))}`, detail: pipeline.integration.commit ? `Commit ${String(pipeline.integration.commit)}` : "No commit identity recorded" });
  }

  const stages = ["planning", "implementation", "validation", "review", "integration"].map((id) => {
    const present = pipelines.some((group) => String((group.pipeline as Record<string, unknown>).phase) === id || (group.runs as Array<Record<string, unknown>>).some((run) => run.role === id));
    return { id: id === "planning" ? "plan" : id, label: titleCase(id), state: present ? "complete" : "pending", detail: present ? "Indexed archive evidence" : "No evidence indexed" };
  });
  const transitions = pipelines.slice(1).map((group, index) => { const pipeline = group.pipeline as Record<string, unknown>; return { from: "implementation", to: String(pipeline.phase) === "complete" ? "integration" : String(pipeline.phase), count: 1, label: titleCase(String(pipeline.trigger)), attempts: [pipelineAttempt.get(String(pipeline.pipelineId)) ?? index], causes: [String(pipeline.trigger)] }; });
  if (!transitions.length) transitions.push({ from: "plan", to: "implementation", count: attempts.length ? 1 : 0, label: "Plan to implementation", attempts: [], causes: [] });

  return {
    task: { id: String(task.taskId), title: isRecord(task.summary) ? String(task.summary.title) : String(task.taskId), kind: "archive", workflow: "Steward 2.0", worker: "Steward archive", priority: "published", risk: "observed", status: String(task.status), summary: isRecord(task.summary) ? String(task.summary.text) : "Archive task evidence.", createdAt: String(task.createdAt), updatedAt: String(task.updatedAt), sourceSignalIds: [], issueUrl: null, plannerRunId: "", commit: null, commitUrl: null },
    pipeline: { stages, transitions },
    plan: { objective: isRecord(task.summary) ? String(task.summary.text) : "Archive task objective", sourceContext: `${pipelines.length} canonical pipeline${pipelines.length === 1 ? "" : "s"}; every Codex process is retained as a run.`, constraints: [], validationCommands: validations.map((item) => String(item.command)), completeness: "archive" },
    planRuns: planRuns.length ? planRuns : undefined,
    attempts, transcript: [] as TranscriptItem[], patches, validations, reviews, timeline,
    completeness: { state: String(response.data.archiveState), transcript: "Complete records load in bounded chunks from the accepted archive prefix.", warnings: response.data.importLag ? [String((response.data.importLag as Record<string, unknown>).reason)] : [] },
  };
}
