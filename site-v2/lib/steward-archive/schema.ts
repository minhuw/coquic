import { isSafeId, isSafeRelativePath } from "./paths";

export type JsonRecord = Record<string, unknown>;

export function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function parseCompleteJson<T extends JsonRecord>(source: string, label: string): T {
  if (!source.trim()) throw new Error(`${label} is empty`);
  const value: unknown = JSON.parse(source);
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value as T;
}

export function parseJsonFileShape(value: JsonRecord, required: string[], label: string) {
  for (const key of required) if (!(key in value)) throw new Error(`${label} is missing ${key}`);
  return value;
}

export function validateEpoch(value: JsonRecord) {
  parseJsonFileShape(value, ["epochId", "formatVersion", "policy", "startedAt"], "epoch.json");
  if (!isSafeId(value.epochId) || value.formatVersion !== "1.0" || value.policy !== "post-steward-2.0" || typeof value.startedAt !== "string") {
    throw new Error("epoch.json does not match the archive contract");
  }
  return value as { epochId: string; formatVersion: "1.0"; policy: "post-steward-2.0"; startedAt: string; endedAt?: string | null };
}

const TASK_STATES = new Set(["queued", "running", "reviewing", "integrating", "succeeded", "pushed", "no_changes", "blocked", "failed", "cancelled"]);
const PIPELINE_STATES = new Set(["active", "succeeded", "failed", "blocked", "cancelled", "interrupted", "superseded"]);
const RUN_STATES = new Set(["running", "succeeded", "failed", "interrupted", "cancelled"]);

export function validateTask(value: JsonRecord) {
  parseJsonFileShape(value, ["taskId", "epochId", "status", "promptPath", "eventsPath", "createdAt", "updatedAt", "currentPipelineId", "summary", "pipelines"], "task.json");
  if (!isSafeId(value.taskId) || !isSafeId(value.epochId) || typeof value.status !== "string" || !TASK_STATES.has(value.status) || !isSafeRelativePath(value.promptPath) || !isSafeRelativePath(value.eventsPath) || typeof value.createdAt !== "string" || typeof value.updatedAt !== "string" || !Array.isArray(value.pipelines) || value.pipelines.length < 1 || !isRecord(value.summary) || typeof value.summary.title !== "string" || typeof value.summary.text !== "string") throw new Error("task.json does not match the archive contract");
  return value;
}

export function validatePipeline(value: JsonRecord) {
  parseJsonFileShape(value, ["pipelineId", "taskId", "ordinal", "trigger", "parentPipelineId", "phase", "state", "startedAt", "updatedAt", "completedAt", "inputs", "patches", "validations", "reviews", "integration", "runs"], "pipeline.json");
  if (!isSafeId(value.pipelineId) || !isSafeId(value.taskId) || !Number.isSafeInteger(value.ordinal) || !PIPELINE_STATES.has(String(value.state)) || typeof value.phase !== "string" || !Array.isArray(value.runs)) throw new Error("pipeline.json does not match the archive contract");
  return value;
}

export function validateRun(value: JsonRecord) {
  parseJsonFileShape(value, ["runId", "taskId", "pipelineId", "role", "roleOrdinal", "sessionId", "resumeOfRunId", "parentRunId", "retryOfRunId", "state", "startedAt", "updatedAt", "completedAt", "model", "reasoning", "exit", "result", "usage", "cost", "artifacts"], "run.json");
  if (!isSafeId(value.runId) || !isSafeId(value.taskId) || !isSafeId(value.pipelineId) || !isSafeId(value.sessionId) || typeof value.role !== "string" || !RUN_STATES.has(String(value.state)) || typeof value.startedAt !== "string" || typeof value.updatedAt !== "string" || !isRecord(value.artifacts)) throw new Error("run.json does not match the archive contract");
  return value;
}

export function validateValidation(value: JsonRecord) {
  parseJsonFileShape(value, ["validationId", "taskId", "pipelineId", "ordinal", "command", "state", "startedAt", "completedAt", "result", "outputPath", "output"], "validation.json");
  if (!isSafeId(value.validationId) || !isSafeId(value.taskId) || !isSafeId(value.pipelineId) || !isSafeRelativePath(value.outputPath) || typeof value.command !== "string") throw new Error("validation.json does not match the archive contract");
  return value;
}

export function validateReview(value: JsonRecord) {
  parseJsonFileShape(value, ["reviewId", "taskId", "pipelineId", "ordinal", "kind", "role", "state", "verdict", "findings", "artifact"], "review.json");
  if (!isSafeId(value.reviewId) || !isSafeId(value.taskId) || !isSafeId(value.pipelineId) || !Array.isArray(value.findings)) throw new Error("review.json does not match the archive contract");
  return value;
}

export function safeString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export function safeInteger(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
