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

function onlyKeys(value: JsonRecord, allowed: string[], label: string) {
  const keys = new Set(allowed);
  for (const key of Object.keys(value)) if (!keys.has(key)) throw new Error(`${label} contains unsupported ${key}`);
}

function timestamp(value: unknown) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function nullableId(value: unknown) { return value === null || isSafeId(value); }
function nullableTimestamp(value: unknown) { return value === null || timestamp(value); }
function nullableString(value: unknown) { return value === null || (typeof value === "string" && value.length > 0); }
function positiveInteger(value: unknown) { return Number.isSafeInteger(value) && Number(value) >= 1; }

const ARTIFACT_KEYS = ["path", "lifecycle", "availability", "mediaType", "byteSize", "sha256", "requiredAtTerminal", "reason"];
const AVAILABILITY = new Set(["available", "partial", "missing", "unavailable", "notProduced"]);
const LIFECYCLE = new Set(["live", "terminal", "optional"]);
const SHA256 = /^[a-f0-9]{64}$/;

export function validateArtifact(value: unknown, label = "artifact") {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  parseJsonFileShape(value, ARTIFACT_KEYS, label);
  onlyKeys(value, ARTIFACT_KEYS, label);
  if (!isSafeRelativePath(value.path) || !LIFECYCLE.has(String(value.lifecycle)) || !AVAILABILITY.has(String(value.availability))) throw new Error(`${label} does not match the archive contract`);
  if (!(value.mediaType === null || typeof value.mediaType === "string") || !(value.byteSize === null || safeInteger(value.byteSize) !== null) || !(value.sha256 === null || typeof value.sha256 === "string" && SHA256.test(value.sha256)) || typeof value.requiredAtTerminal !== "boolean" || !nullableString(value.reason)) throw new Error(`${label} does not match the archive contract`);
  return value;
}

function validateRef(value: unknown, idKey: string, label: string, extra: (record: JsonRecord) => boolean) {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const allowed = idKey === "runId" ? [idKey, "role", "roleOrdinal", "state", "path"] : idKey === "reviewId" ? [idKey, "ordinal", "kind", "path"] : [idKey, "ordinal", "path"];
  parseJsonFileShape(value, allowed, label);
  onlyKeys(value, allowed, label);
  if (!isSafeId(value[idKey]) || !isSafeRelativePath(value.path) || !extra(value)) throw new Error(`${label} does not match the archive contract`);
  return value;
}

export function validateEpoch(value: JsonRecord) {
  const keys = ["epochId", "formatVersion", "policy", "startedAt", "endedAt"];
  parseJsonFileShape(value, ["epochId", "formatVersion", "policy", "startedAt"], "epoch.json");
  onlyKeys(value, keys, "epoch.json");
  if (!isSafeId(value.epochId) || value.formatVersion !== "1.0" || value.policy !== "post-steward-2.0" || !timestamp(value.startedAt) || ("endedAt" in value && !nullableTimestamp(value.endedAt))) throw new Error("epoch.json does not match the archive contract");
  return value as { epochId: string; formatVersion: "1.0"; policy: "post-steward-2.0"; startedAt: string; endedAt?: string | null };
}

const TASK_STATES = new Set(["queued", "running", "reviewing", "integrating", "succeeded", "pushed", "no_changes", "blocked", "failed", "cancelled"]);
const PIPELINE_STATES = new Set(["active", "succeeded", "failed", "blocked", "cancelled", "interrupted", "superseded"]);
const RUN_STATES = new Set(["running", "succeeded", "failed", "interrupted", "cancelled"]);
const TRIGGERS = new Set(["initial", "validation-repair", "review-repair", "integration-rebase", "integration-conflict", "push-race"]);
const PHASES = new Set(["planning", "implementation", "validation", "review", "integration", "complete"]);
const VALIDATION_STATES = new Set(["running", "completed", "unavailable"]);
const VALIDATION_RESULTS = new Set(["pass", "fail", "skipped", "unavailable"]);
const REVIEW_KINDS = new Set(["raw", "effective"]);
const REVIEW_STATES = new Set(["available", "partial", "unavailable"]);
const REVIEW_VERDICTS = new Set(["approve", "request-changes", "unknown", "unavailable"]);
const INTEGRATION_STATES = new Set(["pending", "succeeded", "failed", "conflict", "unavailable"]);

function validateIntegration(value: unknown) {
  const keys = ["state", "resultPath", "commit", "startedAt", "completedAt"];
  if (!isRecord(value)) throw new Error("pipeline integration must be an object");
  parseJsonFileShape(value, keys, "pipeline integration"); onlyKeys(value, keys, "pipeline integration");
  if (!INTEGRATION_STATES.has(String(value.state)) || !(value.resultPath === null || isSafeRelativePath(value.resultPath)) || !(value.commit === null || typeof value.commit === "string" && /^[a-f0-9]{40}$/.test(value.commit)) || !timestamp(value.startedAt) || !nullableTimestamp(value.completedAt)) throw new Error("pipeline integration does not match the archive contract");
}

function validateRunUsage(value: JsonRecord) {
  const keys = ["availability", "promptTokens", "completionTokens", "totalTokens", "sourcePath", "reason"];
  parseJsonFileShape(value, keys, "run usage"); onlyKeys(value, keys, "run usage");
  if (!new Set(["available", "partial", "unavailable"]).has(String(value.availability)) || ![value.promptTokens, value.completionTokens, value.totalTokens].every((item) => item === null || safeInteger(item) !== null) || !(value.sourcePath === null || isSafeRelativePath(value.sourcePath)) || !nullableString(value.reason)) throw new Error("run usage does not match the archive contract");
  if (value.availability === "available" && ([value.promptTokens, value.completionTokens, value.totalTokens].some((item) => safeInteger(item) === null) || !isSafeRelativePath(value.sourcePath) || value.reason !== null)) throw new Error("available run usage is incomplete");
  if (value.availability === "unavailable" && (value.promptTokens !== null || value.completionTokens !== null || value.totalTokens !== null || value.sourcePath !== null || typeof value.reason !== "string")) throw new Error("unavailable run usage is not explicit");
}

function validateRunCost(value: JsonRecord) {
  const keys = ["availability", "estimatedMicroUsd", "currency", "model", "pricingSource", "reason"];
  parseJsonFileShape(value, keys, "run cost"); onlyKeys(value, keys, "run cost");
  if (!new Set(["available", "partial", "unavailable"]).has(String(value.availability)) || !(value.estimatedMicroUsd === null || safeInteger(value.estimatedMicroUsd) !== null) || !(value.currency === null || typeof value.currency === "string" && /^[A-Z]{3}$/.test(value.currency)) || !nullableString(value.model) || !nullableString(value.pricingSource) || !nullableString(value.reason)) throw new Error("run cost does not match the archive contract");
  if (value.availability === "available" && (safeInteger(value.estimatedMicroUsd) === null || value.currency !== "USD" || typeof value.model !== "string" || typeof value.pricingSource !== "string" || value.reason !== null)) throw new Error("available run cost is incomplete");
  if (value.availability === "unavailable" && (value.estimatedMicroUsd !== null || value.currency !== null || value.pricingSource !== null || typeof value.reason !== "string")) throw new Error("unavailable run cost is not explicit");
}

export function validateTask(value: JsonRecord) {
  const keys = ["taskId", "epochId", "status", "promptPath", "eventsPath", "createdAt", "updatedAt", "currentPipelineId", "summary", "pipelines", "terminalStatusObservedAt", "manifestPath"];
  parseJsonFileShape(value, keys.slice(0, 10), "task.json");
  onlyKeys(value, keys, "task.json");
  if (!isSafeId(value.taskId) || !isSafeId(value.epochId) || !TASK_STATES.has(String(value.status)) || !isSafeRelativePath(value.promptPath) || !isSafeRelativePath(value.eventsPath) || !timestamp(value.createdAt) || !timestamp(value.updatedAt) || !nullableId(value.currentPipelineId) || !Array.isArray(value.pipelines) || value.pipelines.length < 1 || !isRecord(value.summary) || typeof value.summary.title !== "string" || !value.summary.title || typeof value.summary.text !== "string" || !value.summary.text) throw new Error("task.json does not match the archive contract");
  onlyKeys(value.summary, ["title", "text"], "task summary");
  for (const ref of value.pipelines) validateRef(ref, "pipelineId", "pipeline reference", (item) => positiveInteger(item.ordinal));
  if ("terminalStatusObservedAt" in value && !nullableTimestamp(value.terminalStatusObservedAt)) throw new Error("task.json has an invalid terminal timestamp");
  if ("manifestPath" in value && !(value.manifestPath === null || isSafeRelativePath(value.manifestPath))) throw new Error("task.json has an invalid manifest path");
  return value;
}

export function validatePipeline(value: JsonRecord) {
  const keys = ["pipelineId", "taskId", "ordinal", "trigger", "parentPipelineId", "phase", "state", "baseIdentity", "inputIdentity", "outputIdentity", "patchIdentity", "startedAt", "updatedAt", "completedAt", "inputs", "patches", "validations", "reviews", "integration", "runs"];
  parseJsonFileShape(value, keys, "pipeline.json");
  onlyKeys(value, keys, "pipeline.json");
  if (!isSafeId(value.pipelineId) || !isSafeId(value.taskId) || !positiveInteger(value.ordinal) || !TRIGGERS.has(String(value.trigger)) || !nullableId(value.parentPipelineId) || !PHASES.has(String(value.phase)) || !PIPELINE_STATES.has(String(value.state)) || !nullableString(value.baseIdentity) || !nullableString(value.inputIdentity) || !nullableString(value.outputIdentity) || !nullableString(value.patchIdentity) || !timestamp(value.startedAt) || !timestamp(value.updatedAt) || !nullableTimestamp(value.completedAt) || !Array.isArray(value.inputs) || !Array.isArray(value.patches) || !Array.isArray(value.validations) || !Array.isArray(value.reviews) || !Array.isArray(value.runs) || value.runs.length < 1) throw new Error("pipeline.json does not match the archive contract");
  for (const item of value.inputs) validateArtifact(item, "pipeline input");
  for (const item of value.patches) validateArtifact(item, "pipeline patch");
  for (const ref of value.validations) validateRef(ref, "validationId", "validation reference", (item) => positiveInteger(item.ordinal));
  for (const ref of value.reviews) validateRef(ref, "reviewId", "review reference", (item) => positiveInteger(item.ordinal) && REVIEW_KINDS.has(String(item.kind)));
  for (const ref of value.runs) validateRef(ref, "runId", "run reference", (item) => positiveInteger(item.roleOrdinal) && typeof item.role === "string" && item.role.length > 0 && RUN_STATES.has(String(item.state)));
  validateIntegration(value.integration);
  return value;
}

export function validateRun(value: JsonRecord) {
  const keys = ["runId", "taskId", "pipelineId", "role", "roleOrdinal", "sessionId", "resumeOfRunId", "parentRunId", "retryOfRunId", "state", "startedAt", "updatedAt", "completedAt", "model", "reasoning", "exit", "result", "usage", "cost", "artifacts"];
  parseJsonFileShape(value, keys, "run.json");
  onlyKeys(value, keys, "run.json");
  if (!isSafeId(value.runId) || !isSafeId(value.taskId) || !isSafeId(value.pipelineId) || !isSafeId(value.sessionId) || typeof value.role !== "string" || !value.role || !positiveInteger(value.roleOrdinal) || !nullableId(value.resumeOfRunId) || !nullableId(value.parentRunId) || !nullableId(value.retryOfRunId) || !RUN_STATES.has(String(value.state)) || !timestamp(value.startedAt) || !timestamp(value.updatedAt) || !nullableTimestamp(value.completedAt) || !nullableString(value.model) || !nullableString(value.reasoning) || !isRecord(value.result) || !isRecord(value.usage) || !isRecord(value.cost) || !isRecord(value.artifacts)) throw new Error("run.json does not match the archive contract");
  parseJsonFileShape(value.result, ["status", "summary", "path"], "run result"); onlyKeys(value.result, ["status", "summary", "path"], "run result");
  if (!REVIEW_STATES.has(String(value.result.status)) || !(value.result.summary === null || typeof value.result.summary === "string") || !(value.result.path === null || isSafeRelativePath(value.result.path))) throw new Error("run result does not match the archive contract");
  if (value.exit !== null) {
    if (!isRecord(value.exit)) throw new Error("run exit must be an object");
    parseJsonFileShape(value.exit, ["code", "signal", "reason"], "run exit"); onlyKeys(value.exit, ["code", "signal", "reason"], "run exit");
    if (!(value.exit.code === null || Number.isSafeInteger(value.exit.code)) || !nullableString(value.exit.signal) || !nullableString(value.exit.reason)) throw new Error("run exit does not match the archive contract");
  }
  validateRunUsage(value.usage); validateRunCost(value.cost);
  const artifactKeys = ["codex", "activities", "telemetry", "lastMessage", "result", "toolChangesManifest", "toolChangesSummary"];
  parseJsonFileShape(value.artifacts, artifactKeys, "run artifacts"); onlyKeys(value.artifacts, artifactKeys, "run artifacts");
  for (const artifact of Object.values(value.artifacts)) validateArtifact(artifact, "run artifact");
  return value;
}

export function validateValidation(value: JsonRecord) {
  const keys = ["validationId", "taskId", "pipelineId", "ordinal", "command", "state", "startedAt", "completedAt", "result", "outputPath", "output"];
  parseJsonFileShape(value, keys, "validation.json"); onlyKeys(value, keys, "validation.json");
  if (!isSafeId(value.validationId) || !isSafeId(value.taskId) || !isSafeId(value.pipelineId) || !positiveInteger(value.ordinal) || !isSafeRelativePath(value.outputPath) || typeof value.command !== "string" || !value.command || !VALIDATION_STATES.has(String(value.state)) || !VALIDATION_RESULTS.has(String(value.result)) || !timestamp(value.startedAt) || !nullableTimestamp(value.completedAt)) throw new Error("validation.json does not match the archive contract");
  validateArtifact(value.output, "validation output");
  return value;
}

export function validateReview(value: JsonRecord) {
  const keys = ["reviewId", "taskId", "pipelineId", "ordinal", "kind", "role", "state", "verdict", "findings", "artifact"];
  parseJsonFileShape(value, keys, "review.json"); onlyKeys(value, keys, "review.json");
  if (!isSafeId(value.reviewId) || !isSafeId(value.taskId) || !isSafeId(value.pipelineId) || !positiveInteger(value.ordinal) || !REVIEW_KINDS.has(String(value.kind)) || typeof value.role !== "string" || !value.role || !REVIEW_STATES.has(String(value.state)) || !REVIEW_VERDICTS.has(String(value.verdict)) || !Array.isArray(value.findings) || value.findings.some((item) => typeof item !== "string")) throw new Error("review.json does not match the archive contract");
  validateArtifact(value.artifact, "review artifact");
  return value;
}

export function validateManifest(value: JsonRecord) {
  const keys = ["manifestVersion", "epochId", "taskId", "completionIdentity", "terminalStatus", "completedAt", "files"];
  parseJsonFileShape(value, keys, "manifest.json"); onlyKeys(value, keys, "manifest.json");
  if (value.manifestVersion !== "1.0" || !isSafeId(value.epochId) || !isSafeId(value.taskId) || !isSafeId(value.completionIdentity) || !new Set(["succeeded", "pushed", "no_changes", "blocked", "failed", "cancelled"]).has(String(value.terminalStatus)) || !timestamp(value.completedAt) || !Array.isArray(value.files) || value.files.length < 1) throw new Error("manifest.json does not match the archive contract");
  let previous = "";
  for (const item of value.files) {
    if (!isRecord(item)) throw new Error("manifest file must be an object");
    parseJsonFileShape(item, ["path", "byteSize", "sha256"], "manifest file"); onlyKeys(item, ["path", "byteSize", "sha256"], "manifest file");
    if (!isSafeRelativePath(item.path) || safeInteger(item.byteSize) === null || typeof item.sha256 !== "string" || !SHA256.test(item.sha256) || String(item.path) <= previous) throw new Error("manifest files must be unique and sorted");
    previous = String(item.path);
  }
  return value;
}

export function safeString(value: unknown): string | null { return typeof value === "string" ? value : null; }
export function safeInteger(value: unknown): number | null { return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null; }

export { TASK_STATES, TERMINAL_TASK_STATES };
const TERMINAL_TASK_STATES = new Set(["succeeded", "pushed", "no_changes", "blocked", "failed", "cancelled"]);
