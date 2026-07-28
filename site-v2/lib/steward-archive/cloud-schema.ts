import Ajv2020, { type AnySchema, type ValidateFunction } from "ajv/dist/2020";
import addFormats from "ajv-formats";
import cloudSchema from "../../schemas/steward-cloud.schema.json";

export type CloudTimestamp = string;
export type CloudLifecycleState = "active" | "completed" | "failed" | "cancelled";
export type CloudRunState = "completed" | "failed" | "cancelled";
export type CloudAvailability = "available" | "unavailable";
export type CloudDisclosure = { redactionApplied: boolean; originalRetained: boolean };
export type CloudMetadata = { generatedAt: CloudTimestamp };
export type CloudProblem = { code: string; message: string; retryable: boolean; status: number | null; type: string | null };
export type CloudStatus = { state: "available" | "empty" | "unavailable"; taskCount: number; latestPublicationAt: CloudTimestamp | null };
export type CloudPipeline = { pipelineId: string; taskId: string; name: string; createdAt: CloudTimestamp };
export type CloudRun = { runId: string; taskId: string; pipelineId: string; role: string; runState: CloudRunState; startedAt: CloudTimestamp; completedAt: CloudTimestamp; durationMs: number; atifDigest: string; atifArtifactId?: string | null };
export type CloudEvent = { taskId: string; sequence: number; eventType: string; occurredAt: CloudTimestamp; summary: string };
export type CloudArtifact = { artifactId: string; taskId: string; runId: string; logicalPath: string; publicKey: string; mediaType: string; byteSize: number; sha256: string; availability: CloudAvailability; disclosure: CloudDisclosure };
export type CloudTrajectoryDescriptor = { taskId: string; pipelineId: string; runId: string; role: string; runState: CloudRunState; startedAt: CloudTimestamp; completedAt: CloudTimestamp; durationMs: number; artifactId?: string | null; publicKey: string; mediaType: "application/json"; byteSize: number; sha256: string; availability: "available"; disclosure: CloudDisclosure };
export type CloudTaskSummary = { taskId: string; title: string; lifecycleState: CloudLifecycleState; createdAt: CloudTimestamp; completedAt: CloudTimestamp | null; completeness: "complete"; pipelineId: string | null; completedRunId: string | null; eventCount: number; artifactCount: number; disclosure: CloudDisclosure };
export type CloudPagination = { page: number; pageSize: number; total: number; hasNextPage: boolean };
export type CloudTaskPage = { items: CloudTaskSummary[]; pagination: CloudPagination };
export type CloudTaskDetail = { task: CloudTaskSummary; pipelines: CloudPipeline[]; runs: CloudRun[]; events: CloudEvent[]; artifacts: CloudArtifact[]; trajectory: CloudTrajectoryDescriptor | null };
export type CloudStatusResponse = { schemaVersion: "3.0"; generatedAt: CloudTimestamp; data: CloudStatus };
export type CloudTaskPageResponse = { schemaVersion: "3.0"; generatedAt: CloudTimestamp; data: CloudTaskPage };
export type CloudTaskDetailResponse = { schemaVersion: "3.0"; generatedAt: CloudTimestamp; data: CloudTaskDetail };
export type CloudTrajectoryDescriptorResponse = { schemaVersion: "3.0"; generatedAt: CloudTimestamp; data: CloudTrajectoryDescriptor };
export type CloudProblemResponse = { schemaVersion: "3.0"; generatedAt: CloudTimestamp; problem: CloudProblem };
export type CloudResponse = CloudStatusResponse | CloudTaskPageResponse | CloudTaskDetailResponse | CloudTrajectoryDescriptorResponse | CloudProblemResponse;

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(cloudSchema as AnySchema);
const schemaId = String(cloudSchema.$id);
const validators = new Map<string, ValidateFunction>();
const INVALID_MESSAGE = "invalid Steward cloud response";
const TIMESTAMP = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?Z$/;
const PRIVATE_NAME = /(?:private|secret|credential|password|authorization|apikey|presign|signed|scanner|filesystem|file[_-]?path|endpoint|uri|url|bucket|object[_-]?key|token)/i;
const LOCATOR = /(?:[a-z][a-z0-9+.-]*:\/\/|(?:^|[\s"'([{<>=,:;])(?:~[\\/]|\/{2}|\\\\|[A-Za-z]:[\\/])|(?:^|[\s"'([{<>=,:;])\/(?:[^\s/]|$))/i;
const PRIVATE_VALUE = /(?:https?|s3|gs|file|ssh|ftp|postgres|redis|wss?):\/\/|(?:^|[-_])(private|internal|secret)[-_](bucket|object(?:[-_]key)?|url|path)(?:$|[-_])/i;

function invalid(): never { throw new Error(INVALID_MESSAGE); }
function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function validatorFor(definition: string) {
  let validator = validators.get(definition);
  if (!validator) { validator = ajv.compile({ $ref: `${schemaId}#/$defs/${definition}` }); validators.set(definition, validator); }
  return validator;
}
function publicScan(value: unknown): void { if (typeof value === "string") { if (LOCATOR.test(value) || PRIVATE_VALUE.test(value)) invalid(); return; } if (Array.isArray(value)) { value.forEach(publicScan); return; } if (!value || typeof value !== "object") return; for (const [key, item] of Object.entries(value as Record<string, unknown>)) { if (PRIVATE_NAME.test(key) && key !== "logicalPath" && key !== "publicKey") invalid(); publicScan(item); } }
function validateDefinition<T>(value: unknown, definition: string): T { if (!isRecord(value) || !validatorFor(definition)(value)) invalid(); publicScan(value); return value as T; }
function time(value: string): bigint { const match = TIMESTAMP.exec(value); if (!match) invalid(); const parsed = Date.parse(`${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`); if (!Number.isSafeInteger(parsed)) invalid(); return BigInt(parsed) * 1000000n + BigInt(((match[7]?.slice(1) || "") + "000000000").slice(0, 9)); }
function ordered(startedAt: string, completedAt: string) { if (time(startedAt) > time(completedAt)) invalid(); }
function exactDuration(startedAt: string, completedAt: string, durationMs: number) { const delta = time(completedAt) - time(startedAt); if (delta < 0n || delta % 1000000n !== 0n || BigInt(durationMs) !== delta / 1000000n) invalid(); }
function publicKeyMatches(key: string, taskId: string, digest: string) {
  const match = /^v1\/tasks\/([^/]+)\/objects\/sha256\/([0-9a-f]{2})\/([0-9a-f]{64})$/.exec(key);
  if (!match || match[1] !== taskId || match[2] !== digest.slice(0, 2) || match[3] !== digest) invalid();
}
function unique(values: string[]) { if (new Set(values).size !== values.length) invalid(); }

function checkTask(value: CloudTaskSummary) { if ((value.lifecycleState === "active") !== (value.completedAt === null)) invalid(); if (value.completedAt !== null) ordered(value.createdAt, value.completedAt); }
function checkArtifact(value: CloudArtifact) { publicKeyMatches(value.publicKey, value.taskId, value.sha256); }
function checkDescriptor(value: CloudTrajectoryDescriptor) { if (value.availability !== "available") invalid(); publicKeyMatches(value.publicKey, value.taskId, value.sha256); ordered(value.startedAt, value.completedAt); exactDuration(value.startedAt, value.completedAt, value.durationMs); }
function checkRun(value: CloudRun) { ordered(value.startedAt, value.completedAt); exactDuration(value.startedAt, value.completedAt, value.durationMs); }

function checkPage(value: CloudTaskPage) {
  value.items.forEach(checkTask);
  unique(value.items.map((item) => item.taskId));
  if (value.pagination.total < value.items.length || value.pagination.hasNextPage !== value.pagination.page * value.pagination.pageSize < value.pagination.total) invalid();
}

function checkDetail(value: CloudTaskDetail) {
  checkTask(value.task);
  const taskId = value.task.taskId;
  const pipelines = new Map(value.pipelines.map((pipeline) => [pipeline.pipelineId, pipeline]));
  const runs = new Map(value.runs.map((run) => [run.runId, run]));
  const artifacts = new Map(value.artifacts.map((artifact) => [artifact.artifactId, artifact]));
  unique(value.pipelines.map((pipeline) => pipeline.pipelineId)); unique(value.runs.map((run) => run.runId));
  unique(value.events.map((event) => `${event.taskId}:${event.sequence}`)); unique(value.artifacts.map((artifact) => artifact.artifactId)); unique(value.artifacts.map((artifact) => artifact.logicalPath));
  if (value.pipelines.some((pipeline) => pipeline.taskId !== taskId)) invalid();
  value.artifacts.forEach((artifact) => { checkArtifact(artifact); if (artifact.taskId !== taskId || !runs.has(artifact.runId)) invalid(); });
  const objectSizes = new Map<string, number>(); value.artifacts.forEach((artifact) => { const prior = objectSizes.get(artifact.publicKey); if (prior !== undefined && prior !== artifact.byteSize) invalid(); objectSizes.set(artifact.publicKey, artifact.byteSize); });
  value.runs.forEach((run) => { checkRun(run); if (run.taskId !== taskId || !pipelines.has(run.pipelineId)) invalid(); const atif = value.artifacts.filter((artifact) => artifact.runId === run.runId && artifact.sha256 === run.atifDigest && artifact.mediaType === "application/json"); if (!atif.length || (run.atifArtifactId != null && (atif.length !== 1 || atif[0].artifactId !== run.atifArtifactId))) invalid(); });
  value.events.forEach((event, index) => { if (event.taskId !== taskId || event.sequence !== index + 1) invalid(); });
  if (value.task.eventCount !== value.events.length || value.task.artifactCount !== value.artifacts.length) invalid();
  if (value.task.pipelineId !== null && !pipelines.has(value.task.pipelineId)) invalid();
  if (value.task.completedRunId !== null) { const completed = runs.get(value.task.completedRunId); if (!completed || completed.runState !== "completed" || (value.task.pipelineId !== null && completed.pipelineId !== value.task.pipelineId)) invalid(); }
  const completed = value.task.completedRunId === null ? undefined : runs.get(value.task.completedRunId);
  const completedAtif = completed ? value.artifacts.filter((artifact) => artifact.runId === completed.runId && artifact.sha256 === completed.atifDigest && artifact.mediaType === "application/json") : [];
  if ((value.trajectory !== null) !== completedAtif.some((artifact) => artifact.availability === "available")) invalid();
  if (value.trajectory !== null) { const descriptor = value.trajectory; checkDescriptor(descriptor); const run = runs.get(descriptor.runId); const matches = value.artifacts.filter((artifact) => artifact.runId === descriptor.runId && artifact.publicKey === descriptor.publicKey && artifact.sha256 === descriptor.sha256 && artifact.mediaType === "application/json"); const artifact = descriptor.artifactId == null ? undefined : artifacts.get(descriptor.artifactId); if (!run || !matches.length || (descriptor.artifactId != null && (!artifact || matches.length !== 1 || artifact !== matches[0]))) invalid(); if (!run || run.taskId !== descriptor.taskId || run.pipelineId !== descriptor.pipelineId || run.role !== descriptor.role || run.runState !== descriptor.runState || run.startedAt !== descriptor.startedAt || run.completedAt !== descriptor.completedAt || run.durationMs !== descriptor.durationMs || run.atifDigest !== descriptor.sha256) invalid(); if (matches.some((item) => item.byteSize !== descriptor.byteSize || item.availability !== descriptor.availability || item.disclosure.redactionApplied !== descriptor.disclosure.redactionApplied || item.disclosure.originalRetained !== descriptor.disclosure.originalRetained)) invalid(); }
}

export function validateCloudMetadata(value: unknown): CloudMetadata { return validateDefinition<CloudMetadata>(value, "metadata"); }
export function validateCloudStatusData(value: unknown): CloudStatus { return validateDefinition<CloudStatus>(value, "status"); }
export function validateCloudTaskSummary(value: unknown): CloudTaskSummary { const result = validateDefinition<CloudTaskSummary>(value, "taskSummary"); checkTask(result); return result; }
export function validateCloudPipeline(value: unknown): CloudPipeline { return validateDefinition<CloudPipeline>(value, "pipeline"); }
export function validateCloudRun(value: unknown): CloudRun { const result = validateDefinition<CloudRun>(value, "run"); checkRun(result); return result; }
export function validateCloudEvent(value: unknown): CloudEvent { return validateDefinition<CloudEvent>(value, "event"); }
export function validateCloudArtifact(value: unknown): CloudArtifact { const result = validateDefinition<CloudArtifact>(value, "artifact"); checkArtifact(result); return result; }
export function validateCloudTrajectoryDescriptorData(value: unknown): CloudTrajectoryDescriptor { const result = validateDefinition<CloudTrajectoryDescriptor>(value, "trajectoryDescriptor"); checkDescriptor(result); return result; }
export function validateCloudTaskPageData(value: unknown): CloudTaskPage { const result = validateDefinition<CloudTaskPage>(value, "taskPage"); checkPage(result); return result; }
export function validateCloudTaskDetailData(value: unknown): CloudTaskDetail { const result = validateDefinition<CloudTaskDetail>(value, "taskDetail"); checkDetail(result); return result; }
export function validateCloudProblemData(value: unknown): CloudProblem { return validateDefinition<CloudProblem>(value, "problem"); }

export function validateCloudStatusResponse(value: unknown): CloudStatusResponse { const result = validateDefinition<CloudStatusResponse>(value, "statusResponse"); return result; }
export function validateCloudTaskPageResponse(value: unknown): CloudTaskPageResponse { const result = validateDefinition<CloudTaskPageResponse>(value, "taskPageResponse"); checkPage(result.data); return result; }
export function validateCloudTaskDetailResponse(value: unknown): CloudTaskDetailResponse { const result = validateDefinition<CloudTaskDetailResponse>(value, "taskDetailResponse"); checkDetail(result.data); return result; }
export function validateCloudTrajectoryDescriptorResponse(value: unknown): CloudTrajectoryDescriptorResponse { const result = validateDefinition<CloudTrajectoryDescriptorResponse>(value, "trajectoryDescriptorResponse"); checkDescriptor(result.data); return result; }
export function validateCloudProblemResponse(value: unknown): CloudProblemResponse { return validateDefinition<CloudProblemResponse>(value, "problemResponse"); }

export const validateCloudStatus = validateCloudStatusResponse;
export const validateCloudTaskPage = validateCloudTaskPageResponse;
export const validateCloudTaskDetail = validateCloudTaskDetailResponse;
export const validateCloudTrajectoryDescriptor = validateCloudTrajectoryDescriptorResponse;
export const validateCloudProblem = validateCloudProblemResponse;

export function validateCloudResponse(value: unknown): CloudResponse {
  if (!isRecord(value) || value.schemaVersion !== "3.0") invalid();
  if ("problem" in value) return validateCloudProblemResponse(value);
  if (!isRecord(value.data)) invalid();
  if ("items" in value.data) return validateCloudTaskPageResponse(value);
  if ("pipelines" in value.data) return validateCloudTaskDetailResponse(value);
  if ("runId" in value.data && "pipelineId" in value.data && "publicKey" in value.data) return validateCloudTrajectoryDescriptorResponse(value);
  return validateCloudStatusResponse(value);
}

export function parseCloudResponse(source: string): CloudResponse { try { return validateCloudResponse(JSON.parse(source)); } catch { invalid(); } }
export function serializeCloudResponse(value: unknown): string { return JSON.stringify(validateCloudResponse(value)); }
export function serializeCloudStatus(value: unknown): string { return JSON.stringify(validateCloudStatusResponse(value)); }
export function serializeCloudTaskPage(value: unknown): string { return JSON.stringify(validateCloudTaskPageResponse(value)); }
export function serializeCloudTaskDetail(value: unknown): string { return JSON.stringify(validateCloudTaskDetailResponse(value)); }
export function serializeCloudTrajectoryDescriptor(value: unknown): string { return JSON.stringify(validateCloudTrajectoryDescriptorResponse(value)); }
export function serializeCloudProblem(value: unknown): string { return JSON.stringify(validateCloudProblemResponse(value)); }
