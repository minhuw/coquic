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
export type CloudRun = { runId: string; taskId: string; pipelineId: string; role: string; runState: CloudRunState; startedAt: CloudTimestamp; completedAt: CloudTimestamp; durationMs: number; atifDigest: string; atifArtifactId: string };
export type CloudEvent = { taskId: string; sequence: number; eventType: string; occurredAt: CloudTimestamp; summary: string };
export type CloudArtifact = { artifactId: string; taskId: string; runId: string; logicalPath: string; publicKey: string; mediaType: string; byteSize: number; sha256: string; availability: CloudAvailability; disclosure: CloudDisclosure };
export type CloudTrajectoryDescriptor = { taskId: string; pipelineId: string; runId: string; role: string; runState: CloudRunState; startedAt: CloudTimestamp; completedAt: CloudTimestamp; durationMs: number; artifactId: string; publicKey: string; mediaType: "application/json"; byteSize: number; sha256: string; availability: CloudAvailability; disclosure: CloudDisclosure };
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

function invalid(): never { throw new Error(INVALID_MESSAGE); }
function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function validatorFor(definition: string) {
  let validator = validators.get(definition);
  if (!validator) { validator = ajv.compile({ $ref: `${schemaId}#/$defs/${definition}` }); validators.set(definition, validator); }
  return validator;
}
function validateDefinition<T>(value: unknown, definition: string): T {
  if (!isRecord(value) || !validatorFor(definition)(value)) invalid();
  return value as T;
}
function time(value: string): number { const parsed = Date.parse(value); return Number.isFinite(parsed) ? parsed : invalid(); }
function ordered(startedAt: string, completedAt: string) { if (time(startedAt) > time(completedAt)) invalid(); }
function publicKeyMatches(key: string, taskId: string, digest: string) {
  const match = /^v1\/tasks\/([^/]+)\/objects\/sha256\/([0-9a-f]{2})\/([0-9a-f]{64})$/.exec(key);
  if (!match || match[1] !== taskId || match[2] !== digest.slice(0, 2) || match[3] !== digest) invalid();
}
function unique(values: string[]) { if (new Set(values).size !== values.length) invalid(); }

function checkArtifact(value: CloudArtifact) { publicKeyMatches(value.publicKey, value.taskId, value.sha256); }
function checkDescriptor(value: CloudTrajectoryDescriptor) { publicKeyMatches(value.publicKey, value.taskId, value.sha256); ordered(value.startedAt, value.completedAt); }
function checkRun(value: CloudRun) { ordered(value.startedAt, value.completedAt); }

function checkPage(value: CloudTaskPage) {
  unique(value.items.map((item) => item.taskId));
  if (value.pagination.total < value.items.length || value.pagination.hasNextPage !== value.pagination.page * value.pagination.pageSize < value.pagination.total) invalid();
}

function checkDetail(value: CloudTaskDetail) {
  const taskId = value.task.taskId;
  const pipelines = new Map(value.pipelines.map((pipeline) => [pipeline.pipelineId, pipeline]));
  const runs = new Map(value.runs.map((run) => [run.runId, run]));
  const artifacts = new Map(value.artifacts.map((artifact) => [artifact.artifactId, artifact]));
  unique(value.pipelines.map((pipeline) => pipeline.pipelineId)); unique(value.runs.map((run) => run.runId));
  unique(value.events.map((event) => `${event.taskId}:${event.sequence}`)); unique(value.artifacts.map((artifact) => artifact.artifactId));
  if (value.pipelines.some((pipeline) => pipeline.taskId !== taskId)) invalid();
  value.runs.forEach((run) => { checkRun(run); if (run.taskId !== taskId || !pipelines.has(run.pipelineId)) invalid(); const atif = artifacts.get(run.atifArtifactId); if (!atif || atif.taskId !== taskId || atif.runId !== run.runId || atif.sha256 !== run.atifDigest) invalid(); });
  value.events.forEach((event, index) => { if (event.taskId !== taskId || event.sequence !== index + 1) invalid(); });
  value.artifacts.forEach((artifact) => { checkArtifact(artifact); if (artifact.taskId !== taskId || !runs.has(artifact.runId)) invalid(); });
  if (value.task.eventCount !== value.events.length || value.task.artifactCount !== value.artifacts.length) invalid();
  if (value.task.pipelineId !== null && !pipelines.has(value.task.pipelineId)) invalid();
  if (value.task.completedRunId !== null && !runs.has(value.task.completedRunId)) invalid();
  if (value.trajectory !== null) { checkDescriptor(value.trajectory); const run = runs.get(value.trajectory.runId); const artifact = artifacts.get(value.trajectory.artifactId); if (!run || !artifact || run.pipelineId !== value.trajectory.pipelineId || run.taskId !== value.trajectory.taskId || run.atifArtifactId !== value.trajectory.artifactId || artifact.publicKey !== value.trajectory.publicKey || artifact.sha256 !== value.trajectory.sha256) invalid(); }
}

export function validateCloudMetadata(value: unknown): CloudMetadata { return validateDefinition<CloudMetadata>(value, "metadata"); }
export function validateCloudStatusData(value: unknown): CloudStatus { return validateDefinition<CloudStatus>(value, "status"); }
export function validateCloudTaskSummary(value: unknown): CloudTaskSummary { return validateDefinition<CloudTaskSummary>(value, "taskSummary"); }
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
  if ("artifactId" in value.data && "pipelineId" in value.data) return validateCloudTrajectoryDescriptorResponse(value);
  return validateCloudStatusResponse(value);
}

export function parseCloudResponse(source: string): CloudResponse { try { return validateCloudResponse(JSON.parse(source)); } catch { invalid(); } }
export function serializeCloudResponse(value: unknown): string { return JSON.stringify(validateCloudResponse(value)); }
export function serializeCloudStatus(value: unknown): string { return JSON.stringify(validateCloudStatusResponse(value)); }
export function serializeCloudTaskPage(value: unknown): string { return JSON.stringify(validateCloudTaskPageResponse(value)); }
export function serializeCloudTaskDetail(value: unknown): string { return JSON.stringify(validateCloudTaskDetailResponse(value)); }
export function serializeCloudTrajectoryDescriptor(value: unknown): string { return JSON.stringify(validateCloudTrajectoryDescriptorResponse(value)); }
export function serializeCloudProblem(value: unknown): string { return JSON.stringify(validateCloudProblemResponse(value)); }
