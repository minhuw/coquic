import Ajv2020, { type AnySchema, type ValidateFunction } from "ajv/dist/2020";
import addFormats from "ajv-formats";
import cloudSchema from "../../schemas/steward-cloud.schema.json";
import type {
  AtifArtifactAction,
  AtifDisplayArtifact,
  AtifDisplayContent,
  AtifDisplayModel,
  AtifDisplayObservation,
  AtifDisplayStep,
  AtifDisplayToolCall,
} from "./atif-view-model";

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
export type CloudCompleteTrajectory = AtifDisplayModel;
export type CloudCompleteTrajectoryResponse = { schemaVersion: "4.0"; generatedAt: CloudTimestamp; data: CloudCompleteTrajectory };
export type CloudResponse = CloudStatusResponse | CloudTaskPageResponse | CloudTaskDetailResponse | CloudTrajectoryDescriptorResponse | CloudCompleteTrajectoryResponse | CloudProblemResponse;

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
const OBJECT_KEY_VALUE = /v1\/(?:tasks\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\/objects\/sha256|originals\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\/sha256)\//;

const SAME_ORIGIN_HREF = /^\/api\/steward\/tasks\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\/artifact\?path=(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~!$'()*+,;=@-])+$/;
const IMAGE_MEDIA_TYPES = new Set(["image/gif", "image/jpeg", "image/png", "image/webp"]);
const PUBLIC_FIELD_NAMES = new Set([
  "cachedTokens", "promptTokens", "uncachedTokens", "completionTokens", "reasoningTokens", "totalTokens", "knownTokenSubtotal",
  "promptTokenIds", "completionTokenIds", "totalPromptTokens", "totalCompletionTokens", "totalCachedTokens",
]);

function invalid(): never { throw new Error(INVALID_MESSAGE); }
function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function validatorFor(definition: string) {
  let validator = validators.get(definition);
  if (!validator) { validator = ajv.compile({ $ref: `${schemaId}#/$defs/${definition}` }); validators.set(definition, validator); }
  return validator;
}
function publicScan(value: unknown, key?: string, rejectObjectKeys = true): void {
  if (typeof value === "string") {
    if (!(key === "href" && SAME_ORIGIN_HREF.test(value)) && (LOCATOR.test(value) || PRIVATE_VALUE.test(value) || (rejectObjectKeys && key !== "publicKey" && OBJECT_KEY_VALUE.test(value)))) invalid();
    return;
  }
  if (Array.isArray(value)) { value.forEach((item) => publicScan(item, undefined, rejectObjectKeys)); return; }
  if (!value || typeof value !== "object") return;
  for (const [childKey, item] of Object.entries(value as Record<string, unknown>)) {
    if (PRIVATE_NAME.test(childKey) && !PUBLIC_FIELD_NAMES.has(childKey) && childKey !== "logicalPath" && childKey !== "publicKey") invalid();
    publicScan(item, childKey, rejectObjectKeys);
  }
}
function validateDefinition<T>(value: unknown, definition: string): T {
  if (!isRecord(value) || !validatorFor(definition)(value)) invalid();
  publicScan(value, undefined, definition.startsWith("completeTrajectory"));
  return value as T;
}
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

function same(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) && Array.isArray(right)) return left.length === right.length && left.every((item, index) => same(item, right[index]));
  if (isRecord(left) && isRecord(right)) {
    const leftKeys = Object.keys(left).filter((key) => left[key] !== undefined).sort();
    const rightKeys = Object.keys(right).filter((key) => right[key] !== undefined).sort();
    return leftKeys.length === rightKeys.length && leftKeys.every((key, index) => key === rightKeys[index] && same(left[key], right[key]));
  }
  return false;
}

function checkAction(action: AtifArtifactAction, taskId: string, runId: string, artifacts: ReadonlyMap<string, AtifDisplayArtifact>): void {
  if (action.kind === "unavailable") return;
  if (action.taskId !== taskId || action.runId !== runId || !SAME_ORIGIN_HREF.test(action.href)) invalid();
  const prefix = "/api/steward/tasks/" + encodeURIComponent(taskId) + "/artifact?path=";
  if (!action.href.startsWith(prefix)) invalid();
  try {
    if (decodeURIComponent(action.href.slice(prefix.length)) !== action.logicalPath) invalid();
  } catch { invalid(); }
  if ((action.kind === "image") !== IMAGE_MEDIA_TYPES.has(action.mediaType)) invalid();
  const artifact = artifacts.get(action.artifactId);
  if (!artifact || artifact.action.kind === "unavailable" || artifact.mediaType !== action.mediaType || !same(artifact.action, action)) invalid();
}

function checkContent(content: AtifDisplayContent, taskId: string, runId: string, artifacts: ReadonlyMap<string, AtifDisplayArtifact>, stepId: number, usedArtifactSteps: Map<string, Set<number>>): void {
  if (content.kind === "image") {
    if (content.artifactId !== content.action.artifactId) invalid();
    checkAction(content.action, taskId, runId, artifacts);
    if (content.artifactId !== null) {
      const artifact = artifacts.get(content.artifactId);
      if (artifact && artifact.mediaType !== content.mediaType) invalid();
      const steps = usedArtifactSteps.get(content.artifactId) ?? new Set<number>();
      steps.add(stepId);
      usedArtifactSteps.set(content.artifactId, steps);
    }
    if (content.action.kind !== "unavailable" && content.action.mediaType !== content.mediaType) invalid();
  }
}

function checkObservation(observation: AtifDisplayObservation, calls: ReadonlySet<string>, taskId: string, runId: string, artifacts: ReadonlyMap<string, AtifDisplayArtifact>, stepId: number, usedArtifactSteps: Map<string, Set<number>>): void {
  if (observation.matchedCallId !== null && !calls.has(observation.matchedCallId)) invalid();
  if (!Object.prototype.hasOwnProperty.call(observation, "sourceCallId") && observation.matchedCallId !== null) invalid();
  if (observation.sourceCallId === null && observation.matchedCallId !== null) invalid();
  if (typeof observation.sourceCallId === "string" && observation.matchedCallId !== null && observation.sourceCallId !== observation.matchedCallId) invalid();
  if (!Object.prototype.hasOwnProperty.call(observation, "content")) {
    if (observation.parts.length !== 0) invalid();
  } else if (typeof observation.content === "string") {
    if (!same(observation.parts, [{ kind: "text", type: "text", text: observation.content }])) invalid();
  } else if (observation.content === null) {
    if (observation.parts.length !== 0) invalid();
  } else if (Array.isArray(observation.content)) {
    if (!same(observation.content, observation.parts)) invalid();
  } else {
    invalid();
  }
  observation.parts.forEach((content) => checkContent(content, taskId, runId, artifacts, stepId, usedArtifactSteps));
}

function checkToolCall(call: AtifDisplayToolCall, seenCalls: Set<string>, anchors: Set<string>, calls: ReadonlySet<string>, taskId: string, runId: string, artifacts: ReadonlyMap<string, AtifDisplayArtifact>, stepId: number, usedArtifactSteps: Map<string, Set<number>>): void {
  if (call.id !== call.callId || seenCalls.has(call.callId) || anchors.has(call.anchor)) invalid();
  seenCalls.add(call.callId); anchors.add(call.anchor);
  call.observations.forEach((observation) => checkObservation(observation, calls, taskId, runId, artifacts, stepId, usedArtifactSteps));
  checkSafe(call.arguments);
}

function checkSafe(value: unknown): void {
  if (Array.isArray(value)) { value.forEach(checkSafe); return; }
  if (!isRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (PRIVATE_NAME.test(key) && !PUBLIC_FIELD_NAMES.has(key)) invalid();
    checkSafe(child);
  }
}

function checkStep(step: AtifDisplayStep, expectedStepId: number, anchors: Set<string>, seenCalls: Set<string>, calls: ReadonlySet<string>, taskId: string, runId: string, artifacts: ReadonlyMap<string, AtifDisplayArtifact>, usedArtifactSteps: Map<string, Set<number>>): void {
  if (step.stepId !== expectedStepId || step.id !== step.anchor || anchors.has(step.anchor) || step.role !== step.source) invalid();
  anchors.add(step.anchor);
  if (!Object.prototype.hasOwnProperty.call(step, "message")) {
    if (step.content.length !== 0) invalid();
  } else if (typeof step.message === "string") {
    if (!same(step.content, [{ kind: "text", type: "text", text: step.message }])) invalid();
  } else if (step.message === null) {
    if (step.content.length !== 0) invalid();
  } else if (Array.isArray(step.message)) {
    if (!same(step.message, step.content)) invalid();
  } else {
    invalid();
  }
  if (!same(step.content, step.parts) || !same(step.tools, step.calls)) invalid();
  if (step.toolCalls !== undefined && step.toolCalls !== null && !same(step.toolCalls, step.calls)) invalid();
  if (step.toolCalls === null && step.calls.length !== 0) invalid();
  if (!Object.prototype.hasOwnProperty.call(step, "observation") && step.observations.length !== 0) invalid();
  if (step.observation === null && step.observations.length !== 0) invalid();
  if (step.observation !== undefined && step.observation !== null && !same(step.observation.results, step.observations)) invalid();
  step.content.forEach((content) => checkContent(content, taskId, runId, artifacts, step.stepId, usedArtifactSteps));
  step.calls.forEach((call) => checkToolCall(call, seenCalls, anchors, calls, taskId, runId, artifacts, step.stepId, usedArtifactSteps));
  step.observations.forEach((observation) => checkObservation(observation, calls, taskId, runId, artifacts, step.stepId, usedArtifactSteps));
}

function matchedObservationsByCall(steps: readonly AtifDisplayStep[]): Map<string, AtifDisplayObservation[]> {
  const matched = new Map<string, AtifDisplayObservation[]>();
  steps.forEach((step) => step.observations.forEach((observation) => {
    if (observation.matchedCallId === null) return;
    const observations = matched.get(observation.matchedCallId) ?? [];
    observations.push(observation);
    matched.set(observation.matchedCallId, observations);
  }));
  return matched;
}

function checkCompleteTrajectory(value: CloudCompleteTrajectory, depth = 0): void {
  if (depth > 32 || value.kind !== "atif-display") invalid();
  if (value.metadata.taskId !== value.taskId || value.metadata.pipelineId !== value.pipelineId || value.metadata.runId !== value.runId || value.metadata.role !== value.role) invalid();
  if (value.metadata.startedAt !== value.timing.startedAt || value.metadata.completedAt !== value.timing.completedAt || value.metadata.durationMs !== value.timing.durationMs) invalid();
  if (!same(value.metadata.timing, value.timing) || !same(value.metadata.disclosure, value.disclosure) || !same(value.metadata.artifacts, value.artifacts)) invalid();
  if ((value.timing.durationSource === "unavailable") !== (value.timing.durationMs === null)) invalid();
  if (value.lineage.trajectoryId !== value.trajectoryId || value.lineage.sessionId !== value.sessionId) invalid();
  const artifacts = new Map(value.artifacts.map((artifact) => [artifact.artifactId, artifact]));
  const anchors = new Set<string>();
  const calls = new Set<string>();
  value.steps.forEach((step) => step.calls.forEach((call) => calls.add(call.callId)));
  if (calls.size !== value.steps.reduce((total, step) => total + step.calls.length, 0)) invalid();
  const seenCalls = new Set<string>();
  const usedArtifactSteps = new Map<string, Set<number>>();
  value.steps.forEach((step, index) => checkStep(step, index + 1, anchors, seenCalls, calls, value.taskId, value.runId, artifacts, usedArtifactSteps));
  const matched = matchedObservationsByCall(value.steps);
  value.steps.forEach((step) => step.calls.forEach((call) => {
    if (!same(call.observations, matched.get(call.callId) ?? [])) invalid();
  }));
  const artifactIds = new Set<string>();
  value.artifacts.forEach((artifact) => {
    if (artifactIds.has(artifact.artifactId) || !value.steps.some((step) => step.stepId === artifact.ownerStepId)) invalid();
    artifactIds.add(artifact.artifactId);
    checkAction(artifact.action, value.taskId, value.runId, artifacts);
    if (artifact.action.artifactId !== artifact.artifactId) invalid();
    if (artifact.action.kind !== "unavailable" && artifact.action.mediaType !== artifact.mediaType) invalid();
    if (Object.prototype.hasOwnProperty.call(artifact, "disclosure") && !same(artifact.disclosure, value.disclosure)) invalid();
    const usedBy = usedArtifactSteps.get(artifact.artifactId);
    if (usedBy && !usedBy.has(artifact.ownerStepId)) invalid();
  });
  const childTrajectoryIds = new Set<string>();
  value.lineage.trajectories.forEach((trajectory) => {
    if (trajectory.trajectoryId !== undefined && trajectory.trajectoryId !== null) {
      if (childTrajectoryIds.has(trajectory.trajectoryId)) invalid();
      childTrajectoryIds.add(trajectory.trajectoryId);
    }
  });
  value.lineage.references.forEach((reference) => {
    if (reference.trajectoryId !== undefined && reference.trajectoryId !== null && !childTrajectoryIds.has(reference.trajectoryId)) invalid();
  });
  value.lineage.trajectories.forEach((trajectory) => checkCompleteTrajectory(trajectory, depth + 1));
}

export function validateCloudMetadata(value: unknown): CloudMetadata { return validateDefinition<CloudMetadata>(value, "metadata"); }
export function validateCloudStatusData(value: unknown): CloudStatus { return validateDefinition<CloudStatus>(value, "status"); }
export function validateCloudTaskSummary(value: unknown): CloudTaskSummary { const result = validateDefinition<CloudTaskSummary>(value, "taskSummary"); checkTask(result); return result; }
export function validateCloudPipeline(value: unknown): CloudPipeline { return validateDefinition<CloudPipeline>(value, "pipeline"); }
export function validateCloudRun(value: unknown): CloudRun { const result = validateDefinition<CloudRun>(value, "run"); checkRun(result); return result; }
export function validateCloudEvent(value: unknown): CloudEvent { return validateDefinition<CloudEvent>(value, "event"); }
export function validateCloudArtifact(value: unknown): CloudArtifact { const result = validateDefinition<CloudArtifact>(value, "artifact"); checkArtifact(result); return result; }
export function validateCloudTrajectoryDescriptorData(value: unknown): CloudTrajectoryDescriptor { const result = validateDefinition<CloudTrajectoryDescriptor>(value, "trajectoryDescriptor"); checkDescriptor(result); return result; }
export function validateCloudCompleteTrajectoryData(value: unknown): CloudCompleteTrajectory { const result = validateDefinition<CloudCompleteTrajectory>(value, "completeTrajectory"); checkCompleteTrajectory(result); return result; }
export function validateCloudTaskPageData(value: unknown): CloudTaskPage { const result = validateDefinition<CloudTaskPage>(value, "taskPage"); checkPage(result); return result; }
export function validateCloudTaskDetailData(value: unknown): CloudTaskDetail { const result = validateDefinition<CloudTaskDetail>(value, "taskDetail"); checkDetail(result); return result; }
export function validateCloudProblemData(value: unknown): CloudProblem { return validateDefinition<CloudProblem>(value, "problem"); }

export function validateCloudStatusResponse(value: unknown): CloudStatusResponse { const result = validateDefinition<CloudStatusResponse>(value, "statusResponse"); return result; }
export function validateCloudTaskPageResponse(value: unknown): CloudTaskPageResponse { const result = validateDefinition<CloudTaskPageResponse>(value, "taskPageResponse"); checkPage(result.data); return result; }
export function validateCloudTaskDetailResponse(value: unknown): CloudTaskDetailResponse { const result = validateDefinition<CloudTaskDetailResponse>(value, "taskDetailResponse"); checkDetail(result.data); return result; }
export function validateCloudTrajectoryDescriptorResponse(value: unknown): CloudTrajectoryDescriptorResponse { const result = validateDefinition<CloudTrajectoryDescriptorResponse>(value, "trajectoryDescriptorResponse"); checkDescriptor(result.data); return result; }
export function validateCloudCompleteTrajectoryResponse(value: unknown): CloudCompleteTrajectoryResponse { const result = validateDefinition<CloudCompleteTrajectoryResponse>(value, "completeTrajectoryResponse"); checkCompleteTrajectory(result.data); return result; }
export function validateCloudProblemResponse(value: unknown): CloudProblemResponse { return validateDefinition<CloudProblemResponse>(value, "problemResponse"); }

export const validateCloudStatus = validateCloudStatusResponse;
export const validateCloudTaskPage = validateCloudTaskPageResponse;
export const validateCloudTaskDetail = validateCloudTaskDetailResponse;
export const validateCloudTrajectoryDescriptor = validateCloudTrajectoryDescriptorResponse;
export const validateCloudCompleteTrajectory = validateCloudCompleteTrajectoryResponse;
export const validateCloudProblem = validateCloudProblemResponse;

export function validateCloudResponse(value: unknown): CloudResponse {
  if (!isRecord(value) || (value.schemaVersion !== "3.0" && value.schemaVersion !== "4.0")) invalid();
  if (value.schemaVersion === "4.0") return validateCloudCompleteTrajectoryResponse(value);
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
export function serializeCloudCompleteTrajectory(value: unknown): string { return JSON.stringify(validateCloudCompleteTrajectoryResponse(value)); }
export function serializeCloudProblem(value: unknown): string { return JSON.stringify(validateCloudProblemResponse(value)); }

/*
 * Usage is a separate clean-launch projection.  The producer-side contract is
 * intentionally not added to the legacy AJV response schema above: usage rows
 * are read from D1 and validated here before they can reach a route.  Keeping
 * the validators closed also means a future response cannot accidentally leak a
 * private sidecar field by merely selecting another column.
 */
export type CloudUsageCoverage = "complete" | "partial" | "unavailable";
export type CloudUsageOwnership = "task-owned" | "steward-overhead";
export type CloudUsageTokenTotals = {
  promptTokens: number | null;
  cachedTokens: number | null;
  uncachedTokens: number | null;
  completionTokens: number | null;
  reasoningTokens: number | null;
  totalTokens: number | null;
};
export type CloudUsageCostTotals = {
  uncachedInputCostMicroUsd: number | null;
  cachedInputCostMicroUsd: number | null;
  outputCostMicroUsd: number | null;
  totalCostMicroUsd: number | null;
};
export type CloudUsageSummary = CloudUsageTokenTotals & CloudUsageCostTotals & {
  summaryId: string;
  usageGenerationId: string;
  publicationId: string;
  taskId: string;
  runId: string | null;
  scope: "task" | "run";
  coverage: CloudUsageCoverage;
  coveredInvocations: number;
  expectedInvocations: number;
  knownTokenSubtotal: number | null;
  knownCostSubtotalMicroUsd: number | null;
  priceProvenanceDigest: string | null;
};
export type CloudUsageInvocation = CloudUsageTokenTotals & CloudUsageCostTotals & {
  invocationId: string | null;
  usageGenerationId: string;
  publicationId: string | null;
  taskId: string | null;
  pipelineId: string | null;
  runId: string | null;
  ownershipClass: CloudUsageOwnership;
  retryOrdinal: number;
  startedAt: CloudTimestamp | null;
  completedAt: CloudTimestamp | null;
  model: string | null;
  billingMode: "unknown" | "chatgpt" | "api" | null;
  processOutcome: string | null;
  coverage: CloudUsageCoverage;
  issueCount: number;
  coveredTurns: number;
  expectedTurns: number;
  priceEntryDigest: string | null;
};
export type CloudUsageTurn = CloudUsageTokenTotals & CloudUsageCostTotals & {
  turnId: string;
  usageGenerationId: string;
  invocationId: string;
  publicationId: string;
  taskId: string;
  runId: string;
  ordinal: number;
  priceEntryDigest: string | null;
};
export type CloudUsagePrice = {
  priceEntryDigest: string;
  usageGenerationId: string;
  catalogDigest: string;
  model: string;
  effectiveAt: CloudTimestamp;
  effectiveUntil: CloudTimestamp | null;
};
export type CloudUsageGlobal = CloudUsageTokenTotals & CloudUsageCostTotals & {
  globalId: string;
  usageGenerationId: string;
  periodKind: "lifetime" | "daily";
  periodKey: string;
  model: string;
  ownershipClass: CloudUsageOwnership;
  coverage: CloudUsageCoverage;
  coveredInvocations: number;
  expectedInvocations: number;
  knownTokenSubtotal: number | null;
  knownCostSubtotalMicroUsd: number | null;
  priceProvenanceDigest: string | null;
  aggregateOnly: boolean;
};
export type CloudUsageGlobalGroup = {
  model: string;
  ownershipClass: CloudUsageOwnership;
  lifetime: CloudUsageGlobal | null;
  daily: CloudUsageGlobal[];
};
export type CloudUsage = {
  schemaVersion: "1.0";
  usageGenerationId: string;
  publicationId: string;
  taskId: string;
  summaries: CloudUsageSummary[];
  invocations: CloudUsageInvocation[];
  globals: CloudUsageGlobalGroup[];
};
export type CloudUsageTurnPage = {
  turns: CloudUsageTurn[];
  nextCursor: string | null;
  previousCursor: string | null;
  total: number;
};
export type CloudUsageUnavailableReason = "missing" | "invalid" | "unavailable";
export type CloudUsageUnavailable = { kind: "unavailable"; reason: CloudUsageUnavailableReason };
export type CloudUsageReadResult<T> = T | CloudUsageUnavailable;

const USAGE_SAFE_INTEGER_MAX = Number.MAX_SAFE_INTEGER;
const USAGE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const USAGE_DIGEST = /^[0-9a-f]{64}$/;
const USAGE_TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$/;
const USAGE_SUMMARY_KEYS = [
  "summaryId", "usageGenerationId", "publicationId", "taskId", "runId", "scope", "coverage",
  "coveredInvocations", "expectedInvocations", "knownTokenSubtotal", "knownCostSubtotalMicroUsd",
  "promptTokens", "cachedTokens", "uncachedTokens", "completionTokens", "reasoningTokens", "totalTokens",
  "uncachedInputCostMicroUsd", "cachedInputCostMicroUsd", "outputCostMicroUsd", "totalCostMicroUsd",
  "priceProvenanceDigest",
] as const;
const USAGE_INVOCATION_KEYS = [
  "invocationId", "usageGenerationId", "publicationId", "taskId", "pipelineId", "runId", "ownershipClass",
  "retryOrdinal", "startedAt", "completedAt", "model", "billingMode", "processOutcome", "coverage", "issueCount",
  "coveredTurns", "expectedTurns", "promptTokens", "cachedTokens", "uncachedTokens", "completionTokens",
  "reasoningTokens", "totalTokens", "uncachedInputCostMicroUsd", "cachedInputCostMicroUsd", "outputCostMicroUsd",
  "totalCostMicroUsd", "priceEntryDigest",
] as const;
const USAGE_TURN_KEYS = [
  "turnId", "usageGenerationId", "invocationId", "publicationId", "taskId", "runId", "ordinal", "promptTokens",
  "cachedTokens", "uncachedTokens", "completionTokens", "reasoningTokens", "totalTokens", "uncachedInputCostMicroUsd",
  "cachedInputCostMicroUsd", "outputCostMicroUsd", "totalCostMicroUsd", "priceEntryDigest",
] as const;
const USAGE_PRICE_KEYS = ["priceEntryDigest", "usageGenerationId", "catalogDigest", "model", "effectiveAt", "effectiveUntil"] as const;
const USAGE_GLOBAL_KEYS = [
  "globalId", "usageGenerationId", "periodKind", "periodKey", "model", "ownershipClass", "coverage",
  "coveredInvocations", "expectedInvocations", "knownTokenSubtotal", "knownCostSubtotalMicroUsd", "promptTokens",
  "cachedTokens", "uncachedTokens", "completionTokens", "reasoningTokens", "totalTokens", "uncachedInputCostMicroUsd",
  "cachedInputCostMicroUsd", "outputCostMicroUsd", "totalCostMicroUsd", "priceProvenanceDigest", "aggregateOnly",
] as const;

function usageInvalid(): never { invalid(); }
function usageRecord(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) usageInvalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) usageInvalid();
  return value;
}
function usageExact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const row = usageRecord(value);
  const actual = Object.keys(row);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) usageInvalid();
  publicScan(row);
  return row;
}
function usageId(value: unknown): string {
  if (typeof value !== "string" || !USAGE_ID.test(value)) usageInvalid();
  return value;
}
function usageDigest(value: unknown): string {
  if (typeof value !== "string" || !USAGE_DIGEST.test(value)) usageInvalid();
  return value;
}
function usageTimestamp(value: unknown): string {
  if (typeof value !== "string" || !USAGE_TIMESTAMP.test(value) || !Number.isFinite(Date.parse(value))) usageInvalid();
  try {
    validateCloudStatusData({ state: "empty", taskCount: 0, latestPublicationAt: value });
  } catch {
    usageInvalid();
  }
  return value;
}
function usageNullableTimestamp(value: unknown): string | null {
  return value === null ? null : usageTimestamp(value);
}
function usageInteger(value: unknown, maximum = USAGE_SAFE_INTEGER_MAX): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum) usageInvalid();
  return value;
}
function usageNullableInteger(value: unknown): number | null {
  return value === null ? null : usageInteger(value);
}
function usageOptionalId(value: unknown): string | null {
  return value === null ? null : usageId(value);
}
function usageOptionalText(value: unknown, maximum: number): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || [...value].length < 1 || [...value].length > maximum || [...value].some((character) => character.charCodeAt(0) < 0x20)) usageInvalid();
  return value;
}
function usageText(value: unknown, maximum: number): string {
  const result = usageOptionalText(value, maximum);
  if (result === null) usageInvalid();
  return result;
}
function usageFlag(value: unknown): boolean {
  if (value === true || value === 1) return true;
  if (value === false || value === 0) return false;
  usageInvalid();
}
function usageOrdered(startedAt: string | null, completedAt: string | null): void {
  if ((startedAt === null) !== (completedAt === null)) usageInvalid();
  if (startedAt !== null && Date.parse(completedAt!) < Date.parse(startedAt)) usageInvalid();
}
function usageTokens(value: unknown, nullable: boolean): CloudUsageTokenTotals {
  const row = usageExact(value, ["promptTokens", "cachedTokens", "uncachedTokens", "completionTokens", "reasoningTokens", "totalTokens"]);
  const result = {
    promptTokens: nullable ? usageNullableInteger(row.promptTokens) : usageInteger(row.promptTokens),
    cachedTokens: nullable ? usageNullableInteger(row.cachedTokens) : usageInteger(row.cachedTokens),
    uncachedTokens: nullable ? usageNullableInteger(row.uncachedTokens) : usageInteger(row.uncachedTokens),
    completionTokens: nullable ? usageNullableInteger(row.completionTokens) : usageInteger(row.completionTokens),
    reasoningTokens: nullable ? usageNullableInteger(row.reasoningTokens) : usageInteger(row.reasoningTokens),
    totalTokens: nullable ? usageNullableInteger(row.totalTokens) : usageInteger(row.totalTokens),
  };
  const values = Object.values(result);
  if (values.every((item) => item !== null)) {
    if (result.cachedTokens! > result.promptTokens! || result.uncachedTokens !== result.promptTokens! - result.cachedTokens! || result.reasoningTokens! > result.completionTokens! || result.totalTokens !== result.promptTokens! + result.completionTokens!) usageInvalid();
  }
  return result;
}
function usageCosts(value: unknown): CloudUsageCostTotals {
  const row = usageExact(value, ["uncachedInputCostMicroUsd", "cachedInputCostMicroUsd", "outputCostMicroUsd", "totalCostMicroUsd"]);
  const result = {
    uncachedInputCostMicroUsd: usageNullableInteger(row.uncachedInputCostMicroUsd),
    cachedInputCostMicroUsd: usageNullableInteger(row.cachedInputCostMicroUsd),
    outputCostMicroUsd: usageNullableInteger(row.outputCostMicroUsd),
    totalCostMicroUsd: usageNullableInteger(row.totalCostMicroUsd),
  };
  const known = Object.values(result).filter((item) => item !== null).length;
  if (known !== 0 && known !== 4) usageInvalid();
  return result;
}
function usageDigestOrNull(value: unknown): string | null {
  return value === null ? null : usageDigest(value);
}

export function validateCloudUsageTokenTotals(value: unknown): CloudUsageTokenTotals { return usageTokens(value, true); }
export function validateCloudUsageCostTotals(value: unknown): CloudUsageCostTotals { return usageCosts(value); }
export function validateCloudUsageSummary(value: unknown): CloudUsageSummary {
  const row = usageExact(value, USAGE_SUMMARY_KEYS);
  const tokens = usageTokens({
    promptTokens: row.promptTokens, cachedTokens: row.cachedTokens, uncachedTokens: row.uncachedTokens,
    completionTokens: row.completionTokens, reasoningTokens: row.reasoningTokens, totalTokens: row.totalTokens,
  }, true);
  const costs = usageCosts({
    uncachedInputCostMicroUsd: row.uncachedInputCostMicroUsd, cachedInputCostMicroUsd: row.cachedInputCostMicroUsd,
    outputCostMicroUsd: row.outputCostMicroUsd, totalCostMicroUsd: row.totalCostMicroUsd,
  });
  const scope = row.scope;
  const coverage = row.coverage;
  if (scope !== "task" && scope !== "run") usageInvalid();
  if (coverage !== "complete" && coverage !== "partial" && coverage !== "unavailable") usageInvalid();
  const coveredInvocations = usageInteger(row.coveredInvocations);
  const expectedInvocations = usageInteger(row.expectedInvocations);
  if (coveredInvocations > expectedInvocations || (coverage === "complete" && coveredInvocations !== expectedInvocations)) usageInvalid();
  if (scope === "task" && row.runId !== null) usageInvalid();
  if (scope === "run" && row.runId === null) usageInvalid();
  if (coverage === "unavailable" && (row.knownTokenSubtotal !== null || row.knownCostSubtotalMicroUsd !== null)) usageInvalid();
  const knownTokenSubtotal = usageNullableInteger(row.knownTokenSubtotal);
  const knownCostSubtotalMicroUsd = usageNullableInteger(row.knownCostSubtotalMicroUsd);
  if (tokens.totalTokens !== null && knownTokenSubtotal !== null && tokens.totalTokens !== knownTokenSubtotal) usageInvalid();
  if (costs.totalCostMicroUsd !== null && knownCostSubtotalMicroUsd !== null && costs.totalCostMicroUsd !== knownCostSubtotalMicroUsd) usageInvalid();
  return {
    summaryId: usageId(row.summaryId), usageGenerationId: usageId(row.usageGenerationId), publicationId: usageId(row.publicationId), taskId: usageId(row.taskId),
    runId: usageOptionalId(row.runId), scope, coverage, coveredInvocations, expectedInvocations, knownTokenSubtotal, knownCostSubtotalMicroUsd,
    ...tokens, ...costs, priceProvenanceDigest: usageDigestOrNull(row.priceProvenanceDigest),
  };
}

export function validateCloudUsageInvocation(value: unknown): CloudUsageInvocation {
  const row = usageExact(value, USAGE_INVOCATION_KEYS);
  const tokens = usageTokens({
    promptTokens: row.promptTokens, cachedTokens: row.cachedTokens, uncachedTokens: row.uncachedTokens,
    completionTokens: row.completionTokens, reasoningTokens: row.reasoningTokens, totalTokens: row.totalTokens,
  }, true);
  const costs = usageCosts({
    uncachedInputCostMicroUsd: row.uncachedInputCostMicroUsd, cachedInputCostMicroUsd: row.cachedInputCostMicroUsd,
    outputCostMicroUsd: row.outputCostMicroUsd, totalCostMicroUsd: row.totalCostMicroUsd,
  });
  const ownershipClass = row.ownershipClass;
  if (ownershipClass !== "task-owned" && ownershipClass !== "steward-overhead") usageInvalid();
  const coverage = row.coverage;
  if (coverage !== "complete" && coverage !== "partial" && coverage !== "unavailable") usageInvalid();
  const coveredTurns = usageInteger(row.coveredTurns, 4096);
  const expectedTurns = usageInteger(row.expectedTurns, 4096);
  if (coveredTurns > expectedTurns || (coverage === "complete" && coveredTurns !== expectedTurns)) usageInvalid();
  if (ownershipClass === "task-owned") {
    if (row.publicationId === null || row.taskId === null || row.pipelineId === null || row.runId === null) usageInvalid();
  } else if (row.publicationId !== null || row.taskId !== null || row.pipelineId !== null || row.runId !== null || coveredTurns !== 0 || expectedTurns !== 0) usageInvalid();
  if (row.invocationId === null && coverage !== "unavailable") usageInvalid();
  if (coverage === "unavailable" && [...Object.values(tokens), ...Object.values(costs)].some((item) => item !== null)) usageInvalid();
  const priceEntryDigest = usageDigestOrNull(row.priceEntryDigest);
  const knownCosts = Object.values(costs).every((item) => item !== null);
  if (knownCosts !== (priceEntryDigest !== null)) usageInvalid();
  const startedAt = usageNullableTimestamp(row.startedAt);
  const completedAt = usageNullableTimestamp(row.completedAt);
  usageOrdered(startedAt, completedAt);
  return {
    invocationId: usageOptionalId(row.invocationId), usageGenerationId: usageId(row.usageGenerationId), publicationId: usageOptionalId(row.publicationId),
    taskId: usageOptionalId(row.taskId), pipelineId: usageOptionalId(row.pipelineId), runId: usageOptionalId(row.runId), ownershipClass,
    retryOrdinal: usageInteger(row.retryOrdinal), startedAt, completedAt, model: usageOptionalText(row.model, 256),
    billingMode: row.billingMode === null || row.billingMode === "unknown" || row.billingMode === "chatgpt" || row.billingMode === "api" ? row.billingMode : usageInvalid(),
    processOutcome: usageOptionalText(row.processOutcome, 48), coverage, issueCount: usageInteger(row.issueCount), coveredTurns, expectedTurns,
    ...tokens, ...costs, priceEntryDigest,
  };
}

export function validateCloudUsageTurn(value: unknown): CloudUsageTurn {
  const row = usageExact(value, USAGE_TURN_KEYS);
  const tokens = usageTokens({
    promptTokens: row.promptTokens, cachedTokens: row.cachedTokens, uncachedTokens: row.uncachedTokens,
    completionTokens: row.completionTokens, reasoningTokens: row.reasoningTokens, totalTokens: row.totalTokens,
  }, false);
  const costs = usageCosts({
    uncachedInputCostMicroUsd: row.uncachedInputCostMicroUsd, cachedInputCostMicroUsd: row.cachedInputCostMicroUsd,
    outputCostMicroUsd: row.outputCostMicroUsd, totalCostMicroUsd: row.totalCostMicroUsd,
  });
  const priceEntryDigest = usageDigestOrNull(row.priceEntryDigest);
  const knownCosts = Object.values(costs).every((item) => item !== null);
  if (knownCosts !== (priceEntryDigest !== null)) usageInvalid();
  const ordinal = usageInteger(row.ordinal, 4096);
  if (ordinal < 1) usageInvalid();
  return {
    turnId: usageId(row.turnId), usageGenerationId: usageId(row.usageGenerationId), invocationId: usageId(row.invocationId),
    publicationId: usageId(row.publicationId), taskId: usageId(row.taskId), runId: usageId(row.runId), ordinal,
    ...tokens, ...costs, priceEntryDigest,
  };
}

export function validateCloudUsagePrice(value: unknown): CloudUsagePrice {
  const row = usageExact(value, USAGE_PRICE_KEYS);
  const effectiveAt = usageTimestamp(row.effectiveAt);
  const effectiveUntil = usageNullableTimestamp(row.effectiveUntil);
  if (effectiveUntil !== null && Date.parse(effectiveUntil) <= Date.parse(effectiveAt)) usageInvalid();
  return {
    priceEntryDigest: usageDigest(row.priceEntryDigest), usageGenerationId: usageId(row.usageGenerationId), catalogDigest: usageDigest(row.catalogDigest),
    model: usageText(row.model, 256), effectiveAt, effectiveUntil,
  };
}

export function validateCloudUsageGlobal(value: unknown): CloudUsageGlobal {
  const row = usageExact(value, USAGE_GLOBAL_KEYS);
  const tokens = usageTokens({
    promptTokens: row.promptTokens, cachedTokens: row.cachedTokens, uncachedTokens: row.uncachedTokens,
    completionTokens: row.completionTokens, reasoningTokens: row.reasoningTokens, totalTokens: row.totalTokens,
  }, true);
  const costs = usageCosts({
    uncachedInputCostMicroUsd: row.uncachedInputCostMicroUsd, cachedInputCostMicroUsd: row.cachedInputCostMicroUsd,
    outputCostMicroUsd: row.outputCostMicroUsd, totalCostMicroUsd: row.totalCostMicroUsd,
  });
  const periodKind = row.periodKind;
  if (periodKind !== "lifetime" && periodKind !== "daily") usageInvalid();
  if (typeof row.periodKey !== "string" || (periodKind === "lifetime" ? row.periodKey !== "lifetime" : !/^20[0-9]{2}-[0-9]{2}-[0-9]{2}$/.test(row.periodKey))) usageInvalid();
  const ownershipClass = row.ownershipClass;
  if (ownershipClass !== "task-owned" && ownershipClass !== "steward-overhead") usageInvalid();
  const coverage = row.coverage;
  if (coverage !== "complete" && coverage !== "partial" && coverage !== "unavailable") usageInvalid();
  const coveredInvocations = usageInteger(row.coveredInvocations);
  const expectedInvocations = usageInteger(row.expectedInvocations);
  if (coveredInvocations > expectedInvocations || (coverage === "complete" && coveredInvocations !== expectedInvocations)) usageInvalid();
  if (coverage === "unavailable" && (row.knownTokenSubtotal !== null || row.knownCostSubtotalMicroUsd !== null)) usageInvalid();
  const knownTokenSubtotal = usageNullableInteger(row.knownTokenSubtotal);
  const knownCostSubtotalMicroUsd = usageNullableInteger(row.knownCostSubtotalMicroUsd);
  if (tokens.totalTokens !== null && knownTokenSubtotal !== null && tokens.totalTokens !== knownTokenSubtotal) usageInvalid();
  if (costs.totalCostMicroUsd !== null && knownCostSubtotalMicroUsd !== null && costs.totalCostMicroUsd !== knownCostSubtotalMicroUsd) usageInvalid();
  const aggregateOnly = usageFlag(row.aggregateOnly);
  if (!aggregateOnly) usageInvalid();
  return {
    globalId: usageId(row.globalId), usageGenerationId: usageId(row.usageGenerationId), periodKind, periodKey: row.periodKey,
    model: usageText(row.model, 256), ownershipClass, coverage, coveredInvocations, expectedInvocations,
    knownTokenSubtotal, knownCostSubtotalMicroUsd, ...tokens, ...costs, priceProvenanceDigest: usageDigestOrNull(row.priceProvenanceDigest), aggregateOnly,
  };
}

export function validateCloudUsageGlobalGroup(value: unknown): CloudUsageGlobalGroup {
  const row = usageExact(value, ["model", "ownershipClass", "lifetime", "daily"]);
  const model = usageText(row.model, 256);
  const ownershipClass = row.ownershipClass;
  if (ownershipClass !== "task-owned" && ownershipClass !== "steward-overhead") usageInvalid();
  const lifetime = row.lifetime === null ? null : validateCloudUsageGlobal(row.lifetime);
  if (lifetime !== null && (lifetime.model !== model || lifetime.ownershipClass !== ownershipClass || lifetime.periodKind !== "lifetime")) usageInvalid();
  if (!Array.isArray(row.daily) || row.daily.length > 4096) usageInvalid();
  const daily = row.daily.map((item) => validateCloudUsageGlobal(item));
  if (daily.some((item) => item.model !== model || item.ownershipClass !== ownershipClass || item.periodKind !== "daily")) usageInvalid();
  if (new Set(daily.map((item) => item.periodKey)).size !== daily.length) usageInvalid();
  return { model, ownershipClass, lifetime, daily };
}

export function validateCloudUsageUnavailable(value: unknown): CloudUsageUnavailable {
  const row = usageExact(value, ["kind", "reason"]);
  if (row.kind !== "unavailable" || row.reason !== "missing" && row.reason !== "invalid" && row.reason !== "unavailable") usageInvalid();
  return { kind: "unavailable", reason: row.reason };
}

function checkUsageRelations(
  summaries: readonly CloudUsageSummary[],
  invocations: readonly CloudUsageInvocation[],
  generationId: string,
  publicationId: string,
  taskId: string,
): void {
  const summaryIds = new Set<string>();
  for (const summary of summaries) {
    if (summaryIds.has(summary.summaryId) || summary.usageGenerationId !== generationId || summary.publicationId !== publicationId || summary.taskId !== taskId) usageInvalid();
    summaryIds.add(summary.summaryId);
  }
  const invocationIds = new Set<string>();
  const retryGroups = new Map<string, number[]>();
  for (const invocation of invocations) {
    if (invocation.usageGenerationId !== generationId) usageInvalid();
    if (invocation.invocationId !== null) {
      if (invocationIds.has(invocation.invocationId)) usageInvalid();
      invocationIds.add(invocation.invocationId);
    }
    if (invocation.ownershipClass === "task-owned") {
      if (invocation.publicationId !== publicationId || invocation.taskId !== taskId || invocation.runId === null || invocation.pipelineId === null) usageInvalid();
      const group = `${invocation.runId}\u0000${invocation.ownershipClass}`;
      const values = retryGroups.get(group) ?? [];
      values.push(invocation.retryOrdinal);
      retryGroups.set(group, values);
    }
  }
  for (const values of retryGroups.values()) {
    values.sort((left, right) => left - right);
    if (values.some((value, index) => value !== index)) usageInvalid();
  }

  const sum = (rows: readonly CloudUsageInvocation[], field: keyof CloudUsageTokenTotals | keyof CloudUsageCostTotals): number | null => {
    let total = 0;
    let known = false;
    for (const row of rows) {
      const value = row[field];
      if (value === null) continue;
      known = true;
      total += value;
      if (!Number.isSafeInteger(total)) usageInvalid();
    }
    return known ? total : null;
  };
  const fields: readonly (keyof CloudUsageTokenTotals | keyof CloudUsageCostTotals)[] = [
    "promptTokens", "cachedTokens", "uncachedTokens", "completionTokens", "reasoningTokens", "totalTokens",
    "uncachedInputCostMicroUsd", "cachedInputCostMicroUsd", "outputCostMicroUsd", "totalCostMicroUsd",
  ];
  for (const summary of summaries) {
    const selected = invocations.filter((invocation) => invocation.ownershipClass === "task-owned"
      && (summary.scope === "task" || invocation.runId === summary.runId));
    if (summary.coveredInvocations !== selected.length || summary.expectedInvocations !== selected.length) usageInvalid();
    if (summary.coverage === "complete" || fields.some((field) => summary[field] !== null)) {
      for (const field of fields) {
        const value = summary[field];
        if (value !== null && value !== sum(selected, field)) usageInvalid();
      }
    }
  }
}

export function validateCloudUsageData(value: unknown): CloudUsage {
  const row = usageExact(value, ["schemaVersion", "usageGenerationId", "publicationId", "taskId", "summaries", "invocations", "globals"]);
  if (row.schemaVersion !== "1.0") usageInvalid();
  const generationId = usageId(row.usageGenerationId);
  const publicationId = usageId(row.publicationId);
  const taskId = usageId(row.taskId);
  if (!Array.isArray(row.summaries) || row.summaries.length < 1 || row.summaries.length > 4096) usageInvalid();
  if (!Array.isArray(row.invocations) || row.invocations.length > 128) usageInvalid();
  if (!Array.isArray(row.globals) || row.globals.length > 4096) usageInvalid();
  const summaries = row.summaries.map((item) => validateCloudUsageSummary(item));
  const invocations = row.invocations.map((item) => validateCloudUsageInvocation(item));
  const globals = row.globals.map((item) => validateCloudUsageGlobalGroup(item));
  checkUsageRelations(summaries, invocations, generationId, publicationId, taskId);
  return { schemaVersion: "1.0", usageGenerationId: generationId, publicationId, taskId, summaries, invocations, globals };
}

export function validateCloudUsageTurnPageData(value: unknown): CloudUsageTurnPage {
  const row = usageExact(value, ["turns", "nextCursor", "previousCursor", "total"]);
  if (!Array.isArray(row.turns) || row.turns.length > 200) usageInvalid();
  if (row.nextCursor !== null && typeof row.nextCursor !== "string") usageInvalid();
  if (row.previousCursor !== null && typeof row.previousCursor !== "string") usageInvalid();
  const turns = row.turns.map((item) => validateCloudUsageTurn(item));
  const total = usageInteger(row.total, 4096);
  if (total < turns.length) usageInvalid();
  for (let index = 1; index < turns.length; index += 1) {
    const left = turns[index - 1]!;
    const right = turns[index]!;
    if (left.invocationId > right.invocationId || left.invocationId === right.invocationId && (left.ordinal > right.ordinal || left.ordinal === right.ordinal && left.turnId >= right.turnId)) usageInvalid();
  }
  return { turns, nextCursor: row.nextCursor, previousCursor: row.previousCursor, total };
}

export const validateCloudUsageTokens = validateCloudUsageTokenTotals;
export const validateCloudUsageCosts = validateCloudUsageCostTotals;
export const validateCloudTokenTotals = validateCloudUsageTokenTotals;
export const validateCloudCostTotals = validateCloudUsageCostTotals;
export const validateCloudUsage = validateCloudUsageData;
export const validateCloudUsageGlobalGroups = (value: unknown): CloudUsageGlobalGroup[] => {
  if (!Array.isArray(value) || value.length > 4096) usageInvalid();
  return value.map((item) => validateCloudUsageGlobalGroup(item));
};
export const validateCloudUsageTurnPage = validateCloudUsageTurnPageData;
