import assert from "node:assert/strict";
import { test } from "node:test";
import cleanPublication from "../../../contracts/steward-cloud/fixtures/clean-publication.json";
import cleanTrajectory from "../../examples/steward-cloud/complete-trajectory-clean.json";
import redactedTrajectory from "../../examples/steward-cloud/complete-trajectory-redacted-multimodal.json";
import { canonicalAtifBytes, validateAtifBytes, type AtifPublicationArtifactDescriptor } from "@/lib/steward-archive/atif";
import { buildAtifViewModel, type AtifViewArtifactDescriptor } from "@/lib/steward-archive/atif-view-model";
import {
  parseCloudResponse,
  STEWARD_CLOUD_SCHEMA_VERSION,
  serializeCloudProblem,
  serializeCloudResponse,
  serializeCloudCompleteTrajectory,
  serializeCloudTrajectoryDescriptor,
  validateCloudArtifact,
  validateCloudCompleteTrajectory,
  validateCloudProblem,
  validateCloudStatus,
  validateCloudTaskDetail,
  validateCloudTaskPage,
  validateCloudTrajectoryDescriptor,
  validateCloudUsage,
  validateCloudUsageCostTotals,
  validateCloudUsageData,
  validateCloudUsageGlobal,
  validateCloudUsageGlobalGroup,
  validateCloudUsageInvocation,
  validateCloudUsageInvocationPage,
  validateCloudUsagePrice,
  validateCloudUsageSummary,
  validateCloudUsageTokenTotals,
  validateCloudUsageTurn,
  validateCloudUsageTurnPage,
  validateCloudUsageUnavailable,
  type CloudArtifact,
  type CloudTaskDetail,
} from "@/lib/steward-archive/cloud-schema";

const taskId = "task-cloud";
const pipelineId = "pipeline-main";
const runId = "run-main";
const digest = "a".repeat(64);
const generatedAt = "2026-07-28T00:00:00Z";
const key = `v1/tasks/${taskId}/objects/sha256/aa/${digest}`;
const disclosure = { redactionApplied: false, originalRetained: true };

function artifact(): CloudArtifact {
  return { artifactId: "artifact-atif", taskId, runId, logicalPath: "runs/run-main/trajectory.json", publicKey: key, mediaType: "application/json", byteSize: 128, sha256: digest, availability: "available", disclosure };
}
function detail(): CloudTaskDetail {
  return {
    task: { taskId, title: "Cloud task", lifecycleState: "completed", createdAt: generatedAt, completedAt: generatedAt, completeness: "complete", pipelineId, completedRunId: runId, eventCount: 1, artifactCount: 1, disclosure },
    pipelines: [{ pipelineId, taskId, name: "Main pipeline", createdAt: generatedAt }],
    runs: [{ runId, taskId, pipelineId, role: "planning", runState: "completed", startedAt: generatedAt, completedAt: generatedAt, durationMs: 0, atifDigest: digest, atifArtifactId: "artifact-atif" }],
    events: [{ taskId, sequence: 1, eventType: "completed", occurredAt: generatedAt, summary: "Done" }],
    artifacts: [artifact()],
    trajectory: { taskId, pipelineId, runId, role: "planning", runState: "completed", startedAt: generatedAt, completedAt: generatedAt, durationMs: 0, artifactId: "artifact-atif", publicKey: key, mediaType: "application/json", byteSize: 128, sha256: digest, availability: "available", disclosure },
  };
}
function response<T>(data: T) { return { schemaVersion: STEWARD_CLOUD_SCHEMA_VERSION, generatedAt, data }; }
function copy<T>(value: T): T { return structuredClone(value); }
function rejects(value: unknown) { assert.throws(() => validateCloudTaskDetail(value), /invalid Steward cloud response/); }
function rejectsComplete(value: unknown) { assert.throws(() => validateCloudCompleteTrajectory(value), /invalid Steward cloud response/); }

const usageGenerationId = "usage-generation";
const usagePublicationId = "publication-usage";
const usageTaskId = "task-usage";
const usagePipelineId = "pipeline-usage";
const usageRunId = "run-usage";
const usageInvocationId = "invocation-usage";
const usageDigest = "c".repeat(64);
const usageTokens = { promptTokens: 11, cachedTokens: 2, uncachedTokens: 9, completionTokens: 7, reasoningTokens: 3, totalTokens: 18 };
const usageCosts = { uncachedInputCostMicroUsd: 10, cachedInputCostMicroUsd: 20, outputCostMicroUsd: 30, totalCostMicroUsd: 60 };

function usageSummary(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    summaryId: "summary-task", usageGenerationId, publicationId: usagePublicationId, taskId: usageTaskId, runId: null,
    scope: "task", coverage: "complete", coveredInvocations: 1, expectedInvocations: 1,
    knownTokenSubtotal: 18, knownCostSubtotalMicroUsd: 60, ...usageTokens, ...usageCosts, priceProvenanceDigest: usageDigest,
    ...overrides,
  };
}

function usageInvocation(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    invocationId: usageInvocationId, usageGenerationId, publicationId: usagePublicationId, taskId: usageTaskId,
    pipelineId: usagePipelineId, runId: usageRunId, ownershipClass: "task-owned", retryOrdinal: 0,
    startedAt: generatedAt, completedAt: "2026-07-28T00:00:01Z", model: "gpt-fixture", billingMode: "api",
    processOutcome: "success", coverage: "complete", issueCount: 0, coveredTurns: 1, expectedTurns: 1,
    ...usageTokens, ...usageCosts, priceEntryDigest: usageDigest,
    ...overrides,
  };
}

function usageTurn(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    turnId: "turn-usage", usageGenerationId, invocationId: usageInvocationId, publicationId: usagePublicationId,
    taskId: usageTaskId, runId: usageRunId, ordinal: 1, ...usageTokens, ...usageCosts, priceEntryDigest: usageDigest,
    ...overrides,
  };
}

function usageGlobal(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    globalId: "global-usage", usageGenerationId, periodKind: "lifetime", periodKey: "lifetime", model: "gpt-fixture",
    ownershipClass: "task-owned", coverage: "complete", coveredInvocations: 1, expectedInvocations: 1,
    knownTokenSubtotal: 18, knownCostSubtotalMicroUsd: 60, ...usageTokens, ...usageCosts, priceProvenanceDigest: usageDigest,
    aggregateOnly: true, ...overrides,
  };
}

function completeUsage() {
  return {
    schemaVersion: "1.0",
    usageGenerationId,
    publicationId: usagePublicationId,
    taskId: usageTaskId,
    summaries: [usageSummary()],
    invocations: [usageInvocation()],
    globals: [{ model: "gpt-fixture", ownershipClass: "task-owned", lifetime: usageGlobal(), daily: [] }],
  };
}

test("accepts version-4 status, page, detail, descriptor, artifact, and problem envelopes", () => {
  const graph = detail();
  const task = graph.task;
  const page = { items: [task], pagination: { page: 1, pageSize: 25, total: 1, hasNextPage: false } };
  const descriptor = graph.trajectory;
  assert.equal(validateCloudStatus(response({ state: "available", taskCount: 1, latestPublicationAt: generatedAt })).schemaVersion, STEWARD_CLOUD_SCHEMA_VERSION);
  assert.equal(validateCloudTaskPage(response(page)).data.items[0].taskId, taskId);
  assert.equal(validateCloudTaskDetail(response(graph)).data.runs[0].runId, runId);
  assert.equal(validateCloudTrajectoryDescriptor(response(descriptor)).data.sha256, digest);
  assert.equal(validateCloudArtifact(graph.artifacts[0]).artifactId, "artifact-atif");
  assert.equal(validateCloudProblem({ schemaVersion: STEWARD_CLOUD_SCHEMA_VERSION, generatedAt, problem: { code: "UNAVAILABLE", message: "Cloud data is unavailable", retryable: true, status: 503, type: null } }).problem.retryable, true);
});

test("accepts only the version-4 envelope across every response family", () => {
  const graph = detail();
  const page = { items: [graph.task], pagination: { page: 1, pageSize: 25, total: 1, hasNextPage: false } };
  const problem = { schemaVersion: STEWARD_CLOUD_SCHEMA_VERSION, generatedAt, problem: { code: "UNAVAILABLE", message: "Cloud data is unavailable", retryable: true, status: 503, type: null } };
  const envelopes: unknown[] = [
    response({ state: "available", taskCount: 1, latestPublicationAt: generatedAt }),
    response(page),
    response(graph),
    response(graph.trajectory),
    problem,
    cleanTrajectory,
  ];
  for (const envelope of envelopes) {
    assert.doesNotThrow(() => parseCloudResponse(JSON.stringify(envelope)));
    const legacy = copy(envelope) as Record<string, unknown>;
    legacy.schemaVersion = "3.0";
    assert.throws(() => parseCloudResponse(JSON.stringify(legacy)), /invalid Steward cloud response/);
  }
});

test("validates complete, partial, unavailable, and zero-token usage rows", () => {
  assert.deepEqual(validateCloudUsageTokenTotals(usageTokens), usageTokens);
  assert.deepEqual(validateCloudUsageCostTotals(usageCosts), usageCosts);
  assert.equal(validateCloudUsageSummary(usageSummary()).totalTokens, 18);
  assert.equal(validateCloudUsageInvocation(usageInvocation()).totalCostMicroUsd, 60);
  assert.equal(validateCloudUsageTurn(usageTurn()).ordinal, 1);

  const partialSummary = usageSummary({
    summaryId: "summary-partial", coverage: "partial", coveredInvocations: 0, expectedInvocations: 1,
    knownTokenSubtotal: null, knownCostSubtotalMicroUsd: null,
    promptTokens: 11, cachedTokens: null, uncachedTokens: null, completionTokens: null, reasoningTokens: null, totalTokens: null,
    uncachedInputCostMicroUsd: null, cachedInputCostMicroUsd: null, outputCostMicroUsd: null, totalCostMicroUsd: null,
    priceProvenanceDigest: null,
  });
  assert.equal(validateCloudUsageSummary(partialSummary).coverage, "partial");

  const unavailableSummary = usageSummary({
    summaryId: "summary-unavailable", coverage: "unavailable", coveredInvocations: 0, expectedInvocations: 1,
    knownTokenSubtotal: null, knownCostSubtotalMicroUsd: null,
    promptTokens: null, cachedTokens: null, uncachedTokens: null, completionTokens: null, reasoningTokens: null, totalTokens: null,
    uncachedInputCostMicroUsd: null, cachedInputCostMicroUsd: null, outputCostMicroUsd: null, totalCostMicroUsd: null,
    priceProvenanceDigest: null,
  });
  assert.equal(validateCloudUsageSummary(unavailableSummary).totalTokens, null);

  const unavailableInvocation = usageInvocation({
    invocationId: null, coverage: "unavailable", coveredTurns: 0, expectedTurns: 0, startedAt: null, completedAt: null,
    model: null, billingMode: null, processOutcome: "missing", issueCount: 1,
    promptTokens: null, cachedTokens: null, uncachedTokens: null, completionTokens: null, reasoningTokens: null, totalTokens: null,
    uncachedInputCostMicroUsd: null, cachedInputCostMicroUsd: null, outputCostMicroUsd: null, totalCostMicroUsd: null,
    priceEntryDigest: null,
  });
  assert.equal(validateCloudUsageInvocation(unavailableInvocation).invocationId, null);

  const zero = usageTurn({
    turnId: "turn-zero", promptTokens: 0, cachedTokens: 0, uncachedTokens: 0, completionTokens: 0, reasoningTokens: 0,
    totalTokens: 0, uncachedInputCostMicroUsd: 0, cachedInputCostMicroUsd: 0, outputCostMicroUsd: 0, totalCostMicroUsd: 0,
  });
  assert.equal(validateCloudUsageTurn(zero).totalTokens, 0);
});

test("validates global groups, prices, complete usage, and bounded turn pages", () => {
  const daily = usageGlobal({ globalId: "global-daily", periodKind: "daily", periodKey: "2026-07-28" });
  const group = validateCloudUsageGlobalGroup({ model: "gpt-fixture", ownershipClass: "task-owned", lifetime: usageGlobal(), daily: [daily] });
  assert.equal(group.daily[0]!.periodKey, "2026-07-28");
  assert.equal(validateCloudUsageGlobal(usageGlobal()).aggregateOnly, true);
  assert.equal(validateCloudUsagePrice({
    priceEntryDigest: usageDigest, usageGenerationId, catalogDigest: "d".repeat(64), model: "gpt-fixture",
    effectiveAt: "2026-01-01T00:00:00Z", effectiveUntil: null,
  }).model, "gpt-fixture");
  assert.equal(validateCloudUsageData(completeUsage()).invocations[0]!.invocationId, usageInvocationId);
  const page = validateCloudUsageTurnPage({ turns: [usageTurn()], nextCursor: "opaque-next", previousCursor: null, total: 1 });
  assert.equal(page.total, 1);
  assert.deepEqual(validateCloudUsageUnavailable({ kind: "unavailable", reason: "missing" }), { kind: "unavailable", reason: "missing" });
});

test("preserves partial counters and cached parent totals without child arithmetic", () => {
  const partial = usageSummary({
    summaryId: "summary-partial", coverage: "partial", coveredInvocations: 0, expectedInvocations: 1,
    knownTokenSubtotal: null, knownCostSubtotalMicroUsd: null,
    promptTokens: null, cachedTokens: null, uncachedTokens: null, completionTokens: null, reasoningTokens: null, totalTokens: null,
    uncachedInputCostMicroUsd: null, cachedInputCostMicroUsd: null, outputCostMicroUsd: null, totalCostMicroUsd: null,
    priceProvenanceDigest: null,
  });
  const partialUsage = validateCloudUsageData({ ...completeUsage(), summaries: [partial], invocations: [] });
  assert.equal(partialUsage.summaries[0]!.coveredInvocations, 0);
  assert.equal(partialUsage.summaries[0]!.expectedInvocations, 1);

  const cachedParent = usageSummary({
    summaryId: "summary-cached-parent", promptTokens: 13, cachedTokens: 3, uncachedTokens: 10, completionTokens: 7,
    reasoningTokens: 3, totalTokens: 20, knownTokenSubtotal: 20, uncachedInputCostMicroUsd: 17,
    cachedInputCostMicroUsd: 23, outputCostMicroUsd: 59, totalCostMicroUsd: 99, knownCostSubtotalMicroUsd: 99,
  });
  const cachedUsage = validateCloudUsageData({ ...completeUsage(), summaries: [cachedParent] });
  assert.equal(cachedUsage.summaries[0]!.totalTokens, 20);
  assert.equal(cachedUsage.summaries[0]!.totalCostMicroUsd, 99);
});

test("validates bounded invocation pages and rejects unavailable rows", () => {
  const page = validateCloudUsageInvocationPage({ invocations: [usageInvocation()], nextCursor: "next", previousCursor: null, total: 129 });
  assert.equal(page.total, 129);
  assert.throws(() => validateCloudUsageInvocationPage({ invocations: [usageInvocation({ coverage: "unavailable", invocationId: null, publicationId: null, taskId: null, pipelineId: null, runId: null, coveredTurns: 0, expectedTurns: 0, startedAt: null, completedAt: null, model: null, billingMode: null, processOutcome: null, promptTokens: null, cachedTokens: null, uncachedTokens: null, completionTokens: null, reasoningTokens: null, totalTokens: null, uncachedInputCostMicroUsd: null, cachedInputCostMicroUsd: null, outputCostMicroUsd: null, totalCostMicroUsd: null, priceEntryDigest: null })], nextCursor: null, previousCursor: null, total: 1 }), /invalid Steward cloud response/);
});

test("rejects private keys, unsafe integers, malformed coverage, ownership, and cursor rows", () => {
  assert.throws(() => validateCloudUsageSummary({ ...usageSummary(), extra: true }), /invalid Steward cloud response/);
  assert.throws(() => validateCloudUsageSummary({ ...usageSummary(), credentialPath: "hidden" }), /invalid Steward cloud response/);
  assert.throws(() => validateCloudUsageInvocation({ ...usageInvocation(), totalTokens: Number.MAX_SAFE_INTEGER + 1 }), /invalid Steward cloud response/);
  assert.throws(() => validateCloudUsageSummary({ ...usageSummary(), coverage: "unknown" }), /invalid Steward cloud response/);
  assert.throws(() => validateCloudUsageGlobal({ ...usageGlobal(), aggregateOnly: false }), /invalid Steward cloud response/);
  assert.throws(() => validateCloudUsageGlobalGroup({ model: "gpt-fixture", ownershipClass: "task-owned", lifetime: usageGlobal(), daily: [usageGlobal({ globalId: "global-daily", periodKind: "daily", periodKey: "2026-07-28" }), usageGlobal({ globalId: "global-daily-2", periodKind: "daily", periodKey: "2026-07-28" })] }), /invalid Steward cloud response/);
  assert.throws(() => validateCloudUsagePrice({
    priceEntryDigest: usageDigest, usageGenerationId, catalogDigest: "d".repeat(64), model: null,
    effectiveAt: generatedAt, effectiveUntil: null,
  }), /invalid Steward cloud response/);
  assert.throws(() => validateCloudUsageTurnPage({ turns: [usageTurn({ ordinal: 0 })], nextCursor: null, previousCursor: null, total: 1 }), /invalid Steward cloud response/);
  assert.throws(() => validateCloudUsageData({ ...completeUsage(), summaries: [usageSummary(), usageSummary({ summaryId: "summary-task" })] }), /invalid Steward cloud response/);
  assert.throws(() => validateCloudUsageData({
    ...completeUsage(), summaries: [usageSummary({ totalTokens: 19, knownTokenSubtotal: 19 })],
  }), /invalid Steward cloud response/);
});

test("serializes only validated closed envelopes and parses them back", () => {
  const value = response({ state: "empty", taskCount: 0, latestPublicationAt: null });
  const encoded = serializeCloudResponse(value);
  assert.deepEqual(parseCloudResponse(encoded), value);
  assert.throws(() => serializeCloudResponse({ ...value, data: { state: "empty", taskCount: 0, latestPublicationAt: null, credential: "do-not-echo" } }), /invalid Steward cloud response/);
  assert(!encoded.includes("credential"));
});

test("accepts only available standalone trajectory descriptors on every path", () => {
  const value = response(detail().trajectory!);
  assert.equal(validateCloudTrajectoryDescriptor(value).data.availability, "available");
  assert.deepEqual(JSON.parse(serializeCloudTrajectoryDescriptor(value)), value);
  assert.deepEqual(parseCloudResponse(JSON.stringify(value)), value);

  const unavailable = copy(value) as { schemaVersion: typeof STEWARD_CLOUD_SCHEMA_VERSION; generatedAt: string; data: Record<string, unknown> };
  unavailable.data.availability = "unavailable";
  const attempts = [
    () => validateCloudTrajectoryDescriptor(unavailable),
    () => serializeCloudTrajectoryDescriptor(unavailable),
    () => parseCloudResponse(JSON.stringify(unavailable)),
  ];
  for (const attempt of attempts) assert.throws(attempt, (error) => error instanceof Error && error.message === "invalid Steward cloud response");
});

test("requires exact major and rejects private, legacy, and global-only fields", () => {
  const badVersion = response({ state: "available", taskCount: 1, latestPublicationAt: generatedAt }) as { schemaVersion: string; generatedAt: string; data: unknown };
  badVersion.schemaVersion = "2.0";
  assert.throws(() => validateCloudStatus(badVersion), /invalid Steward cloud response/);
  const legacyVersion = response({ state: "available", taskCount: 1, latestPublicationAt: generatedAt }) as { schemaVersion: string; generatedAt: string; data: unknown };
  legacyVersion.schemaVersion = "3.0";
  assert.throws(() => validateCloudStatus(legacyVersion), /invalid Steward cloud response/);
  for (const field of ["privateBucket", "objectKey", "url", "credentialPath", "cursor", "filePath", "revision", "signals", "plannerRuns"]) {
    const value = response({ state: "available", taskCount: 1, latestPublicationAt: generatedAt }) as Record<string, unknown>;
    (value.data as Record<string, unknown>)[field] = "private-value";
    assert.throws(() => validateCloudStatus(value), /invalid Steward cloud response/);
  }
});

test("rejects relationship, time, key, count, and partial-record mutations", () => {
  const graph = detail();
  const mismatchedPipeline = copy(graph); mismatchedPipeline.runs[0].pipelineId = "other-pipeline"; rejects(response(mismatchedPipeline));
  const mismatchedArtifact = copy(graph); mismatchedArtifact.artifacts[0].publicKey = `v1/tasks/${taskId}/objects/sha256/bb/${digest}`; rejects(response(mismatchedArtifact));
  const backwards = copy(graph); backwards.runs[0].startedAt = "2026-07-29T00:00:00Z"; rejects(response(backwards));
  const partial = copy(graph); (partial.task as unknown as { completeness: string }).completeness = "partial"; rejects(response(partial));
  const legacyFile = copy(graph) as Record<string, unknown>; legacyFile.filePath = "/private/archive"; rejects(response(legacyFile));
  const page = { items: [graph.task], pagination: { page: 1, pageSize: 101, total: 1, hasNextPage: false } };
  assert.throws(() => validateCloudTaskPage(response(page)), /invalid Steward cloud response/);
});

test("uses run and content identity when ATIF artifact aliases are ambiguous", () => {
  const graph = detail();
  graph.artifacts.push({ ...artifact(), artifactId: "artifact-alias", logicalPath: "runs/run-main/trajectory-copy.json" });
  graph.task.artifactCount = 2; graph.runs[0].atifArtifactId = null; graph.trajectory!.artifactId = null;
  assert.equal(validateCloudTaskDetail(response(graph)).data.trajectory!.artifactId, null);
  const arbitrary = detail(); arbitrary.artifacts.push({ ...artifact(), artifactId: "artifact-alias", logicalPath: "runs/run-main/trajectory-copy.json" });
  arbitrary.task.artifactCount = 2; arbitrary.runs[0].atifArtifactId = null; assert.throws(() => validateCloudTaskDetail(response(arbitrary)), /invalid Steward cloud response/);
});

test("rejects lifecycle, duration, availability, identity, size, and sub-millisecond mutations", () => {
  const lifecycle = copy(detail()); lifecycle.task.completedAt = null; rejects(response(lifecycle));
  const duration = copy(detail()); duration.runs[0].durationMs = 1; rejects(response(duration));
  const unavailable = copy(detail()); unavailable.artifacts[0].availability = "unavailable"; rejects(response(unavailable));
  const path = copy(detail()); path.artifacts.push({ ...artifact(), artifactId: "artifact-alias", logicalPath: artifact().logicalPath }); path.task.artifactCount = 2; path.runs[0].atifArtifactId = null; path.trajectory!.artifactId = null; rejects(response(path));
  const size = copy(detail()); size.artifacts.push({ ...artifact(), artifactId: "artifact-alias", logicalPath: "runs/run-main/trajectory-copy.json", byteSize: 129 }); size.task.artifactCount = 2; size.runs[0].atifArtifactId = null; size.trajectory!.artifactId = null; rejects(response(size));
  const descriptor = copy(detail()); descriptor.trajectory!.role = "execution"; rejects(response(descriptor));
  const reversed = copy(detail()); reversed.runs[0].startedAt = "2026-07-28T00:00:00.000000002Z"; reversed.runs[0].completedAt = "2026-07-28T00:00:00.000000001Z"; rejects(response(reversed));
});

test("bounds UTC fractional precision and rejects private problem locators", () => {
  const precise = response({ state: "empty", taskCount: 0, latestPublicationAt: "2026-07-28T00:00:00.123456789Z" });
  assert.equal(validateCloudStatus(precise).data.latestPublicationAt, precise.data.latestPublicationAt);
  const tooPrecise = copy(precise); tooPrecise.generatedAt = "2026-07-28T00:00:00.1234567890Z"; assert.throws(() => validateCloudStatus(tooPrecise), /invalid Steward cloud response/);
  const problem = { schemaVersion: STEWARD_CLOUD_SCHEMA_VERSION, generatedAt, problem: { code: "BAD", message: "file:///srv/private/credential.json", retryable: false, status: 500, type: null } };
  assert.throws(() => serializeCloudProblem(problem), /invalid Steward cloud response/);
});

test("validation errors are stable and never contain rejected values", () => {
  const first = copy(detail()) as Record<string, unknown>;
  const second = copy(detail()) as Record<string, unknown>;
  (first.task as Record<string, unknown>).title = "first title";
  (second.task as Record<string, unknown>).title = "second title";
  let firstMessage = ""; let secondMessage = "";
  try { validateCloudTaskDetail(response(first)); } catch (error) { firstMessage = (error as Error).message; }
  try { validateCloudTaskDetail(response(second)); } catch (error) { secondMessage = (error as Error).message; }
  assert.equal(firstMessage, ""); assert.equal(secondMessage, "");
  const invalidFirst = copy(detail()); const invalidSecond = copy(detail());
  invalidFirst.artifacts[0].publicKey = "private://first-secret";
  invalidSecond.artifacts[0].publicKey = "private://second-secret";
  try { validateCloudTaskDetail(response(invalidFirst)); } catch (error) { firstMessage = (error as Error).message; }
  try { validateCloudTaskDetail(response(invalidSecond)); } catch (error) { secondMessage = (error as Error).message; }
  assert.equal(firstMessage, secondMessage); assert.equal(firstMessage, "invalid Steward cloud response");
  assert(!firstMessage.includes("secret"));
});

test("accepts complete normalized trajectories and preserves their public display model", () => {
  const clean = validateCloudCompleteTrajectory(cleanTrajectory);
  const redacted = validateCloudCompleteTrajectory(redactedTrajectory);
  assert.equal(clean.schemaVersion, STEWARD_CLOUD_SCHEMA_VERSION);
  assert.equal(redacted.data.disclosure.redactionApplied, true);
  assert.equal(redacted.data.steps[1]!.content[2]!.kind, "image");
  assert.equal((redacted.data.steps[1]!.content[2] as { action: { kind: string } }).action.kind, "unavailable");
  assert.deepEqual(parseCloudResponse(serializeCloudCompleteTrajectory(cleanTrajectory)), cleanTrajectory);
  assert(!serializeCloudCompleteTrajectory(cleanTrajectory).includes("publicKey"));
  assert(!serializeCloudCompleteTrajectory(cleanTrajectory).includes("://"));
});

test("requires every call alias to mirror matched step observations in source order", () => {
  const missing = structuredClone(cleanTrajectory) as Record<string, any>;
  for (const alias of ["toolCalls", "calls", "tools"]) missing.data.steps[1][alias][0].observations = [];
  rejectsComplete(missing);

  const delayed = structuredClone(cleanTrajectory) as Record<string, any>;
  const steps = delayed.data.steps as Record<string, any>[];
  const matched = steps[1].observations[0];
  const later = structuredClone(matched);
  const unmatched = structuredClone(matched);
  unmatched.sourceCallId = null;
  unmatched.matchedCallId = null;
  const followUp = structuredClone(steps[0]);
  followUp.id = "step-3";
  followUp.anchor = "step-3";
  followUp.stepId = 3;
  followUp.observation = { results: [later, unmatched] };
  followUp.observations = followUp.observation.results;
  steps.push(followUp);
  delayed.data.finalMetrics.totalSteps = 3;
  for (const alias of ["toolCalls", "calls", "tools"]) delayed.data.steps[1][alias][0].observations = [matched, later];
  assert.equal(validateCloudCompleteTrajectory(delayed).data.steps[2]!.observations[1]!.matchedCallId, null);
});

test("rejects complete trajectory order, private shape, direct locator, and partial mutations", () => {
  const clean = structuredClone(cleanTrajectory) as Record<string, any>;
  const data = clean.data as Record<string, any>;
  const duplicateAnchor = structuredClone(clean);
  (duplicateAnchor.data.steps as Record<string, any>[])[1].anchor = "step-1";
  rejectsComplete(duplicateAnchor);
  const reordered = structuredClone(clean);
  (reordered.data.steps as Record<string, any>[])[0].stepId = 2;
  rejectsComplete(reordered);
  const directUrl = structuredClone(clean);
  (directUrl.data.steps as Record<string, any>[])[1].content[1].action.href = "https://r2.example/object";
  rejectsComplete(directUrl);
  const objectKey = structuredClone(clean);
  (objectKey.data.steps as Record<string, any>[])[1].content[0].text = "v1/tasks/task-clean/objects/sha256/aa/" + "a".repeat(64);
  rejectsComplete(objectKey);
  const privateField = structuredClone(clean);
  (privateField.data as Record<string, any>).privateBucket = "hidden";
  rejectsComplete(privateField);
  const rawAtif = structuredClone(clean);
  (rawAtif.data as Record<string, any>).raw = { steps: [] };
  rejectsComplete(rawAtif);
  const unknownRecord = structuredClone(clean);
  (unknownRecord.data.steps as Record<string, any>[])[1].content[1].record = {};
  rejectsComplete(unknownRecord);
  const unknownAction = structuredClone(clean);
  (unknownAction.data.steps as Record<string, any>[])[1].content[1].action.extra = "unexpected";
  rejectsComplete(unknownAction);
  const partial = structuredClone(clean);
  delete (partial.data as Record<string, any>).steps;
  rejectsComplete(partial);
  assert.equal(data.schemaVersion, "ATIF-v1.7");
});

test("accepts bounded mapper-preserved strings without truncation", () => {
  const source = structuredClone(cleanPublication.atif) as Record<string, any>;
  const message = "x".repeat(4097);
  source.steps[0].message = message;
  const provenance = source.extra.coquic as Record<string, any>;
  const publicationArtifacts = cleanPublication.publication.artifacts as unknown as readonly AtifPublicationArtifactDescriptor[];
  const viewArtifacts = publicationArtifacts as unknown as readonly AtifViewArtifactDescriptor[];
  const document = validateAtifBytes(canonicalAtifBytes(source), {
    taskId: provenance.taskId,
    pipelineId: provenance.pipelineId,
    runId: provenance.runId,
    role: provenance.role,
    startedAt: provenance.startedAt,
    completedAt: provenance.completedAt,
    durationMs: provenance.durationMs,
    disclosure: provenance.disclosure,
    artifacts: publicationArtifacts,
  });
  const model = buildAtifViewModel(document, { artifacts: viewArtifacts });
  assert.equal(model.steps[0]!.message, message);
  const response = { schemaVersion: STEWARD_CLOUD_SCHEMA_VERSION, generatedAt, data: model };
  assert.equal(validateCloudCompleteTrajectory(response).data.steps[0]!.message, message);
});

test("rejects mapper-impossible duplicate identities, media, ownership, timing, lineage, disclosure, and actions", () => {
  const imageIdentity = structuredClone(cleanTrajectory) as Record<string, any>;
  for (const field of ["message", "content", "parts"]) imageIdentity.data.steps[1][field][1].action.artifactId = "artifact-log";
  rejectsComplete(imageIdentity);

  const mutations: Array<(candidate: Record<string, any>) => void> = [
    (candidate) => {
      candidate.data.artifacts[0].mediaType = "image/png";
      candidate.data.metadata.artifacts[0].mediaType = "image/png";
    },
    (candidate) => { candidate.data.metadata.durationMs = 999; },
    (candidate) => { candidate.data.lineage.trajectoryId = "trajectory-other"; },
    (candidate) => {
      candidate.data.artifacts[0].disclosure.redactionApplied = true;
      candidate.data.metadata.artifacts[0].disclosure.redactionApplied = true;
    },
    (candidate) => { candidate.data.steps[1].content[1].action.taskId = "task-other"; },
    (candidate) => { candidate.data.artifacts[1].action.logicalPath = "steps/2/other.log"; },
  ];
  for (const [index, mutate] of mutations.entries()) {
    const candidate = structuredClone(cleanTrajectory) as Record<string, any>;
    mutate(candidate);
    assert.throws(() => validateCloudCompleteTrajectory(candidate), /invalid Steward cloud response/, `mutation ${index} must be rejected`);
  }
});

test("keeps public object-key text accepted in task detail while complete trajectories deny it", () => {
  const graph = detail();
  const summary = `Published ${graph.artifacts[0].publicKey}`;
  graph.events[0]!.summary = summary;
  assert.equal(validateCloudTaskDetail(response(graph)).data.events[0]!.summary, summary);

  const v4 = structuredClone(cleanTrajectory) as Record<string, any>;
  const objectKey = `v1/tasks/${v4.data.taskId}/objects/sha256/aa/${"a".repeat(64)}`;
  v4.data.steps[0].message = objectKey;
  v4.data.steps[0].content = [{ kind: "text", type: "text", text: objectKey }];
  v4.data.steps[0].parts = [{ kind: "text", type: "text", text: objectKey }];
  rejectsComplete(v4);
});
