import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseCloudResponse,
  serializeCloudProblem,
  serializeCloudResponse,
  serializeCloudTrajectoryDescriptor,
  validateCloudArtifact,
  validateCloudProblem,
  validateCloudStatus,
  validateCloudTaskDetail,
  validateCloudTaskPage,
  validateCloudTrajectoryDescriptor,
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
function response<T>(data: T) { return { schemaVersion: "3.0" as const, generatedAt, data }; }
function copy<T>(value: T): T { return structuredClone(value); }
function rejects(value: unknown) { assert.throws(() => validateCloudTaskDetail(value), /invalid Steward cloud response/); }

test("accepts version-3 status, page, detail, descriptor, artifact, and problem envelopes", () => {
  const graph = detail();
  const task = graph.task;
  const page = { items: [task], pagination: { page: 1, pageSize: 25, total: 1, hasNextPage: false } };
  const descriptor = graph.trajectory;
  assert.equal(validateCloudStatus(response({ state: "available", taskCount: 1, latestPublicationAt: generatedAt })).schemaVersion, "3.0");
  assert.equal(validateCloudTaskPage(response(page)).data.items[0].taskId, taskId);
  assert.equal(validateCloudTaskDetail(response(graph)).data.runs[0].runId, runId);
  assert.equal(validateCloudTrajectoryDescriptor(response(descriptor)).data.sha256, digest);
  assert.equal(validateCloudArtifact(graph.artifacts[0]).artifactId, "artifact-atif");
  assert.equal(validateCloudProblem({ schemaVersion: "3.0", generatedAt, problem: { code: "UNAVAILABLE", message: "Cloud data is unavailable", retryable: true, status: 503, type: null } }).problem.retryable, true);
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

  const unavailable = copy(value) as { schemaVersion: "3.0"; generatedAt: string; data: Record<string, unknown> };
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
  const problem = { schemaVersion: "3.0" as const, generatedAt, problem: { code: "BAD", message: "file:///srv/private/credential.json", retryable: false, status: 500, type: null } };
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
