import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseCloudResponse,
  serializeCloudResponse,
  validateCloudArtifact,
  validateCloudProblem,
  validateCloudStatus,
  validateCloudTaskDetail,
  validateCloudTaskPage,
  validateCloudTrajectoryDescriptor,
} from "@/lib/steward-archive/cloud-schema";

const taskId = "task-cloud";
const pipelineId = "pipeline-main";
const runId = "run-main";
const digest = "a".repeat(64);
const generatedAt = "2026-07-28T00:00:00Z";
const key = `v1/tasks/${taskId}/objects/sha256/aa/${digest}`;
const disclosure = { redactionApplied: false, originalRetained: true };

function artifact() {
  return { artifactId: "artifact-atif", taskId, runId, logicalPath: "runs/run-main/trajectory.json", publicKey: key, mediaType: "application/json", byteSize: 128, sha256: digest, availability: "available", disclosure };
}
function detail() {
  return {
    task: { taskId, title: "Cloud task", lifecycleState: "completed", createdAt: generatedAt, completedAt: generatedAt, completeness: "complete", pipelineId, completedRunId: runId, eventCount: 1, artifactCount: 1, disclosure },
    pipelines: [{ pipelineId, taskId, name: "Main pipeline", createdAt: generatedAt }],
    runs: [{ runId, taskId, pipelineId, role: "planning", runState: "completed", startedAt: generatedAt, completedAt: generatedAt, durationMs: 0, atifDigest: digest, atifArtifactId: "artifact-atif" }],
    events: [{ taskId, sequence: 1, eventType: "completed", occurredAt: generatedAt, summary: "Done" }],
    artifacts: [artifact()],
    trajectory: { taskId, pipelineId, runId, role: "planning", runState: "completed", startedAt: generatedAt, completedAt: generatedAt, durationMs: 0, artifactId: "artifact-atif", publicKey: key, mediaType: "application/json", byteSize: 128, sha256: digest, availability: "available", disclosure },
  };
}
function response(data: unknown) { return { schemaVersion: "3.0", generatedAt, data }; }
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

test("requires exact major and rejects private, legacy, and global-only fields", () => {
  const badVersion = response({ state: "available", taskCount: 1, latestPublicationAt: generatedAt });
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
  const partial = copy(graph); partial.task.completeness = "partial"; rejects(response(partial));
  const legacyFile = copy(graph) as Record<string, unknown>; legacyFile.filePath = "/private/archive"; rejects(response(legacyFile));
  const page = { items: [graph.task], pagination: { page: 1, pageSize: 101, total: 1, hasNextPage: false } };
  assert.throws(() => validateCloudTaskPage(response(page)), /invalid Steward cloud response/);
});

test("validation errors are stable and never contain rejected values", () => {
  const first = copy(detail()) as Record<string, unknown>;
  const second = copy(detail()) as Record<string, unknown>;
  (first.task as Record<string, unknown>).title = "super-secret-token-value";
  (second.task as Record<string, unknown>).title = "another-private-value";
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
