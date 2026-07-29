import assert from "node:assert/strict";
import { test } from "node:test";
import type { CloudTaskDetail } from "../../lib/steward-archive/cloud-schema";
import { buildCloudTaskViewModel, type CloudTaskViewModel } from "../../lib/steward-archive/cloud-view-model";

const taskId = "task-cloud-view";
const pipelineId = "pipeline-main";
const secondPipelineId = "pipeline-retry";
const planningRunId = "run-planning";
const workerRunId = "run-worker";
const retryRunId = "run-retry";
const planningDigest = "a".repeat(64);
const workerDigest = "b".repeat(64);
const retryDigest = "c".repeat(64);

function publicKey(digest: string) {
  return `v1/tasks/${taskId}/objects/sha256/${digest.slice(0, 2)}/${digest}`;
}

function artifact(runId: string, digest: string, artifactId: string, availability: "available" | "unavailable" = "available") {
  return {
    artifactId,
    taskId,
    runId,
    logicalPath: `runs/${runId}/trajectory.json`,
    publicKey: publicKey(digest),
    mediaType: "application/json",
    byteSize: 128,
    sha256: digest,
    availability,
    disclosure: { redactionApplied: false, originalRetained: true },
  };
}

function detail(options: { active?: boolean; trajectory?: boolean; unavailableWorker?: boolean } = {}): CloudTaskDetail {
  const active = options.active ?? false;
  const workerAvailable = !(options.unavailableWorker ?? false);
  const planningArtifact = artifact(planningRunId, planningDigest, "artifact-planning");
  const workerArtifact = artifact(workerRunId, workerDigest, "artifact-worker", workerAvailable ? "available" : "unavailable");
  const retryArtifact = artifact(retryRunId, retryDigest, "artifact-retry");
  return {
    task: {
      taskId,
      title: "Cloud task",
      lifecycleState: active ? "active" : "completed",
      createdAt: "2026-07-28T00:00:00Z",
      completedAt: active ? null : "2026-07-28T00:00:05Z",
      completeness: "complete",
      pipelineId,
      completedRunId: options.trajectory === false ? null : workerRunId,
      eventCount: 2,
      artifactCount: 3,
      disclosure: { redactionApplied: false, originalRetained: true },
    },
    pipelines: [
      { pipelineId, taskId, name: "Main pipeline", createdAt: "2026-07-28T00:00:00Z" },
      { pipelineId: secondPipelineId, taskId, name: "Retry pipeline", createdAt: "2026-07-28T00:00:04Z" },
    ],
    runs: [
      { runId: planningRunId, taskId, pipelineId, role: "planning", runState: "completed", startedAt: "2026-07-28T00:00:00Z", completedAt: "2026-07-28T00:00:01.500Z", durationMs: 1_500, atifDigest: planningDigest, atifArtifactId: "artifact-planning" },
      { runId: workerRunId, taskId, pipelineId, role: "execution", runState: "completed", startedAt: "2026-07-28T00:00:01Z", completedAt: "2026-07-28T00:00:04Z", durationMs: 3_000, atifDigest: workerDigest, atifArtifactId: workerAvailable ? "artifact-worker" : null },
      { runId: retryRunId, taskId, pipelineId: secondPipelineId, role: "execution", runState: "failed", startedAt: "2026-07-28T00:00:04Z", completedAt: "2026-07-28T00:00:05Z", durationMs: 1_000, atifDigest: retryDigest, atifArtifactId: "artifact-retry" },
    ],
    events: [
      { taskId, sequence: 1, eventType: "started", occurredAt: "2026-07-28T00:00:00Z", summary: "Started" },
      { taskId, sequence: 2, eventType: "completed", occurredAt: "2026-07-28T00:00:05Z", summary: "Completed" },
    ],
    artifacts: [planningArtifact, workerArtifact, retryArtifact],
    trajectory: options.trajectory === false || !workerAvailable ? null : {
      taskId,
      pipelineId,
      runId: workerRunId,
      role: "execution",
      runState: "completed",
      startedAt: "2026-07-28T00:00:01Z",
      completedAt: "2026-07-28T00:00:04Z",
      durationMs: 3_000,
      artifactId: "artifact-worker",
      publicKey: publicKey(workerDigest),
      mediaType: "application/json",
      byteSize: 128,
      sha256: workerDigest,
      availability: "available",
      disclosure: { redactionApplied: false, originalRetained: true },
    },
  };
}

function redact(value: CloudTaskDetail): CloudTaskDetail {
  return {
    ...value,
    task: { ...value.task, disclosure: { redactionApplied: true, originalRetained: false } },
    artifacts: value.artifacts.map((item) => ({ ...item, disclosure: { redactionApplied: true, originalRetained: false } })),
    trajectory: value.trajectory ? { ...value.trajectory, disclosure: { redactionApplied: true, originalRetained: false } } : null,
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

test("projects clean cloud evidence with stable source ordering and descriptor actions", () => {
  const model = buildCloudTaskViewModel(detail());
  assert.equal(model.task.id, taskId);
  assert.equal(model.task.status, "completed");
  assert.deepEqual(model.pipelines.map((item) => item.pipelineId), [pipelineId, secondPipelineId]);
  assert.deepEqual(model.pipelines.map((item) => item.runIds), [[planningRunId, workerRunId], [retryRunId]]);
  assert.deepEqual(model.runs.map((item) => item.runId), [planningRunId, workerRunId, retryRunId]);
  assert.deepEqual(model.attempts.map((item) => item.number), [0, 1]);
  assert.deepEqual(model.events.map((item) => item.id), [`${taskId}:event-1`, `${taskId}:event-2`]);
  assert.equal(model.runs[1]!.timing?.durationMs, 3_000);
  assert.equal(model.attempts[0]!.durationMs, 4_000);
  assert.equal(model.artifacts[0]!.action?.kind, "download");
  assert.equal(model.trajectory.state, "available");
  assert.equal(model.trajectory.action.kind, "trajectory");
  assert.equal(model.trajectory.action.artifactId, "artifact-worker");
  assert.equal(model.trajectory.action.logicalPath, "runs/run-worker/trajectory.json");
  assert.deepEqual(model.completeness, { state: "complete", trajectory: "available", warnings: [] });
});

test("does not synthesize attempt lifecycle status from mixed run states", () => {
  const mixed = clone(detail());
  mixed.runs[2] = { ...mixed.runs[2]!, pipelineId };
  const model = buildCloudTaskViewModel(mixed);
  assert.deepEqual(model.attempts.map((attempt) => attempt.status), ["unavailable", "unavailable"]);
});

test("preserves redaction disclosure and keeps unavailable usage explicit", () => {
  const model = buildCloudTaskViewModel(redact(detail()));
  assert.deepEqual(model.task.disclosure, { redactionApplied: true, originalRetained: false });
  assert.deepEqual(model.artifacts[0]!.disclosure, { redactionApplied: true, originalRetained: false });
  assert.equal(model.runs[0]!.usage, null);
  assert.equal(model.runs[0]!.timing?.durationSeconds, 1);
});

test("keeps an active task distinct while exposing its completed trajectory", () => {
  const model = buildCloudTaskViewModel(detail({ active: true }));
  assert.equal(model.task.status, "active");
  assert.equal(model.task.completedAt, null);
  assert.equal(model.task.completedRunId, workerRunId);
  assert.equal(model.trajectory.state, "available");
  assert.equal(model.completeness.state, "complete");
});

test("uses a bounded placeholder when the completed trajectory is absent", () => {
  const noCompletedRun = buildCloudTaskViewModel(detail({ trajectory: false }));
  assert.deepEqual(noCompletedRun.trajectory, { state: "placeholder", descriptor: null, action: null, reason: "no-completed-run" });
  assert.deepEqual(noCompletedRun.completeness.warnings, ["No completed run has a public trajectory descriptor."]);

  const unavailable = buildCloudTaskViewModel(detail({ active: true, unavailableWorker: true }));
  assert.equal(unavailable.trajectory.state, "placeholder");
  assert.equal(unavailable.trajectory.reason, "artifact-unavailable");
  assert.equal(unavailable.artifacts.find((item) => item.artifactId === "artifact-worker")!.action, null);
});

test("derives run duration only from valid timestamps and leaves invalid timing unavailable", () => {
  const missingDuration = clone(detail());
  (missingDuration.runs[0] as { durationMs?: number }).durationMs = undefined;
  const derived = buildCloudTaskViewModel(missingDuration);
  assert.equal(derived.runs[0]!.timing?.durationMs, 1_500);

  const invalidTiming = clone(detail());
  (invalidTiming.runs[0] as unknown as { startedAt: string; completedAt: string; durationMs?: number }).startedAt = "not-a-timestamp";
  (invalidTiming.runs[0] as unknown as { startedAt: string; completedAt: string; durationMs?: number }).completedAt = "also-not-a-timestamp";
  (invalidTiming.runs[0] as unknown as { startedAt: string; completedAt: string; durationMs?: number }).durationMs = undefined;
  assert.equal(buildCloudTaskViewModel(invalidTiming).runs[0]!.timing, null);
});

test("uses chronological extrema for fractional RFC3339 timestamps", () => {
  const fractional = clone(detail());
  fractional.runs[0] = {
    ...fractional.runs[0]!,
    startedAt: "2026-07-28T00:00:00Z",
    completedAt: "2026-07-28T00:00:00.900Z",
    durationMs: 900,
  };
  fractional.runs[1] = {
    ...fractional.runs[1]!,
    startedAt: "2026-07-28T00:00:00.500Z",
    completedAt: "2026-07-28T00:00:00.600Z",
    durationMs: 100,
  };
  if (fractional.trajectory !== null) {
    fractional.trajectory = {
      ...fractional.trajectory,
      startedAt: "2026-07-28T00:00:00.500Z",
      completedAt: "2026-07-28T00:00:00.600Z",
      durationMs: 100,
    };
  }
  const attempt = buildCloudTaskViewModel(fractional).attempts[0]!;
  assert.equal(attempt.startedAt, "2026-07-28T00:00:00Z");
  assert.equal(attempt.completedAt, "2026-07-28T00:00:00.900Z");
  assert.equal(attempt.durationMs, 900);
  assert.equal(attempt.durationSeconds, 0);
});

test("does not expose archive cursors, records, revisions, or direct URLs", () => {
  const model: CloudTaskViewModel = buildCloudTaskViewModel(detail());
  const serialized = JSON.stringify(model);
  for (const forbidden of ["transcriptPath", "completeRecords", "recordCount", "nextCursor", "fileRevision", "importerRevision", "partialTail", "publicUrl", "privateUrl"]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
});
