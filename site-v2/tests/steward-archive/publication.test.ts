import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodePublicationCursor, encodePublicationCursor, resolvePublicObjectUrl, validatePublicArtifact,
  validatePublicPublication, type PublicPublicationRows,
} from "@/lib/steward-archive/publication";

const digest = "a".repeat(64);
const taskId = "task-clean";
const publicationId = "publication-clean";
const runId = "run-clean";
const publicKey = `v1/tasks/${taskId}/objects/sha256/aa/${digest}`;

function rows(): PublicPublicationRows {
  return {
    generation: { publication_id: publicationId, task_id: taskId, run_id: runId, metadata_digest: "b".repeat(64), idempotency_key: "retry-clean", state: "visible", expected_task_count: 1, expected_pipeline_count: 1, expected_run_count: 1, expected_event_count: 2, expected_artifact_count: 1, created_at: "2026-07-28T00:00:00Z", exposed_at: "2026-07-28T00:00:02Z" },
    head: { task_id: taskId, publication_id: publicationId, state: "visible", updated_at: "2026-07-28T00:00:02Z" },
    task: { publication_id: publicationId, task_id: taskId, title: "Clean task", lifecycle_state: "active", created_at: "2026-07-28T00:00:00Z", completed_at: null },
    pipelines: [{ publication_id: publicationId, pipeline_id: "pipeline-clean", task_id: taskId, name: "Planning", created_at: "2026-07-28T00:00:00Z" }],
    runs: [{ publication_id: publicationId, run_id: runId, task_id: taskId, pipeline_id: "pipeline-clean", role: "planning", run_state: "completed", started_at: "2026-07-28T00:00:00Z", completed_at: "2026-07-28T00:00:01Z", duration_ms: 1000, atif_digest: digest }],
    events: [
      { publication_id: publicationId, task_id: taskId, sequence: 1, event_type: "started", occurred_at: "2026-07-28T00:00:00Z", summary: "Started" },
      { publication_id: publicationId, task_id: taskId, sequence: 2, event_type: "completed", occurred_at: "2026-07-28T00:00:01Z", summary: "Completed" },
    ],
    artifacts: [{ publication_id: publicationId, artifact_id: "artifact-atif", task_id: taskId, run_id: runId, logical_path: "runs/run-clean/trajectory.json", public_key: publicKey, media_type: "application/json", byte_size: 10, sha256: digest, availability: "available", redaction_applied: 0, original_retained: 1 }],
  };
}

test("validates clean public rows and same-publication ownership", () => {
  const result = validatePublicPublication(rows());
  assert.equal(result.generation.publication_id, publicationId);
  assert.equal(result.task.lifecycle_state, "active");
  assert.equal(result.artifacts[0].public_key, publicKey);
});

test("rejects visibility, exact-key, relationship, private-shape, and duplicate-path violations", () => {
  const hidden = rows(); hidden.head.state = "hidden" as never;
  assert.throws(() => validatePublicPublication(hidden), /head is not visible/);
  const unknown = rows() as unknown as Record<string, unknown>; unknown.task = { ...rows().task, private_locator: "secret" };
  assert.throws(() => validatePublicPublication(unknown), /unexpected public fields|private-shaped field/);
  const dangling = rows(); dangling.artifacts[0].run_id = "other-run";
  assert.throws(() => validatePublicPublication(dangling), /dangling run/);
  const duplicate = rows(); duplicate.artifacts.push({ ...duplicate.artifacts[0], artifact_id: "artifact-other" }); duplicate.generation.expected_artifact_count = 2;
  assert.throws(() => validatePublicPublication(duplicate), /logical_path/);
  const locator = { ...rows().artifacts[0], logical_path: "https://private.example/object" };
  assert.throws(() => validatePublicArtifact(locator), /private locator|logical path/);
  const embeddedLocator = rows(); embeddedLocator.task.title = "Copy at https://private.example/object";
  assert.throws(() => validatePublicPublication(embeddedLocator), /private locator/);
});

test("requires every run to belong to the generation tuple", () => {
  const extraRun = rows(); extraRun.generation.expected_run_count = 2;
  extraRun.runs.push({ ...extraRun.runs[0], run_id: "run-extra" });
  assert.throws(() => validatePublicPublication(extraRun), /generation.run_id|run.run_id/);
});

test("rejects malformed UTF-8 cursor bytes before JSON validation", () => {
  const malformed = "eyJ2ZXJzaW9uIjoxLCJxdWVyeSI6InRhc2tzIiwicHVibGljYXRpb25JZCI6InB1YiIsInNvcnQiOlsigCJdfQ";
  assert.throws(() => decodePublicationCursor(malformed, { query: "tasks", publicationId: "pub" }), /invalid cursor/);
});

test("counts Unicode code points for bounded public text", () => {
  const unicode = rows(); unicode.task.title = String.fromCodePoint(0x1f600).repeat(300);
  assert.equal(validatePublicPublication(unicode).task.title, unicode.task.title);
});

test("validates calendar dates and preserves fractional timestamp ordering", () => {
  const impossible = rows(); impossible.generation.created_at = "2026-02-30T00:00:00Z";
  assert.throws(() => validatePublicPublication(impossible), /invalid UTC timestamp/);
  const precise = rows(); precise.runs[0].started_at = "2026-01-01T00:00:00.0009Z"; precise.runs[0].completed_at = "2026-01-01T00:00:00.0010Z"; precise.runs[0].duration_ms = 0;
  assert.doesNotThrow(() => validatePublicPublication(precise));
  const reversed = rows(); reversed.runs[0].started_at = "2026-01-01T00:00:00.0010Z"; reversed.runs[0].completed_at = "2026-01-01T00:00:00.0009Z"; reversed.runs[0].duration_ms = 0;
  assert.throws(() => validatePublicPublication(reversed), /timestamp order/);
});

test("cursors are canonical, query/publication-bound structural values", () => {
  const token = encodePublicationCursor({ query: "tasks", publicationId, sort: ["2026-07-28T00:00:00Z", taskId] });
  assert.deepEqual(decodePublicationCursor(token, { query: "tasks", publicationId }), { version: 1, query: "tasks", publicationId, sort: ["2026-07-28T00:00:00Z", taskId] });
  assert.throws(() => decodePublicationCursor(token, { query: "runs", publicationId }), /stale/);
  assert.throws(() => decodePublicationCursor(token, { query: "tasks", publicationId: "publication-new" }), /stale/);
  assert.throws(() => decodePublicationCursor(`${token.slice(0, -1)}!`, { query: "tasks", publicationId }), /invalid cursor/);
});

test("R2 URLs contain only validated public keys below the configured HTTPS base", () => {
  const url = resolvePublicObjectUrl("https://objects.example.test/public", publicKey);
  assert.equal(url, `https://objects.example.test/public/${publicKey}`);
  assert.throws(() => resolvePublicObjectUrl("https://objects.example.test/public", "v1/originals/task/run/sha256/aa.jsonl"), /invalid public key/);
  assert.throws(() => resolvePublicObjectUrl("https://objects.example.test/public", "v1/tasks/other/objects/sha256/bb/" + digest), /invalid public key/);
  assert.throws(() => resolvePublicObjectUrl("http://objects.example.test/public", publicKey), /invalid public base/);
  assert.throws(() => resolvePublicObjectUrl("https://objects.example.test/public?private=1", publicKey), /invalid public base/);
});
