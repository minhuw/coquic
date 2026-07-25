import assert from "node:assert/strict";
import { appendFile, cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { getArchiveConfig } from "@/lib/steward-archive/config";
import { StewardArchiveImporter } from "@/lib/steward-archive/importer";
import { StewardArchiveRepository } from "@/lib/steward-archive/repository";

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "coquic-control-loop-"));
  const tasksRoot = join(root, "tasks");
  const controlLoopRoot = join(root, "control-loop");
  const cachePath = join(root, "cache", "site-v2.sqlite");
  await cp(new URL("../../examples/steward-dataset", import.meta.url), tasksRoot, { recursive: true });
  await cp(new URL("../../examples/steward-control-loop", import.meta.url), controlLoopRoot, { recursive: true });
  const config = getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: tasksRoot, COQUIC_STEWARD_CONTROL_LOOP_ROOT: controlLoopRoot, COQUIC_STEWARD_CACHE_PATH: cachePath });
  const importer = new StewardArchiveImporter(config);
  await importer.reconcile();
  return { root, tasksRoot, controlLoopRoot, importer, repository: new StewardArchiveRepository(importer) };
}

test("control-loop configuration rejects relative and unsafe roots", () => {
  assert.throws(() => getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: "/tmp/tasks", COQUIC_STEWARD_CONTROL_LOOP_ROOT: "control-loop", COQUIC_STEWARD_CACHE_PATH: "/tmp/cache/site-v2.sqlite" }), /absolute/);
  assert.throws(() => getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: "/tmp/tasks", COQUIC_STEWARD_CONTROL_LOOP_ROOT: "/tmp/control\\loop", COQUIC_STEWARD_CACHE_PATH: "/tmp/cache/site-v2.sqlite" }), /unsafe/);
});

test("control-loop importer indexes normalized records and keeps revisions idempotent", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 39);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_signals").get()?.count, 3);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_proposals").get()?.count, 5);
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_artifacts WHERE status='verified'").get()?.count, 10);
  const revision = state.importer.revision().revision;
  await state.importer.reconcile();
  assert.equal(state.importer.revision().revision, revision);
  assert.equal(state.repository.listSignalsPage().total, 3);
  assert.equal(state.repository.listPlannerRunsPage().total, 2);
});

test("complete-line append, partial tails, and replacement retain safe evidence", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const path = join(state.controlLoopRoot, "events/2026/07/24.jsonl");
  const original = await readFile(path, "utf8");
  const before = state.repository.getSignalDetail("signal-synthetic-open");
  await appendFile(path, "{\"eventId\":\"partial-tail\"");
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 39);
  assert.equal(state.importer.db.prepare("SELECT state FROM domain_health WHERE domain='control-loop'").get()?.state, "degraded");
  await writeFile(path, `${original}${JSON.stringify({ eventId: "event-runtime-extra", epochId: "epoch-synthetic-20260722", sequence: 39, occurredAt: "2026-07-24T12:06:00Z", kind: "daemon.runtime", payload: { state: "running", instanceId: "instance-extra" } })}\n`);
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 40);
  assert.equal(state.repository.getSignalDetail("signal-synthetic-open")?.eventCount, before?.eventCount);
});

test("malformed event replacement keeps the last valid generation queryable", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const path = join(state.controlLoopRoot, "events/2026/07/24.jsonl");
  const original = await readFile(path, "utf8");
  await writeFile(path, `${original}{malformed}\n`);
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT state FROM domain_health WHERE domain='control-loop'").get()?.state, "degraded");
  const evidence = await state.repository.readSignalEvents("signal-synthetic-open", null, 100);
  assert(evidence); assert(evidence.records.length > 0);
});

test("selected readers expose complete records and manifest-verified downloads only", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const events = await state.repository.readSignalEvents("signal-synthetic-consumed", null, 2);
  assert(events); assert.equal(events.records.length, 2); assert(events.nextCursor);
  const continued = await state.repository.readSignalEvents("signal-synthetic-consumed", events.nextCursor, 20);
  assert(continued); assert.equal(new Set([...events.records, ...continued.records].map((record) => record.eventId)).size, 11);
  const transcript = await state.repository.readPlannerTranscript("planner-synthetic-success");
  assert(transcript); assert.equal(transcript.records.length, 2); assert.equal(transcript.incompleteTail, false);
  const artifact = await state.repository.readPlannerArtifact("planner-synthetic-success", "prompt.md");
  const chunks: Buffer[] = []; for await (const chunk of artifact.stream) chunks.push(Buffer.from(chunk));
  assert.match(Buffer.concat(chunks).toString("utf8"), /Current signal/);
  assert(state.repository.getTaskProvenance("task-synthetic-accepted"));
  state.importer.db.prepare("DELETE FROM control_edges WHERE edge_type='proposal_task' AND target_id=?").run("task-synthetic-accepted");
  assert.equal(state.repository.getTaskProvenance("task-synthetic-accepted"), null);
});

test("peer epoch mismatch preserves the last compatible control-loop generation", async (t) => {
  const state = await fixture();
  t.after(() => { state.importer.db.close(); return rm(state.root, { recursive: true, force: true }); });
  const epochPath = join(state.controlLoopRoot, "epoch.json");
  const original = await readFile(epochPath, "utf8");
  await writeFile(epochPath, original.replace("epoch-synthetic-20260722", "epoch-other"));
  await state.importer.reconcile();
  assert.equal(state.importer.db.prepare("SELECT state FROM domain_health WHERE domain='control-loop'").get()?.state, "incompatible");
  assert.equal(state.importer.db.prepare("SELECT count(*) AS count FROM control_records").get()?.count, 39);
});
