import assert from "node:assert/strict";
import { appendFile, cp, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { getArchiveConfig, validateArchivePaths } from "@/lib/steward-archive/config";
import { StewardArchiveImporter } from "@/lib/steward-archive/importer";
import { StewardArchiveRepository } from "@/lib/steward-archive/repository";
import { validatePipeline } from "@/lib/steward-archive/schema";
import { loadArchiveTaskView, loadInitialTranscript } from "@/lib/steward-archive/view-model";

async function fixtureImporter() {
  const root = await mkdtemp(join(tmpdir(), "coquic-steward-"));
  const tasksRoot = join(root, "tasks");
  await cp(new URL("../../examples/steward-dataset", import.meta.url), tasksRoot, { recursive: true });
  const importer = new StewardArchiveImporter(getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: tasksRoot, COQUIC_STEWARD_CACHE_PATH: join(root, "cache", "index.sqlite"), COQUIC_STEWARD_BATCH_SIZE: "1" }));
  await importer.reconcile();
  return { root, tasksRoot, importer, repository: new StewardArchiveRepository(importer) };
}

async function json(path: string) { return JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>; }
async function writeJson(path: string, value: unknown) { await writeFile(path, `${JSON.stringify(value, null, 2)}\n`); }

async function rewriteTaskIdentity(root: string, oldId: string, newId: string) {
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) await rewriteTaskIdentity(path, oldId, newId);
    else if (entry.isFile() && entry.name.endsWith(".json")) {
      const source = await readFile(path, "utf8");
      await writeFile(path, source.replaceAll(oldId, newId));
    }
  }
}

test("F016 configuration rejects lexical nesting and symlinked cache ancestors", async () => {
  assert.throws(() => validateArchivePaths("/tmp/tasks", "/tmp/tasks/cache", "test"), /contain one another/);
  assert.throws(() => validateArchivePaths("relative/tasks", "/tmp/cache", "test"), /absolute/);
  const root = await mkdtemp(join(tmpdir(), "coquic-config-"));
  try {
    const raw = join(root, "raw"); const link = join(root, "cache-link");
    await mkdir(raw); await symlink(raw, link, "dir");
    assert.throws(() => validateArchivePaths(raw, join(link, "index.sqlite"), "test"), /symlink|real paths/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("F001 reconciliation is repeatable and usage facts remain idempotent", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const first = Number(fixture.importer.db.prepare("SELECT count(*) AS count FROM usage_facts").get()?.count);
  await fixture.importer.reconcile();
  const second = Number(fixture.importer.db.prepare("SELECT count(*) AS count FROM usage_facts").get()?.count);
  assert(first > 0); assert.equal(second, first); assert.equal(fixture.importer.status().state, "ready");
});

test("F002 accepted transcript and artifact identities reject replacement and truncation", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const events = join(fixture.tasksRoot, "task-running", "events.jsonl");
  await writeFile(events, '{"kind":"replacement","text":"must not escape"}\n');
  await assert.rejects(() => fixture.repository.readArtifact("task-running-synthetic", "events.jsonl"), (error: Error & { code?: string }) => error.code === "STALE_CURSOR" && !error.message.includes("must not escape"));
  const transcript = join(fixture.tasksRoot, "task-running", "pipelines", "pipeline-initial", "runs", "run-implementation-recovery", "codex.jsonl");
  await writeFile(transcript, "");
  await assert.rejects(() => fixture.repository.readTranscriptChunk("task-running-synthetic", "run-implementation-recovery", "pipelines/pipeline-initial/runs/run-implementation-recovery/codex.jsonl"), (error: Error & { code?: string }) => error.code === "STALE_CURSOR");
});

test("F003 intermediate symlinks cannot escape a selected task", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const runs = join(fixture.tasksRoot, "task-running", "pipelines", "pipeline-initial", "runs");
  const outside = join(fixture.root, "outside-runs");
  await rename(runs, outside); await symlink(outside, runs, "dir");
  await assert.rejects(() => fixture.repository.readTranscriptChunk("task-running-synthetic", "run-implementation-recovery", "pipelines/pipeline-initial/runs/run-implementation-recovery/codex.jsonl"), /symlink|outside/);
  await fixture.importer.reconcile();
  assert.equal(fixture.importer.status().state, "degraded");
});

test("F004 transcript view loading is bounded, lazy, and cursor-bearing", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  let reads = 0;
  const original = fixture.repository.readTranscriptChunk.bind(fixture.repository);
  fixture.repository.readTranscriptChunk = async (...args) => { reads += 1; return original(...args); };
  const view = await loadArchiveTaskView(fixture.repository, "task-running-synthetic");
  assert(view); assert.equal(reads, 0, "metadata view must not eagerly read every transcript");
  const selected = view.attempts.find((attempt) => Number((attempt.workerRun as Record<string, unknown>).events) > 1) ?? view.attempts[0];
  const run = selected.workerRun as Record<string, unknown>;
  const initial = await loadInitialTranscript(fixture.repository, "task-running-synthetic", String(run.name), String(run.transcriptPath), Number(selected.number), 1);
  assert.equal(reads, 1); assert.equal(initial.items.length, 1); assert.equal(initial.hasMore, true); assert(initial.nextCursor);
});

test("F005 canonical pipelines retain every run, review kind, patch, and integration event", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const view = await loadArchiveTaskView(fixture.repository, "task-complete-synthetic");
  assert(view);
  assert.equal(view.attempts.length, 6); assert.equal(view.planRuns?.length, 1); assert.equal(view.patches.length, 2);
  assert.deepEqual(new Set(view.reviews.map((review) => review.kind)), new Set(["raw", "effective"]));
  assert(view.timeline.some((event) => event.kind === "integration"));
  assert(view.attempts.some((attempt) => (attempt.workerRun as Record<string, unknown>).resumeOfRunId !== undefined));
});

test("F006 complete append advances global revision without staling prior cursors", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const path = "pipelines/pipeline-initial/runs/run-implementation-recovery/codex.jsonl";
  const first = await fixture.repository.readTranscriptChunk("task-running-synthetic", "run-implementation-recovery", path, null, 1);
  const generation = first.data.file.fileRevision; const revision = fixture.importer.revision().revision;
  assert(first.data.nextCursor);
  await appendFile(join(fixture.tasksRoot, "task-running", ...path.split("/")), `${JSON.stringify({ record_type: "assistant.message", text: "appended" })}\n`);
  await fixture.importer.reconcile();
  assert(fixture.importer.revision().revision > revision);
  const continued = await fixture.repository.readTranscriptChunk("task-running-synthetic", "run-implementation-recovery", path, first.data.nextCursor);
  assert.equal(continued.data.file.fileRevision, generation); assert(continued.data.records.some((record) => (record.value as Record<string, unknown>).text === "appended"));
});

test("F007 malformed replacement metadata retains the last-valid indexed run", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const path = join(fixture.tasksRoot, "task-running", "pipelines", "pipeline-initial", "runs", "run-implementation-recovery", "run.json");
  const before = fixture.importer.db.prepare("SELECT state, updated_at FROM runs WHERE task_id=? AND run_id=?").get("task-running-synthetic", "run-implementation-recovery");
  await writeFile(path, '{"runId":"run-implementation-recovery"');
  await fixture.importer.reconcile();
  assert.equal(fixture.importer.status().state, "degraded");
  assert.deepEqual(fixture.importer.db.prepare("SELECT state, updated_at FROM runs WHERE task_id=? AND run_id=?").get("task-running-synthetic", "run-implementation-recovery"), before);
});

test("F008 terminal verification requires a complete schema-valid manifest identity", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const path = join(fixture.tasksRoot, "task-complete", "manifest.json");
  const manifest = await json(path); delete manifest.completionIdentity;
  await writeJson(path, manifest); await fixture.importer.reconcile();
  const task = fixture.importer.db.prepare("SELECT archive_state, archive_reason FROM tasks WHERE task_id=?").get("task-complete-synthetic");
  assert.equal(task?.archive_state, "incomplete"); assert.equal(task?.archive_reason, "manifest-invalid"); assert.equal(fixture.importer.status().verifiedTaskCount, 0);
});

test("F009 and F015 dashboard returns every state and distinguishes missing totals from zero", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const dashboard = fixture.repository.getTaskDashboard();
  for (const state of ["queued", "running", "reviewing", "integrating", "succeeded", "pushed", "no_changes", "blocked", "failed", "cancelled"]) assert.equal(typeof dashboard.counts[state], "number");
  assert.equal(dashboard.usage.tokens.total, 1050); assert.equal(dashboard.usage.cost.availableRuns, 7);
  fixture.importer.db.exec("DELETE FROM usage_facts");
  const unavailable = fixture.repository.getTaskDashboard();
  assert.equal(unavailable.usage.tokens.total, null); assert.equal(unavailable.usage.cost.microUsd, null); assert.equal(unavailable.usage.tokens.totalRuns, 0);
});

test("F010 history cursors survive new arrivals and support reverse navigation", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const template = join(fixture.tasksRoot, "task-running");
  for (let index = 0; index < 52; index += 1) {
    const id = `task-history-${String(index).padStart(3, "0")}`; const destination = join(fixture.tasksRoot, id);
    await cp(template, destination, { recursive: true }); await rewriteTaskIdentity(destination, "task-running-synthetic", id);
    const taskPath = join(destination, "task.json"); const task = await json(taskPath); task.status = "succeeded"; task.summary = { title: `History ${index}`, text: "Stable cursor history" }; task.updatedAt = `2026-07-21T${String(Math.floor(index / 60)).padStart(2, "0")}:${String(index % 60).padStart(2, "0")}:00Z`; await writeJson(taskPath, task);
  }
  await fixture.importer.reconcile();
  const first = fixture.repository.listTasksPage(); assert.equal(first.tasks.length, 50); assert(first.nextCursor); assert.equal(first.tasks.some((task) => task.status === "running"), false);
  const newId = "task-history-new"; const destination = join(fixture.tasksRoot, newId); await cp(template, destination, { recursive: true }); await rewriteTaskIdentity(destination, "task-running-synthetic", newId); const taskPath = join(destination, "task.json"); const task = await json(taskPath); task.status = "succeeded"; task.summary = { title: "New arrival", text: "Arrived after page one" }; task.updatedAt = "2026-07-23T00:00:00Z"; await writeJson(taskPath, task); await fixture.importer.reconcile();
  const second = fixture.repository.listTasksPage(first.nextCursor); assert(second.tasks.length > 0); assert(second.previousCursor); assert.equal(second.tasks.some((taskRow) => taskRow.taskId === newId), false);
  const previous = fixture.repository.listTasksPage(second.previousCursor); assert.equal(previous.tasks.length, 50); assert(previous.nextCursor); assert(previous.previousCursor);
  const newest = fixture.repository.listTasksPage(previous.previousCursor); assert(newest.tasks.some((taskRow) => taskRow.taskId === newId));
});

test("F011 external metadata validator rejects invented or incomplete pipelines", () => {
  assert.throws(() => validatePipeline({ pipelineId: "pipeline-x", taskId: "task-x", ordinal: 0, trigger: "invented", phase: "invented" }), /missing|contract/);
});

test("F014 large JSONL indexing yields while acquisition remains outside the transaction", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const path = join(fixture.tasksRoot, "task-running", "pipelines", "pipeline-initial", "runs", "run-implementation-recovery", "codex.jsonl");
  let payload = ""; for (let index = 0; index < 2500; index += 1) payload += `${JSON.stringify({ record_type: "assistant.message", text: `record-${index}` })}\n`; await appendFile(path, payload);
  let yielded = false; setImmediate(() => { yielded = true; }); await fixture.importer.reconcile();
  assert.equal(yielded, true); assert.equal(fixture.importer.status().state, "ready");
  const file = fixture.importer.db.prepare("SELECT complete_records FROM files WHERE task_id=? AND relative_path LIKE '%run-implementation-recovery/codex.jsonl'").get("task-running-synthetic"); assert.equal(Number(file?.complete_records), 2502);
});

test("schema stores offsets and relationships but no raw body columns", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const columns = fixture.importer.db.prepare("PRAGMA table_info(records)").all().map((row) => String(row.name));
  assert.ok(columns.includes("byte_start")); assert.ok(!columns.some((column) => /body|text|payload|content/i.test(column)));
  assert.equal((await lstat(fixture.tasksRoot)).isDirectory(), true);
});
