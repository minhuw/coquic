import assert from "node:assert/strict";
import { appendFile, cp, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { getArchiveConfig, validateArchivePaths } from "@/lib/steward-archive/config";
import { StewardArchiveImporter } from "@/lib/steward-archive/importer";
import { StewardArchiveRepository } from "@/lib/steward-archive/repository";
import { validatePipeline, validateRun, validateTask } from "@/lib/steward-archive/schema";
import { loadArchiveTaskView, loadInitialTranscript } from "@/lib/steward-archive/view-model";

async function fixtureImporter(prepare?: (tasksRoot: string) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), "coquic-steward-"));
  const tasksRoot = join(root, "tasks");
  const cachePath = join(root, "cache", "index.sqlite");
  await cp(new URL("../../examples/steward-dataset", import.meta.url), tasksRoot, { recursive: true });
  await prepare?.(tasksRoot);
  const config = getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: tasksRoot, COQUIC_STEWARD_CACHE_PATH: cachePath, COQUIC_STEWARD_BATCH_SIZE: "1" });
  const importer = new StewardArchiveImporter(config);
  await importer.reconcile();
  return { root, tasksRoot, cachePath, config, importer, repository: new StewardArchiveRepository(importer) };
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
  const complete = await original("task-running-synthetic", String(run.name), String(run.transcriptPath), null, 100);
  assert.equal(complete.data.hasMore, false); assert(complete.data.nextCursor, "an end cursor must remain available for active append");
  await appendFile(join(fixture.tasksRoot, "task-running", ...String(run.transcriptPath).split("/")), `${JSON.stringify({ record_type: "assistant.message", text: "after-end" })}\n`);
  await fixture.importer.reconcile();
  const appended = await original("task-running-synthetic", String(run.name), String(run.transcriptPath), complete.data.nextCursor);
  assert.equal(appended.data.records.length, 1); assert.equal((appended.data.records[0].value as Record<string, unknown>).text, "after-end");
});

test("F005 every owned run exposes independently loadable transcript evidence", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const view = await loadArchiveTaskView(fixture.repository, "task-complete-synthetic");
  assert(view);
  assert.equal(view.attempts.length, 2, "pipelines are the outer processing passes"); assert.equal(view.planRuns?.length, 1); assert.equal(view.patches.length, 2);
  assert.equal(view.attempts.reduce((total, pipeline) => total + (pipeline.runs as Array<unknown>).length, 0), 7);
  assert.deepEqual(view.attempts.map((pipeline) => (pipeline.runs as Array<unknown>).length), [4, 3]);
  for (const pipeline of view.attempts) {
    for (const run of pipeline.runs as Array<Record<string, unknown>>) {
      assert.equal(typeof run.transcriptPath, "string", `${String(run.runId)} needs a selectable transcript locator`);
      const chunk = await loadInitialTranscript(fixture.repository, "task-complete-synthetic", String(run.runId), String(run.transcriptPath), Number(pipeline.number), 1);
      assert.equal(chunk.items.length, 1, `${String(run.runId)} transcript must be independently reachable`);
    }
  }
  assert(view.attempts.some((pipeline) => (pipeline.runs as Array<Record<string, unknown>>).some((run) => run.runId === "run-repair-implementation")));
  assert(view.attempts.every((pipeline) => (pipeline.runs as Array<Record<string, unknown>>).every((run) => "resumeOfRunId" in run && "sessionId" in run)));
  assert(view.attempts.some((pipeline) => (pipeline.runs as Array<Record<string, unknown>>).some((run) => (run.usage as Record<string, unknown>).totalTokens !== undefined)));
  assert.deepEqual(new Set(view.reviews.map((review) => review.kind)), new Set(["raw", "effective"]));
  assert(view.timeline.some((event) => event.kind === "integration"));
  assert(view.validations.every((validation) => typeof validation.outputUrl === "string"));
  assert(view.attempts.some((pipeline) => (pipeline.integration as Record<string, unknown>).state === "succeeded"));
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

test("F006 content-bound cursors survive cache rebuild and stale after replacement", async () => {
  const fixture = await fixtureImporter();
  const importers: StewardArchiveImporter[] = [fixture.importer];
  try {
    const path = "pipelines/pipeline-initial/runs/run-implementation-recovery/codex.jsonl";
    const first = await fixture.repository.readTranscriptChunk("task-running-synthetic", "run-implementation-recovery", path, null, 1);
    fixture.importer.db.close();
    await rm(fixture.cachePath, { force: true }); await rm(`${fixture.cachePath}-wal`, { force: true }); await rm(`${fixture.cachePath}-shm`, { force: true });
    const rebuilt = new StewardArchiveImporter(fixture.config); importers.push(rebuilt); await rebuilt.reconcile();
    const rebuiltRepository = new StewardArchiveRepository(rebuilt);
    assert.equal((await rebuiltRepository.readTranscriptChunk("task-running-synthetic", "run-implementation-recovery", path, first.data.nextCursor)).data.file.fileRevision, first.data.file.fileRevision);
    rebuilt.db.close();
    await writeFile(join(fixture.tasksRoot, "task-running", ...path.split("/")), `${JSON.stringify({ record_type: "assistant.message", text: "replacement" })}\n`);
    await rm(fixture.cachePath, { force: true }); await rm(`${fixture.cachePath}-wal`, { force: true }); await rm(`${fixture.cachePath}-shm`, { force: true });
    const replaced = new StewardArchiveImporter(fixture.config); importers.push(replaced); await replaced.reconcile();
    await assert.rejects(() => new StewardArchiveRepository(replaced).readTranscriptChunk("task-running-synthetic", "run-implementation-recovery", path, first.data.nextCursor), (error: Error & { code?: string }) => error.code === "STALE_CURSOR");
  } finally {
    for (const importer of importers) try { importer.db.close(); } catch { /* already closed */ }
    await rm(fixture.root, { recursive: true, force: true });
  }
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

test("F008 invalid mutation of a previously verified manifest is terminal corruption", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const path = join(fixture.tasksRoot, "task-complete", "manifest.json");
  const runCount = Number(fixture.importer.db.prepare("SELECT count(*) AS count FROM runs WHERE task_id=?").get("task-complete-synthetic")?.count);
  const manifest = await json(path); delete manifest.completionIdentity;
  await writeJson(path, manifest);
  for (let reconciliation = 1; reconciliation <= 2; reconciliation += 1) {
    await fixture.importer.reconcile();
    const task = fixture.importer.db.prepare("SELECT archive_state, archive_reason FROM tasks WHERE task_id=?").get("task-complete-synthetic");
    assert.equal(task?.archive_state, "corrupt", `reconciliation ${reconciliation} must retain known corruption`);
    assert.equal(task?.archive_reason, "manifest-invalid");
    assert.equal(Number(fixture.importer.db.prepare("SELECT count(*) AS count FROM runs WHERE task_id=?").get("task-complete-synthetic")?.count), runCount);
    assert.equal(fixture.importer.status().verifiedTaskCount, 0);
    assert.equal(fixture.importer.status().state, "archive-corrupt");
  }
});

test("F008 never-verified incomplete terminal evidence remains recoverable", async (t) => {
  let completeManifest: Record<string, unknown> | undefined;
  const fixture = await fixtureImporter(async (tasksRoot) => {
    const path = join(tasksRoot, "task-complete", "manifest.json");
    completeManifest = await json(path);
    const incompleteManifest = { ...completeManifest };
    delete incompleteManifest.completionIdentity;
    await writeJson(path, incompleteManifest);
  });
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const query = fixture.importer.db.prepare("SELECT archive_state FROM tasks WHERE task_id=?");
  assert.equal(query.get("task-complete-synthetic")?.archive_state, "incomplete");
  assert(completeManifest);
  await writeJson(join(fixture.tasksRoot, "task-complete", "manifest.json"), completeManifest);
  await fixture.importer.reconcile();
  assert.equal(query.get("task-complete-synthetic")?.archive_state, "verified");
});

test("F008 mutation of verified terminal metadata preserves the task and revokes verification", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  assert.equal(fixture.importer.db.prepare("SELECT archive_state FROM tasks WHERE task_id=?").get("task-complete-synthetic")?.archive_state, "verified");
  const path = join(fixture.tasksRoot, "task-complete", "pipelines", "pipeline-initial", "runs", "run-implementation", "run.json");
  const run = await json(path); run.startedAt = "0"; await writeJson(path, run);
  await fixture.importer.reconcile();
  const row = fixture.importer.db.prepare("SELECT archive_state, archive_reason FROM tasks WHERE task_id=?").get("task-complete-synthetic");
  assert.equal(row?.archive_state, "corrupt"); assert.equal(row?.archive_reason, "manifest-mismatch");
  assert.equal(fixture.importer.status().verifiedTaskCount, 0); assert.equal(fixture.importer.status().state, "archive-corrupt");
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

test("F011 canonical schema rejects null available descriptors and non-RFC3339 timestamps", async () => {
  const run = await json(fileURLToPath(new URL("../../examples/steward-dataset/task-running/pipelines/pipeline-initial/runs/run-implementation-recovery/run.json", import.meta.url)));
  const artifacts = run.artifacts as Record<string, Record<string, unknown>>;
  artifacts.codex.availability = "available"; artifacts.codex.reason = null; artifacts.codex.mediaType = null; artifacts.codex.byteSize = null;
  assert.throws(() => validateRun(run), /archive contract/);
  const task = await json(fileURLToPath(new URL("../../examples/steward-dataset/task-running/task.json", import.meta.url)));
  task.updatedAt = "0";
  assert.throws(() => validateTask(task), /archive contract/);
});

test("F014 unchanged JSONL reuses durable cursors and append parses only new records", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const path = join(fixture.tasksRoot, "task-running", "pipelines", "pipeline-initial", "runs", "run-implementation-recovery", "codex.jsonl");
  let payload = ""; for (let index = 0; index < 200_000; index += 1) payload += `${JSON.stringify({ record_type: "assistant.message", text: `record-${index}` })}\n`; await appendFile(path, payload);
  let ticks = 0; let maximumGap = 0; let previous = performance.now();
  const timer = setInterval(() => { const current = performance.now(); maximumGap = Math.max(maximumGap, current - previous); previous = current; ticks += 1; }, 10);
  await fixture.importer.reconcile(); clearInterval(timer);
  assert(ticks > 10); assert(maximumGap < 750, `event-loop stall was ${maximumGap}ms`); assert.equal(fixture.importer.status().state, "ready");
  const fileQuery = fixture.importer.db.prepare("SELECT complete_records FROM files WHERE task_id=? AND relative_path LIKE '%run-implementation-recovery/codex.jsonl'");
  assert.equal(Number(fileQuery.get("task-running-synthetic")?.complete_records), 200_002);
  assert.equal(fixture.importer.diagnostics().jsonlRecordsParsed, 200_000);
  const indexedRows = Number(fixture.importer.db.prepare("SELECT count(*) AS count FROM records WHERE task_id=? AND relative_path LIKE '%run-implementation-recovery/codex.jsonl'").get("task-running-synthetic")?.count);
  await fixture.importer.reconcile();
  const unchanged = fixture.importer.diagnostics();
  assert.equal(unchanged.jsonlRecordsParsed, 0, "unchanged accepted files must not be reparsed");
  assert.equal(unchanged.recordRowsStaged, 0, "unchanged accepted records must not be restaged");
  assert(unchanged.jsonlFilesReused > 0); assert.equal(Number(fileQuery.get("task-running-synthetic")?.complete_records), indexedRows);
  await appendFile(path, `${JSON.stringify({ record_type: "assistant.message", text: "append-a" })}\n${JSON.stringify({ record_type: "assistant.message", text: "append-b" })}\n`);
  await fixture.importer.reconcile();
  const appended = fixture.importer.diagnostics();
  assert.equal(appended.jsonlRecordsParsed, 2); assert.equal(appended.recordRowsStaged, 2); assert(appended.jsonlFilesAppended > 0);
  assert.equal(Number(fileQuery.get("task-running-synthetic")?.complete_records), 200_004);
});

test("F018 the 51st active task is reachable through stable bounded pagination", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  for (let index = 0; index < 50; index += 1) {
    const taskId = `task-active-${String(index).padStart(3, "0")}`;
    const destination = join(fixture.tasksRoot, taskId); await cp(join(fixture.tasksRoot, "task-running"), destination, { recursive: true });
    await rewriteTaskIdentity(destination, "task-running-synthetic", taskId);
    const taskPath = join(destination, "task.json"); const task = await json(taskPath); task.summary = { title: `Active ${index}`, text: "Must remain reachable" }; await writeJson(taskPath, task);
  }
  await fixture.importer.reconcile();
  const dashboard = fixture.repository.getTaskDashboard(); const history = fixture.repository.listTasksPage(); const first = fixture.repository.listActiveTasksPage();
  assert.equal(dashboard.counts.running, 51); assert.equal(dashboard.active.length, 50);
  assert.equal(first.tasks.length, 50); assert(first.nextCursor); assert.equal(first.previousCursor, null); assert.equal(first.total, 51);
  const second = fixture.repository.listActiveTasksPage(first.nextCursor); assert.equal(second.tasks.length, 1); assert(second.previousCursor); assert.equal(second.nextCursor, null);
  assert.equal(new Set([...first.tasks, ...second.tasks].map((item) => item.taskId)).size, 51);
  const previous = fixture.repository.listActiveTasksPage(second.previousCursor); assert.deepEqual(previous.tasks.map((item) => item.taskId), first.tasks.map((item) => item.taskId));
  assert.equal(history.tasks.some((item) => item.status === "running"), false);
});

test("F019 unknown transcript records are bounded opaque evidence without provider payload", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const relative = "pipelines/pipeline-initial/runs/run-implementation-recovery/codex.jsonl";
  await appendFile(join(fixture.tasksRoot, "task-running", ...relative.split("/")), `${JSON.stringify({ record_type: "provider.private", provider_thread_id: "secret-provider-id", body: { private: "never disclose" }, text: "private body" })}\n`);
  await fixture.importer.reconcile();
  const chunk = await fixture.repository.readTranscriptChunk("task-running-synthetic", "run-implementation-recovery", relative, null, 100);
  const serialized = JSON.stringify(chunk.data.records.at(-1));
  assert.match(serialized, /unrecognized-record/); assert.doesNotMatch(serialized, /secret-provider-id|never disclose|private body|provider\.private/);
});

test("F020 raw artifact access exposes a stream after accepted identity validation", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const artifact = await fixture.repository.readArtifact("task-running-synthetic", "prompt.md");
  assert.equal("bytes" in artifact, false); assert.equal(typeof artifact.stream.pipe, "function");
  const chunks: Buffer[] = []; for await (const chunk of artifact.stream) chunks.push(Buffer.from(chunk));
  assert.equal(Buffer.concat(chunks).length, artifact.size); assert.match(Buffer.concat(chunks).toString("utf8"), /synthetic/i);
});

test("schema stores offsets and relationships but no raw body columns", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const columns = fixture.importer.db.prepare("PRAGMA table_info(records)").all().map((row) => String(row.name));
  assert.ok(columns.includes("byte_start")); assert.ok(!columns.some((column) => /body|text|payload|content/i.test(column)));
  assert.equal((await lstat(fixture.tasksRoot)).isDirectory(), true);
});
