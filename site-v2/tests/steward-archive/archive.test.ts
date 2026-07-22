import assert from "node:assert/strict";
import { cp, mkdtemp, appendFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { getArchiveConfig, validateArchivePaths } from "@/lib/steward-archive/config";
import { StewardArchiveImporter } from "@/lib/steward-archive/importer";
import { StewardArchiveRepository } from "@/lib/steward-archive/repository";

async function fixtureImporter() {
  const root = await mkdtemp(join(tmpdir(), "coquic-steward-"));
  const tasksRoot = join(root, "tasks");
  const cacheRoot = join(root, "cache");
  await cp(new URL("../../examples/steward-dataset", import.meta.url), tasksRoot, { recursive: true });
  const importer = new StewardArchiveImporter(getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: tasksRoot, COQUIC_STEWARD_CACHE_PATH: join(cacheRoot, "index.sqlite") }));
  await importer.reconcile();
  return { root, tasksRoot, importer, repository: new StewardArchiveRepository(importer) };
}

test("configuration rejects nested or unsafe paths", () => {
  assert.throws(() => validateArchivePaths("/tmp/tasks", "/tmp/tasks/cache", "test"), /contain one another/);
  assert.throws(() => validateArchivePaths("relative/tasks", "/tmp/cache", "test"), /absolute/);
  assert.throws(() => validateArchivePaths("/tmp/tasks\\root", "/tmp/cache", "test"), /unsafe/);
});

test("importer indexes fixture tasks and preserves explicit availability", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.stop(); fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const status = fixture.importer.status();
  assert.equal(status.state, "ready");
  assert.equal(status.taskCount, 2);
  assert.equal(status.verifiedTaskCount, 1);
  const dashboard = fixture.repository.getTaskDashboard();
  assert.equal(dashboard.counts.total, 2);
  assert.equal(dashboard.usage.tokens.total, 1050);
  assert.equal(dashboard.usage.tokens.availableRuns, 7);
  assert.equal(dashboard.usage.cost.availableRuns, 7);
  const page = fixture.repository.listTasksPage();
  assert.equal(page.tasks.length, 2);
  assert.equal(page.nextCursor, null);
  const detail = await fixture.repository.loadTaskDetail("task-complete-synthetic");
  assert.equal(detail?.data.task.taskId, "task-complete-synthetic");
  assert.equal(detail?.data.archiveState, "verified");
});

test("JSONL importer ignores an incomplete tail and exposes only complete records", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.stop(); fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const path = join(fixture.tasksRoot, "task-running", "pipelines", "pipeline-initial", "runs", "run-implementation-recovery", "codex.jsonl");
  await appendFile(path, '{"record_type":"synthetic.incomplete"');
  await fixture.importer.reconcile();
  const file = fixture.importer.db.prepare("SELECT accepted_end, complete_records FROM files WHERE task_id=? AND relative_path=?").get("task-running-synthetic", "pipelines/pipeline-initial/runs/run-implementation-recovery/codex.jsonl");
  const bytes = await readFile(path);
  assert.equal(Number(file?.accepted_end), bytes.lastIndexOf(10) + 1);
  assert.equal(Number(file?.complete_records), 2);
  const chunk = await fixture.repository.readTranscriptChunk("task-running-synthetic", "run-implementation-recovery", "pipelines/pipeline-initial/runs/run-implementation-recovery/codex.jsonl");
  assert.equal(chunk.data.records.length, 2);
  assert.equal(chunk.data.hasMore, false);
});

test("SQLite schema contains offsets but no raw body columns", async (t) => {
  const fixture = await fixtureImporter();
  t.after(async () => { fixture.importer.stop(); fixture.importer.db.close(); await rm(fixture.root, { recursive: true, force: true }); });
  const columns = fixture.importer.db.prepare("PRAGMA table_info(records)").all().map((row) => String(row.name));
  assert.ok(columns.includes("byte_start"));
  assert.ok(!columns.some((column) => /body|text|payload|content/i.test(column)));
});
