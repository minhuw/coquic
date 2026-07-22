import assert from "node:assert/strict";
import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getArchiveConfig } from "../lib/steward-archive/config";
import { StewardArchiveImporter } from "../lib/steward-archive/importer";
import { StewardArchiveRepository } from "../lib/steward-archive/repository";

(async () => {
  const root = await mkdtemp(join(tmpdir(), "coquic-steward-browser-"));
  const tasksRoot = join(root, "tasks");
  await cp(new URL("../examples/steward-dataset", import.meta.url), tasksRoot, { recursive: true });
  const importer = new StewardArchiveImporter(getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: tasksRoot, COQUIC_STEWARD_CACHE_PATH: join(root, "cache", "site-v2.sqlite") }));
  try {
    await importer.reconcile();
    const repository = new StewardArchiveRepository(importer);
    const dashboard = repository.getTaskDashboard();
    assert.equal(dashboard.counts.total, 2);
    assert.equal(dashboard.counts.verified, 1);
    const detail = await repository.loadTaskDetail("task-complete-synthetic");
    assert.equal(detail?.data.task.taskId, "task-complete-synthetic");
    const run = detail?.data.pipelines[0]?.runs[0] as Record<string, unknown> | undefined;
    const artifacts = run?.artifacts as Record<string, unknown> | undefined;
    const codex = artifacts?.codex as Record<string, unknown> | undefined;
    if (codex?.path && run?.runId) {
      const chunk = await repository.readTranscriptChunk("task-complete-synthetic", String(run.runId), String(codex.path));
      assert.ok(chunk.data.records.length >= 1);
    }
    process.stdout.write("Steward archive smoke test passed\n");
  } finally {
    importer.stop();
    importer.db.close();
    await rm(root, { recursive: true, force: true });
  }
})();
