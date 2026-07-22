import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getArchiveConfig } from "../lib/steward-archive/config";

(async () => {
  const root = await mkdtemp(join(tmpdir(), "coquic-deploy-"));
  try {
    const tasks = join(root, "steward", "tasks");
    const cache = join(root, "steward", "cache", "site-v2.sqlite");
    await mkdir(join(root, "steward", "cache"), { recursive: true });
    await writeFile(join(root, "marker"), "owned\n");
    const config = getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: tasks, COQUIC_STEWARD_CACHE_PATH: cache });
    assert.equal(config.tasksRoot, tasks);
    assert.equal(config.cachePath, cache);
    assert.throws(() => getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: tasks, COQUIC_STEWARD_CACHE_PATH: join(tasks, "cache.sqlite") }));
    assert.equal((await readFile(join(root, "marker"), "utf8")).trim(), "owned");
    process.stdout.write("Deployment path smoke test passed\n");
  } finally { await rm(root, { recursive: true, force: true }); }
})();
