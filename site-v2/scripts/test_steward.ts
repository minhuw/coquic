import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { appendFile, cp, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

async function availablePort() {
  const server = createServer();
  await new Promise<void>((resolveReady, reject) => server.once("error", reject).listen(0, "127.0.0.1", resolveReady));
  const address = server.address();
  assert(address && typeof address === "object");
  const port = address.port;
  await new Promise<void>((resolveClosed) => server.close(() => resolveClosed()));
  return port;
}

async function waitForStatus(baseUrl: string, child: ChildProcess) {
  let lastStatus = "no response";
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Next server exited before archive readiness (${child.exitCode})`);
    try {
      const response = await fetch(`${baseUrl}/api/steward/status`, { cache: "no-store" });
      if (response.ok) {
        const payload = await response.json() as { data?: { state?: string; taskCount?: number } };
        lastStatus = JSON.stringify(payload.data);
        if (payload.data?.state === "ready" && payload.data.taskCount === 102) return;
      }
    } catch { /* server is still starting */ }
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
  }
  throw new Error(`temporary Steward archive did not become ready: ${lastStatus}`);
}

async function rewriteTaskIdentity(root: string, oldId: string, newId: string) {
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) await rewriteTaskIdentity(path, oldId, newId);
    else if (entry.isFile() && entry.name.endsWith(".json")) await writeFile(path, (await readFile(path, "utf8")).replaceAll(oldId, newId));
  }
}

async function stop(child: ChildProcess) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise<void>((resolveExit) => child.once("exit", () => resolveExit())),
    new Promise<void>((resolveTimeout) => setTimeout(() => { child.kill("SIGKILL"); resolveTimeout(); }, 5_000)),
  ]);
}

void (async () => {
  const siteRoot = fileURLToPath(new URL("..", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "coquic-steward-browser-"));
  const tasksRoot = join(root, "tasks");
  const cachePath = join(root, "cache", "site-v2.sqlite");
  const serverRoot = join(root, "standalone");
  const port = await availablePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  await cp(new URL("../examples/steward-dataset", import.meta.url), tasksRoot, { recursive: true });
  const runningTemplate = join(tasksRoot, "task-running");
  for (let index = 0; index < 50; index += 1) {
    const taskId = `task-browser-active-${String(index).padStart(3, "0")}`;
    const destination = join(tasksRoot, taskId); await cp(runningTemplate, destination, { recursive: true }); await rewriteTaskIdentity(destination, "task-running-synthetic", taskId);
    const taskPath = join(destination, "task.json"); const task = JSON.parse(await readFile(taskPath, "utf8")) as Record<string, unknown>;
    task.summary = { title: index === 0 ? "Active task 51" : `Active task ${String(50 - index).padStart(2, "0")}`, text: "Paginated active archive fixture." }; task.updatedAt = "2026-07-22T08:00:00Z"; await writeFile(taskPath, `${JSON.stringify(task, null, 2)}\n`);
  }
  for (let index = 0; index < 50; index += 1) {
    const taskId = `task-browser-history-${String(index).padStart(3, "0")}`;
    const destination = join(tasksRoot, taskId); await cp(runningTemplate, destination, { recursive: true }); await rewriteTaskIdentity(destination, "task-running-synthetic", taskId);
    const taskPath = join(destination, "task.json"); const task = JSON.parse(await readFile(taskPath, "utf8")) as Record<string, unknown>;
    task.status = "succeeded"; task.summary = { title: `Browser history ${String(index).padStart(2, "0")}`, text: "Paginated terminal archive fixture." }; task.updatedAt = `2026-07-21T08:00:${String(index).padStart(2, "0")}Z`; await writeFile(taskPath, `${JSON.stringify(task, null, 2)}\n`);
  }
  await cp(join(siteRoot, ".next", "standalone"), serverRoot, { recursive: true });
  await cp(join(siteRoot, ".next", "static"), join(serverRoot, ".next", "static"), { recursive: true });
  if (existsSync(join(siteRoot, "public"))) await cp(join(siteRoot, "public"), join(serverRoot, "public"), { recursive: true });
  const activeTranscript = join(tasksRoot, "task-running", "pipelines", "pipeline-initial", "runs", "run-implementation-recovery", "codex.jsonl");
  for (let ordinal = 0; ordinal < 75; ordinal += 1) await appendFile(activeTranscript, `${JSON.stringify({ record_type: "assistant.message", timestamp: `2026-07-22T09:${String(ordinal % 60).padStart(2, "0")}:00Z`, text: `Lazy archive record ${ordinal + 1}` })}\n`);

  const server = spawn(process.execPath, [join(serverRoot, "server.js")], {
    cwd: serverRoot,
    env: { ...process.env, HOSTNAME: "127.0.0.1", PORT: String(port), NODE_ENV: "production", COQUIC_STEWARD_TASKS_ROOT: tasksRoot, COQUIC_STEWARD_CACHE_PATH: cachePath, COQUIC_STEWARD_RECONCILE_MS: "60000", COQUIC_STEWARD_BATCH_SIZE: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverOutput = "";
  server.stdout?.on("data", (chunk) => { serverOutput = `${serverOutput}${String(chunk)}`.slice(-8_000); });
  server.stderr?.on("data", (chunk) => { serverOutput = `${serverOutput}${String(chunk)}`.slice(-8_000); });
  try {
    await waitForStatus(baseUrl, server);
    const playwright = spawn(process.execPath, [resolve(siteRoot, "node_modules/@playwright/test/cli.js"), "test", "tests/steward.spec.ts", "--config", "playwright.config.ts", "--workers=1"], {
      cwd: siteRoot,
      env: { ...process.env, PLAYWRIGHT_BASE_URL: baseUrl, STEWARD_TEST_TASKS_ROOT: tasksRoot },
      stdio: "inherit",
    });
    const code = await new Promise<number>((resolveExit) => playwright.once("exit", (value) => resolveExit(value ?? 1)));
    if (code !== 0) throw new Error(`Steward Playwright suite failed with exit ${code}`);
    process.stdout.write("Steward Playwright archive suite passed\n");
  } catch (error) {
    if (serverOutput) process.stderr.write(serverOutput);
    throw error;
  } finally {
    await stop(server);
    await rm(root, { recursive: true, force: true });
  }
})();
