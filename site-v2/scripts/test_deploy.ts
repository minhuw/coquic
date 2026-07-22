import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getArchiveConfig } from "../lib/steward-archive/config";

async function executable(path: string, source: string) { await writeFile(path, source); await chmod(path, 0o755); }

async function run(command: string, args: string[], env: NodeJS.ProcessEnv) {
  const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (chunk) => { output += String(chunk); });
  child.stderr.on("data", (chunk) => { output += String(chunk); });
  const code = await Promise.race([
    new Promise<number>((resolveExit) => child.once("exit", (value) => resolveExit(value ?? 1))),
    new Promise<number>((resolveTimeout) => setTimeout(() => { child.kill("SIGKILL"); resolveTimeout(124); }, 10_000)),
  ]);
  return { code, output };
}

void (async () => {
  const siteRoot = fileURLToPath(new URL("..", import.meta.url));
  const repoRoot = resolve(siteRoot, "..");
  const runDemo = join(repoRoot, "site", "deploy", "run-demo.sh");
  const deployRemote = join(repoRoot, "site", "deploy", "deploy-remote.sh");
  const root = await mkdtemp(join(tmpdir(), "coquic-deploy-"));
  try {
    const release = join(root, "release");
    const app = join(release, "app");
    const tasks = join(root, "persistent", "steward", "tasks");
    const cache = join(root, "persistent", "steward", "cache", "site-v2.sqlite");
    const fakeBin = join(root, "bin");
    const processLog = join(root, "process.log");
    const curlLog = join(root, "curl.log");
    await mkdir(app, { recursive: true }); await mkdir(tasks, { recursive: true }); await mkdir(dirname(cache), { recursive: true }); await mkdir(fakeBin);
    await writeFile(join(app, "server.js"), "// fake Next entry\n");
    await executable(join(release, "h3-server"), "#!/usr/bin/env bash\necho h3 >>\"${FAKE_PROCESS_LOG}\"\nsleep 0.2\n");
    await executable(join(fakeBin, "node"), "#!/usr/bin/env bash\nif [[ \"${1:-}\" == \"-e\" ]]; then [[ \"${FAKE_NODE_SQLITE:-1}\" == \"1\" ]]; exit; fi\necho \"next:${COQUIC_STEWARD_TASKS_ROOT}:${COQUIC_STEWARD_CACHE_PATH}\" >>\"${FAKE_PROCESS_LOG}\"\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n");
    await executable(join(fakeBin, "curl"), "#!/usr/bin/env bash\nurl=\"${!#}\"\necho \"${url}\" >>\"${FAKE_CURL_LOG}\"\nif [[ \"${url}\" == */api/steward/status ]]; then printf '%s\\n' '{\"data\":{\"state\":\"indexing\"}}'; else printf '%s\\n' ready; fi\n");
    const deployTestRoot = join(root, "deploy-remote");
    await mkdir(deployTestRoot); await writeFile(join(deployTestRoot, ".coquic-deploy-test-root"), "owned\n");
    const probe = join(fakeBin, "probe");
    await executable(probe, "#!/usr/bin/env bash\nprintf '%s\\n' '{\"data\":{\"state\":\"ready\"}}'\n");
    const env = { ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, COQUIC_DEMO_RELEASE_DIR: release, COQUIC_DEMO_QA_ENABLED: "false", COQUIC_DEMO_NEXT_PORT: "39111", COQUIC_DEMO_PORT: "39443", COQUIC_DEMO_BOOTSTRAP_PORT: "39443", COQUIC_STEWARD_TASKS_ROOT: tasks, COQUIC_STEWARD_CACHE_PATH: cache, FAKE_PROCESS_LOG: processLog, FAKE_CURL_LOG: curlLog, FAKE_NODE_SQLITE: "1" };
    const first = await run("bash", [runDemo], env);
    assert.equal(first.code, 0, first.output);
    const processes = await readFile(processLog, "utf8");
    assert.equal(processes.split("\n").filter((line) => line.startsWith("next:")).length, 1, "exactly one Next process owns the importer");
    assert.match(processes, new RegExp(`next:${tasks.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:${cache.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.match(await readFile(curlLog, "utf8"), /\/api\/steward\/status/);

    const repeated = await run("bash", [runDemo], env);
    assert.equal(repeated.code, 0, repeated.output);
    assert.equal((await readFile(processLog, "utf8")).split("\n").filter((line) => line.startsWith("next:")).length, 2, "repeat launch still creates one Next owner per invocation");
    assert.equal((await readFile(join(app, "server.js"), "utf8")).trim(), "// fake Next entry");

    const unsafe = await run("bash", [runDemo], { ...env, COQUIC_STEWARD_TASKS_ROOT: join(release, "tasks") });
    assert.notEqual(unsafe.code, 0); assert.match(unsafe.output, /outside the release/);
    const noSqlite = await run("bash", [runDemo], { ...env, FAKE_NODE_SQLITE: "0" });
    assert.notEqual(noSqlite.code, 0); assert.match(noSqlite.output, /node:sqlite/);

    const config = getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: tasks, COQUIC_STEWARD_CACHE_PATH: cache });
    assert.equal(config.tasksRoot, tasks); assert.equal(config.cachePath, cache);
    const remote = await run("bash", [deployRemote], { ...process.env, COQUIC_DEPLOY_TEST_MODE: "1", COQUIC_DEPLOY_TEST_ROOT: deployTestRoot, COQUIC_DEPLOY_TEST_PROBE: probe });
    assert.equal(remote.code, 0, remote.output); assert.match(remote.output, /first\/repeat\/repair\/rollback completed/);
    assert.equal((await readFile(join(deployTestRoot, "opt", "coquic-demo", "steward", "tasks", "publisher.marker"), "utf8")).trim(), "raw-preserved");
    assert.equal((await readFile(join(deployTestRoot, "opt", "coquic-demo", "steward", "cache", "index.marker"), "utf8")).trim(), "cache-preserved");
    assert.equal(await readFile(join(deployTestRoot, "opt", "coquic-demo", "current", "app", "version"), "utf8"), "repaired\n");
    const deploySource = await readFile(deployRemote, "utf8");
    assert.match(deploySource, /ensure_steward_state_dir \/opt\/coquic-demo\/steward\/tasks/);
    assert.match(deploySource, /same-release repair mode/);
    assert.match(deploySource, /rollback/);
    assert.doesNotMatch(deploySource, /rm\s+-rf\s+["']?\/opt\/coquic-demo\/steward/);
    process.stdout.write("Offline deployment process and persistence suite passed\n");
  } finally { await rm(root, { recursive: true, force: true }); }
})();
