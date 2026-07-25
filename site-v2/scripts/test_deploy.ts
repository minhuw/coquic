import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, readlink, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getArchiveConfig } from "../lib/steward-archive/config";

async function executable(path: string, source: string) { await writeFile(path, source); await chmod(path, 0o755); }

async function run(command: string, args: string[], env: NodeJS.ProcessEnv, timeoutMs = 30_000) {
  const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (chunk) => { output += String(chunk); });
  child.stderr.on("data", (chunk) => { output += String(chunk); });
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const code = await Promise.race([
    new Promise<number>((resolveExit) => child.once("exit", (value) => resolveExit(value ?? 1))),
    new Promise<number>((resolveTimeout) => { timeout = setTimeout(() => { child.kill("SIGKILL"); resolveTimeout(124); }, timeoutMs); }),
  ]);
  if (timeout) clearTimeout(timeout);
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
    const controlLoop = join(root, "persistent", "steward", "control-loop");
    const cache = join(root, "persistent", "steward", "cache", "site-v2.sqlite");
    const fakeBin = join(root, "bin");
    const processLog = join(root, "process.log");
    const curlLog = join(root, "curl.log");
    await mkdir(app, { recursive: true }); await mkdir(tasks, { recursive: true }); await mkdir(controlLoop, { recursive: true }); await mkdir(dirname(cache), { recursive: true }); await mkdir(fakeBin);
    await writeFile(join(app, "server.js"), "// fake Next entry\n");
    await executable(join(release, "h3-server"), "#!/usr/bin/env bash\necho h3 >>\"${FAKE_PROCESS_LOG}\"\nsleep 0.2\n");
    await executable(join(fakeBin, "node"), `#!/usr/bin/env bash
if [[ "\${1:-}" == "-e" ]]; then [[ "\${FAKE_NODE_SQLITE:-1}" == "1" ]]; exit; fi
if [[ "\${1:-}" == "-p" ]]; then printf '%s\\n' 24; exit; fi
if [[ "\${1:-}" == "--version" ]]; then printf '%s\\n' v24.0.0; exit; fi
echo "next:\${COQUIC_STEWARD_TASKS_ROOT}:\${COQUIC_STEWARD_CONTROL_LOOP_ROOT}:\${COQUIC_STEWARD_CACHE_PATH}" >>"\${FAKE_PROCESS_LOG}"
trap 'exit 0' TERM INT
while :; do sleep 1; done
`);
    await executable(join(fakeBin, "curl"), `#!/usr/bin/env bash
url="\${!#}"
echo "\${url}" >>"\${FAKE_CURL_LOG}"
if [[ "\${url}" == */api/steward/status ]]; then printf '%s\\n' '{"data":{"state":"indexing"}}'; else printf '%s\\n' ready; fi
`);
    const env = { ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, COQUIC_DEMO_RELEASE_DIR: release, COQUIC_DEMO_QA_ENABLED: "false", COQUIC_DEMO_NEXT_PORT: "39111", COQUIC_DEMO_PORT: "39443", COQUIC_DEMO_BOOTSTRAP_PORT: "39443", COQUIC_STEWARD_TASKS_ROOT: tasks, COQUIC_STEWARD_CONTROL_LOOP_ROOT: controlLoop, COQUIC_STEWARD_CACHE_PATH: cache, FAKE_PROCESS_LOG: processLog, FAKE_CURL_LOG: curlLog, FAKE_NODE_SQLITE: "1" };
    const first = await run("bash", [runDemo], env);
    assert.equal(first.code, 0, first.output);
    const processes = await readFile(processLog, "utf8");
    assert.equal(processes.split("\n").filter((line) => line.startsWith("next:")).length, 1, "exactly one Next process owns the importer");
    assert.match(processes, new RegExp(`next:${tasks.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:${controlLoop.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:${cache.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.match(await readFile(curlLog, "utf8"), /\/api\/steward\/status/);
    const repeated = await run("bash", [runDemo], env);
    assert.equal(repeated.code, 0, repeated.output);
    assert.equal((await readFile(processLog, "utf8")).split("\n").filter((line) => line.startsWith("next:")).length, 2);
    const unsafe = await run("bash", [runDemo], { ...env, COQUIC_STEWARD_TASKS_ROOT: join(release, "tasks") });
    assert.notEqual(unsafe.code, 0); assert.match(unsafe.output, /outside the release/);
    const noSqlite = await run("bash", [runDemo], { ...env, FAKE_NODE_SQLITE: "0" });
    assert.notEqual(noSqlite.code, 0); assert.match(noSqlite.output, /node:sqlite/);
    const config = getArchiveConfig({ NODE_ENV: "test", COQUIC_STEWARD_TASKS_ROOT: tasks, COQUIC_STEWARD_CONTROL_LOOP_ROOT: controlLoop, COQUIC_STEWARD_CACHE_PATH: cache });
    assert.equal(config.tasksRoot, tasks); assert.equal(config.controlLoopRoot, controlLoop); assert.equal(config.cachePath, cache);

    const remoteRoot = join(root, "remote");
    const remoteState = join(remoteRoot, ".fake-systemd");
    const sshKey = join(root, "deploy.key");
    const binary = join(root, "coquic-server");
    const deployApp = join(root, "deploy-app");
    const nixOut = join(root, "curl-http3");
    await mkdir(join(remoteRoot, "etc", "systemd", "system"), { recursive: true });
    await mkdir(join(remoteRoot, "tmp"), { recursive: true });
    await mkdir(deployApp); await mkdir(join(nixOut, "bin"), { recursive: true });
    await writeFile(join(remoteRoot, ".coquic-deploy-test-root"), "owned\n");
    await writeFile(sshKey, "test key\n");
    await executable(binary, "#!/usr/bin/env bash\nexit 0\n");
    await writeFile(join(deployApp, "server.js"), "// deployment fixture\n");
    await executable(join(fakeBin, "sudo"), "#!/usr/bin/env bash\nexec \"$@\"\n");
    await executable(join(fakeBin, "systemctl"), `#!/usr/bin/env bash
set -euo pipefail
mkdir -p "\${FAKE_SYSTEMD_STATE}"
case "\${1:-}" in
  is-active) [[ -f "\${FAKE_SYSTEMD_STATE}/active" ]] ;;
  is-enabled) [[ -f "\${FAKE_SYSTEMD_STATE}/enabled" ]] ;;
  start|restart) touch "\${FAKE_SYSTEMD_STATE}/active" ;;
  stop) rm -f "\${FAKE_SYSTEMD_STATE}/active" ;;
  enable) touch "\${FAKE_SYSTEMD_STATE}/enabled" ;;
  disable) rm -f "\${FAKE_SYSTEMD_STATE}/enabled" ;;
  daemon-reload) : ;;
  *) exit 1 ;;
esac
`);
    await executable(join(fakeBin, "ssh"), `#!/usr/bin/env bash
set -euo pipefail
while [[ $# -gt 0 && "$1" != *@* ]]; do shift; done
[[ $# -gt 0 ]] || exit 2
shift
[[ $# -gt 0 ]] || exit 0
if [[ "$1" == "bash" && "\${2:-}" == "-s" ]]; then exec bash "\${@:2}"; fi
exec bash -c "$*"
`);
    await executable(join(fakeBin, "scp"), `#!/usr/bin/env bash
set -euo pipefail
source_path="\${@: -2:1}"
destination="\${@: -1}"
target="\${destination#*:}"
mkdir -p "$(dirname "\${target}")"
cp "\${source_path}" "\${target}"
`);
    await executable(join(fakeBin, "nix"), "#!/usr/bin/env bash\nprintf '%s\\n' \"${FAKE_NIX_OUT}\"\n");
    await executable(join(nixOut, "bin", "curl-http3"), `#!/usr/bin/env bash
if [[ "\${FAKE_VERIFY_FAILURE:-0}" == "1" ]]; then exit 7; fi
if [[ " $* " == *" -I "* ]]; then printf 'HTTP/1.1 200 OK\\r\\nalt-svc: h3=\":443\"; ma=86400\\r\\n';
elif [[ " $* " == *" -w "* ]]; then printf 3;
else printf '%s\\n' coquic-wasm-demo-v1; fi
`);
    const deployEnv = { ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, COQUIC_DEMO_CERT_CHAIN_PEM: "fixture cert", COQUIC_DEMO_PRIVATE_KEY_PEM: "fixture key", COQUIC_DEMO_REMOTE_SSH_KEY_PATH: sshKey, COQUIC_DEPLOY_OFFLINE_ROOT: remoteRoot, COQUIC_DEMO_VERIFICATION_ATTEMPTS: "1", COQUIC_DEMO_VERIFICATION_SLEEP_SECONDS: "0", COQUIC_DEMO_VERIFY_WASM: "false", FAKE_SYSTEMD_STATE: remoteState, FAKE_NIX_OUT: nixOut, FAKE_PROCESS_LOG: processLog, FAKE_CURL_LOG: curlLog, GITHUB_SHA: "111111111111aaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
    const deployed = await run("bash", [deployRemote, binary, deployApp], deployEnv);
    assert.equal(deployed.code, 0, deployed.output);
    const current = join(remoteRoot, "opt", "coquic-demo", "current");
    const firstTarget = await readlink(current);
    assert.match(firstTarget, /111111111111$/);
    const stewardRoot = join(remoteRoot, "opt", "coquic-demo", "steward");
    await writeFile(join(stewardRoot, "tasks", "publisher.marker"), "raw-preserved\n");
    await writeFile(join(stewardRoot, "cache", "index.marker"), "cache-preserved\n");
    await writeFile(join(stewardRoot, "control-loop", "publisher.marker"), "raw-preserved\n");
    const repaired = await run("bash", [deployRemote, binary, deployApp], deployEnv);
    assert.equal(repaired.code, 0, repaired.output);
    assert.equal(await readlink(current), firstTarget, "same-release repair preserves the release identity");
    const rolledBack = await run("bash", [deployRemote, binary, deployApp], { ...deployEnv, GITHUB_SHA: "222222222222bbbbbbbbbbbbbbbbbbbbbbbbbbbb", FAKE_VERIFY_FAILURE: "1" });
    assert.notEqual(rolledBack.code, 0, rolledBack.output);
    assert.equal(await readlink(current), firstTarget, "failed verification restores the previous release");
    assert.equal((await readFile(join(stewardRoot, "tasks", "publisher.marker"), "utf8")).trim(), "raw-preserved");
    assert.equal((await readFile(join(stewardRoot, "cache", "index.marker"), "utf8")).trim(), "cache-preserved");
    assert.equal((await readFile(join(stewardRoot, "control-loop", "publisher.marker"), "utf8")).trim(), "raw-preserved");
    assert.equal((await readFile(join(remoteState, "active"), "utf8")).length, 0);
    const deploySource = await readFile(deployRemote, "utf8");
    assert.doesNotMatch(deploySource, /COQUIC_DEPLOY_TEST_MODE/);
    assert.match(deploySource, /same-release repair mode/);
    assert.match(deploySource, /rollback/);
    assert.doesNotMatch(deploySource, /rm\s+-rf\s+["']?\/opt\/coquic-demo\/steward/);
    process.stdout.write("Offline deployment normal-path, repair, rollback, and persistence suite passed\n");
  } finally { await rm(root, { recursive: true, force: true }); }
})();
