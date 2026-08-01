import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, readlink, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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

async function snapshotPath(path: string) {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) return { kind: "symlink", mode: info.mode & 0o777, target: await readlink(path) };
    if (info.isDirectory()) return { kind: "directory", mode: info.mode & 0o777 };
    return { kind: "file", mode: info.mode & 0o777, content: (await readFile(path)).toString("base64") };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { kind: "missing" };
    throw error;
  }
}

async function snapshotPaths(paths: string[]) {
  return Promise.all(paths.map(async (path) => [path, await snapshotPath(path)] as const));
}

void (async () => {
  const siteRoot = fileURLToPath(new URL("..", import.meta.url));
  const repoRoot = resolve(siteRoot, "..");
  const runDemo = join(repoRoot, "site", "deploy", "run-demo.sh");
  const deployRemote = join(repoRoot, "site", "deploy", "deploy-remote.sh");
  const installCloudConfig = join(repoRoot, "site", "deploy", "install-cloud-config.sh");
  const root = await mkdtemp(join(tmpdir(), "coquic-deploy-"));
  try {
    const release = join(root, "release");
    const app = join(release, "app");
    const fakeBin = join(root, "bin");
    const processLog = join(root, "process.log");
    const curlLog = join(root, "curl.log");
    const appEnv = join(root, "app.env");
    const cloudAccount = "A".repeat(32);
    const cloudDatabase = "12345678-1234-4abc-8def-1234567890ab";
    const cloudSecret = ["handoff", "read", "token"].join("-");
    const cloudBaseUrl = "https://objects.example.test/public";
    const sshLog = join(root, "ssh.log");
    const systemdLog = join(root, "systemd.log");
    await mkdir(app, { recursive: true }); await mkdir(fakeBin);
    await writeFile(join(app, "server.js"), "// fake Next entry\n");
    await writeFile(appEnv, [
      `export CLOUDFLARE_ACCOUNT_ID=${cloudAccount}`,
      `export COQUIC_STEWARD_D1_DATABASE_ID=${cloudDatabase}`,
      `export COQUIC_STEWARD_D1_READ_TOKEN=${cloudSecret}`,
      `export COQUIC_STEWARD_PUBLIC_R2_BASE_URL=${cloudBaseUrl}`,
      "export COQUIC_DEMO_QA_ENABLED=false",
      "",
    ].join("\n"));
    await chmod(appEnv, 0o600);
    await executable(join(release, "h3-server"), "#!/usr/bin/env bash\necho h3 >>\"${FAKE_PROCESS_LOG}\"\nsleep 0.2\n");
    await executable(join(fakeBin, "node"), `#!/usr/bin/env bash
if [[ "\${1:-}" == "-e" ]]; then
  exec "\${FAKE_REAL_NODE}" "$@"
fi
if [[ "\${1:-}" == "-p" ]]; then printf '%s\\n' 24; exit; fi
if [[ "\${1:-}" == "--version" ]]; then printf '%s\\n' v24.0.0; exit; fi
cloud_token_state=missing
if [[ -n "\${COQUIC_STEWARD_D1_READ_TOKEN:-}" ]]; then cloud_token_state=set; fi
printf 'next:%s:%s:%s:%s\\n' "\${CLOUDFLARE_ACCOUNT_ID:-}" "\${COQUIC_STEWARD_D1_DATABASE_ID:-}" "\${COQUIC_STEWARD_PUBLIC_R2_BASE_URL:-}" "\${cloud_token_state}" >>"\${FAKE_PROCESS_LOG}"
trap 'exit 0' TERM INT
while :; do sleep 1; done
`);
    await executable(join(fakeBin, "curl"), `#!/usr/bin/env bash
url="\${!#}"
echo "\${url}" >>"\${FAKE_CURL_LOG}"
if [[ "\${url}" == */api/steward/status ]]; then
  if [[ -n "\${FAKE_STEWARD_STATUS:-}" ]]; then printf '%s\\n' "\${FAKE_STEWARD_STATUS}";
  else printf '%s\\n' '{"schemaVersion":"3.0","generatedAt":"2026-07-31T00:00:00Z","data":{"state":"empty","taskCount":0,"latestPublicationAt":null}}'; fi
else printf '%s\\n' ready; fi
`);
    const env = { ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, COQUIC_DEMO_RELEASE_DIR: release, COQUIC_DEMO_APP_ENV_FILE: appEnv, COQUIC_DEMO_NEXT_PORT: "39111", COQUIC_DEMO_PORT: "39443", COQUIC_DEMO_BOOTSTRAP_PORT: "39443", FAKE_PROCESS_LOG: processLog, FAKE_CURL_LOG: curlLog, FAKE_REAL_NODE: process.execPath };
    const first = await run("bash", [runDemo], env);
    assert.equal(first.code, 0, first.output);
    const processes = await readFile(processLog, "utf8");
    assert.equal(processes.split("\n").filter((line) => line.startsWith("next:")).length, 1, "exactly one Next process receives cloud configuration");
    assert.match(processes, new RegExp(`next:${cloudAccount}:${cloudDatabase}:${cloudBaseUrl}:set`));
    assert.match(await readFile(curlLog, "utf8"), /\/api\/steward\/status/);
    const repeated = await run("bash", [runDemo], env);
    assert.equal(repeated.code, 0, repeated.output);
    assert.equal((await readFile(processLog, "utf8")).split("\n").filter((line) => line.startsWith("next:")).length, 2);
    const incompatibleStatus = JSON.stringify({ schemaVersion: "3.0", generatedAt: "2026-07-31T00:00:00Z", data: { state: "unavailable", taskCount: 0, latestPublicationAt: null } });
    const incompatible = await run("bash", [runDemo], { ...env, FAKE_STEWARD_STATUS: incompatibleStatus });
    assert.notEqual(incompatible.code, 0); assert.match(incompatible.output, /status did not become available/);
    const missingCloudEnv = join(root, "missing-cloud.env");
    await writeFile(missingCloudEnv, [
      `export CLOUDFLARE_ACCOUNT_ID=${cloudAccount}`,
      `export COQUIC_STEWARD_D1_DATABASE_ID=${cloudDatabase}`,
      `export COQUIC_STEWARD_D1_READ_TOKEN=${cloudSecret}`,
      "export COQUIC_DEMO_QA_ENABLED=false",
      "",
    ].join("\n"));
    await chmod(missingCloudEnv, 0o600);
    const missingCloud = await run("bash", [runDemo], { ...env, COQUIC_DEMO_APP_ENV_FILE: missingCloudEnv });
    assert.notEqual(missingCloud.code, 0); assert.match(missingCloud.output, /cloud configuration/);
    const insecureCloudEnv = join(root, "insecure-cloud.env");
    await writeFile(insecureCloudEnv, await readFile(appEnv));
    await chmod(insecureCloudEnv, 0o644);
    const insecureCloud = await run("bash", [runDemo], { ...env, COQUIC_DEMO_APP_ENV_FILE: insecureCloudEnv });
    assert.notEqual(insecureCloud.code, 0); assert.match(insecureCloud.output, /mode 0600/);

    const remoteRoot = join(root, "remote");
    const remoteState = join(remoteRoot, ".fake-systemd");
    const stewardRoot = join(remoteRoot, "opt", "coquic-demo", "steward");
    const sshKey = join(root, "deploy.key");
    const binary = join(root, "coquic-server");
    const deployApp = join(root, "deploy-app");
    const nixOut = join(root, "curl-http3");
    const cloudLines = [
      `CLOUDFLARE_ACCOUNT_ID=${cloudAccount}`,
      `COQUIC_STEWARD_D1_DATABASE_ID=${cloudDatabase}`,
      `COQUIC_STEWARD_D1_READ_TOKEN=${cloudSecret}`,
      `COQUIC_STEWARD_PUBLIC_R2_BASE_URL=${cloudBaseUrl}`,
    ];
    let cloudInputNumber = 0;
    async function writeCloudInput(lines: string[], mode = 0o600) {
      const path = join(root, `cloud-input-${cloudInputNumber++}.env`);
      await writeFile(path, `${lines.join("\n")}\n`);
      await chmod(path, mode);
      return path;
    }
    await mkdir(join(remoteRoot, "etc", "systemd", "system"), { recursive: true });
    await mkdir(join(remoteRoot, "tmp"), { recursive: true });
    await mkdir(join(stewardRoot, "tasks"), { recursive: true });
    await mkdir(join(stewardRoot, "cache"), { recursive: true });
    await mkdir(join(stewardRoot, "control-loop"), { recursive: true });
    await writeFile(join(stewardRoot, "tasks", "publisher.marker"), "raw-preserved\n");
    await writeFile(join(stewardRoot, "cache", "index.marker"), "cache-preserved\n");
    await writeFile(join(stewardRoot, "control-loop", "publisher.marker"), "raw-preserved\n");
    await mkdir(deployApp); await mkdir(join(nixOut, "bin"), { recursive: true });
    await writeFile(join(remoteRoot, ".coquic-deploy-test-root"), "owned\n");
    await writeFile(sshKey, "test key\n");
    await executable(binary, "#!/usr/bin/env bash\nexit 0\n");
    await writeFile(join(deployApp, "server.js"), "// deployment fixture\n");
    await executable(join(fakeBin, "sudo"), "#!/usr/bin/env bash\nif [[ \"${1:-}\" == chown ]]; then exit 0; fi\nexec \"$@\"\n");
    await executable(join(fakeBin, "mv"), `#!/usr/bin/env bash
if [[ "\${FAKE_CLOUD_CONFIG_FAIL_MV:-0}" == "1" && " $* " == *"/app.env.tmp."* ]]; then exit 19; fi
exec /bin/mv "$@"
`);
    await executable(join(fakeBin, "systemctl"), `#!/usr/bin/env bash
set -euo pipefail
mkdir -p "\${FAKE_SYSTEMD_STATE}"
if [[ -n "\${FAKE_SYSTEMD_LOG:-}" ]]; then printf '%s\\n' "$*" >>"\${FAKE_SYSTEMD_LOG}"; fi
case "\${1:-}" in
  is-active) [[ -f "\${FAKE_SYSTEMD_STATE}/active" ]] ;;
  is-enabled) [[ -f "\${FAKE_SYSTEMD_STATE}/enabled" ]] ;;
  start) touch "\${FAKE_SYSTEMD_STATE}/active" ;;
  restart) if [[ "\${FAKE_SYSTEMD_FAIL_RESTART:-0}" == "1" ]]; then rm -f "\${FAKE_SYSTEMD_STATE}/active"; exit 17; fi; touch "\${FAKE_SYSTEMD_STATE}/active" ;;
  stop) rm -f "\${FAKE_SYSTEMD_STATE}/active" ;;
  enable) touch "\${FAKE_SYSTEMD_STATE}/enabled" ;;
  disable) rm -f "\${FAKE_SYSTEMD_STATE}/enabled" ;;
  daemon-reload) : ;;
  *) exit 1 ;;
esac
`);
    await executable(join(fakeBin, "ssh"), `#!/usr/bin/env bash
set -euo pipefail
if [[ -n "\${FAKE_SSH_LOG:-}" ]]; then printf '%q ' "$@" >>"\${FAKE_SSH_LOG}"; printf '\\n' >>"\${FAKE_SSH_LOG}"; fi
if [[ "\${FAKE_SSH_REQUIRE_HOST_KEY:-0}" == "1" ]]; then
  args="$*"
  [[ "\${args}" == *"StrictHostKeyChecking=yes"* && "\${args}" == *"UserKnownHostsFile="* ]] || exit 31
fi
while [[ $# -gt 0 && "$1" != *@* ]]; do shift; done
[[ $# -gt 0 ]] || exit 2
shift
[[ $# -gt 0 ]] || exit 0
if [[ "$1" == "bash" && "\${2:-}" == "-s" ]]; then exec bash "\${@:2}"; fi
exec bash -c "$*"
`);
    await executable(join(fakeBin, "scp"), `#!/usr/bin/env bash
set -euo pipefail
if [[ -n "\${FAKE_SSH_LOG:-}" ]]; then printf '%q ' "$@" >>"\${FAKE_SSH_LOG}"; printf '\\n' >>"\${FAKE_SSH_LOG}"; fi
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
    const deployEnv = { ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, COQUIC_DEMO_CERT_CHAIN_PEM: "fixture cert", COQUIC_DEMO_PRIVATE_KEY_PEM: "fixture key", COQUIC_DEMO_REMOTE_SSH_KEY_PATH: sshKey, COQUIC_DEPLOY_OFFLINE_ROOT: remoteRoot, COQUIC_DEMO_QA_ENABLED: "false", COQUIC_V2_PREVIEW_PASSWORD: "preview-fixture", COQUIC_DEMO_VERIFICATION_ATTEMPTS: "1", COQUIC_DEMO_VERIFICATION_SLEEP_SECONDS: "0", COQUIC_DEMO_VERIFY_WASM: "false", FAKE_SYSTEMD_STATE: remoteState, FAKE_SYSTEMD_LOG: systemdLog, FAKE_SSH_LOG: sshLog, FAKE_NIX_OUT: nixOut, FAKE_PROCESS_LOG: processLog, FAKE_CURL_LOG: curlLog, GITHUB_SHA: "111111111111aaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
    const releasesRoot = join(remoteRoot, "opt", "coquic-demo", "releases");
    const current = join(remoteRoot, "opt", "coquic-demo", "current");
    const retainedRelease = join(releasesRoot, "retained-sentinel");
    const obsoleteRelease = join(releasesRoot, "obsolete-sentinel");
    const remoteConfigRoot = join(remoteRoot, "etc", "coquic-demo");
    const appEnvPath = join(remoteConfigRoot, "app.env");
    const servicePath = join(remoteRoot, "etc", "systemd", "system", "coquic-demo.service");
    await mkdir(retainedRelease, { recursive: true });
    await mkdir(obsoleteRelease, { recursive: true });
    await writeFile(join(retainedRelease, "marker"), "retained\n");
    await writeFile(join(obsoleteRelease, "marker"), "obsolete\n");
    await symlink(retainedRelease, current);
    await writeFile(servicePath, "service-preserved\n");
    await mkdir(join(remoteConfigRoot, "tls"), { recursive: true });
    await writeFile(join(remoteConfigRoot, "tls", "fullchain.pem"), "fullchain-preserved\n");
    await writeFile(join(remoteConfigRoot, "tls", "privkey.pem"), "privkey-preserved\n");
    await mkdir(remoteState, { recursive: true });
    await writeFile(join(remoteState, "active"), "active\n");
    await writeFile(join(remoteState, "enabled"), "enabled\n");
    const mutationPaths = [
      join(retainedRelease, "marker"),
      join(obsoleteRelease, "marker"),
      current,
      servicePath,
      join(remoteConfigRoot, "tls", "fullchain.pem"),
      join(remoteConfigRoot, "tls", "privkey.pem"),
      appEnvPath,
      join(remoteState, "active"),
      join(remoteState, "enabled"),
      join(stewardRoot, "tasks", "publisher.marker"),
      join(stewardRoot, "cache", "index.marker"),
      join(stewardRoot, "control-loop", "publisher.marker"),
    ];
    const beforeMissingHostConfig = await snapshotPaths(mutationPaths);
    const missingHostConfig = await run("bash", [deployRemote, binary, deployApp], { ...deployEnv, COQUIC_DEMO_RELEASE_RETENTION: "1" });
    assert.notEqual(missingHostConfig.code, 0, "deployment unexpectedly accepted missing host app.env");
    assert.match(missingHostConfig.output, /protected cloud app\.env/);
    assert.ok(!new RegExp(cloudSecret).test(missingHostConfig.output), "missing host config rejection is redacted");
    assert.deepEqual(await snapshotPaths(mutationPaths), beforeMissingHostConfig, "missing host config mutates deployment state");
    await rm(join(remoteState, "active"), { force: true });

    const cloudEnv = { ...deployEnv, FAKE_SSH_REQUIRE_HOST_KEY: "1" };
    const cloudInput = await writeCloudInput(cloudLines);
    const installed = await run("bash", [installCloudConfig, cloudInput], cloudEnv);
    assert.equal(installed.code, 0, installed.output);
    assert.ok(!new RegExp(cloudSecret).test(installed.output), "successful handoff output is redacted");
    const handoffAppEnv = await readFile(appEnvPath, "utf8");
    assert.ok(handoffAppEnv.includes(`export CLOUDFLARE_ACCOUNT_ID=${cloudAccount.toLowerCase()}`));
    assert.ok(handoffAppEnv.includes(`export COQUIC_STEWARD_D1_DATABASE_ID=${cloudDatabase}`));
    assert.ok(handoffAppEnv.includes(`export COQUIC_STEWARD_D1_READ_TOKEN=${cloudSecret}`));
    assert.ok(handoffAppEnv.includes(`export COQUIC_STEWARD_PUBLIC_R2_BASE_URL=${cloudBaseUrl}/`));
    assert.equal((await stat(appEnvPath)).mode & 0o777, 0o600);

    const deployed = await run("bash", [deployRemote, binary, deployApp], deployEnv);
    assert.equal(deployed.code, 0, deployed.output);
    const firstTarget = await readlink(current);
    assert.match(firstTarget, /111111111111$/);
    const installedAppEnv = await readFile(appEnvPath, "utf8");
    assert.ok(installedAppEnv.includes(`export CLOUDFLARE_ACCOUNT_ID=${cloudAccount.toLowerCase()}`));
    assert.ok(installedAppEnv.includes(`export COQUIC_STEWARD_D1_DATABASE_ID=${cloudDatabase}`));
    assert.ok(installedAppEnv.includes(`export COQUIC_STEWARD_D1_READ_TOKEN=${cloudSecret}`));
    assert.ok(installedAppEnv.includes(`export COQUIC_STEWARD_PUBLIC_R2_BASE_URL=${cloudBaseUrl}/`));
    assert.match(installedAppEnv, /export COQUIC_DEMO_QA_ENABLED=false/);
    assert.match(installedAppEnv, /export COQUIC_V2_PREVIEW_PASSWORD=preview-fixture/);
    assert.equal((await stat(appEnvPath)).mode & 0o777, 0o600);
    const restartCount = () => readFile(systemdLog, "utf8").then((value) => value.split("\n").filter((line) => line.startsWith("restart ")).length);
    const restartCountAfterInstall = await restartCount();
    assert.equal(restartCountAfterInstall, 0);

    const unchanged = await run("bash", [installCloudConfig, cloudInput], cloudEnv);
    assert.equal(unchanged.code, 0, unchanged.output);
    assert.ok(!new RegExp(cloudSecret).test(unchanged.output), "unchanged handoff output is redacted");
    assert.equal(await restartCount(), restartCountAfterInstall, "unchanged cloud values do not restart Site");
    await chmod(appEnvPath, 0o644);
    const modeRepair = await run("bash", [installCloudConfig, cloudInput], cloudEnv);
    assert.equal(modeRepair.code, 0, modeRepair.output);
    assert.equal((await stat(appEnvPath)).mode & 0o777, 0o600);
    assert.equal(await restartCount(), restartCountAfterInstall, "mode repair does not restart Site");

    const validHostAppEnv = await readFile(appEnvPath);
    const validCloudHostLines = [
      `export CLOUDFLARE_ACCOUNT_ID=${cloudAccount.toLowerCase()}`,
      `export COQUIC_STEWARD_D1_DATABASE_ID=${cloudDatabase}`,
      `export COQUIC_STEWARD_D1_READ_TOKEN=${cloudSecret}`,
      `export COQUIC_STEWARD_PUBLIC_R2_BASE_URL=${cloudBaseUrl}/`,
    ];
    const hostSymlinkTarget = join(root, "host-app.env.target");
    const hostMutationPaths = [...mutationPaths, hostSymlinkTarget];
    async function restoreHostAppEnv() {
      await rm(appEnvPath, { recursive: true, force: true });
      await rm(hostSymlinkTarget, { recursive: true, force: true });
      await writeFile(appEnvPath, validHostAppEnv);
      await chmod(appEnvPath, 0o600);
    }
    const invalidHostVariants: Array<[string, () => Promise<void>]> = [
      ["missing", async () => { await rm(appEnvPath, { recursive: true, force: true }); }],
      ["incomplete", async () => { await writeFile(appEnvPath, `${validCloudHostLines.slice(0, 3).join("\n")}\n`); }],
      ["malformed", async () => { await writeFile(appEnvPath, `${["export CLOUDFLARE_ACCOUNT_ID=not-an-account", ...validCloudHostLines.slice(1)].join("\n")}\n`); }],
      ["duplicate", async () => { await writeFile(appEnvPath, `${[...validCloudHostLines, validCloudHostLines[0]].join("\n")}\n`); }],
      ["insecure-mode", async () => { await writeFile(appEnvPath, `${validCloudHostLines.join("\n")}\n`); await chmod(appEnvPath, 0o644); }],
      ["symlink", async () => { await writeFile(hostSymlinkTarget, `${validCloudHostLines.join("\n")}\n`); await chmod(hostSymlinkTarget, 0o600); await rm(appEnvPath, { recursive: true, force: true }); await symlink(hostSymlinkTarget, appEnvPath); }],
      ["non-regular", async () => { await rm(appEnvPath, { recursive: true, force: true }); await mkdir(appEnvPath); }],
    ];
    for (const [label, setupInvalidHostAppEnv] of invalidHostVariants) {
      await restoreHostAppEnv();
      await setupInvalidHostAppEnv();
      const beforeInvalidHostConfig = await snapshotPaths(hostMutationPaths);
      const invalidHostConfig = await run("bash", [deployRemote, binary, deployApp], { ...deployEnv, COQUIC_DEMO_RELEASE_RETENTION: "1" });
      assert.notEqual(invalidHostConfig.code, 0, `${label} host app.env unexpectedly accepted`);
      assert.match(invalidHostConfig.output, /protected cloud app\.env/, `${label} rejection is not a protected-config failure`);
      assert.ok(!new RegExp(cloudSecret).test(invalidHostConfig.output), `${label} rejection is redacted`);
      assert.deepEqual(await snapshotPaths(hostMutationPaths), beforeInvalidHostConfig, `${label} host app.env mutates deployment state`);
    }
    await restoreHostAppEnv();

    const invalidInputs: Array<[string, string[]]> = [
      ["missing", cloudLines.slice(0, 3)],
      ["extra", [...cloudLines, "NEXT_PUBLIC_STEWARD_D1_READ_TOKEN=client"]],
      ["duplicate", [...cloudLines, cloudLines[0]]],
      ["malformed", ["CLOUDFLARE_ACCOUNT_ID=not-an-account", ...cloudLines.slice(1)]],
      ["insecure-url", cloudLines.map((line) => line.replace(cloudBaseUrl, "http://objects.example.test/public"))],
      ["out-of-range-port", cloudLines.map((line) => line.replace(cloudBaseUrl, "https://objects.example.test:99999/public"))],
      ["private-url", cloudLines.map((line) => line.replace(cloudBaseUrl, "https://objects.example.test/public/../private"))],
      ["writer", [...cloudLines.slice(0, 2), "COQUIC_STEWARD_D1_WRITE_TOKEN=writer", ...cloudLines.slice(2)]],
      ["r2-credential", [...cloudLines.slice(0, 2), "AWS_SECRET_ACCESS_KEY=credential", ...cloudLines.slice(2)]],
      ["private-locator", [...cloudLines.slice(0, 2), "COQUIC_STEWARD_PRIVATE_R2_BUCKET=private", ...cloudLines.slice(2)]],
    ];
    assert.throws(() => new URL("https://objects.example.test:99999/public"), /Invalid URL/);
    const sshLogBeforeInvalid = await readFile(sshLog, "utf8");
    for (const [label, lines] of invalidInputs) {
      const invalidInput = await writeCloudInput(lines);
      const invalid = await run("bash", [installCloudConfig, invalidInput], cloudEnv);
      assert.notEqual(invalid.code, 0, `${label} input unexpectedly succeeded`);
      assert.ok(!new RegExp(cloudSecret).test(invalid.output), `${label} rejection is redacted`);
      if (label === "out-of-range-port") assert.equal(await readFile(sshLog, "utf8"), sshLogBeforeInvalid, "malformed port is rejected before SSH");
    }
    const wrongModeInput = await writeCloudInput(cloudLines, 0o644);
    const wrongMode = await run("bash", [installCloudConfig, wrongModeInput], cloudEnv);
    assert.notEqual(wrongMode.code, 0);

    const writeFailureSecret = `${cloudSecret}-write`;
    const writeFailureInput = await writeCloudInput(cloudLines.map((line) => line.replace(cloudSecret, writeFailureSecret)));
    const beforeWriteFailure = await readFile(appEnvPath);
    const writeFailure = await run("bash", [installCloudConfig, writeFailureInput], { ...cloudEnv, FAKE_CLOUD_CONFIG_FAIL_MV: "1" });
    assert.notEqual(writeFailure.code, 0, writeFailure.output);
    assert.ok(!new RegExp(writeFailureSecret).test(writeFailure.output), "write failure output is redacted");
    assert.ok((await readFile(appEnvPath)).equals(beforeWriteFailure), "remote write failure restores app.env bytes");
    assert.equal((await stat(appEnvPath)).mode & 0o777, 0o600);
    assert.equal((await stat(join(remoteState, "active"))).isFile(), true, "remote write failure restores active service");

    const restartFailureSecret = `${cloudSecret}-restart`;
    const restartFailureInput = await writeCloudInput(cloudLines.map((line) => line.replace(cloudSecret, restartFailureSecret)));
    const beforeRestartFailure = await readFile(appEnvPath);
    const restartFailure = await run("bash", [installCloudConfig, restartFailureInput], { ...cloudEnv, FAKE_SYSTEMD_FAIL_RESTART: "1" });
    assert.notEqual(restartFailure.code, 0, restartFailure.output);
    assert.ok(!new RegExp(restartFailureSecret).test(restartFailure.output), "restart failure output is redacted");
    assert.ok((await readFile(appEnvPath)).equals(beforeRestartFailure), "restart failure restores app.env bytes");
    assert.equal((await stat(join(remoteState, "active"))).isFile(), true, "restart failure restores active service");
    assert.ok(!new RegExp(cloudSecret).test(await readFile(sshLog, "utf8")), "SSH argv logs are redacted");

    const repaired = await run("bash", [deployRemote, binary, deployApp], deployEnv);
    assert.equal(repaired.code, 0, repaired.output);
    assert.equal(await readlink(current), firstTarget, "same-release repair preserves the release identity");
    const repairedAppEnv = await readFile(appEnvPath, "utf8");
    assert.ok(repairedAppEnv.includes(`export COQUIC_STEWARD_D1_READ_TOKEN=${cloudSecret}`), "same-release repair preserves cloud configuration");
    const rolledBack = await run("bash", [deployRemote, binary, deployApp], { ...deployEnv, GITHUB_SHA: "222222222222bbbbbbbbbbbbbbbbbbbbbbbbbbbb", FAKE_VERIFY_FAILURE: "1" });
    assert.notEqual(rolledBack.code, 0, rolledBack.output);
    assert.equal(await readlink(current), firstTarget, "failed verification restores the previous release");
    assert.equal((await readFile(join(stewardRoot, "tasks", "publisher.marker"), "utf8")).trim(), "raw-preserved");
    assert.equal((await readFile(join(stewardRoot, "cache", "index.marker"), "utf8")).trim(), "cache-preserved");
    assert.equal((await readFile(join(stewardRoot, "control-loop", "publisher.marker"), "utf8")).trim(), "raw-preserved");
    assert.equal((await readFile(join(remoteState, "active"), "utf8")).length, 0);
    assert.ok((await readFile(appEnvPath, "utf8")) === repairedAppEnv, "ordinary rollback preserves installed cloud configuration");
    assert.equal((await stat(appEnvPath)).mode & 0o777, 0o600);

    const absentRoot = join(root, "remote-absent");
    await mkdir(join(absentRoot, "tmp"), { recursive: true });
    await writeFile(join(absentRoot, ".coquic-deploy-test-root"), "owned\n");
    const absent = await run("bash", [installCloudConfig, cloudInput], { ...cloudEnv, COQUIC_DEPLOY_OFFLINE_ROOT: absentRoot, FAKE_SYSTEMD_STATE: join(absentRoot, ".fake-systemd") });
    assert.equal(absent.code, 0, absent.output);
    const absentAppEnv = join(absentRoot, "etc", "coquic-demo", "app.env");
    assert.equal((await stat(absentAppEnv)).mode & 0o777, 0o600);
    assert.doesNotMatch(await readFile(absentAppEnv, "utf8"), /COQUIC_DEMO_QA_ENABLED/);
    const deploySource = await readFile(deployRemote, "utf8");
    assert.doesNotMatch(deploySource, /COQUIC_DEPLOY_TEST_MODE/);
    assert.match(deploySource, /same-release repair mode/);
    assert.match(deploySource, /rollback/);
    assert.doesNotMatch(deploySource, /rm\s+-rf\s+["']?\/opt\/coquic-demo\/steward/);
    process.stdout.write("Offline deployment normal-path, repair, rollback, and persistence suite passed\n");
  } finally { await rm(root, { recursive: true, force: true }); }
})();
