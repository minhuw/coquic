#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

python3 - <<'PY'
import pathlib
import os
import yaml

workflow_path = pathlib.Path(".github/workflows/deploy-demo.yml")
workflow = yaml.safe_load(workflow_path.read_text())

on_block = workflow.get("on", workflow.get(True))
if on_block is None:
    raise SystemExit("missing trigger block")

push = on_block.get("push")
if push is None:
    raise SystemExit("missing push trigger")

if push.get("branches") != ["main"]:
    raise SystemExit(f"unexpected push branches: {push.get('branches')!r}")

expected_paths = [
    "demo/**",
    "src/**",
    "build.zig",
    "build.zig.zon",
    "flake.nix",
    "flake.lock",
    "docker/h3-server/Dockerfile",
    ".github/workflows/deploy-demo.yml",
]
if push.get("paths") != expected_paths:
    raise SystemExit(f"unexpected push paths: {push.get('paths')!r}")

if "workflow_dispatch" not in on_block:
    raise SystemExit("missing workflow_dispatch trigger")

if workflow.get("permissions") != {"contents": "read"}:
    raise SystemExit(f"unexpected workflow permissions: {workflow.get('permissions')!r}")

concurrency = workflow.get("concurrency")
if concurrency is None:
    raise SystemExit("missing workflow concurrency")
if concurrency.get("group") != "deploy-demo":
    raise SystemExit(f"unexpected workflow concurrency group: {concurrency.get('group')!r}")
if concurrency.get("cancel-in-progress") is not False:
    raise SystemExit("workflow concurrency must set cancel-in-progress: false")

jobs = workflow.get("jobs", {})
deploy_job = jobs.get("deploy-demo")
if deploy_job is None:
    raise SystemExit("missing job: deploy-demo")

steps = deploy_job.get("steps", [])
step_names = [step.get("name") for step in steps]
required_step_names = [
    "Checkout",
    "Install Nix",
    "Build h3-server",
    "Package demo site",
    "Configure SSH",
    "Deploy demo",
]
for step_name in required_step_names:
    if step_name not in step_names:
        raise SystemExit(f"missing step name: {step_name}")

step_by_name = {step.get("name"): step for step in steps}

install_nix_step = step_by_name["Install Nix"]
expected_install_nix_uses = "DeterminateSystems/nix-installer-action@92148bb48b9a0c5458c53dd0b368fbfbfbaa3210"
if install_nix_step.get("uses") != expected_install_nix_uses:
    raise SystemExit(f"unexpected Install Nix uses: {install_nix_step.get('uses')!r}")

build_step = step_by_name["Build h3-server"]
expected_build_command = "nix develop .#quictls-musl -c zig build -Dtls_backend=quictls -Dtarget=x86_64-linux-musl -Dspdlog_shared=false"
if build_step.get("run") != expected_build_command:
    raise SystemExit(f"unexpected Build h3-server command: {build_step.get('run')!r}")

configure_ssh_env = step_by_name["Configure SSH"].get("env", {})
for env_name in ["COQUIC_DEMO_REMOTE_SSH_KEY", "COQUIC_DEMO_REMOTE_KNOWN_HOSTS"]:
    if env_name not in configure_ssh_env:
        raise SystemExit(f"Configure SSH missing env: {env_name}")

deploy_step = step_by_name["Deploy demo"]
expected_deploy_command = 'demo/deploy/deploy-remote.sh "$(pwd)/zig-out/bin/h3-server" "${RUNNER_TEMP}/demo-site"'
if deploy_step.get("run") != expected_deploy_command:
    raise SystemExit(f"unexpected Deploy demo command: {deploy_step.get('run')!r}")

deploy_env = deploy_step.get("env", {})
expected_deploy_env_names = [
    "COQUIC_DEMO_REMOTE_HOST",
    "COQUIC_DEMO_REMOTE_USER",
    "COQUIC_DEMO_REMOTE_SSH_PORT",
    "COQUIC_DEMO_PUBLIC_HOST",
    "COQUIC_DEMO_PUBLIC_PORT",
    "COQUIC_DEMO_REMOTE_SSH_KEY_PATH",
    "COQUIC_DEMO_CERT_CHAIN_PEM",
    "COQUIC_DEMO_PRIVATE_KEY_PEM",
]
if set(deploy_env.keys()) != set(expected_deploy_env_names):
    raise SystemExit(f"unexpected Deploy demo env keys: {sorted(deploy_env.keys())!r}")

print("deploy-demo workflow structure looks correct")

deploy_script_path = pathlib.Path("demo/deploy/deploy-remote.sh")
deploy_script = deploy_script_path.read_text()
if "/opt/coquic-demo/releases" not in deploy_script:
    raise SystemExit("deploy script missing release root path")
if "/opt/coquic-demo/current" not in deploy_script:
    raise SystemExit("deploy script missing current symlink path")
if "mktemp -d" not in deploy_script:
    raise SystemExit("deploy script missing mktemp -d usage")
if "StrictHostKeyChecking=yes" not in deploy_script:
    raise SystemExit("deploy script missing strict host checking")
rollback_markers = [
    "rollback: restore /opt/coquic-demo/current",
    "rollback: restore /etc/systemd/system/coquic-demo.service",
    "rollback: restore /etc/coquic-demo/tls/privkey.pem",
]
for marker in rollback_markers:
    if marker not in deploy_script:
        raise SystemExit(f"deploy script missing rollback marker: {marker}")
if "refusing to redeploy over live release dir" not in deploy_script:
    raise SystemExit("deploy script missing same-release refusal message")
if "COQUIC_DEMO_PUBLIC_PORT must be 4433 for the current service template" not in deploy_script:
    raise SystemExit("deploy script missing COQUIC_DEMO_PUBLIC_PORT guard")
if "verification retry loop" not in deploy_script:
    raise SystemExit("deploy script missing verification retry-loop marker")
if "rollback: cleanup failed ${remote_release_dir}" not in deploy_script:
    raise SystemExit("deploy script missing failed release cleanup marker")
if not os.access(deploy_script_path, os.X_OK):
    raise SystemExit("deploy script is not executable")

service_unit = pathlib.Path("demo/deploy/coquic-demo.service").read_text()
if "/etc/coquic-demo/tls/fullchain.pem" not in service_unit:
    raise SystemExit("service unit missing fullchain path")
if "ExecStart=/opt/coquic-demo/current/h3-server" not in service_unit:
    raise SystemExit("service unit missing ExecStart path")

contract_test_path = pathlib.Path("tests/nix/demo_remote_deploy_contract_test.sh")
if not os.access(contract_test_path, os.X_OK):
    raise SystemExit("demo remote deploy contract test is not executable")

print("demo remote deploy contract looks correct")
PY

test_tmp="$(mktemp -d)"
cleanup_test_tmp() {
  rm -rf "${test_tmp}"
}
trap cleanup_test_tmp EXIT

stub_bin="${test_tmp}/bin"
mkdir -p "${stub_bin}"

cat > "${stub_bin}/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

log_path="${COQUIC_TEST_SSH_LOG:?}"
printf 'ssh %s\n' "$*" >> "${log_path}"

if [[ "$*" == *"readlink '/opt/coquic-demo/current'"* ]]; then
  printf '%s\n' "/opt/coquic-demo/releases/${COQUIC_TEST_SAME_SHA:?}"
  exit 0
fi

if [[ "$*" == *"mktemp -d"* ]]; then
  printf 'unexpected mktemp call\n' >> "${log_path}"
  exit 70
fi

if [[ "$*" == *"bash -s --"* ]]; then
  printf 'unexpected remote install call\n' >> "${log_path}"
  exit 71
fi

exit 0
EOF

cat > "${stub_bin}/scp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'scp %s\n' "$*" >> "${COQUIC_TEST_SCP_LOG:?}"
exit 0
EOF

cat > "${stub_bin}/nix" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'nix %s\n' "$*" >> "${COQUIC_TEST_NIX_LOG:?}"
exit 0
EOF

chmod 755 "${stub_bin}/ssh" "${stub_bin}/scp" "${stub_bin}/nix"

fake_binary="${test_tmp}/h3-server"
fake_site="${test_tmp}/site"
touch "${fake_binary}"
chmod 755 "${fake_binary}"
mkdir -p "${fake_site}"
printf '<html>demo</html>\n' > "${fake_site}/index.html"

fake_home="${test_tmp}/home"
mkdir -p "${fake_home}/.ssh"
printf 'known-host-entry\n' > "${fake_home}/.ssh/known_hosts"

fake_key="${test_tmp}/coquic-demo.key"
printf 'test-key\n' > "${fake_key}"

ssh_log="${test_tmp}/ssh.log"
scp_log="${test_tmp}/scp.log"
nix_log="${test_tmp}/nix.log"
: > "${ssh_log}"
: > "${scp_log}"
: > "${nix_log}"

set +e
same_sha_output="$(
  PATH="${stub_bin}:${PATH}" \
  HOME="${fake_home}" \
  GITHUB_SHA="deadbeefcafebabe1234" \
  COQUIC_DEMO_REMOTE_HOST="example.test" \
  COQUIC_DEMO_REMOTE_USER="deployer" \
  COQUIC_DEMO_REMOTE_SSH_KEY_PATH="${fake_key}" \
  COQUIC_DEMO_CERT_CHAIN_PEM="chain" \
  COQUIC_DEMO_PRIVATE_KEY_PEM="key" \
  COQUIC_DEMO_PUBLIC_HOST="demo.example.test" \
  COQUIC_TEST_SAME_SHA="deadbeefcafe" \
  COQUIC_TEST_SSH_LOG="${ssh_log}" \
  COQUIC_TEST_SCP_LOG="${scp_log}" \
  COQUIC_TEST_NIX_LOG="${nix_log}" \
  demo/deploy/deploy-remote.sh "${fake_binary}" "${fake_site}" 2>&1
)"
same_sha_status=$?
set -e

if [[ ${same_sha_status} -eq 0 ]]; then
  echo "expected same-SHA redeploy refusal to fail" >&2
  exit 1
fi

if [[ "${same_sha_output}" != *"refusing to redeploy over live release dir"* ]]; then
  echo "expected same-SHA refusal message, got: ${same_sha_output}" >&2
  exit 1
fi

if [[ -s "${scp_log}" ]]; then
  echo "same-SHA refusal should not invoke scp" >&2
  cat "${scp_log}" >&2
  exit 1
fi

if grep -Fq "mktemp -d" "${ssh_log}"; then
  echo "same-SHA refusal should happen before remote mktemp" >&2
  cat "${ssh_log}" >&2
  exit 1
fi

if grep -Fq "bash -s --" "${ssh_log}"; then
  echo "same-SHA refusal should happen before remote install" >&2
  cat "${ssh_log}" >&2
  exit 1
fi

if [[ -s "${nix_log}" ]]; then
  echo "same-SHA refusal should happen before verification commands" >&2
  cat "${nix_log}" >&2
  exit 1
fi

echo "same-SHA redeploy guard behaves correctly"
