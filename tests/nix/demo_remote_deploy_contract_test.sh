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
if deploy_job.get("if") != "github.ref == 'refs/heads/main'":
    raise SystemExit(f"unexpected deploy-demo job guard: {deploy_job.get('if')!r}")
if deploy_job.get("timeout-minutes") != 30:
    raise SystemExit(f"unexpected deploy-demo timeout-minutes: {deploy_job.get('timeout-minutes')!r}")

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
for network_timeout_marker in [
    "ConnectTimeout=10",
    "ServerAliveInterval=10",
    "ServerAliveCountMax=3",
]:
    if network_timeout_marker not in deploy_script:
        raise SystemExit(f"deploy script missing network timeout marker: {network_timeout_marker}")
rollback_markers = [
    "rollback: restore /opt/coquic-demo/current",
    "rollback: restore /etc/systemd/system/coquic-demo.service",
    "rollback: restore /etc/coquic-demo/tls/privkey.pem",
]
for marker in rollback_markers:
    if marker not in deploy_script:
        raise SystemExit(f"deploy script missing rollback marker: {marker}")
if "same-release repair mode" not in deploy_script:
    raise SystemExit("deploy script missing same-release repair mode marker")
if "COQUIC_DEMO_PUBLIC_PORT must be 4433 for the current service template" not in deploy_script:
    raise SystemExit("deploy script missing COQUIC_DEMO_PUBLIC_PORT guard")
if "install: restart existing service if already active" not in deploy_script:
    raise SystemExit("deploy script missing active-service restart install path marker")
if "verification retry loop" not in deploy_script:
    raise SystemExit("deploy script missing verification retry-loop marker")
if "verification marker: coquic-demo-v1" not in deploy_script:
    raise SystemExit("deploy script missing stable verification marker check")
if "normalized_headers" not in deploy_script or "grep -Eiq '^alt-svc:" not in deploy_script:
    raise SystemExit("deploy script missing normalized case-insensitive Alt-Svc check")
if "rollback: cleanup failed ${remote_release_dir}" not in deploy_script:
    raise SystemExit("deploy script missing failed release cleanup marker")
if "service.was_active" not in deploy_script:
    raise SystemExit("deploy script missing pre-deploy active-state marker")
if "service.was_enabled" not in deploy_script:
    raise SystemExit("deploy script missing pre-deploy enabled-state marker")
if "sudo rm -rf '${remote_upload_dir}'" not in deploy_script:
    raise SystemExit("deploy script missing sudo-based remote cleanup")
if "preflight: current must be symlink if present" not in deploy_script:
    raise SystemExit("deploy script missing current-symlink preflight marker")
if '[[ ! -e "${remote_current_link}" && ! -L "${remote_current_link}" ]]' not in deploy_script:
    raise SystemExit("deploy script missing compound absent check for dangling-symlink safety")
if "preflight: current target must resolve within /opt/coquic-demo/releases" not in deploy_script:
    raise SystemExit("deploy script missing current-target preflight marker")
if "preflight: current target must resolve to existing directory" not in deploy_script:
    raise SystemExit("deploy script missing existing-directory preflight marker")
if "ln -sfnT" not in deploy_script:
    raise SystemExit("deploy script missing guarded symlink replacement")
if "timeout 20s nix run .#curl-http3" not in deploy_script:
    raise SystemExit("deploy script missing bounded verification timeout wrapper")
if "same-release gate: stop active service before in-place mutation" not in deploy_script:
    raise SystemExit("deploy script missing same-release stop gate marker")
if "same-release gate: ensure service is inactive before mutating files" not in deploy_script:
    raise SystemExit("deploy script missing same-release inactive verification marker")
same_release_backup_restore_markers = [
    "same-release backup /opt/coquic-demo/current/h3-server",
    "same-release backup /opt/coquic-demo/current/site",
    "rollback: restore same-release /opt/coquic-demo/current/h3-server",
    "rollback: restore same-release /opt/coquic-demo/current/site",
]
for marker in same_release_backup_restore_markers:
    if marker not in deploy_script:
        raise SystemExit(f"deploy script missing same-release backup/restore marker: {marker}")
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

run_same_release_case() {
  local case_name="$1"
  local nix_mode="$2"
  local expected_status="$3"
  local readlink_target="$4"

  local case_dir="${test_tmp}/${case_name}"
  local stub_bin="${case_dir}/bin"
  local fake_home="${case_dir}/home"
  local fake_site="${case_dir}/site"
  local fake_binary="${case_dir}/h3-server"
  local fake_key="${case_dir}/coquic-demo.key"
  local ssh_log="${case_dir}/ssh.log"
  local scp_log="${case_dir}/scp.log"
  local nix_log="${case_dir}/nix.log"
  local ssh_bash_count="${case_dir}/ssh_bash_count.txt"

  mkdir -p "${stub_bin}" "${fake_home}/.ssh" "${fake_site}"
  touch "${fake_binary}"
  chmod 755 "${fake_binary}"
  printf '<html>demo</html>\n' > "${fake_site}/index.html"
  printf 'known-host-entry\n' > "${fake_home}/.ssh/known_hosts"
  printf 'test-key\n' > "${fake_key}"

  dangling_probe="${case_dir}/dangling-current"
  ln -s "${case_dir}/missing-target" "${dangling_probe}"
  if [[ ! -e "${dangling_probe}" && -L "${dangling_probe}" ]]; then
    :
  else
    echo "local shell dangling-symlink semantics check failed" >&2
    exit 1
  fi

  : > "${ssh_log}"
  : > "${scp_log}"
  : > "${nix_log}"
  : > "${ssh_bash_count}"

  cat > "${stub_bin}/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

log_path="${COQUIC_TEST_SSH_LOG:?}"
printf 'ssh %s\n' "$*" >> "${log_path}"

if [[ "$*" == *"readlink '/opt/coquic-demo/current'"* ]]; then
  if [[ -n "${COQUIC_TEST_READLINK_TARGET:-}" ]]; then
    printf '%s\n' "${COQUIC_TEST_READLINK_TARGET}"
  fi
  exit 0
fi

if [[ "$*" == *"mktemp -d"* ]]; then
  printf '%s\n' "/tmp/coquic-demo-release-${COQUIC_TEST_CASE_NAME:?}"
  exit 0
fi

if [[ "$*" == *"bash -s --"* &&
      "$*" == *"/opt/coquic-demo/current"* &&
      "$*" == *"/opt/coquic-demo/releases"* &&
      "$*" != *"/tmp/coquic-demo-release-"* ]]; then
  printf 'preflight-invoked\n' >> "${log_path}"
  if [[ -n "${COQUIC_TEST_READLINK_TARGET:-}" ]]; then
    printf '%s\n' "${COQUIC_TEST_READLINK_TARGET}"
  fi
  exit 0
fi

if [[ "$*" == *"bash -s --"* ]]; then
  count_path="${COQUIC_TEST_SSH_BASH_COUNT_PATH:?}"
  count="$(cat "${count_path}")"
  count=$((count + 1))
  printf '%s' "${count}" > "${count_path}"
  if [[ "${count}" -eq 1 ]]; then
    if [[ "${COQUIC_TEST_NIX_MODE:?}" == "stop_gate_fail" ]]; then
      printf 'stop-gate-failed\n' >> "${log_path}"
      exit 61
    fi
    printf 'remote-install-invoked\n' >> "${log_path}"
  else
    printf 'rollback-invoked\n' >> "${log_path}"
  fi
  exit 0
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

case "${COQUIC_TEST_NIX_MODE:?}" in
  success)
    if [[ "$*" == *"run .#curl-http3 -- -I "* ]]; then
      cat <<'HEADERS'
HTTP/1.1 200 OK
Alt-Svc: h3=":4433"; ma=60
HEADERS
      exit 0
    fi

    if [[ "$*" == *"--http3-only -sS -o /dev/null -w %{http_version}"* ]]; then
      printf '3'
      exit 0
    fi

    if [[ "$*" == *"run .#curl-http3 -- --http3-only -sS https://"* ]]; then
      cat <<'PAGE'
<meta name="coquic-demo-marker" content="coquic-demo-v1">
PAGE
      exit 0
    fi
    ;;
  fail_after_install)
    if [[ "$*" == *"run .#curl-http3 -- -I "* ]]; then
      cat <<'HEADERS'
HTTP/1.1 503 Service Unavailable
HEADERS
      exit 0
    fi
    ;;
  stop_gate_fail)
    ;;
esac

exit 0
EOF

  chmod 755 "${stub_bin}/ssh" "${stub_bin}/scp" "${stub_bin}/nix"

  set +e
  case_output="$(
    PATH="${stub_bin}:${PATH}" \
    HOME="${fake_home}" \
    GITHUB_SHA="deadbeefcafebabe1234" \
    COQUIC_DEMO_REMOTE_HOST="example.test" \
    COQUIC_DEMO_REMOTE_USER="deployer" \
    COQUIC_DEMO_REMOTE_SSH_KEY_PATH="${fake_key}" \
    COQUIC_DEMO_CERT_CHAIN_PEM="chain" \
    COQUIC_DEMO_PRIVATE_KEY_PEM="key" \
    COQUIC_DEMO_PUBLIC_HOST="demo.example.test" \
    COQUIC_DEMO_PUBLIC_PORT="4433" \
    COQUIC_TEST_CASE_NAME="${case_name}" \
    COQUIC_TEST_NIX_MODE="${nix_mode}" \
    COQUIC_TEST_READLINK_TARGET="${readlink_target}" \
    COQUIC_TEST_SSH_LOG="${ssh_log}" \
    COQUIC_TEST_SCP_LOG="${scp_log}" \
    COQUIC_TEST_NIX_LOG="${nix_log}" \
    COQUIC_TEST_SSH_BASH_COUNT_PATH="${ssh_bash_count}" \
    demo/deploy/deploy-remote.sh "${fake_binary}" "${fake_site}" 2>&1
  )"
  case_status=$?
  set -e

  if [[ "${expected_status}" == "success" && ${case_status} -ne 0 ]]; then
    echo "${case_name} expected success, got: ${case_output}" >&2
    exit 1
  fi
  if [[ "${expected_status}" == "failure" && ${case_status} -eq 0 ]]; then
    echo "${case_name} expected failure but command succeeded" >&2
    exit 1
  fi

  if [[ "${expected_status}" == "success" ]]; then
    if [[ "${case_output}" != *"remote demo deploy verified"* ]]; then
      echo "${case_name} expected success output, got: ${case_output}" >&2
      exit 1
    fi
  else
    if [[ "${nix_mode}" == "stop_gate_fail" ]]; then
      if [[ "${case_output}" != *"deployment failed during remote install"* ]]; then
        echo "${case_name} expected stop-gate install failure output, got: ${case_output}" >&2
        exit 1
      fi
    else
      if [[ "${case_output}" != *"deployment verification failed"* ]]; then
        echo "${case_name} expected verification failure output, got: ${case_output}" >&2
        exit 1
      fi
    fi
  fi

  if ! grep -Fq "mktemp -d" "${ssh_log}"; then
    echo "${case_name} should invoke remote mktemp" >&2
    cat "${ssh_log}" >&2
    exit 1
  fi

  if [[ ! -s "${scp_log}" ]]; then
    echo "${case_name} should invoke scp uploads" >&2
    cat "${scp_log}" >&2
    exit 1
  fi

  if [[ "${nix_mode}" == "stop_gate_fail" ]]; then
    if ! grep -Fq "stop-gate-failed" "${ssh_log}"; then
      echo "${case_name} should hit same-release stop gate failure" >&2
      cat "${ssh_log}" >&2
      exit 1
    fi
  else
    if ! grep -Fq "remote-install-invoked" "${ssh_log}"; then
      echo "${case_name} should invoke remote install" >&2
      cat "${ssh_log}" >&2
      exit 1
    fi
  fi

  if [[ "${nix_mode}" != "stop_gate_fail" ]]; then
    if ! grep -Fq "run .#curl-http3 -- -I https://demo.example.test:4433/" "${nix_log}"; then
      echo "${case_name} should invoke header verification command" >&2
      cat "${nix_log}" >&2
      exit 1
    fi
  fi

  if [[ "${expected_status}" == "success" ]]; then
    for nix_expected in \
      "run .#curl-http3 -- --http3-only -sS -o /dev/null -w %{http_version} https://demo.example.test:4433/" \
      "run .#curl-http3 -- --http3-only -sS https://demo.example.test:4433/"; do
      if ! grep -Fq "${nix_expected}" "${nix_log}"; then
        echo "${case_name} should invoke nix verification command: ${nix_expected}" >&2
        cat "${nix_log}" >&2
        exit 1
      fi
    done
  else
    if ! grep -Fq "rollback-invoked" "${ssh_log}"; then
      echo "${case_name} should invoke rollback ssh path after verification failure" >&2
      cat "${ssh_log}" >&2
      exit 1
    fi
    if [[ "$(cat "${ssh_bash_count}")" -lt 2 ]]; then
      echo "${case_name} should invoke distinct install and rollback ssh bash paths" >&2
      cat "${ssh_log}" >&2
      exit 1
    fi
    cleanup_line="$(grep -Fn "sudo rm -rf '/tmp/coquic-demo-release-${case_name}'" "${ssh_log}" | tail -n1 | cut -d: -f1)"
    rollback_line="$(grep -Fn "rollback-invoked" "${ssh_log}" | tail -n1 | cut -d: -f1)"
    if [[ -z "${cleanup_line}" ]]; then
      echo "${case_name} should invoke remote cleanup after rollback" >&2
      cat "${ssh_log}" >&2
      exit 1
    fi
    if [[ "${cleanup_line}" -le "${rollback_line}" ]]; then
      echo "${case_name} remote cleanup should occur after rollback" >&2
      cat "${ssh_log}" >&2
      exit 1
    fi
    if [[ "${nix_mode}" == "stop_gate_fail" && -s "${nix_log}" ]]; then
      echo "${case_name} should not reach verification probes after stop-gate failure" >&2
      cat "${nix_log}" >&2
      exit 1
    fi
  fi
}

run_same_release_case "same-sha-success" "success" "success" "/opt/coquic-demo/releases/deadbeefcafe"
echo "same-SHA repair mode behaves correctly"

run_same_release_case "same-sha-failure" "fail_after_install" "failure" "/opt/coquic-demo/releases/deadbeefcafe"
echo "same-SHA repair rollback on verification failure behaves correctly"

run_same_release_case "same-sha-stop-gate-failure" "stop_gate_fail" "failure" "/opt/coquic-demo/releases/deadbeefcafe"
echo "same-SHA stop gate failure triggers rollback before verification probes"

run_same_release_case "new-release-failure" "fail_after_install" "failure" "/opt/coquic-demo/releases/112233445566"
echo "new-release rollback on verification failure behaves correctly"

run_dangling_preflight_case() {
  local case_name="dangling-preflight"
  local case_dir="${test_tmp}/${case_name}"
  local stub_bin="${case_dir}/bin"
  local fake_home="${case_dir}/home"
  local fake_site="${case_dir}/site"
  local fake_binary="${case_dir}/h3-server"
  local fake_key="${case_dir}/coquic-demo.key"
  local ssh_log="${case_dir}/ssh.log"
  local scp_log="${case_dir}/scp.log"
  local nix_log="${case_dir}/nix.log"

  mkdir -p "${stub_bin}" "${fake_home}/.ssh" "${fake_site}"
  touch "${fake_binary}"
  chmod 755 "${fake_binary}"
  printf '<html>demo</html>\n' > "${fake_site}/index.html"
  printf 'known-host-entry\n' > "${fake_home}/.ssh/known_hosts"
  printf 'test-key\n' > "${fake_key}"

  dangling_probe="${case_dir}/dangling-current"
  ln -s "${case_dir}/missing-target" "${dangling_probe}"
  if [[ ! -e "${dangling_probe}" && -L "${dangling_probe}" ]]; then
    :
  else
    echo "local shell dangling-symlink semantics check failed in dangling-preflight harness" >&2
    exit 1
  fi

  : > "${ssh_log}"
  : > "${scp_log}"
  : > "${nix_log}"

  cat > "${stub_bin}/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'ssh %s\n' "$*" >> "${COQUIC_TEST_SSH_LOG:?}"

if [[ "$*" == *"bash -s --"* &&
      "$*" == *"/opt/coquic-demo/current"* &&
      "$*" == *"/opt/coquic-demo/releases"* &&
      "$*" != *"/tmp/coquic-demo-release-"* ]]; then
  echo "remote preflight failed: /opt/coquic-demo/current target is missing or not a directory" >&2
  exit 42
fi

if [[ "$*" == *"mktemp -d"* ]]; then
  printf '%s\n' "/tmp/unexpected-preflight-mktemp"
  exit 0
fi

if [[ "$*" == *"bash -s --"* ]]; then
  printf 'unexpected-install-or-rollback\n' >> "${COQUIC_TEST_SSH_LOG:?}"
  exit 0
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

  set +e
  case_output="$(
    PATH="${stub_bin}:${PATH}" \
    HOME="${fake_home}" \
    GITHUB_SHA="deadbeefcafebabe1234" \
    COQUIC_DEMO_REMOTE_HOST="example.test" \
    COQUIC_DEMO_REMOTE_USER="deployer" \
    COQUIC_DEMO_REMOTE_SSH_KEY_PATH="${fake_key}" \
    COQUIC_DEMO_CERT_CHAIN_PEM="chain" \
    COQUIC_DEMO_PRIVATE_KEY_PEM="key" \
    COQUIC_DEMO_PUBLIC_HOST="demo.example.test" \
    COQUIC_DEMO_PUBLIC_PORT="4433" \
    COQUIC_TEST_SSH_LOG="${ssh_log}" \
    COQUIC_TEST_SCP_LOG="${scp_log}" \
    COQUIC_TEST_NIX_LOG="${nix_log}" \
    demo/deploy/deploy-remote.sh "${fake_binary}" "${fake_site}" 2>&1
  )"
  case_status=$?
  set -e

  if [[ ${case_status} -eq 0 ]]; then
    echo "dangling-preflight expected failure but command succeeded" >&2
    exit 1
  fi

  if [[ "${case_output}" != *"remote preflight failed"* ]]; then
    echo "dangling-preflight expected preflight failure output, got: ${case_output}" >&2
    exit 1
  fi

  if [[ -s "${scp_log}" ]]; then
    echo "dangling-preflight should not invoke scp" >&2
    cat "${scp_log}" >&2
    exit 1
  fi

  if grep -Fq "unexpected-install-or-rollback" "${ssh_log}"; then
    echo "dangling-preflight should not invoke remote install or rollback paths" >&2
    cat "${ssh_log}" >&2
    exit 1
  fi
}

run_dangling_preflight_case
echo "dangling current preflight failure behaves correctly"
