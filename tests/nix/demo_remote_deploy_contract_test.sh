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
required_deploy_env_names = [
    "COQUIC_DEMO_REMOTE_HOST",
    "COQUIC_DEMO_REMOTE_USER",
    "COQUIC_DEMO_REMOTE_SSH_PORT",
    "COQUIC_DEMO_PUBLIC_HOST",
    "COQUIC_DEMO_PUBLIC_PORT",
    "COQUIC_DEMO_REMOTE_SSH_KEY_PATH",
    "COQUIC_DEMO_CERT_CHAIN_PEM",
    "COQUIC_DEMO_PRIVATE_KEY_PEM",
]
for env_name in required_deploy_env_names:
    if env_name not in deploy_env:
        raise SystemExit(f"Deploy demo missing env: {env_name}")

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
