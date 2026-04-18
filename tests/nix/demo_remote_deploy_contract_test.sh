#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

python3 - <<'PY'
import pathlib
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

jobs = workflow.get("jobs", {})
deploy_job = jobs.get("deploy-demo")
if deploy_job is None:
    raise SystemExit("missing job: deploy-demo")

step_names = [step.get("name") for step in deploy_job.get("steps", [])]
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

print("deploy-demo workflow structure looks correct")

deploy_script = pathlib.Path("demo/deploy/deploy-remote.sh").read_text()
if "/opt/coquic-demo/releases" not in deploy_script:
    raise SystemExit("deploy script missing release root path")
if "/opt/coquic-demo/current" not in deploy_script:
    raise SystemExit("deploy script missing current symlink path")

service_unit = pathlib.Path("demo/deploy/coquic-demo.service").read_text()
if "/etc/coquic-demo/tls/fullchain.pem" not in service_unit:
    raise SystemExit("service unit missing fullchain path")
if "ExecStart=/opt/coquic-demo/current/h3-server" not in service_unit:
    raise SystemExit("service unit missing ExecStart path")

print("demo remote deploy contract looks correct")
PY
