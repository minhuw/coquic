#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

python3 - <<'PY'
import pathlib
import yaml

workflow_path = pathlib.Path(".github/workflows/ci.yml")
workflow = yaml.safe_load(workflow_path.read_text())
jobs = workflow.get("jobs", {})
ci_job = jobs.get("ci")

if ci_job is None:
    raise SystemExit("missing job: ci")

steps = ci_job.get("steps", [])
magic_step = next(
    (
        step
        for step in steps
        if step.get("uses") == "DeterminateSystems/magic-nix-cache-action@main"
    ),
    None,
)
if magic_step is not None:
    raise SystemExit("ci workflow must not use DeterminateSystems/magic-nix-cache-action@main")

lint_step = next((step for step in steps if step.get("name") == "Lint"), None)
if lint_step is None:
    raise SystemExit("missing step: Lint")
if lint_step.get("run") != "nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure":
    raise SystemExit(f"unexpected lint step command: {lint_step.get('run')!r}")

print("ci workflow nix setup looks safe")
PY
