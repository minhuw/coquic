#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

python3 - <<'PY'
import pathlib

ci_text = pathlib.Path(".github/workflows/ci.yml").read_text()
if "DeterminateSystems/magic-nix-cache-action@main" in ci_text:
    raise SystemExit("ci workflow must not use DeterminateSystems/magic-nix-cache-action@main")
if "zig build" in ci_text:
    raise SystemExit("ci workflow should only run format/lint gates")

required_ci_markers = [
    "name: Format / Lint",
    "format:",
    "name: Format",
    "name: Format Check",
    "nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure",
    "lint:",
    "name: Lint",
    "name: Refresh compile_commands.json",
    "nix develop -c ./scripts/refresh-compile-commands.sh",
    "nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure",
]
for marker in required_ci_markers:
    if marker not in ci_text:
        raise SystemExit(f"ci workflow missing marker: {marker}")

test_workflow_path = pathlib.Path(".github/workflows/test.yml")
test_text = test_workflow_path.read_text()
required_markers = [
    "name: Test",
    "workflow_dispatch:",
    "test:",
    "name: Build / Test / Coverage",
    "name: Build",
    "run: nix develop -c zig build",
    "name: Test With Coverage",
    "run: nix develop -c zig build coverage",
    "id-token: write",
    "python3 scripts/render-coverage-summary.py",
    "--lcov coverage/lcov.info",
    "--json-out coverage/coverage-results.json",
    "uses: codecov/codecov-action@v5",
    "coverage/html",
    "coverage/coverage-results.json",
    "COQUIC_DEMO_REMOTE_SSH_KEY",
    "/opt/coquic-demo/current/site/coverage-results.json",
    "/opt/coquic-demo/current/site/coverage",
]
for marker in required_markers:
    if marker not in test_text:
        raise SystemExit(f"test workflow missing marker: {marker}")

print("ci and test workflow split looks safe")
PY
