#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

python3 - <<'PY'
import json
import subprocess

packages = json.loads(
    subprocess.check_output(
        [
            "nix",
            "eval",
            "--json",
            ".#packages.x86_64-linux",
        ],
        text=True,
    )
)

expected_present = {
    "interop-image-quictls-musl",
    "interop-image-boringssl-musl",
}
missing = sorted(name for name in expected_present if name not in packages)
if missing:
    raise SystemExit(f"missing expected interop package exports: {missing!r}")

unexpected = sorted(
    name for name in packages
    if name.startswith("interop-image") and name not in expected_present
)
if unexpected:
    raise SystemExit(f"unexpected extra interop package exports still present: {unexpected!r}")

print("interop package exports ok")
PY
