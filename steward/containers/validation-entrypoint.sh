#!/usr/bin/env bash
set -euo pipefail

# The validation image is a one-shot, no-Codex boundary.  It receives a
# read-only worktree and a disposable writable root/store from the daemon.
fail() { printf 'validation entrypoint refused (%s)\n' "$1" >&2; exit 78; }

worktree="${VALIDATION_WORKTREE:-/validation/worktree}"
output="${VALIDATION_OUTPUT:-/validation/output}"
store="${NIX_STORE_DIR:-/validation/store}"
[[ "$worktree" == /* && "$output" == /* && "$store" == /* ]] || fail 'validation paths must be absolute'
[[ -d "$worktree" && ! -L "$worktree" ]] || fail 'read-only validation worktree is missing'
[[ ! -e /run/secrets/codex-api-key && ! -e /run/secrets/codex-api ]] || fail 'validation image received a credential mount'
[[ ! -e /var/run/docker.sock ]] || fail 'validation image received the Docker socket'
mkdir -p "$output" "$store" /tmp

export HOME=/tmp/validation-home
export COQUIC_HOME=/tmp/validation-home
export NIX_PATH=
export NIX_CONFIG="sandbox = true\nsubstituters =\ntrusted-public-keys =\nconnect-timeout = 1\n"
mkdir -p "$HOME"

export VALIDATION_WORKTREE="$worktree"
export VALIDATION_OUTPUT="$output"
export NIX_STORE_DIR="$store"
exec python - <<'PY'
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from coquic_steward.execution.validation import default_gates

worktree = Path(os.environ["VALIDATION_WORKTREE"])
output = Path(os.environ["VALIDATION_OUTPUT"])
results = []
for filename, command in default_gates(worktree):
    target = output / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            command,
            cwd=worktree,
            check=False,
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("VALIDATION_TIMEOUT_SECONDS", "1800")),
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ["HOME"],
                "COQUIC_HOME": os.environ["COQUIC_HOME"],
                "NIX_STORE_DIR": os.environ.get("NIX_STORE_DIR", "/validation/store"),
                "NIX_CONFIG": os.environ.get("NIX_CONFIG", ""),
            },
        )
        stdout, stderr = completed.stdout, completed.stderr
        exit_code = completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        exit_code = 124
    target.write_text(
        "$ " + " ".join(command) + "\n\nSTDOUT:\n" + stdout[-2_000_000:]
        + "\n\nSTDERR:\n" + stderr[-2_000_000:] + "\n",
        encoding="utf-8",
    )
    results.append({"filename": filename, "command": command, "exitCode": exit_code})
    if exit_code != 0:
        break
(output / "results.json").write_text(
    json.dumps({"gates": results}, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
raise SystemExit(0 if results and all(item["exitCode"] == 0 for item in results) and len(results) == 4 else 1)
PY
