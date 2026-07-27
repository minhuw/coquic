#!/bin/sh
set -eu

# The validation image is a one-shot, no-Codex boundary.  It receives a
# read-only worktree and a disposable writable root/store from the daemon.
fail() { printf 'validation entrypoint refused (%s)\n' "$1" >&2; exit 78; }

worktree="${VALIDATION_WORKTREE:-/validation/worktree}"
output="${VALIDATION_OUTPUT:-/validation/output}"
state="${NIX_STATE_DIR:-/nix/var/nix}"
store="${NIX_STORE_DIR:-/nix/store}"
lower_store="${NIX_LOWER_STORE_DIR:-/validation/lower/nix/store}"
case "$worktree:$output:$state:$store:$lower_store" in
  /*:/*:/*:/*:/*) ;;
  *) fail 'validation paths must be absolute' ;;
esac
[ "$store" = /nix/store ] || fail 'logical Nix store identity changed'
[ -d "$worktree" ] && [ ! -L "$worktree" ] || fail 'read-only validation worktree is missing'
[ -d "$store" ] && [ ! -L "$store" ] || fail 'bounded writable Nix store is missing'
[ -d "$lower_store" ] && [ ! -L "$lower_store" ] || fail 'read-only validation closure is missing'
[ ! -e /run/secrets/codex-api-key ] && [ ! -e /run/secrets/codex-api ] || fail 'validation image received a credential mount'
[ ! -S /var/run/docker.sock ] && [ ! -S /run/docker.sock ] && [ ! -S /nix/var/nix/daemon-socket/socket ] || fail 'validation image received an authority socket'
[ ! -x /bin/codex ] && [ ! -x /bin/docker ] && [ ! -x /bin/gh ] || fail 'validation image contains forbidden authority tooling'

umask 077
mkdir -p "$output" "$state/db" "$state/log" "$state/profiles" /tmp
export HOME=/tmp/validation-home
export COQUIC_HOME=/tmp/validation-home
export NIX_PATH=
export NIX_CONFIG='experimental-features = nix-command flakes
sandbox = true
substituters =
trusted-public-keys =
connect-timeout = 1
'
export NIX_STATE_DIR="$state"
export NIX_LOG_DIR="$state/log"
export TMPDIR=/tmp
export XDG_CACHE_HOME=/tmp/cache
export XDG_CONFIG_HOME=/tmp/config
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-/tmp/zig-global-cache}"
export ZIG_LOCAL_CACHE_DIR="${ZIG_LOCAL_CACHE_DIR:-/tmp/zig-local-cache}"
mkdir -p "$HOME/.config/nix" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME"
printf '%s' "$NIX_CONFIG" >"$HOME/.config/nix/nix.conf"
[ -f "${NIX_REGISTRATION:-}" ] || fail 'validation closure registration is missing'
[ -f "${NIX_MATERIALIZED_STORE_PATHS:-}" ] || fail 'validation materialized path list is missing'
[ -f "${NIX_STORE_PATHS:-}" ] || fail 'validation closure path list is missing'

while IFS= read -r store_path; do
  name="${store_path##*/}"
  [ "$store_path" = "/nix/store/$name" ] && [ -n "$name" ] || fail 'validation materialized path is invalid'
  lower_path="$lower_store/$name"
  target="$store/$name"
  [ -e "$lower_path" ] && [ ! -L "$lower_path" ] || fail 'validation materialized source is missing'
  if [ -e "$target" ] || [ -L "$target" ]; then
    [ -e "$target" ] && [ ! -L "$target" ] || fail 'validation materialized path is mismatched'
  else
    cp -R "$lower_path" "$target"
  fi
done <"$NIX_MATERIALIZED_STORE_PATHS"

store_path_count=0
while IFS= read -r store_path; do
  name="${store_path##*/}"
  [ "$store_path" = "/nix/store/$name" ] && [ -n "$name" ] || fail 'validation closure path is invalid'
  lower_path="$lower_store/$name"
  target="$store/$name"
  [ -e "$lower_path" ] || [ -L "$lower_path" ] || fail 'validation closure path is missing'
  if [ -e "$target" ] || [ -L "$target" ]; then
    if [ -L "$target" ]; then
      [ "$(readlink "$target")" = "$lower_path" ] || fail 'validation store path is mismatched'
    fi
  else
    ln -s "$lower_path" "$target"
  fi
  store_path_count=$((store_path_count + 1))
done <"$NIX_STORE_PATHS"
[ "$store_path_count" -gt 0 ] || fail 'validation closure path list is empty'

if [ ! -f "$NIX_STATE_DIR/db/db.sqlite" ]; then
  nix-store --load-db <"$NIX_REGISTRATION"
fi

git_objects="${VALIDATION_GIT_OBJECTS_DIR:-}"
git_alternate="${VALIDATION_GIT_ALTERNATE_OBJECTS:-}"
if [ -n "$git_objects" ] || [ -n "$git_alternate" ]; then
  case "$git_objects:$git_alternate" in
    /*:/*) ;;
    *) fail 'validation Git object paths must be absolute' ;;
  esac
  [ -d "$git_objects" ] && [ ! -L "$git_objects" ] || fail 'writable validation Git objects are missing'
  [ -d "$git_alternate" ] && [ ! -L "$git_alternate" ] || fail 'read-only validation Git objects are missing'
  mkdir -p "$git_objects/info"
  printf '%s\n' "$git_alternate" >"$git_objects/info/alternates"
fi

source_worktree="${VALIDATION_SOURCE_WORKTREE:-}"
if [ -n "$source_worktree" ]; then
  case "$source_worktree" in
    /*) ;;
    *) fail 'validation source worktree must be absolute' ;;
  esac
  [ "$source_worktree" != "$worktree" ] || fail 'validation source worktree is not isolated'
  [ -d "$source_worktree/site/next" ] && [ ! -L "$source_worktree/site/next" ] || fail 'validation frontend source is missing'
  [ -d "$source_worktree/.duvet" ] && [ ! -L "$source_worktree/.duvet" ] || fail 'validation report source is missing'
  [ -d "$worktree/site/next" ] && [ ! -L "$worktree/site/next" ] || fail 'validation frontend scratch is missing'
  [ -d "$worktree/.duvet" ] && [ ! -L "$worktree/.duvet" ] || fail 'validation report scratch is missing'
  cp -R "$source_worktree/site/next/." "$worktree/site/next/"
  cp -R "$source_worktree/.duvet/." "$worktree/.duvet/"
fi

: > /tmp/coquic-validation-ready
if [ "${1:-}" = --idle ]; then
  trap 'exit 0' TERM INT
  while :; do sleep 3600; done
fi
[ "${1:-}" = --exec ] || [ "$#" -eq 0 ] || fail 'validation entrypoint argument is invalid'
if [ "${1:-}" = --exec ]; then
  shift
  [ "$#" -gt 0 ] || fail 'validation exec command is empty'
  exec "$@"
fi
[ "$#" -eq 0 ] || fail 'validation entrypoint argument is invalid'

export VALIDATION_WORKTREE="$worktree"
export VALIDATION_OUTPUT="$output"
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
                "NIX_STATE_DIR": os.environ["NIX_STATE_DIR"],
                "NIX_LOG_DIR": os.environ["NIX_LOG_DIR"],
                "NIX_CONFIG": os.environ.get("NIX_CONFIG", ""),
                "TMPDIR": os.environ["TMPDIR"],
                "XDG_CACHE_HOME": os.environ["XDG_CACHE_HOME"],
                "XDG_CONFIG_HOME": os.environ["XDG_CONFIG_HOME"],
                "ZIG_GLOBAL_CACHE_DIR": os.environ["ZIG_GLOBAL_CACHE_DIR"],
                "ZIG_LOCAL_CACHE_DIR": os.environ["ZIG_LOCAL_CACHE_DIR"],
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
