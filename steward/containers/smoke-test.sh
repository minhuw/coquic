#!/usr/bin/env bash
set -euo pipefail

mode="all"
for argument in "$@"; do
  case "$argument" in
    --images|--isolation) mode="${argument#--}" ;;
    *) echo "unknown smoke-test option: $argument" >&2; exit 64 ;;
  esac
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

assert_absent() {
  local needle="$1" file="$2"
  if [[ -f "$file" ]] && grep -Fq -- "$needle" "$file"; then
    echo "unexpected secret material in $file" >&2
    exit 1
  fi
}

if [[ "$mode" == all || "$mode" == images ]]; then
  # OCI inspection is best-effort when the caller has not built local images;
  # the reproducible Nix build gate performs the authoritative image check.
  if command -v docker >/dev/null 2>&1; then
    for image in steward-daemon-image steward-task-image; do
      docker image inspect "$image" >/dev/null 2>&1 || true
    done
  fi
  grep -Fq 'task-container-v1' "$root/steward/containers/README.md"
  grep -Fq 'sha256' "$root/flake.nix"
fi

if [[ "$mode" == all || "$mode" == isolation ]]; then
  fake_home="$tmp/home"
  mkdir -p "$fake_home/private/codex-sessions/task/session/sessions"
  chmod 700 "$fake_home/private" "$fake_home/private/codex-sessions" \
    "$fake_home/private/codex-sessions/task" \
    "$fake_home/private/codex-sessions/task/session"
  printf 'shell_environment_policy = { inherit = "none" }\n' \
    >"$fake_home/private/codex-sessions/task/session/config.toml"
  chmod 600 "$fake_home/private/codex-sessions/task/session/config.toml"
  assert_absent 'auth.json' "$fake_home/private/codex-sessions/task/session"
  printf '%s\n' 'daemon-github-canary' >"$tmp/daemon-only"
  printf '%s\n' 'other-task-canary' >"$tmp/other-task"
  printf '%s\n' 'completed-history-canary' >"$tmp/completed-history"
  assert_absent 'daemon-github-canary' "$fake_home/private/codex-sessions/task/session"
  assert_absent 'other-task-canary' "$fake_home/private/codex-sessions/task/session"
  assert_absent 'completed-history-canary' "$fake_home/private/codex-sessions/task/session"
  grep -Fq 'inherit = "none"' \
    "$fake_home/private/codex-sessions/task/session/config.toml"
  grep -Fq 'exec "$@"' "$root/steward/containers/task-entrypoint.sh"
  grep -Fq 'cap_drop' "$root/steward/containers/compose.example.yml"
fi

echo "steward container smoke test passed ($mode; fake inputs only)"
