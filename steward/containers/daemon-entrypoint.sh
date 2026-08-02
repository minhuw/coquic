#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'steward entrypoint refused (%s)\n' "$1" >&2; exit 78; }

home="${COQUIC_HOME:-}"
repo="${COQUIC_REPOSITORY:-${home:+$home/repository}}"
socket="${DOCKER_SOCKET:-/var/run/docker.sock}"
[[ "$home" == /* && "$home" != *$'\n'* ]] || fail 'COQUIC_HOME must be absolute'
[[ "$repo" == "$home/repository" ]] || fail 'repository must be COQUIC_HOME/repository'
[[ ! -L "$home" && -d "$home" ]] || fail 'COQUIC_HOME is missing or a symlink'
[[ -d "$repo" ]] || fail 'dedicated repository clone is missing'
[[ ! -L "$repo" ]] || fail 'repository clone is a symlink'
[[ -S "$socket" ]] || fail 'Docker endpoint is not a local Unix socket'

if [[ -n "${DOCKER_HOST:-}" ]]; then
  [[ "$DOCKER_HOST" == "unix://$socket" ]] || fail 'DOCKER_HOST must match the configured local Unix socket'
else
  export DOCKER_HOST="unix://$socket"
fi

uid="${STEWARD_UID:-$(id -u)}"
gid="${STEWARD_GID:-$(id -g)}"
docker_gid="${STEWARD_DOCKER_GID:-}"
[[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ && -n "$docker_gid" && "$docker_gid" =~ ^[0-9]+$ ]] || fail 'numeric UID/GID configuration is missing'
(( $(id -u) == uid && $(id -g) == gid )) || fail 'process UID/GID does not match configured owner'
socket_group="$(stat -c '%g' -- "$socket" 2>/dev/null || true)"
[[ "$socket_group" == "$docker_gid" ]] || fail 'Docker socket group does not match configured Docker GID'
if ! id -G | tr ' ' '\n' | grep -qx "$docker_gid" && [[ "$(id -g)" != "$docker_gid" ]]; then
  fail 'process lacks configured Docker socket group'
fi

check_secret() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || fail 'Compose secret is not a regular file'
  local mode owner expected_uid="${STEWARD_UID:-}"
  mode="$(stat -c '%a' -- "$path")"
  (( (8#$mode & 022) == 0 )) || fail 'Compose secret permissions are unsafe'
  if [[ -n "$expected_uid" ]]; then
    owner="$(stat -c '%u' -- "$path")"
    [[ "$owner" == "$expected_uid" ]] || fail 'Compose secret owner is mismatched'
  fi
}
check_secret /run/secrets/codex-api-key
check_secret /run/secrets/github-identity
check_secret /run/secrets/d1-read-token
check_secret /run/secrets/r2-access-key-id
check_secret /run/secrets/r2-secret-access-key
[[ -f /etc/coquic-steward/steward.toml && -f /etc/coquic-steward/known_hosts ]] || fail 'read-only runtime configuration is missing'
stop_grace="${STEWARD_STOP_GRACE:-0}"
[[ "$stop_grace" =~ ^[0-9]+$ ]] || fail 'stop grace is not numeric'
(( stop_grace > 30 )) || fail 'stop grace is shorter than daemon shutdown grace'

if command -v docker >/dev/null 2>&1 && [[ -S "$socket" ]]; then
  expected="${STEWARD_DAEMON_IMAGE:-}"
  if [[ -n "$expected" ]]; then
    docker image inspect "$expected" >/dev/null 2>&1 || fail 'daemon image identity is not loaded'
    labels="$(docker image inspect --format '{{json .Config.Labels}}' "$expected" 2>/dev/null || true)"
    python - "$labels" <<'PY' || fail 'daemon image labels are incomplete'
import json, sys
labels = json.loads(sys.argv[1] or "{}")
required = (
    "org.opencontainers.image.source-revision",
    "org.opencontainers.image.architecture",
    "coquic.steward.runtime-protocol",
    "coquic.steward.codex-version",
    "coquic.steward.closure",
    "coquic.steward.release",
)
if any(not isinstance(labels.get(key), str) or not labels[key] for key in required):
    raise SystemExit(1)
if labels["org.opencontainers.image.architecture"] != "x86_64-linux" or labels["coquic.steward.runtime-protocol"] != "task-container-v1":
    raise SystemExit(1)
PY
  fi
fi

cd "$repo"
exec coquic-steward daemon "$@"
