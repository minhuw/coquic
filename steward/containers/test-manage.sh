#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
manage="$script_dir/manage.sh"
mode="${1:-}"
[[ "$mode" == --config || "$mode" == --bootstrap || "$mode" == --lifecycle ]] || {
  printf 'usage: %s --config|--bootstrap|--lifecycle\n' "$0" >&2
  exit 64
}

tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

home="$tmp/home"
remote="$tmp/remote.git"
mkdir -p "$home/private/credentials" "$home/private/runtime" "$home/tasks" "$home/control-loop" "$home/worktrees"
git init -q --bare "$remote"
seed="$tmp/seed"
git init -q -b main "$seed"
git -C "$seed" config user.email test@example.invalid
git -C "$seed" config user.name 'Steward fake'
printf 'fake\n' >"$seed/README.md"
git -C "$seed" add README.md
git -C "$seed" commit -qm seed
git -C "$seed" remote add origin "$remote"
git -C "$seed" push -q origin main

for file in codex-api github dataset-sync known_hosts; do
  printf 'fake-%s\n' "$file" >"$home/private/credentials/$file"
  chmod 600 "$home/private/credentials/$file"
done
touch "$tmp/docker.sock"
touch "$tmp/steward.toml"

export COQUIC_HOME="$home"
export COQUIC_REPOSITORY="$home/repository"
export COQUIC_REMOTE_URL="$remote"
export STEWARD_EXPECTED_REMOTE=origin
export STEWARD_EXPECTED_BRANCH=main
export DOCKER_SOCKET="$tmp/docker.sock"
export CODEX_API_KEY_PATH="$home/private/credentials/codex-api"
export GITHUB_IDENTITY_PATH="$home/private/credentials/github"
export DATASET_IDENTITY_PATH="$home/private/credentials/dataset-sync"
export KNOWN_HOSTS_PATH="$home/private/credentials/known_hosts"
export STEWARD_UID="$(id -u)"
export STEWARD_GID="$(id -g)"
export STEWARD_DOCKER_GID="$(id -g)"
export STEWARD_STOP_GRACE=45
export STEWARD_MAX_PIDS=128
export STEWARD_MAX_MEMORY=134217728
export STEWARD_MAX_LOG_BYTES=1048576
export STEWARD_MAX_SCRATCH_BYTES=16777216
export STEWARD_MIN_FREE_BYTES=1024
export STEWARD_MAX_OWNED_DOCKER_BYTES=1048576
export STEWARD_RECOVERY_FREE_BYTES=2048
export STEWARD_RECOVERY_OWNED_DOCKER_BYTES=524288
export STEWARD_COMPOSE_PROJECT=coquic-steward-test
export STEWARD_CONFIG_PATH="$tmp/steward.toml"
export STEWARD_RELEASE_ID=release-config-test
export STEWARD_DAEMON_IMAGE=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export STEWARD_TASK_IMAGE=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
export STEWARD_VALIDATION_IMAGE=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
export STEWARD_MANAGE_FAKE=1
export STEWARD_FAKE_DAEMON_ID=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export STEWARD_FAKE_TASK_ID=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
export STEWARD_FAKE_VALIDATION_ID=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

case "$mode" in
  --config)
    "$manage" --config
    ! rg -n 'fake-codex-api|fake-github|fake-dataset' "$script_dir/compose.yml" "$script_dir/.env.example" >/dev/null
    rendered="$(docker compose --project-name "$STEWARD_COMPOSE_PROJECT" --file "$script_dir/compose.yml" config --format json)"
    RENDERED_COMPOSE="$rendered" python - "$STEWARD_UID" "$STEWARD_GID" "$STEWARD_DOCKER_GID" <<'PY'
import json, os, sys
value = json.loads(os.environ["RENDERED_COMPOSE"])
service = value["services"]["steward"]
environment = service["environment"]
assert len(value["services"]) == 1
assert environment["STEWARD_UID"] == sys.argv[1]
assert environment["STEWARD_GID"] == sys.argv[2]
assert environment["STEWARD_DOCKER_GID"] == sys.argv[3]
assert service["user"] == f"{sys.argv[1]}:{sys.argv[2]}"
PY
    ;;
  --bootstrap)
    "$manage" bootstrap >/dev/null
    first="$(cat "$home/private/deployment/current")"
    python - "$home/private/deployment/releases/$first.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["daemonImage"] == value["daemonImageId"]
assert value["taskImage"] == value["taskImageId"]
assert value["validationImage"] == value["validationImageId"]
assert value["daemonImage"].startswith("sha256:")
assert value["taskImage"].startswith("sha256:")
PY
    "$manage" bootstrap >/dev/null
    second="$(cat "$home/private/deployment/current")"
    [[ "$first" == "$second" && -d "$home/repository/.git" && ! -e "$home/steward.sqlite" ]]
    cp "$home/private/deployment/operation.journal" "$tmp/journal.before"
    git -C "$home/repository" worktree add --detach "$home/worktrees/unexpected" HEAD >/dev/null
    ! "$manage" bootstrap >/dev/null 2>&1
    cmp "$tmp/journal.before" "$home/private/deployment/operation.journal"
    [[ -d "$home/worktrees/unexpected" && "$(cat "$home/private/deployment/current")" == "$first" ]]
    ;;
  --lifecycle)
    "$manage" bootstrap >/dev/null
    old="$(cat "$home/private/deployment/current")"
    "$manage" start
    "$manage" status | rg 'state=running'
    "$manage" stop
    ! "$manage" status | rg 'state=running'
    "$manage" start
    export STEWARD_FAKE_DAEMON_ID=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    export STEWARD_FAKE_TASK_ID=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
    "$manage" upgrade
    candidate="$(cat "$home/private/deployment/current")"
    [[ "$candidate" != "$old" && "$(cat "$home/private/deployment/previous")" == "$old" ]]
    [[ "$(cat "$home/private/deployment/service.release")" == "$candidate" ]]
    export STEWARD_FAKE_BUSY=1
    ! "$manage" upgrade >/dev/null 2>&1
    [[ "$(cat "$home/private/deployment/current")" == "$candidate" ]]
    "$manage" upgrade --force
    forced_candidate="$(cat "$home/private/deployment/current")"
    [[ "$forced_candidate" == "$candidate" && -f "$home/private/deployment/service.running" ]]
    unset STEWARD_FAKE_BUSY
    export STEWARD_FAKE_DAEMON_ID=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    export STEWARD_FAKE_TASK_ID=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    failed="$(printf '%s\n' "$STEWARD_FAKE_DAEMON_ID:$STEWARD_FAKE_TASK_ID:$STEWARD_FAKE_VALIDATION_ID" | sha256sum | cut -c1-24)"
    export STEWARD_FAKE_HEALTH_FAIL_RELEASE="$failed"
    ! "$manage" upgrade >/dev/null 2>&1
    unset STEWARD_FAKE_HEALTH_FAIL_RELEASE
    [[ "$(cat "$home/private/deployment/current")" == "$candidate" ]]
    [[ "$(cat "$home/private/deployment/service.release")" == "$candidate" ]]
    "$manage" rollback
    [[ "$(cat "$home/private/deployment/current")" == "$old" ]]
    ;;
esac
printf 'management smoke test passed (%s; fake credentials, remote, and Docker state only)\n' "$mode"
