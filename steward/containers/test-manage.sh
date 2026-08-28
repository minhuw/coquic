#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
manage="$script_dir/manage.sh"
mode="${1:-}"
[[ "$mode" == --config || "$mode" == --bootstrap || "$mode" == --init || "$mode" == --lifecycle ]] || {
  printf 'usage: %s --config|--bootstrap|--init|--lifecycle\n' "$0" >&2
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

for file in codex-api github-token git-ssh-key d1-read-token r2-access-key-id r2-secret-access-key known_hosts; do
  printf 'synthetic-%s-credential-value\n' "$file" >"$home/private/credentials/$file"
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
export GITHUB_TOKEN_PATH="$home/private/credentials/github-token"
export GIT_SSH_KEY_PATH="$home/private/credentials/git-ssh-key"
export D1_TOKEN_PATH="$home/private/credentials/d1-read-token"
export R2_ACCESS_KEY_ID_PATH="$home/private/credentials/r2-access-key-id"
export R2_SECRET_ACCESS_KEY_PATH="$home/private/credentials/r2-secret-access-key"
export GIT_KNOWN_HOSTS_PATH="$home/private/credentials/known_hosts"
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
export STEWARD_FAKE_VALIDATION_REF=coquic-steward-validation:synthetic-tag

credential_canary='credential-value'
expect_bootstrap_refusal() {
  local label="$1" expected="$2" output
  if output="$($manage bootstrap 2>&1)"; then
    printf 'expected bootstrap refusal for %s\n' "$label" >&2
    return 1
  fi
  [[ "$output" == *"$expected"* ]]
  [[ "$output" != *"$credential_canary"* ]]
}

restore_credential() {
  local path="$1" name="${1##*/}"
  if [[ -d "$path" && ! -L "$path" ]]; then
    rmdir "$path"
  elif [[ -L "$path" ]]; then
    unlink "$path"
  fi
  printf 'synthetic-%s-credential-value\n' "$name" >"$path"
  chmod 600 "$path"
}

check_credential_refusals() {
  local path
  for path in "$D1_TOKEN_PATH" "$R2_ACCESS_KEY_ID_PATH" "$R2_SECRET_ACCESS_KEY_PATH"; do
    rm -f "$path"
    expect_bootstrap_refusal "missing ${path##*/}" 'publication' || return 1
    restore_credential "$path"

    unlink "$path"
    ln -s "$CODEX_API_KEY_PATH" "$path"
    expect_bootstrap_refusal "symlink ${path##*/}" 'regular file' || return 1
    restore_credential "$path"

    rm -f "$path"
    mkdir "$path"
    expect_bootstrap_refusal "non-regular ${path##*/}" 'regular file' || return 1
    restore_credential "$path"

    chmod 620 "$path"
    expect_bootstrap_refusal "unsafe mode ${path##*/}" 'permissions are unsafe' || return 1
    chmod 600 "$path"
  done

  local original_uid="$STEWARD_UID"
  export STEWARD_UID=$((original_uid + 1))
  expect_bootstrap_refusal 'wrong owner codex-api' 'owner is mismatched' || return 1
  export STEWARD_UID="$original_uid"
}

set_fake_pair() {
  local daemon_digit="$1" task_digit="$2" daemon_hex task_hex
  daemon_hex="$(printf '%*s' 64 '' | tr ' ' "$daemon_digit")"
  task_hex="$(printf '%*s' 64 '' | tr ' ' "$task_digit")"
  export STEWARD_FAKE_DAEMON_ID="sha256:$daemon_hex"
  export STEWARD_FAKE_TASK_ID="sha256:$task_hex"
}

release_for_fake_pair() {
  printf '%s\n' "$STEWARD_FAKE_DAEMON_ID:$STEWARD_FAKE_TASK_ID:$STEWARD_FAKE_VALIDATION_ID" | sha256sum | cut -c1-24
}

check_build_source_contract() {
  local image
  ! grep -Fq 'repo_root' "$manage"
  for image in daemon task validation; do
    grep -Fq "\"\$repository#steward-$image-image\"" "$manage"
  done
}

release_snapshot() {
  find "$home/private/deployment" -maxdepth 2 -type f ! -name operation.lock -exec sha256sum {} + | sort
}

expect_build_source_refusal() {
  local label="$1" expected="$2" output before after
  before="$(release_snapshot)"
  if output="$($manage build 2>&1)"; then
    printf 'expected build refusal for %s\n' "$label" >&2
    return 1
  fi
  [[ "$output" == *"$expected"* ]]
  after="$(release_snapshot)"
  [[ "$before" == "$after" ]]
}

check_standalone_build_source_refusals() {
  local repository_backup="$tmp/repository.valid"
  mv "$home/repository" "$repository_backup"
  set_fake_pair a b
  expect_build_source_refusal missing 'canonical repository is not a Git checkout'
  mv "$repository_backup" "$home/repository"

  printf 'dirty\n' >"$home/repository/dirty"
  set_fake_pair c d
  expect_build_source_refusal dirty 'canonical repository is dirty'
  rm -f "$home/repository/dirty"

  git -C "$home/repository" checkout -q -b unexpected-branch
  set_fake_pair e f
  expect_build_source_refusal 'wrong branch' 'detached or on wrong branch'
  git -C "$home/repository" checkout -q main

  git -C "$home/repository" worktree add --detach "$home/worktrees/unexpected-build" HEAD >/dev/null
  set_fake_pair 1 2
  expect_build_source_refusal 'extra worktree' 'unexpected linked worktree'
  git -C "$home/repository" worktree remove --force "$home/worktrees/unexpected-build"
}

expect_manage_refusal() {
  local output
  if output="$($manage "$@" 2>&1)"; then
    printf 'expected management refusal for %s\n' "$*" >&2
    return 1
  fi
  [[ "$output" == *'operation refused'* ]]
}

interrupt_upgrade_and_recover() {
  local point="$1" candidate
  set_fake_pair e f
  candidate="$(release_for_fake_pair)"
  export STEWARD_FAKE_SELECTOR_INTERRUPT="$point"
  ! "$manage" upgrade >/dev/null 2>&1
  unset STEWARD_FAKE_SELECTOR_INTERRUPT
  [[ -f "$home/private/deployment/operation.journal" ]]
  "$manage" start >/dev/null
  "$manage" start >/dev/null
  [[ "$(cat "$home/private/deployment/current")" == "$candidate" ]]
  [[ "$(cat "$home/private/deployment/previous")" == "$old" ]]
  "$manage" rollback >/dev/null
  [[ "$(cat "$home/private/deployment/current")" == "$old" ]]
}

interrupt_upgrade_and_restore_before() {
  local candidate
  set_fake_pair e f
  candidate="$(release_for_fake_pair)"
  export STEWARD_FAKE_SELECTOR_INTERRUPT=after-journal
  ! "$manage" upgrade >/dev/null 2>&1
  unset STEWARD_FAKE_SELECTOR_INTERRUPT
  printf '%s\n' "$old" >"$home/private/deployment/service.release"
  "$manage" start >/dev/null
  [[ "$(cat "$home/private/deployment/current")" == "$old" ]]
  [[ "$(cat "$home/private/deployment/service.release")" == "$old" ]]
  [[ "$(cat "$home/private/deployment/current")" != "$candidate" ]]
}

selector_restore_checkpoint() {
  local candidate
  set_fake_pair e f
  candidate="$(release_for_fake_pair)"
  export STEWARD_FAKE_SELECTOR_INTERRUPT=after-journal
  ! "$manage" upgrade >/dev/null 2>&1
  unset STEWARD_FAKE_SELECTOR_INTERRUPT
  [[ "$(cat "$home/private/deployment/current")" == "$old" ]]
  [[ "$(cat "$home/private/deployment/service.release")" == "$candidate" ]]
  python - "$home/private/deployment/operation.journal" <<'PY'
import json
import sys

path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["selectorPending"] = "current"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(value, handle)
    handle.write("\n")
PY
  printf '%s\n' "$old" >"$home/private/deployment/service.release"
  "$manage" start >/dev/null
  "$manage" start >/dev/null
  [[ "$(cat "$home/private/deployment/current")" == "$old" ]]
  [[ ! -e "$home/private/deployment/previous" ]]
  [[ "$(cat "$home/private/deployment/service.release")" == "$old" ]]
}

interrupt_rollback_and_recover() {
  local point="$1" candidate
  set_fake_pair e f
  candidate="$(release_for_fake_pair)"
  "$manage" upgrade >/dev/null
  [[ "$(cat "$home/private/deployment/current")" == "$candidate" ]]
  export STEWARD_FAKE_SELECTOR_INTERRUPT="$point"
  ! "$manage" rollback >/dev/null 2>&1
  unset STEWARD_FAKE_SELECTOR_INTERRUPT
  "$manage" start >/dev/null
  "$manage" start >/dev/null
  [[ "$(cat "$home/private/deployment/current")" == "$old" ]]
  [[ "$(cat "$home/private/deployment/previous")" == "$candidate" ]]
  "$manage" upgrade >/dev/null
  [[ "$(cat "$home/private/deployment/current")" == "$candidate" ]]
}

selector_recovery_negative_fixtures() {
  local candidate journal_backup record_backup selector_backup service_backup
  set_fake_pair e f
  candidate="$(release_for_fake_pair)"
  export STEWARD_FAKE_SELECTOR_INTERRUPT=after-journal
  ! "$manage" upgrade >/dev/null 2>&1
  unset STEWARD_FAKE_SELECTOR_INTERRUPT

  journal_backup="$tmp/selector.journal.valid"
  cp "$home/private/deployment/operation.journal" "$journal_backup"
  printf '{malformed\n' >"$home/private/deployment/operation.journal"
  expect_manage_refusal start
  cp "$journal_backup" "$home/private/deployment/operation.journal"
  "$manage" start >/dev/null
  "$manage" rollback >/dev/null

  local outcome
  for outcome in success unknown missing; do
    export STEWARD_FAKE_SELECTOR_INTERRUPT=after-journal
    ! "$manage" upgrade >/dev/null 2>&1
    unset STEWARD_FAKE_SELECTOR_INTERRUPT
    cp "$home/private/deployment/operation.journal" "$journal_backup"
    python - "$home/private/deployment/operation.journal" "$outcome" <<'PY'
import json
import sys

path, outcome = sys.argv[1:]
value = json.loads(open(path, encoding="utf-8").read())
if outcome == "missing":
    value.pop("outcome", None)
else:
    value["outcome"] = outcome
with open(path, "w", encoding="utf-8") as handle:
    json.dump(value, handle)
    handle.write("\n")
PY
    expect_manage_refusal start
    cp "$journal_backup" "$home/private/deployment/operation.journal"
    "$manage" start >/dev/null
    "$manage" rollback >/dev/null
  done

  export STEWARD_FAKE_SELECTOR_INTERRUPT=after-journal
  ! "$manage" upgrade >/dev/null 2>&1
  unset STEWARD_FAKE_SELECTOR_INTERRUPT
  record_backup="$tmp/$candidate.json.valid"
  mv "$home/private/deployment/releases/$candidate.json" "$record_backup"
  expect_manage_refusal start
  mv "$record_backup" "$home/private/deployment/releases/$candidate.json"
  "$manage" start >/dev/null
  "$manage" rollback >/dev/null

  export STEWARD_FAKE_SELECTOR_INTERRUPT=after-journal
  ! "$manage" upgrade >/dev/null 2>&1
  unset STEWARD_FAKE_SELECTOR_INTERRUPT
  selector_backup="$tmp/current.valid"
  cp "$home/private/deployment/current" "$selector_backup"
  printf 'unknown-selector\n' >"$home/private/deployment/current"
  expect_manage_refusal start
  cp "$selector_backup" "$home/private/deployment/current"
  "$manage" start >/dev/null
  "$manage" rollback >/dev/null

  export STEWARD_FAKE_SELECTOR_INTERRUPT=after-journal
  ! "$manage" upgrade >/dev/null 2>&1
  unset STEWARD_FAKE_SELECTOR_INTERRUPT
  service_backup="$tmp/service.release.valid"
  cp "$home/private/deployment/service.release" "$service_backup"
  printf 'foreign-running-release\n' >"$home/private/deployment/service.release"
  expect_manage_refusal start
  cp "$service_backup" "$home/private/deployment/service.release"
  "$manage" start >/dev/null
  "$manage" rollback >/dev/null
}

case "$mode" in
  --config)
    "$manage" --config
    rendered="$(docker compose --project-name "$STEWARD_COMPOSE_PROJECT" --file "$script_dir/compose.yml" config --format json)"
    RENDERED_COMPOSE="$rendered" D1_SOURCE="$D1_TOKEN_PATH" R2_ID_SOURCE="$R2_ACCESS_KEY_ID_PATH" \
      R2_SECRET_SOURCE="$R2_SECRET_ACCESS_KEY_PATH" CODEX_SOURCE="$CODEX_API_KEY_PATH" \
      GITHUB_SOURCE="$GITHUB_TOKEN_PATH" SSH_KEY_SOURCE="$GIT_SSH_KEY_PATH" \
      KNOWN_HOSTS_SOURCE="$GIT_KNOWN_HOSTS_PATH" python - "$STEWARD_UID" "$STEWARD_GID" "$STEWARD_DOCKER_GID" <<'PY'
import json, os, sys
value = json.loads(os.environ["RENDERED_COMPOSE"])
service = value["services"]["steward"]
environment = service["environment"]
assert len(value["services"]) == 1
assert environment["STEWARD_UID"] == sys.argv[1]
assert environment["STEWARD_GID"] == sys.argv[2]
assert environment["STEWARD_DOCKER_GID"] == sys.argv[3]
assert service["user"] == f"{sys.argv[1]}:{sys.argv[2]}"
assert {
    (item["source"], item["target"]) for item in service["secrets"]
} == {
    ("codex_api_key", "/run/secrets/codex-api-key"),
    ("github_token", "/run/secrets/github-token"),
    ("git_ssh_key", "/run/secrets/git-ssh-key"),
    ("d1_token", "/run/secrets/d1-read-token"),
    ("r2_access_key_id", "/run/secrets/r2-access-key-id"),
    ("r2_secret_access_key", "/run/secrets/r2-secret-access-key"),
}
sources = value["secrets"]
assert sources["codex_api_key"]["file"] == os.environ["CODEX_SOURCE"]
assert sources["github_token"]["file"] == os.environ["GITHUB_SOURCE"]
assert sources["git_ssh_key"]["file"] == os.environ["SSH_KEY_SOURCE"]
assert service["volumes"][-1]["source"] == os.environ["KNOWN_HOSTS_SOURCE"]
assert service["volumes"][-1]["target"] == "/etc/coquic-steward/known_hosts"
assert sources["d1_token"]["file"] == os.environ["D1_SOURCE"]
assert sources["r2_access_key_id"]["file"] == os.environ["R2_ID_SOURCE"]
assert sources["r2_secret_access_key"]["file"] == os.environ["R2_SECRET_SOURCE"]
assert all("credential-value" not in json.dumps(item) for item in (value,))
assert service["read_only"] is True
assert not any(
    key.lower().startswith(("d1_", "r2_", "cloudflare", "coquic_steward_d1", "coquic_steward_public_r2"))
    for key in environment
)
PY
    ;;
  --bootstrap)
    check_build_source_contract
    unset STEWARD_MANAGE_FAKE
    expect_bootstrap_refusal 'local production remote' 'credential-free SSH'
    export STEWARD_MANAGE_FAKE=1
    check_credential_refusals
    mkdir -p "$home/private/deployment/bootstrap-repository.tmp"
    printf 'foreign\n' >"$home/private/deployment/bootstrap-repository.tmp/marker"
    printf '%s\n' '{"phase":"layout","outcome":"pending"}' >"$home/private/deployment/operation.journal"
    ! "$manage" bootstrap >/dev/null 2>&1
    [[ -f "$home/private/deployment/bootstrap-repository.tmp/marker" ]]
    printf '%s\n' '{"phase":"clone","outcome":"pending","cloneTemporary":"bootstrap-repository.tmp"}' >"$home/private/deployment/operation.journal"
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
    for remote_url in \
      'https://github.com/minhuw/coquic.git' \
      'ssh://git:password@github.com/minhuw/coquic.git' \
      'git:password@github.com:minhuw/coquic.git' \
      'ext::/bin/sh'; do
      git -C "$home/repository" remote set-url origin "$remote_url"
      unset STEWARD_MANAGE_FAKE
      expect_bootstrap_refusal "remote $remote_url" 'credential-free SSH'
      export STEWARD_MANAGE_FAKE=1
      git -C "$home/repository" remote set-url origin "$remote"
    done
    ipv6_remote='git@[::1]:org/repo.git'
    git -C "$home/repository" remote set-url origin "$ipv6_remote"
    export COQUIC_REMOTE_URL="$ipv6_remote"
    "$manage" bootstrap >/dev/null
    git -C "$home/repository" remote set-url origin "$remote"
    export COQUIC_REMOTE_URL="$remote"
    git -C "$home/repository" remote set-url origin 'git@github.com:minhuw/coquic.git'
    git -C "$home/repository" config --local remote.origin.pushurl 'file:///tmp/forbidden.git'
    export COQUIC_REMOTE_URL='git@github.com:minhuw/coquic.git'
    unset STEWARD_MANAGE_FAKE
    expect_bootstrap_refusal 'unsafe production pushurl' 'credential-free SSH'
    export STEWARD_MANAGE_FAKE=1
    git -C "$home/repository" config --local --unset-all remote.origin.pushurl
    git -C "$home/repository" remote set-url origin "$remote"
    export COQUIC_REMOTE_URL="$remote"
    second="$(cat "$home/private/deployment/current")"
    [[ "$first" == "$second" && -d "$home/repository/.git" && ! -e "$home/steward.sqlite" ]]
    check_standalone_build_source_refusals
    "$manage" build >/dev/null
    cp "$home/private/deployment/operation.journal" "$tmp/journal.before"
    git -C "$home/repository" worktree add --detach "$home/worktrees/unexpected" HEAD >/dev/null
    ! "$manage" bootstrap >/dev/null 2>&1
    cmp "$tmp/journal.before" "$home/private/deployment/operation.journal"
    [[ -d "$home/worktrees/unexpected" && "$(cat "$home/private/deployment/current")" == "$first" ]]
    ;;
  --init)
    "$manage" bootstrap >/dev/null
    [[ ! -e "$home/steward.sqlite" ]]
    expect_manage_refusal start
    "$manage" init
    marker="$home/private/deployment/store.initialized"
    [[ "$(cat "$marker")" == initialized ]]
    before="$(stat -c '%s:%Y:%i' "$marker")"
    "$manage" init >/dev/null
    [[ "$(stat -c '%s:%Y:%i' "$marker")" == "$before" ]]
    printf 'invalid\n' >"$marker"
    expect_manage_refusal init
    [[ "$(cat "$marker")" == invalid ]]
    printf 'initialized\n' >"$marker"
    "$manage" start >/dev/null
    expect_manage_refusal init
    "$manage" stop >/dev/null
    ;;
  --lifecycle)
    "$manage" bootstrap >/dev/null
    old="$(cat "$home/private/deployment/current")"
    expect_manage_refusal start
    "$manage" init >/dev/null
    "$manage" start
    "$manage" status | rg 'state=running'
    "$manage" stop
    ! "$manage" status | rg 'state=running'
    "$manage" start
    selector_restore_checkpoint
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
    export STEWARD_FAKE_BUSY=1
    ! "$manage" rollback >/dev/null 2>&1
    [[ "$(cat "$home/private/deployment/current")" == "$candidate" ]]
    [[ "$(cat "$home/private/deployment/service.release")" == "$candidate" ]]
    unset STEWARD_FAKE_BUSY
    "$manage" rollback
    [[ "$(cat "$home/private/deployment/current")" == "$old" ]]
    interrupt_upgrade_and_restore_before
    for point in after-journal after-previous after-current; do
      interrupt_upgrade_and_recover "$point"
    done
    for point in after-journal after-previous after-current; do
      interrupt_rollback_and_recover "$point"
    done
    selector_recovery_negative_fixtures
    ;;
esac
printf 'management smoke test passed (%s; fake credentials, remote, and Docker state only)\n' "$mode"
