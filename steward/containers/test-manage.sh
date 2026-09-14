#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
manage="$script_dir/manage.sh"
mode="${1:-}"
[[ "$mode" == --config || "$mode" == --bootstrap || "$mode" == --init || "$mode" == --lifecycle ]] || {
  printf 'usage: %s --config|--bootstrap|--init|--lifecycle\n' "$0" >&2
  exit 64
}

umask 077
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

for file in d1-read-token r2-access-key-id r2-secret-access-key live-write-token; do
  printf 'synthetic-%s-credential-value\n' "$file" >"$home/private/credentials/$file"
  chmod 600 "$home/private/credentials/$file"
done
touch "$tmp/docker.sock"
cat >"$tmp/steward.toml" <<'TOML'
[steward.authentication]
github_token = "synthetic-github-token-credential-value"
proxy_url = "https://localhost.invalid/v1"
api_key = "synthetic-inline-credential-value"
TOML
chmod 600 "$tmp/steward.toml"

export COQUIC_HOME="$home"
export COQUIC_REPOSITORY="$home/repository"
export COQUIC_REMOTE_URL="$remote"
export STEWARD_EXPECTED_REMOTE=origin
export STEWARD_EXPECTED_BRANCH=main
export DOCKER_SOCKET="$tmp/docker.sock"
export D1_TOKEN_PATH="$home/private/credentials/d1-read-token"
export R2_ACCESS_KEY_ID_PATH="$home/private/credentials/r2-access-key-id"
export R2_SECRET_ACCESS_KEY_PATH="$home/private/credentials/r2-secret-access-key"
export LIVE_SNAPSHOT_TOKEN_PATH="$home/private/credentials/live-write-token"
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

check_environment_template() {
  python - "$script_dir/.env.example" <<'PY'
import re
import sys
from pathlib import Path

assignments = {}
for raw_line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    name, separator, value = line.partition("=")
    assert separator and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
    assert name not in assignments and value
    assignments[name] = value

expected = {
    "COQUIC_REMOTE_URL": "https://github.com/minhuw/coquic.git",
    "STEWARD_EXPECTED_REMOTE": "origin",
    "STEWARD_EXPECTED_BRANCH": "main",
}
assert all(assignments.get(name) == value for name, value in expected.items())
assert "GITHUB_TOKEN_PATH" not in assignments
assert "CODEX_API_KEY_PATH" not in assignments
assert not any("api_key" in name.lower() for name in assignments)
remote = assignments["COQUIC_REMOTE_URL"]
assert remote == "https://github.com/minhuw/coquic.git"
assert "GIT_SSH_KEY_PATH" not in assignments
assert "GIT_KNOWN_HOSTS_PATH" not in assignments
assert not re.search(r"://[^/?#]*:[^/?#@]+@", remote)
assert not any(marker in remote for marker in ("?", "#"))
PY
}

expect_config_refusal() {
  local expected="$1" command output
  for command in config bootstrap init start upgrade rollback; do
    if output="$("$manage" "$command" 2>&1)"; then
      printf 'expected private config refusal for %s\n' "$command" >&2
      return 1
    fi
    [[ "$output" == *"$expected"* && "$output" != *"$credential_canary"* ]]
  done
}

check_config_refusals() (
  local path="$STEWARD_CONFIG_PATH" mode
  unset STEWARD_CONFIG_PATH
  expect_config_refusal 'configuration path is required'
  export STEWARD_CONFIG_PATH=relative.toml
  expect_config_refusal 'configuration path must be absolute'
  export STEWARD_CONFIG_PATH="$path"
  mv "$path" "$path.saved"
  expect_config_refusal 'configuration must be a regular file'
  ln -s "$path.saved" "$path"
  expect_config_refusal 'configuration must be a regular file'
  unlink "$path"
  mkdir "$path"
  expect_config_refusal 'configuration must be a regular file'
  rmdir "$path"
  mv "$path.saved" "$path"
  for mode in 000 200 500 700 1600 4600; do
    chmod "$mode" "$path"
    expect_config_refusal 'configuration must have mode 0600 or 0400'
  done
  chmod 640 "$path"
  expect_config_refusal 'configuration permissions are unsafe'
  for mode in 400 600; do
    chmod "$mode" "$path"
    "$manage" config >/dev/null
  done
  export STEWARD_UID=$((STEWARD_UID + 1))
  expect_config_refusal 'configuration owner is mismatched'
)

check_daemon_config_file() (
  # Exercise the entrypoint's real metadata check without a socket or service.
  grep -Fxq 'check_secret /etc/coquic-steward/steward.toml config' "$script_dir/daemon-entrypoint.sh"
  eval "$(sed -n '/^check_secret() {$/,/^}$/p' "$script_dir/daemon-entrypoint.sh")"
  fail() { printf 'entrypoint refused (%s)\n' "$1" >&2; exit 78; }
  local uid="$STEWARD_UID" path="$STEWARD_CONFIG_PATH" mode output
  unset STEWARD_UID
  for mode in 400 600; do
    chmod "$mode" "$path"
    check_secret "$path" config
  done
  for mode in 000 200 500 700 640 1600 4600; do
    chmod "$mode" "$path"
    if output="$(check_secret "$path" config 2>&1)"; then return 1; fi
    [[ "$output" == *'mode 0600 or 0400'* && "$output" != *"$credential_canary"* ]]
  done
  chmod 600 "$path"
  ln -s "$path" "$path.link"
  if output="$(check_secret "$path.link" config 2>&1)"; then return 1; fi
  [[ "$output" == *'not a regular file'* ]]
  uid=$((uid + 1))
  if output="$(check_secret "$path" config 2>&1)"; then return 1; fi
  [[ "$output" == *'owner is mismatched'* && "$output" != *"$credential_canary"* ]]
)

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
  for path in "$D1_TOKEN_PATH" "$R2_ACCESS_KEY_ID_PATH" "$R2_SECRET_ACCESS_KEY_PATH" "$LIVE_SNAPSHOT_TOKEN_PATH"; do
    rm -f "$path"
    expect_bootstrap_refusal "missing ${path##*/}" 'publication' || return 1
    restore_credential "$path"

    unlink "$path"
    ln -s "$STEWARD_CONFIG_PATH" "$path"
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
  expect_bootstrap_refusal 'wrong owner config' 'owner is mismatched' || return 1
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

expect_bootstrap_refusal_without_release_mutation() {
  local label="$1" expected="$2" output before after
  before="$(release_snapshot)"
  if output="$($manage bootstrap 2>&1)"; then
    printf 'expected bootstrap refusal for %s\n' "$label" >&2
    return 1
  fi
  [[ "$output" == *"$expected"* ]]
  [[ "$output" != *"$credential_canary"* ]]
  after="$(release_snapshot)"
  [[ "$before" == "$after" ]]
}

expect_inline_auth_refusal() (
  local command="$1" invalid output before after variant
  invalid="$tmp/$command-invalid-auth.toml"
  before="$(release_snapshot)"
  for variant in missing empty; do
    cat >"$invalid" <<'TOML'
[steward.authentication]
proxy_url = "https://localhost.invalid/v1"
api_key = "synthetic-inline-credential-value"
TOML
    [[ "$variant" == empty ]] && printf 'github_token = ""\n' >>"$invalid"
    chmod 600 "$invalid"
    export STEWARD_CONFIG_PATH="$invalid"
    if output="$($manage "$command" 2>&1)"; then
      printf 'expected inline GitHub authentication refusal for %s (%s)\n' "$command" "$variant" >&2
      return 1
    fi
    [[ "$output" == *'valid inline GitHub token'* ]]
    [[ "$output" != *"$credential_canary"* ]]
    after="$(release_snapshot)"
    [[ "$before" == "$after" ]]
  done
)

check_inline_auth_contract() (
  python - "$script_dir/../src/coquic_steward/core" "$STEWARD_CONFIG_PATH" <<'PY_AUTH'
import sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
from github_auth import read_config_github_token, github_cli_environment, token_git_environment

token = read_config_github_token(Path(sys.argv[2]))
assert token == "synthetic-github-token-credential-value"
config = SimpleNamespace(authentication=SimpleNamespace(
    github_token=SimpleNamespace(get_secret_value=lambda: token)))
assert github_cli_environment(config)["GH_TOKEN"] == token_git_environment(token)["GH_TOKEN"]
PY_AUTH
  local original="$STEWARD_CONFIG_PATH" output
  export COQUIC_REMOTE_URL='https://github.com/minhuw/coquic.git'
  export STEWARD_CONFIG_PATH="$tmp/invalid-auth.toml"
  # Duplicate keys/tables and malformed TOML must fail without echoing either secret.
  for suffix in 'github_token = "duplicate-credential-value"' '[steward.authentication]' 'bad = "unterminated-credential-value'; do
    cat "$original" >"$STEWARD_CONFIG_PATH"
    printf '%s\n' "$suffix" >>"$STEWARD_CONFIG_PATH"
    chmod 600 "$STEWARD_CONFIG_PATH"
    if output="$("$manage" bootstrap 2>&1)"; then return 1; fi
    [[ "$output" == *'invalid Steward TOML configuration'* ]]
    [[ "$output" != *"$credential_canary"* ]]
    [[ ! -e "$home/repository" && ! -e "$home/private/deployment/current" ]]
  done
)

check_clone_https_contract() (
  # Copied management fixtures retain the shared standalone auth module layout.
  local fixture="$tmp/https-checkout"
  mkdir -p "$fixture/containers" "$fixture/src/coquic_steward/core"
  cp "$manage" "$script_dir/compose.yml" "$fixture/containers/"
  cp "$script_dir/../src/coquic_steward/core/"{github_auth,private_config}.py "$fixture/src/coquic_steward/core/"
  local manage="$fixture/containers/manage.sh"
  local git_dir="$tmp/https-bin" git_log="$tmp/https.args" real_git
  real_git="$(command -v git)"
  mkdir -p "$git_dir"
  cat >"$git_dir/git" <<SH
#!/usr/bin/env python
import json, os, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
assert "clone" in args
assert "https://github.com/minhuw/coquic.git" in args
assert "main" in args
assert os.environ["GH_TOKEN"] == "synthetic-github-token-credential-value"
assert all(os.environ["GH_TOKEN"] not in arg for arg in args)
assert any(value.endswith("gh auth git-credential") for key, value in os.environ.items() if key.startswith("GIT_CONFIG_VALUE_"))
assert "GIT_SSH_COMMAND" not in os.environ
assert not os.environ.get("GITHUB_TOKEN")
rewrites = subprocess.run(["$real_git", "config", "--get-regexp", r"^url\..*\.insteadof$"], capture_output=True)
assert rewrites.returncode == 1 and not rewrites.stdout
Path("$git_log").write_text(json.dumps(args))
sys.exit(42)
SH
  chmod 755 "$git_dir/git"
  export PATH="$git_dir:$PATH"
  if [[ "${1:-}" == default ]]; then
    unset COQUIC_REMOTE_URL
  else
    export COQUIC_REMOTE_URL='https://github.com/minhuw/coquic.git'
  fi
  export GIT_SSH_COMMAND='ssh -i /ambient-key'
  export SSH_AUTH_SOCK="$tmp/ambient-agent" GITHUB_TOKEN=ambient-token
  rm -f "$git_log"
  if "$manage" bootstrap >"$tmp/clone.output" 2>&1; then
    printf 'expected intercepted clone to fail\n' >&2
    exit 1
  fi
  [[ -s "$git_log" ]]
  ! grep -Fq "$credential_canary" "$tmp/clone.output"
  [[ ! -e "$home/repository" && ! -e "$home/private/deployment/current" && ! -d "$home/private/deployment/releases" ]]
  rm -rf "$home/private/deployment/bootstrap-repository.tmp"
  printf '%s\n' '{"phase":"layout","outcome":"pending"}' >"$home/private/deployment/operation.journal"
  chmod 600 "$home/private/deployment/operation.journal"
)

check_clone_rewrite_contract() (
  local attacker_remote="$tmp/attacker.git" attacker_seed="$tmp/attacker-seed"
  local rewrite_config="$tmp/rewrite.gitconfig" vulnerable="$tmp/vulnerable-repository"
  local canonical_remote='https://github.com/minhuw/coquic.git'
  git init -q --bare "$attacker_remote"
  git init -q -b main "$attacker_seed"
  git -C "$attacker_seed" config user.email test@example.invalid
  git -C "$attacker_seed" config user.name 'Steward attacker fixture'
  printf 'attacker\n' >"$attacker_seed/README.md"
  git -C "$attacker_seed" add README.md
  git -C "$attacker_seed" commit -qm attacker
  git -C "$attacker_seed" remote add origin "$attacker_remote"
  git -C "$attacker_seed" push -q origin main

  git config --file "$rewrite_config" "url.$attacker_remote.insteadOf" "$canonical_remote"
  unset GIT_CONFIG_NOSYSTEM
  export GIT_CONFIG_SYSTEM="$rewrite_config" GIT_CONFIG_GLOBAL="$rewrite_config"
  export GIT_CONFIG_COUNT=1
  export GIT_CONFIG_KEY_0="url.$attacker_remote.insteadOf" GIT_CONFIG_VALUE_0="$canonical_remote"
  export GIT_CONFIG_PARAMETERS="'url.$attacker_remote.insteadOf=$canonical_remote'"
  git clone -q --branch main --single-branch "$canonical_remote" "$vulnerable"
  [[ "$(cat "$vulnerable/README.md")" == attacker ]]
  [[ "$(git -C "$vulnerable" config --local --get remote.origin.url)" == "$canonical_remote" ]]
  rm -rf "$vulnerable"

  check_clone_https_contract
)

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
  [[ "$output" != *"$credential_canary"* ]]
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

# Exercise the production health-call branches independently of the fake
# deployment fixture: Store readiness is valid while the daemon is stopped.
check_health_contract() (
  unset STEWARD_MANAGE_FAKE
  local deployment="$home/private/deployment" repository="$home/repository"
  local running=0 ready=1 health_release=release-test matches=true runtime_healthy=true
  local lifecycle=running heartbeat=ok protocol=task-container-v1
  source <(sed -n '/^validate_store() {$/,/^}$/p' "$manage")
  source <(sed -n '/^verify_release_health() {$/,/^}$/p' "$manage")
  source <(sed -n '/^running_release_identity() {$/,/^}$/p' "$manage")
  die() { printf '%s\n' "$*" >&2; exit 1; }
  sleep() { :; }
  expect_health_refusal() {
    if "$@"; then
      printf 'expected health refusal: %s\n' "$*" >&2
      exit 1
    fi
  }
  compose_run() {
    if [[ "$*" == 'run --rm --no-deps --entrypoint /usr/bin/env steward coquic-steward health --store-only' ]]; then
      [[ "$ready" == 1 ]] || return 1
      printf '%s\n' '{"mode":"store-only","store":"ok"}'
    elif [[ "$*" == "exec -T --workdir $repository steward /usr/bin/env coquic-steward health" ]]; then
      [[ "$running" == 1 ]] || return 1
      printf '{"mode":"runtime","runtimeHealthy":%s,"releaseMatches":%s,"lifecycle":"%s","heartbeat":"%s","release":"%s","runtimeProtocol":"%s"}\n' \
        "$runtime_healthy" "$matches" "$lifecycle" "$heartbeat" "$health_release" "$protocol"
    else
      printf 'unexpected health invocation: %s\n' "$*" >&2
      return 1
    fi
  }
  validate_store
  expect_health_refusal verify_release_health release-test
  expect_health_refusal running_release_identity
  ready=0
  if (validate_store) 2>/dev/null; then exit 1; fi
  ready=1 running=1
  verify_release_health release-test
  [[ "$(running_release_identity)" == release-test ]]
  health_release=old-release
  expect_health_refusal verify_release_health release-test
  health_release=release-test matches=false
  expect_health_refusal verify_release_health release-test
  expect_health_refusal running_release_identity
  matches=true runtime_healthy=false
  expect_health_refusal verify_release_health release-test
  expect_health_refusal running_release_identity
  runtime_healthy=true heartbeat=stale
  expect_health_refusal verify_release_health release-test
  expect_health_refusal running_release_identity
  heartbeat=ok lifecycle=stopped
  expect_health_refusal verify_release_health release-test
  expect_health_refusal running_release_identity
  lifecycle=running protocol=wrong-protocol
  expect_health_refusal verify_release_health release-test
  expect_health_refusal running_release_identity
)

# Run the real lifecycle/journal and health parsers; intercept only image builds
# and Docker. Legacy replies deliberately fabricate the old DB-only liveness.
check_mixed_version_lifecycle() (
  source <(sed '/^command="${1:-}"/,$d' "$manage")
  script_dir="$(dirname "$manage")"
  deployment="$home/private/deployment"
  unset STEWARD_MANAGE_FAKE
  local legacy_release='' failed_release='' probe_format=runtime probe_status=1
  local events="$tmp/contract.events" original target candidate before output
  : >"$events"
  validate_socket() { :; }
  docker() { [[ "$*" == info ]]; }
  sleep() { :; }
  eval "$(declare -f build_release | sed '1s/build_release/build_fixture_release/')"
  build_release() (
    printf 'build\n' >>"$events"
    export STEWARD_MANAGE_FAKE=1
    build_fixture_release
  )
  compose_run() {
    local release
    if [[ "$1" == run || "$1" == up ]]; then
      [[ -f "$home/private/runtime/daemon-passwd" && -f "$home/private/runtime/daemon-group" ]] || return 1
    fi
    case "$*" in
      'run --rm --no-deps --entrypoint /usr/bin/env steward coquic-steward health')
        release="$STEWARD_RELEASE_ID"
        if [[ "$release" != "$legacy_release" ]]; then
          # A stopped/nonselected compatible image need not report live health.
          case "$probe_format" in
            runtime) printf '%s\n' '{"mode":"runtime","runtimeHealthy":false,"releaseMatches":false}' ;;
            store-only) printf '%s\n' '{"mode":"store-only","store":"ok"}' ;;
            malformed) printf '{malformed\n' ;;
            mistyped) printf '%s\n' '{"mode":"runtime","runtimeHealthy":"true","releaseMatches":true}' ;;
          esac
          return "$probe_status"
        fi
        ;;
      "exec -T --workdir $repository steward /usr/bin/env coquic-steward health")
        [[ -f "$deployment/service.running" ]] || return 1
        release="$(cat "$deployment/service.release")"
        if [[ "$release" != "$legacy_release" ]]; then
          local healthy=true
          [[ "$release" != "$failed_release" ]] || healthy=false
          printf '{"mode":"runtime","runtimeHealthy":%s,"releaseMatches":true,"lifecycle":"running","heartbeat":"ok","release":"%s","runtimeProtocol":"task-container-v1","quiescent":true}\n' "$healthy" "$release"
          [[ "$healthy" == true ]]
          return
        fi
        ;;
      'up -d --no-deps --force-recreate steward')
        printf 'recreate %s\n' "$STEWARD_RELEASE_ID" >>"$events"
        : >"$deployment/service.running"
        printf '%s\n' "$STEWARD_RELEASE_ID" >"$deployment/service.release"
        return ;;
      *) printf 'unexpected Compose call: %s\n' "$*" >&2; return 1 ;;
    esac
    printf '{"lifecycle":"running","heartbeat":"ok","release":"%s","runtimeProtocol":"task-container-v1","quiescent":true}\n' "$release"
  }
  refuse_unchanged() {
    local expected="$1" before event_before output
    shift
    before="$(release_snapshot)"
    event_before="$(cat "$events")"
    if output="$( ("$@") 2>&1)"; then
      printf 'expected contract refusal: %s\n' "$*" >&2
      exit 1
    fi
    [[ "$output" == *"$expected"* ]]
    [[ "$(release_snapshot)" == "$before" ]]
    [[ "$(cat "$events")" == "$event_before" ]]
  }
  original="$(selector_value current)"
  target="$(selector_value previous)"
  set_fake_pair 7 8
  candidate="$(release_for_fake_pair)"
  [[ "$candidate" != "$original" && "$candidate" != "$target" ]]

  legacy_release="$original" failed_release="$candidate"
  if verify_release_health "$original"; then exit 1; fi
  if running_release_identity; then exit 1; fi
  refuse_unchanged 'lacks the runtime health contract' upgrade_service
  refuse_unchanged 'lacks the runtime health contract' upgrade_service --force
  refuse_unchanged 'lacks the runtime health contract' rollback_service
  legacy_release="$target"
  refuse_unchanged 'lacks the runtime health contract' rollback_service
  refuse_unchanged 'lacks the runtime health contract' rollback_service
  legacy_release=''
  for probe_format in store-only malformed mistyped; do
    refuse_unchanged 'lacks the runtime health contract' upgrade_service --force
  done
  probe_format=runtime probe_status=125
  refuse_unchanged 'contract probe failed' rollback_service
  probe_status=1
  failed_release="$original"
  refuse_unchanged 'fallback runtime health is unverified' upgrade_service --force
  refuse_unchanged 'fallback runtime health is unverified' rollback_service

  # An already failed/interrupted candidate must not destructively retry a
  # legacy restore, even if the current wrapper did not initiate that upgrade.
  legacy_release="$original" failed_release=''
  journal recreate pending "$candidate"
  printf '%s\n' "$target" >"$deployment/service.release"
  restore_fixture_release() ( with_lock; restore_release "$@"; )
  refuse_unchanged 'lacks the runtime health contract' restore_fixture_release "$original"
  refuse_unchanged 'lacks the runtime health contract' restore_fixture_release "$original"
  printf '%s\n' "$original" >"$deployment/service.release"
  # Recovery validates both records before it checks the old daemon response.
  (export STEWARD_MANAGE_FAKE=1; build_fixture_release >/dev/null)
  selector_journal upgrade "$original" "$candidate" previous "$original" "$target" "$candidate" "$original"
  refuse_unchanged 'running release is unverified' start_service
  journal complete success

  # Compatible fallback: a failed new candidate is recreated once, then the
  # fallback is recreated once and verified with the real strict parser.
  legacy_release='' failed_release="$candidate"
  before="$(cat "$deployment/current" "$deployment/previous")"
  if output="$( (upgrade_service) 2>&1)"; then exit 1; fi
  [[ "$output" == *'previous release restored'* ]]
  [[ "$(cat "$deployment/current" "$deployment/previous")" == "$before" ]]
  [[ "$(cat "$deployment/service.release")" == "$original" ]]
  [[ "$(cat "$events")" == "$(printf 'build\nrecreate %s\nrecreate %s' "$candidate" "$original")" ]]
  [[ "$(cat "$deployment/operation.journal")" == '{"phase":"restore","outcome":"failure"}' ]]
  [[ "$(cat "$deployment/last-outcome.json")" == '{"operation":"upgrade","result":"failure"}' ]]

  failed_release='' probe_status=0
  (upgrade_service)
  [[ "$(selector_value current)" == "$candidate" && "$(selector_value previous)" == "$original" ]]
  # Rollback health failure restores the new current, with selectors unchanged.
  failed_release="$original"
  : >"$events"
  if output="$( (rollback_service) 2>&1)"; then exit 1; fi
  [[ "$output" == *'current release restored'* ]]
  [[ "$(selector_value current)" == "$candidate" && "$(selector_value previous)" == "$original" ]]
  [[ "$(cat "$deployment/service.release")" == "$candidate" ]]
  [[ "$(cat "$events")" == "$(printf 'recreate %s\nrecreate %s' "$original" "$candidate")" ]]
  failed_release=''
  (rollback_service)
  [[ "$(selector_value current)" == "$original" && "$(selector_value previous)" == "$candidate" ]]
  [[ "$(cat "$deployment/service.release")" == "$original" ]]
  [[ "$(cat "$deployment/operation.journal")" == '{"phase":"complete","outcome":"success"}' ]]
)

case "$mode" in
  --config)
    check_environment_template
    check_config_refusals
    check_daemon_config_file
    config_output="$("$manage" --config)"
    [[ "$config_output" != *"$credential_canary"* ]]
    printf '%s\n' "$config_output"
    [[ ! -e "$home/private/runtime/daemon-passwd" && ! -e "$home/private/runtime/daemon-group" ]]
    rendered="$(docker compose --project-name "$STEWARD_COMPOSE_PROJECT" --file "$script_dir/compose.yml" config --format json)"
    RENDERED_COMPOSE="$rendered" D1_SOURCE="$D1_TOKEN_PATH" R2_ID_SOURCE="$R2_ACCESS_KEY_ID_PATH" \
      R2_SECRET_SOURCE="$R2_SECRET_ACCESS_KEY_PATH" LIVE_SOURCE="$LIVE_SNAPSHOT_TOKEN_PATH" \
      python - "$STEWARD_UID" "$STEWARD_GID" "$STEWARD_DOCKER_GID" <<'PY'
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
    ("d1_token", "/run/secrets/d1-read-token"),
    ("r2_access_key_id", "/run/secrets/r2-access-key-id"),
    ("r2_secret_access_key", "/run/secrets/r2-secret-access-key"),
    ("live_snapshot_token", "/run/secrets/live-write-token"),
}
sources = value["secrets"]
assert "codex_api_key" not in sources
assert "git_ssh_key" not in sources
assert not any(item["target"] == "/etc/coquic-steward/known_hosts" for item in service["volumes"])
config_mounts = [item for item in service["volumes"] if item["target"] == "/etc/coquic-steward/steward.toml"]
assert len(config_mounts) == 1
assert config_mounts[0]["type"] == "bind"
assert config_mounts[0]["source"] == os.environ["STEWARD_CONFIG_PATH"]
assert config_mounts[0]["read_only"] is True
for name in ("passwd", "group"):
    mounts = [item for item in service["volumes"] if item["target"] == f"/etc/{name}"]
    assert len(mounts) == 1
    assert mounts[0]["type"] == "bind"
    assert mounts[0]["source"] == f"{os.environ['COQUIC_HOME']}/private/runtime/daemon-{name}"
    assert mounts[0]["read_only"] is True
    # Compose versions that omit false-valued fields render bind as {}.
    assert mounts[0]["bind"].get("create_host_path", False) is False
assert "github_token" not in sources
assert not any("github" in name.lower() or name == "GH_TOKEN" for name in environment)
assert "github-token" not in json.dumps(value)
assert sources["d1_token"]["file"] == os.environ["D1_SOURCE"]
assert sources["r2_access_key_id"]["file"] == os.environ["R2_ID_SOURCE"]
assert sources["r2_secret_access_key"]["file"] == os.environ["R2_SECRET_SOURCE"]
assert sources["live_snapshot_token"]["file"] == os.environ["LIVE_SOURCE"]
assert "credential-value" not in json.dumps(value)
assert not any("api_key" in name.lower() for name in environment)
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
    expect_bootstrap_refusal 'local production remote' 'credential-free GitHub HTTPS'
    check_inline_auth_contract
    check_clone_https_contract
    check_clone_https_contract default
    check_clone_rewrite_contract
    export STEWARD_MANAGE_FAKE=1
    check_credential_refusals
    [[ ! -e "$home/repository" && ! -e "$home/private/deployment/current" && ! -d "$home/private/deployment/releases" ]]
    export COQUIC_REMOTE_URL="$remote"
    mkdir -p "$home/private/deployment/bootstrap-repository.tmp"
    printf 'foreign\n' >"$home/private/deployment/bootstrap-repository.tmp/marker"
    printf '%s\n' '{"phase":"layout","outcome":"pending"}' >"$home/private/deployment/operation.journal"
    ! "$manage" bootstrap >/dev/null 2>&1
    [[ -f "$home/private/deployment/bootstrap-repository.tmp/marker" ]]
    printf '%s\n' '{"phase":"clone","outcome":"pending","cloneTemporary":"bootstrap-repository.tmp"}' >"$home/private/deployment/operation.journal"
    "$manage" bootstrap >/dev/null
    first="$(cat "$home/private/deployment/current")"
    expect_inline_auth_refusal bootstrap
    python - "$home/private/deployment/releases/$first.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["daemonImage"] == value["daemonImageId"]
assert value["taskImage"] == value["taskImageId"]
assert value["validationImage"] == value["validationImageId"]
assert value["daemonImage"].startswith("sha256:")
assert value["taskImage"].startswith("sha256:")
PY
    export COQUIC_REMOTE_URL='https://github.com/minhuw/other.git'
    expect_bootstrap_refusal_without_release_mutation 'existing clone remote mismatch' 'canonical repository remote does not match the configured remote'
    export COQUIC_REMOTE_URL="$remote"
    "$manage" bootstrap >/dev/null
    for remote_url in \
      'git@github.com:minhuw/coquic.git' \
      'https://token@github.com/minhuw/coquic.git' \
      'https://github.com.evil.invalid/minhuw/coquic.git' \
      'ssh://git@github.com/minhuw/coquic.git' \
      'git@[::1]:org/repo.git' \
      'ssh://git:password@github.com/minhuw/coquic.git' \
      'git:password@github.com:minhuw/coquic.git' \
      'ext::/bin/sh'; do
      git -C "$home/repository" remote set-url origin "$remote_url"
      unset STEWARD_MANAGE_FAKE
      expect_bootstrap_refusal "remote $remote_url" 'credential-free GitHub HTTPS'
      export STEWARD_MANAGE_FAKE=1
      git -C "$home/repository" remote set-url origin "$remote"
    done
    git -C "$home/repository" remote set-url origin 'https://github.com/minhuw/coquic.git'
    git -C "$home/repository" config --local remote.origin.pushurl 'file:///tmp/forbidden.git'
    export COQUIC_REMOTE_URL='https://github.com/minhuw/coquic.git'
    unset STEWARD_MANAGE_FAKE
    expect_bootstrap_refusal 'unsafe production pushurl' 'credential-free GitHub HTTPS'
    git -C "$home/repository" config --local remote.origin.pushurl 'https://github.com/minhuw/other.git'
    expect_bootstrap_refusal_without_release_mutation 'mismatched HTTPS pushurl' 'canonical repository remote does not match the configured remote'
    git -C "$home/repository" config --local --unset-all remote.origin.pushurl
    git -C "$home/repository" config --local --add remote.origin.url 'https://github.com/minhuw/other.git'
    expect_bootstrap_refusal_without_release_mutation 'mismatched second HTTPS remote' 'canonical repository remote does not match the configured remote'
    git -C "$home/repository" config --local --unset-all remote.origin.url
    git -C "$home/repository" config --local remote.origin.url "$remote"
    export STEWARD_MANAGE_FAKE=1
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
    check_health_contract
    "$manage" bootstrap >/dev/null
    [[ ! -e "$home/steward.sqlite" ]]
    expect_inline_auth_refusal init
    expect_manage_refusal start
    # Existing deployments predate these files; init must provision them too.
    rm "$home/private/runtime/daemon-passwd" "$home/private/runtime/daemon-group"
    "$manage" init
    [[ -f "$home/private/runtime/daemon-passwd" && -f "$home/private/runtime/daemon-group" ]]
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
    expect_inline_auth_refusal start
    [[ ! -e "$home/private/deployment/service.running" ]]
    rm "$home/private/runtime/daemon-passwd" "$home/private/runtime/daemon-group"
    "$manage" start
    [[ -f "$home/private/runtime/daemon-passwd" && -f "$home/private/runtime/daemon-group" ]]
    identity_before="$(stat -c '%i:%Y:%Z' "$home/private/runtime/daemon-"*)"
    "$manage" config >/dev/null
    "$manage" status >/dev/null
    [[ "$(stat -c '%i:%Y:%Z' "$home/private/runtime/daemon-"*)" == "$identity_before" ]]
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
    check_mixed_version_lifecycle
    ;;
esac
printf 'management smoke test passed (%s; fake credentials, remote, and Docker state only)\n' "$mode"
