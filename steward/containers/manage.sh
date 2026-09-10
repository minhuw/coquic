#!/usr/bin/env bash
set -euo pipefail

# Docker Compose is the outer lifecycle manager. This wrapper deliberately
# builds argv arrays and records only bounded deployment facts.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
compose_file="${COMPOSE_FILE:-$script_dir/compose.yml}"
project="${STEWARD_COMPOSE_PROJECT:-coquic-steward}"
home="${COQUIC_HOME:-}"
repository="${COQUIC_REPOSITORY:-}"
socket_path="${DOCKER_SOCKET:-/var/run/docker.sock}"
deployment=""
lock_fd=""
selected_release=""

die() { printf 'manage: operation refused (%s)\n' "$1" >&2; exit 1; }
is_abs() { [[ "$1" == /* && "$1" != *$'\n'* ]]; }
release_token() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$ ]]; }
image_id() { [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]; }
number() { [[ "$1" =~ ^[0-9]+$ ]]; }

require_paths() {
  [[ -n "$home" ]] || die 'COQUIC_HOME is required'
  is_abs "$home" || die 'COQUIC_HOME must be absolute'
  [[ ! -L "$home" ]] || die 'COQUIC_HOME must not be a symlink'
  repository="${repository:-$home/repository}"
  [[ "$repository" == "$home/repository" ]] || die 'repository must be COQUIC_HOME/repository'
  is_abs "$repository" || die 'repository must be absolute'
  is_abs "$socket_path" || die 'DOCKER_SOCKET must be absolute'
  deployment="$home/private/deployment"
  local configured_host="${DOCKER_HOST:-}"
  if [[ -n "$configured_host" ]]; then
    [[ "$configured_host" == "unix://$socket_path" ]] || die 'DOCKER_HOST must match the configured local Unix socket'
  else
    export DOCKER_HOST="unix://$socket_path"
  fi
}

validate_socket() {
  [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]] && return
  [[ -S "$socket_path" ]] || die 'Docker endpoint must be an available local Unix socket'
}

require_numeric_config() {
  local name value
  for name in STEWARD_UID STEWARD_GID STEWARD_DOCKER_GID STEWARD_STOP_GRACE STEWARD_MAX_PIDS STEWARD_MAX_MEMORY STEWARD_MAX_LOG_BYTES STEWARD_MAX_SCRATCH_BYTES STEWARD_MIN_FREE_BYTES STEWARD_MAX_OWNED_DOCKER_BYTES STEWARD_RECOVERY_FREE_BYTES STEWARD_RECOVERY_OWNED_DOCKER_BYTES; do
    value="${!name:-}"
    number "$value" || die "$name must be numeric"
    [[ "$value" != 0 ]] || die "$name must be positive"
  done
  (( STEWARD_STOP_GRACE > 30 )) || die 'STEWARD_STOP_GRACE must exceed daemon shutdown grace'
  (( STEWARD_RECOVERY_FREE_BYTES > STEWARD_MIN_FREE_BYTES )) || die 'free-space recovery threshold must be above the pressure threshold'
  (( STEWARD_RECOVERY_OWNED_DOCKER_BYTES < STEWARD_MAX_OWNED_DOCKER_BYTES )) || die 'Docker recovery threshold must be lower'
}

check_private_file() {
  local path="$1" label="$2" expected_uid="${STEWARD_UID:-}"
  [[ -n "$path" ]] || die "$label path is required"
  is_abs "$path" || die "$label path must be absolute"
  [[ -f "$path" && ! -L "$path" ]] || die "$label must be a regular file"
  local mode owner
  mode="$(stat -c '%a' -- "$path")"
  (( (8#$mode & 077) == 0 )) || die "$label permissions are unsafe"
  if [[ -n "$expected_uid" ]]; then
    owner="$(stat -c '%u' -- "$path")"
    [[ "$owner" == "$expected_uid" ]] || die "$label owner is mismatched"
  fi
}

check_host_credential() {
  local path="$1" name="$2" label="$3"
  [[ "$path" == "$home/private/credentials/$name" ]] || die "$label path must use the canonical host source"
  check_private_file "$path" "$label"
}

validate_config_file() {
  local path="${STEWARD_CONFIG_PATH:-}" mode
  [[ "${STEWARD_UID:-}" =~ ^[0-9]+$ ]] || die 'STEWARD_UID must be numeric'
  check_private_file "$path" 'Steward configuration'
  mode="$(stat -c '%a' -- "$path")"
  [[ "$mode" == 600 || "$mode" == 400 ]] || die 'Steward configuration must have mode 0600 or 0400'
}

validate_credentials() {
  validate_config_file
  check_host_credential "${GITHUB_TOKEN_PATH:-$home/private/credentials/github-token}" github-token 'GitHub API token'
  check_host_credential "${GIT_SSH_KEY_PATH:-$home/private/credentials/git-ssh-key}" git-ssh-key 'Git SSH key'
  check_private_file "${D1_TOKEN_PATH:-$home/private/credentials/d1-read-token}" 'D1 publication token'
  check_private_file "${R2_ACCESS_KEY_ID_PATH:-$home/private/credentials/r2-access-key-id}" 'R2 access-key ID'
  check_private_file "${R2_SECRET_ACCESS_KEY_PATH:-$home/private/credentials/r2-secret-access-key}" 'R2 secret access key'
  check_host_credential "${GIT_KNOWN_HOSTS_PATH:-$home/private/credentials/known_hosts}" known_hosts 'Git known-hosts'
}

git_ssh_command() {
  local key_path="${GIT_SSH_KEY_PATH:-$home/private/credentials/git-ssh-key}"
  local known_hosts_path="${GIT_KNOWN_HOSTS_PATH:-$home/private/credentials/known_hosts}"
  local escaped_key escaped_known_hosts
  printf -v escaped_key '%q' "$key_path"
  printf -v escaped_known_hosts '%q' "$known_hosts_path"
  printf 'ssh -F /dev/null -o IdentityFile=none -i %s -o IdentityFile=%s -o IdentitiesOnly=yes -o IdentityAgent=none -o UserKnownHostsFile=%s -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes' \
    "$escaped_key" "$escaped_key" "$escaped_known_hosts"
}

validate_ssh_remote() {
  if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 && "$1" == /* ]]; then
    return 0
  fi
  python - "$1" <<'PY' || die 'configured Git remote must be credential-free SSH'
import re
import sys
from urllib.parse import urlsplit

value = sys.argv[1]
if not value or any(character.isspace() or ord(character) < 0x20 for character in value):
    raise SystemExit(1)
if "://" in value:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        raise SystemExit(1)
    user = parsed.username
    if (
        parsed.scheme.lower() != "ssh"
        or not hostname
        or hostname.startswith("-")
        or re.fullmatch(r"^(?:[A-Za-z0-9.-]+|[0-9A-Fa-f:.]+)$", hostname) is None
        or (user is not None and (re.fullmatch(r"[A-Za-z0-9._-]+", user) is None or user.startswith("-")))
        or not parsed.path
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "%" in parsed.netloc
    ):
        raise SystemExit(1)
else:
    scp = re.compile(
        r"^(?:(?P<user>[A-Za-z0-9._-]+)@)?(?P<host>[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):(?P<path>[^\s\x00-\x1f]+)$"
    )
    credentials = re.compile(
        r"@(?:localhost|(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+):"
    )
    match = scp.fullmatch(value)
    if (
        match is None
        or match.group("host").startswith("-")
        or (match.group("user") is not None and match.group("user").startswith("-"))
        or "::" in value.replace(match.group("host"), "", 1)
        or credentials.search(match.group("path")) is not None
    ):
        raise SystemExit(1)
PY
}

validate_compose_static() {
  [[ -f "$compose_file" ]] || die 'Compose manifest is missing'
  grep -q '^services:' "$compose_file" || die 'Compose manifest has no services'
  [[ "$(awk '/^services:/{inside=1; next} inside && /^[^ ]/{exit} inside && /^  [A-Za-z0-9_.-]+:$/{count++} END{print count+0}' "$compose_file")" -eq 1 ]] || die 'Compose manifest must define one service'
  ! grep -Eq '(^|[[:space:]])(privileged|network_mode:[[:space:]]*host|pid:[[:space:]]*host|ipc:[[:space:]]*host)' "$compose_file" || die 'forbidden privileged or host namespace setting'
  ! grep -Eq 'docker compose[[:space:]]+down|docker (system|image|container) prune' "$compose_file" || die 'forbidden cleanup operation in Compose manifest'
  ! grep -Eq '/var/lib/docker|/root/\.docker|auth\.json' "$compose_file" || die 'forbidden Docker state or credential mount'
}

release_field() {
  local release="$1" field="$2" record="$deployment/releases/$release.json"
  [[ -f "$record" && ! -L "$record" ]] || die 'selected release record is unavailable'
  python - "$record" "$field" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]]
if not isinstance(value, str) or not value or "\n" in value:
    raise SystemExit("invalid release field")
print(value)
PY
}

select_release() {
  local release="$1" protocol validation_protocol
  release_token "$release" || die 'selected release identity is invalid'
  STEWARD_RELEASE_ID="$(release_field "$release" releaseId)"
  [[ "$STEWARD_RELEASE_ID" == "$release" ]] || die 'release record identity is mismatched'
  protocol="$(release_field "$release" runtimeProtocol)"
  [[ "$protocol" == task-container-v1 ]] || die 'release runtime protocol is incompatible'
  STEWARD_DAEMON_IMAGE="$(release_field "$release" daemonImage)"
  STEWARD_TASK_IMAGE="$(release_field "$release" taskImage)"
  STEWARD_VALIDATION_IMAGE="$(release_field "$release" validationImage)"
  image_id "$STEWARD_DAEMON_IMAGE" && image_id "$STEWARD_TASK_IMAGE" && image_id "$STEWARD_VALIDATION_IMAGE" || die 'release images are not exact local IDs'
  validation_protocol="$(release_field "$release" validationRuntime)"
  [[ "$validation_protocol" == validation-container-v1 ]] || die 'validation image identity is incompatible'
  selected_release="$release"
  export STEWARD_RELEASE_ID STEWARD_DAEMON_IMAGE STEWARD_TASK_IMAGE STEWARD_VALIDATION_IMAGE
}

compose_run() {
  if [[ -z "$selected_release" && -f "$deployment/current" ]]; then
    select_release "$(tr -d '\n' <"$deployment/current")"
  fi
  local -a args=(docker compose --project-name "$project" --file "$compose_file")
  args+=("$@")
  "${args[@]}"
}

read_release_file() {
  local path="$1" label="$2"
  [[ -f "$path" && ! -L "$path" ]] || die "$label is unavailable"
  python - "$path" <<'PY' || die "${2:-release selector} is malformed"
import re, sys
from pathlib import Path

value = Path(sys.argv[1]).read_bytes()
if not value.endswith(b"\n") or value.count(b"\n") != 1:
    raise SystemExit(1)
release = value[:-1].decode("ascii")
if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}", release) is None:
    raise SystemExit(1)
print(release)
PY
}

selector_value() {
  local name="$1"
  read_release_file "$deployment/$name" "$name selector"
}

durable_replace() {
  local source="$1" target="$2"
  python - "$source" "$target" <<'PY'
import os
import sys

source, target = sys.argv[1:]
source_fd = os.open(source, os.O_RDONLY)
try:
    os.fsync(source_fd)
finally:
    os.close(source_fd)
os.replace(source, target)
directory_fd = os.open(
    os.path.dirname(target) or ".",
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
}

durable_unlink() {
  local target="$1"
  python - "$target" <<'PY'
import os
import sys

target = sys.argv[1]
os.unlink(target)
directory_fd = os.open(
    os.path.dirname(target) or ".",
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
}

journal() {
  local phase="$1" outcome="${2:-pending}" candidate="${3:-}" clone_temp="${4:-}"
  mkdir -p -m 700 "$deployment"
  if [[ -n "$clone_temp" ]]; then
    [[ "$clone_temp" == bootstrap-repository.tmp ]] || die 'journal clone identity is invalid'
    printf '{"phase":"%s","outcome":"%s","cloneTemporary":"%s"}\n' \
      "$phase" "$outcome" "$clone_temp" >"$deployment/operation.journal.tmp"
  elif [[ -n "$candidate" ]]; then
    release_token "$candidate" || die 'journal candidate release identity is invalid'
    printf '{"phase":"%s","outcome":"%s","candidateRelease":"%s"}\n' \
      "$phase" "$outcome" "$candidate" >"$deployment/operation.journal.tmp"
  else
    printf '{"phase":"%s","outcome":"%s"}\n' "$phase" "$outcome" >"$deployment/operation.journal.tmp"
  fi
  chmod 600 "$deployment/operation.journal.tmp"
  durable_replace "$deployment/operation.journal.tmp" "$deployment/operation.journal"
}

selector_journal() {
  local operation="$1" from_release="$2" to_release="$3" selector_pending="$4"
  local before_current="$5" before_previous="$6" after_current="$7" after_previous="$8"
  release_token "$from_release" && release_token "$to_release" || die 'selector journal release identity is invalid'
  [[ "$from_release" != "$to_release" ]] || die 'selector journal identities must differ'
  [[ "$operation" == upgrade || "$operation" == rollback ]] || die 'selector journal operation is invalid'
  [[ "$selector_pending" == previous || "$selector_pending" == current ]] || die 'selector journal pending selector is invalid'
  [[ "$before_current" == "$from_release" && "$after_current" == "$to_release" ]] || die 'selector journal pair is inconsistent'
  [[ "$after_previous" == "$from_release" ]] || die 'selector journal previous identity is inconsistent'
  local before_previous_json='null'
  if [[ "$before_previous" != __NONE__ ]]; then
    release_token "$before_previous" || die 'selector journal before identity is invalid'
    [[ "$before_previous" != "$from_release" ]] || die 'selector journal before pair is ambiguous'
    before_previous_json="\"$before_previous\""
  fi
  mkdir -p -m 700 "$deployment"
  printf '{"phase":"selector","outcome":"pending","operation":"%s","fromRelease":"%s","toRelease":"%s","selectorPending":"%s","beforeCurrent":"%s","beforePrevious":%s,"afterCurrent":"%s","afterPrevious":"%s"}\n' \
    "$operation" "$from_release" "$to_release" "$selector_pending" "$before_current" "$before_previous_json" "$after_current" "$after_previous" >"$deployment/operation.journal.tmp"
  chmod 600 "$deployment/operation.journal.tmp"
  durable_replace "$deployment/operation.journal.tmp" "$deployment/operation.journal"
}

selector_interrupt() {
  local operation="$1" point="$2" requested="${STEWARD_FAKE_SELECTOR_INTERRUPT:-${STEWARD_FAKE_INTERRUPT_AFTER:-${STEWARD_FAKE_INTERRUPT:-}}}"
  case "$operation" in
    upgrade) requested="${STEWARD_FAKE_UPGRADE_INTERRUPT:-$requested}" ;;
    rollback) requested="${STEWARD_FAKE_ROLLBACK_INTERRUPT:-$requested}" ;;
  esac
  case "$requested" in
    "$point"|"${point#after-}"|"$operation-$point"|"$operation:${point#after-}"|"$operation/$point")
      die "fake selector interruption after ${point#after-}"
      ;;
  esac
}

validate_selector_state() {
  local current previous
  if [[ ! -e "$deployment/current" ]]; then
    [[ ! -e "$deployment/previous" ]] || die 'previous selector exists without current selector'
    return 0
  fi
  current="$(selector_value current)"
  select_release "$current"
  if [[ -e "$deployment/previous" ]]; then
    previous="$(selector_value previous)"
    select_release "$previous"
  fi
}

running_release_identity() {
  local health
  if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]]; then
    [[ -f "$deployment/service.running" && ! -L "$deployment/service.running" ]] || return 1
    [[ -f "$deployment/service.release" && ! -L "$deployment/service.release" ]] || return 1
    local release="$(<"$deployment/service.release")"
    release_token "$release" || return 1
    printf '%s\n' "$release"
    return 0
  fi
  health="$(compose_run exec -T --workdir "$repository" steward /usr/bin/env coquic-steward health 2>/dev/null)" || return 1
  python -c '
import json, sys
value = json.loads(sys.stdin.read())
release = value.get("release")
if value.get("runtimeHealthy") is not True or value.get("releaseMatches") is not True or value.get("lifecycle") != "running" or value.get("heartbeat") != "ok" or value.get("runtimeProtocol") != "task-container-v1":
    raise SystemExit(1)
if not isinstance(release, str) or "\n" in release:
    raise SystemExit(1)
print(release)
' <<<"$health"
}

selector_journal_fields() {
  python - "$deployment/operation.journal" <<'PY'
import json, re, sys

release_re = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\Z")
value = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(value, dict):
    raise SystemExit(1)
if value.get("phase") not in {"selector", "selector-pair"}:
    print("none")
    raise SystemExit(0)
if value.get("outcome") != "pending":
    raise SystemExit(1)
required = ("operation", "fromRelease", "toRelease", "selectorPending", "beforeCurrent", "beforePrevious", "afterCurrent", "afterPrevious")
if any(key not in value for key in required):
    raise SystemExit(1)
operation = value["operation"]
pending = value["selectorPending"]
if operation not in {"upgrade", "rollback"} or pending not in {"previous", "current"}:
    raise SystemExit(1)
for key in ("fromRelease", "toRelease", "beforeCurrent", "afterCurrent", "afterPrevious"):
    if not isinstance(value[key], str) or release_re.fullmatch(value[key]) is None:
        raise SystemExit(1)
before_previous = value["beforePrevious"]
if before_previous is not None and (not isinstance(before_previous, str) or release_re.fullmatch(before_previous) is None):
    raise SystemExit(1)
if before_previous == value["fromRelease"]:
    raise SystemExit(1)
if value["beforeCurrent"] != value["fromRelease"] or value["afterCurrent"] != value["toRelease"] or value["afterPrevious"] != value["fromRelease"]:
    raise SystemExit(1)
print("\t".join((operation, value["fromRelease"], value["toRelease"], pending, value["beforeCurrent"], before_previous or "__NONE__", value["afterCurrent"], value["afterPrevious"])))
PY
}

remove_selector() {
  local name="$1" path="$deployment/$1"
  [[ ! -e "$path" ]] && return 0
  [[ -f "$path" && ! -L "$path" ]] || die "$name selector is not removable"
  durable_unlink "$path"
}

recover_selector_commit() {
  local journal_path="$deployment/operation.journal"
  [[ ! -e "$journal_path" ]] && return 0
  [[ -f "$journal_path" && ! -L "$journal_path" ]] || die 'deployment operation journal is not a regular file'
  local fields
  fields="$(selector_journal_fields)" || die 'selector recovery journal is malformed'
  [[ "$fields" == none ]] && return 0
  local operation from_release to_release selector_pending before_current before_previous after_current after_previous
  IFS=$'\t' read -r operation from_release to_release selector_pending before_current before_previous after_current after_previous <<<"$fields"
  if [[ "$operation" == rollback && "$before_previous" != "$to_release" ]]; then
    die 'selector recovery before pair is inconsistent'
  fi
  [[ -f "$deployment/current" ]] || die 'selector recovery current selector is unavailable'
  local current previous='__NONE__'
  current="$(selector_value current)"
  if [[ -e "$deployment/previous" ]]; then
    previous="$(selector_value previous)"
  fi
  select_release "$from_release"
  select_release "$to_release"
  if [[ "$before_previous" != __NONE__ ]]; then
    select_release "$before_previous"
  fi
  [[ "$current" == "$before_current" || "$current" == "$after_current" ]] || die 'selector recovery current identity is ambiguous'
  [[ "$previous" == "$before_previous" || "$previous" == "$after_previous" ]] || die 'selector recovery previous identity is ambiguous'
  local before_match=0 partial_match=0 after_match=0
  [[ "$current" == "$before_current" && "$previous" == "$before_previous" ]] && before_match=1
  [[ "$current" == "$before_current" && "$previous" == "$after_previous" ]] && partial_match=1
  [[ "$current" == "$after_current" && "$previous" == "$after_previous" ]] && after_match=1
  local running
  select_release "$current"
  if ! running="$(running_release_identity)"; then
    die 'selector recovery running release is unverified'
  fi
  case "$selector_pending" in
    previous)
      (( before_match || partial_match )) || die 'selector recovery pair is ambiguous'
      ;;
    current)
      if (( before_match )); then
        [[ "$running" == "$from_release" ]] || die 'selector recovery pending selector is inconsistent'
      else
        (( partial_match || after_match )) || die 'selector recovery pair is ambiguous'
      fi
      ;;
  esac
  local target_current target_previous
  if [[ "$running" == "$to_release" ]]; then
    target_current="$after_current"
    target_previous="$after_previous"
  elif [[ "$running" == "$from_release" ]]; then
    target_current="$before_current"
    target_previous="$before_previous"
  else
    die 'selector recovery running release is outside the recorded pair'
  fi
  selector_journal "$operation" "$from_release" "$to_release" previous "$before_current" "$before_previous" "$after_current" "$after_previous"
  if [[ "$target_previous" == __NONE__ ]]; then
    remove_selector previous
  elif [[ "$previous" != "$target_previous" ]]; then
    write_selector previous "$target_previous"
  fi
  selector_journal "$operation" "$from_release" "$to_release" current "$before_current" "$before_previous" "$after_current" "$after_previous"
  if [[ "$current" != "$target_current" ]]; then
    write_selector current "$target_current"
  fi
  current="$(selector_value current)"
  previous='__NONE__'
  if [[ -e "$deployment/previous" ]]; then
    previous="$(selector_value previous)"
  fi
  [[ "$current" == "$target_current" && "$previous" == "$target_previous" ]] || die 'selector recovery did not persist an exact pair'
  select_release "$target_current"
  if ! running="$(running_release_identity)" || [[ "$running" != "$target_current" ]]; then
    die 'selector recovery running release changed during commit'
  fi
  journal complete success
  record_outcome "$operation" recovered
}

with_lock() {
  mkdir -p -m 700 "$deployment"
  exec {lock_fd}>"$deployment/operation.lock"
  flock -n "$lock_fd" || die 'another deployment operation is active'
  validate_selector_state
  recover_selector_commit
}

record_outcome() {
  local operation="$1" result="$2"
  printf '{"operation":"%s","result":"%s"}\n' "$operation" "$result" >"$deployment/last-outcome.tmp"
  chmod 600 "$deployment/last-outcome.tmp"
  durable_replace "$deployment/last-outcome.tmp" "$deployment/last-outcome.json"
}

write_selector() {
  local name="$1" release="$2"
  printf '%s\n' "$release" >"$deployment/$name.tmp"
  chmod 600 "$deployment/$name.tmp"
  durable_replace "$deployment/$name.tmp" "$deployment/$name"
}

commit_selector_pair() {
  local operation="$1" from_release="$2" to_release="$3" before_previous="$4"
  selector_journal "$operation" "$from_release" "$to_release" previous "$from_release" "$before_previous" "$to_release" "$from_release"
  selector_interrupt "$operation" after-journal
  write_selector previous "$from_release"
  selector_journal "$operation" "$from_release" "$to_release" current "$from_release" "$before_previous" "$to_release" "$from_release"
  selector_interrupt "$operation" after-previous
  write_selector current "$to_release"
  selector_interrupt "$operation" after-current
  journal complete success
}

release_id_from_values() {
  local daemon_id="$1" task_id="$2" validation_id="$3"
  printf '%s\n' "$daemon_id:$task_id:$validation_id" | sha256sum | cut -c1-24
}

build_release() {
  local daemon_archive task_archive validation_archive daemon_ref task_ref validation_ref daemon_id task_id validation_id release
  validate_repository
  journal build
  if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]]; then
    daemon_id="${STEWARD_FAKE_DAEMON_ID:-sha256:1111111111111111111111111111111111111111111111111111111111111111}"
    task_id="${STEWARD_FAKE_TASK_ID:-sha256:2222222222222222222222222222222222222222222222222222222222222222}"
    validation_id="${STEWARD_FAKE_VALIDATION_ID:-sha256:3333333333333333333333333333333333333333333333333333333333333333}"
    daemon_ref="$daemon_id"
    task_ref="$task_id"
    validation_ref="${STEWARD_FAKE_VALIDATION_REF:-$validation_id}"
  else
    validate_socket
    command -v nix >/dev/null || die 'Nix is unavailable for pinned image build'
    mapfile -t archives < <(nix build --no-link --print-out-paths "$repository#steward-daemon-image" "$repository#steward-task-image" "$repository#steward-validation-image")
    [[ "${#archives[@]}" -eq 3 ]] || die 'Nix did not produce all three image archives'
    daemon_archive="${archives[0]}"; task_archive="${archives[1]}"; validation_archive="${archives[2]}"
    docker load --input "$daemon_archive" >/dev/null
    docker load --input "$task_archive" >/dev/null
    docker load --input "$validation_archive" >/dev/null
    daemon_ref="$(tar -xOzf "$daemon_archive" manifest.json | python -c 'import json,sys; print(json.load(sys.stdin)[0]["RepoTags"][0])')"
    task_ref="$(tar -xOzf "$task_archive" manifest.json | python -c 'import json,sys; print(json.load(sys.stdin)[0]["RepoTags"][0])')"
    validation_ref="$(tar -xOzf "$validation_archive" manifest.json | python -c 'import json,sys; print(json.load(sys.stdin)[0]["RepoTags"][0])')"
    daemon_id="$(docker image inspect --format '{{.Id}}' "$daemon_ref")"
    task_id="$(docker image inspect --format '{{.Id}}' "$task_ref")"
    validation_id="$(docker image inspect --format '{{.Id}}' "$validation_ref")"
    validate_image_labels "$daemon_ref" daemon
    validate_image_labels "$task_ref" task
    validate_image_labels "$validation_ref" validation
    daemon_ref="$daemon_id"
    task_ref="$task_id"
  fi
  validation_ref="$validation_id"
  image_id "$daemon_id" && image_id "$task_id" && image_id "$validation_id" || die 'loaded image IDs are not immutable'
  release="$(release_id_from_values "$daemon_id" "$task_id" "$validation_id")"
  release_token "$release" || die 'release identity is invalid'
  journal build pending "$release"
  mkdir -p -m 700 "$deployment/releases"
  printf '{"releaseId":"%s","daemonImage":"%s","daemonImageId":"%s","taskImage":"%s","taskImageId":"%s","validationImage":"%s","validationImageId":"%s","validationRuntime":"validation-container-v1","architecture":"x86_64-linux","runtimeProtocol":"task-container-v1"}\n' "$release" "$daemon_ref" "$daemon_id" "$task_ref" "$task_id" "$validation_ref" "$validation_id" >"$deployment/releases/$release.json.tmp"
  chmod 600 "$deployment/releases/$release.json.tmp"
  mv -f "$deployment/releases/$release.json.tmp" "$deployment/releases/$release.json"
  printf '%s\n' "$release"
}

validate_image_labels() {
  local image="$1" kind="$2" labels
  labels="$(docker image inspect --format '{{json .Config.Labels}}' "$image")"
  python - "$labels" "$kind" <<'PY'
import json, sys
labels = json.loads(sys.argv[1])
kind = sys.argv[2]
required = (
    "org.opencontainers.image.source-revision",
    "org.opencontainers.image.revision",
    "org.opencontainers.image.architecture",
    "coquic.steward.runtime-protocol",
    "coquic.steward.codex-version",
    "coquic.steward.closure",
    "coquic.steward.release",
)
if not isinstance(labels, dict) or any(not isinstance(labels.get(key), str) or not labels[key] for key in required):
    raise SystemExit(f"{kind} image labels are incomplete")
if labels["org.opencontainers.image.architecture"] != "x86_64-linux" or labels["coquic.steward.runtime-protocol"] != "task-container-v1":
    raise SystemExit(f"{kind} image labels are incompatible")
if kind != "validation" and labels["coquic.steward.codex-version"] != "0.144.6":
    raise SystemExit(f"{kind} image Codex identity is incompatible")
if kind == "validation" and labels.get("coquic.steward.runtime") != "validation-container-v1":
    raise SystemExit("validation image runtime identity is incompatible")
if labels.get("coquic.steward.owner") != "steward":
    raise SystemExit(f"{kind} image ownership label is incompatible")
PY
}

validate_repository() {
  local repository_path="${1:-$repository}"
  [[ -d "$repository_path/.git" || -f "$repository_path/.git" ]] || die 'canonical repository is not a Git checkout'
  local remote branch dirty expected_url actual_url
  local -a remote_urls=() push_urls=() worktree_paths=()
  remote="${STEWARD_EXPECTED_REMOTE:-origin}"
  branch="${STEWARD_EXPECTED_BRANCH:-main}"
  mapfile -d '' -t remote_urls < <(
    git -C "$repository_path" config --null --get-all "remote.$remote.url" || true
  )
  ((${#remote_urls[@]} > 0)) || die 'expected Git remote is missing'
  for actual_url in "${remote_urls[@]}"; do
    validate_ssh_remote "$actual_url"
  done
  mapfile -d '' -t push_urls < <(
    git -C "$repository_path" config --null --get-all "remote.$remote.pushurl" || true
  )
  if ((${#push_urls[@]} == 0)); then
    push_urls=("${remote_urls[@]}")
  fi
  for actual_url in "${push_urls[@]}"; do
    validate_ssh_remote "$actual_url"
  done
  actual_url="${remote_urls[0]}"
  expected_url="${COQUIC_REMOTE_URL:-}"
  if [[ -n "$expected_url" && "$actual_url" != "$expected_url" ]]; then
    die 'canonical repository remote does not match the configured remote'
  fi
  [[ "$(git -C "$repository_path" symbolic-ref --quiet --short HEAD)" == "$branch" ]] || die 'repository is detached or on wrong branch'
  [[ -z "$(git -C "$repository_path" status --porcelain)" ]] || die 'canonical repository is dirty'
  mapfile -t worktree_paths < <(
    git -C "$repository_path" worktree list --porcelain | sed -n 's/^worktree //p'
  )
  [[ "${#worktree_paths[@]}" -eq 1 && "${worktree_paths[0]}" == "$repository_path" ]] || \
    die 'repository has an unexpected linked worktree'
}

recover_interrupted_clone() {
  local clone_tmp="$deployment/bootstrap-repository.tmp"
  [[ -e "$clone_tmp" ]] || return 0
  [[ ! -L "$clone_tmp" ]] || die 'interrupted clone path is a symlink'
  [[ -f "$deployment/operation.journal" ]] || die 'interrupted clone has no ownership journal'
  python - "$deployment/operation.journal" <<'PY' || die 'interrupted clone is not journal-owned'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if value == {
    "phase": "clone",
    "outcome": "pending",
    "cloneTemporary": "bootstrap-repository.tmp",
} else 1)
PY
  rm -rf -- "$clone_tmp"
}

bootstrap() {
  require_paths; require_numeric_config; validate_credentials; with_lock
  if [[ -e "$repository" ]]; then
    validate_repository
  else
    recover_interrupted_clone
  fi
  journal layout
  mkdir -p -m 700 "$home" "$home/private" "$home/private/runtime" "$home/private/codex-sessions" "$home/private/credentials" "$home/private/deployment" "$home/worktrees" "$home/tasks" "$home/control-loop"
  [[ ! -e "$repository" ]] && {
    [[ -n "${COQUIC_REMOTE_URL:-}" ]] || die 'COQUIC_REMOTE_URL is required for a fresh clone'
    validate_ssh_remote "$COQUIC_REMOTE_URL"
    [[ -d "$(dirname "$repository")" ]] || die 'repository parent is missing'
    local unexpected
    unexpected="$(find "$home" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | while read -r entry; do case "$entry" in private|worktrees|tasks|control-loop) ;; *) printf '%s\n' "$entry" ;; esac; done | head -n 1)"
    [[ -z "$unexpected" ]] || die 'repository parent contains unexpected state'
    local clone_tmp="$deployment/bootstrap-repository.tmp"
    journal clone pending '' bootstrap-repository.tmp
    env -i \
      PATH="$PATH" \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_CONFIG_COUNT=0 \
      GIT_CONFIG_PARAMETERS= \
      GIT_SSH_COMMAND="$(git_ssh_command)" \
      GIT_SSH_VARIANT=ssh \
      git clone --branch "${STEWARD_EXPECTED_BRANCH:-main}" --single-branch "$COQUIC_REMOTE_URL" "$clone_tmp" >/dev/null
    validate_repository "$clone_tmp"
    [[ ! -e "$repository" ]] || die 'repository appeared while bootstrap was cloning'
    mv -- "$clone_tmp" "$repository"
  }
  validate_repository
  local release
  release="$(build_release)"
  [[ -f "$deployment/current" ]] || write_selector current "$release"
  journal complete success; record_outcome bootstrap success
  printf 'bootstrap complete release=%s repository=verified\n' "$release"
}

config_check() {
  require_paths; require_numeric_config; validate_config_file; validate_compose_static
  printf 'compose valid service=steward socket=local-unix secrets=individual\n'
}

validate_store() {
  local marker="$deployment/store.initialized"
  if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]]; then
    [[ -f "$marker" && ! -L "$marker" ]] || die 'Store is not initialized'
    [[ "$(cat "$marker")" == initialized ]] || die 'Store validation failed'
    return 0
  fi
  local health
  health="$(compose_run run --rm --no-deps --entrypoint /usr/bin/env steward coquic-steward health --store-only 2>/dev/null)" || \
    die 'Store validation failed before start'
  python - "$health" <<'PY' || die 'Store validation failed before start'
import json
import sys

value = json.loads(sys.argv[1])
if value.get("mode") != "store-only" or value.get("store") != "ok":
    raise SystemExit(1)
PY
}

init_service() {
  require_paths; require_numeric_config; validate_credentials; validate_socket; with_lock
  [[ -f "$deployment/current" ]] || die 'bootstrap is incomplete'
  local release marker="$deployment/store.initialized"
  release="$(tr -d '\n' <"$deployment/current")"
  select_release "$release"
  journal init
  if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]]; then
    [[ ! -e "$deployment/service.running" ]] || die 'daemon is running'
    if [[ -e "$marker" ]]; then
      [[ -f "$marker" && ! -L "$marker" ]] || die 'Store validation failed'
      [[ "$(cat "$marker")" == initialized ]] || die 'Store validation failed'
    else
      printf 'initialized\n' >"$marker"
      chmod 600 "$marker"
    fi
  else
    compose_run run --rm --no-deps --entrypoint /usr/bin/env steward coquic-steward init >/dev/null || \
      die 'Store initialization failed'
  fi
  journal complete success
  record_outcome init success
  printf 'init complete release=%s store=verified\n' "$release"
}

start_service() { require_paths; validate_credentials; validate_socket; with_lock; [[ -f "$deployment/current" ]] || die 'bootstrap is incomplete'; local release; release="$(tr -d '\n' <"$deployment/current")"; select_release "$release"; validate_store; journal start; if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]]; then : >"$deployment/service.running"; printf '%s\n' "$release" >"$deployment/service.release"; else compose_run up -d steward >/dev/null; fi; journal complete success; record_outcome start success; }
stop_service() { require_paths; validate_socket; with_lock; journal stop; if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]]; then rm -f "$deployment/service.running"; else compose_run stop --timeout "${STEWARD_STOP_GRACE:-45}" steward >/dev/null; fi; journal complete success; record_outcome stop success; }

status_service() {
  require_paths
  local release='none' current='none'
  [[ -f "$deployment/current" ]] && current="$(tr -d '\n' <"$deployment/current")" && release="$current"
  printf 'release=%s current=%s pressure=unknown cleanup_pending=unknown\n' "$release" "$current"
  if command -v docker >/dev/null && [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 || -S "$socket_path" ]] && docker info >/dev/null 2>&1; then
    compose_run ps --format 'service={{.Service}} state={{.State}} health={{.Health}}' steward 2>/dev/null || true
  fi
  [[ ! -e "$deployment/service.running" ]] || printf 'service=steward state=running health=ok\n'
}

logs_service() { require_paths; validate_socket; compose_run logs --tail 100 steward; }

require_runtime_health_contract() {
  local release="$1" health status=0
  select_release "$release"
  [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]] && return 0
  # Probe the exact fallback image, not the running service or a release-record
  # assertion. This runs only the read-only CLI, never the fallback daemon.
  health="$(compose_run run --rm --no-deps --entrypoint /usr/bin/env steward coquic-steward health 2>/dev/null)" || status=$?
  [[ "$status" == 0 || "$status" == 1 ]] || die 'runtime health contract probe failed; see stopped legacy transition in CONTAINER_OPERATIONS.md'
  python -c '
import json, sys
value = json.load(sys.stdin)
raise SystemExit(0 if value.get("mode") == "runtime" and type(value.get("runtimeHealthy")) is bool and type(value.get("releaseMatches")) is bool else 1)
' <<<"$health" || die 'release lacks the runtime health contract; see stopped legacy transition in CONTAINER_OPERATIONS.md'
}

verify_release_health() {
  local release="$1" health attempt
  if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]]; then
    [[ "${STEWARD_FAKE_HEALTH_FAIL_RELEASE:-}" != "$release" ]] || return 1
    [[ -f "$deployment/service.running" && "$(tr -d '\n' <"$deployment/service.release")" == "$release" ]]
    return
  fi
  for attempt in {1..30}; do
    if health="$(compose_run exec -T --workdir "$repository" steward /usr/bin/env coquic-steward health 2>/dev/null)" && \
      python -c '
import json, sys
value = json.load(sys.stdin)
expected = sys.argv[1]
raise SystemExit(0 if value.get("runtimeHealthy") is True and value.get("releaseMatches") is True and value.get("lifecycle") == "running" and value.get("heartbeat") == "ok" and value.get("release") == expected and value.get("runtimeProtocol") == "task-container-v1" else 1)
' "$release" <<<"$health"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

recreate_release() {
  local release="$1"
  select_release "$release"
  if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]]; then
    : >"$deployment/service.running"
    printf '%s\n' "$release" >"$deployment/service.release"
  else
    compose_run up -d --no-deps --force-recreate steward >/dev/null
  fi
}

restore_release() {
  local release="$1"
  require_runtime_health_contract "$release"
  journal restore failure
  recreate_release "$release" && verify_release_health "$release" || die 'candidate failed and the previous release could not be restored'
}

require_quiescence() {
  local operation="$1" health
  if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]]; then
    [[ "${STEWARD_FAKE_BUSY:-0}" != 1 ]] || die "$operation requires proven quiescence"
  elif command -v docker >/dev/null && docker info >/dev/null 2>&1; then
    health="$(compose_run exec -T --workdir "$repository" steward /usr/bin/env coquic-steward health 2>/dev/null)" || die "$operation quiescence is ambiguous"
    python -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("quiescent") is True else 1)' <<<"$health" || die "$operation requires proven quiescence"
  else
    die "$operation quiescence is ambiguous without the daemon health API"
  fi
}

upgrade_service() {
  require_paths; require_numeric_config; validate_credentials; validate_socket; with_lock
  local force=0 arg
  for arg in "$@"; do [[ "$arg" == --force ]] && force=1 || die 'upgrade accepts only --force'; done
  [[ -f "$deployment/current" ]] || die 'bootstrap is incomplete'
  local old candidate before_previous='__NONE__'
  old="$(selector_value current)"
  require_runtime_health_contract "$old"
  verify_release_health "$old" || die 'upgrade fallback runtime health is unverified'
  if (( force == 0 )); then
    require_quiescence upgrade
  fi
  if [[ -e "$deployment/previous" ]]; then
    before_previous="$(selector_value previous)"
  fi
  candidate="$(build_release)"
  if (( force == 1 )); then
    journal forced-stop
    if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]]; then
      rm -f "$deployment/service.running"
    else
      select_release "$old"
      compose_run stop --timeout "${STEWARD_STOP_GRACE:-45}" steward >/dev/null
    fi
  fi
  journal recreate pending "$candidate"
  if ! recreate_release "$candidate" || ! verify_release_health "$candidate"; then
    restore_release "$old"
    record_outcome upgrade failure
    die 'candidate release failed health verification; previous release restored'
  fi
  if [[ "$candidate" != "$old" ]]; then
    commit_selector_pair upgrade "$old" "$candidate" "$before_previous"
  else
    journal complete success
  fi
  record_outcome upgrade success
}

rollback_service() {
  require_paths; require_numeric_config; validate_credentials; validate_socket; with_lock
  [[ -f "$deployment/previous" ]] || die 'no previous verified release is recorded'
  local previous current before_previous
  previous="$(selector_value previous)"
  current="$(selector_value current)"
  before_previous="$previous"
  require_runtime_health_contract "$previous"
  require_runtime_health_contract "$current"
  verify_release_health "$current" || die 'rollback fallback runtime health is unverified'
  require_quiescence rollback
  journal rollback
  if ! recreate_release "$previous" || ! verify_release_health "$previous"; then
    restore_release "$current"
    record_outcome rollback failure
    die 'rollback release failed health verification; current release restored'
  fi
  commit_selector_pair rollback "$current" "$previous" "$before_previous"
  record_outcome rollback success
}

usage() { printf 'usage: %s {config|bootstrap|build|init|start|stop|status|logs|upgrade [--force]|rollback}\n' "$0"; }

command="${1:-}"
shift || true
case "$command" in
  config|--config) config_check ;;
  build) require_paths; require_numeric_config; with_lock; build_release >/dev/null ;;
  bootstrap) bootstrap ;;
  init) init_service ;;
  start) start_service ;;
  stop) stop_service ;;
  status) status_service ;;
  logs) logs_service ;;
  upgrade) upgrade_service "$@" ;;
  rollback) rollback_service ;;
  *) usage >&2; exit 64 ;;
esac
