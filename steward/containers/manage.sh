#!/usr/bin/env bash
set -euo pipefail

# Docker Compose is the outer lifecycle manager. This wrapper deliberately
# builds argv arrays and records only bounded deployment facts.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/../.." && pwd -P)"
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

validate_credentials() {
  check_private_file "${CODEX_API_KEY_PATH:-$home/private/credentials/codex-api}" 'Codex API credential'
  check_private_file "${GITHUB_IDENTITY_PATH:-$home/private/credentials/github}" 'GitHub integration identity'
  check_private_file "${DATASET_IDENTITY_PATH:-$home/private/credentials/dataset-sync}" 'dataset publication identity'
  check_private_file "${KNOWN_HOSTS_PATH:-$home/private/credentials/known_hosts}" 'known-hosts'
}

validate_compose_static() {
  [[ -f "$compose_file" ]] || die 'Compose manifest is missing'
  grep -q '^services:' "$compose_file" || die 'Compose manifest has no services'
  [[ "$(awk '/^services:/{inside=1; next} inside && /^[^ ]/{exit} inside && /^  [A-Za-z0-9_.-]+:$/{count++} END{print count+0}' "$compose_file")" -eq 1 ]] || die 'Compose manifest must define one service'
  ! grep -Eq '(^|[[:space:]])(privileged|network_mode:[[:space:]]*host|pid:[[:space:]]*host|ipc:[[:space:]]*host)' "$compose_file" || die 'forbidden privileged or host namespace setting'
  ! grep -Eq 'docker compose[[:space:]]+down|docker (system|image|container) prune' "$compose_file" || die 'forbidden cleanup operation in Compose manifest'
  ! grep -Eq '/var/lib/docker|/root/\.docker|auth\.json' "$compose_file" || die 'forbidden Docker state or credential mount'
}

compose_argv() {
  printf '%s\n' docker compose --project-name "$project" --file "$compose_file"
}

release_field() {
  local release="$1" field="$2" record="$deployment/releases/$release.json"
  [[ -f "$record" ]] || die 'selected release record is unavailable'
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
  mv -f "$deployment/operation.journal.tmp" "$deployment/operation.journal"
}

with_lock() {
  mkdir -p -m 700 "$deployment"
  exec {lock_fd}>"$deployment/operation.lock"
  flock -n "$lock_fd" || die 'another deployment operation is active'
}

record_outcome() {
  local operation="$1" result="$2"
  printf '{"operation":"%s","result":"%s"}\n' "$operation" "$result" >"$deployment/last-outcome.tmp"
  chmod 600 "$deployment/last-outcome.tmp"
  mv -f "$deployment/last-outcome.tmp" "$deployment/last-outcome.json"
}

write_selector() {
  local name="$1" release="$2"
  printf '%s\n' "$release" >"$deployment/$name.tmp"
  chmod 600 "$deployment/$name.tmp"
  mv -f "$deployment/$name.tmp" "$deployment/$name"
}

release_id_from_values() {
  local daemon_id="$1" task_id="$2" validation_id="$3"
  printf '%s\n' "$daemon_id:$task_id:$validation_id" | sha256sum | cut -c1-24
}

build_release() {
  local daemon_archive task_archive validation_archive daemon_ref task_ref validation_ref daemon_id task_id validation_id release
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
    mapfile -t archives < <(nix build --no-link --print-out-paths "$repo_root#steward-daemon-image" "$repo_root#steward-task-image" "$repo_root#steward-validation-image")
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
  local -a worktree_paths=()
  remote="${STEWARD_EXPECTED_REMOTE:-origin}"
  branch="${STEWARD_EXPECTED_BRANCH:-main}"
  actual_url="$(git -C "$repository_path" config --get "remote.$remote.url" || true)"
  [[ -n "$actual_url" ]] || die 'expected Git remote is missing'
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
    [[ -d "$(dirname "$repository")" ]] || die 'repository parent is missing'
    local unexpected
    unexpected="$(find "$home" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | while read -r entry; do case "$entry" in private|worktrees|tasks|control-loop) ;; *) printf '%s\n' "$entry" ;; esac; done | head -n 1)"
    [[ -z "$unexpected" ]] || die 'repository parent contains unexpected state'
    local clone_tmp="$deployment/bootstrap-repository.tmp"
    journal clone pending '' bootstrap-repository.tmp
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
  require_paths; require_numeric_config; validate_compose_static
  printf 'compose valid service=steward socket=local-unix secrets=individual\n'
}

start_service() { require_paths; validate_socket; with_lock; [[ -f "$deployment/current" ]] || die 'bootstrap is incomplete'; local release; release="$(tr -d '\n' <"$deployment/current")"; select_release "$release"; journal start; if [[ "${STEWARD_MANAGE_FAKE:-0}" == 1 ]]; then : >"$deployment/service.running"; printf '%s\n' "$release" >"$deployment/service.release"; else compose_run up -d steward >/dev/null; fi; journal complete success; record_outcome start success; }
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
raise SystemExit(0 if value.get("lifecycle") == "running" and value.get("heartbeat") == "ok" and value.get("release") == expected and value.get("runtimeProtocol") == "task-container-v1" else 1)
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
  require_paths; require_numeric_config; validate_socket; with_lock
  local force=0 arg
  for arg in "$@"; do [[ "$arg" == --force ]] && force=1 || die 'upgrade accepts only --force'; done
  [[ -f "$deployment/current" ]] || die 'bootstrap is incomplete'
  if (( force == 0 )); then
    require_quiescence upgrade
  fi
  local old candidate
  old="$(tr -d '\n' <"$deployment/current")"
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
    write_selector previous "$old"
  fi
  write_selector current "$candidate"
  journal complete success; record_outcome upgrade success
}

rollback_service() {
  require_paths; require_numeric_config; validate_socket; with_lock
  [[ -f "$deployment/previous" ]] || die 'no previous verified release is recorded'
  local previous current
  previous="$(tr -d '\n' <"$deployment/previous")"
  current="$(tr -d '\n' <"$deployment/current")"
  [[ -f "$deployment/releases/$previous.json" ]] || die 'previous release record is unavailable'
  require_quiescence rollback
  journal rollback
  if ! recreate_release "$previous" || ! verify_release_health "$previous"; then
    restore_release "$current"
    record_outcome rollback failure
    die 'rollback release failed health verification; current release restored'
  fi
  write_selector previous "$current"
  write_selector current "$previous"
  journal complete success; record_outcome rollback success
}

usage() { printf 'usage: %s {config|bootstrap|build|start|stop|status|logs|upgrade [--force]|rollback}\n' "$0"; }

command="${1:-}"
shift || true
case "$command" in
  config|--config) config_check ;;
  build) require_paths; require_numeric_config; with_lock; build_release >/dev/null ;;
  bootstrap) bootstrap ;;
  start) start_service ;;
  stop) stop_service ;;
  status) status_service ;;
  logs) logs_service ;;
  upgrade) upgrade_service "$@" ;;
  rollback) rollback_service ;;
  *) usage >&2; exit 64 ;;
esac
