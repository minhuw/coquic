#!/usr/bin/env bash
set -euo pipefail

mode="all"
shutdown_check=0
sync_check=0
for argument in "$@"; do
  case "$argument" in
    --images|--isolation|--planner) mode="${argument#--}" ;;
    --shutdown) shutdown_check=1 ;;
    --sync) sync_check=1 ;;
    *) echo "unknown smoke-test option: $argument" >&2; exit 64 ;;
  esac
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
container_name=""
loaded_image=""
remove_loaded_image=0

cleanup() {
  if [[ -n "$container_name" ]]; then
    docker rm -f "$container_name" >/dev/null 2>&1 || true
  fi
  if [[ -n "$loaded_image" && -d "$tmp" ]]; then
    docker run --rm --entrypoint /bin/chmod \
      --mount "type=bind,src=$tmp,dst=/host" \
      "$loaded_image" -R a+rwx /host >/dev/null 2>&1 || true
  fi
  if [[ "$remove_loaded_image" -eq 1 && -n "$loaded_image" ]]; then
    docker image rm "$loaded_image" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
  echo "smoke failure: $*" >&2
  exit 1
}

inspect_image() {
  local image="$1" kind="$2"
  local unpacked="$tmp/image-$kind" names="$tmp/$kind.names"
  mkdir -p "$unpacked"
  tar -xzf "$image" -C "$unpacked"
  find "$unpacked" -name layer.tar -exec tar -tf '{}' \; >"$names" 2>/dev/null
  python - "$unpacked" "$names" "$kind" <<'PY'
import json
import sys
from pathlib import Path

root, names_path, kind = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
manifest = json.loads((root / "manifest.json").read_text())[0]
config = json.loads((root / manifest["Config"]).read_text())["config"]
labels = config.get("Labels", {})
names = {line.lstrip("./") for line in names_path.read_text().splitlines()}

expected_entrypoint = f"{kind}-entrypoint.sh"
if not any(str(item).endswith(expected_entrypoint) for item in config.get("Entrypoint", [])):
    raise SystemExit(f"{kind} image entrypoint is missing")
for key in (
    "org.opencontainers.image.source-revision",
    "coquic.steward.runtime-protocol",
    "coquic.steward.codex-version",
    "coquic.steward.closure",
):
    if not labels.get(key):
        raise SystemExit(f"{kind} image label is missing: {key}")
if labels["coquic.steward.codex-version"] != "0.144.6":
    raise SystemExit(f"{kind} image has the wrong Codex identity")

required = {
    "task": ("bin/codex", "bin/git", "bin/pre-commit", "bin/uv", "bin/zig"),
    "daemon": ("bin/coquic-steward", "bin/docker", "bin/gh", "bin/git", "bin/ssh"),
}[kind]
for path in required:
    if path not in names:
        raise SystemExit(f"{kind} image tool is missing: {path}")
if kind == "daemon" and not any(
    path.endswith("opt/coquic/steward/src/coquic_steward/cli.py") for path in names
):
    raise SystemExit("daemon image does not contain the Steward Python package")
if kind == "task":
    forbidden = ("bin/docker", "bin/gh", "auth.json", "docker.sock", ".ssh/id_")
    for path in names:
        if any(item in path for item in forbidden):
            raise SystemExit(f"task image contains daemon authority material: {path}")
PY
}

if [[ "$mode" == all || "$mode" == images ]]; then
  mapfile -t images < <(
    nix build --no-link --print-out-paths \
      "$root#steward-daemon-image" "$root#steward-task-image"
  )
  [[ "${#images[@]}" -eq 2 ]] || fail "Nix did not return both OCI archives"
  for image in "${images[@]}"; do
    case "$(basename "$image")" in
      *daemon*) inspect_image "$image" daemon ;;
      *task*) inspect_image "$image" task ;;
      *) fail "unexpected OCI archive: $image" ;;
    esac
  done
fi

if [[ "$mode" == planner ]]; then
  nix develop "$root" -c uv run --project "$root/steward" python - <<'PY'
from pathlib import Path
from tempfile import TemporaryDirectory

from coquic_steward.execution.container_config import PlannerContainerConfig

with TemporaryDirectory() as value:
    root = Path(value)
    history = root / "history"
    private = root / "private"
    output = root / "output"
    for path in (history, private, output):
        path.mkdir()
    config = PlannerContainerConfig(
        image="coquic-steward-task",
        image_digest="sha256:" + "a" * 64,
        history_root=history,
        private_root=private,
        output_root=output,
    )
    assert config.network == "bridge"
    assert config.container_name == "coquic-steward-planner"
    assert [mount.target for mount in config.mounts] == [
        "/planner/history",
        "/planner/session",
        "/planner/output",
    ]
    assert all(mount.source not in {Path("/"), Path("/var/run/docker.sock")} for mount in config.mounts)
print("planner container boundary ok")
PY
  echo "steward container smoke test passed ($mode; fake inputs only)"
  exit 0
fi

if [[ "$mode" == all || "$mode" == isolation ]]; then
  command -v docker >/dev/null || fail "Docker CLI is unavailable"
  docker info >/dev/null 2>&1 || fail "Docker runtime is unavailable"

  task_image="$(
    nix build --no-link --print-out-paths "$root#steward-task-image"
  )"
  loaded_image="$(
    tar -xOzf "$task_image" manifest.json | \
      python -c 'import json, sys; print(json.load(sys.stdin)[0]["RepoTags"][0])'
  )"
  if ! docker image inspect "$loaded_image" >/dev/null 2>&1; then
    remove_loaded_image=1
  fi
  docker load --input "$task_image" >/dev/null
  image_digest="$(docker image inspect --format '{{.Id}}' "$loaded_image")"

  isolation_root="$tmp/isolation"
  git_root="$isolation_root/git-root"
  git_worktree="$isolation_root/worktree"
  archive="$isolation_root/archive"
  session_root="$isolation_root/sessions"
  scratch="$isolation_root/scratch"
  mkdir -p "$isolation_root" "$archive" "$session_root/session-owner/sessions" \
    "$session_root/session-other/sessions" "$scratch"

  git init -q -b main "$git_root"
  git -C "$git_root" config user.email smoke@example.test
  git -C "$git_root" config user.name "Steward Smoke"
  printf 'base\n' >"$git_root/file.txt"
  git -C "$git_root" add file.txt
  git -C "$git_root" commit -qm base
  git -C "$git_root" worktree add -q -b smoke-worktree "$git_worktree"
  linked_git="$(sed 's/^gitdir: //' "$git_worktree/.git")"
  common_git="$(cd "$git_worktree" && realpath "$(git rev-parse --git-common-dir)")"

  printf 'completed-history\n' >"$archive/completed.txt"
  printf 'owner-private\n' >"$session_root/session-owner/private.txt"
  printf 'other-private\n' >"$session_root/session-other/private.txt"
  printf 'shell_environment_policy = { inherit = "none" }\n' \
    >"$session_root/session-owner/config.toml"
  printf 'fake-github-canary\n' >"$isolation_root/daemon-github"
  printf 'fake-ssh-canary\n' >"$isolation_root/daemon-ssh"
  printf 'fake-sync-canary\n' >"$isolation_root/daemon-sync"
  printf 'fake-other-task-canary\n' >"$isolation_root/other-task"

  fake_codex="$git_worktree/fake-codex"
  cat >"$fake_codex" <<'SH'
#!/bin/bash
set -euo pipefail
key_hash="$(printf %s "${CODEX_API_KEY:-}" | sha256sum | cut -d ' ' -f 1)"
[[ "$key_hash" == "ff7a01fdf80840b3dedd96ca086b399307d29de841c75e10c2c697a429b63300" ]] || exit 70
/bin/python - <<'PY'
from pathlib import Path

try:
    daemon_environment = Path("/proc/1/environ").read_bytes()
except PermissionError:
    daemon_environment = b""
if b"CODEX_API_KEY" in daemon_environment:
    raise SystemExit(71)
PY
/bin/env -i /bin/bash -c '[[ -z "${CODEX_API_KEY:-}" ]]' || exit 72
last_message=""
block=0
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output-last-message" ]]; then
    last_message="$2"
    shift 2
  elif [[ "$1" == "--smoke-block" ]]; then
    block=1
    shift
  else
    shift
  fi
done
[[ -n "$last_message" ]] || exit 64
cat >/dev/null
printf '%s\n' '{"type":"thread.started","thread_id":"fake-provider"}'
if [[ "$block" -eq 1 ]]; then
  exec /bin/python -c 'import signal; signal.signal(signal.SIGTERM, lambda *_: exit(143)); signal.pause()'
fi

printf 'fake completion\n' >"$last_message"
SH
  chmod 755 "$fake_codex"

  docker run --rm --entrypoint /bin/bash \
    --mount "type=bind,src=$isolation_root,dst=/host" \
    "$loaded_image" -c '
      set -e
      chown 0:0 /host/sessions
      chmod 711 /host/sessions
      chown -R 10000:10000 /host/sessions/session-owner
      chmod 700 /host/sessions/session-owner /host/sessions/session-owner/sessions
      chmod 600 /host/sessions/session-owner/private.txt /host/sessions/session-owner/config.toml
      chown -R 10001:10001 /host/sessions/session-other
      chmod 700 /host/sessions/session-other /host/sessions/session-other/sessions
      chmod 600 /host/sessions/session-other/private.txt
      chgrp -R 52000 /host/worktree
      chmod -R u+rwX,g+rwX,o+rX /host/worktree
      chmod 444 /host/worktree/.git
      chgrp -R 52001 /host/scratch
      chmod 2770 /host/scratch
    '

  task_id="smoke-$(basename "$tmp" | tr -cd 'A-Za-z0-9_.-')"
  container_name="coquic-steward-task-$task_id"
  SMOKE_ROOT="$isolation_root" \
  SMOKE_TASK_ID="$task_id" \
  SMOKE_IMAGE="$loaded_image" \
  SMOKE_IMAGE_DIGEST="$image_digest" \
  SMOKE_WORKTREE="$git_worktree" \
  SMOKE_ARCHIVE="$archive" \
  SMOKE_SESSIONS="$session_root" \
  SMOKE_SCRATCH="$scratch" \
  SMOKE_GIT_DIR="$linked_git" \
  SMOKE_GIT_COMMON_DIR="$common_git" \
    nix develop "$root" -c uv run --project "$root/steward" python - <<'PY'
import os
import signal
import time
from pathlib import Path

from coquic_steward.execution.container import (
    ContainerBoundaryError,
    ExecIdentity,
    TaskContainerRuntime,
)
from coquic_steward.execution.container_config import TaskContainerConfig, TaskRole


def path(name: str) -> Path:
    return Path(os.environ[name]).resolve()


config = TaskContainerConfig(
    task_id=os.environ["SMOKE_TASK_ID"],
    image=os.environ["SMOKE_IMAGE"],
    image_digest=os.environ["SMOKE_IMAGE_DIGEST"],
    worktree=path("SMOKE_WORKTREE"),
    archive=path("SMOKE_ARCHIVE"),
    private_sessions=path("SMOKE_SESSIONS"),
    git_dir=path("SMOKE_GIT_DIR"),
    git_common_dir=path("SMOKE_GIT_COMMON_DIR"),
    scratch=path("SMOKE_SCRATCH"),
    labels={"coquic.steward.codex": "fake-codex-smoke"},
    task_write_gid=52000,
    validation_gid=52001,
)
runtime = TaskContainerRuntime(config)
runtime.ensure_started()
inspection = runtime.adopt()

mounts = {item["Destination"]: item for item in inspection.raw["Mounts"]}
assert set(mounts) == {
    "/task/worktree-ro",
    "/task/worktree",
    "/task/archive",
    "/task/session",
    "/task/scratch",
    "/task/git/linked",
    "/task/git/common",
}
assert mounts["/task/worktree-ro"]["RW"] is False
assert mounts["/task/worktree"]["RW"] is True
assert mounts["/task/archive"]["RW"] is False
assert mounts["/task/session"]["RW"] is True
assert all("docker.sock" not in item["Source"] for item in mounts.values())
assert all(inspection.labels.get(key) == value for key, value in config.labels.items())
assert "canary" not in repr(inspection.labels)


def run(role: TaskRole, uid: int, session_id: str, command: list[str]) -> bytes:
    return runtime.exec(
        role,
        session_uid=uid,
        session_id=session_id,
        command=command,
        timeout=10,
    ).stdout


def rejected(role: TaskRole, uid: int, session_id: str, command: list[str]) -> None:
    try:
        run(role, uid, session_id, command)
    except ContainerBoundaryError:
        return
    raise AssertionError(f"command unexpectedly succeeded for {role.value}")


run(
    TaskRole.reviewer,
    10000,
    "session-owner",
    ["git", "-c", "safe.directory=*", "status", "--porcelain"],
)
assert run(
    TaskRole.reviewer,
    10000,
    "session-owner",
    ["cat", "/task/archive/completed.txt"],
) == b"completed-history\n"
rejected(
    TaskRole.reviewer,
    10000,
    "session-owner",
    ["bash", "-c", "echo review >> /task/worktree/file.txt"],
)
rejected(
    TaskRole.commit_message,
    10002,
    "session-owner",
    ["bash", "-c", "echo message >> /task/worktree/file.txt"],
)
run(
    TaskRole.implementation,
    10000,
    "session-owner",
    ["bash", "-c", "echo implementation >> /task/worktree/file.txt"],
)
run(
    TaskRole.validation,
    10003,
    "session-owner",
    ["bash", "-c", "echo validation > /task/scratch/result.txt"],
)
rejected(
    TaskRole.validation,
    10003,
    "session-owner",
    ["bash", "-c", "echo validation >> /task/worktree/file.txt"],
)
rejected(
    TaskRole.implementation,
    10000,
    "session-owner",
    ["bash", "-c", "echo mutate >> /task/archive/completed.txt"],
)
assert run(
    TaskRole.implementation,
    10000,
    "session-owner",
    ["cat", "/task/session/session-owner/private.txt"],
) == b"owner-private\n"
rejected(
    TaskRole.reviewer,
    10001,
    "session-other",
    ["cat", "/task/session/session-owner/private.txt"],
)
rejected(
    TaskRole.reviewer,
    10001,
    "session-other",
    ["ls", "/task/session"],
)
for canary in ("daemon-github", "daemon-ssh", "daemon-sync", "other-task"):
    rejected(
        TaskRole.reviewer,
        10000,
        "session-owner",
        ["cat", f"/host/{canary}"],
    )
run(
    TaskRole.reviewer,
    10000,
    "session-owner",
    ["bash", "-c", "test ! -S /var/run/docker.sock"],
)


def start_fake(run_id: str, *, block: bool):
    last = f"/task/session/session-owner/{run_id}-last.md"
    command = [
        "/bin/task-entrypoint.sh",
        "run",
        "/task/worktree-ro/fake-codex",
        "--output-last-message",
        last,
    ]
    if block:
        command.append("--smoke-block")
    process = runtime.exec_stream(
        TaskRole.reviewer,
        session_uid=10000,
        session_id="session-owner",
        command=command,
        env={"COQUIC_STEWARD_RUN_ID": run_id},
        workdir="/task/worktree-ro",
    )
    key = b"fake-api-key-canary"
    process.stdin.write(len(key).to_bytes(4, "big") + key + b"fake prompt\n")
    process.stdin.close()
    return process


completed = start_fake("smoke-complete", block=False)
stdout = completed.stdout.read()
stderr = completed.stderr.read()
assert completed.wait(timeout=10) == 0, stderr.decode("utf-8", "replace")
assert stdout == b'{"type":"thread.started","thread_id":"fake-provider"}\n'
assert run(
    TaskRole.reviewer,
    10000,
    "session-owner",
    ["cat", "/task/session/session-owner/smoke-complete-last.md"],
) == b"fake completion\n"
run(
    TaskRole.reviewer,
    10000,
    "session-owner",
    ["bash", "-c", "test ! -e /task/session/session-owner/auth.json"],
)

blocked = start_fake("smoke-blocked", block=True)
assert blocked.stdout.readline() == b'{"type":"thread.started","thread_id":"fake-provider"}\n'
deadline = time.monotonic() + 5
pid_text = b""
while not pid_text and time.monotonic() < deadline:
    try:
        pid_text = run(
            TaskRole.reviewer,
            10000,
            "session-owner",
            ["cat", "/task/session/session-owner/wrapper-smoke-blocked.pid"],
        )
    except ContainerBoundaryError:
        time.sleep(0.01)
pid = int(pid_text.strip())
identity = ExecIdentity(config.container_name, "smoke-blocked", pid, 10000)
assert runtime.exec_is_live(identity)
runtime.signal(identity, signal.SIGTERM)
assert blocked.wait(timeout=10) != 0
assert not runtime.exec_is_live(identity)

scan = """
import hashlib
from pathlib import Path

expected = 'ff7a01fdf80840b3dedd96ca086b399307d29de841c75e10c2c697a429b63300'
for root in ('/task/worktree-ro', '/task/archive', '/task/session/session-owner'):
    for item in Path(root).rglob('*'):
        if not item.is_file():
            continue
        data = item.read_bytes()
        for offset in range(max(0, len(data) - 18)):
            if hashlib.sha256(data[offset:offset + 19]).hexdigest() == expected:
                raise SystemExit(73)
"""
run(
    TaskRole.reviewer,
    10000,
    "session-owner",
    ["python", "-c", scan],
)
PY
fi

if [[ "$shutdown_check" -eq 1 && -n "$container_name" ]]; then
  docker stop --time 1 "$container_name" >/dev/null
  running="$(docker inspect --format '{{.State.Running}}' "$container_name" 2>/dev/null || true)"
  [[ "$running" == "false" ]] || fail "graceful shutdown left task container running"
  [[ -f "$archive/completed.txt" ]] || fail "shutdown removed public archive state"
  shutdown_private="$tmp/shutdown-private.txt"
  docker cp "$container_name:/task/session/session-owner/private.txt" "$shutdown_private" \
    >/dev/null 2>&1 || fail "shutdown removed private session state"
  [[ -f "$shutdown_private" ]] || fail "shutdown removed private session state"
fi

if [[ "$sync_check" -eq 1 ]]; then
  [[ -f "$isolation_root/daemon-sync" ]] || fail "sync isolation fixture is missing"
  [[ ! -e "$git_worktree/daemon-sync" ]] || fail "task worktree received sync state"
fi

echo "steward container smoke test passed ($mode; fake inputs only)"
