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
    "daemon": ("bin/coquic-steward", "bin/docker", "bin/git", "bin/ssh"),
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

if [[ "$mode" == all || "$mode" == isolation ]]; then
  fake_home="$tmp/session-home"
  mkdir -p "$fake_home/sessions"
  chmod 700 "$fake_home" "$fake_home/sessions"
  printf 'shell_environment_policy = { inherit = "none" }\n' >"$fake_home/config.toml"
  chmod 600 "$fake_home/config.toml"

  fake_codex="$tmp/fake-codex"
  cat >"$fake_codex" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${CODEX_API_KEY:-}" == "fake-api-key-canary" ]] || exit 70
last_message=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output-last-message" ]]; then
    last_message="$2"
    shift 2
  else
    shift
  fi
done
[[ -n "$last_message" ]] || exit 64
cat >/dev/null
printf 'fake completion\n' >"$last_message"
printf '%s\n' '{"type":"thread.started","thread_id":"fake-provider"}'
SH
  chmod 755 "$fake_codex"
  raw="$tmp/codex.jsonl"
  last_message="$fake_home/last-message.md"
  python - <<'PY' | \
    CODEX_HOME="$fake_home" \
    COQUIC_STEWARD_RUN_ID="smoke-run" \
    "$root/steward/containers/task-entrypoint.sh" run \
      "$fake_codex" --output-last-message "$last_message" >"$raw"
import sys
key = b"fake-api-key-canary"
sys.stdout.buffer.write(len(key).to_bytes(4, "big") + key + b"fake prompt\n")
PY
  grep -Fxq '{"type":"thread.started","thread_id":"fake-provider"}' "$raw"
  grep -Fxq 'fake completion' "$last_message"
  [[ -s "$fake_home/wrapper-smoke-run.pid" ]] || fail "wrapper PID was not recorded"
  if rg -q 'fake-api-key-canary' "$fake_home" "$raw"; then
    fail "fake API key escaped the Codex process boundary"
  fi
  [[ ! -e "$fake_home/auth.json" ]] || fail "auth.json was persisted"

  printf 'daemon-github-canary\n' >"$tmp/daemon-only"
  printf 'other-task-canary\n' >"$tmp/other-task"
  if rg -q 'daemon-github-canary|other-task-canary' "$fake_home" "$raw"; then
    fail "daemon or other-task canary crossed the task boundary"
  fi

  sleep 60 &
  signal_target=$!
  COQUIC_STEWARD_SIGNAL=15 \
    "$root/steward/containers/task-entrypoint.sh" signal "$signal_target"
  if wait "$signal_target"; then
    fail "signal target exited successfully"
  fi
  if kill -0 "$signal_target" 2>/dev/null; then
    fail "trusted wrapper did not signal the invocation process"
  fi

  git_root="$tmp/git-root"
  git_worktree="$tmp/git-worktree"
  git init -q -b main "$git_root"
  git -C "$git_root" config user.email smoke@example.test
  git -C "$git_root" config user.name "Steward Smoke"
  printf 'base\n' >"$git_root/file.txt"
  git -C "$git_root" add file.txt
  git -C "$git_root" commit -qm base
  git -C "$git_root" worktree add -q -b smoke-worktree "$git_worktree"
  linked_git="$(sed 's/^gitdir: //' "$git_worktree/.git")"
  common_git="$(git -C "$git_worktree" rev-parse --git-common-dir)"
  GIT_DIR="$linked_git" GIT_COMMON_DIR="$common_git" \
    GIT_WORK_TREE="$git_worktree" git status --porcelain >/dev/null

  readonly="$tmp/readonly"
  mkdir "$readonly"
  printf 'history\n' >"$readonly/completed.txt"
  chmod 555 "$readonly"
  chmod 444 "$readonly/completed.txt"
  if (printf 'mutate\n' >>"$readonly/completed.txt") 2>/dev/null; then
    fail "completed history was writable"
  fi
  grep -Fxq 'history' "$readonly/completed.txt"
  chmod 755 "$readonly"
  chmod 644 "$readonly/completed.txt"

  implementation="$tmp/implementation"
  mkdir "$implementation"
  printf 'base\n' >"$implementation/file.txt"
  chmod 775 "$implementation"
  chmod 664 "$implementation/file.txt"
  printf 'implementation-write\n' >>"$implementation/file.txt"
  grep -Fxq 'implementation-write' "$implementation/file.txt"

  nix develop "$root" -c uv run --project "$root/steward" \
    python -m pytest \
      "$root/steward/tests/test_container_runtime.py" \
      "$root/steward/tests/test_codex_sessions.py" -q
fi

echo "steward container smoke test passed ($mode; fake inputs only)"
