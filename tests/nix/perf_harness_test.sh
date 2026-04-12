#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
script="${repo_root}/bench/run-host-matrix.sh"
flake="${repo_root}/flake.nix"
ignore_file="${repo_root}/.gitignore"

[ -f "${script}" ] || {
  echo "missing harness script: ${script}" >&2
  exit 1
}

grep -F -- '--network host' "${script}" >/dev/null || {
  echo 'missing host networking in harness script' >&2
  exit 1
}

grep -F -- '--cpuset-cpus' "${script}" >/dev/null || {
  echo 'missing CPU pinning in harness script' >&2
  exit 1
}

grep -F -- '--security-opt seccomp=unconfined' "${script}" >/dev/null || {
  echo 'missing io_uring seccomp override in harness script' >&2
  exit 1
}

grep -F -- '--cap-add IPC_LOCK' "${script}" >/dev/null || {
  echo 'missing IPC_LOCK capability in harness script' >&2
  exit 1
}

grep -F -- '--ulimit memlock=-1:-1' "${script}" >/dev/null || {
  echo 'missing memlock ulimit in harness script' >&2
  exit 1
}

grep -F -- '.bench-results/manifest.json' "${script}" >/dev/null || {
  echo 'missing aggregate manifest write in harness script' >&2
  exit 1
}

grep -F -- 'usage: bash bench/run-host-matrix.sh [--preset smoke|ci]' "${script}" >/dev/null || {
  echo 'missing ci preset in harness usage' >&2
  exit 1
}

grep -F -- 'ci)' "${script}" >/dev/null || {
  echo 'missing ci preset case in harness script' >&2
  exit 1
}

grep -F -- 'perf-image-quictls-musl' "${flake}" >/dev/null || {
  echo 'missing perf image package export in flake.nix' >&2
  exit 1
}

grep -F -- '.bench-results/' "${ignore_file}" >/dev/null || {
  echo 'missing benchmark results ignore rule' >&2
  exit 1
}

echo 'perf harness contract looks correct'
