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

grep -F -- 'PERF_BINARY_ATTR' "${script}" >/dev/null || {
  echo 'missing binary attr override in harness script' >&2
  exit 1
}

grep -F -- 'coquic-perf-quictls-musl' "${script}" >/dev/null || {
  echo 'missing direct perf binary default in harness script' >&2
  exit 1
}

grep -F -- 'taskset -c "${server_cpus}"' "${script}" >/dev/null || {
  echo 'missing server CPU pinning in harness script' >&2
  exit 1
}

grep -F -- 'taskset -c "${client_cpus}"' "${script}" >/dev/null || {
  echo 'missing client CPU pinning in harness script' >&2
  exit 1
}

grep -F -- 'tests/fixtures/quic-server-cert.pem' "${script}" >/dev/null || {
  echo 'missing server certificate path in harness script' >&2
  exit 1
}

grep -F -- 'tests/fixtures/quic-server-key.pem' "${script}" >/dev/null || {
  echo 'missing server key path in harness script' >&2
  exit 1
}

grep -F -- 'environment.txt' "${script}" >/dev/null || {
  echo 'missing environment snapshot in harness script' >&2
  exit 1
}

if grep -F -- 'docker ' "${script}" >/dev/null; then
  echo 'unexpected docker usage in direct harness script' >&2
  exit 1
fi

if grep -F -- '--network host' "${script}" >/dev/null; then
  echo 'unexpected host-network docker flag in direct harness script' >&2
  exit 1
fi

if grep -F -- '--cap-add IPC_LOCK' "${script}" >/dev/null; then
  echo 'unexpected container capability override in direct harness script' >&2
  exit 1
fi

grep -F -- 'usage: bash bench/run-host-matrix.sh [--preset smoke|ci]' "${script}" >/dev/null || {
  echo 'missing ci preset in harness usage' >&2
  exit 1
}

grep -F -- 'ci)' "${script}" >/dev/null || {
  echo 'missing ci preset case in harness script' >&2
  exit 1
}

smoke_runs=(
  '"socket bulk download 65536 0 0 1 1 1 0ms 5s"'
  '"socket rr stay 32 48 32 1 1 4 0ms 5s"'
  '"socket crr stay 24 24 8 1 2 1 0ms 5s"'
)

for run in "${smoke_runs[@]}"; do
  grep -F -- "${run}" "${script}" >/dev/null || {
    echo "missing smoke run tuple: ${run}" >&2
    exit 1
  }
done

ci_runs=(
  '"socket bulk download 0 1048576 none 4 1 1 5s 60s"'
  '"socket rr stay 32 32 none 1 256 16 5s 45s"'
  '"socket crr stay 32 32 none 1 512 1 5s 45s"'
)

for run in "${ci_runs[@]}"; do
  grep -F -- "${run}" "${script}" >/dev/null || {
    echo "missing ci run tuple: ${run}" >&2
    exit 1
  }
done

if grep -F -- '"io_uring ' "${script}" >/dev/null; then
  echo 'unexpected io_uring run tuple in harness script' >&2
  exit 1
fi

grep -F -- 'coquic-perf-quictls-musl' "${flake}" >/dev/null || {
  echo 'missing direct perf package export in flake.nix' >&2
  exit 1
}

grep -F -- '.bench-results/' "${ignore_file}" >/dev/null || {
  echo 'missing benchmark results ignore rule' >&2
  exit 1
}

echo 'perf harness contract looks correct'
