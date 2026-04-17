#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

zig build >/dev/null

if [ ! -x ./zig-out/bin/h3-server ]; then
  echo "expected zig-out/bin/h3-server to exist after zig build" >&2
  exit 1
fi

stderr_file="$(mktemp)"
trap 'rm -f "${stderr_file}"' EXIT

if ./zig-out/bin/coquic h3-server >"${stderr_file}" 2>&1; then
  echo "expected coquic h3-server to fail after the standalone split" >&2
  exit 1
fi

if ! grep -Fq "usage: coquic [interop-server|interop-client]" "${stderr_file}"; then
  echo "expected coquic h3-server to fail via top-level coquic usage after dispatch removal" >&2
  cat "${stderr_file}" >&2
  exit 1
fi

printf 'standalone h3-server dispatch smoke passed\n'
