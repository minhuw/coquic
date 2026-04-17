#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

zig build >/dev/null

if [ ! -x ./zig-out/bin/h3-server ]; then
  echo "expected zig-out/bin/h3-server to exist after zig build" >&2
  exit 1
fi

if ./zig-out/bin/coquic h3-server >/tmp/coquic-h3-server.out 2>&1; then
  echo "expected coquic h3-server to fail after the standalone split" >&2
  exit 1
fi

printf 'standalone h3-server dispatch smoke passed\n'
