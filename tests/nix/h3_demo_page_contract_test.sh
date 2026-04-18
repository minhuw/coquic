#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

page="docker/h3-server/www/index.html"

assert_contains() {
  local marker="$1"
  if ! grep -Fq "${marker}" "${page}"; then
    echo "expected demo page to contain marker: ${marker}" >&2
    exit 1
  fi
}

assert_contains "Showcase"
assert_contains "Technical"
assert_contains "Run Live Checks"
assert_contains "coquic.minhuw.dev:4433"
assert_contains "/_coquic/inspect"
assert_contains "/_coquic/echo"
assert_contains "localStorage"
assert_contains "window.location"
assert_contains "How To Verify In Chrome"
assert_contains "Browser Verification"
assert_contains "safeStorageGet"
assert_contains "safeStorageSet"
assert_contains "safeReadJson"
assert_contains "runProbe"

echo "h3 demo page contract looks correct"
