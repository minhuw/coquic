#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workflow="${repo_root}/.github/workflows/perf.yml"

[ -f "${workflow}" ] || {
  echo "missing workflow: ${workflow}" >&2
  exit 1
}

grep -F 'pull_request:' "${workflow}" >/dev/null || {
  echo 'missing pull_request trigger' >&2
  exit 1
}

grep -F 'push:' "${workflow}" >/dev/null || {
  echo 'missing push trigger' >&2
  exit 1
}

grep -F 'branches:' "${workflow}" >/dev/null || {
  echo 'missing push branch filter' >&2
  exit 1
}

grep -F -- '- main' "${workflow}" >/dev/null || {
  echo 'missing main branch filter' >&2
  exit 1
}

if grep -F 'schedule:' "${workflow}" >/dev/null; then
  echo 'perf workflow must not use schedule trigger' >&2
  exit 1
fi

if grep -F 'workflow_dispatch:' "${workflow}" >/dev/null; then
  echo 'perf workflow must not use workflow_dispatch trigger' >&2
  exit 1
fi

grep -F 'runs-on: ubuntu-latest' "${workflow}" >/dev/null || {
  echo 'missing ubuntu-latest runner' >&2
  exit 1
}

grep -F 'timeout-minutes: 45' "${workflow}" >/dev/null || {
  echo 'missing workflow timeout' >&2
  exit 1
}

grep -F 'bash tests/nix/perf_harness_test.sh' "${workflow}" >/dev/null || {
  echo 'missing perf harness contract step' >&2
  exit 1
}

grep -F 'bash bench/run-host-matrix.sh --preset ci' "${workflow}" >/dev/null || {
  echo 'missing ci harness step' >&2
  exit 1
}

grep -F 'python3 scripts/render-perf-summary.py' "${workflow}" >/dev/null || {
  echo 'missing perf summary renderer step' >&2
  exit 1
}

grep -F 'GITHUB_STEP_SUMMARY' "${workflow}" >/dev/null || {
  echo 'missing GitHub summary output' >&2
  exit 1
}

grep -F 'uses: actions/upload-artifact@v4' "${workflow}" >/dev/null || {
  echo 'missing artifact upload step' >&2
  exit 1
}

grep -F 'if: always()' "${workflow}" >/dev/null || {
  echo 'missing always-upload behavior' >&2
  exit 1
}

grep -F 'path: .bench-results' "${workflow}" >/dev/null || {
  echo 'missing benchmark artifact path' >&2
  exit 1
}

grep -F 'include-hidden-files: true' "${workflow}" >/dev/null || {
  echo 'missing hidden benchmark artifact upload setting' >&2
  exit 1
}

echo 'perf workflow contract looks correct'
