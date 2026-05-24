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

grep -F 'timeout-minutes: 120' "${workflow}" >/dev/null || {
  echo 'missing workflow timeout' >&2
  exit 1
}

grep -F 'bash tests/nix/perf_harness_test.sh' "${workflow}" >/dev/null || {
  echo 'missing perf harness contract step' >&2
  exit 1
}

grep -F 'Run CoQUIC Perf CI Matrix (NewReno + CUBIC + BBR + Copa)' "${workflow}" >/dev/null || {
  echo 'missing coquic congestion-control matrix label' >&2
  exit 1
}

grep -F 'PERF_RESULTS_ROOT=.bench-results/coquic bash bench/run-host-matrix.sh --preset ci' "${workflow}" >/dev/null || {
  echo 'missing coquic ci harness step' >&2
  exit 1
}

for marker in \
  'PERF_RESULTS_ROOT=.bench-results/quic-go' \
  'PERF_CLIENT_IMPL=quic-go' \
  'PERF_SERVER_IMPL=quic-go' \
  'PERF_RESULTS_ROOT=.bench-results/quinn' \
  'PERF_CLIENT_IMPL=quinn' \
  'PERF_SERVER_IMPL=quinn' \
  'PERF_RESULTS_ROOT=.bench-results/picoquic' \
  'PERF_CLIENT_IMPL=picoquic' \
  'PERF_SERVER_IMPL=picoquic' \
  'PERF_CONGESTION_CONTROLS=default'; do
  if ! grep -F "${marker}" "${workflow}" >/dev/null; then
    echo "missing baseline perf workflow marker: ${marker}" >&2
    exit 1
  fi
done

grep -F 'continue-on-error: true' "${workflow}" >/dev/null || {
  echo 'missing independent benchmark step collection' >&2
  exit 1
}

grep -F 'python3 scripts/render-perf-comparison.py' "${workflow}" >/dev/null || {
  echo 'missing perf comparison renderer step' >&2
  exit 1
}

grep -F -- '--json-out .bench-results/perf-results.json' "${workflow}" >/dev/null || {
  echo 'missing perf JSON output marker' >&2
  exit 1
}

for marker in \
  '--manifest coquic=.bench-results/coquic/manifest.json' \
  '--manifest quic-go=.bench-results/quic-go/manifest.json' \
  '--manifest quinn=.bench-results/quinn/manifest.json' \
  '--manifest picoquic=.bench-results/picoquic/manifest.json'; do
  if ! grep -F -- "${marker}" "${workflow}" >/dev/null; then
    echo "missing comparison manifest marker: ${marker}" >&2
    exit 1
  fi
done

grep -F 'Fail On Perf Matrix Errors' "${workflow}" >/dev/null || {
  echo 'missing final perf failure gate' >&2
  exit 1
}

grep -F 'steps.perf_picoquic.outcome' "${workflow}" >/dev/null || {
  echo 'missing picoquic failure gate marker' >&2
  exit 1
}

for marker in \
  'Configure Demo SSH' \
  'COQUIC_DEMO_REMOTE_SSH_KEY: ${{ secrets.COQUIC_DEMO_REMOTE_SSH_KEY }}' \
  'Upload Perf Results To Demo' \
  'github.event_name == '\''push'\'' && github.ref == '\''refs/heads/main'\''' \
  'scp \' \
  'ssh \' \
  'minhuw@coquic.minhuw.dev:/tmp/coquic-perf-results.json' \
  '/opt/coquic-demo/current/site/perf-results.json'; do
  if ! grep -F -- "${marker}" "${workflow}" >/dev/null; then
    echo "missing demo perf upload workflow marker: ${marker}" >&2
    exit 1
  fi
done

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
