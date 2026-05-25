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
  'PERF_RESULTS_ROOT=.bench-results/msquic' \
  'PERF_CLIENT_IMPL=msquic' \
  'PERF_SERVER_IMPL=msquic' \
  'PERF_RESULTS_ROOT=.bench-results/quiche' \
  'PERF_CLIENT_IMPL=quiche' \
  'PERF_SERVER_IMPL=quiche' \
  'PERF_RESULTS_ROOT=.bench-results/quicly' \
  'PERF_CLIENT_IMPL=quicly' \
  'PERF_SERVER_IMPL=quicly' \
  'PERF_RESULTS_ROOT=.bench-results/google-quiche' \
  'PERF_CLIENT_IMPL=google-quiche' \
  'PERF_SERVER_IMPL=google-quiche' \
  'PERF_RESULTS_ROOT=.bench-results/tquic' \
  'PERF_CLIENT_IMPL=tquic' \
  'PERF_SERVER_IMPL=tquic' \
  'PERF_RESULTS_ROOT=.bench-results/mvfst' \
  'PERF_CLIENT_IMPL=mvfst' \
  'PERF_SERVER_IMPL=mvfst' \
  'PERF_RESULTS_ROOT=.bench-results/s2n-quic' \
  'PERF_CLIENT_IMPL=s2n-quic' \
  'PERF_SERVER_IMPL=s2n-quic' \
  'PERF_RESULTS_ROOT=.bench-results/xquic' \
  'PERF_CLIENT_IMPL=xquic' \
  'PERF_SERVER_IMPL=xquic' \
  'PERF_RESULTS_ROOT=.bench-results/aioquic' \
  'PERF_CLIENT_IMPL=aioquic' \
  'PERF_SERVER_IMPL=aioquic' \
  'PERF_RESULTS_ROOT=.bench-results/ngtcp2' \
  'PERF_CLIENT_IMPL=ngtcp2' \
  'PERF_SERVER_IMPL=ngtcp2' \
  'PERF_RESULTS_ROOT=.bench-results/lsquic' \
  'PERF_CLIENT_IMPL=lsquic' \
  'PERF_SERVER_IMPL=lsquic' \
  'PERF_RESULTS_ROOT=.bench-results/neqo' \
  'PERF_CLIENT_IMPL=neqo' \
  'PERF_SERVER_IMPL=neqo' \
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
  '--manifest picoquic=.bench-results/picoquic/manifest.json' \
  '--manifest msquic=.bench-results/msquic/manifest.json' \
  '--manifest quiche=.bench-results/quiche/manifest.json' \
  '--manifest quicly=.bench-results/quicly/manifest.json' \
  '--manifest google-quiche=.bench-results/google-quiche/manifest.json' \
  '--manifest tquic=.bench-results/tquic/manifest.json' \
  '--manifest mvfst=.bench-results/mvfst/manifest.json' \
  '--manifest s2n-quic=.bench-results/s2n-quic/manifest.json' \
  '--manifest xquic=.bench-results/xquic/manifest.json' \
  '--manifest aioquic=.bench-results/aioquic/manifest.json' \
  '--manifest ngtcp2=.bench-results/ngtcp2/manifest.json' \
  '--manifest lsquic=.bench-results/lsquic/manifest.json' \
  '--manifest neqo=.bench-results/neqo/manifest.json'; do
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

grep -F 'steps.perf_msquic.outcome' "${workflow}" >/dev/null || {
  echo 'missing MSQUIC failure gate marker' >&2
  exit 1
}

grep -F 'steps.perf_quiche.outcome' "${workflow}" >/dev/null || {
  echo 'missing quiche failure gate marker' >&2
  exit 1
}

grep -F 'steps.perf_quicly.outcome' "${workflow}" >/dev/null || {
  echo 'missing quicly failure gate marker' >&2
  exit 1
}

grep -F 'steps.perf_google_quiche.outcome' "${workflow}" >/dev/null || {
  echo 'missing Google QUICHE failure gate marker' >&2
  exit 1
}

grep -F 'steps.perf_tquic.outcome' "${workflow}" >/dev/null || {
  echo 'missing TQUIC failure gate marker' >&2
  exit 1
}

grep -F 'steps.perf_mvfst.outcome' "${workflow}" >/dev/null || {
  echo 'missing mvfst failure gate marker' >&2
  exit 1
}

grep -F 'steps.perf_s2n_quic.outcome' "${workflow}" >/dev/null || {
  echo 'missing s2n-quic failure gate marker' >&2
  exit 1
}

grep -F 'steps.perf_xquic.outcome' "${workflow}" >/dev/null || {
  echo 'missing xquic failure gate marker' >&2
  exit 1
}

grep -F 'steps.perf_aioquic.outcome' "${workflow}" >/dev/null || {
  echo 'missing aioquic failure gate marker' >&2
  exit 1
}

grep -F 'steps.perf_ngtcp2.outcome' "${workflow}" >/dev/null || {
  echo 'missing ngtcp2 failure gate marker' >&2
  exit 1
}

grep -F 'steps.perf_lsquic.outcome' "${workflow}" >/dev/null || {
  echo 'missing LSQUIC failure gate marker' >&2
  exit 1
}

grep -F 'steps.perf_neqo.outcome' "${workflow}" >/dev/null || {
  echo 'missing Neqo failure gate marker' >&2
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
