#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workflow="${repo_root}/.github/workflows/perf.yml"

[ -f "${workflow}" ] || {
  echo "missing workflow: ${workflow}" >&2
  exit 1
}

grep -F 'schedule:' "${workflow}" >/dev/null || {
  echo 'missing schedule trigger' >&2
  exit 1
}

grep -F 'cron: "0 4 * * *"' "${workflow}" >/dev/null || {
  echo 'missing daily perf cron trigger' >&2
  exit 1
}

grep -F 'workflow_dispatch:' "${workflow}" >/dev/null || {
  echo 'missing workflow_dispatch trigger' >&2
  exit 1
}

if grep -F 'pull_request:' "${workflow}" >/dev/null; then
  echo 'perf workflow must not use pull_request trigger' >&2
  exit 1
fi

if grep -F 'push:' "${workflow}" >/dev/null; then
  echo 'perf workflow must not use push trigger' >&2
  exit 1
fi

for marker in \
  'perf-contract:' \
  'name: Perf Harness Contract' \
  'timeout-minutes: 20' \
  'bash tests/nix/perf_harness_test.sh' \
  'perf-impl:' \
  'name: ${{ matrix.display_name }} Perf' \
  'fail-fast: false' \
  'publish-perf-results:' \
  'name: Publish Perf Results' \
  'needs:' \
  '- perf-contract' \
  '- perf-impl' \
  'if: always()'; do
  if ! grep -F -- "${marker}" "${workflow}" >/dev/null; then
    echo "missing split perf workflow marker: ${marker}" >&2
    exit 1
  fi
done

grep -F 'runs-on: ubuntu-latest' "${workflow}" >/dev/null || {
  echo 'missing ubuntu-latest runner' >&2
  exit 1
}

grep -F 'timeout-minutes: 120' "${workflow}" >/dev/null || {
  echo 'missing implementation workflow timeout' >&2
  exit 1
}

for marker in \
  'NIX_CONFIG: |' \
  'max-jobs = 2' \
  'cores = 2' \
  'Free Runner Disk' \
  '/opt/hostedtoolcache/CodeQL' \
  '/usr/share/dotnet' \
  'Configure Nix Build Parallelism' \
  'docker/setup-docker-action@v5' \
  'version: version=v28.3.0'; do
  if ! grep -F -- "${marker}" "${workflow}" >/dev/null; then
    echo "missing per-runner resource marker: ${marker}" >&2
    exit 1
  fi
done

for marker in \
  'label: coquic' \
  'display_name: CoQUIC' \
  'client_impl: coquic' \
  'server_impl: coquic' \
  'congestion_controls: newreno cubic bbr copa' \
  'image_attr: perf-image-coquic-quictls-musl' \
  'image_tag: coquic-perf-coquic:quictls-musl' \
  'label: quic-go' \
  'client_impl: quic-go' \
  'server_impl: quic-go' \
  'image_attr: perf-image-quic-go-quictls-musl' \
  'image_tag: coquic-perf-quic-go:quictls-musl' \
  'label: quinn' \
  'client_impl: quinn' \
  'server_impl: quinn' \
  'image_attr: perf-image-quinn-quictls-musl' \
  'label: picoquic' \
  'client_impl: picoquic' \
  'server_impl: picoquic' \
  'image_attr: perf-image-picoquic-quictls-musl' \
  'label: msquic' \
  'client_impl: msquic' \
  'server_impl: msquic' \
  'image_attr: perf-image-msquic-quictls-musl' \
  'label: quiche' \
  'client_impl: quiche' \
  'server_impl: quiche' \
  'image_attr: perf-image-quiche-quictls-musl' \
  'label: quicly' \
  'client_impl: quicly' \
  'server_impl: quicly' \
  'image_attr: perf-image-quicly-quictls-musl' \
  'label: google-quiche' \
  'client_impl: google-quiche' \
  'server_impl: google-quiche' \
  'image_attr: perf-image-google-quiche-quictls-musl' \
  'label: tquic' \
  'client_impl: tquic' \
  'server_impl: tquic' \
  'image_attr: perf-image-tquic-quictls-musl' \
  'label: mvfst' \
  'client_impl: mvfst' \
  'server_impl: mvfst' \
  'image_attr: perf-image-mvfst-quictls-musl' \
  'label: s2n-quic' \
  'client_impl: s2n-quic' \
  'server_impl: s2n-quic' \
  'image_attr: perf-image-s2n-quic-quictls-musl' \
  'label: xquic' \
  'client_impl: xquic' \
  'server_impl: xquic' \
  'image_attr: perf-image-xquic-quictls-musl' \
  'label: aioquic' \
  'client_impl: aioquic' \
  'server_impl: aioquic' \
  'image_attr: perf-image-aioquic-quictls-musl' \
  'label: ngtcp2' \
  'client_impl: ngtcp2' \
  'server_impl: ngtcp2' \
  'image_attr: perf-image-ngtcp2-quictls-musl' \
  'label: lsquic' \
  'client_impl: lsquic' \
  'server_impl: lsquic' \
  'image_attr: perf-image-lsquic-quictls-musl' \
  'label: neqo' \
  'client_impl: neqo' \
  'server_impl: neqo' \
  'image_attr: perf-image-neqo-quictls-musl' \
  'congestion_controls: default'; do
  if ! grep -F -- "${marker}" "${workflow}" >/dev/null; then
    echo "missing implementation matrix marker: ${marker}" >&2
    exit 1
  fi
done

for marker in \
  'PERF_RESULTS_ROOT: .bench-results/${{ matrix.label }}' \
  'PERF_CLIENT_IMPL: ${{ matrix.client_impl }}' \
  'PERF_SERVER_IMPL: ${{ matrix.server_impl }}' \
  'PERF_CONGESTION_CONTROLS: ${{ matrix.congestion_controls }}' \
  'PERF_IMAGE_ATTR: ${{ matrix.image_attr }}' \
  'PERF_IMAGE_TAG: ${{ matrix.image_tag }}' \
  'bash bench/run-host-matrix.sh --preset ci' \
  'continue-on-error: true' \
  'Publish ${{ matrix.display_name }} Perf Summary' \
  '--manifest "${{ matrix.label }}=.bench-results/${{ matrix.label }}/manifest.json"' \
  '--json-out ".bench-results/perf-results-${{ matrix.label }}.json"' \
  'Upload ${{ matrix.display_name }} Perf Result Snapshot' \
  'name: perf-results-${{ matrix.label }}' \
  'path: .bench-results/perf-results-${{ matrix.label }}.json' \
  'Upload ${{ matrix.display_name }} Perf Artifacts' \
  'name: perf-artifacts-${{ matrix.label }}' \
  'path: .bench-results/${{ matrix.label }}' \
  'Fail On ${{ matrix.display_name }} Perf Errors' \
  'steps.run_perf.outcome'; do
  if ! grep -F -- "${marker}" "${workflow}" >/dev/null; then
    echo "missing implementation job marker: ${marker}" >&2
    exit 1
  fi
done

for marker in \
  'uses: actions/download-artifact@v4' \
  'pattern: perf-results-*' \
  'path: .bench-results/downloaded' \
  'merge-multiple: true' \
  'Merge Perf Result Snapshots' \
  'python3 scripts/render-perf-comparison.py' \
  '--json-out .bench-results/perf-results.json'; do
  if ! grep -F -- "${marker}" "${workflow}" >/dev/null; then
    echo "missing publish merge marker: ${marker}" >&2
    exit 1
  fi
done

for marker in \
  '--manifest coquic=.bench-results/downloaded/perf-results-coquic.json' \
  '--manifest quic-go=.bench-results/downloaded/perf-results-quic-go.json' \
  '--manifest quinn=.bench-results/downloaded/perf-results-quinn.json' \
  '--manifest picoquic=.bench-results/downloaded/perf-results-picoquic.json' \
  '--manifest msquic=.bench-results/downloaded/perf-results-msquic.json' \
  '--manifest quiche=.bench-results/downloaded/perf-results-quiche.json' \
  '--manifest quicly=.bench-results/downloaded/perf-results-quicly.json' \
  '--manifest google-quiche=.bench-results/downloaded/perf-results-google-quiche.json' \
  '--manifest tquic=.bench-results/downloaded/perf-results-tquic.json' \
  '--manifest mvfst=.bench-results/downloaded/perf-results-mvfst.json' \
  '--manifest s2n-quic=.bench-results/downloaded/perf-results-s2n-quic.json' \
  '--manifest xquic=.bench-results/downloaded/perf-results-xquic.json' \
  '--manifest aioquic=.bench-results/downloaded/perf-results-aioquic.json' \
  '--manifest ngtcp2=.bench-results/downloaded/perf-results-ngtcp2.json' \
  '--manifest lsquic=.bench-results/downloaded/perf-results-lsquic.json' \
  '--manifest neqo=.bench-results/downloaded/perf-results-neqo.json'; do
  if ! grep -F -- "${marker}" "${workflow}" >/dev/null; then
    echo "missing merged comparison manifest marker: ${marker}" >&2
    exit 1
  fi
done

for marker in \
  'Configure Demo SSH' \
  'COQUIC_DEMO_REMOTE_SSH_KEY: ${{ secrets.COQUIC_DEMO_REMOTE_SSH_KEY }}' \
  'Upload Perf Results To Demo' \
  'github.ref == '\''refs/heads/main'\''' \
  'sudo cat /opt/coquic-demo/current/site/perf-history.json' \
  'python3 scripts/update-perf-history.py' \
  '--json-out .bench-results/perf-history.json' \
  'scp \' \
  'ssh \' \
  'minhuw@coquic.minhuw.dev:/tmp/coquic-perf-results.json' \
  'minhuw@coquic.minhuw.dev:/tmp/coquic-perf-history.json' \
  '/opt/coquic-demo/current/site/perf-results.json' \
  '/opt/coquic-demo/current/site/perf-history.json'; do
  if ! grep -F -- "${marker}" "${workflow}" >/dev/null; then
    echo "missing demo perf upload workflow marker: ${marker}" >&2
    exit 1
  fi
done

for marker in \
  'Fail On Perf Job Errors' \
  'check_job "perf-contract" "${{ needs.perf-contract.result }}"' \
  'check_job "perf-impl" "${{ needs.perf-impl.result }}"' \
  'uses: actions/upload-artifact@v4' \
  'name: quic-perf-results' \
  'path: .bench-results' \
  'include-hidden-files: true' \
  'if-no-files-found: warn' \
  'GITHUB_STEP_SUMMARY'; do
  if ! grep -F -- "${marker}" "${workflow}" >/dev/null; then
    echo "missing final perf workflow marker: ${marker}" >&2
    exit 1
  fi
done

echo 'perf workflow contract looks correct'
