#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

runner_bin="${RUN_OFFICIAL_BIN:-interop/run-official.sh}"

export INTEROP_TESTCASES="${INTEROP_TESTCASES:-http3}"
export INTEROP_PEER_IMPL="${INTEROP_PEER_IMPL:-chrome}"
export INTEROP_PEER_IMAGE="${INTEROP_PEER_IMAGE:-martenseemann/chrome-quic-interop-runner@sha256:5f0762811a21631d656a8e321e577538e1a0ef8541967f7db346a8eadbf1491a}"
export INTEROP_DIRECTIONS="${INTEROP_DIRECTIONS:-coquic-server}"
export INTEROP_LOG_ROOT="${INTEROP_LOG_ROOT:-${repo_root}/.interop-logs/chrome-http3}"

if [ "${INTEROP_TESTCASES}" != "http3" ]; then
  echo "INTEROP_TESTCASES must be http3 for the Chrome interop harness" >&2
  exit 1
fi

if [ "${INTEROP_DIRECTIONS}" != "coquic-server" ]; then
  echo "INTEROP_DIRECTIONS must be coquic-server because the Chrome runner is client-only" >&2
  exit 1
fi

bash "${runner_bin}"
