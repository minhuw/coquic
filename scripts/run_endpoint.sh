#!/usr/bin/env bash
set -euo pipefail

binary="${COQUIC_BIN:-/usr/local/bin/coquic}"
role="${ROLE:-}"
testcase="${TESTCASE:-}"

supports_testcase() {
  case "$1" in
    handshake | transfer | multiconnect)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

run_setup() {
  if [ "${COQUIC_SKIP_SETUP:-0}" != "1" ] && [ -x /setup.sh ]; then
    /setup.sh
  fi
}

wait_for_sim() {
  if [ "${COQUIC_SKIP_WAIT:-0}" != "1" ] && [ -x /wait-for-it.sh ]; then
    /wait-for-it.sh sim:57832 -s -t "${SIM_WAIT_TIMEOUT_SECONDS:-30}" -- true
  fi
}

if [ -n "${testcase}" ] && ! supports_testcase "${testcase}"; then
  echo "unsupported TESTCASE=${testcase}" >&2
  exit 127
fi

case "${role}" in
server)
  run_setup
  export HOST="${HOST:-0.0.0.0}"
  export PORT="${PORT:-443}"
  export DOCUMENT_ROOT="${DOCUMENT_ROOT:-/www}"
  export CERTIFICATE_CHAIN_PATH="${CERTIFICATE_CHAIN_PATH:-/certs/cert.pem}"
  export PRIVATE_KEY_PATH="${PRIVATE_KEY_PATH:-/certs/priv.key}"
  exec "${binary}" interop-server
  ;;
client)
  run_setup
  wait_for_sim
  export HOST="${HOST:-}"
  export PORT="${PORT:-443}"
  export SERVER_NAME="${SERVER_NAME:-}"
  export DOWNLOAD_ROOT="${DOWNLOAD_ROOT:-/downloads}"
  exec "${binary}" interop-client
  ;;
*)
  echo "unsupported ROLE=${role}" >&2
  echo "expected ROLE=server or ROLE=client" >&2
  exit 1
  ;;
esac
