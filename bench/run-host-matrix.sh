#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
default_manifest_path="${repo_root}/.bench-results/manifest.json"
results_root="${PERF_RESULTS_ROOT:-$(dirname "${default_manifest_path}")}"
manifest_path="${results_root}/manifest.json"
environment_path="${results_root}/environment.txt"
binary_attr="${PERF_BINARY_ATTR:-coquic-quictls-musl}"
build_target="${PERF_BUILD_TARGET:-coquic-perf-quictls-musl}"
server_cpus="${PERF_SERVER_CPUS:-2}"
client_cpus="${PERF_CLIENT_CPUS:-3}"
port="${PERF_PORT:-9443}"
preset="smoke"
perf_bin=''
server_pid=''
server_shutdown_poll_attempts=20
server_shutdown_poll_interval_seconds=0.1

usage() {
  cat <<'USAGE'
usage: bash bench/run-host-matrix.sh [--preset smoke|ci]

environment overrides:
  PERF_RESULTS_ROOT  result directory (default: .bench-results)
  PERF_BINARY_ATTR   nix package attr to build (default: coquic-quictls-musl)
  PERF_BUILD_TARGET  manifest label for summary output (default: coquic-perf-quictls-musl)
  PERF_SERVER_CPUS   CPU set for server process (default: 2)
  PERF_CLIENT_CPUS   CPU set for client process (default: 3)
  PERF_PORT          UDP port for server/client (default: 9443)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --preset)
      [ $# -ge 2 ] || {
        echo 'missing value for --preset' >&2
        exit 1
      }
      preset="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "${preset}" in
  smoke)
    runs=(
      "socket bulk download 65536 0 0 1 1 1 0ms 5s"
      "socket rr stay 32 48 32 1 1 4 0ms 5s"
      "socket crr stay 24 24 8 1 2 1 0ms 5s"
    )
    ;;
  ci)
    runs=(
      "socket bulk download 0 1048576 none 4 1 1 5s 60s"
      "socket rr stay 32 32 none 1 256 16 5s 45s"
      "socket crr stay 32 32 none 1 512 1 5s 45s"
    )
    ;;
  *)
    echo "unsupported preset: ${preset}" >&2
    exit 1
    ;;
esac

mkdir -p "${results_root}"
rm -f "${results_root}"/*.json "${results_root}"/*.txt "${results_root}"/*.log "${environment_path}"

wait_for_server_shutdown() {
  local attempts_remaining="${server_shutdown_poll_attempts}"

  while kill -0 "${server_pid}" >/dev/null 2>&1; do
    [ "${attempts_remaining}" -gt 0 ] || return 1
    sleep "${server_shutdown_poll_interval_seconds}"
    attempts_remaining=$((attempts_remaining - 1))
  done

  return 0
}

stop_server() {
  if [ -z "${server_pid}" ]; then
    return
  fi

  if ! kill -0 "${server_pid}" >/dev/null 2>&1; then
    wait "${server_pid}" >/dev/null 2>&1 || true
    server_pid=''
    return
  fi

  kill "${server_pid}" >/dev/null 2>&1 || true
  if ! wait_for_server_shutdown; then
    kill -KILL "${server_pid}" >/dev/null 2>&1 || true
    wait_for_server_shutdown || true
  fi

  wait "${server_pid}" >/dev/null 2>&1 || true
  server_pid=''
}

cleanup() {
  stop_server
}

handle_signal() {
  signal_name="$1"
  cleanup
  case "${signal_name}" in
    INT)
      exit 130
      ;;
    TERM)
      exit 143
      ;;
    *)
      exit 1
      ;;
  esac
}
trap cleanup EXIT
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM

command -v taskset >/dev/null || {
  echo 'taskset is required for bench/run-host-matrix.sh' >&2
  exit 1
}

binary_path="$(nix build --print-out-paths ".#${binary_attr}")"
perf_bin="${binary_path}/bin/coquic-perf"
[ -x "${perf_bin}" ] || {
  echo "missing perf binary: ${perf_bin}" >&2
  exit 1
}

{
  echo "build_target=${build_target}"
  echo "binary_attr=${binary_attr}"
  echo "server_cpus=${server_cpus}"
  echo "client_cpus=${client_cpus}"
  echo "port=${port}"
  echo
  uname -a
  echo
  lscpu
  echo
  nproc
} > "${environment_path}"

for run in "${runs[@]}"; do
  read -r backend mode direction request_bytes response_bytes limit streams connections inflight warmup duration <<<"${run}"
  run_name="${preset}-${backend}-${mode}-s${streams}-c${connections}-q${inflight}"
  json_path="${results_root}/${run_name}.json"
  txt_path="${results_root}/${run_name}.txt"
  server_log_path="${results_root}/${run_name}.server.log"

  stop_server
  taskset -c "${server_cpus}" "${perf_bin}" server \
    --host 127.0.0.1 \
    --port "${port}" \
    --certificate-chain "${repo_root}/tests/fixtures/quic-server-cert.pem" \
    --private-key "${repo_root}/tests/fixtures/quic-server-key.pem" \
    --io-backend "${backend}" >"${server_log_path}" 2>&1 &
  server_pid="$!"

  sleep 1

  client_args=(
    client
    --host 127.0.0.1
    --port "${port}"
    --mode "${mode}"
    --io-backend "${backend}"
    --request-bytes "${request_bytes}"
    --response-bytes "${response_bytes}"
    --streams "${streams}"
    --connections "${connections}"
    --requests-in-flight "${inflight}"
    --warmup "${warmup}"
    --duration "${duration}"
    --json-out "${json_path}"
  )

  if [ "${mode}" = 'bulk' ]; then
    client_args+=(--direction "${direction}")
    if [ "${limit}" != 'none' ]; then
      client_args+=(--total-bytes "${limit}")
    fi
  elif [ "${limit}" != 'none' ]; then
    client_args+=(--requests "${limit}")
  fi

  taskset -c "${client_cpus}" "${perf_bin}" "${client_args[@]}" | tee "${txt_path}"

  stop_server
  [ -f "${json_path}" ] || {
    echo "missing JSON result: ${json_path}" >&2
    exit 1
  }
done

python3 - <<'PY' "${results_root}" "${manifest_path}" "${preset}" "${build_target}"
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
preset = sys.argv[3]
build_target = sys.argv[4]

runs = []
for path in sorted(root.glob('*.json')):
    if path.name == manifest_path.name:
        continue
    record = json.loads(path.read_text())
    record['result_file'] = path.name
    txt_path = path.with_suffix('.txt')
    if txt_path.exists():
        record['summary_file'] = txt_path.name
    runs.append(record)

manifest = {
    'preset': preset,
    'build_target': build_target,
    'results_root': str(root),
    'runs': runs,
}
manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
PY

echo "wrote manifest to ${manifest_path}"
