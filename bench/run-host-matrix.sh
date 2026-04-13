#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
default_manifest_path="${repo_root}/.bench-results/manifest.json"
results_root="${PERF_RESULTS_ROOT:-$(dirname "${default_manifest_path}")}"
manifest_path="${results_root}/manifest.json"
image_attr="${PERF_IMAGE_ATTR:-perf-image-quictls-musl}"
image_tag="${PERF_IMAGE_TAG:-coquic-perf:quictls-musl}"
server_name="${PERF_SERVER_NAME:-coquic-perf-server}"
server_cpus="${PERF_SERVER_CPUS:-2}"
client_cpus="${PERF_CLIENT_CPUS:-3}"
port="${PERF_PORT:-9443}"
preset="smoke"

usage() {
  cat <<'USAGE'
usage: bash bench/run-host-matrix.sh [--preset smoke|ci]

environment overrides:
  PERF_RESULTS_ROOT  result directory (default: .bench-results)
  PERF_IMAGE_ATTR    nix package attr to build/load (default: perf-image-quictls-musl)
  PERF_IMAGE_TAG     docker tag to run (default: coquic-perf:quictls-musl)
  PERF_SERVER_CPUS   CPU set for server container (default: 2)
  PERF_CLIENT_CPUS   CPU set for client container (default: 3)
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
rm -f "${results_root}"/*.json "${results_root}"/*.txt

cleanup() {
  docker rm -f "${server_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

image_path="$(nix build --print-out-paths ".#${image_attr}")"
docker load -i "${image_path}" >/dev/null

for run in "${runs[@]}"; do
  read -r backend mode direction request_bytes response_bytes limit streams connections inflight warmup duration <<<"${run}"
  run_name="${preset}-${backend}-${mode}-s${streams}-c${connections}-q${inflight}"
  json_path="${results_root}/${run_name}.json"
  txt_path="${results_root}/${run_name}.txt"

  docker rm -f "${server_name}" >/dev/null 2>&1 || true
  docker run -d --rm --name "${server_name}" \
    --network host \
    --cpuset-cpus "${server_cpus}" \
    --security-opt seccomp=unconfined \
    --cap-add IPC_LOCK \
    --ulimit memlock=-1:-1 \
    -v "${repo_root}/tests/fixtures:/certs:ro" \
    "${image_tag}" server \
      --host 127.0.0.1 \
      --port "${port}" \
      --certificate-chain /certs/quic-server-cert.pem \
      --private-key /certs/quic-server-key.pem \
      --io-backend "${backend}" >/dev/null

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
    --json-out "/results/${run_name}.json"
  )

  if [ "${mode}" = 'bulk' ]; then
    client_args+=(--direction "${direction}")
    if [ "${limit}" != 'none' ]; then
      client_args+=(--total-bytes "${limit}")
    fi
  elif [ "${limit}" != 'none' ]; then
    client_args+=(--requests "${limit}")
  fi

  docker run --rm \
    --network host \
    --cpuset-cpus "${client_cpus}" \
    --security-opt seccomp=unconfined \
    --cap-add IPC_LOCK \
    --ulimit memlock=-1:-1 \
    -v "${results_root}:/results" \
    "${image_tag}" "${client_args[@]}" | tee "${txt_path}"

  docker rm -f "${server_name}" >/dev/null 2>&1 || true
  [ -f "${json_path}" ] || {
    echo "missing JSON result: ${json_path}" >&2
    exit 1
  }
done

python3 - <<'PY' "${results_root}" "${manifest_path}" "${preset}" "${image_attr}" "${image_tag}"
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
preset = sys.argv[3]
image_attr = sys.argv[4]
image_tag = sys.argv[5]

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
    'image_attr': image_attr,
    'image_tag': image_tag,
    'results_root': str(root),
    'runs': runs,
}
manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
PY

echo "wrote manifest to ${manifest_path}"
