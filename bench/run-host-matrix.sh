#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
default_manifest_path="${repo_root}/.bench-results/manifest.json"
results_root="${PERF_RESULTS_ROOT:-$(dirname "${default_manifest_path}")}"
mkdir -p "${results_root}"
results_root="$(cd "${results_root}" && pwd)"
manifest_path="${results_root}/manifest.json"
environment_path="${results_root}/environment.txt"
image_attr="${PERF_IMAGE_ATTR:-perf-image-quictls-musl}"
image_tag="${PERF_IMAGE_TAG:-coquic-perf:quictls-musl}"
server_cpus="${PERF_SERVER_CPUS:-2}"
client_cpus="${PERF_CLIENT_CPUS:-3}"
port="${PERF_PORT:-9443}"
network_mtu="${PERF_NETWORK_MTU:-1500}"
run_timeout_seconds="${PERF_RUN_TIMEOUT_SECONDS:-120}"
congestion_controls="${PERF_CONGESTION_CONTROLS:-newreno cubic bbr copa}"
client_impl="${PERF_CLIENT_IMPL:-coquic}"
server_impl="${PERF_SERVER_IMPL:-coquic}"
implementations_manifest="${PERF_IMPLEMENTATIONS_JSON:-${repo_root}/bench/implementations.json}"
library_version="${PERF_LIBRARY_VERSION:-}"
nix_build_attempts="${PERF_NIX_BUILD_ATTEMPTS:-3}"
nix_build_retry_delay_seconds="${PERF_NIX_BUILD_RETRY_DELAY_SECONDS:-10}"
preset="smoke"
network_name=''
server_name=''
client_name=''
failed_runs=0

usage() {
  cat <<'USAGE'
usage: bash bench/run-host-matrix.sh [--preset smoke|ci]

environment overrides:
  PERF_RESULTS_ROOT          result directory (default: .bench-results)
  PERF_IMAGE_ATTR            nix image attr to build (default: perf-image-quictls-musl)
  PERF_IMAGE_TAG             Docker image tag to run (default: coquic-perf:quictls-musl)
  PERF_SERVER_CPUS           Docker cpuset for server container (default: 2)
  PERF_CLIENT_CPUS           Docker cpuset for client container (default: 3)
  PERF_PORT                  UDP port for server/client (default: 9443)
  PERF_NETWORK_MTU           Docker bridge MTU (default: 1500)
  PERF_RUN_TIMEOUT_SECONDS   per-client Docker run timeout (default: 120)
  PERF_CONGESTION_CONTROLS   space-separated algorithms to run (default: "newreno cubic bbr copa")
  PERF_CLIENT_IMPL           client implementation to run, coquic, coquic-rust, coquic-python, coquic-go, coquic-js, quic-go, quinn, picoquic, msquic, quiche, quicly, google-quiche, tquic, mvfst, s2n-quic, xquic, aioquic, ngtcp2, lsquic, or neqo (default: coquic)
  PERF_SERVER_IMPL           server implementation to run, coquic, coquic-rust, coquic-python, coquic-go, coquic-js, quic-go, quinn, picoquic, msquic, quiche, quicly, google-quiche, tquic, mvfst, s2n-quic, xquic, aioquic, ngtcp2, lsquic, or neqo (default: coquic)
  PERF_IMPLEMENTATIONS_JSON  implementation metadata JSON (default: bench/implementations.json)
  PERF_LIBRARY_VERSION       explicit implementation library version override
  PERF_DOCKER_ENV            space-separated NAME=value environment entries passed to both containers
  PERF_NIX_BUILD_ATTEMPTS    attempts for the perf image nix build (default: 3)
  PERF_NIX_BUILD_RETRY_DELAY_SECONDS
                             delay before retrying a failed image build (default: 10)
USAGE
}

build_perf_image() {
  local attempt=1
  while :; do
    if nix build --print-out-paths ".#${image_attr}"; then
      return 0
    fi
    if [ "${attempt}" -ge "${nix_build_attempts}" ]; then
      return 1
    fi
    echo "nix build for .#${image_attr} failed; retrying in ${nix_build_retry_delay_seconds}s (${attempt}/${nix_build_attempts})" >&2
    sleep "${nix_build_retry_delay_seconds}"
    attempt=$((attempt + 1))
  done
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
      "socket bulk download 0 65536 65536 1 1 1 0ms 5s"
      "socket rr stay 32 48 32 1 1 4 0ms 5s"
      "socket crr stay 24 24 8 1 2 1 0ms 5s"
    )
    ;;
  ci)
    runs=(
      "socket bulk download 0 1048576 none 4 1 1 0ms 60s"
      "socket rr stay 32 32 none 1 128 4 5s 45s"
      "socket crr stay 32 32 none 1 64 1 5s 45s"
    )
    ;;
  *)
    echo "unsupported preset: ${preset}" >&2
    exit 1
    ;;
esac

read -r -a congestion_control_list <<<"${congestion_controls}"
[ "${#congestion_control_list[@]}" -gt 0 ] || {
  echo 'at least one congestion-control algorithm is required' >&2
  exit 1
}

docker_env_args=()
if [ -n "${PERF_DOCKER_ENV:-}" ]; then
  read -r -a docker_env_entries <<<"${PERF_DOCKER_ENV}"
  for env_entry in "${docker_env_entries[@]}"; do
    docker_env_args+=(-e "${env_entry}")
  done
fi
for congestion_control in "${congestion_control_list[@]}"; do
  case "${congestion_control}" in
    newreno|cubic|bbr|copa)
      ;;
    default)
      if [ "${client_impl}" = "${server_impl}" ] \
        && { [ "${client_impl}" = 'quic-go' ] || [ "${client_impl}" = 'quinn' ] || [ "${client_impl}" = 'picoquic' ] || [ "${client_impl}" = 'msquic' ] || [ "${client_impl}" = 'quiche' ] || [ "${client_impl}" = 'quicly' ] || [ "${client_impl}" = 'google-quiche' ] || [ "${client_impl}" = 'tquic' ] || [ "${client_impl}" = 'mvfst' ] || [ "${client_impl}" = 's2n-quic' ] || [ "${client_impl}" = 'xquic' ] || [ "${client_impl}" = 'aioquic' ] || [ "${client_impl}" = 'ngtcp2' ] || [ "${client_impl}" = 'lsquic' ] || [ "${client_impl}" = 'neqo' ]; }; then
        :
      else
        echo 'congestion-control label "default" is only supported for paired external baseline runs' >&2
        exit 1
      fi
      ;;
    *)
      echo "unsupported congestion-control algorithm: ${congestion_control}" >&2
      exit 1
      ;;
  esac
done

case "${client_impl}" in
  coquic|coquic-rust|coquic-python|coquic-go|coquic-js|quic-go|quinn|picoquic|msquic|quiche|quicly|google-quiche|tquic|mvfst|s2n-quic|xquic|aioquic|ngtcp2|lsquic|neqo)
    ;;
  *)
    echo "unsupported client implementation: ${client_impl}" >&2
    exit 1
    ;;
esac

case "${server_impl}" in
  coquic|coquic-rust|coquic-python|coquic-go|coquic-js|quic-go|quinn|picoquic|msquic|quiche|quicly|google-quiche|tquic|mvfst|s2n-quic|xquic|aioquic|ngtcp2|lsquic|neqo)
    ;;
  *)
    echo "unsupported server implementation: ${server_impl}" >&2
    exit 1
    ;;
esac

if [ -z "${library_version}" ]; then
  library_version="$(
    python3 "${repo_root}/scripts/resolve-bench-implementation-version.py" \
      --manifest "${implementations_manifest}" \
      --implementation "${client_impl}" \
      --server-implementation "${server_impl}" \
      --commit "${GITHUB_SHA:-}"
  )"
fi

rm -f "${results_root}"/*.json "${results_root}"/*.txt "${results_root}"/*.log \
  "${results_root}"/*.cid \
  "${environment_path}"

cleanup_containers() {
  if [ -n "${client_name}" ]; then
    docker rm -f "${client_name}" >/dev/null 2>&1 || true
  fi
  if [ -n "${server_name}" ]; then
    docker rm -f "${server_name}" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  cleanup_containers
  if [ -n "${network_name}" ]; then
    docker network rm "${network_name}" >/dev/null 2>&1 || true
  fi
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

command -v docker >/dev/null || {
  echo 'docker is required for bench/run-host-matrix.sh' >&2
  exit 1
}

command -v nix >/dev/null || {
  echo 'nix is required for bench/run-host-matrix.sh' >&2
  exit 1
}

image_path="$(build_perf_image)"
docker load -i "${image_path}" >/dev/null
docker image inspect "${image_tag}" >/dev/null

network_name="coquic-perf-${preset}-$$"
docker network create --opt "com.docker.network.driver.mtu=${network_mtu}" "${network_name}" >/dev/null

{
  echo "topology=docker-bridge-two-containers"
  echo "image_attr=${image_attr}"
  echo "image_tag=${image_tag}"
  echo "network=${network_name}"
  echo "server_cpus=${server_cpus}"
  echo "client_cpus=${client_cpus}"
  echo "port=${port}"
  echo "network_mtu=${network_mtu}"
  echo "run_timeout_seconds=${run_timeout_seconds}"
  echo "congestion_controls=${congestion_controls}"
  echo "client_impl=${client_impl}"
  echo "server_impl=${server_impl}"
  echo "implementations_manifest=${implementations_manifest}"
  echo "library_version=${library_version}"
  echo "docker_env=${PERF_DOCKER_ENV:-}"
  echo
  docker version
  echo
  docker info
  echo
  docker image inspect "${image_tag}"
  echo
  docker network inspect "${network_name}"
  echo
  uname -a
  echo
  lscpu
  echo
  nproc
} > "${environment_path}"

for congestion_control in "${congestion_control_list[@]}"; do
  for run in "${runs[@]}"; do
    read -r backend mode direction request_bytes response_bytes limit streams connections inflight warmup duration <<<"${run}"
    effective_connections="${connections}"
    effective_inflight="${inflight}"
    if { [ "${client_impl}" = 'ngtcp2' ] || [ "${client_impl}" = 'neqo' ] || [ "${client_impl}" = 'quicly' ] || [ "${client_impl}" = 'lsquic' ]; } \
      && [ "${client_impl}" = "${server_impl}" ] && [ "${mode}" = 'rr' ]; then
      effective_connections=1
      effective_inflight=$((inflight * connections))
    fi
    if [ "${client_impl}" = 'coquic' ] && [ "${server_impl}" = 'coquic' ]; then
      run_name="${preset}-${congestion_control}-${backend}-${mode}-s${streams}-c${effective_connections}-q${effective_inflight}"
    else
      run_name="${preset}-${client_impl}-to-${server_impl}-${congestion_control}-${backend}-${mode}-s${streams}-c${effective_connections}-q${effective_inflight}"
    fi
    json_path="${results_root}/${run_name}.json"
    txt_path="${results_root}/${run_name}.txt"
    server_log_path="${results_root}/${run_name}.server.log"
    server_cid_path="${results_root}/${run_name}.server.cid"
    client_name="coquic-perf-client-${preset}-${congestion_control}-${mode}-$$"
    server_name="coquic-perf-server-${preset}-${congestion_control}-${mode}-$$"

    cleanup_containers

    server_entrypoint=()
    case "${server_impl}" in
      quic-go)
        server_entrypoint=(--entrypoint /usr/local/bin/quicgo-perf)
        ;;
      coquic-rust)
        server_entrypoint=(--entrypoint /usr/local/bin/coquic-rust-perf)
        ;;
      coquic-python)
        server_entrypoint=(--entrypoint /usr/local/bin/coquic-python-perf)
        ;;
      coquic-go)
        server_entrypoint=(--entrypoint /usr/local/bin/coquic-go-perf)
        ;;
      coquic-js)
        server_entrypoint=(--entrypoint /usr/local/bin/coquic-js-perf)
        ;;
      quinn)
        server_entrypoint=(--entrypoint /usr/local/bin/quinn-perf)
        ;;
      picoquic)
        server_entrypoint=(--entrypoint /usr/local/bin/picoquic-perf)
        ;;
      msquic)
        server_entrypoint=(--entrypoint /usr/local/bin/msquic-perf)
        ;;
      quiche)
        server_entrypoint=(--entrypoint /usr/local/bin/quiche-perf)
        ;;
      quicly)
        server_entrypoint=(--entrypoint /usr/local/bin/quicly-perf)
        ;;
      google-quiche)
        server_entrypoint=(--entrypoint /usr/local/bin/google-quiche-perf)
        ;;
      tquic)
        server_entrypoint=(--entrypoint /usr/local/bin/tquic-perf)
        ;;
      mvfst)
        server_entrypoint=(--entrypoint /usr/local/bin/mvfst-perf)
        ;;
      s2n-quic)
        server_entrypoint=(--entrypoint /usr/local/bin/s2n-quic-perf)
        ;;
      xquic)
        server_entrypoint=(--entrypoint /usr/local/bin/xquic-perf)
        ;;
      aioquic)
        server_entrypoint=(--entrypoint /usr/local/bin/aioquic-perf)
        ;;
      ngtcp2)
        server_entrypoint=(--entrypoint /usr/local/bin/ngtcp2-perf)
        ;;
      lsquic)
        server_entrypoint=(--entrypoint /usr/local/bin/lsquic-perf)
        ;;
      neqo)
        server_entrypoint=(--entrypoint /usr/local/bin/neqo-perf)
        ;;
    esac

    docker run -d --rm \
      --name "${server_name}" \
      --network "${network_name}" \
      --cpuset-cpus "${server_cpus}" \
      "${docker_env_args[@]}" \
      -v "${repo_root}/tests/fixtures:/certs:ro" \
      "${server_entrypoint[@]}" \
      "${image_tag}" server \
      --host 0.0.0.0 \
      --port "${port}" \
      --certificate-chain /certs/quic-server-cert.pem \
      --private-key /certs/quic-server-key.pem \
      --io-backend "${backend}" \
      --congestion-control "${congestion_control}" > "${server_cid_path}"

    sleep 1

    client_args=(
      client
      --host "${server_name}"
      --port "${port}"
      --mode "${mode}"
      --io-backend "${backend}"
      --congestion-control "${congestion_control}"
      --request-bytes "${request_bytes}"
      --response-bytes "${response_bytes}"
      --streams "${streams}"
      --connections "${effective_connections}"
      --requests-in-flight "${effective_inflight}"
      --warmup "${warmup}"
      --duration "${duration}"
      --json-out /results/result.json
    )

    if [ "${mode}" = 'bulk' ]; then
      client_args+=(--direction "${direction}")
      bulk_limit="${limit}"
      if [ "${limit}" = 'none' ] && [ "${client_impl}" = 'msquic' ] && [ "${server_impl}" = 'msquic' ]; then
        bulk_limit="${PERF_MSQUIC_BULK_TOTAL_BYTES:-134217728}"
      fi
      if [ "${bulk_limit}" != 'none' ]; then
        client_args+=(--total-bytes "${bulk_limit}")
      fi
    elif [ "${limit}" != 'none' ]; then
      client_args+=(--requests "${limit}")
    fi

    set +e
    client_entrypoint=()
    case "${client_impl}" in
      quic-go)
        client_entrypoint=(--entrypoint /usr/local/bin/quicgo-perf)
        ;;
      coquic-rust)
        client_entrypoint=(--entrypoint /usr/local/bin/coquic-rust-perf)
        ;;
      coquic-python)
        client_entrypoint=(--entrypoint /usr/local/bin/coquic-python-perf)
        ;;
      coquic-go)
        client_entrypoint=(--entrypoint /usr/local/bin/coquic-go-perf)
        ;;
      coquic-js)
        client_entrypoint=(--entrypoint /usr/local/bin/coquic-js-perf)
        ;;
      quinn)
        client_entrypoint=(--entrypoint /usr/local/bin/quinn-perf)
        ;;
      picoquic)
        client_entrypoint=(--entrypoint /usr/local/bin/picoquic-perf)
        ;;
      msquic)
        client_entrypoint=(--entrypoint /usr/local/bin/msquic-perf)
        ;;
      quiche)
        client_entrypoint=(--entrypoint /usr/local/bin/quiche-perf)
        ;;
      quicly)
        client_entrypoint=(--entrypoint /usr/local/bin/quicly-perf)
        ;;
      google-quiche)
        client_entrypoint=(--entrypoint /usr/local/bin/google-quiche-perf)
        ;;
      tquic)
        client_entrypoint=(--entrypoint /usr/local/bin/tquic-perf)
        ;;
      mvfst)
        client_entrypoint=(--entrypoint /usr/local/bin/mvfst-perf)
        ;;
      s2n-quic)
        client_entrypoint=(--entrypoint /usr/local/bin/s2n-quic-perf)
        ;;
      xquic)
        client_entrypoint=(--entrypoint /usr/local/bin/xquic-perf)
        ;;
      aioquic)
        client_entrypoint=(--entrypoint /usr/local/bin/aioquic-perf)
        ;;
      ngtcp2)
        client_entrypoint=(--entrypoint /usr/local/bin/ngtcp2-perf)
        ;;
      lsquic)
        client_entrypoint=(--entrypoint /usr/local/bin/lsquic-perf)
        ;;
      neqo)
        client_entrypoint=(--entrypoint /usr/local/bin/neqo-perf)
        ;;
    esac

    timeout --kill-after=5s "${run_timeout_seconds}s" docker run --rm \
      --name "${client_name}" \
      --network "${network_name}" \
      --cpuset-cpus "${client_cpus}" \
      "${docker_env_args[@]}" \
      -v "${results_root}:/results" \
      -v "${repo_root}/tests/fixtures:/certs:ro" \
      "${client_entrypoint[@]}" \
      "${image_tag}" "${client_args[@]}" | tee "${txt_path}"
    client_status=${PIPESTATUS[0]}
    set -e

    docker logs "${server_name}" > "${server_log_path}" 2>&1 || true
    docker rm -f "${server_name}" >/dev/null 2>&1 || true
    docker rm -f "${client_name}" >/dev/null 2>&1 || true

    if [ ! -f "${results_root}/result.json" ]; then
      echo "missing JSON result for ${run_name}: ${results_root}/result.json" >&2
      exit "${client_status:-1}"
    fi
    mv "${results_root}/result.json" "${json_path}"

    if [ "${client_status}" -ne 0 ]; then
      echo "client container failed for ${run_name} with status ${client_status}; kept ${json_path}" >&2
      failed_runs=1
    fi
  done
done

python3 - <<'PY' "${results_root}" "${manifest_path}" "${preset}" "${image_attr}" "${image_tag}" "${congestion_controls}" "${client_impl}" "${server_impl}" "${library_version}" "${implementations_manifest}"
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
preset = sys.argv[3]
image_attr = sys.argv[4]
image_tag = sys.argv[5]
congestion_controls = sys.argv[6].split()
client_impl = sys.argv[7]
server_impl = sys.argv[8]
library_version = sys.argv[9]
implementations_manifest = sys.argv[10]

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
    'topology': 'docker-bridge-two-containers',
    'image_attr': image_attr,
    'image_tag': image_tag,
    'congestion_controls': congestion_controls,
    'client_impl': client_impl,
    'server_impl': server_impl,
    'implementations_manifest': implementations_manifest,
    'library_version': library_version,
    'results_root': str(root),
    'runs': runs,
}
manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
PY

echo "wrote manifest to ${manifest_path}"

if ! python3 - <<'PY' "${manifest_path}"; then
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
manifest = json.loads(manifest_path.read_text())
failed = [
    run
    for run in manifest.get("runs", [])
    if isinstance(run, dict) and run.get("status") != "ok"
]
for run in failed:
    result = run.get("result_file", "<unknown>")
    reason = run.get("failure_reason", "")
    if reason:
        print(f"failed benchmark result: {result}: {reason}", file=sys.stderr)
    else:
        print(f"failed benchmark result: {result}", file=sys.stderr)
sys.exit(1 if failed else 0)
PY
  failed_runs=1
fi

exit "${failed_runs}"
