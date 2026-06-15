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
congestion_controls="${PERF_CONGESTION_CONTROLS:-newreno cubic bbr copa pcc pcc-vivace}"
client_impl="${PERF_CLIENT_IMPL:-coquic}"
server_impl="${PERF_SERVER_IMPL:-coquic}"
implementations_manifest="${PERF_IMPLEMENTATIONS_JSON:-${repo_root}/bench/implementations.json}"
library_version="${PERF_LIBRARY_VERSION:-}"
nix_build_attempts="${PERF_NIX_BUILD_ATTEMPTS:-6}"
nix_build_retry_delay_seconds="${PERF_NIX_BUILD_RETRY_DELAY_SECONDS:-15}"
nix_build_retry_max_delay_seconds="${PERF_NIX_BUILD_RETRY_MAX_DELAY_SECONDS:-120}"
utilization_enabled="${PERF_UTILIZATION_ENABLED:-1}"
stats_sample_interval_seconds="${PERF_STATS_SAMPLE_INTERVAL_SECONDS:-1}"
profile_flamegraphs_enabled="${PERF_PROFILE_FLAMEGRAPHS:-0}"
profile_frequency="${PERF_PROFILE_FREQUENCY:-99}"
profile_use_sudo="${PERF_PROFILE_USE_SUDO:-0}"
profile_perf_bin="${PERF_PROFILE_PERF_BIN:-}"
profile_docker_image="${PERF_PROFILE_DOCKER_IMAGE:-}"
preset="smoke"
network_name=''
server_name=''
client_name=''
failed_runs=0

is_managed_pid() {
  local pid="${1:-}"
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] && [[ "${pid}" != "1" ]]
}

pid_is_alive() {
  local pid="$1"
  is_managed_pid "${pid}" && kill -0 -- "${pid}" >/dev/null 2>&1
}

signal_pid() {
  local signal_name="$1"
  local pid="$2"
  is_managed_pid "${pid}" && kill "-${signal_name}" -- "${pid}" >/dev/null 2>&1
}

signal_process_group() {
  local signal_name="$1"
  local pid="$2"
  is_managed_pid "${pid}" && kill "-${signal_name}" -- "-${pid}" >/dev/null 2>&1
}

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
  PERF_CONGESTION_CONTROLS   space-separated algorithms to run (default: "newreno cubic bbr copa pcc pcc-vivace")
  PERF_CLIENT_IMPL           client implementation to run, coquic, coquic-rust, coquic-python, coquic-go, coquic-js, quic-go, quinn, picoquic, msquic, quiche, quicly, google-quiche, tquic, mvfst, s2n-quic, xquic, aioquic, ngtcp2, lsquic, or neqo (default: coquic)
  PERF_SERVER_IMPL           server implementation to run, coquic, coquic-rust, coquic-python, coquic-go, coquic-js, quic-go, quinn, picoquic, msquic, quiche, quicly, google-quiche, tquic, mvfst, s2n-quic, xquic, aioquic, ngtcp2, lsquic, or neqo (default: coquic)
  PERF_IMPLEMENTATIONS_JSON  implementation metadata JSON (default: bench/implementations.json)
  PERF_LIBRARY_VERSION       explicit implementation library version override
  PERF_DOCKER_ENV            space-separated NAME=value environment entries passed to both containers
  PERF_NIX_BUILD_ATTEMPTS    attempts for retryable perf image nix build failures (default: 6)
  PERF_NIX_BUILD_RETRY_DELAY_SECONDS
                             base delay before retrying a retryable image build failure (default: 15)
  PERF_NIX_BUILD_RETRY_MAX_DELAY_SECONDS
                             maximum exponential retry delay for retryable image build failures (default: 120)
  PERF_UTILIZATION_ENABLED   sample Docker CPU and memory stats (default: 1)
  PERF_STATS_SAMPLE_INTERVAL_SECONDS
                             Docker stats sample interval in seconds (default: 1)
  PERF_PROFILE_FLAMEGRAPHS   record host perf flamegraphs for client/server when possible (default: 0)
  PERF_PROFILE_FREQUENCY     perf sampling frequency in Hz (default: 99)
  PERF_PROFILE_USE_SUDO      run host perf through passwordless sudo when recording container PIDs (default: 0)
  PERF_PROFILE_PERF_BIN      explicit perf binary path or command name (default: resolved from PATH)
  PERF_PROFILE_DOCKER_IMAGE  run perf record in this privileged --pid=host helper image
USAGE
}

nix_build_error_is_retryable() {
  local log_path="$1"
  grep -Eiq \
    'Could not resolve (host|hostname)|Could not connect to server|Temporary failure in name resolution|Name or service not known|Failed to connect to [^ ]+ port [0-9]+|Connection (timed out|reset by peer|refused)|network is unreachable|No route to host|TLS connection was non-properly terminated|unexpected EOF|HTTP error 5[0-9][0-9]|status code 5[0-9][0-9]' \
    "${log_path}"
}

nix_build_retry_delay() {
  local attempt="$1"
  local delay="${nix_build_retry_delay_seconds}"
  local step=1
  while [ "${step}" -lt "${attempt}" ]; do
    delay=$((delay * 2))
    if [ "${delay}" -ge "${nix_build_retry_max_delay_seconds}" ]; then
      delay="${nix_build_retry_max_delay_seconds}"
      break
    fi
    step=$((step + 1))
  done
  printf '%s\n' "${delay}"
}

build_perf_image() {
  local attempt=1
  local attempt_log
  local delay
  local image_path
  while :; do
    attempt_log="${results_root}/nix-build-${image_attr}-attempt-${attempt}.log"
    printf 'nix build attempt %s/%s for .#%s\n' "${attempt}" "${nix_build_attempts}" "${image_attr}" > "${attempt_log}"
    if image_path="$(nix build --print-out-paths ".#${image_attr}" 2> >(tee -a "${attempt_log}" >&2))"; then
      printf '%s\n' "${image_path}" >> "${attempt_log}"
      printf '%s\n' "${image_path}"
      return 0
    fi
    if [ "${attempt}" -ge "${nix_build_attempts}" ]; then
      return 1
    fi
    if ! nix_build_error_is_retryable "${attempt_log}"; then
      echo "nix build for .#${image_attr} failed with a non-retryable error; see ${attempt_log}" >&2
      return 1
    fi
    delay="$(nix_build_retry_delay "${attempt}")"
    echo "nix build for .#${image_attr} failed with a retryable fetch/cache error; retrying in ${delay}s (${attempt}/${nix_build_attempts})" >&2
    sleep "${delay}"
    attempt=$((attempt + 1))
  done
}

container_host_pid() {
  local container_name="$1"
  docker inspect -f '{{.State.Pid}}' "${container_name}" 2>/dev/null || true
}

monitor_docker_stats() {
  local output_path="$1"
  local interval_seconds="$2"
  shift 2
  local container_name
  while :; do
    for container_name in "$@"; do
      if docker inspect "${container_name}" >/dev/null 2>&1; then
        docker stats --no-stream --format '{{json .}}' "${container_name}" >> "${output_path}" 2>/dev/null || true
      fi
    done
    sleep "${interval_seconds}"
  done
}

write_profile_status() {
  local status_path="$1"
  local status="$2"
  local reason="$3"
  printf '%s\t%s\n' "${status}" "${reason}" > "${status_path}"
}

resolve_perf_bin() {
  if [ -n "${profile_perf_bin}" ]; then
    case "${profile_perf_bin}" in
      */*)
        [ -x "${profile_perf_bin}" ] && printf '%s\n' "${profile_perf_bin}"
        ;;
      *)
        command -v -- "${profile_perf_bin}"
        ;;
    esac
    return
  fi
  command -v perf
}

perf_command() {
  local perf_bin
  perf_bin="$(resolve_perf_bin)" || return 127
  if [ "${profile_use_sudo}" = "1" ]; then
    sudo -n "${perf_bin}" "$@"
  else
    "${perf_bin}" "$@"
  fi
}

start_perf_record() {
  local container_name="$1"
  local role="$2"
  local data_path="$3"
  local log_path="$4"
  local status_path="$5"
  local host_pid
  local perf_bin
  local recorder_name
  STARTED_PERF_PID=''
  STARTED_PERF_CONTAINER=''

  if [ "${profile_flamegraphs_enabled}" != "1" ]; then
    write_profile_status "${status_path}" "disabled" "PERF_PROFILE_FLAMEGRAPHS is not enabled"
    return
  fi
  if ! perf_bin="$(resolve_perf_bin)"; then
    write_profile_status "${status_path}" "unavailable" "perf is not available on the runner"
    return
  fi
  if [ "${profile_use_sudo}" = "1" ] && ! sudo -n true >/dev/null 2>&1; then
    write_profile_status "${status_path}" "unavailable" "passwordless sudo is not available for perf"
    return
  fi
  if [ "${profile_use_sudo}" = "1" ] && ! sudo -n "${perf_bin}" --version >/dev/null 2>&1; then
    write_profile_status "${status_path}" "unavailable" "passwordless sudo cannot execute perf"
    return
  fi

  host_pid="$(container_host_pid "${container_name}")"
  if ! is_managed_pid "${host_pid}"; then
    write_profile_status "${status_path}" "unavailable" "unable to resolve ${role} container host pid"
    return
  fi

  if [ -n "${profile_docker_image}" ]; then
    recorder_name="${container_name}-${role}-perf-record"
    docker rm -f "${recorder_name}" >/dev/null 2>&1 || true
    setsid docker run --rm \
      --name "${recorder_name}" \
      --privileged \
      --pid=host \
      -v "${results_root}:${results_root}" \
      -w "${results_root}" \
      "${profile_docker_image}" \
      record -F "${profile_frequency}" -g -p "${host_pid}" -o "${data_path}" > "${log_path}" 2>&1 &
    STARTED_PERF_CONTAINER="${recorder_name}"
  elif [ "${profile_use_sudo}" = "1" ]; then
    setsid sudo -n "${perf_bin}" record -F "${profile_frequency}" -g -p "${host_pid}" -o "${data_path}" > "${log_path}" 2>&1 &
  else
    setsid "${perf_bin}" record -F "${profile_frequency}" -g -p "${host_pid}" -o "${data_path}" > "${log_path}" 2>&1 &
  fi
  STARTED_PERF_PID="$!"
  write_profile_status "${status_path}" "recording" "perf recording started for host pid ${host_pid}"
}

generate_flamegraph() {
  local data_path="$1"
  local svg_path="$2"
  local title="$3"
  local log_path="$4"
  local script_path="${data_path}.script"
  local folded_path="${data_path}.folded"

  if [ ! -s "${data_path}" ]; then
    echo "perf data is empty or missing: ${data_path}" >> "${log_path}"
    return 1
  fi
  if command -v stackcollapse-perf.pl >/dev/null 2>&1 && command -v flamegraph.pl >/dev/null 2>&1; then
    perf_command script -i "${data_path}" > "${script_path}" 2>> "${log_path}" &&
      stackcollapse-perf.pl "${script_path}" > "${folded_path}" 2>> "${log_path}" &&
      flamegraph.pl --title "${title}" "${folded_path}" > "${svg_path}" 2>> "${log_path}"
  elif command -v inferno-collapse-perf >/dev/null 2>&1 && command -v inferno-flamegraph >/dev/null 2>&1; then
    perf_command script -i "${data_path}" > "${script_path}" 2>> "${log_path}" &&
      inferno-collapse-perf "${script_path}" > "${folded_path}" 2>> "${log_path}" &&
      inferno-flamegraph --title "${title}" "${folded_path}" > "${svg_path}" 2>> "${log_path}"
  else
    echo "flamegraph tooling is unavailable; install stackcollapse-perf.pl and flamegraph.pl or inferno-flamegraph" >> "${log_path}"
    return 1
  fi
}

write_failed_result() {
  local output_path="$1"
  local failure_reason="$2"
  local client_status_value="$3"
  local elapsed_ms_value
  if [ "${client_status_value}" = "124" ]; then
    elapsed_ms_value=$((run_timeout_seconds * 1000))
  else
    elapsed_ms_value=0
  fi
  python3 - <<'PY' \
    "${output_path}" \
    "${failure_reason}" \
    "${client_status_value}" \
    "${mode}" \
    "${direction}" \
    "${backend}" \
    "${congestion_control}" \
    "${server_name}" \
    "${port}" \
    "${elapsed_ms_value}" \
    "${warmup}" \
    "${request_bytes}" \
    "${response_bytes}" \
    "${streams}" \
    "${effective_connections}" \
    "${effective_inflight}"
import json
import pathlib
import re
import sys

(
    output_path,
    failure_reason,
    client_status,
    mode,
    direction,
    backend,
    congestion_control,
    remote_host,
    remote_port,
    elapsed_ms,
    warmup,
    request_bytes,
    response_bytes,
    streams,
    connections,
    requests_in_flight,
) = sys.argv[1:]


def parse_duration_ms(value: str) -> int:
    match = re.fullmatch(r"([0-9]+)(ms|s)", value)
    if not match:
        return 0
    amount = int(match.group(1))
    return amount if match.group(2) == "ms" else amount * 1000


record = {
    "schema_version": 1,
    "status": "failed",
    "failure_reason": failure_reason,
    "mode": mode,
    "direction": "download" if direction == "stay" else direction,
    "backend": backend,
    "congestion_control": congestion_control,
    "remote_host": remote_host,
    "remote_port": int(remote_port),
    "alpn": "coquic-perf/1",
    "elapsed_ms": int(elapsed_ms),
    "warmup_ms": parse_duration_ms(warmup),
    "bytes_sent": 0,
    "bytes_received": 0,
    "server_counters": {
        "bytes_sent": 0,
        "bytes_received": 0,
        "requests_completed": 0,
    },
    "requests_completed": 0,
    "streams": int(streams),
    "connections": int(connections),
    "requests_in_flight": int(requests_in_flight),
    "request_bytes": int(request_bytes),
    "response_bytes": int(response_bytes),
    "throughput_mib_per_s": 0.0,
    "throughput_gbit_per_s": 0.0,
    "requests_per_s": 0.0,
    "latency": {
        "min_us": 0,
        "avg_us": 0,
        "p50_us": 0,
        "p90_us": 0,
        "p99_us": 0,
        "max_us": 0,
    },
    "client_status": client_status,
}
pathlib.Path(output_path).write_text(json.dumps(record, indent=2) + "\n")
PY
}

finish_perf_record() {
  local recorder_pid="$1"
  local recorder_container="$2"
  local data_path="$3"
  local svg_path="$4"
  local title="$5"
  local log_path="$6"
  local status_path="$7"
  local current_status=''

  if [ -n "${recorder_container}" ]; then
    docker kill --signal INT "${recorder_container}" >/dev/null 2>&1 || true
    if is_managed_pid "${recorder_pid}"; then
      wait "${recorder_pid}" >/dev/null 2>&1 || true
    fi
  elif is_managed_pid "${recorder_pid}"; then
    if pid_is_alive "${recorder_pid}"; then
      signal_process_group INT "${recorder_pid}" || signal_pid INT "${recorder_pid}" || true
    fi
    wait "${recorder_pid}" >/dev/null 2>&1 || true
  elif [ -f "${status_path}" ]; then
    current_status="$(cut -f1 "${status_path}" 2>/dev/null || true)"
    if [ "${current_status}" = "disabled" ] || [ "${current_status}" = "unavailable" ]; then
      return
    fi
  fi

  if [ -s "${svg_path}" ]; then
    write_profile_status "${status_path}" "ok" "flamegraph generated"
    return
  fi
  if generate_flamegraph "${data_path}" "${svg_path}" "${title}" "${log_path}"; then
    write_profile_status "${status_path}" "ok" "flamegraph generated"
  else
    rm -f "${svg_path}"
    write_profile_status "${status_path}" "unavailable" "perf data could not be converted to a flamegraph"
  fi
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
      "socket bulk download 0 65536 none 1 1 1 0ms 5s"
      "socket rr stay 32 48 none 1 1 4 0ms 5s"
      "socket persistent-rr stay 32 48 none 1 1 4 0ms 5s"
      "socket crr stay 24 24 none 1 2 1 0ms 5s"
    )
    ;;
  ci)
    runs=(
      "socket bulk download 0 1048576 none 4 1 1 0ms 60s"
      "socket rr stay 32 32 none 1 128 4 5s 45s"
      "socket persistent-rr stay 32 32 none 1 128 4 5s 45s"
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
    newreno|cubic|bbr|copa|pcc|pcc-vivace)
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
  "${results_root}"/*.cid "${results_root}"/*.exit "${results_root}"/*.jsonl \
  "${results_root}"/*.perf.data "${results_root}"/*.perf.data.* "${results_root}"/*.flamegraph.svg \
  "${results_root}"/*.profile.status \
  "${environment_path}"

cleanup_containers() {
  if [ -n "${client_name}" ]; then
    docker rm -f "${client_name}" "${client_name}-client-perf-record" >/dev/null 2>&1 || true
  fi
  if [ -n "${server_name}" ]; then
    docker rm -f "${server_name}" "${server_name}-server-perf-record" >/dev/null 2>&1 || true
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
  echo "utilization_enabled=${utilization_enabled}"
  echo "stats_sample_interval_seconds=${stats_sample_interval_seconds}"
  echo "profile_flamegraphs_enabled=${profile_flamegraphs_enabled}"
  echo "profile_frequency=${profile_frequency}"
  echo "profile_use_sudo=${profile_use_sudo}"
  echo "profile_docker_image=${profile_docker_image}"
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
    if [ "${client_impl}" = 'coquic' ] && [ "${server_impl}" = 'coquic' ]; then
      run_name="${preset}-${congestion_control}-${backend}-${mode}-s${streams}-c${effective_connections}-q${effective_inflight}"
    else
      run_name="${preset}-${client_impl}-to-${server_impl}-${congestion_control}-${backend}-${mode}-s${streams}-c${effective_connections}-q${effective_inflight}"
    fi
    json_path="${results_root}/${run_name}.json"
    txt_path="${results_root}/${run_name}.txt"
    server_log_path="${results_root}/${run_name}.server.log"
    server_cid_path="${results_root}/${run_name}.server.cid"
    client_log_path="${results_root}/${run_name}.client.log"
    stats_path="${results_root}/${run_name}.stats.jsonl"
    client_perf_data_path="${results_root}/${run_name}.client.perf.data"
    server_perf_data_path="${results_root}/${run_name}.server.perf.data"
    client_flamegraph_path="${results_root}/${run_name}.client.flamegraph.svg"
    server_flamegraph_path="${results_root}/${run_name}.server.flamegraph.svg"
    client_profile_log_path="${results_root}/${run_name}.client.perf.log"
    server_profile_log_path="${results_root}/${run_name}.server.perf.log"
    client_profile_status_path="${results_root}/${run_name}.client.profile.status"
    server_profile_status_path="${results_root}/${run_name}.server.profile.status"
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
      if [ "${limit}" != 'none' ]; then
        client_args+=(--total-bytes "${limit}")
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

    timeout --kill-after=5s "${run_timeout_seconds}s" docker run -d \
      --name "${client_name}" \
      --network "${network_name}" \
      --cpuset-cpus "${client_cpus}" \
      "${docker_env_args[@]}" \
      -v "${results_root}:/results" \
      -v "${repo_root}/tests/fixtures:/certs:ro" \
      "${client_entrypoint[@]}" \
      "${image_tag}" "${client_args[@]}" > "${results_root}/${run_name}.client.cid"
    client_start_status=$?
    client_status=125
    stats_pid=''
    client_perf_pid=''
    client_perf_container=''
    server_perf_pid=''
    server_perf_container=''
    if [ "${client_start_status}" -eq 0 ]; then
      if [ "${utilization_enabled}" = "1" ]; then
        monitor_docker_stats "${stats_path}" "${stats_sample_interval_seconds}" "${client_name}" "${server_name}" &
        stats_pid="$!"
      fi
      start_perf_record "${client_name}" "client" "${client_perf_data_path}" "${client_profile_log_path}" "${client_profile_status_path}" || true
      client_perf_pid="${STARTED_PERF_PID:-}"
      client_perf_container="${STARTED_PERF_CONTAINER:-}"
      start_perf_record "${server_name}" "server" "${server_perf_data_path}" "${server_profile_log_path}" "${server_profile_status_path}" || true
      server_perf_pid="${STARTED_PERF_PID:-}"
      server_perf_container="${STARTED_PERF_CONTAINER:-}"
      timeout --kill-after=5s "${run_timeout_seconds}s" docker wait "${client_name}" > "${results_root}/${run_name}.client.exit" || true
      if [ -s "${results_root}/${run_name}.client.exit" ]; then
        client_status="$(tail -n 1 "${results_root}/${run_name}.client.exit")"
      else
        client_status=124
        docker kill "${client_name}" >/dev/null 2>&1 || true
      fi
      if is_managed_pid "${stats_pid}"; then
        kill -- "${stats_pid}" >/dev/null 2>&1 || true
        wait "${stats_pid}" >/dev/null 2>&1 || true
      fi
      finish_perf_record "${client_perf_pid}" "${client_perf_container}" "${client_perf_data_path}" "${client_flamegraph_path}" "${run_name} client" "${client_profile_log_path}" "${client_profile_status_path}"
      finish_perf_record "${server_perf_pid}" "${server_perf_container}" "${server_perf_data_path}" "${server_flamegraph_path}" "${run_name} server" "${server_profile_log_path}" "${server_profile_status_path}"
      docker logs "${client_name}" > "${client_log_path}" 2>&1 || true
      cp "${client_log_path}" "${txt_path}"
      cat "${txt_path}"
    else
      echo "client container failed to start for ${run_name}" | tee "${txt_path}" >&2
    fi
    set -e

    docker logs "${server_name}" > "${server_log_path}" 2>&1 || true
    docker rm -f "${server_name}" "${server_name}-server-perf-record" >/dev/null 2>&1 || true
    docker rm -f "${client_name}" "${client_name}-client-perf-record" >/dev/null 2>&1 || true

    if [ ! -f "${results_root}/result.json" ]; then
      failure_reason="missing JSON result for ${run_name}: ${results_root}/result.json"
      echo "${failure_reason}" >&2
      write_failed_result "${json_path}" "${failure_reason}" "${client_status:-1}"
      failed_runs=1
      continue
    fi
    mv "${results_root}/result.json" "${json_path}"

    if [ "${client_status}" -ne 0 ]; then
      echo "client container failed for ${run_name} with status ${client_status}; kept ${json_path}" >&2
      failed_runs=1
    fi
  done
done

python3 - <<'PY' "${results_root}" "${manifest_path}" "${preset}" "${image_attr}" "${image_tag}" "${congestion_controls}" "${client_impl}" "${server_impl}" "${library_version}" "${implementations_manifest}" "${client_cpus}" "${server_cpus}"
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

def cpuset_count(value):
    count = 0
    for part in str(value).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            if start.isdigit() and end.isdigit() and int(end) >= int(start):
                count += int(end) - int(start) + 1
        elif part.isdigit():
            count += 1
    return max(count, 1)


client_cpu_count = cpuset_count(sys.argv[11])
server_cpu_count = cpuset_count(sys.argv[12])


def parse_percent(value):
    try:
        return float(str(value).strip().rstrip("%"))
    except ValueError:
        return None


def parse_memory_bytes(value):
    units = {
        "b": 1,
        "kib": 1024,
        "mib": 1024**2,
        "gib": 1024**3,
        "tib": 1024**4,
        "kb": 1000,
        "mb": 1000**2,
        "gb": 1000**3,
        "tb": 1000**4,
    }
    text = str(value).strip()
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    number = ""
    unit = ""
    for char in text:
        if char.isdigit() or char in ".-":
            number += char
        elif not char.isspace():
            unit += char
    try:
        parsed = float(number)
    except ValueError:
        return None
    return int(parsed * units.get(unit.lower(), 1))


def summarize(values):
    if not values:
        return {}
    ordered = sorted(values)
    return {
        "avg": sum(values) / len(values),
        "max": max(values),
        "p50": ordered[len(ordered) // 2],
        "samples": len(values),
    }


def load_stats(path, client_name_fragment, server_name_fragment):
    grouped = {
        "client": {"cpu": [], "mem": []},
        "server": {"cpu": [], "mem": []},
    }
    if not path.exists():
        return {}
    for line in path.read_text(errors="replace").splitlines():
        try:
            sample = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = str(sample.get("Name") or sample.get("Container") or "")
        role = None
        if "client" in name:
            role = "client"
        elif "server" in name:
            role = "server"
        elif client_name_fragment in name:
            role = "client"
        elif server_name_fragment in name:
            role = "server"
        if role is None:
            continue
        cpu = parse_percent(sample.get("CPUPerc"))
        if cpu is not None:
            grouped[role]["cpu"].append(cpu)
        mem = parse_memory_bytes(sample.get("MemUsage"))
        if mem is not None:
            grouped[role]["mem"].append(mem)
    output = {}
    for role, samples in grouped.items():
        cpu = summarize(samples["cpu"])
        mem = summarize(samples["mem"])
        if not cpu and not mem:
            continue
        cpu_count = client_cpu_count if role == "client" else server_cpu_count
        role_output = {}
        if cpu:
            role_output.update(
                {
                    "cpu_percent_avg": cpu["avg"],
                    "cpu_percent_max": cpu["max"],
                    "cpu_percent_p50": cpu["p50"],
                    "cpu_limit": cpu_count,
                    "cpu_utilization_avg": cpu["avg"] / (100.0 * cpu_count),
                    "cpu_utilization_max": cpu["max"] / (100.0 * cpu_count),
                    "samples": cpu["samples"],
                }
            )
        if mem:
            role_output.update(
                {
                    "memory_bytes_avg": mem["avg"],
                    "memory_bytes_max": mem["max"],
                }
            )
        output[role] = role_output
    return output


def load_profile_status(path):
    if not path.exists():
        return {"status": "unavailable", "reason": "profile status was not recorded"}
    status, _, reason = path.read_text(errors="replace").partition("\t")
    return {"status": status.strip() or "unavailable", "reason": reason.strip()}


def profile_entry(role, base_name):
    svg_name = f"{base_name}.{role}.flamegraph.svg"
    log_name = f"{base_name}.{role}.perf.log"
    status = load_profile_status(root / f"{base_name}.{role}.profile.status")
    entry = dict(status)
    if (root / svg_name).exists():
        entry["svg_file"] = svg_name
    if (root / log_name).exists():
        entry["log_file"] = log_name
    return entry

runs = []
for path in sorted(root.glob('*.json')):
    if path.name == manifest_path.name:
        continue
    record = json.loads(path.read_text())
    record['result_file'] = path.name
    base_name = path.stem
    txt_path = path.with_suffix('.txt')
    if txt_path.exists():
        record['summary_file'] = txt_path.name
    stats_path = root / f"{base_name}.stats.jsonl"
    if stats_path.exists():
        record['stats_file'] = stats_path.name
        stats = load_stats(stats_path, "client", "server")
        if stats:
            record['utilization'] = stats
    profiles = {
        "client": profile_entry("client", base_name),
        "server": profile_entry("server", base_name),
    }
    if any(profile.get("status") != "disabled" or profile.get("svg_file") for profile in profiles.values()):
        record['profiles'] = profiles
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
