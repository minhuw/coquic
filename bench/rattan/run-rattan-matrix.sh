#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
subset=smoke
trace_manifest="${RATTAN_TRACE_MANIFEST:-${repo_root}/.bench-traces/manifest.json}"
results_root="${RATTAN_RESULTS_ROOT:-${repo_root}/.bench-results/rattan/$(date -u +%Y%m%dT%H%M%SZ)}"
rattan_bin="${RATTAN_BIN:-rattan}"
rattan_use_sudo="${RATTAN_USE_SUDO:-0}"
rattan_extra_args="${RATTAN_EXTRA_ARGS:-}"
perf_bin="${RATTAN_PERF_BIN:-${repo_root}/zig-out/bin/coquic-perf}"
congestion_controls="${RATTAN_CONGESTION_CONTROLS:-newreno}"
modes="${RATTAN_MODES:-bulk-download}"
repetitions="${RATTAN_REPETITIONS:-1}"
duration="${RATTAN_DURATION:-30s}"
warmup="${RATTAN_WARMUP:-0s}"
total_bytes="${RATTAN_TOTAL_BYTES-}"
requests="${RATTAN_REQUESTS:-1000}"
request_bytes="${RATTAN_REQUEST_BYTES:-64}"
response_bytes="${RATTAN_RESPONSE_BYTES-}"
default_response_bytes=65536
bulk_download_response_bytes="${RATTAN_BULK_DOWNLOAD_RESPONSE_BYTES:-16777216}"
streams="${RATTAN_STREAMS:-1}"
connections="${RATTAN_CONNECTIONS:-1}"
requests_in_flight="${RATTAN_REQUESTS_IN_FLIGHT:-1}"
queue_bdp_multiplier="${RATTAN_QUEUE_BDP_MULTIPLIER:-2.0}"
min_queue_bytes="${RATTAN_MIN_QUEUE_BYTES:-65536}"
loss_rate="${RATTAN_LOSS_RATE:-0.0}"
server_host="${RATTAN_SERVER_HOST:-10.2.1.1}"
io_backend="${RATTAN_IO_BACKEND:-socket}"
run_timeout="${RATTAN_RUN_TIMEOUT:-90s}"
dry_run=0
skip_prepare=0
trace_filter=()

usage() {
  cat <<'USAGE'
usage: bench/rattan/run-rattan-matrix.sh [--subset NAME] [--trace-id ID] [--dry-run] [--skip-prepare]

Environment overrides:
  RATTAN_BIN                    rattan binary (default: rattan)
  RATTAN_PERF_BIN               coquic-perf binary (default: zig-out/bin/coquic-perf)
  RATTAN_TRACE_MANIFEST         prepared trace manifest (default: .bench-traces/manifest.json)
  RATTAN_RESULTS_ROOT           result directory (default: .bench-results/rattan/<utc-timestamp>)
  RATTAN_USE_SUDO               run rattan through sudo -E when set to 1 (default: 0)
  RATTAN_EXTRA_ARGS             extra whitespace-separated rattan CLI args
  RATTAN_CONGESTION_CONTROLS    algorithms (default: newreno)
  RATTAN_MODES                  workload labels: bulk-download bulk-upload rr crr persistent-rr
  RATTAN_REPETITIONS            repetitions per trace/control/workload (default: 1)
  RATTAN_DURATION               measured duration (default: 30s)
  RATTAN_WARMUP                 warmup duration (default: 0s)
  RATTAN_TOTAL_BYTES            optional bulk byte target; empty means timed bulk
  RATTAN_REQUESTS               request count for rr/crr/persistent-rr (default: 1000)
  RATTAN_REQUEST_BYTES          request bytes (default: 64)
  RATTAN_RESPONSE_BYTES         response bytes override for all workloads
  RATTAN_BULK_DOWNLOAD_RESPONSE_BYTES
                                  bulk-download response bytes when unset (default: 16777216)
  RATTAN_STREAMS                streams (default: 1)
  RATTAN_CONNECTIONS            connections (default: 1)
  RATTAN_REQUESTS_IN_FLIGHT     request concurrency (default: 1)
  RATTAN_QUEUE_BDP_MULTIPLIER   queue size multiplier over average BDP (default: 2.0)
  RATTAN_MIN_QUEUE_BYTES        minimum queue size in bytes (default: 65536)
  RATTAN_LOSS_RATE              optional fixed per-packet loss rate (default: 0.0)
  RATTAN_SERVER_HOST            right namespace server IP (default: 10.2.1.1)
  RATTAN_IO_BACKEND             coquic-perf IO backend (default: socket)
  RATTAN_RUN_TIMEOUT            timeout per Rattan invocation (default: 90s)
USAGE
}

cleanup_run_processes() {
  local run_dir="$1"
  local kill_cmd=(kill)
  if [ "${rattan_use_sudo}" = "1" ]; then
    kill_cmd=(sudo kill)
  fi
  local -a pids=()
  mapfile -t pids < <(
    ps -eo pid=,comm=,args= |
      awk -v run_dir="${run_dir}" -v self="$$" '
        $1 != self && ($2 == "coquic-perf" || $2 == "rattan") && index($0, run_dir) { print $1 }
      '
  )
  if [ "${#pids[@]}" -eq 0 ]; then
    return 0
  fi
  "${kill_cmd[@]}" -TERM "${pids[@]}" 2>/dev/null || true
  sleep 1
  "${kill_cmd[@]}" -KILL "${pids[@]}" 2>/dev/null || true
}

while [ $# -gt 0 ]; do
  case "$1" in
    --subset)
      subset="$2"
      shift 2
      ;;
    --trace-id)
      trace_filter+=("$2")
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --skip-prepare)
      skip_prepare=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "${results_root}"
results_root="$(cd "${results_root}" && pwd)"

if [ "${skip_prepare}" = "0" ]; then
  prepare_args=(--subset "${subset}")
  for trace_id in "${trace_filter[@]}"; do
    prepare_args+=(--trace-id "${trace_id}")
  done
  python3 "${repo_root}/bench/rattan/prepare-traces.py" "${prepare_args[@]}" >/dev/null
fi

if [ ! -f "${trace_manifest}" ]; then
  echo "missing trace manifest: ${trace_manifest}" >&2
  exit 1
fi

mapfile -t traces < <(python3 - <<'PY' "${trace_manifest}" "${subset}" "${trace_filter[@]}"
import json
import sys

manifest = json.loads(open(sys.argv[1], encoding="utf-8").read())
subset = sys.argv[2]
requested = set(sys.argv[3:])
for trace in manifest.get("traces", []):
    if requested and trace["id"] not in requested:
        continue
    if not requested and subset not in set(trace.get("subset", [])):
        continue
    print(trace["id"])
PY
)

if [ "${#traces[@]}" -eq 0 ]; then
  echo "no prepared traces selected" >&2
  exit 1
fi

read -r -a rattan_extra_arg_list <<<"${rattan_extra_args}"
if [ "${rattan_use_sudo}" = "1" ]; then
  rattan_cmd=(sudo -E "${rattan_bin}" run)
else
  rattan_cmd=("${rattan_bin}" run)
fi

{
  echo "subset=${subset}"
  echo "trace_manifest=${trace_manifest}"
  echo "results_root=${results_root}"
  echo "rattan_bin=${rattan_bin}"
  echo "rattan_use_sudo=${rattan_use_sudo}"
  echo "rattan_extra_args=${rattan_extra_args}"
  printf "rattan_command="
  printf "%q " "${rattan_cmd[@]}" "${rattan_extra_arg_list[@]}"
  echo
  echo "perf_bin=${perf_bin}"
  echo "congestion_controls=${congestion_controls}"
  echo "modes=${modes}"
  echo "repetitions=${repetitions}"
  echo "duration=${duration}"
  echo "warmup=${warmup}"
  echo "total_bytes=${total_bytes}"
  echo "requests=${requests}"
  echo "request_bytes=${request_bytes}"
  echo "response_bytes=${response_bytes:-mode-default}"
  echo "default_response_bytes=${default_response_bytes}"
  echo "bulk_download_response_bytes=${bulk_download_response_bytes}"
  echo "streams=${streams}"
  echo "connections=${connections}"
  echo "requests_in_flight=${requests_in_flight}"
  echo "queue_bdp_multiplier=${queue_bdp_multiplier}"
  echo "min_queue_bytes=${min_queue_bytes}"
  echo "loss_rate=${loss_rate}"
  echo "server_host=${server_host}"
  echo "io_backend=${io_backend}"
  echo "run_timeout=${run_timeout}"
  echo
  uname -a
  command -v "${rattan_bin}" || true
  if [ "${rattan_use_sudo}" = "1" ]; then
    command -v sudo || true
  fi
  command -v "${perf_bin}" || true
} > "${results_root}/environment.txt"

read -r -a cc_list <<<"${congestion_controls}"
read -r -a mode_list <<<"${modes}"

for trace_id in "${traces[@]}"; do
  for cc in "${cc_list[@]}"; do
    for mode_label in "${mode_list[@]}"; do
      for rep in $(seq 1 "${repetitions}"); do
        case "${mode_label}" in
          bulk-download)
            mode=bulk
            direction=download
            effective_response_bytes="${response_bytes:-${bulk_download_response_bytes}}"
            extra_limit=()
            if [ -n "${total_bytes}" ]; then
              extra_limit=(--total-bytes "${total_bytes}")
            fi
            ;;
          bulk-upload)
            mode=bulk
            direction=upload
            effective_response_bytes="${response_bytes:-${default_response_bytes}}"
            extra_limit=()
            if [ -n "${total_bytes}" ]; then
              extra_limit=(--total-bytes "${total_bytes}")
            fi
            ;;
          rr|crr|persistent-rr)
            mode="${mode_label}"
            direction=download
            effective_response_bytes="${response_bytes:-${default_response_bytes}}"
            extra_limit=(--requests "${requests}")
            ;;
          *)
            echo "unsupported mode label: ${mode_label}" >&2
            exit 2
            ;;
        esac

        run_name="${trace_id}-${cc}-${mode_label}-rep${rep}"
        run_dir="${results_root}/${run_name}"
        mkdir -p "${run_dir}"
        config_path="${run_dir}/${run_name}.rattan.toml"

        python3 "${repo_root}/bench/rattan/generate-config.py" \
          --manifest "${trace_manifest}" \
          --trace-id "${trace_id}" \
          --output "${config_path}" \
          --results-root "${run_dir}" \
          --perf-bin "${perf_bin}" \
          --congestion-control "${cc}" \
          --mode "${mode}" \
          --direction "${direction}" \
          --request-bytes "${request_bytes}" \
          --response-bytes "${effective_response_bytes}" \
          --streams "${streams}" \
          --connections "${connections}" \
          --requests-in-flight "${requests_in_flight}" \
          --warmup "${warmup}" \
          --duration "${duration}" \
          --queue-bdp-multiplier "${queue_bdp_multiplier}" \
          --min-queue-bytes "${min_queue_bytes}" \
          --loss-rate "${loss_rate}" \
          --server-host "${server_host}" \
          --io-backend "${io_backend}" \
          "${extra_limit[@]}" >/dev/null

        if [ "${dry_run}" = "1" ]; then
          echo "generated ${config_path}"
          continue
        fi

        set +e
        timeout --kill-after=5s "${run_timeout}" \
          "${rattan_cmd[@]}" "${rattan_extra_arg_list[@]}" -c "${config_path}" > "${run_dir}/rattan.log" 2>&1
        status=$?
        set -e
        echo "${status}" > "${run_dir}/rattan.exit"
        if [ "${status}" -ne 0 ]; then
          echo "rattan run failed: ${run_name}" >&2
          cleanup_run_processes "${run_dir}"
        else
          cleanup_run_processes "${run_dir}"
        fi
      done
    done
  done
done

python3 "${repo_root}/bench/rattan/summarize-results.py" "${results_root}" >/dev/null
echo "${results_root}"
