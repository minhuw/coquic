#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
state_dir="${RATTAN_TRACE_STATE_DIR:-${repo_root}/.bench-traces}"
prepare_subset="${RATTAN_PREPARE_SUBSET:-full}"
quick_subset="${RATTAN_QUICK_SUBSET:-quick}"
quick_dir="${RATTAN_QUICK_DIR:-${state_dir}/banks/${quick_subset}}"
quick_manifest="${RATTAN_QUICK_MANIFEST:-${quick_dir}/manifest.json}"
window_seconds="${RATTAN_WINDOW_SECONDS:-30}"
target_wallclock_seconds="${RATTAN_TARGET_WALLCLOCK_SECONDS:-1800}"
per_run_overhead_seconds="${RATTAN_PER_RUN_OVERHEAD_SECONDS:-7}"
min_avg_mbps="${RATTAN_MIN_AVG_MBPS:-0.05}"
max_outage_ratio="${RATTAN_MAX_OUTAGE_RATIO:-0.5}"
max_windows="${RATTAN_MAX_WINDOWS:-}"

export RATTAN_CONGESTION_CONTROLS="${RATTAN_CONGESTION_CONTROLS:-pcc-vivace}"
export RATTAN_MODES="${RATTAN_MODES:-bulk-download}"
export RATTAN_REPETITIONS="${RATTAN_REPETITIONS:-1}"
export RATTAN_DURATION="${RATTAN_DURATION:-${window_seconds}s}"
export RATTAN_WARMUP="${RATTAN_WARMUP:-0s}"
export RATTAN_TOTAL_BYTES="${RATTAN_TOTAL_BYTES-}"
export RATTAN_TRACE_MANIFEST="${RATTAN_TRACE_MANIFEST:-${quick_manifest}}"

read -r -a cc_list <<<"${RATTAN_CONGESTION_CONTROLS}"
read -r -a mode_list <<<"${RATTAN_MODES}"
matrix_multiplier=$((${#cc_list[@]} * ${#mode_list[@]} * RATTAN_REPETITIONS))
if [ "${matrix_multiplier}" -lt 1 ]; then
  matrix_multiplier=1
fi

bank_args=()
if [ -n "${max_windows}" ]; then
  bank_args+=(--max-windows "${max_windows}")
fi

python3 "${repo_root}/bench/rattan/prepare-traces.py" \
  --subset "${prepare_subset}" \
  --state-dir "${state_dir}" \
  --direction-model symmetric >/dev/null

python3 "${repo_root}/bench/rattan/build-trace-bank.py" \
  --manifest "${state_dir}/manifest.json" \
  --output-dir "${quick_dir}" \
  --output-manifest "${quick_manifest}" \
  --subset-name "${quick_subset}" \
  --window-seconds "${window_seconds}" \
  --target-wallclock-seconds "${target_wallclock_seconds}" \
  --per-run-overhead-seconds "${per_run_overhead_seconds}" \
  --min-avg-mbps "${min_avg_mbps}" \
  --max-outage-ratio "${max_outage_ratio}" \
  --matrix-multiplier "${matrix_multiplier}" \
  "${bank_args[@]}" >/dev/null

exec "${repo_root}/bench/rattan/run-rattan-matrix.sh" --subset "${quick_subset}" --skip-prepare "$@"
