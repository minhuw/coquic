#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

script="interop/run-official.sh"

grep -F 'readonly interop_runner_output_tail_lines=' "${script}" >/dev/null || {
  echo "run-official must define a configurable runner output tail length" >&2
  exit 1
}

grep -F 'show_runner_output_tail()' "${script}" >/dev/null || {
  echo "run-official must expose a helper for printing a bounded runner log tail" >&2
  exit 1
}

grep -F 'readonly interop_retry_testcases="${INTEROP_RETRY_TESTCASES:-amplificationlimit,handshakeloss,handshakecorruption}"' "${script}" >/dev/null || {
  echo "run-official must keep stochastic isolated retries configurable" >&2
  exit 1
}

grep -F 'Retrying official ${server}/${client} testcase in isolation: ${testcase}' "${script}" >/dev/null || {
  echo "run-official must isolate retryable official testcase failures" >&2
  exit 1
}

grep -F 'mark_official_testcases_recovered "${results_json}"' "${script}" >/dev/null || {
  echo "run-official must record recovered official testcase retries" >&2
  exit 1
}

grep -F 'Official runner output saved to ${runner_output_log}' "${script}" >/dev/null || {
  echo "run-official must record where full runner output was written" >&2
  exit 1
}

grep -F '> "${runner_output_log}" 2>&1' "${script}" >/dev/null || {
  echo "run-official must redirect full runner output to a file" >&2
  exit 1
}

if grep -F 'run_output="$(' "${script}" >/dev/null; then
  echo "run-official must not buffer full runner output in a shell variable" >&2
  exit 1
fi

if grep -F "printf '%s\\n' \"\${run_output}\"" "${script}" >/dev/null; then
  echo "run-official must not print the full runner output unconditionally" >&2
  exit 1
fi

echo "run-official logging contract looks correct"
