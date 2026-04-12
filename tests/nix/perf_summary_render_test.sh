#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="${repo_root}/tests/fixtures/perf/smoke-manifest.json"
script="${repo_root}/scripts/render-perf-summary.py"
empty_manifest="$(mktemp)"
invalid_json_manifest="$(mktemp)"
invalid_runs_manifest="$(mktemp)"
invalid_metric_manifest="$(mktemp)"
output="$(mktemp)"
stderr_output="$(mktemp)"
trap 'rm -f "${output}" "${stderr_output}" "${empty_manifest}" "${invalid_json_manifest}" "${invalid_runs_manifest}" "${invalid_metric_manifest}"' EXIT

python3 "${script}"   --manifest "${manifest}"   --event-name pull_request   --commit 0123456789abcdef0123456789abcdef01234567   > "${output}"

grep -F '## Advisory QUIC Perf' "${output}" >/dev/null || {
  echo 'missing summary title' >&2
  exit 1
}

grep -F 'Event: `pull_request`' "${output}" >/dev/null || {
  echo 'missing event name line' >&2
  exit 1
}

grep -F 'Commit: `0123456789abcdef0123456789abcdef01234567`' "${output}" >/dev/null || {
  echo 'missing commit line' >&2
  exit 1
}

grep -F 'Preset: `smoke`' "${output}" >/dev/null || {
  echo 'missing preset line' >&2
  exit 1
}

grep -F 'Image: `coquic-perf:quictls-musl`' "${output}" >/dev/null || {
  echo 'missing image line' >&2
  exit 1
}

grep -F '| socket | rr | ok | 98 | 0.025 | 326.531 | 5565 | 21820 | smoke-socket-rr-s1-c1-q4.json |' "${output}" >/dev/null || {
  echo 'missing success row' >&2
  exit 1
}

grep -F '| io_uring | crr | failed | 17 | 0.000 | 0.000 | 0 | 0 | smoke-io_uring-crr-s1-c2-q1.json |' "${output}" >/dev/null || {
  echo 'missing failure row' >&2
  exit 1
}

grep -F 'Benchmark data from GitHub-hosted runners is advisory and may vary between runs.' "${output}" >/dev/null || {
  echo 'missing advisory note' >&2
  exit 1
}

grep -F '### Failures' "${output}" >/dev/null || {
  echo 'missing failures header' >&2
  exit 1
}

grep -F -- '- `io_uring/crr`: client wait failed' "${output}" >/dev/null || {
  echo 'missing failure reason section' >&2
  exit 1
}

printf '%s
' '{' '  "preset": "smoke",' '  "image_tag": "coquic-perf:quictls-musl",' '  "runs": []' '}' > "${empty_manifest}"
python3 "${script}" --manifest "${empty_manifest}" --event-name pull_request --commit 0123456789abcdef0123456789abcdef01234567 > "${output}"
grep -F 'No benchmark runs were recorded.' "${output}" >/dev/null || {
  echo 'missing empty-run message' >&2
  exit 1
}

printf '%s
' '{' > "${invalid_json_manifest}"
if python3 "${script}" --manifest "${invalid_json_manifest}" --event-name pull_request --commit 0123456789abcdef0123456789abcdef01234567 > "${output}" 2>"${stderr_output}"; then
  echo 'invalid JSON manifest should fail' >&2
  exit 1
fi
grep -F 'error: failed to parse manifest JSON:' "${stderr_output}" >/dev/null || {
  echo 'missing invalid JSON error' >&2
  exit 1
}

printf '%s
' '{' '  "preset": "smoke",' '  "image_tag": "coquic-perf:quictls-musl",' '  "runs": {}' '}' > "${invalid_runs_manifest}"
if python3 "${script}" --manifest "${invalid_runs_manifest}" --event-name pull_request --commit 0123456789abcdef0123456789abcdef01234567 > "${output}" 2>"${stderr_output}"; then
  echo 'invalid runs manifest should fail' >&2
  exit 1
fi
grep -F 'error: manifest field `runs` must be a list' "${stderr_output}" >/dev/null || {
  echo 'missing invalid runs error' >&2
  exit 1
}

printf '%s
' '{' '  "preset": "smoke",' '  "image_tag": "coquic-perf:quictls-musl",' '  "runs": [' '    {' '      "status": "ok",' '      "mode": "rr",' '      "backend": "socket",' '      "elapsed_ms": 1,' '      "throughput_mib_per_s": "bad",' '      "requests_per_s": 1.0,' '      "latency": {' '        "p50_us": 1,' '        "p99_us": 1' '      },' '      "result_file": "bad.json"' '    }' '  ]' '}' > "${invalid_metric_manifest}"
if python3 "${script}" --manifest "${invalid_metric_manifest}" --event-name pull_request --commit 0123456789abcdef0123456789abcdef01234567 > "${output}" 2>"${stderr_output}"; then
  echo 'invalid metric manifest should fail' >&2
  exit 1
fi
grep -F 'error: run field `throughput_mib_per_s` must be numeric' "${stderr_output}" >/dev/null || {
  echo 'missing invalid metric error' >&2
  exit 1
}

echo 'perf summary renderer looks correct'
