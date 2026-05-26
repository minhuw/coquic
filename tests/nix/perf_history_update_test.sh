#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="${repo_root}/scripts/update-perf-history.py"
tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

make_snapshot() {
  local path="$1"
  local generated_at="$2"
  local implementation="$3"
  local mib="$4"

  cat > "${path}" <<JSON
{
  "schema_version": 1,
  "generated_at": "${generated_at}",
  "event_name": "schedule",
  "commit": "0123456789abcdef0123456789abcdef01234567",
  "sources": [
    {"label": "${implementation}", "missing": false, "ok_runs": 1, "total_runs": 1}
  ],
  "rows": [
    {
      "implementation": "${implementation}",
      "pair": "${implementation} -> ${implementation}",
      "mode": "bulk",
      "status": "ok",
      "congestion_control": "default",
      "elapsed_ms": 60000,
      "throughput_mib_per_s": ${mib},
      "throughput_gbit_per_s": 1.0,
      "requests_per_s": 0,
      "p50_us": 0,
      "p99_us": 0,
      "skipped_setup_errors": 0,
      "result": "bulk.json",
      "failure_reason": ""
    }
  ]
}
JSON
}

snapshot_one="${tmpdir}/snapshot-one.json"
snapshot_two="${tmpdir}/snapshot-two.json"
snapshot_three="${tmpdir}/snapshot-three.json"
history_one="${tmpdir}/history-one.json"
history_two="${tmpdir}/history-two.json"
history_three="${tmpdir}/history-three.json"
empty_history="${tmpdir}/empty-history.json"
history_from_empty="${tmpdir}/history-from-empty.json"
output="${tmpdir}/output.txt"
stderr_output="${tmpdir}/stderr.txt"

make_snapshot "${snapshot_one}" "2026-05-24T03:00:00Z" "quic-go" "111.0"
make_snapshot "${snapshot_two}" "2026-05-25T03:00:00Z" "quinn" "222.0"
make_snapshot "${snapshot_three}" "2026-05-25T04:00:00Z" "quiche" "333.0"

python3 "${script}" \
  --snapshot "${snapshot_one}" \
  --json-out "${history_one}" \
  --max-days 2 > "${output}"

grep -F "perf history contains 1 daily snapshots; latest=2026-05-24" "${output}" >/dev/null || {
  echo "missing first history summary" >&2
  exit 1
}

: > "${empty_history}"
python3 "${script}" \
  --snapshot "${snapshot_one}" \
  --history "${empty_history}" \
  --json-out "${history_from_empty}" \
  --max-days 2 > "${output}"

python3 - "${history_from_empty}" <<'PY'
import json
import pathlib
import sys

history = json.loads(pathlib.Path(sys.argv[1]).read_text())
if len(history["snapshots"]) != 1:
    raise SystemExit("empty existing history should behave like no history")
PY

python3 "${script}" \
  --snapshot "${snapshot_two}" \
  --history "${history_one}" \
  --json-out "${history_two}" \
  --max-days 2 > "${output}"

python3 "${script}" \
  --snapshot "${snapshot_three}" \
  --history "${history_two}" \
  --json-out "${history_three}" \
  --max-days 2 > "${output}"

python3 - "${history_three}" <<'PY'
import json
import pathlib
import sys

history = json.loads(pathlib.Path(sys.argv[1]).read_text())
if history["schema_version"] != 1:
    raise SystemExit("unexpected schema version")
if history["max_days"] != 2:
    raise SystemExit("unexpected max_days")
snapshots = history["snapshots"]
if [snapshot["date"] for snapshot in snapshots] != ["2026-05-24", "2026-05-25"]:
    raise SystemExit("unexpected snapshot dates")
latest = snapshots[-1]
if latest["rows"][0]["implementation"] != "quiche":
    raise SystemExit("same-day snapshot was not replaced")
if latest["rows"][0]["throughput_mib_per_s"] != 333.0:
    raise SystemExit("unexpected latest metric")
PY

invalid_snapshot="${tmpdir}/invalid-snapshot.json"
printf '{"schema_version": 2, "sources": [], "rows": []}\n' > "${invalid_snapshot}"
if python3 "${script}" --snapshot "${invalid_snapshot}" --json-out "${tmpdir}/invalid-history.json" > "${output}" 2>"${stderr_output}"; then
  echo "invalid snapshot should fail" >&2
  exit 1
fi

grep -F "error: snapshot schema_version must be 1" "${stderr_output}" >/dev/null || {
  echo "missing invalid snapshot error" >&2
  exit 1
}

echo "perf history updater contract looks correct"
