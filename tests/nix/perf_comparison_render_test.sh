#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="${repo_root}/scripts/render-perf-comparison.py"
tmpdir="$(mktemp -d)"
output="$(mktemp)"
stderr_output="$(mktemp)"
json_output="$(mktemp)"
coquic_snapshot="$(mktemp)"
quic_go_snapshot="$(mktemp)"
merged_snapshot="$(mktemp)"
json_nested_output="$(mktemp -d)/nested/perf-results.json"
trap 'rm -rf "${tmpdir}" "${output}" "${stderr_output}" "${json_output}" "${coquic_snapshot}" "${quic_go_snapshot}" "${merged_snapshot}"' EXIT

make_manifest() {
  local dir="$1"
  local client_impl="$2"
  local server_impl="$3"
  local congestion_control="$4"
  local bulk_mib="$5"
  local rr_requests="$6"
  local crr_requests="$7"
  local crr_status="$8"
  local failure_reason="$9"

  install -d "${dir}"
  cat > "${dir}/manifest.json" <<JSON
{
  "preset": "ci",
  "client_impl": "${client_impl}",
  "server_impl": "${server_impl}",
  "runs": [
    {
      "status": "ok",
      "mode": "bulk",
      "backend": "socket",
      "congestion_control": "${congestion_control}",
      "elapsed_ms": 60000,
      "throughput_mib_per_s": ${bulk_mib},
      "throughput_gbit_per_s": 1.5,
      "requests_per_s": 0.0,
      "latency": {"p50_us": 0, "p99_us": 0},
      "result_file": "bulk.json"
    },
    {
      "status": "ok",
      "mode": "rr",
      "backend": "socket",
      "congestion_control": "${congestion_control}",
      "elapsed_ms": 45000,
      "throughput_mib_per_s": 0.5,
      "requests_per_s": ${rr_requests},
      "latency": {"p50_us": 101, "p99_us": 909},
      "result_file": "rr.json"
    },
    {
      "status": "${crr_status}",
      "mode": "crr",
      "backend": "socket",
      "congestion_control": "${congestion_control}",
      "elapsed_ms": 45000,
      "throughput_mib_per_s": 0.2,
      "requests_per_s": ${crr_requests},
      "latency": {"p50_us": 202, "p99_us": 1001},
      "skipped_setup_errors": 7,
      "result_file": "crr.json",
      "failure_reason": "${failure_reason}"
    }
  ]
}
JSON
}

make_manifest "${tmpdir}/coquic" coquic coquic bbr 46.626 4030.511 63.578 ok ""
make_manifest "${tmpdir}/quic-go" quic-go quic-go default 358.0833333333333 11454.066666666668 404.6222222222222 failed "client wait failed"
make_manifest "${tmpdir}/quinn" quinn quinn default 527.2166666666667 33868.73333333333 648.8222222222222 ok ""
make_manifest "${tmpdir}/msquic" msquic msquic default 188.5 21000.125 512.25 ok ""
make_manifest "${tmpdir}/quiche" quiche quiche default 241.75 17000.5 444.125 ok ""

python3 "${script}" \
  --manifest "coquic=${tmpdir}/coquic/manifest.json" \
  --manifest "quic-go=${tmpdir}/quic-go/manifest.json" \
  --manifest "quinn=${tmpdir}/quinn/manifest.json" \
  --manifest "picoquic=${tmpdir}/missing/manifest.json" \
  --manifest "msquic=${tmpdir}/msquic/manifest.json" \
  --manifest "quiche=${tmpdir}/quiche/manifest.json" \
  --event-name pull_request \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --json-out "${json_output}" \
  > "${output}"

grep -F '## Advisory QUIC Perf Comparison' "${output}" >/dev/null || {
  echo 'missing comparison summary title' >&2
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

grep -F -- '- `coquic`: `' "${output}" >/dev/null || {
  echo 'missing coquic manifest line' >&2
  exit 1
}

grep -F -- '- `picoquic`: missing `' "${output}" >/dev/null || {
  echo 'missing absent picoquic manifest line' >&2
  exit 1
}

grep -F -- '- `msquic`: `' "${output}" >/dev/null || {
  echo 'missing MSQUIC manifest line' >&2
  exit 1
}

grep -F -- '- `quiche`: `' "${output}" >/dev/null || {
  echo 'missing quiche manifest line' >&2
  exit 1
}

grep -F '### Best By Mode' "${output}" >/dev/null || {
  echo 'missing best-by-mode section' >&2
  exit 1
}

grep -F '| Bulk Download | quinn | quinn -> quinn | default | Throughput MiB/s | 527.217 |' "${output}" >/dev/null || {
  echo 'missing bulk leader row' >&2
  exit 1
}

grep -F '| Request/Response | quinn | quinn -> quinn | default | Requests/s | 33868.733 |' "${output}" >/dev/null || {
  echo 'missing rr leader row' >&2
  exit 1
}

grep -F '### Bulk Download' "${output}" >/dev/null || {
  echo 'missing bulk table' >&2
  exit 1
}

grep -F '### Request/Response' "${output}" >/dev/null || {
  echo 'missing rr table' >&2
  exit 1
}

grep -F '### Connection Request/Response' "${output}" >/dev/null || {
  echo 'missing crr table' >&2
  exit 1
}

grep -F '| quic-go | quic-go -> quic-go | default | failed | 45000 | 0.200 | 0.002 | 404.622 | 202 | 1001 | 7 | quic-go/crr.json |' "${output}" >/dev/null || {
  echo 'missing failed quic-go crr row' >&2
  exit 1
}

grep -F '### Failures' "${output}" >/dev/null || {
  echo 'missing failures section' >&2
  exit 1
}

grep -F -- '- `quic-go/default/crr`: client wait failed' "${output}" >/dev/null || {
  echo 'missing failure reason' >&2
  exit 1
}

if grep -F '`picoquic` is driven through the native `pqbench` adapter' "${output}" >/dev/null; then
  echo 'unexpected stale picoquic adapter note' >&2
  exit 1
fi

python3 - <<'PY' "${json_output}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
if payload.get("schema_version") != 1:
    raise SystemExit("missing perf JSON schema version")
if payload.get("event_name") != "pull_request":
    raise SystemExit("missing perf JSON event name")
if payload.get("commit") != "0123456789abcdef0123456789abcdef01234567":
    raise SystemExit("missing perf JSON commit")
if "generated_at" not in payload:
    raise SystemExit("missing perf JSON generated_at")
sources = payload.get("sources")
if not isinstance(sources, list) or len(sources) != 6:
    raise SystemExit("unexpected perf JSON sources")
rows = payload.get("rows")
if not isinstance(rows, list) or len(rows) != 15:
    raise SystemExit("unexpected perf JSON rows")
missing = [source for source in sources if source.get("label") == "picoquic"][0]
if missing.get("missing") is not True:
    raise SystemExit("missing picoquic source was not marked missing")
labels = {source.get("label") for source in sources}
if not {"msquic", "quiche"}.issubset(labels):
    raise SystemExit("missing external baseline sources")
quic_go_crr = [
    row for row in rows
    if row.get("implementation") == "quic-go" and row.get("mode") == "crr"
][0]
if quic_go_crr.get("skipped_setup_errors") != 7:
    raise SystemExit("missing skipped setup errors in perf JSON")
if quic_go_crr.get("pair") != "quic-go -> quic-go":
    raise SystemExit("missing implementation pair in perf JSON")
PY

python3 "${script}" \
  --manifest "picoquic=${tmpdir}/missing/manifest.json" \
  --event-name workflow_dispatch \
  --commit nested-output \
  --json-out "${json_nested_output}" \
  > /dev/null

if [[ ! -f "${json_nested_output}" ]]; then
  echo 'renderer did not create nested JSON output directory' >&2
  exit 1
fi

python3 "${script}" \
  --manifest "coquic=${tmpdir}/coquic/manifest.json" \
  --event-name workflow_dispatch \
  --commit coquic-snapshot \
  --json-out "${coquic_snapshot}" \
  > /dev/null

python3 "${script}" \
  --manifest "quic-go=${tmpdir}/quic-go/manifest.json" \
  --event-name workflow_dispatch \
  --commit quic-go-snapshot \
  --json-out "${quic_go_snapshot}" \
  > /dev/null

python3 "${script}" \
  --manifest "coquic=${coquic_snapshot}" \
  --manifest "quic-go=${quic_go_snapshot}" \
  --event-name workflow_dispatch \
  --commit merged-snapshot \
  --json-out "${merged_snapshot}" \
  > /dev/null

python3 - <<'PY' "${merged_snapshot}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
sources = payload.get("sources")
rows = payload.get("rows")
if not isinstance(sources, list) or len(sources) != 2:
    raise SystemExit("merged perf snapshot sources were not preserved")
if not isinstance(rows, list) or len(rows) != 6:
    raise SystemExit("merged perf snapshot rows were not preserved")
labels = {source.get("label") for source in sources}
if labels != {"coquic", "quic-go"}:
    raise SystemExit("merged perf snapshot labels are wrong")
pairs = {row.get("pair") for row in rows}
if not {"coquic -> coquic", "quic-go -> quic-go"}.issubset(pairs):
    raise SystemExit("merged perf snapshot rows lost implementation pairs")
PY

invalid_manifest="${tmpdir}/invalid.json"
printf '%s\n' '{' '  "runs": {}' '}' > "${invalid_manifest}"
if python3 "${script}" \
  --manifest "bad=${invalid_manifest}" \
  --event-name pull_request \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  > "${output}" 2>"${stderr_output}"; then
  echo 'invalid comparison manifest should fail' >&2
  exit 1
fi

grep -F 'error: manifest `' "${stderr_output}" >/dev/null || {
  echo 'missing invalid manifest error' >&2
  exit 1
}

echo 'perf comparison renderer looks correct'
