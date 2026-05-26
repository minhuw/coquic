#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="${repo_root}/scripts/render-interop-results.py"
tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

raw_result="${tmpdir}/results.json"
summary="${tmpdir}/summary.md"
payload="${tmpdir}/interop-results.json"
merged_payload="${tmpdir}/merged-interop-results.json"

cat > "${raw_result}" <<'JSON'
{
  "start_time": 1,
  "end_time": 2,
  "servers": ["coquic"],
  "clients": ["picoquic"],
  "quic_version": "0x1",
  "results": [[
    {"abbr": "H", "name": "handshake", "result": "succeeded"},
    {"abbr": "A", "name": "amplificationlimit", "result": "failed"}
  ]],
  "measurements": [[
    {"abbr": "G", "name": "goodput", "result": "succeeded", "details": "9000 kbps"}
  ]]
}
JSON

python3 "${script}" \
  --result picoquic="${raw_result}" \
  --result missing="${tmpdir}/missing.json" \
  --event-name schedule \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --json-out "${payload}" > "${summary}"

for marker in \
  "Official QUIC Interop Results" \
  "Event: \`schedule\`" \
  "\`picoquic\`: \`coquic\` -> \`picoquic\` (2/3 succeeded)" \
  "\`missing\`: missing" \
  "| picoquic | coquic-server | amplificationlimit | failed |"; do
  if ! grep -Fq -- "${marker}" "${summary}"; then
    echo "interop summary missing marker: ${marker}" >&2
    exit 1
  fi
done

python3 - "${payload}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
if payload["schema_version"] != 1:
    raise SystemExit("unexpected schema version")
if payload["event_name"] != "schedule":
    raise SystemExit("unexpected event name")
if len(payload["sources"]) != 2:
    raise SystemExit("expected raw and missing sources")
source = payload["sources"][0]
if source["server"] != "coquic" or source["client"] != "picoquic":
    raise SystemExit("unexpected source pair")
if source["succeeded"] != 2 or source["failed"] != 1 or source["total"] != 3:
    raise SystemExit("unexpected status counts")
rows = payload["rows"]
if len(rows) != 3:
    raise SystemExit("unexpected row count")
if not any(row["name"] == "goodput" and row["kind"] == "measurement" and row["details"] == "9000 kbps" for row in rows):
    raise SystemExit("missing measurement row")
if not any(row["name"] == "amplificationlimit" and row["result"] == "failed" for row in rows):
    raise SystemExit("missing failed testcase row")
PY

python3 "${script}" \
  --result rendered="${payload}" \
  --event-name workflow_dispatch \
  --commit abcdef0123456789abcdef0123456789abcdef01 \
  --json-out "${merged_payload}" > /dev/null

python3 - "${merged_payload}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
if payload["event_name"] != "workflow_dispatch":
    raise SystemExit("unexpected merged event name")
if len(payload["sources"]) != 2:
    raise SystemExit("expected merged sources")
if len(payload["rows"]) != 3:
    raise SystemExit("expected merged rows")
PY

if python3 "${script}" --result bad="${tmpdir}/does-not-exist.json" --event-name schedule --commit bad --json-out "${tmpdir}/missing-only.json" > /dev/null; then
  python3 - "${tmpdir}/missing-only.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
if payload["rows"]:
    raise SystemExit("missing-only payload should have no rows")
if not payload["sources"][0].get("missing"):
    raise SystemExit("missing source was not marked missing")
PY
else
  echo "renderer should tolerate missing result paths" >&2
  exit 1
fi

echo "interop result renderer contract looks correct"
