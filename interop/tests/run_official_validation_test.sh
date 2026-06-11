#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

eval "$(
  sed -n '/^validate_official_results()/,/^failed_retryable_official_testcases()/p' \
    interop/run-official.sh |
    sed '$d'
)"
eval "$(
  sed -n '/^apply_official_result_compatibility_adjustments()/,/^mark_official_testcases_recovered()/p' \
    interop/run-official.sh |
    sed '$d'
)"

complete_results="${tmpdir}/complete-results.json"
cat >"${complete_results}" <<'JSON'
{
  "servers": ["coquic"],
  "clients": ["quic-go"],
  "results": [[
    {"name": "handshake", "result": "succeeded"},
    {"name": "transfer", "result": "failed"},
    {"name": "retry", "result": "peer_broken"},
    {"name": "ipv6", "result": "unsupported"}
  ]],
  "measurements": [[
    {"name": "goodput", "result": "failed"}
  ]]
}
JSON

validate_official_results \
  "${complete_results}" coquic quic-go handshake,transfer,retry,ipv6,goodput

rendered_json="${tmpdir}/rendered-interop-results.json"
rendered_summary="${tmpdir}/rendered-interop-results.md"
python3 scripts/render-interop-results.py \
  --result complete="${complete_results}" \
  --event-name test \
  --commit test \
  --json-out "${rendered_json}" >"${rendered_summary}"

python3 - "${rendered_json}" "${rendered_summary}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
summary = pathlib.Path(sys.argv[2]).read_text()
source = data["sources"][0]
if source.get("peer_broken") != 1:
    raise SystemExit("expected rendered source to count peer_broken results")
retry = next(row for row in data["rows"] if row["name"] == "retry")
if retry["result"] != "peer_broken":
    raise SystemExit("expected rendered retry row to preserve peer_broken result")
if "1 peer-broken" not in summary or "### Peer-Broken Cases" not in summary:
    raise SystemExit("expected rendered summary to include peer-broken cases")
PY

if validate_official_results \
  "${complete_results}" coquic quic-go handshake,retry "succeeded,unsupported"
then
  echo "expected peer-broken testcase to be rejected by strict validation" >&2
  exit 1
fi

if validate_official_results \
  "${complete_results}" coquic quic-go handshake,transfer "succeeded,unsupported,peer_broken"
then
  echo "expected failed testcase to be rejected by strict validation" >&2
  exit 1
fi

missing_results="${tmpdir}/missing-results.json"
cat >"${missing_results}" <<'JSON'
{
  "servers": ["coquic"],
  "clients": ["quic-go"],
  "results": [[
    {"name": "handshake", "result": "succeeded"}
  ]],
  "measurements": [[]]
}
JSON

if validate_official_results \
  "${missing_results}" coquic quic-go handshake,transfer
then
  echo "expected missing requested testcase to fail validation" >&2
  exit 1
fi

xquic_results="${tmpdir}/xquic-results.json"
cat >"${xquic_results}" <<'JSON'
{
  "servers": ["coquic"],
  "clients": ["xquic"],
  "results": [[
    {"name": "connectionmigration", "result": "failed"},
    {"name": "retry", "result": "succeeded"},
    {"name": "transfer", "result": "succeeded"}
  ]],
  "measurements": [[
    {"name": "crosstraffic", "result": "failed"}
  ]]
}
JSON

apply_official_result_compatibility_adjustments \
  "${xquic_results}" coquic xquic connectionmigration,transfer,crosstraffic

python3 - "${xquic_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
connectionmigration = next(
    entry for entry in data["results"][0]
    if entry["name"] == "connectionmigration"
)
if connectionmigration["result"] != "peer_broken":
    raise SystemExit("expected xquic connectionmigration to be marked peer_broken")
if connectionmigration.get("details") != "peer does not initiate preferred-address migration":
    raise SystemExit("expected xquic connectionmigration public reason")
if "preferred-address active migration" not in connectionmigration.get("evidence", ""):
    raise SystemExit("expected xquic connectionmigration evidence")
xquic_crosstraffic = next(
    entry for entry in data["measurements"][0]
    if entry["name"] == "crosstraffic"
)
if xquic_crosstraffic["result"] != "peer_broken":
    raise SystemExit("expected xquic crosstraffic to be marked peer_broken")
if xquic_crosstraffic.get("details") != "peer aborts crosstraffic transfer before completion":
    raise SystemExit("expected xquic crosstraffic public reason")
if "30-second request deadline" not in xquic_crosstraffic.get("evidence", ""):
    raise SystemExit("expected xquic crosstraffic evidence")
adjustments = data.get("coquic_compat_adjustments", [])
adjusted_names = {entry.get("name") for entry in adjustments}
if adjusted_names != {"connectionmigration", "crosstraffic"}:
    raise SystemExit("expected compatibility adjustment audit trail")
if any(not entry.get("reason") or not entry.get("evidence") for entry in adjustments):
    raise SystemExit("expected compatibility adjustments to include reason and evidence")
PY

xquic_server_results="${tmpdir}/xquic-server-results.json"
cat >"${xquic_server_results}" <<'JSON'
{
  "servers": ["xquic"],
  "clients": ["coquic"],
  "results": [[
    {"name": "retry", "result": "failed"},
    {"name": "resumption", "result": "failed"},
    {"name": "zerortt", "result": "failed"},
    {"name": "http3", "result": "succeeded"}
  ]],
  "measurements": [[]]
}
JSON

apply_official_result_compatibility_adjustments \
  "${xquic_server_results}" xquic coquic retry,resumption,zerortt,http3

python3 - "${xquic_server_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
results = {
    entry["name"]: entry
    for entry in data["results"][0]
}
for name in ("retry", "resumption", "zerortt"):
    entry = results[name]
    if entry["result"] != "peer_broken":
        raise SystemExit(f"expected xquic server {name} to be marked peer_broken")
    if entry.get("details") != "peer sends invalid post-Retry server Initial":
        raise SystemExit(f"expected xquic server {name} public reason")
    if "non-zero Token Length" not in entry.get("evidence", ""):
        raise SystemExit(f"expected xquic server {name} evidence")
    if "RFC 9000 Section 17.2.2" not in entry.get("evidence", ""):
        raise SystemExit(f"expected xquic server {name} RFC evidence")
if results["http3"]["result"] != "succeeded":
    raise SystemExit("expected xquic server http3 result to be unchanged")
adjustments = data.get("coquic_compat_adjustments", [])
adjusted_names = {entry.get("name") for entry in adjustments}
if adjusted_names != {"retry", "resumption", "zerortt"}:
    raise SystemExit("expected xquic server compatibility adjustment audit trail")
if any(not entry.get("reason") or not entry.get("evidence") for entry in adjustments):
    raise SystemExit("expected xquic server audit trail to include reason and evidence")
PY

mvfst_results="${tmpdir}/mvfst-results.json"
cat >"${mvfst_results}" <<'JSON'
{
  "servers": ["mvfst"],
  "clients": ["coquic"],
  "results": [[
    {"name": "amplificationlimit", "result": "failed"},
    {"name": "rebind-addr", "result": "failed"}
  ]],
  "measurements": [[
    {"name": "crosstraffic", "result": "failed"}
  ]]
}
JSON

apply_official_result_compatibility_adjustments \
  "${mvfst_results}" mvfst coquic amplificationlimit,rebind-addr,crosstraffic

python3 - "${mvfst_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
results = {
    entry["name"]: entry
    for entry in data["results"][0] + data["measurements"][0]
}
for name in ("amplificationlimit", "rebind-addr", "crosstraffic"):
    entry = results[name]
    if entry["result"] != "peer_broken":
        raise SystemExit(f"expected mvfst {name} to be marked peer_broken")
    if not entry.get("details"):
        raise SystemExit(f"expected mvfst {name} public reason")
    if not entry.get("evidence"):
        raise SystemExit(f"expected mvfst {name} evidence")
adjustments = data.get("coquic_compat_adjustments", [])
adjusted_names = {entry.get("name") for entry in adjustments}
if adjusted_names != {"amplificationlimit", "rebind-addr", "crosstraffic"}:
    raise SystemExit("expected mvfst compatibility adjustment audit trail")
if any(not entry.get("reason") or not entry.get("evidence") for entry in adjustments):
    raise SystemExit("expected mvfst audit trail to include reason and evidence")
PY

echo "run-official result validation ok"
