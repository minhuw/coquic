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
    {"name": "ipv6", "result": "unsupported"}
  ]],
  "measurements": [[
    {"name": "goodput", "result": "failed"}
  ]]
}
JSON

validate_official_results \
  "${complete_results}" coquic quic-go handshake,transfer,ipv6,goodput

if validate_official_results \
  "${complete_results}" coquic quic-go handshake,transfer "succeeded,unsupported"
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
if connectionmigration["result"] != "unsupported":
    raise SystemExit("expected xquic connectionmigration to be marked unsupported")
if "preferred-address active migration" not in connectionmigration.get("details", ""):
    raise SystemExit("expected xquic connectionmigration rationale details")
xquic_crosstraffic = next(
    entry for entry in data["measurements"][0]
    if entry["name"] == "crosstraffic"
)
if xquic_crosstraffic["result"] != "unsupported":
    raise SystemExit("expected xquic crosstraffic to be marked unsupported")
if "30-second request deadline" not in xquic_crosstraffic.get("details", ""):
    raise SystemExit("expected xquic crosstraffic rationale details")
adjusted_names = {entry.get("name") for entry in data.get("coquic_compat_adjustments", [])}
if adjusted_names != {"connectionmigration", "crosstraffic"}:
    raise SystemExit("expected compatibility adjustment audit trail")
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
    if entry["result"] != "unsupported":
        raise SystemExit(f"expected xquic server {name} to be marked unsupported")
    if "non-zero Token Length" not in entry.get("details", ""):
        raise SystemExit(f"expected xquic server {name} rationale details")
if results["http3"]["result"] != "succeeded":
    raise SystemExit("expected xquic server http3 result to be unchanged")
adjusted_names = {entry.get("name") for entry in data.get("coquic_compat_adjustments", [])}
if adjusted_names != {"retry", "resumption", "zerortt"}:
    raise SystemExit("expected xquic server compatibility adjustment audit trail")
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
    if entry["result"] != "unsupported":
        raise SystemExit(f"expected mvfst {name} to be marked unsupported")
    if not entry.get("details"):
        raise SystemExit(f"expected mvfst {name} rationale details")
adjustments = data.get("coquic_compat_adjustments", [])
adjusted_names = {entry.get("name") for entry in adjustments}
if adjusted_names != {"amplificationlimit", "rebind-addr", "crosstraffic"}:
    raise SystemExit("expected mvfst compatibility adjustment audit trail")
PY

echo "run-official result validation ok"
