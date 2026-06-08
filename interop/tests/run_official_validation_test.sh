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
    {"name": "transfer", "result": "succeeded"}
  ]],
  "measurements": [[]]
}
JSON

apply_official_result_compatibility_adjustments \
  "${xquic_results}" coquic xquic connectionmigration,transfer

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
if not data.get("coquic_compat_adjustments"):
    raise SystemExit("expected compatibility adjustment audit trail")
PY

echo "run-official result validation ok"
