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
  sed -n '/^build_coquic_image_tar()/,/^validate_official_results()/p' \
    interop/run-official.sh |
    sed '$d'
)"
eval "$(
  sed -n '/^validate_official_results()/,/^failed_retryable_official_testcases()/p' \
    interop/run-official.sh |
    sed '$d'
)"
eval "$(
  sed -n '/^failed_retryable_official_testcases()/,/^logged_official_testcases()/p' \
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

test_build_coquic_image_tar_retries() {
  local fake_bin="${tmpdir}/fake-bin"
  mkdir -p "${fake_bin}"

  cat >"${fake_bin}/nix" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

count_file="${FAKE_NIX_COUNT_FILE:?}"
count=0
if [ -f "${count_file}" ]; then
  count="$(cat "${count_file}")"
fi
count=$((count + 1))
printf '%s\n' "${count}" >"${count_file}"

if [ "${count}" -lt 3 ]; then
  echo "fake nix failure ${count}" >&2
  exit 1
fi

echo "/nix/store/fake-coquic-interop.tar.gz"
SH
  chmod +x "${fake_bin}/nix"

  cat >"${fake_bin}/sleep" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  chmod +x "${fake_bin}/sleep"

  local stdout_log="${tmpdir}/build-stdout.txt"
  local stderr_log="${tmpdir}/build-stderr.txt"
  local count_file="${tmpdir}/fake-nix-count.txt"

  PATH="${fake_bin}:${PATH}" \
    FAKE_NIX_COUNT_FILE="${count_file}" \
    interop_nix_build_attempts=3 \
    interop_nix_build_retry_delay_seconds=0 \
    coquic_package=interop-image-test \
    build_coquic_image_tar >"${stdout_log}" 2>"${stderr_log}"

  if [ "$(cat "${stdout_log}")" != "/nix/store/fake-coquic-interop.tar.gz" ]; then
    echo "expected build helper stdout to contain only the image tar path" >&2
    exit 1
  fi
  if [ "$(cat "${count_file}")" != "3" ]; then
    echo "expected build helper to retry until the third attempt" >&2
    exit 1
  fi
  if [ "$(rg -c 'retrying in 0s' "${stderr_log}")" != "2" ]; then
    echo "expected build helper to log two retry messages on stderr" >&2
    exit 1
  fi
}

test_build_coquic_image_tar_retries

patched_runner="${tmpdir}/interop.py"
cat >"${patched_runner}" <<'PY'
import os

def run():
    if True:
        if status == TestResult.FAILED or status == TestResult.SUCCEEDED:
            copy_logs()
PY

patch_official_runner "${patched_runner}"
if ! rg -q 'COQUIC_INTEROP_PRESERVE_TESTCASE_LOGS' "${patched_runner}"; then
  echo "expected official runner patch to gate per-testcase log copying" >&2
  exit 1
fi

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

retryable_results="${tmpdir}/retryable-results.json"
cat >"${retryable_results}" <<'JSON'
{
  "servers": ["xquic"],
  "clients": ["coquic"],
  "results": [[
    {"name": "http3", "result": "failed"},
    {"name": "retry", "result": "peer_broken"},
    {"name": "handshake", "result": "failed"}
  ]],
  "measurements": [[
    {"name": "crosstraffic", "result": "failed"}
  ]]
}
JSON

mapfile -t retryable_tests < <(
  failed_retryable_official_testcases \
    "${retryable_results}" \
    http3,retry,handshake,crosstraffic \
    amplificationlimit,handshakeloss,handshakecorruption,rebind-addr,connectionmigration,http3
)
if [ "${#retryable_tests[@]}" -ne 1 ] || [ "${retryable_tests[0]}" != "http3" ]; then
  echo "expected only failed retryable http3 testcase to be selected" >&2
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

mvfst_client_results="${tmpdir}/mvfst-client-results.json"
cat >"${mvfst_client_results}" <<'JSON'
{
  "servers": ["coquic"],
  "clients": ["mvfst"],
  "results": [[
    {"name": "handshakeloss", "result": "failed"},
    {"name": "handshakecorruption", "result": "failed"},
    {"name": "connectionmigration", "result": "failed"},
    {"name": "zerortt", "result": "failed"}
  ]],
  "measurements": [[]]
}
JSON

apply_official_result_compatibility_adjustments \
  "${mvfst_client_results}" coquic mvfst \
  handshakeloss,handshakecorruption,connectionmigration,zerortt

python3 - "${mvfst_client_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
results = {
    entry["name"]: entry
    for entry in data["results"][0]
}
for name in ("handshakeloss", "handshakecorruption"):
    entry = results[name]
    if entry["result"] != "peer_broken":
        raise SystemExit(f"expected mvfst client {name} to be marked peer_broken")
    if entry.get("details") != "peer reuses one connection for multiconnect":
        raise SystemExit(f"expected mvfst client {name} public reason")
    if "require 50 handshakes" not in entry.get("evidence", ""):
        raise SystemExit(f"expected mvfst client {name} evidence")
connectionmigration = results["connectionmigration"]
if connectionmigration["result"] != "peer_broken":
    raise SystemExit("expected mvfst client connectionmigration to be marked peer_broken")
if connectionmigration.get("details") != "peer does not perform active migration":
    raise SystemExit("expected mvfst client connectionmigration public reason")
if "sees only one server path" not in connectionmigration.get("evidence", ""):
    raise SystemExit("expected mvfst client connectionmigration evidence")
if results["zerortt"]["result"] != "failed":
    raise SystemExit("expected mvfst client zerortt to remain failed")
adjustments = data.get("coquic_compat_adjustments", [])
adjusted_names = {entry.get("name") for entry in adjustments}
if adjusted_names != {"handshakeloss", "handshakecorruption", "connectionmigration"}:
    raise SystemExit("expected mvfst client compatibility adjustment audit trail")
if any(not entry.get("reason") or not entry.get("evidence") for entry in adjustments):
    raise SystemExit("expected mvfst client audit trail to include reason and evidence")
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
