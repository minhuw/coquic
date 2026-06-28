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
  sed -n '/^failed_official_testcases()/,/^logged_official_testcases()/p' \
    interop/run-official.sh |
    sed '$d'
)"
eval "$(
  sed -n '/^apply_official_result_compatibility_adjustments()/,/^mark_official_testcases_recovered()/p' \
    interop/run-official.sh |
    sed '$d'
)"
eval "$(
  sed -n '/^have_interop_analysis_tools()/,/^show_runner_output_tail()/p' \
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

test_packet_analysis_tool_selection_defaults_to_nix_shell() {
  local fake_bin="${tmpdir}/fake-analysis-bin"
  mkdir -p "${fake_bin}"

  cat >"${fake_bin}/tshark" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  cat >"${fake_bin}/editcap" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  chmod +x "${fake_bin}/tshark" "${fake_bin}/editcap"

  if ! PATH="${fake_bin}:${PATH}" have_interop_analysis_tools; then
    echo "expected fake host packet analysis tools to be detected" >&2
    exit 1
  fi
  if PATH="${fake_bin}:${PATH}" \
    interop_use_host_analysis_tools=0 \
    use_host_interop_analysis_tools
  then
    echo "expected host packet analysis tools to be ignored by default" >&2
    exit 1
  fi
  if ! PATH="${fake_bin}:${PATH}" \
    interop_use_host_analysis_tools=1 \
    use_host_interop_analysis_tools
  then
    echo "expected explicit opt-in to use host packet analysis tools" >&2
    exit 1
  fi
}

test_packet_analysis_tool_selection_defaults_to_nix_shell

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

runner_dir="${tmpdir}/runner"
coquic_image="coquic-interop:test"
mkdir -p "${runner_dir}"
unset WAITFORSERVER CERTS TESTCASE_SERVER TESTCASE_CLIENT CLIENT_WWW CLIENT_DOWNLOADS
unset SERVER_WWW SERVER_DOWNLOADS SERVER_LOGS CLIENT_LOGS SCENARIO CLIENT SERVER
unset REQUESTS_CLIENT REQUESTS_SERVER PROTOCOLS_CLIENT PROTOCOLS_SERVER
prepare_official_runner_compose_defaults
for env_name in \
  CERTS CLIENT_WWW CLIENT_DOWNLOADS SERVER_WWW SERVER_DOWNLOADS \
  SERVER_LOGS CLIENT_LOGS CLIENT SERVER
do
  if [ -z "${!env_name}" ]; then
    echo "expected ${env_name} to have a non-empty compose cleanup default" >&2
    exit 1
  fi
done
if [ "${CLIENT}" != "${coquic_image}" ] || [ "${SERVER}" != "${coquic_image}" ]; then
  echo "expected compose cleanup image defaults to use the CoQUIC image" >&2
  exit 1
fi
for env_name in \
  WAITFORSERVER TESTCASE_SERVER TESTCASE_CLIENT SCENARIO \
  PROTOCOLS_CLIENT PROTOCOLS_SERVER
do
  if [ -n "${!env_name-}" ]; then
    echo "expected ${env_name} to remain unset by compose cleanup defaults" >&2
    exit 1
  fi
done
if [ "${REQUESTS_CLIENT}" != "" ]; then
  echo "expected REQUESTS_CLIENT default to preserve empty client requests" >&2
  exit 1
fi
if [ "${REQUESTS_SERVER}" != "" ]; then
  echo "expected REQUESTS_SERVER default to preserve empty server requests" >&2
  exit 1
fi

validate_official_results \
  "${complete_results}" coquic quic-go handshake,transfer,retry,ipv6,goodput \
  "succeeded,unsupported,peer_broken,failed"

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
    {"name": "multiplexing", "result": "failed"},
    {"name": "retry", "result": "peer_broken"},
    {"name": "handshake", "result": "failed"}
  ]],
  "measurements": [[
    {"name": "crosstraffic", "result": "failed"}
  ]]
}
JSON

known_broken_results="${tmpdir}/known-broken-results.json"
cat >"${known_broken_results}" <<'JSON'
{
  "servers": ["xquic", "quiche", "ngtcp2"],
  "clients": ["coquic", "quinn"],
  "results": [
    [
      {"name": "rebind-addr", "result": "failed"},
      {"name": "http3", "result": "succeeded"}
    ],
    [
      {"name": "connectionmigration", "result": "failed"}
    ],
    [
      {"name": "connectionmigration", "result": "failed"}
    ],
    [
      {"name": "multiplexing", "result": "failed"}
    ],
    [
      {"name": "rebind-addr", "result": "failed"},
      {"name": "connectionmigration", "result": "succeeded"}
    ],
    [
      {"name": "connectionmigration", "result": "failed"}
    ]
  ],
  "measurements": [
    [],
    [],
    [],
    [],
    [],
    []
  ]
}
JSON

mapfile -t retryable_tests < <(
  failed_retryable_official_testcases \
    "${retryable_results}" \
    http3,multiplexing,retry,handshake,crosstraffic \
    amplificationlimit,multiplexing,handshakeloss,handshakecorruption,rebind-addr,rebind-port,connectionmigration,http3
)
if [ "${#retryable_tests[@]}" -ne 2 ] ||
  [ "${retryable_tests[0]}" != "http3" ] ||
  [ "${retryable_tests[1]}" != "multiplexing" ]
then
  echo "expected failed retryable http3 and multiplexing testcases to be selected" >&2
  exit 1
fi

mapfile -t retryable_tests_with_known < <(
  failed_retryable_official_testcases \
    "${retryable_results}" \
    http3,multiplexing,retry,handshake,crosstraffic \
    amplificationlimit,multiplexing,handshakeloss,handshakecorruption,rebind-addr,rebind-port,connectionmigration,http3 \
    "${known_broken_results}" xquic coquic
)
if [ "${#retryable_tests_with_known[@]}" -ne 1 ] ||
  [ "${retryable_tests_with_known[0]}" != "http3" ]
then
  echo "expected known peer-broken retryable xquic multiplexing to be skipped" >&2
  exit 1
fi

mapfile -t failed_tests < <(
  failed_official_testcases \
    "${retryable_results}" \
    http3,multiplexing,retry,handshake,crosstraffic
)
if [ "${#failed_tests[@]}" -ne 4 ] ||
  [ "${failed_tests[0]}" != "http3" ] ||
  [ "${failed_tests[1]}" != "multiplexing" ] ||
  [ "${failed_tests[2]}" != "handshake" ] ||
  [ "${failed_tests[3]}" != "crosstraffic" ]
then
  echo "expected failed testcase helper to include testcase and measurement failures" >&2
  exit 1
fi

mapfile -t failed_tests_with_known < <(
  failed_official_testcases \
    "${retryable_results}" \
    http3,multiplexing,retry,handshake,crosstraffic \
    "${known_broken_results}" xquic coquic
)
if [ "${#failed_tests_with_known[@]}" -ne 3 ] ||
  [ "${failed_tests_with_known[0]}" != "http3" ] ||
  [ "${failed_tests_with_known[1]}" != "handshake" ] ||
  [ "${failed_tests_with_known[2]}" != "crosstraffic" ]
then
  echo "expected known peer-broken xquic multiplexing to be omitted from failure helper" >&2
  exit 1
fi

mapfile -t known_broken_tests < <(
  known_broken_official_testcases "${known_broken_results}" quiche coquic
)
if [ "${#known_broken_tests[@]}" -ne 1 ] ||
  [ "${known_broken_tests[0]}" != "rebind-addr" ]
then
  echo "expected known peer-broken helper to list quiche rebind-addr" >&2
  exit 1
fi

known_broken_local_results="${tmpdir}/known-broken-local-results.json"
cat >"${known_broken_local_results}" <<'JSON'
{
  "servers": ["quiche"],
  "clients": ["coquic"],
  "results": [[
    {"name": "rebind-addr", "result": "failed"},
    {"name": "connectionmigration", "result": "succeeded"}
  ]],
  "measurements": [[]]
}
JSON

mapfile -t known_broken_failed_tests < <(
  known_broken_failed_official_testcases \
    "${known_broken_local_results}" rebind-addr,connectionmigration \
    "${known_broken_results}" quiche coquic
)
if [ "${#known_broken_failed_tests[@]}" -ne 1 ] ||
  [ "${known_broken_failed_tests[0]}" != "rebind-addr" ]
then
  echo "expected known peer-broken failed helper to list only failed local rows" >&2
  exit 1
fi

xquic_dir="${tmpdir}/xquic"
mkdir -p "${xquic_dir}"
xquic_results="${xquic_dir}/results.json"
cat >"${xquic_results}" <<'JSON'
{
  "servers": ["coquic"],
  "clients": ["xquic"],
  "results": [[
    {"name": "connectionmigration", "result": "failed"},
    {"name": "handshakeloss", "result": "failed"},
    {"name": "retry", "result": "succeeded"},
    {"name": "transfer", "result": "succeeded"}
  ]],
  "measurements": [[
    {"name": "crosstraffic", "result": "failed"}
  ]]
}
JSON
mkdir -p "${xquic_dir}/retry-handshakeloss"
cat >"${xquic_dir}/retry-handshakeloss/runner-output.txt" <<'TXT'
client  | start requesty[37]: https://server4:443/jubilant-worried-bulbasaur
Test failed: took longer than 300s.
Test: handshakeloss took 300.628237s, status: TestResult.FAILED
TXT

apply_official_result_compatibility_adjustments \
  "${xquic_results}" coquic xquic connectionmigration,handshakeloss,transfer,crosstraffic

python3 - "${xquic_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
results = {
    entry["name"]: entry
    for entry in data["results"][0]
}
connectionmigration = next(
    entry for entry in data["results"][0]
    if entry["name"] == "connectionmigration"
)
if connectionmigration["result"] != "failed":
    raise SystemExit("expected xquic connectionmigration to remain failed")
if "details" in connectionmigration or "evidence" in connectionmigration:
    raise SystemExit("expected xquic connectionmigration metadata to remain unchanged")
handshakeloss = results["handshakeloss"]
if handshakeloss["result"] != "peer_broken":
    raise SystemExit("expected xquic handshakeloss to be marked peer_broken")
if handshakeloss.get("details") != "peer exceeds official handshakeloss timeout":
    raise SystemExit("expected xquic handshakeloss public reason")
if "300 seconds" not in handshakeloss.get("evidence", ""):
    raise SystemExit("expected xquic handshakeloss evidence")
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
if adjusted_names != {"handshakeloss", "crosstraffic"}:
    raise SystemExit("expected compatibility adjustment audit trail")
if any(not entry.get("reason") or not entry.get("evidence") for entry in adjustments):
    raise SystemExit("expected compatibility adjustments to include reason and evidence")
PY

xquic_missing_evidence_dir="${tmpdir}/xquic-missing-evidence"
mkdir -p "${xquic_missing_evidence_dir}"
xquic_missing_evidence_results="${xquic_missing_evidence_dir}/results.json"
cat >"${xquic_missing_evidence_results}" <<'JSON'
{
  "servers": ["coquic"],
  "clients": ["xquic"],
  "results": [[
    {"name": "handshakeloss", "result": "failed"}
  ]],
  "measurements": [[]]
}
JSON

apply_official_result_compatibility_adjustments \
  "${xquic_missing_evidence_results}" coquic xquic handshakeloss

python3 - "${xquic_missing_evidence_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
handshakeloss = data["results"][0][0]
if handshakeloss["result"] != "failed":
    raise SystemExit("expected xquic handshakeloss without timeout evidence to remain failed")
if "details" in handshakeloss or "evidence" in handshakeloss:
    raise SystemExit("expected xquic handshakeloss without timeout evidence to avoid metadata")
if data.get("coquic_compat_adjustments"):
    raise SystemExit("expected no xquic missing-evidence compatibility audit trail")
PY

xquic_main_only_dir="${tmpdir}/xquic-main-only"
mkdir -p "${xquic_main_only_dir}"
xquic_main_only_results="${xquic_main_only_dir}/results.json"
cat >"${xquic_main_only_results}" <<'JSON'
{
  "servers": ["coquic"],
  "clients": ["xquic"],
  "results": [[
    {"name": "handshakeloss", "result": "failed"}
  ]],
  "measurements": [[]]
}
JSON
cat >"${xquic_main_only_dir}/runner-output.txt" <<'TXT'
client  | start requesty[37]: https://server4:443/tiny-savory-viking
Test failed: took longer than 300s.
Test: handshakeloss took 300.123456s, status: TestResult.FAILED
TXT

apply_official_result_compatibility_adjustments \
  "${xquic_main_only_results}" coquic xquic handshakeloss

python3 - "${xquic_main_only_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
handshakeloss = data["results"][0][0]
if handshakeloss["result"] != "failed":
    raise SystemExit("expected xquic handshakeloss with only full-run evidence to remain failed")
if "details" in handshakeloss or "evidence" in handshakeloss:
    raise SystemExit("expected xquic handshakeloss with only full-run evidence to avoid metadata")
if data.get("coquic_compat_adjustments"):
    raise SystemExit("expected no xquic main-output-only compatibility audit trail")
PY

xquic_client_known_broken_results="${tmpdir}/xquic-client-known-broken-results.json"
cat >"${xquic_client_known_broken_results}" <<'JSON'
{
  "servers": ["coquic"],
  "clients": ["xquic"],
  "results": [[
    {"name": "connectionmigration", "result": "failed"}
  ]],
  "measurements": [[
    {"name": "crosstraffic", "result": "failed"}
  ]]
}
JSON

xquic_known_results="${tmpdir}/xquic-known-results.json"
cat >"${xquic_known_results}" <<'JSON'
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
  "${xquic_known_results}" coquic xquic connectionmigration,transfer,crosstraffic \
  "${xquic_client_known_broken_results}"

python3 - "${xquic_known_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
xquic_crosstraffic = next(
    entry for entry in data["measurements"][0]
    if entry["name"] == "crosstraffic"
)
if xquic_crosstraffic["result"] != "failed":
    raise SystemExit("expected upstream-known xquic crosstraffic to remain failed")
if "details" in xquic_crosstraffic or "evidence" in xquic_crosstraffic:
    raise SystemExit("expected upstream-known xquic crosstraffic to avoid local peer-broken metadata")
adjustments = data.get("coquic_compat_adjustments", [])
if any(entry.get("name") == "crosstraffic" for entry in adjustments):
    raise SystemExit("expected no local adjustment audit entry for upstream-known xquic crosstraffic")
PY

msquic_server_dir="${tmpdir}/msquic-server"
mkdir -p "${msquic_server_dir}"
msquic_server_results="${msquic_server_dir}/results.json"
cat >"${msquic_server_results}" <<'JSON'
{
  "servers": ["coquic"],
  "clients": ["msquic"],
  "results": [[
    {"name": "connectionmigration", "result": "failed"},
    {"name": "zerortt", "result": "failed"}
  ]],
  "measurements": [[]]
}
JSON
cat >"${msquic_server_dir}/runner-output.txt" <<'TXT'
Check of downloaded files succeeded.
0-RTT size: 10694
1-RTT size: 5122
Client sent too much data in 1-RTT packets.
Test: zerortt took 19.584131s, status: TestResult.FAILED
TXT

apply_official_result_compatibility_adjustments \
  "${msquic_server_results}" coquic msquic connectionmigration,zerortt

python3 - "${msquic_server_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
results = {
    entry["name"]: entry
    for entry in data["results"][0]
}
connectionmigration = results["connectionmigration"]
if connectionmigration["result"] != "failed":
    raise SystemExit("expected msquic connectionmigration to remain failed")
if "details" in connectionmigration or "evidence" in connectionmigration:
    raise SystemExit("expected msquic connectionmigration metadata to remain unchanged")
if results["zerortt"]["result"] != "peer_broken":
    raise SystemExit("expected msquic zerortt result to be marked peer_broken")
if results["zerortt"].get("details") != "peer sends too much request data after 0-RTT":
    raise SystemExit("expected msquic zerortt public reason")
if "5122 bytes in 1-RTT" not in results["zerortt"].get("evidence", ""):
    raise SystemExit("expected msquic zerortt evidence")
adjustments = data.get("coquic_compat_adjustments", [])
adjusted_names = {entry.get("name") for entry in adjustments}
if adjusted_names != {"zerortt"}:
    raise SystemExit("expected msquic zerortt audit trail")
if any(not entry.get("reason") or not entry.get("evidence") for entry in adjustments):
    raise SystemExit("expected msquic audit trail to include reason and evidence")
PY

msquic_missing_evidence_dir="${tmpdir}/msquic-missing-evidence"
mkdir -p "${msquic_missing_evidence_dir}"
msquic_missing_evidence_results="${msquic_missing_evidence_dir}/results.json"
cat >"${msquic_missing_evidence_results}" <<'JSON'
{
  "servers": ["coquic"],
  "clients": ["msquic"],
  "results": [[
    {"name": "zerortt", "result": "failed"}
  ]],
  "measurements": [[]]
}
JSON

apply_official_result_compatibility_adjustments \
  "${msquic_missing_evidence_results}" coquic msquic zerortt

python3 - "${msquic_missing_evidence_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
zerortt = data["results"][0][0]
if zerortt["result"] != "failed":
    raise SystemExit("expected msquic zerortt without 1-RTT evidence to remain failed")
if "details" in zerortt or "evidence" in zerortt:
    raise SystemExit("expected msquic zerortt without 1-RTT evidence to avoid metadata")
if data.get("coquic_compat_adjustments"):
    raise SystemExit("expected no msquic missing-evidence compatibility audit trail")
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

ngtcp2_server_dir="${tmpdir}/ngtcp2-server"
mkdir -p "${ngtcp2_server_dir}"
ngtcp2_server_results="${ngtcp2_server_dir}/results.json"
cat >"${ngtcp2_server_results}" <<'JSON'
{
  "servers": ["ngtcp2"],
  "clients": ["coquic"],
  "results": [[
    {"name": "connectionmigration", "result": "failed"},
    {"name": "transfer", "result": "succeeded"}
  ]],
  "measurements": [[
    {"name": "goodput", "result": "failed"},
    {"name": "crosstraffic", "result": "failed"}
  ]]
}
JSON
cat >"${ngtcp2_server_dir}/runner-output.txt" <<'TXT'
Test failed: took longer than 60s.
invalid spec: :/www:ro: empty section between colons
Test: connectionmigration took 60.701594s, status: TestResult.FAILED
 Container sim  Running
Test failed: took longer than 60s.
invalid spec: :/www:ro: empty section between colons
Test: goodput took 60.686975s, status: TestResult.FAILED
 Container sim  Running
Test failed: took longer than 180s.
invalid spec: :/www:ro: empty section between colons
Test: crosstraffic took 182.404s, status: TestResult.FAILED
TXT

apply_official_result_compatibility_adjustments \
  "${ngtcp2_server_results}" ngtcp2 coquic connectionmigration,transfer,goodput,crosstraffic

python3 - "${ngtcp2_server_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
results = {
    entry["name"]: entry
    for entry in data["results"][0] + data["measurements"][0]
}
connectionmigration = results["connectionmigration"]
if connectionmigration["result"] != "failed":
    raise SystemExit("expected ngtcp2 connectionmigration to remain failed")
if "details" in connectionmigration or "evidence" in connectionmigration:
    raise SystemExit("expected ngtcp2 connectionmigration metadata to remain unchanged")
if results["transfer"]["result"] != "succeeded":
    raise SystemExit("expected ngtcp2 transfer result to remain unchanged")
for name in ("goodput", "crosstraffic"):
    entry = results[name]
    if entry["result"] != "failed":
        raise SystemExit(f"expected ngtcp2 stale-runner {name} measurement to remain failed")
    if "details" in entry or "evidence" in entry:
        raise SystemExit(f"expected ngtcp2 stale-runner {name} metadata to remain unchanged")
adjustments = data.get("coquic_compat_adjustments", [])
if adjustments:
    raise SystemExit("expected no ngtcp2 stale-runner compatibility audit trail")
PY

ngtcp2_measurement_only_results="${tmpdir}/ngtcp2-measurement-only-results.json"
cat >"${ngtcp2_measurement_only_results}" <<'JSON'
{
  "servers": ["ngtcp2"],
  "clients": ["coquic"],
  "results": [[
    {"name": "connectionmigration", "result": "succeeded"},
    {"name": "transfer", "result": "succeeded"}
  ]],
  "measurements": [[
    {"name": "goodput", "result": "failed"},
    {"name": "crosstraffic", "result": "failed"}
  ]]
}
JSON

apply_official_result_compatibility_adjustments \
  "${ngtcp2_measurement_only_results}" ngtcp2 coquic connectionmigration,transfer,goodput,crosstraffic

python3 - "${ngtcp2_measurement_only_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
results = {
    entry["name"]: entry
    for entry in data["results"][0] + data["measurements"][0]
}
if results["connectionmigration"]["result"] != "succeeded":
    raise SystemExit("expected ngtcp2 successful connectionmigration to remain unchanged")
if results["goodput"]["result"] != "failed":
    raise SystemExit("expected standalone ngtcp2 goodput failure to remain failed")
if results["crosstraffic"]["result"] != "failed":
    raise SystemExit("expected standalone ngtcp2 crosstraffic failure to remain failed")
if data.get("coquic_compat_adjustments"):
    raise SystemExit("expected no ngtcp2 measurement-only compatibility audit trail")
PY

ngtcp2_missing_evidence_dir="${tmpdir}/ngtcp2-missing-evidence"
mkdir -p "${ngtcp2_missing_evidence_dir}"
ngtcp2_missing_evidence_results="${ngtcp2_missing_evidence_dir}/results.json"
cat >"${ngtcp2_missing_evidence_results}" <<'JSON'
{
  "servers": ["ngtcp2"],
  "clients": ["coquic"],
  "results": [[
    {"name": "connectionmigration", "result": "failed"},
    {"name": "transfer", "result": "succeeded"}
  ]],
  "measurements": [[
    {"name": "goodput", "result": "failed"},
    {"name": "crosstraffic", "result": "failed"}
  ]]
}
JSON

apply_official_result_compatibility_adjustments \
  "${ngtcp2_missing_evidence_results}" ngtcp2 coquic connectionmigration,transfer,goodput,crosstraffic

python3 - "${ngtcp2_missing_evidence_results}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
results = {
    entry["name"]: entry
    for entry in data["results"][0] + data["measurements"][0]
}
if results["connectionmigration"]["result"] != "failed":
    raise SystemExit("expected ngtcp2 failed connectionmigration to remain unchanged")
if results["goodput"]["result"] != "failed":
    raise SystemExit("expected ngtcp2 goodput without cleanup evidence to remain failed")
if results["crosstraffic"]["result"] != "failed":
    raise SystemExit("expected ngtcp2 crosstraffic without cleanup evidence to remain failed")
if data.get("coquic_compat_adjustments"):
    raise SystemExit("expected no ngtcp2 missing-evidence compatibility audit trail")
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
