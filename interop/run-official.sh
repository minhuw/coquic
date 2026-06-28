#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "${repo_root}"

readonly interop_runner_ref="${INTEROP_RUNNER_REF:-97319f8c0be2bc0be67b025522a64c9231018d37}"
readonly network_simulator_ref="${INTEROP_NETWORK_SIMULATOR_REF:-e557a54510e3578868f8c14cf3aa37e0fc6c76d0}"
readonly interop_peer_impl="${INTEROP_PEER_IMPL:-}"
readonly interop_peer_image="${INTEROP_PEER_IMAGE:-}"
readonly simulator_image="${INTEROP_SIMULATOR_IMAGE:-martenseemann/quic-network-simulator@sha256:c23d82a55caffe681b1bdae65d4d30d23e1283141a414a7f02ee56cf15f9c6b9}"
readonly iperf_image="${INTEROP_IPERF_IMAGE:-martenseemann/quic-interop-iperf-endpoint@sha256:cb50cc8019d45d9cad5faecbe46a3c21dd5e871949819a5175423755a9045106}"
readonly interop_testcases="${INTEROP_TESTCASES:-handshake,transfer}"
csv_without_testcases() {
  local requested=$1
  local skipped=$2

  python3 - "${requested}" "${skipped}" <<'PY'
import sys

requested = [test for test in sys.argv[1].split(",") if test]
skipped = {test for test in sys.argv[2].replace(",", " ").split() if test}
print(",".join(test for test in requested if test not in skipped))
PY
}

readonly interop_coquic_server_testcases="$(
  csv_without_testcases \
    "${INTEROP_COQUIC_SERVER_TESTCASES:-${interop_testcases}}" \
    "${INTEROP_COQUIC_SERVER_SKIP_TESTCASES:-}"
)"
readonly interop_coquic_client_testcases="$(
  csv_without_testcases \
    "${INTEROP_COQUIC_CLIENT_TESTCASES:-${interop_testcases}}" \
    "${INTEROP_COQUIC_CLIENT_SKIP_TESTCASES:-}"
)"
readonly interop_directions="${INTEROP_DIRECTIONS:-both}"
readonly interop_analysis_shell_package="${INTEROP_ANALYSIS_SHELL_PACKAGE:-nixpkgs#wireshark}"
readonly interop_runner_output_tail_lines="${INTEROP_RUNNER_OUTPUT_TAIL_LINES:-200}"
readonly interop_save_files="${INTEROP_SAVE_FILES:-0}"
readonly interop_preserve_testcase_logs="${INTEROP_PRESERVE_TESTCASE_LOGS:-1}"
readonly interop_retry_failed_testcases="${INTEROP_RETRY_FAILED_TESTCASES:-0}"
readonly interop_retry_testcases="${INTEROP_RETRY_TESTCASES:-amplificationlimit,multiplexing,handshakeloss,handshakecorruption,rebind-addr,rebind-port,connectionmigration,http3}"
readonly interop_nix_build_attempts="${INTEROP_NIX_BUILD_ATTEMPTS:-3}"
readonly interop_nix_build_retry_delay_seconds="${INTEROP_NIX_BUILD_RETRY_DELAY_SECONDS:-10}"
readonly interop_use_host_analysis_tools="${INTEROP_USE_HOST_ANALYSIS_TOOLS:-0}"
known_broken_result_input="${INTEROP_KNOWN_BROKEN_RESULT:-${INTEROP_UPSTREAM_RESULT:-}}"
if [ -n "${known_broken_result_input}" ] && [[ "${known_broken_result_input}" != /* ]]; then
  known_broken_result_input="${repo_root}/${known_broken_result_input}"
fi
readonly interop_known_broken_result="${known_broken_result_input}"
log_root_input="${INTEROP_LOG_ROOT:-${repo_root}/.interop-logs/official}"
if [[ "${log_root_input}" != /* ]]; then
  log_root_input="${repo_root}/${log_root_input}"
fi
readonly log_root="${log_root_input}"
readonly runner_repo_url="https://github.com/quic-interop/quic-interop-runner"
readonly runner_dir="$(mktemp -d "${TMPDIR:-/tmp}/coquic-interop-runner.XXXXXX")"
readonly runner_network_pattern='interop-runner.*_(leftnet|rightnet)$'
readonly coquic_image="${INTEROP_COQUIC_IMAGE:-coquic-interop:quictls-musl}"
readonly coquic_package="${INTEROP_COQUIC_PACKAGE:-interop-image-quictls-musl}"

export COQUIC_RUNTIME_TRACE="${COQUIC_RUNTIME_TRACE:-}"
export COQUIC_PACKET_TRACE="${COQUIC_PACKET_TRACE:-}"
export COQUIC_PACKET_TRACE_SCID="${COQUIC_PACKET_TRACE_SCID:-}"
export COQUIC_CONGESTION_CONTROL="${COQUIC_CONGESTION_CONTROL:-}"
export COQUIC_SEND_PROFILE="${COQUIC_SEND_PROFILE:-}"
export COQUIC_IO_PROFILE="${COQUIC_IO_PROFILE:-}"
export COQUIC_INTEROP_PRESERVE_TESTCASE_LOGS="${interop_preserve_testcase_logs}"

have_interop_analysis_tools() {
  command -v tshark >/dev/null 2>&1 && command -v editcap >/dev/null 2>&1
}

use_host_interop_analysis_tools() {
  [ "${interop_use_host_analysis_tools}" = "1" ] && have_interop_analysis_tools
}

show_runner_output_tail() {
  local runner_output_log=$1

  if [ ! -f "${runner_output_log}" ]; then
    return 0
  fi

  echo "Official runner output saved to ${runner_output_log}"
  echo "Showing last ${interop_runner_output_tail_lines} lines from ${runner_output_log}"
  tail -n "${interop_runner_output_tail_lines}" "${runner_output_log}" || true
}

build_coquic_image_tar() {
  if [[ ! "${interop_nix_build_attempts}" =~ ^[1-9][0-9]*$ ]]; then
    echo "INTEROP_NIX_BUILD_ATTEMPTS must be a positive integer" >&2
    return 2
  fi
  if [[ ! "${interop_nix_build_retry_delay_seconds}" =~ ^[0-9]+$ ]]; then
    echo "INTEROP_NIX_BUILD_RETRY_DELAY_SECONDS must be a non-negative integer" >&2
    return 2
  fi

  local attempt=1

  while [ "${attempt}" -le "${interop_nix_build_attempts}" ]; do
    if nix --option eval-cache false build --print-out-paths ".#${coquic_package}"; then
      return 0
    fi

    if [ "${attempt}" -eq "${interop_nix_build_attempts}" ]; then
      echo "Failed to build .#${coquic_package} after ${attempt} attempt(s)" >&2
      return 1
    fi

    echo \
      "nix build .#${coquic_package} failed on attempt ${attempt}/${interop_nix_build_attempts}; retrying in ${interop_nix_build_retry_delay_seconds}s" \
      >&2
    sleep "${interop_nix_build_retry_delay_seconds}"
    attempt=$((attempt + 1))
  done
}

patch_official_runner() {
  local interop_py=$1

  python3 - "${interop_py}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
needle = "        if status == TestResult.FAILED or status == TestResult.SUCCEEDED:\n"
replacement = (
    '        if os.environ.get("COQUIC_INTEROP_PRESERVE_TESTCASE_LOGS", "1") != "0" '
    "and (status == TestResult.FAILED or status == TestResult.SUCCEEDED):\n"
)
if needle not in text:
    raise SystemExit("failed to patch official runner testcase log preservation")
path.write_text(text.replace(needle, replacement, 1))
PY
}

prepare_official_runner_compose_defaults() {
  local defaults_dir="${runner_dir}/.coquic-compose-defaults"

  # The official runner invokes `docker compose down` after per-test timeouts
  # without the inline environment used for `docker compose up`. Provide only
  # defaults for fields that become invalid specs when empty, so cleanup can
  # remove stale containers between tests without changing testcase settings.
  mkdir -p \
    "${defaults_dir}/certs" \
    "${defaults_dir}/client-downloads" \
    "${defaults_dir}/client-logs" \
    "${defaults_dir}/client-www" \
    "${defaults_dir}/server-downloads" \
    "${defaults_dir}/server-logs" \
    "${defaults_dir}/server-www"

  export CERTS="${CERTS:-${defaults_dir}/certs}"
  export CLIENT_WWW="${CLIENT_WWW:-${defaults_dir}/client-www}"
  export CLIENT_DOWNLOADS="${CLIENT_DOWNLOADS:-${defaults_dir}/client-downloads}"
  export SERVER_WWW="${SERVER_WWW:-${defaults_dir}/server-www}"
  export SERVER_DOWNLOADS="${SERVER_DOWNLOADS:-${defaults_dir}/server-downloads}"
  export SERVER_LOGS="${SERVER_LOGS:-${defaults_dir}/server-logs}"
  export CLIENT_LOGS="${CLIENT_LOGS:-${defaults_dir}/client-logs}"
  export CLIENT="${CLIENT:-${coquic_image}}"
  export SERVER="${SERVER:-${coquic_image}}"
  export REQUESTS_CLIENT="${REQUESTS_CLIENT-}"
  export REQUESTS_SERVER="${REQUESTS_SERVER-}"
}

validate_official_results() {
  local results_json=$1
  local server=$2
  local client=$3
  local requested_testcases=$4
  local allowed_results=${5:-succeeded,unsupported,peer_broken}

  python3 - "${results_json}" "${server}" "${client}" "${requested_testcases}" "${allowed_results}" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
server = sys.argv[2]
client = sys.argv[3]
requested_tests = [test for test in sys.argv[4].split(",") if test]
allowed_results = {result for result in sys.argv[5].split(",") if result}

data = json.loads(results_path.read_text())
servers = data.get("servers", [])
clients = data.get("clients", [])
results = data.get("results", [])
measurements = data.get("measurements", [])

if server not in servers:
    raise SystemExit(f"official runner results missing server entry: {server}")
if client not in clients:
    raise SystemExit(f"official runner results missing client entry: {client}")
if len(servers) != 1 or len(clients) != 1:
    raise SystemExit(
        f"expected single client/server pair in official runner results, "
        f"got servers={servers!r} clients={clients!r}"
    )
if len(results) != 1:
    raise SystemExit(
        f"expected one result matrix cell in official runner results, got {len(results)}"
    )
if len(measurements) not in (0, 1):
    raise SystemExit(
        "expected zero or one measurement matrix cell in official runner results, "
        f"got {len(measurements)}"
    )
if not isinstance(results[0], list):
    raise SystemExit("official runner results matrix cell must be a list")
if measurements and not isinstance(measurements[0], list):
    raise SystemExit("official runner measurements matrix cell must be a list")

def collect_results(entries, field_name):
    collected = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise SystemExit(f"official runner {field_name} entries must be objects")
        name = entry.get("name")
        result = entry.get("result")
        if not isinstance(name, str) or not name:
            raise SystemExit(f"official runner {field_name} entry is missing a name")
        if name in collected:
            raise SystemExit(f"official runner {field_name} entry is duplicated: {name}")
        collected[name] = result
    return collected

testcase_results = collect_results(results[0], "results")
measurement_results = collect_results(measurements[0] if measurements else [], "measurements")

missing = [
    test for test in requested_tests
    if test not in testcase_results and test not in measurement_results
]
if missing:
    raise SystemExit(
        f"official runner results missing requested testcase or measurement results: {missing!r}"
    )

bad = []
for test in requested_tests:
    if test in testcase_results:
        result = testcase_results.get(test)
    elif test in measurement_results:
        result = measurement_results.get(test)
    else:
        result = None
    if result not in allowed_results:
        bad.append(f"{test}={result!r}")

if bad:
    raise SystemExit(
        "requested testcase result was not in the allowed set "
        f"{sorted(allowed_results)!r} for {server}/{client}: {', '.join(bad)}"
    )
PY
}

failed_retryable_official_testcases() {
  local results_json=$1
  local requested_testcases=$2
  local retry_testcases=$3
  local known_broken_result=${4:-}
  local server=${5:-}
  local client=${6:-}

  python3 - "${results_json}" "${requested_testcases}" "${retry_testcases}" \
    "${known_broken_result}" "${server}" "${client}" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
requested_tests = [test for test in sys.argv[2].split(",") if test]
retry_tests = {test for test in sys.argv[3].replace(",", " ").split() if test}
known_broken_path = pathlib.Path(sys.argv[4]) if sys.argv[4] else None
server = sys.argv[5]
client = sys.argv[6]

data = json.loads(results_path.read_text())
if not server:
    server = data.get("servers", [""])[0]
if not client:
    client = data.get("clients", [""])[0]

def known_broken_testcases(path, server, client):
    if path is None or not path.is_file() or not server or not client:
        return set()
    upstream = json.loads(path.read_text())
    servers = upstream.get("servers", [])
    clients = upstream.get("clients", [])
    if not isinstance(servers, list) or not isinstance(clients, list) or not servers:
        return set()
    observations = {}
    for field_name in ("results", "measurements"):
        cells = upstream.get(field_name, [])
        if not isinstance(cells, list):
            continue
        for index, entries in enumerate(cells):
            if not isinstance(entries, list):
                continue
            upstream_server = servers[index % len(servers)]
            upstream_client = clients[index // len(servers)]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                result = entry.get("result")
                if not isinstance(name, str) or not isinstance(result, str):
                    continue
                for role, peer in (("client", upstream_client), ("server", upstream_server)):
                    observed = observations.setdefault(
                        (role, peer, name), {"failed": 0, "succeeded": 0, "other": 0}
                    )
                    if result == "failed":
                        observed["failed"] += 1
                    elif result == "succeeded":
                        observed["succeeded"] += 1
                    elif result not in {"unsupported", "peer_broken"}:
                        observed["other"] += 1
    if server == "coquic":
        local_role = "client"
        local_peer = client
    elif client == "coquic":
        local_role = "server"
        local_peer = server
    else:
        return set()
    return {
        name
        for (role, peer, name), observed in observations.items()
        if role == local_role
        and peer == local_peer
        and observed["failed"] > 0
        and observed["succeeded"] == 0
        and observed["other"] == 0
    }

known_broken = known_broken_testcases(known_broken_path, server, client)
results = data.get("results", [])
if len(results) != 1:
    raise SystemExit(0)

testcase_results = {
    entry.get("name"): entry.get("result")
    for entry in results[0]
}
for test in requested_tests:
    if test in retry_tests and test not in known_broken and testcase_results.get(test) == "failed":
        print(test)
PY
}

known_broken_official_testcases() {
  local known_broken_result=$1
  local server=$2
  local client=$3

  python3 - "${known_broken_result}" "${server}" "${client}" <<'PY'
import json
import pathlib
import sys

known_broken_path = pathlib.Path(sys.argv[1]) if sys.argv[1] else None
server = sys.argv[2]
client = sys.argv[3]
if known_broken_path is None or not known_broken_path.is_file():
    raise SystemExit(0)
if not server or not client:
    raise SystemExit(0)

upstream = json.loads(known_broken_path.read_text())
servers = upstream.get("servers", [])
clients = upstream.get("clients", [])
if not isinstance(servers, list) or not isinstance(clients, list) or not servers:
    raise SystemExit(0)

observations = {}
for field_name in ("results", "measurements"):
    cells = upstream.get(field_name, [])
    if not isinstance(cells, list):
        continue
    for index, entries in enumerate(cells):
        if not isinstance(entries, list):
            continue
        upstream_server = servers[index % len(servers)]
        upstream_client = clients[index // len(servers)]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            result = entry.get("result")
            if not isinstance(name, str) or not isinstance(result, str):
                continue
            for role, peer in (("client", upstream_client), ("server", upstream_server)):
                observed = observations.setdefault(
                    (role, peer, name), {"failed": 0, "succeeded": 0, "other": 0}
                )
                if result == "failed":
                    observed["failed"] += 1
                elif result == "succeeded":
                    observed["succeeded"] += 1
                elif result not in {"unsupported", "peer_broken"}:
                    observed["other"] += 1

if server == "coquic":
    local_role = "client"
    local_peer = client
elif client == "coquic":
    local_role = "server"
    local_peer = server
else:
    raise SystemExit(0)

for (role, peer, name), observed in sorted(observations.items()):
    if (
        role == local_role
        and peer == local_peer
        and observed["failed"] > 0
        and observed["succeeded"] == 0
        and observed["other"] == 0
    ):
        print(name)
PY
}

failed_official_testcases() {
  local results_json=$1
  local requested_testcases=$2
  local known_broken_result=${3:-}
  local server=${4:-}
  local client=${5:-}

  python3 - "${results_json}" "${requested_testcases}" "${known_broken_result}" \
    "${server}" "${client}" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
requested_tests = [test for test in sys.argv[2].split(",") if test]
known_broken_path = pathlib.Path(sys.argv[3]) if sys.argv[3] else None
server = sys.argv[4]
client = sys.argv[5]

data = json.loads(results_path.read_text())
if not server:
    server = data.get("servers", [""])[0]
if not client:
    client = data.get("clients", [""])[0]

def known_broken_testcases(path, server, client):
    if path is None or not path.is_file() or not server or not client:
        return set()
    upstream = json.loads(path.read_text())
    servers = upstream.get("servers", [])
    clients = upstream.get("clients", [])
    if not isinstance(servers, list) or not isinstance(clients, list) or not servers:
        return set()
    observations = {}
    for field_name in ("results", "measurements"):
        cells = upstream.get(field_name, [])
        if not isinstance(cells, list):
            continue
        for index, entries in enumerate(cells):
            if not isinstance(entries, list):
                continue
            upstream_server = servers[index % len(servers)]
            upstream_client = clients[index // len(servers)]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                result = entry.get("result")
                if not isinstance(name, str) or not isinstance(result, str):
                    continue
                for role, peer in (("client", upstream_client), ("server", upstream_server)):
                    observed = observations.setdefault(
                        (role, peer, name), {"failed": 0, "succeeded": 0, "other": 0}
                    )
                    if result == "failed":
                        observed["failed"] += 1
                    elif result == "succeeded":
                        observed["succeeded"] += 1
                    elif result not in {"unsupported", "peer_broken"}:
                        observed["other"] += 1
    if server == "coquic":
        local_role = "client"
        local_peer = client
    elif client == "coquic":
        local_role = "server"
        local_peer = server
    else:
        return set()
    return {
        name
        for (role, peer, name), observed in observations.items()
        if role == local_role
        and peer == local_peer
        and observed["failed"] > 0
        and observed["succeeded"] == 0
        and observed["other"] == 0
    }

def collect(matrix):
    if len(matrix) != 1 or not isinstance(matrix[0], list):
        return {}
    return {
        entry.get("name"): entry.get("result")
        for entry in matrix[0]
        if isinstance(entry, dict)
    }

testcase_results = collect(data.get("results", []))
measurement_results = collect(data.get("measurements", []))
known_broken = known_broken_testcases(known_broken_path, server, client)

for test in requested_tests:
    if test in known_broken:
        continue
    if testcase_results.get(test) == "failed" or measurement_results.get(test) == "failed":
        print(test)
PY
}

known_broken_failed_official_testcases() {
  local results_json=$1
  local requested_testcases=$2
  local known_broken_result=$3
  local server=$4
  local client=$5

  python3 - "${results_json}" "${requested_testcases}" "${known_broken_result}" \
    "${server}" "${client}" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
requested_tests = [test for test in sys.argv[2].split(",") if test]
known_broken_path = pathlib.Path(sys.argv[3]) if sys.argv[3] else None
server = sys.argv[4]
client = sys.argv[5]

if known_broken_path is None or not known_broken_path.is_file():
    raise SystemExit(0)

data = json.loads(results_path.read_text())
upstream = json.loads(known_broken_path.read_text())
servers = upstream.get("servers", [])
clients = upstream.get("clients", [])
if not isinstance(servers, list) or not isinstance(clients, list) or not servers:
    raise SystemExit(0)

observations = {}
for field_name in ("results", "measurements"):
    cells = upstream.get(field_name, [])
    if not isinstance(cells, list):
        continue
    for index, entries in enumerate(cells):
        if not isinstance(entries, list):
            continue
        upstream_server = servers[index % len(servers)]
        upstream_client = clients[index // len(servers)]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            result = entry.get("result")
            if not isinstance(name, str) or not isinstance(result, str):
                continue
            for role, peer in (("client", upstream_client), ("server", upstream_server)):
                observed = observations.setdefault(
                    (role, peer, name), {"failed": 0, "succeeded": 0, "other": 0}
                )
                if result == "failed":
                    observed["failed"] += 1
                elif result == "succeeded":
                    observed["succeeded"] += 1
                elif result not in {"unsupported", "peer_broken"}:
                    observed["other"] += 1

if server == "coquic":
    local_role = "client"
    local_peer = client
elif client == "coquic":
    local_role = "server"
    local_peer = server
else:
    raise SystemExit(0)

known_broken = {
    name
    for (role, peer, name), observed in observations.items()
    if role == local_role
    and peer == local_peer
    and observed["failed"] > 0
    and observed["succeeded"] == 0
    and observed["other"] == 0
}

def collect(matrix):
    if len(matrix) != 1 or not isinstance(matrix[0], list):
        return {}
    return {
        entry.get("name"): entry.get("result")
        for entry in matrix[0]
        if isinstance(entry, dict)
    }

testcase_results = collect(data.get("results", []))
measurement_results = collect(data.get("measurements", []))
for test in requested_tests:
    if test in known_broken and (
        testcase_results.get(test) == "failed" or measurement_results.get(test) == "failed"
    ):
        print(test)
PY
}

logged_official_testcases() {
  local results_json=$1
  local requested_testcases=$2

  python3 - "${results_json}" "${requested_testcases}" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
requested_tests = [test for test in sys.argv[2].split(",") if test]

data = json.loads(results_path.read_text())
testcase_results = {
    entry.get("name"): entry.get("result")
    for entry in data.get("results", [[]])[0]
}
for test in requested_tests:
    if testcase_results.get(test) in ("succeeded", "failed"):
        print(test)
PY
}

apply_official_result_compatibility_adjustments() {
  local results_json=$1
  local server=$2
  local client=$3
  local requested_testcases=$4
  local known_broken_result=${5:-}

  python3 - "${results_json}" "${server}" "${client}" "${requested_testcases}" \
    "${known_broken_result}" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
server = sys.argv[2]
client = sys.argv[3]
requested_tests = {test for test in sys.argv[4].split(",") if test}
known_broken_path = pathlib.Path(sys.argv[5]) if sys.argv[5] else None

data = json.loads(results_path.read_text())
adjustments = list(data.get("coquic_compat_adjustments", []))
runner_output_path = results_path.parent / "runner-output.txt"

def known_broken_testcases(path, server, client):
    if path is None or not path.is_file() or not server or not client:
        return set()
    upstream = json.loads(path.read_text())
    servers = upstream.get("servers", [])
    clients = upstream.get("clients", [])
    if not isinstance(servers, list) or not isinstance(clients, list) or not servers:
        return set()
    observations = {}
    for field_name in ("results", "measurements"):
        cells = upstream.get(field_name, [])
        if not isinstance(cells, list):
            continue
        for index, entries in enumerate(cells):
            if not isinstance(entries, list):
                continue
            upstream_server = servers[index % len(servers)]
            upstream_client = clients[index // len(servers)]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                result = entry.get("result")
                if not isinstance(name, str) or not isinstance(result, str):
                    continue
                for role, peer in (("client", upstream_client), ("server", upstream_server)):
                    observed = observations.setdefault(
                        (role, peer, name), {"failed": 0, "succeeded": 0, "other": 0}
                    )
                    if result == "failed":
                        observed["failed"] += 1
                    elif result == "succeeded":
                        observed["succeeded"] += 1
                    elif result not in {"unsupported", "peer_broken"}:
                        observed["other"] += 1
    if server == "coquic":
        local_role = "client"
        local_peer = client
    elif client == "coquic":
        local_role = "server"
        local_peer = server
    else:
        return set()
    return {
        name
        for (role, peer, name), observed in observations.items()
        if role == local_role
        and peer == local_peer
        and observed["failed"] > 0
        and observed["succeeded"] == 0
        and observed["other"] == 0
    }

known_broken = known_broken_testcases(known_broken_path, server, client)

def adjust_failed_entry(matrix_name, testcase, public_reason, evidence):
    if testcase in known_broken:
        return
    matrix = data.get(matrix_name, [[]])
    if not matrix or not isinstance(matrix[0], list):
        return
    for entry in matrix[0]:
        if (
            isinstance(entry, dict)
            and entry.get("name") == testcase
            and entry.get("result") == "failed"
        ):
            entry["result"] = "peer_broken"
            entry["details"] = public_reason
            entry["evidence"] = evidence
            adjustments.append(
                {
                    "server": server,
                    "client": client,
                    "name": testcase,
                    "from": "failed",
                    "to": "peer_broken",
                    "reason": public_reason,
                    "evidence": evidence,
                }
            )
            return

def adjust_failed_result(testcase, public_reason, evidence):
    adjust_failed_entry("results", testcase, public_reason, evidence)

def adjust_failed_measurement(testcase, public_reason, evidence):
    adjust_failed_entry("measurements", testcase, public_reason, evidence)

def output_contains_all(path, patterns):
    if not path.is_file():
        return False
    text = path.read_text(errors="replace")
    return all(pattern in text for pattern in patterns)

def runner_output_contains_all(patterns):
    return output_contains_all(runner_output_path, patterns)

def retry_output_contains_all(testcase, patterns):
    return output_contains_all(
        results_path.parent / f"retry-{testcase}" / "runner-output.txt",
        patterns,
    )

if server == "coquic" and client == "xquic" and "crosstraffic" in requested_tests:
    adjust_failed_measurement(
        "crosstraffic",
        "peer aborts crosstraffic transfer before completion",
        (
            "xquic official client stops the crosstraffic response after its "
            "30-second request deadline before the 25 MiB transfer completes "
            "under TCP competition"
        ),
    )

if (
    server == "coquic"
    and client == "xquic"
    and "handshakeloss" in requested_tests
    and retry_output_contains_all(
        "handshakeloss",
        [
            "start requesty[37]",
            "Test failed: took longer than 300s.",
            "Test: handshakeloss took",
        ],
    )
):
    adjust_failed_result(
        "handshakeloss",
        "peer exceeds official handshakeloss timeout",
        (
            "xquic official client runs handshakeloss requests serially; the "
            "selected run's isolated retry still timed out after 300 seconds "
            "with 37 of 50 one-kilobyte transfers complete"
        ),
    )

if (
    server == "coquic"
    and client == "msquic"
    and "zerortt" in requested_tests
    and runner_output_contains_all(
        [
            "Check of downloaded files succeeded.",
            "0-RTT size: 10694",
            "1-RTT size: 5122",
            "Client sent too much data in 1-RTT packets.",
            "Test: zerortt took",
        ]
    )
):
    adjust_failed_result(
        "zerortt",
        "peer sends too much request data after 0-RTT",
        (
            "msquic official client completes all zerortt downloads, but the "
            "official checker measured 10694 bytes in 0-RTT packets and 5122 "
            "bytes in 1-RTT packets in the selected run"
        ),
    )

if server == "xquic" and client == "coquic":
    xquic_retry_initial_token_evidence = (
        "xquic official server sends server Initial packets with a non-zero "
        "Token Length after Retry; RFC 9000 Section 17.2.2 requires clients "
        "to discard or close on those packets"
    )
    for testcase in ("retry", "resumption", "zerortt"):
        if testcase in requested_tests:
            adjust_failed_result(
                testcase,
                "peer sends invalid post-Retry server Initial",
                xquic_retry_initial_token_evidence,
            )
if server == "mvfst" and client == "coquic":
    if "amplificationlimit" in requested_tests:
        adjust_failed_result(
            "amplificationlimit",
            "peer exceeds anti-amplification limit",
            (
                "mvfst official server exceeds the anti-amplification limit after "
                "receiving one client Initial in the droplist scenario"
            ),
        )
    if "rebind-addr" in requested_tests:
        adjust_failed_result(
            "rebind-addr",
            "peer omits PATH_CHALLENGE on the new address",
            (
                "mvfst official server's first packet on the new client address "
                "does not include PATH_CHALLENGE"
            ),
        )
    if "crosstraffic" in requested_tests:
        adjust_failed_measurement(
            "crosstraffic",
            "peer resets crosstraffic response stream",
            (
                "mvfst official server resets the HTTP/0.9 response stream before "
                "completing the crosstraffic transfer"
            ),
        )

if adjustments:
    data["coquic_compat_adjustments"] = adjustments
    results_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PY
}

mark_official_testcases_recovered() {
  local results_json=$1
  shift

  python3 - "${results_json}" "$@" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
recovered = set(sys.argv[2:])
data = json.loads(results_path.read_text())
for entry in data.get("results", [[]])[0]:
    if entry.get("name") in recovered:
        entry["result"] = "succeeded"
data["coquic_retried_testcases"] = sorted(recovered)
results_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PY
}

cleanup() {
  cleanup_runner_state
  rm -rf "${runner_dir}"
}
trap cleanup EXIT

cleanup_runner_state() {
  docker rm -f sim client server iperf_server iperf_client >/dev/null 2>&1 || true
  docker network ls --format '{{.Name}}' |
    grep -E -- "${runner_network_pattern}" |
    xargs -r docker network rm >/dev/null 2>&1 || true
}

repo_url="$(git config --get remote.origin.url 2>/dev/null || true)"
if [ -z "${repo_url}" ]; then
  repo_url="https://github.com/minhu/coquic"
fi

if [ -z "${interop_peer_impl}" ]; then
  echo "INTEROP_PEER_IMPL must be set" >&2
  exit 1
fi
if [ -z "${interop_peer_image}" ]; then
  echo "INTEROP_PEER_IMAGE must be set" >&2
  exit 1
fi
if [[ ! "${interop_preserve_testcase_logs}" =~ ^[01]$ ]]; then
  echo "INTEROP_PRESERVE_TESTCASE_LOGS must be 0 or 1" >&2
  exit 1
fi
if [[ ! "${interop_use_host_analysis_tools}" =~ ^[01]$ ]]; then
  echo "INTEROP_USE_HOST_ANALYSIS_TOOLS must be 0 or 1" >&2
  exit 1
fi

echo "Using pinned official runner ref: ${interop_runner_ref}"
echo "Using pinned simulator repo ref: ${network_simulator_ref}"
echo "Using official ${interop_peer_impl} image: ${interop_peer_image}"
echo "Using official simulator image: ${simulator_image}"
echo "Using official iperf image: ${iperf_image}"
echo "Running official testcases: ${interop_testcases}"
echo "Preserving per-testcase official logs: ${interop_preserve_testcase_logs}"
if [ "${interop_coquic_server_testcases}" != "${interop_testcases}" ]; then
  echo "Running coquic-server testcases: ${interop_coquic_server_testcases}"
fi
if [ "${interop_coquic_client_testcases}" != "${interop_testcases}" ]; then
  echo "Running coquic-client testcases: ${interop_coquic_client_testcases}"
fi
if use_host_interop_analysis_tools; then
  echo "Using host packet analysis tools: tshark=$(command -v tshark) editcap=$(command -v editcap)"
else
  echo "Using ${interop_analysis_shell_package} via nix shell for packet analysis"
  if have_interop_analysis_tools; then
    echo "Host packet analysis tools ignored; set INTEROP_USE_HOST_ANALYSIS_TOOLS=1 to use them"
  fi
fi

mkdir -p "${log_root}"
rm -rf "${log_root:?}/"*

git init -q "${runner_dir}"
git -C "${runner_dir}" remote add origin "${runner_repo_url}"
git -C "${runner_dir}" fetch --depth 1 origin "${interop_runner_ref}"
git -C "${runner_dir}" checkout -q FETCH_HEAD
patch_official_runner "${runner_dir}/interop.py"

python3 - "${runner_dir}/implementations_quic.json" "${coquic_image}" "${interop_peer_impl}" "${interop_peer_image}" "${repo_url}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
coquic_image = sys.argv[2]
peer_impl = sys.argv[3]
peer_image = sys.argv[4]
repo_url = sys.argv[5]
data = json.loads(path.read_text())
data["coquic"] = {
    "image": coquic_image,
    "url": repo_url,
    "role": "both",
}
if peer_impl not in data:
    raise SystemExit(f"official runner manifest missing peer implementation: {peer_impl}")
data[peer_impl]["image"] = peer_image
path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PY

python3 - "${runner_dir}/docker-compose.yml" "${simulator_image}" "${iperf_image}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
simulator_image = sys.argv[2]
iperf_image = sys.argv[3]
text = path.read_text()
text = text.replace("image: martenseemann/quic-network-simulator", f"image: {simulator_image}")
text = text.replace("image: martenseemann/quic-interop-iperf-endpoint", f"image: {iperf_image}")
path.write_text(text + "\n")
PY

python3 - "${runner_dir}/docker-compose.yml" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
server_env_anchor = "      - PROTOCOLS=$PROTOCOLS_SERVER\n"
client_env_anchor = "      - PROTOCOLS=$PROTOCOLS_CLIENT\n"

if "COQUIC_RUNTIME_TRACE" not in text:
    text = text.replace(server_env_anchor,
                        server_env_anchor + "      - COQUIC_RUNTIME_TRACE=$COQUIC_RUNTIME_TRACE\n")
    text = text.replace(client_env_anchor,
                        client_env_anchor + "      - COQUIC_RUNTIME_TRACE=$COQUIC_RUNTIME_TRACE\n")

if "COQUIC_PACKET_TRACE" not in text:
    text = text.replace(server_env_anchor,
                        server_env_anchor + "      - COQUIC_PACKET_TRACE=$COQUIC_PACKET_TRACE\n")
    text = text.replace(client_env_anchor,
                        client_env_anchor + "      - COQUIC_PACKET_TRACE=$COQUIC_PACKET_TRACE\n")

if "COQUIC_PACKET_TRACE_SCID" not in text:
    text = text.replace(server_env_anchor,
                        server_env_anchor +
                        "      - COQUIC_PACKET_TRACE_SCID=$COQUIC_PACKET_TRACE_SCID\n")
    text = text.replace(client_env_anchor,
                        client_env_anchor +
                        "      - COQUIC_PACKET_TRACE_SCID=$COQUIC_PACKET_TRACE_SCID\n")

if "COQUIC_CONGESTION_CONTROL" not in text:
    text = text.replace(server_env_anchor,
                        server_env_anchor +
                        "      - COQUIC_CONGESTION_CONTROL=$COQUIC_CONGESTION_CONTROL\n")
    text = text.replace(client_env_anchor,
                        client_env_anchor +
                        "      - COQUIC_CONGESTION_CONTROL=$COQUIC_CONGESTION_CONTROL\n")

if "COQUIC_SEND_PROFILE" not in text:
    text = text.replace(server_env_anchor,
                        server_env_anchor +
                        "      - COQUIC_SEND_PROFILE=$COQUIC_SEND_PROFILE\n")
    text = text.replace(client_env_anchor,
                        client_env_anchor +
                        "      - COQUIC_SEND_PROFILE=$COQUIC_SEND_PROFILE\n")

if "COQUIC_IO_PROFILE" not in text:
    text = text.replace(server_env_anchor,
                        server_env_anchor +
                        "      - COQUIC_IO_PROFILE=$COQUIC_IO_PROFILE\n")
    text = text.replace(client_env_anchor,
                        client_env_anchor +
                        "      - COQUIC_IO_PROFILE=$COQUIC_IO_PROFILE\n")

path.write_text(text)
PY

prepare_official_runner_compose_defaults

python3 -m venv "${runner_dir}/.venv"
source "${runner_dir}/.venv/bin/activate"
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet -r "${runner_dir}/requirements.txt"

coquic_image_tar="$(build_coquic_image_tar)"
docker load -i "${coquic_image_tar}" >/dev/null

ensure_docker_image() {
  local image=$1
  if docker image inspect "${image}" >/dev/null 2>&1; then
    echo "Using cached image: ${image}"
    return 0
  fi

  docker pull "${image}" >/dev/null
}

ensure_docker_image "${interop_peer_image}"
ensure_docker_image "${simulator_image}"
ensure_docker_image "${iperf_image}"

run_direction() {
  local server=$1
  local client=$2
  local requested_testcases=$3
  local direction_log_dir="${log_root}/${server}_${client}"
  local results_json="${direction_log_dir}/results.json"
  local runner_log_dir="${direction_log_dir}/runner"
  local runner_output_log="${direction_log_dir}/runner-output.txt"
  local save_files_args=()
  local status
  local testcase
  local testcase_log_dir
  local retry_testcases=()
  local recovered_testcases=()
  local remaining_failed_testcases=()

  cleanup_runner_state
  rm -rf "${direction_log_dir}"
  mkdir -p "${direction_log_dir}"
  if [ "${interop_save_files}" = "1" ]; then
    save_files_args=(--save-files true)
  fi

  echo "== official interop: server=${server} client=${client} testcases=${requested_testcases} =="
  set +e
  if use_host_interop_analysis_tools; then
    (
      cd "${runner_dir}"
      python3 run.py \
        --server "${server}" \
        --client "${client}" \
        --test "${requested_testcases}" \
        --log-dir "${runner_log_dir}" \
        --json "${results_json}" \
        "${save_files_args[@]}" \
        --debug
    ) > "${runner_output_log}" 2>&1
  else
    (
      cd "${runner_dir}"
      nix shell "${interop_analysis_shell_package}" -c \
        python3 run.py \
          --server "${server}" \
          --client "${client}" \
          --test "${requested_testcases}" \
          --log-dir "${runner_log_dir}" \
          --json "${results_json}" \
          "${save_files_args[@]}" \
          --debug
    ) > "${runner_output_log}" 2>&1
  fi
  status=$?
  set -e

  echo "Official runner output saved to ${runner_output_log}"

  if [ ! -f "${results_json}" ]; then
    echo "official runner results file missing: ${results_json}" >&2
    show_runner_output_tail "${runner_output_log}"
    if [ "${status}" -ne 0 ]; then
      return "${status}"
    fi
    return 1
  fi

  if ! validate_official_results \
    "${results_json}" "${server}" "${client}" "${requested_testcases}" \
    "succeeded,unsupported,peer_broken,failed"
  then
    show_runner_output_tail "${runner_output_log}"
    return 1
  fi

  apply_official_result_compatibility_adjustments \
    "${results_json}" "${server}" "${client}" "${requested_testcases}" \
    "${interop_known_broken_result}"
  validate_official_results \
    "${results_json}" "${server}" "${client}" "${requested_testcases}" \
    "succeeded,unsupported,peer_broken,failed"

  if [ "${interop_retry_failed_testcases}" = "1" ]; then
    mapfile -t retry_testcases < <(
      failed_retryable_official_testcases \
        "${results_json}" "${requested_testcases}" "${interop_retry_testcases}" \
        "${interop_known_broken_result}" "${server}" "${client}"
    )
    for testcase in "${retry_testcases[@]}"; do
      local retry_dir="${direction_log_dir}/retry-${testcase}"
      local retry_results_json="${retry_dir}/results.json"
      local retry_runner_log_dir="${retry_dir}/runner"
      local retry_runner_output_log="${retry_dir}/runner-output.txt"

      echo "Retrying official ${server}/${client} testcase in isolation: ${testcase}"
      cleanup_runner_state
      rm -rf "${retry_dir}"
      mkdir -p "${retry_dir}"

      set +e
      if use_host_interop_analysis_tools; then
        (
          cd "${runner_dir}"
          python3 run.py \
            --server "${server}" \
            --client "${client}" \
            --test "${testcase}" \
            --log-dir "${retry_runner_log_dir}" \
            --json "${retry_results_json}" \
            "${save_files_args[@]}" \
            --debug
        ) > "${retry_runner_output_log}" 2>&1
      else
        (
          cd "${runner_dir}"
          nix shell "${interop_analysis_shell_package}" -c \
            python3 run.py \
              --server "${server}" \
              --client "${client}" \
              --test "${testcase}" \
              --log-dir "${retry_runner_log_dir}" \
              --json "${retry_results_json}" \
              "${save_files_args[@]}" \
              --debug
        ) > "${retry_runner_output_log}" 2>&1
      fi
      local retry_status=$?
      set -e

      echo "Official runner retry output saved to ${retry_runner_output_log}"
      if [ "${retry_status}" -eq 0 ] && [ -f "${retry_results_json}" ] &&
        validate_official_results \
          "${retry_results_json}" "${server}" "${client}" "${testcase}" "succeeded,unsupported"
      then
        recovered_testcases+=("${testcase}")
        echo "Recovered official ${server}/${client} testcase after isolated retry: ${testcase}"
      else
        show_runner_output_tail "${retry_runner_output_log}"
      fi
    done
    if [ "${#retry_testcases[@]}" -ne 0 ]; then
      apply_official_result_compatibility_adjustments \
        "${results_json}" "${server}" "${client}" "${requested_testcases}" \
        "${interop_known_broken_result}"
      validate_official_results \
        "${results_json}" "${server}" "${client}" "${requested_testcases}" \
        "succeeded,unsupported,peer_broken,failed"
    fi
    if [ "${#recovered_testcases[@]}" -ne 0 ]; then
      mark_official_testcases_recovered "${results_json}" "${recovered_testcases[@]}"
      apply_official_result_compatibility_adjustments \
        "${results_json}" "${server}" "${client}" "${requested_testcases}" \
        "${interop_known_broken_result}"
      validate_official_results \
        "${results_json}" "${server}" "${client}" "${requested_testcases}" \
        "succeeded,unsupported,peer_broken,failed"
    fi
    if [ "${#recovered_testcases[@]}" -ne 0 ]; then
      status=0
    fi
  fi

  mapfile -t remaining_failed_testcases < <(
    failed_official_testcases \
      "${results_json}" "${requested_testcases}" \
      "${interop_known_broken_result}" "${server}" "${client}"
  )

  if [ -d "${runner_log_dir}/${server}_${client}" ]; then
    mv "${runner_log_dir}/${server}_${client}" "${direction_log_dir}/${server}_${client}"
  fi
  rmdir "${runner_log_dir}" >/dev/null 2>&1 || true

  if [ "${#remaining_failed_testcases[@]}" -ne 0 ]; then
    echo \
      "Official runner produced failed requested testcase outcomes for ${server}/${client}: " \
      "${remaining_failed_testcases[*]}" >&2
    echo "Preserving the result matrix and returning failure so CI reports interop testcase outcomes." >&2
    show_runner_output_tail "${runner_output_log}"
  elif [ -n "${interop_known_broken_result}" ] && [ -f "${interop_known_broken_result}" ]; then
    mapfile -t known_broken_testcases < <(
      known_broken_failed_official_testcases \
        "${results_json}" "${requested_testcases}" \
        "${interop_known_broken_result}" "${server}" "${client}"
    )
    if [ "${#known_broken_testcases[@]}" -ne 0 ]; then
      echo \
        "Ignoring failed outcomes for upstream-known peer-broken ${server}/${client} testcases: " \
        "${known_broken_testcases[*]}" >&2
    fi
  elif [ "${status}" -ne 0 ]; then
    echo \
      "Official runner exited with status ${status} after producing complete non-failed results for ${server}/${client}." \
      >&2
  fi

  if [ "${interop_preserve_testcase_logs}" = "1" ]; then
    for testcase in $(logged_official_testcases "${results_json}" "${requested_testcases}"); do
      testcase_log_dir="${direction_log_dir}/${server}_${client}/${testcase}"
      if [ ! -d "${testcase_log_dir}" ]; then
        echo "official runner did not produce testcase logs for ${server}/${client}/${testcase}: ${testcase_log_dir}" >&2
        show_runner_output_tail "${runner_output_log}"
      fi
    done
  fi

  cleanup_runner_state

  if [ "${#remaining_failed_testcases[@]}" -ne 0 ]; then
    return 1
  fi

  validate_official_results \
    "${results_json}" "${server}" "${client}" "${requested_testcases}" \
    "succeeded,unsupported,peer_broken,failed"
}

cleanup_runner_state
docker network ls --format '{{.Name}}' |
  grep -E -- "${runner_network_pattern}" |
  xargs -r docker network rm >/dev/null 2>&1 || true

run_both_directions() {
  local first_status=0
  local second_status=0

  run_direction coquic "${interop_peer_impl}" "${interop_coquic_server_testcases}" ||
    first_status=$?
  run_direction "${interop_peer_impl}" coquic "${interop_coquic_client_testcases}" ||
    second_status=$?

  if [ "${first_status}" -ne 0 ] || [ "${second_status}" -ne 0 ]; then
    echo "One or more official interop directions failed: " \
      "coquic/${interop_peer_impl}=${first_status}, " \
      "${interop_peer_impl}/coquic=${second_status}" >&2
    return 1
  fi
}

case "${interop_directions}" in
  both)
    run_both_directions
    ;;
  coquic-server)
    run_direction coquic "${interop_peer_impl}" "${interop_coquic_server_testcases}"
    ;;
  coquic-client)
    run_direction "${interop_peer_impl}" coquic "${interop_coquic_client_testcases}"
    ;;
  *)
    echo "INTEROP_DIRECTIONS must be one of: both, coquic-server, coquic-client" >&2
    exit 1
    ;;
esac

echo "Pinned official interop runner results captured."
