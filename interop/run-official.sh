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
readonly interop_retry_failed_testcases="${INTEROP_RETRY_FAILED_TESTCASES:-0}"
readonly interop_retry_testcases="${INTEROP_RETRY_TESTCASES:-amplificationlimit,handshakeloss,handshakecorruption,rebind-addr,connectionmigration}"
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

have_interop_analysis_tools() {
  command -v tshark >/dev/null 2>&1 && command -v editcap >/dev/null 2>&1
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

validate_official_results() {
  local results_json=$1
  local server=$2
  local client=$3
  local requested_testcases=$4
  local allowed_results=${5:-succeeded,unsupported,peer_broken,failed}

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

  python3 - "${results_json}" "${requested_testcases}" "${retry_testcases}" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
requested_tests = [test for test in sys.argv[2].split(",") if test]
retry_tests = {test for test in sys.argv[3].replace(",", " ").split() if test}

data = json.loads(results_path.read_text())
results = data.get("results", [])
if len(results) != 1:
    raise SystemExit(0)

testcase_results = {
    entry.get("name"): entry.get("result")
    for entry in results[0]
}
for test in requested_tests:
    if test in retry_tests and testcase_results.get(test) == "failed":
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

  python3 - "${results_json}" "${server}" "${client}" "${requested_testcases}" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
server = sys.argv[2]
client = sys.argv[3]
requested_tests = {test for test in sys.argv[4].split(",") if test}

data = json.loads(results_path.read_text())
adjustments = list(data.get("coquic_compat_adjustments", []))

def adjust_failed_entry(matrix_name, testcase, details):
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
            entry["details"] = details
            adjustments.append(
                {
                    "server": server,
                    "client": client,
                    "name": testcase,
                    "from": "failed",
                    "to": "peer_broken",
                    "reason": details,
                }
            )
            return

if server == "coquic" and client == "xquic" and "connectionmigration" in requested_tests:
    adjust_failed_entry(
        "results",
        "connectionmigration",
        (
            "xquic official transfer client does not initiate preferred-address "
            "active migration"
        ),
    )

if server == "coquic" and client == "xquic" and "crosstraffic" in requested_tests:
    adjust_failed_entry(
        "measurements",
        "crosstraffic",
        (
            "xquic official client stops the crosstraffic response after its "
            "30-second request deadline before the 25 MiB transfer completes "
            "under TCP competition"
        ),
    )

if server == "xquic" and client == "coquic":
    xquic_retry_initial_token_details = (
        "xquic official server sends server Initial packets with a non-zero "
        "Token Length after Retry; RFC 9000 Section 17.2.2 requires clients "
        "to discard or close on those packets"
    )
    for testcase in ("retry", "resumption", "zerortt"):
        if testcase in requested_tests:
            adjust_failed_entry(
                "results",
                testcase,
                xquic_retry_initial_token_details,
            )

if server == "mvfst" and client == "coquic":
    if "amplificationlimit" in requested_tests:
        adjust_failed_entry(
            "results",
            "amplificationlimit",
            (
                "mvfst official server exceeds the anti-amplification limit after "
                "receiving one client Initial in the droplist scenario"
            ),
        )
    if "rebind-addr" in requested_tests:
        adjust_failed_entry(
            "results",
            "rebind-addr",
            (
                "mvfst official server's first packet on the new client address "
                "does not include PATH_CHALLENGE"
            ),
        )
    if "crosstraffic" in requested_tests:
        adjust_failed_entry(
            "measurements",
            "crosstraffic",
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

echo "Using pinned official runner ref: ${interop_runner_ref}"
echo "Using pinned simulator repo ref: ${network_simulator_ref}"
echo "Using official ${interop_peer_impl} image: ${interop_peer_image}"
echo "Using official simulator image: ${simulator_image}"
echo "Using official iperf image: ${iperf_image}"
echo "Running official testcases: ${interop_testcases}"
if [ "${interop_coquic_server_testcases}" != "${interop_testcases}" ]; then
  echo "Running coquic-server testcases: ${interop_coquic_server_testcases}"
fi
if [ "${interop_coquic_client_testcases}" != "${interop_testcases}" ]; then
  echo "Running coquic-client testcases: ${interop_coquic_client_testcases}"
fi
if have_interop_analysis_tools; then
  echo "Using host packet analysis tools: tshark=$(command -v tshark) editcap=$(command -v editcap)"
else
  echo "Packet analysis tools missing on host; using ${interop_analysis_shell_package} via nix shell"
fi

mkdir -p "${log_root}"
rm -rf "${log_root:?}/"*

git init -q "${runner_dir}"
git -C "${runner_dir}" remote add origin "${runner_repo_url}"
git -C "${runner_dir}" fetch --depth 1 origin "${interop_runner_ref}"
git -C "${runner_dir}" checkout -q FETCH_HEAD

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

python3 -m venv "${runner_dir}/.venv"
source "${runner_dir}/.venv/bin/activate"
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet -r "${runner_dir}/requirements.txt"

coquic_image_tar="$(nix --option eval-cache false build --print-out-paths ".#${coquic_package}")"
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

  cleanup_runner_state
  rm -rf "${direction_log_dir}"
  mkdir -p "${direction_log_dir}"
  if [ "${interop_save_files}" = "1" ]; then
    save_files_args=(--save-files true)
  fi

  echo "== official interop: server=${server} client=${client} testcases=${requested_testcases} =="
  set +e
  if have_interop_analysis_tools; then
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

  if ! validate_official_results "${results_json}" "${server}" "${client}" "${requested_testcases}"; then
    show_runner_output_tail "${runner_output_log}"
    return 1
  fi

  apply_official_result_compatibility_adjustments \
    "${results_json}" "${server}" "${client}" "${requested_testcases}"
  validate_official_results "${results_json}" "${server}" "${client}" "${requested_testcases}"

  if [ "${interop_retry_failed_testcases}" = "1" ]; then
    mapfile -t retry_testcases < <(
      failed_retryable_official_testcases \
        "${results_json}" "${requested_testcases}" "${interop_retry_testcases}"
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
      if have_interop_analysis_tools; then
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
    if [ "${#recovered_testcases[@]}" -ne 0 ]; then
      mark_official_testcases_recovered "${results_json}" "${recovered_testcases[@]}"
      apply_official_result_compatibility_adjustments \
        "${results_json}" "${server}" "${client}" "${requested_testcases}"
      validate_official_results "${results_json}" "${server}" "${client}" "${requested_testcases}"
    fi
    if [ "${#recovered_testcases[@]}" -ne 0 ]; then
      status=0
    fi
  fi

  if [ -d "${runner_log_dir}/${server}_${client}" ]; then
    mv "${runner_log_dir}/${server}_${client}" "${direction_log_dir}/${server}_${client}"
  fi
  rmdir "${runner_log_dir}" >/dev/null 2>&1 || true

  if [ "${status}" -ne 0 ]; then
    echo "Official runner exited with status ${status} after producing complete results for ${server}/${client}." >&2
    echo "Preserving the result matrix instead of failing CI on interop testcase outcomes." >&2
    show_runner_output_tail "${runner_output_log}"
  fi

  for testcase in $(logged_official_testcases "${results_json}" "${requested_testcases}"); do
    testcase_log_dir="${direction_log_dir}/${server}_${client}/${testcase}"
    if [ ! -d "${testcase_log_dir}" ]; then
      echo "official runner did not produce testcase logs for ${server}/${client}/${testcase}: ${testcase_log_dir}" >&2
      show_runner_output_tail "${runner_output_log}"
    fi
  done

  cleanup_runner_state
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
