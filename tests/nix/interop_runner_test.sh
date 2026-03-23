#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

readonly interop_runner_ref="${INTEROP_RUNNER_REF:-97319f8c0be2bc0be67b025522a64c9231018d37}"
readonly network_simulator_ref="${INTEROP_NETWORK_SIMULATOR_REF:-e557a54510e3578868f8c14cf3aa37e0fc6c76d0}"
readonly quicgo_image="${INTEROP_QUICGO_IMAGE:-martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424}"
readonly simulator_image="${INTEROP_SIMULATOR_IMAGE:-martenseemann/quic-network-simulator@sha256:c23d82a55caffe681b1bdae65d4d30d23e1283141a414a7f02ee56cf15f9c6b9}"
readonly iperf_image="${INTEROP_IPERF_IMAGE:-martenseemann/quic-interop-iperf-endpoint@sha256:cb50cc8019d45d9cad5faecbe46a3c21dd5e871949819a5175423755a9045106}"
readonly interop_testcases="${INTEROP_TESTCASES:-handshake,transfer}"
readonly log_root="${INTEROP_LOG_ROOT:-${repo_root}/.interop-logs/official}"
readonly runner_repo_url="https://github.com/quic-interop/quic-interop-runner"
readonly runner_dir="$(mktemp -d "${TMPDIR:-/tmp}/coquic-interop-runner.XXXXXX")"
readonly runner_network_pattern='interop-runner.*_(leftnet|rightnet)$'
readonly coquic_image="${INTEROP_COQUIC_IMAGE:-coquic-interop:quictls-musl}"
readonly coquic_package="${INTEROP_COQUIC_PACKAGE:-interop-image-quictls-musl}"

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

echo "Using pinned official runner ref: ${interop_runner_ref}"
echo "Using pinned simulator repo ref: ${network_simulator_ref}"
echo "Using official quic-go image: ${quicgo_image}"
echo "Using official simulator image: ${simulator_image}"
echo "Using official iperf image: ${iperf_image}"
echo "Running official testcases: ${interop_testcases}"

mkdir -p "${log_root}"
rm -rf "${log_root:?}/"*

git init -q "${runner_dir}"
git -C "${runner_dir}" remote add origin "${runner_repo_url}"
git -C "${runner_dir}" fetch --depth 1 origin "${interop_runner_ref}"
git -C "${runner_dir}" checkout -q FETCH_HEAD

python3 - "${runner_dir}/implementations_quic.json" "${coquic_image}" "${quicgo_image}" "${repo_url}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
coquic_image = sys.argv[2]
quicgo_image = sys.argv[3]
repo_url = sys.argv[4]
data = json.loads(path.read_text())
data["coquic"] = {
    "image": coquic_image,
    "url": repo_url,
    "role": "both",
}
if "quic-go" in data:
    data["quic-go"]["image"] = quicgo_image
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
text = "\n".join(
    line for line in text.splitlines()
    if "interface_name:" not in line
)
path.write_text(text + "\n")
PY

python3 -m venv "${runner_dir}/.venv"
source "${runner_dir}/.venv/bin/activate"
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet -r "${runner_dir}/requirements.txt"

nix --option eval-cache false build ".#${coquic_package}"
docker load -i "$(nix path-info ".#${coquic_package}")" >/dev/null
docker pull "${quicgo_image}" >/dev/null
docker pull "${simulator_image}" >/dev/null
docker pull "${iperf_image}" >/dev/null

run_direction() {
  local server=$1
  local client=$2
  local direction_log_dir="${log_root}/${server}_${client}"
  local results_json="${direction_log_dir}/results.json"
  local run_output
  local status
  local testcase
  local testcase_log_dir

  cleanup_runner_state
  rm -rf "${direction_log_dir}"

  echo "== official interop: server=${server} client=${client} testcases=${interop_testcases} =="
  set +e
  run_output="$(
    cd "${runner_dir}"
    python3 run.py \
      --server "${server}" \
      --client "${client}" \
      --test "${interop_testcases}" \
      --log-dir "${direction_log_dir}" \
      --json "${results_json}" \
      --debug
  2>&1
  )"
  status=$?
  set -e

  printf '%s\n' "${run_output}"

  if [ ! -f "${results_json}" ]; then
    echo "official runner results file missing: ${results_json}" >&2
    if [ "${status}" -ne 0 ]; then
      return "${status}"
    fi
    return 1
  fi

  python3 - "${results_json}" "${server}" "${client}" "${interop_testcases}" <<'PY'
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
server = sys.argv[2]
client = sys.argv[3]
requested_tests = [test for test in sys.argv[4].split(",") if test]

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

testcase_results = {
    entry.get("name"): entry.get("result")
    for entry in results[0]
}
measurement_results = {
    entry.get("name"): entry.get("result")
    for entry in (measurements[0] if measurements else [])
}

missing = [
    test for test in requested_tests
    if test not in testcase_results and test not in measurement_results
]
if missing:
    raise SystemExit(
        f"official runner results missing requested testcase or measurement results: {missing!r}"
    )

failed = []
for test in requested_tests:
    if test in testcase_results:
        result = testcase_results.get(test)
    elif test in measurement_results:
        result = measurement_results.get(test)
    else:
        result = None
    if result != "succeeded":
        failed.append(f"{test}={result!r}")

if failed:
    raise SystemExit(
        "requested testcase did not succeed for "
        f"{server}/{client}: {', '.join(failed)}"
    )
PY

  if [ "${status}" -ne 0 ]; then
    return "${status}"
  fi

  for testcase in ${interop_testcases//,/ }; do
    testcase_log_dir="${direction_log_dir}/${server}_${client}/${testcase}"
    if [ ! -d "${testcase_log_dir}" ]; then
      echo "official runner did not produce testcase logs for ${server}/${client}/${testcase}: ${testcase_log_dir}" >&2
      return 1
    fi
  done

  cleanup_runner_state
}

cleanup_runner_state
docker network ls --format '{{.Name}}' |
  grep -E -- "${runner_network_pattern}" |
  xargs -r docker network rm >/dev/null 2>&1 || true

run_direction coquic quic-go
run_direction quic-go coquic

echo "Pinned official interop runner cases passed."
