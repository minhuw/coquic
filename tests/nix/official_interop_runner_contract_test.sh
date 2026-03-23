#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

script=tests/nix/interop_runner_test.sh

if [ ! -f "${script}" ]; then
  echo "missing script: ${script}" >&2
  exit 1
fi

python3 - "${script}" <<'PY'
import pathlib
import sys

script = pathlib.Path(sys.argv[1]).read_text()

required_fragments = [
    'readonly interop_peer_impl="${INTEROP_PEER_IMPL:-}"',
    'readonly interop_peer_image="${INTEROP_PEER_IMAGE:-}"',
    'if [ -z "${interop_peer_impl}" ]; then',
    'if [ -z "${interop_peer_image}" ]; then',
    '"${runner_dir}/implementations_quic.json" "${coquic_image}" "${interop_peer_impl}" "${interop_peer_image}" "${repo_url}"',
    'if peer_impl not in data:',
    'data[peer_impl]["image"] = peer_image',
    'echo "Using official ${interop_peer_impl} image: ${interop_peer_image}"',
    'docker pull "${interop_peer_image}" >/dev/null',
    'run_direction coquic "${interop_peer_impl}"',
    'run_direction "${interop_peer_impl}" coquic',
    '--json "${results_json}"',
    'rm -rf "${direction_log_dir}"',
    '${direction_log_dir}/${server}_${client}/${testcase}',
    'official runner results file missing',
    'grep -E -- "${runner_network_pattern}"',
    'requested testcase did not succeed',
    'measurements = data.get("measurements", [])',
    'if len(measurements) not in (0, 1):',
    'expected zero or one measurement matrix cell in official runner results',
    'measurement_results = {',
    'if test in testcase_results:',
    'elif test in measurement_results:',
    'official runner results missing requested testcase or measurement results',
    'readonly coquic_image="${INTEROP_COQUIC_IMAGE:-coquic-interop:quictls-musl}"',
    'readonly coquic_package="${INTEROP_COQUIC_PACKAGE:-interop-image-quictls-musl}"',
    'nix --option eval-cache false build ".#${coquic_package}"',
    'docker load -i "$(nix path-info ".#${coquic_package}")" >/dev/null',
]

missing = [fragment for fragment in required_fragments if fragment not in script]
if missing:
    raise SystemExit(f"official interop wrapper missing fragments: {missing!r}")

forbidden_fragments = [
    'readonly interop_wait_for_server="${INTEROP_WAIT_FOR_SERVER:-193.167.100.100:443}"',
    'echo "Using warmup target: ${interop_wait_for_server}"',
    '"${runner_dir}/interop.py" "${interop_wait_for_server}"',
    'text.replace("WAITFORSERVER=server:443 ",',
    'f"WAITFORSERVER={interop_wait_for_server} ")',
    'readonly quicgo_image=',
    'echo "Using official quic-go image:',
    'docker pull "${quicgo_image}" >/dev/null',
    'run_direction coquic quic-go',
    'run_direction quic-go coquic',
    'if "quic-go" in data:',
    'data["quic-go"]["image"] = quicgo_image',
    'mkdir -p "${direction_log_dir}"',
    'if [[ ",${interop_testcases}," == *",chacha20,"* ]]; then',
    'coquic-interop:boringssl-musl',
    'interop-image-boringssl-musl',
    'tests = data.get("tests", {})',
    'rg "${runner_network_pattern}"',
    'cat > "${runner_dir}/sim-run.sh" <<\'EOF\'',
    'normalize_simulator_interfaces() {',
    'left_if="$(interface_for_ipv4 193.167.0.2 || true)"',
    'right_if="$(interface_for_ipv4 193.167.100.2 || true)"',
    'nameif tmp0 "${right_mac}"',
    'nameif eth0 "${left_mac}"',
    'nameif eth1 "${right_mac}"',
    './sim-run.sh:/ns3/run.sh:ro',
    'if "interface_name:" not in line',
]

present_forbidden = [fragment for fragment in forbidden_fragments if fragment in script]
if present_forbidden:
    raise SystemExit(
        f"official interop wrapper still contains deprecated fragments: {present_forbidden!r}"
    )
PY
