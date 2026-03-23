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
    'readonly quicgo_image="${INTEROP_QUICGO_IMAGE:-martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424}"',
    'readonly interop_wait_for_server="${INTEROP_WAIT_FOR_SERVER:-193.167.100.100:443}"',
    'echo "Using official quic-go image: ${quicgo_image}"',
    'echo "Using warmup target: ${interop_wait_for_server}"',
    'docker pull "${quicgo_image}" >/dev/null',
    '"${runner_dir}/interop.py" "${interop_wait_for_server}"',
    'text.replace("WAITFORSERVER=server:443 ",',
    'f"WAITFORSERVER={interop_wait_for_server} ")',
    'run_direction coquic quic-go',
    'run_direction quic-go coquic',
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
