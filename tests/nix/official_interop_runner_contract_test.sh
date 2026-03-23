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
    '--json "${results_json}"',
    '${direction_log_dir}/${server}_${client}/${testcase}',
    'official runner results file missing',
    'requested testcase did not succeed',
    'measurements = data.get("measurements", [])',
    'measurement_results = {',
    'if test in testcase_results:',
    'elif test in measurement_results:',
    'readonly coquic_image="${INTEROP_COQUIC_IMAGE:-coquic-interop:quictls-musl}"',
    'readonly coquic_package="${INTEROP_COQUIC_PACKAGE:-interop-image-quictls-musl}"',
    'nix --option eval-cache false build ".#${coquic_package}"',
    'docker load -i "$(nix path-info ".#${coquic_package}")" >/dev/null',
]

missing = [fragment for fragment in required_fragments if fragment not in script]
if missing:
    raise SystemExit(f"official interop wrapper missing fragments: {missing!r}")

forbidden_fragments = [
    'if [[ ",${interop_testcases}," == *",chacha20,"* ]]; then',
    'coquic-interop:boringssl-musl',
    'interop-image-boringssl-musl',
]

present_forbidden = [fragment for fragment in forbidden_fragments if fragment in script]
if present_forbidden:
    raise SystemExit(
        f"official interop wrapper still contains deprecated fragments: {present_forbidden!r}"
    )
PY
