#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

script=tests/nix/official_interop_runner_test.sh

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
]

missing = [fragment for fragment in required_fragments if fragment not in script]
if missing:
    raise SystemExit(f"official interop wrapper missing fragments: {missing!r}")
PY
