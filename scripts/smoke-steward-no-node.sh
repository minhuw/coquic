#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/coquic-steward-no-node.XXXXXX")"
trap 'rm -rf "${temporary_root}"' EXIT

uv venv --python python3 "${temporary_root}/venv" >/dev/null
uv pip install --python "${temporary_root}/venv/bin/python" --quiet --editable "${repo_root}/steward"

mkdir -p "${temporary_root}/bin" "${temporary_root}/home"
ln -s "${temporary_root}/venv/bin/python" "${temporary_root}/bin/python"
ln -s "${temporary_root}/venv/bin/coquic-steward" "${temporary_root}/bin/coquic-steward"

if env PATH="${temporary_root}/bin" command -v node >/dev/null 2>&1 ||
  env PATH="${temporary_root}/bin" command -v npm >/dev/null 2>&1; then
  echo "Node.js or npm unexpectedly available in the smoke PATH" >&2
  exit 1
fi

env -i HOME="${temporary_root}/home" PATH="${temporary_root}/bin" \
  "${temporary_root}/venv/bin/python" -c "import coquic_steward"
env -i HOME="${temporary_root}/home" PATH="${temporary_root}/bin" \
  "${temporary_root}/venv/bin/coquic-steward" --help >/dev/null
echo "Steward no-Node smoke passed"
