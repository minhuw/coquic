#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
requested_output_dir="${1:-${repo_root}/zig-out/demo-site}"
requested_next_dir="${2:-${repo_root}/demo/next/out}"
requested_wasm_module="${3:-${repo_root}/zig-out/share/wasm-quic/coquic-wasm-quic.wasm}"
output_dir="$(realpath -m -- "${requested_output_dir}")"
next_dir="$(realpath -m -- "${requested_next_dir}")"
wasm_module="$(realpath -m -- "${requested_wasm_module}")"

if [[ ! -d "${next_dir}" ]]; then
  echo "missing Next.js demo export directory: ${next_dir}" >&2
  exit 1
fi

if [[ ! -f "${wasm_module}" ]]; then
  echo "missing wasm demo module: ${wasm_module}" >&2
  exit 1
fi

is_same_or_descendant() {
  local path="$1"
  local root="$2"
  [[ "${path}" == "${root}" || "${path}" == "${root}/"* ]]
}

if is_same_or_descendant "${output_dir}" "${next_dir}" || is_same_or_descendant "${next_dir}" "${output_dir}"; then
  echo "output directory must not overlap demo source ancestry: ${output_dir}" >&2
  exit 1
fi

for required_next_file in index.html docs.html workbench.html perf-comparison.html interop-results.html coverage-results.html performance.html interop.html coverage.html coquic-logo.svg quic-demo.js perf-comparison.js interop-results.js coverage-results.js; do
  if [[ ! -f "${next_dir}/${required_next_file}" ]]; then
    echo "next demo export is missing ${required_next_file}: ${next_dir}" >&2
    exit 1
  fi
done

rm -rf -- "${output_dir}"
install -d -m 755 -- "${output_dir}"
cp -R -- "${next_dir}/." "${output_dir}/"
rm -f -- "${output_dir}/coquic-wasm-quic.wasm"
install -m 644 -- "${wasm_module}" "${output_dir}/coquic-wasm-quic.wasm"

printf '%s\n' "${output_dir}"
