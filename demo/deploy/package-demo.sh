#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
requested_output_dir="${1:-${repo_root}/zig-out/demo-site}"
requested_source_dir="${2:-${repo_root}/zig-out/share/wasm-quic}"
source_dir="$(realpath -m -- "${requested_source_dir}")"
output_dir="$(realpath -m -- "${requested_output_dir}")"

if [[ ! -d "${source_dir}" ]]; then
  echo "missing wasm demo build directory: ${source_dir}" >&2
  exit 1
fi

is_same_or_descendant() {
  local path="$1"
  local root="$2"
  [[ "${path}" == "${root}" || "${path}" == "${root}/"* ]]
}

if is_same_or_descendant "${output_dir}" "${source_dir}" || is_same_or_descendant "${source_dir}" "${output_dir}"; then
  echo "output directory must not overlap wasm demo source ancestry: ${output_dir}" >&2
  exit 1
fi

for required_file in index.html workbench.html demo-theme.css quic-demo.js perf-comparison.html perf-comparison.js interop-results.html interop-results.js coquic-wasm-quic.wasm; do
  if [[ ! -f "${source_dir}/${required_file}" ]]; then
    echo "wasm demo source is missing ${required_file}: ${source_dir}" >&2
    exit 1
  fi
done

rm -rf -- "${output_dir}"
install -d -m 755 -- "${output_dir}"
cp -R -- "${source_dir}/." "${output_dir}/"

printf '%s\n' "${output_dir}"
