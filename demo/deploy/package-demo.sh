#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
requested_output_dir="${1:-${repo_root}/zig-out/demo-site}"
requested_source_dir="${2:-${repo_root}/zig-out/share/wasm-quic}"
requested_next_dir="${3:-${repo_root}/demo/next/out}"
source_dir="$(realpath -m -- "${requested_source_dir}")"
output_dir="$(realpath -m -- "${requested_output_dir}")"
next_dir="$(realpath -m -- "${requested_next_dir}")"

if [[ ! -d "${source_dir}" ]]; then
  echo "missing wasm demo build directory: ${source_dir}" >&2
  exit 1
fi

is_same_or_descendant() {
  local path="$1"
  local root="$2"
  [[ "${path}" == "${root}" || "${path}" == "${root}/"* ]]
}

if is_same_or_descendant "${output_dir}" "${source_dir}" || is_same_or_descendant "${source_dir}" "${output_dir}" ||
  is_same_or_descendant "${output_dir}" "${next_dir}" || is_same_or_descendant "${next_dir}" "${output_dir}"; then
  echo "output directory must not overlap demo source ancestry: ${output_dir}" >&2
  exit 1
fi

for required_file in demo-theme.css coquic-logo.svg quic-demo.js perf-comparison.js interop-results.js coverage-results.js coquic-wasm-quic.wasm; do
  if [[ ! -f "${source_dir}/${required_file}" ]]; then
    echo "wasm demo source is missing ${required_file}: ${source_dir}" >&2
    exit 1
  fi
done

if [[ -d "${next_dir}" ]]; then
  if [[ ! -f "${next_dir}/index.html" ]]; then
    echo "next demo export is missing index.html: ${next_dir}" >&2
    exit 1
  fi
  for required_next_file in workbench.html perf-comparison.html interop-results.html coverage-results.html; do
    if [[ ! -f "${next_dir}/${required_next_file}" ]]; then
      echo "next demo export is missing ${required_next_file}: ${next_dir}" >&2
      exit 1
    fi
  done
fi

rm -rf -- "${output_dir}"
install -d -m 755 -- "${output_dir}"
cp -R -- "${source_dir}/." "${output_dir}/"
if [[ -d "${next_dir}" ]]; then
  cp -R -- "${next_dir}/_next" "${output_dir}/"
  find "${next_dir}" -maxdepth 1 -type f \( -name '*.html' -o -name '*.txt' \) -exec cp -- {} "${output_dir}/" \;
fi

printf '%s\n' "${output_dir}"
