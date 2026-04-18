#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source_dir="$(realpath -m "${repo_root}/demo/site")"
requested_output_dir="${1:-${repo_root}/zig-out/demo-site}"
output_dir="$(realpath -m "${requested_output_dir}")"

if [[ ! -d "${source_dir}" ]]; then
  echo "missing demo/site source directory: ${source_dir}" >&2
  exit 1
fi

if [[ "${output_dir}" == "${source_dir}" || "${output_dir}" == "${source_dir}/"* ]]; then
  echo "output directory must not be demo/site or inside it: ${output_dir}" >&2
  exit 1
fi

rm -rf "${output_dir}"
install -d -m 755 "${output_dir}"
cp -R "${source_dir}/." "${output_dir}/"

if [[ ! -f "${output_dir}/index.html" ]]; then
  echo "packaged demo site is missing index.html" >&2
  exit 1
fi

printf '%s\n' "${output_dir}"
