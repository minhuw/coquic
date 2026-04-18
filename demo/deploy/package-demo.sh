#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source_dir="${repo_root}/demo/site"
output_dir="${1:-${repo_root}/zig-out/demo-site}"

if [[ ! -d "${source_dir}" ]]; then
  echo "missing demo/site source directory: ${source_dir}" >&2
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
