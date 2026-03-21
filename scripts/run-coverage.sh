#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <test-binary>" >&2
    exit 1
fi

if [ -z "${LLVM_COV:-}" ] || [ -z "${LLVM_PROFDATA:-}" ]; then
    echo "LLVM_COV and LLVM_PROFDATA must be set; run inside nix develop" >&2
    exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
test_binary="$1"
coverage_dir="${repo_root}/coverage"
profile_raw_pattern="${coverage_dir}/coquic-%p.profraw"
profile_data="${coverage_dir}/coquic.profdata"
html_dir="${coverage_dir}/html"
lcov_report="${coverage_dir}/lcov.info"
ignore_pattern='(^/nix/store/|/tests/|/\.zig-cache/)'

rm -rf "${coverage_dir}"
mkdir -p "${html_dir}"

LLVM_PROFILE_FILE="${profile_raw_pattern}" "${test_binary}"

shopt -s nullglob
profile_raws=( "${coverage_dir}"/coquic-*.profraw )
shopt -u nullglob

if [ "${#profile_raws[@]}" -eq 0 ]; then
    echo "no LLVM raw profiles generated" >&2
    exit 1
fi

"${LLVM_PROFDATA}" merge \
    -sparse \
    "${profile_raws[@]}" \
    -o "${profile_data}"

"${LLVM_COV}" export \
    --format=lcov \
    --instr-profile="${profile_data}" \
    --ignore-filename-regex="${ignore_pattern}" \
    "${test_binary}" > "${lcov_report}"

"${LLVM_COV}" show \
    "${test_binary}" \
    --instr-profile="${profile_data}" \
    --format=html \
    --output-dir="${html_dir}" \
    --ignore-filename-regex="${ignore_pattern}"
