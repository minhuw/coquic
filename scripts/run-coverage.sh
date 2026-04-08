#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <test-binary> [<test-binary> ...]" >&2
    exit 1
fi

if [ -z "${LLVM_COV:-}" ] || [ -z "${LLVM_PROFDATA:-}" ]; then
    echo "LLVM_COV and LLVM_PROFDATA must be set; run inside nix develop" >&2
    exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
coverage_dir="${repo_root}/coverage"
profile_data="${coverage_dir}/coquic.profdata"
html_dir="${coverage_dir}/html"
lcov_report="${coverage_dir}/lcov.info"
ignore_pattern='(^/nix/store/|/tests/|/\.zig-cache/)'

rm -rf "${coverage_dir}"
mkdir -p "${html_dir}"

profraws=()
index=0
for test_binary in "$@"; do
    profile_raw="${coverage_dir}/coquic-${index}.profraw"
    LLVM_PROFILE_FILE="${profile_raw}" "${test_binary}"
    profraws+=("${profile_raw}")
    index=$((index + 1))
done

"${LLVM_PROFDATA}" merge \
    -sparse \
    "${profraws[@]}" \
    -o "${profile_data}"

binary_args=()
for test_binary in "$@"; do
    binary_args+=("-object" "${test_binary}")
done

"${LLVM_COV}" export \
    --format=lcov \
    --instr-profile="${profile_data}" \
    --ignore-filename-regex="${ignore_pattern}" \
    "${binary_args[@]}" > "${lcov_report}"

"${LLVM_COV}" show \
    --instr-profile="${profile_data}" \
    --format=html \
    --output-dir="${html_dir}" \
    --ignore-filename-regex="${ignore_pattern}" \
    "${binary_args[@]}"
