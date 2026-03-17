#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -eq 0 ]; then
    exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cd "${repo_root}"

for file in "$@"; do
    clang-tidy \
        --quiet \
        --config-file="${repo_root}/.clang-tidy" \
        "${file}" \
        -- \
        -xc++ \
        -std=c++20 \
        -I"${repo_root}"
done
