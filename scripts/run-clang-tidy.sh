#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -eq 0 ]; then
    exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cd "${repo_root}"

tls_backend="${COQUIC_TLS_BACKEND:-quictls}"
tls_include_dir=""
clang_extra_args=()

case "${tls_backend}" in
    quictls)
        tls_include_dir="${QUICTLS_INCLUDE_DIR:-${OPENSSL_INCLUDE_DIR:-}}"
        ;;
    boringssl)
        tls_include_dir="${BORINGSSL_INCLUDE_DIR:-}"
        ;;
esac

if [ -n "${tls_include_dir}" ]; then
    clang_extra_args+=("-I${tls_include_dir}")
fi

for file in "$@"; do
    clang-tidy \
        --quiet \
        --config-file="${repo_root}/.clang-tidy" \
        "${file}" \
        -- \
        -xc++ \
        -std=c++20 \
        -I"${repo_root}" \
        "${clang_extra_args[@]}"
done
