#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -eq 0 ]; then
    exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cd "${repo_root}"

tls_backend="${COQUIC_TLS_BACKEND:-quictls}"

include_dir_for_backend() {
    case "$1" in
        quictls)
            printf '%s\n' "${QUICTLS_INCLUDE_DIR:-${OPENSSL_INCLUDE_DIR:-}}"
            ;;
        boringssl)
            printf '%s\n' "${BORINGSSL_INCLUDE_DIR:-}"
            ;;
        *)
            printf '\n'
            ;;
    esac
}

backend_for_file() {
    case "$1" in
        *packet_crypto_quictls.cpp|*tls_adapter_quictls.cpp)
            printf '%s\n' "quictls"
            ;;
        *packet_crypto_boringssl.cpp|*tls_adapter_boringssl.cpp)
            printf '%s\n' "boringssl"
            ;;
        *)
            printf '%s\n' "${tls_backend}"
            ;;
    esac
}

filtered_nix_compile_args=()
if [ -n "${NIX_CFLAGS_COMPILE:-}" ]; then
    read -r -a raw_nix_compile_args <<< "${NIX_CFLAGS_COMPILE}"
    index=0
    while [ "${index}" -lt "${#raw_nix_compile_args[@]}" ]; do
        arg="${raw_nix_compile_args[${index}]}"
        if [ "${arg}" = "-isystem" ] && [ "$((index + 1))" -lt "${#raw_nix_compile_args[@]}" ]; then
            next_arg="${raw_nix_compile_args[$((index + 1))]}"
            if [ "${next_arg}" = "${QUICTLS_INCLUDE_DIR:-}" ] || \
                [ "${next_arg}" = "${BORINGSSL_INCLUDE_DIR:-}" ]; then
                index=$((index + 2))
                continue
            fi
            filtered_nix_compile_args+=("${arg}" "${next_arg}")
            index=$((index + 2))
            continue
        fi

        filtered_nix_compile_args+=("${arg}")
        index=$((index + 1))
    done
fi

for file in "$@"; do
    file_backend="$(backend_for_file "${file}")"
    tls_include_dir="$(include_dir_for_backend "${file_backend}")"
    clang_extra_args=()
    if [ "${#filtered_nix_compile_args[@]}" -gt 0 ]; then
        clang_extra_args+=("${filtered_nix_compile_args[@]}")
    fi
    if [ -n "${tls_include_dir}" ]; then
        clang_extra_args+=("-I${tls_include_dir}")
    fi

    env NIX_CFLAGS_COMPILE= clang-tidy \
        --quiet \
        --config-file="${repo_root}/.clang-tidy" \
        "${file}" \
        -- \
        -xc++ \
        -std=c++20 \
        -I"${repo_root}" \
        "${clang_extra_args[@]}"
done
