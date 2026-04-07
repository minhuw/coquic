#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
compile_commands="${repo_root}/compile_commands.json"
lock_file="${repo_root}/.zig-cache/compile-commands.lock"

mkdir -p "${repo_root}/.zig-cache"
exec 9>"${lock_file}"
flock 9

inputs=(
    "${repo_root}/build.zig"
    "${repo_root}/flake.nix"
    "${repo_root}/flake.lock"
    "${repo_root}/.clang-tidy"
    "${repo_root}/scripts/compile-commands-from-verbose-cc.py"
    "${repo_root}/scripts/refresh-compile-commands.sh"
    "${repo_root}/scripts/run-clang-tidy.sh"
)

needs_refresh=0
if [ ! -f "${compile_commands}" ]; then
    needs_refresh=1
else
    for input in "${inputs[@]}"; do
        if [ "${input}" -nt "${compile_commands}" ]; then
            needs_refresh=1
            break
        fi
    done
fi

if [ "${needs_refresh}" -eq 0 ]; then
    exit 0
fi

cache_root="${repo_root}/.zig-cache/compile-commands"
mkdir -p "${cache_root}"

tmp_output="$(mktemp "${repo_root}/compile_commands.json.tmp.XXXXXX")"
trap 'rm -f "${tmp_output}"' EXIT

run_compdb_for_backend() {
    local backend="$1"
    local backend_cache="${cache_root}/${backend}"
    local local_cache="${backend_cache}/local"
    local global_cache="${backend_cache}/global"

    rm -rf "${backend_cache}"
    mkdir -p "${local_cache}" "${global_cache}"

    zig build compdb \
        "-Dtls_backend=${backend}" \
        --summary none \
        --verbose-cc \
        --cache-dir "${local_cache}" \
        --global-cache-dir "${global_cache}"
}

available_backends=()
if [ -n "${BORINGSSL_INCLUDE_DIR:-}" ] && [ -n "${BORINGSSL_LIB_DIR:-}" ]; then
    available_backends+=("boringssl")
fi
if [ -n "${QUICTLS_INCLUDE_DIR:-}" ] && [ -n "${QUICTLS_LIB_DIR:-}" ]; then
    available_backends+=("quictls")
fi
if [ "${#available_backends[@]}" -eq 0 ]; then
    available_backends+=("${COQUIC_TLS_BACKEND:-quictls}")
fi

current_backend="${COQUIC_TLS_BACKEND:-quictls}"
ordered_backends=()
for backend in "${available_backends[@]}"; do
    if [ "${backend}" != "${current_backend}" ]; then
        ordered_backends+=("${backend}")
    fi
done
for backend in "${available_backends[@]}"; do
    if [ "${backend}" = "${current_backend}" ]; then
        ordered_backends+=("${backend}")
        break
    fi
done
if [ "${#ordered_backends[@]}" -eq 0 ]; then
    ordered_backends=("${available_backends[@]}")
fi

cd "${repo_root}"
{
    for backend in "${ordered_backends[@]}"; do
        if [ "${backend}" = "${current_backend}" ]; then
            run_compdb_for_backend "${backend}"
        else
            run_compdb_for_backend "${backend}" || true
        fi
    done
} 2>&1 | python3 "${repo_root}/scripts/compile-commands-from-verbose-cc.py" "${repo_root}" > "${tmp_output}"

mv "${tmp_output}" "${compile_commands}"
