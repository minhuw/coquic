#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
compile_commands="${repo_root}/compile_commands.json"

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
local_cache="${cache_root}/local"
global_cache="${cache_root}/global"

rm -rf "${cache_root}"
mkdir -p "${local_cache}" "${global_cache}"

tmp_output="$(mktemp "${repo_root}/compile_commands.json.tmp.XXXXXX")"
trap 'rm -f "${tmp_output}"' EXIT

cd "${repo_root}"
zig build compdb \
    --summary none \
    --verbose-cc \
    --cache-dir "${local_cache}" \
    --global-cache-dir "${global_cache}" \
    2>&1 | python3 "${repo_root}/scripts/compile-commands-from-verbose-cc.py" "${repo_root}" > "${tmp_output}"

mv "${tmp_output}" "${compile_commands}"
