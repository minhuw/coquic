#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -eq 0 ]; then
    exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

"${repo_root}/scripts/refresh-compile-commands.sh"

job_count="${COQUIC_CLANG_TIDY_JOBS:-}"
if [ -z "${job_count}" ] && command -v getconf >/dev/null 2>&1; then
    job_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
fi
if [ -z "${job_count}" ] && command -v nproc >/dev/null 2>&1; then
    job_count="$(nproc 2>/dev/null || true)"
fi
if ! [[ "${job_count}" =~ ^[1-9][0-9]*$ ]]; then
    job_count=4
fi

export COQUIC_CLANG_TIDY_REPO_ROOT="${repo_root}"

printf '%s\0' "$@" | xargs -0 -P "${job_count}" -n 1 bash -c '
    clang-tidy \
        --quiet \
        --config-file="${COQUIC_CLANG_TIDY_REPO_ROOT}/.clang-tidy" \
        -p "${COQUIC_CLANG_TIDY_REPO_ROOT}" \
        "$1"
' _
