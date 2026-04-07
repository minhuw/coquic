#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -eq 0 ]; then
    exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cd "${repo_root}"

"${repo_root}/scripts/refresh-compile-commands.sh"

mapfile -d '' lintable_files < <(
    python3 - "${repo_root}/compile_commands.json" "$@" <<'PY'
import json
import pathlib
import sys

compile_commands_path = pathlib.Path(sys.argv[1])
requested_files = sys.argv[2:]
compile_commands = json.loads(compile_commands_path.read_text())
files_in_database = {
    str(pathlib.Path(entry["file"]).resolve()) for entry in compile_commands
}
header_suffixes = {".h", ".hh", ".hpp", ".hxx"}

for requested_file in requested_files:
    path = pathlib.Path(requested_file)
    if path.suffix.lower() in header_suffixes:
        sys.stdout.buffer.write(requested_file.encode() + b"\0")
        continue

    if str(path.resolve()) in files_in_database:
        sys.stdout.buffer.write(requested_file.encode() + b"\0")
PY
)

if [ "${#lintable_files[@]}" -eq 0 ]; then
    exit 0
fi

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

printf '%s\0' "${lintable_files[@]}" | xargs -0 -P "${job_count}" -n 1 bash -c '
    clang-tidy \
        --quiet \
        --config-file="${COQUIC_CLANG_TIDY_REPO_ROOT}/.clang-tidy" \
        -p "${COQUIC_CLANG_TIDY_REPO_ROOT}" \
        "$1"
' _
