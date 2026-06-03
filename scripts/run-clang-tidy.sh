#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

if [ -z "${COQUIC_CLANG_TIDY_IN_NIX:-}" ] &&
    { [ -z "${GTEST_INCLUDE_DIR:-}" ] ||
      [ -z "${SPDLOG_INCLUDE_DIR:-}" ] ||
      [ -z "${FMT_INCLUDE_DIR:-}" ] ||
      [ -z "${LIBURING_INCLUDE_DIR:-}" ]; }; then
    command -v nix >/dev/null || {
        echo "clang-tidy requires nix develop or the coquic build environment" >&2
        exit 1
    }
    cd "${repo_root}"
    exec nix develop .#lint -c env COQUIC_CLANG_TIDY_IN_NIX=1 bash "${BASH_SOURCE[0]}" "$@"
fi

cd "${repo_root}"

mode="${COQUIC_CLANG_TIDY_MODE:-diff}"
if [ "$#" -gt 0 ]; then
    case "$1" in
        --diff)
            mode="diff"
            shift
            ;;
        --full)
            mode="full"
            shift
            ;;
    esac
fi

case "${mode}" in
    diff | full) ;;
    *)
        echo "unsupported COQUIC_CLANG_TIDY_MODE=${mode}; expected diff or full" >&2
        exit 2
        ;;
esac

source_pathspecs=(
    '*.c'
    '*.cc'
    '*.cpp'
    '*.cxx'
    '*.h'
    '*.hh'
    '*.hpp'
    '*.hxx'
)
if [ "${mode}" = "full" ] && [ "$#" -eq 0 ]; then
    mapfile -d '' requested_files < <(
        git ls-files -z -- "${source_pathspecs[@]}"
    )
else
    requested_files=("$@")
fi

run_diff_command() {
    if [ -n "${COQUIC_CLANG_TIDY_DIFF_BASE:-}" ] ||
        [ -n "${COQUIC_CLANG_TIDY_DIFF_HEAD:-}" ]; then
        local base="${COQUIC_CLANG_TIDY_DIFF_BASE:-}"
        local head="${COQUIC_CLANG_TIDY_DIFF_HEAD:-HEAD}"

        if [ -z "${base}" ]; then
            echo "COQUIC_CLANG_TIDY_DIFF_BASE is required when COQUIC_CLANG_TIDY_DIFF_HEAD is set" >&2
            exit 2
        fi

        git diff --unified=0 --no-ext-diff "${base}" "${head}" -- "$@"
        return
    fi

    if git diff --cached --quiet -- "$@"; then
        git diff --unified=0 --no-ext-diff -- "$@"
    else
        git diff --cached --unified=0 --no-ext-diff -- "$@"
    fi
}

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/coquic-clang-tidy.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

diff_patch="${tmp_dir}/diff.patch"
lintable_files_nul="${tmp_dir}/lintable-files.nul"
line_filter_json="${tmp_dir}/line-filter.json"

if [ "${mode}" = "diff" ]; then
    run_diff_command "${requested_files[@]}" > "${diff_patch}"
    has_source_changes="$(
        python3 - "${diff_patch}" <<'PY'
import pathlib
import sys

diff_path = pathlib.Path(sys.argv[1])
suffixes = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
current_file = None

for raw_line in diff_path.read_text().splitlines():
    line = raw_line.rstrip("\n")
    if line.startswith("+++ "):
        current_file = line[4:].split("\t", 1)[0]
        if current_file.startswith("a/") or current_file.startswith("b/"):
            current_file = current_file[2:]
        continue

    if current_file is None or current_file == "/dev/null":
        continue

    if line.startswith("@@ ") and pathlib.PurePosixPath(current_file).suffix.lower() in suffixes:
        print("yes")
        raise SystemExit(0)
PY
    )"
    if [ -z "${has_source_changes}" ]; then
        exit 0
    fi
fi

"${repo_root}/scripts/refresh-compile-commands.sh"

write_lintable_files() {
    python3 - "${repo_root}" "${repo_root}/compile_commands.json" "$@" <<'PY'
import json
import pathlib
import sys

repo_root = pathlib.Path(sys.argv[1]).resolve()
compile_commands_path = pathlib.Path(sys.argv[2])
requested_files = sys.argv[3:]
compile_commands = json.loads(compile_commands_path.read_text())
files_in_database = {
    str(pathlib.Path(entry["file"]).resolve()) for entry in compile_commands
}
header_suffixes = {".h", ".hh", ".hpp", ".hxx"}
source_suffixes = {".c", ".cc", ".cpp", ".cxx"}

for requested_file in requested_files:
    path = pathlib.Path(requested_file)
    suffix = path.suffix.lower()
    if suffix not in header_suffixes and suffix not in source_suffixes:
        continue

    absolute_path = (repo_root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        output_path = absolute_path.relative_to(repo_root).as_posix()
    except ValueError:
        output_path = requested_file

    if path.suffix.lower() in header_suffixes:
        sys.stdout.buffer.write(output_path.encode() + b"\0")
        continue

    if str(absolute_path) in files_in_database:
        sys.stdout.buffer.write(output_path.encode() + b"\0")
PY
}

write_diff_lint_input() {
    python3 - "${repo_root}" "${repo_root}/compile_commands.json" "${line_filter_json}" "${diff_patch}" "$@" <<'PY'
import json
import pathlib
import re
import sys

repo_root = pathlib.Path(sys.argv[1]).resolve()
compile_commands_path = pathlib.Path(sys.argv[2])
line_filter_path = pathlib.Path(sys.argv[3])
diff_path = pathlib.Path(sys.argv[4])
requested_files = sys.argv[5:]

compile_commands = json.loads(compile_commands_path.read_text())
files_in_database = {
    str(pathlib.Path(entry["file"]).resolve()) for entry in compile_commands
}
header_suffixes = {".h", ".hh", ".hpp", ".hxx"}
source_suffixes = {".c", ".cc", ".cpp", ".cxx"}
hunk_pattern = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def normalize_repo_path(path: str) -> str | None:
    if path == "/dev/null":
        return None
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    normalized = pathlib.PurePosixPath(path).as_posix()
    if normalized.startswith("../") or normalized == "..":
        return None
    return normalized


def is_lintable(relative_path: str) -> bool:
    path = pathlib.Path(relative_path)
    suffix = path.suffix.lower()
    if suffix in header_suffixes:
        return True
    if suffix not in source_suffixes:
        return False
    return str((repo_root / path).resolve()) in files_in_database


requested = set()
for requested_file in requested_files:
    path = pathlib.Path(requested_file)
    absolute_path = (repo_root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        requested.add(absolute_path.relative_to(repo_root).as_posix())
    except ValueError:
        continue

line_ranges_by_file: dict[str, list[list[int]]] = {}
current_file: str | None = None

for raw_line in diff_path.read_text().splitlines():
    line = raw_line.rstrip("\n")
    if line.startswith("+++ "):
        current_file = normalize_repo_path(line[4:].split("\t", 1)[0])
        continue

    if current_file is None:
        continue

    match = hunk_pattern.search(line)
    if match is None:
        continue

    start = int(match.group(1))
    count = int(match.group(2) or "1")
    if count == 0:
        continue

    if requested and current_file not in requested:
        continue
    if not is_lintable(current_file):
        continue

    line_ranges_by_file.setdefault(current_file, []).append([start, start + count - 1])

line_filter = [
    {"name": path, "lines": ranges}
    for path, ranges in sorted(line_ranges_by_file.items())
]
line_filter_path.write_text(json.dumps(line_filter, separators=(",", ":")))

for path in sorted(line_ranges_by_file):
    sys.stdout.buffer.write(path.encode() + b"\0")
PY
}

if [ "${mode}" = "diff" ]; then
    : > "${line_filter_json}"
    write_diff_lint_input "${requested_files[@]}" > "${lintable_files_nul}"
else
    write_lintable_files "${requested_files[@]}" > "${lintable_files_nul}"
fi

mapfile -d '' lintable_files < "${lintable_files_nul}"

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
export COQUIC_CLANG_TIDY_LINE_FILTER=""
if [ "${mode}" = "diff" ]; then
    COQUIC_CLANG_TIDY_LINE_FILTER="$(cat "${line_filter_json}")"
    export COQUIC_CLANG_TIDY_LINE_FILTER
fi

# shellcheck disable=SC2016
printf '%s\0' "${lintable_files[@]}" | xargs -0 -P "${job_count}" -n 1 bash -c '
    args=(
        clang-tidy
        --quiet \
        --config-file="${COQUIC_CLANG_TIDY_REPO_ROOT}/.clang-tidy" \
        -p "${COQUIC_CLANG_TIDY_REPO_ROOT}" \
    )
    if [ -n "${COQUIC_CLANG_TIDY_LINE_FILTER}" ]; then
        args+=("-line-filter=${COQUIC_CLANG_TIDY_LINE_FILTER}")
    fi
    args+=("$1")
    "${args[@]}"
' _
