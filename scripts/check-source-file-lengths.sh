#!/usr/bin/env bash
set -euo pipefail

limit="${COQUIC_SOURCE_LINE_LIMIT:-5000}"

if [[ "${1:-}" == "--limit" ]]; then
    if [[ $# -lt 2 ]]; then
        echo "usage: $0 [--limit N] [FILE...]" >&2
        exit 2
    fi
    limit="$2"
    shift 2
fi

if ! [[ "${limit}" =~ ^[0-9]+$ ]] || [[ "${limit}" -eq 0 ]]; then
    echo "source file length limit must be a positive integer" >&2
    exit 2
fi

is_cpp_source() {
    case "$1" in
        *.c | *.cc | *.cpp | *.cxx | *.h | *.hh | *.hpp | *.hxx) return 0 ;;
        *) return 1 ;;
    esac
}

is_excluded_path() {
    case "$1" in
        .git/* | .zig-cache/* | zig-out/* | .rag/* | .remote-ci/* | node_modules/* | outputs/*)
            return 0
            ;;
        docs/rfc/*) return 0 ;;
        *) return 1 ;;
    esac
}

check_file() {
    local file="$1"
    if [[ ! -f "${file}" ]] || ! is_cpp_source "${file}" || is_excluded_path "${file}"; then
        return 0
    fi

    local lines
    lines="$(wc -l < "${file}")"
    if (( lines > limit )); then
        printf '%7d %s\n' "${lines}" "${file}"
        return 1
    fi
    return 0
}

failed=0
if (( $# > 0 )); then
    for file in "$@"; do
        check_file "${file}" || failed=1
    done
else
    while IFS= read -r file; do
        check_file "${file}" || failed=1
    done < <(rg --files \
        -g '!{.git,.zig-cache,zig-out,.rag,.remote-ci,node_modules,outputs}/**' \
        -g '!docs/rfc/**')
fi

if (( failed != 0 )); then
    echo "C++ source/header files above ${limit} lines are listed above." >&2
    exit 1
fi
