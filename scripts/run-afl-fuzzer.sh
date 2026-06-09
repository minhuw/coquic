#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$#" -lt 1 ]; then
  printf 'usage: %s <target> [afl-fuzz-args...]\n' "$0" >&2
  exit 2
fi

target="$1"
shift

binary="${COQUIC_FUZZ_OUT_DIR:-$repo_root/.fuzz/bin}/$target"
input_dir="${COQUIC_FUZZ_CORPUS_DIR:-$repo_root/.fuzz/corpus}/$target"
output_dir="${COQUIC_AFL_OUTPUT_DIR:-$repo_root/.fuzz/afl/$target}"

if [ ! -x "$binary" ]; then
  "$repo_root/scripts/build-fuzzers.sh"
fi

"$repo_root/scripts/prepare-fuzz-corpus.sh" "$target"

if [ ! -d "$input_dir" ]; then
  printf 'missing seed corpus directory: %s\n' "$input_dir" >&2
  exit 1
fi

mkdir -p "$output_dir"

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="${AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES:-1}"
if [ ! -t 1 ]; then
  export AFL_NO_UI="${AFL_NO_UI:-1}"
fi

exec afl-fuzz -m none -i "$input_dir" -o "$output_dir" "$@" -- "$binary" @@
