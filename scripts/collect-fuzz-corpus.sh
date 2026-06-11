#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: scripts/collect-fuzz-corpus.sh [--output DIR] [--limit N] -- <command> [args...]

Run a normal CoQUIC workload with runtime fuzz-corpus capture enabled. The
workload writes raw candidate inputs under target-specific subdirectories of
DIR, defaulting to .fuzz/captured/<timestamp>-<pid>/.
EOF
}

output_dir=""
limit="${COQUIC_FUZZ_CORPUS_CAPTURE_LIMIT:-5000}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      if [ "$#" -lt 2 ]; then
        printf 'error: --output requires a directory\n' >&2
        exit 2
      fi
      output_dir="$2"
      shift 2
      ;;
    --limit)
      if [ "$#" -lt 2 ]; then
        printf 'error: --limit requires a number\n' >&2
        exit 2
      fi
      limit="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'error: expected -- before command, got: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ "$#" -eq 0 ]; then
  usage
  exit 2
fi
if [[ ! "$limit" =~ ^[0-9]+$ ]]; then
  printf 'error: --limit must be a non-negative integer\n' >&2
  exit 2
fi

if [ -z "$output_dir" ]; then
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  output_dir="$repo_root/.fuzz/captured/${timestamp}-$$"
elif [[ "$output_dir" != /* ]]; then
  output_dir="$repo_root/$output_dir"
fi

mkdir -p "$output_dir"

printf 'capturing fuzz corpus candidates under %s\n' "$output_dir"
COQUIC_FUZZ_CORPUS_CAPTURE_DIR="$output_dir" \
  COQUIC_FUZZ_CORPUS_CAPTURE_LIMIT="$limit" \
  "$@"

find "$output_dir" -mindepth 1 -maxdepth 1 -type d -print | sort | while read -r target_dir; do
  count=$(find "$target_dir" -maxdepth 1 -type f | wc -l)
  bytes=$(find "$target_dir" -maxdepth 1 -type f -printf '%s\n' | awk '{s += $1} END {print s + 0}')
  printf '%s: %s files, %s bytes\n' "$(basename "$target_dir")" "$count" "$bytes"
done
