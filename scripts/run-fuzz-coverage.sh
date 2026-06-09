#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
coverage_root="${COQUIC_FUZZ_COVERAGE_DIR:-$repo_root/.fuzz/coverage}"
out_dir="$coverage_root/bin"
corpus_dir="$coverage_root/corpus"
generated_dir="$coverage_root/generated-corpus"
generator_profile_dir="$coverage_root/generator-profiles"
profile_dir="$coverage_root/profiles"
report_dir="$coverage_root/report"
profdata="$coverage_root/fuzz.profdata"
cxx="${COQUIC_FUZZ_COVERAGE_CXX:-clang++}"

source "$repo_root/scripts/fuzz-targets.sh"

if ! command -v "$cxx" >/dev/null 2>&1; then
  printf 'missing coverage compiler: %s\n' "$cxx" >&2
  exit 1
fi
if ! command -v llvm-profdata >/dev/null 2>&1; then
  printf 'missing llvm-profdata\n' >&2
  exit 1
fi
if ! command -v llvm-cov >/dev/null 2>&1; then
  printf 'missing llvm-cov\n' >&2
  exit 1
fi

rm -rf \
  "$out_dir" \
  "$corpus_dir" \
  "$generated_dir" \
  "$generator_profile_dir" \
  "$profile_dir" \
  "$report_dir" \
  "$profdata"
mkdir -p "$generator_profile_dir" "$profile_dir" "$report_dir"

COQUIC_AFL_CXX="$cxx" \
  COQUIC_FUZZ_COVERAGE=1 \
  COQUIC_FUZZ_OUT_DIR="$out_dir" \
  COQUIC_FUZZ_SANITIZERS="${COQUIC_FUZZ_SANITIZERS:-}" \
  "$repo_root/scripts/build-fuzzers.sh"

COQUIC_FUZZ_OUT_DIR="$out_dir" \
  COQUIC_FUZZ_CORPUS_DIR="$corpus_dir" \
  COQUIC_FUZZ_GENERATED_CORPUS_DIR="$generated_dir" \
  LLVM_PROFILE_FILE="$generator_profile_dir/generate_corpus-%p-%m.profraw" \
  "$repo_root/scripts/prepare-fuzz-corpus.sh"

replay_dir() {
  local target="$1"
  local dir="$2"
  local binary="$out_dir/$target"

  [ -d "$dir" ] || return 0
  while IFS= read -r -d '' input; do
    LLVM_PROFILE_FILE="$profile_dir/$target-%p-%m.profraw" "$binary" "$input"
  done < <(find "$dir" -type f ! -name README.txt -print0 | sort -z)
}

replay_extra_root() {
  local target="$1"
  local root="$2"
  local target_root="$root/$target"

  if [ -d "$root/default/queue" ] || compgen -G "$root/*/queue" >/dev/null; then
    target_root="$root"
  fi

  for queue in "$target_root"/*/queue; do
    replay_dir "$target" "$queue"
  done
}

for target in "${COQUIC_FUZZ_TARGETS[@]}"; do
  printf 'replaying coverage corpus for %s\n' "$target"
  replay_dir "$target" "$corpus_dir/$target"
  for root in "$@"; do
    replay_extra_root "$target" "$root"
  done
done

shopt -s nullglob
profiles=("$profile_dir"/*.profraw)
if [ "${#profiles[@]}" -eq 0 ]; then
  printf 'no coverage profiles were produced\n' >&2
  exit 1
fi

llvm-profdata merge -sparse "${profiles[@]}" -o "$profdata"

objects=("$out_dir/${COQUIC_FUZZ_TARGETS[0]}")
for target in "${COQUIC_FUZZ_TARGETS[@]:1}"; do
  objects+=("-object=$out_dir/$target")
done

sources=(
  "$repo_root/src/quic/codec/frame.cpp"
  "$repo_root/src/quic/codec/packet.cpp"
  "$repo_root/src/quic/codec/plaintext_codec.cpp"
  "$repo_root/src/quic/codec/varint.cpp"
  "$repo_root/src/quic/transport/transport_parameters.cpp"
)

llvm-cov report "${objects[@]}" \
  -instr-profile="$profdata" \
  --ignore-filename-regex='(/nix/store/|/fuzz/src/)' \
  --sources "${sources[@]}" | tee "$report_dir/summary.txt"

if [ "${COQUIC_FUZZ_COVERAGE_HTML:-0}" = "1" ]; then
  llvm-cov show "${objects[@]}" \
    -instr-profile="$profdata" \
    --ignore-filename-regex='(/nix/store/|/fuzz/src/)' \
    --format=html \
    --output-dir="$report_dir/html" \
    --sources "${sources[@]}"
fi

printf 'coverage summary: %s\n' "$report_dir/summary.txt"
