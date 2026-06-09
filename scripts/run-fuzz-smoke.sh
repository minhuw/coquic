#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${COQUIC_FUZZ_OUT_DIR:-$repo_root/.fuzz/bin}"
corpus_dir="${COQUIC_FUZZ_CORPUS_DIR:-$repo_root/.fuzz/corpus}"

"$repo_root/scripts/build-fuzzers.sh"
"$repo_root/scripts/prepare-fuzz-corpus.sh"

for target in fuzz_varint fuzz_frame fuzz_plaintext_packet fuzz_transport_parameters; do
  binary="$bin_dir/$target"
  corpus="$corpus_dir/$target"
  printf 'replaying %s seeds\n' "$target"
  for seed in "$corpus"/*; do
    [ -f "$seed" ] || continue
    "$binary" "$seed"
  done
done
