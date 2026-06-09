#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${COQUIC_FUZZ_OUT_DIR:-$repo_root/.fuzz/bin}"
cxx="${CXX:-}"

if command -v afl-clang-lto++ >/dev/null 2>&1; then
  cxx="${COQUIC_AFL_CXX:-afl-clang-lto++}"
elif command -v afl-clang-fast++ >/dev/null 2>&1; then
  cxx="${COQUIC_AFL_CXX:-afl-clang-fast++}"
elif [ -n "$cxx" ]; then
  printf 'warning: AFL++ compiler wrappers not found; using CXX=%s for replay-only build\n' "$cxx" >&2
else
  printf 'error: AFL++ compiler wrappers not found; run inside `nix develop` after flake setup\n' >&2
  exit 1
fi

mkdir -p "$out_dir"

common_flags=(
  -std=c++20
  -g
  -O1
  -fno-omit-frame-pointer
  -DCOQUIC_PROFILE_HOOKS=0
  -I"$repo_root"
  -I"$repo_root/include"
)

sanitizers="${COQUIC_FUZZ_SANITIZERS:-address,undefined}"
if [ -n "$sanitizers" ]; then
  common_flags+=("-fsanitize=$sanitizers")
fi

common_sources=(
  "$repo_root/src/quic/codec/buffer.cpp"
  "$repo_root/src/quic/codec/frame.cpp"
  "$repo_root/src/quic/codec/packet.cpp"
  "$repo_root/src/quic/codec/plaintext_codec.cpp"
  "$repo_root/src/quic/codec/varint.cpp"
)

transport_sources=(
  "$repo_root/src/quic/transport/transport_parameters.cpp"
  "$repo_root/fuzz/src/fuzz_support.cpp"
)

build_target() {
  local name="$1"
  shift
  printf 'building %s\n' "$name"
  "$cxx" "${common_flags[@]}" \
    "$repo_root/fuzz/src/${name}.cpp" \
    "$repo_root/fuzz/src/afl_main.cpp" \
    "${common_sources[@]}" \
    "$@" \
    -o "$out_dir/$name"
}

build_target fuzz_varint
build_target fuzz_frame
build_target fuzz_plaintext_packet
build_target fuzz_transport_parameters "${transport_sources[@]}"

printf 'built fuzzers in %s\n' "$out_dir"
