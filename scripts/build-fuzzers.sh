#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${COQUIC_FUZZ_OUT_DIR:-$repo_root/.fuzz/bin}"
cxx="${CXX:-}"

source "$repo_root/scripts/fuzz-targets.sh"

if command -v afl-clang-lto++ >/dev/null 2>&1; then
  cxx="${COQUIC_AFL_CXX:-afl-clang-lto++}"
elif command -v afl-clang-fast++ >/dev/null 2>&1; then
  cxx="${COQUIC_AFL_CXX:-afl-clang-fast++}"
elif [ -n "$cxx" ]; then
  printf 'warning: AFL++ compiler wrappers not found; using CXX=%s for replay-only build\n' "$cxx" >&2
else
  printf 'error: AFL++ compiler wrappers not found; run inside nix develop after flake setup\n' >&2
  exit 1
fi

mkdir -p "$out_dir"

common_flags=(
  -std=c++20
  -g
  -O1
  -fno-omit-frame-pointer
  -DCOQUIC_FUZZ_BUILD=1
  -DCOQUIC_PROFILE_HOOKS=0
  -I"$repo_root"
  -I"$repo_root/include"
)

tls_backend="${COQUIC_TLS_BACKEND:-quictls}"
tls_linkage="${COQUIC_TLS_LINKAGE:-static}"
case "$tls_backend" in
  quictls)
    tls_include_dir="${QUICTLS_INCLUDE_DIR:-}"
    tls_lib_dir="${QUICTLS_LIB_DIR:-}"
    packet_crypto_source="$repo_root/src/quic/crypto/packet_crypto_quictls.cpp"
    ;;
  boringssl)
    tls_include_dir="${BORINGSSL_INCLUDE_DIR:-}"
    tls_lib_dir="${BORINGSSL_LIB_DIR:-}"
    packet_crypto_source="$repo_root/src/quic/crypto/packet_crypto_boringssl.cpp"
    ;;
  *)
    printf 'error: unsupported COQUIC_TLS_BACKEND=%s\n' "$tls_backend" >&2
    exit 1
    ;;
esac

tls_lib_ext="a"
if [ "$tls_linkage" = "shared" ]; then
  tls_lib_ext="so"
elif [ "$tls_linkage" != "static" ]; then
  printf 'error: unsupported COQUIC_TLS_LINKAGE=%s\n' "$tls_linkage" >&2
  exit 1
fi

sanitizers="${COQUIC_FUZZ_SANITIZERS:-address,undefined}"
if [ -n "$sanitizers" ]; then
  common_flags+=("-fsanitize=$sanitizers")
fi

if [ "${COQUIC_FUZZ_COVERAGE:-0}" = "1" ]; then
  common_flags+=(-fprofile-instr-generate -fcoverage-mapping)
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
)

crypto_stream_sources=(
  "$repo_root/src/quic/crypto/crypto_stream.cpp"
)

stream_sources=(
  "${crypto_stream_sources[@]}"
  "$repo_root/src/quic/transport/streams.cpp"
)

recovery_sources=(
  "${stream_sources[@]}"
  "$repo_root/src/quic/transport/recovery.cpp"
)

congestion_sources=(
  "${recovery_sources[@]}"
  "$repo_root/src/quic/cca/common.cpp"
  "$repo_root/src/quic/cca/newreno.cpp"
  "$repo_root/src/quic/cca/cubic.cpp"
  "$repo_root/src/quic/cca/bbr.cpp"
  "$repo_root/src/quic/cca/copa.cpp"
  "$repo_root/src/quic/transport/congestion.cpp"
)

protected_sources=(
  "$repo_root/src/quic/codec/packet_number.cpp"
  "$repo_root/src/quic/codec/protected_codec.cpp"
  "$repo_root/src/quic/codec/protected_codec_test_hooks.cpp"
  "$packet_crypto_source"
  "${stream_sources[@]}"
)

protected_link_args=()
if [ -n "$tls_include_dir" ] && [ -n "$tls_lib_dir" ]; then
  common_flags+=("-I$tls_include_dir")
  protected_link_args+=(
    "$tls_lib_dir/libssl.$tls_lib_ext"
    "$tls_lib_dir/libcrypto.$tls_lib_ext"
    -lm
    -pthread
    -ldl
  )
fi

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

build_seed_generator() {
  printf 'building generate_corpus\n'
  "$cxx" "${common_flags[@]}" \
    "$repo_root/fuzz/src/generate_corpus.cpp" \
    "${common_sources[@]}" \
    "${transport_sources[@]}" \
    -o "$out_dir/generate_corpus"
}

for target in "${COQUIC_FUZZ_TARGETS[@]}"; do
  case "$target" in
    fuzz_transport_parameters)
      build_target "$target" "${transport_sources[@]}"
      ;;
    fuzz_protected_packet)
      if [ -z "$tls_include_dir" ] || [ -z "$tls_lib_dir" ]; then
        printf 'error: %s requires TLS include/lib env for backend %s\n' "$target" "$tls_backend" >&2
        exit 1
      fi
      build_target "$target" "${protected_sources[@]}" "${protected_link_args[@]}"
      ;;
    fuzz_stream_state)
      build_target "$target" "${stream_sources[@]}"
      ;;
    fuzz_recovery_ack)
      build_target "$target" "${recovery_sources[@]}"
      ;;
    fuzz_congestion)
      build_target "$target" "${congestion_sources[@]}"
      ;;
    *)
      build_target "$target"
      ;;
  esac
done
build_seed_generator

printf 'built fuzzers in %s\n' "$out_dir"
