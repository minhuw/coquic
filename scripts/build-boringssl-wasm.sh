#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
state_dir="${COQUIC_WASM_BORINGSSL_STATE_DIR:-${repo_root}/.zig-cache/boringssl-wasm}"
source_dir="${WASM_BORINGSSL_SOURCE_DIR:-${state_dir}/src}"
build_dir="${WASM_BORINGSSL_BUILD_DIR:-${state_dir}/build}"
tool_dir="${state_dir}/tools"

mkdir -p "${state_dir}" "${tool_dir}"

if [ ! -d "${source_dir}/.git" ]; then
    rm -rf "${source_dir}"
    git clone --depth 1 https://boringssl.googlesource.com/boringssl "${source_dir}"
fi

zig_path="$(command -v zig)"
llvm_ar_path="$(command -v llvm-ar)"
llvm_ranlib_path="$(command -v llvm-ranlib)"

wasm_cc="${tool_dir}/wasm-cc"
wasm_cxx="${tool_dir}/wasm-cxx"
printf '%s\n' '#!/usr/bin/env bash' "exec ${zig_path} cc -target wasm32-wasi \"\$@\"" > "${wasm_cc}"
printf '%s\n' '#!/usr/bin/env bash' "exec ${zig_path} c++ -target wasm32-wasi \"\$@\"" > "${wasm_cxx}"
chmod +x "${wasm_cc}" "${wasm_cxx}"

rm -rf "${build_dir}"
mkdir -p "${build_dir}"

export WASM_BORINGSSL_SOURCE_DIR="${source_dir}"
export WASM_BORINGSSL_BUILD_DIR="${build_dir}"
export WASM_BORINGSSL_CC="${wasm_cc}"
export WASM_BORINGSSL_CXX="${wasm_cxx}"
export WASM_BORINGSSL_AR="${llvm_ar_path}"
export WASM_BORINGSSL_RANLIB="${llvm_ranlib_path}"

# shellcheck disable=SC2016
nix shell nixpkgs#cmake nixpkgs#ninja -c bash -lc '
cd "${WASM_BORINGSSL_BUILD_DIR}"
cmake -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF \
  -DOPENSSL_NO_ASM=1 \
  -DCMAKE_C_COMPILER="${WASM_BORINGSSL_CC}" \
  -DCMAKE_CXX_COMPILER="${WASM_BORINGSSL_CXX}" \
  -DCMAKE_AR="${WASM_BORINGSSL_AR}" \
  -DCMAKE_RANLIB="${WASM_BORINGSSL_RANLIB}" \
  -DCMAKE_SYSTEM_NAME=Generic \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_C_FLAGS="-DOPENSSL_SMALL -DOPENSSL_NO_SOCK -DOPENSSL_NO_FILESYSTEM -DOPENSSL_NO_POSIX_IO -DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED" \
  -DCMAKE_CXX_FLAGS="-fno-exceptions -fno-rtti -DOPENSSL_SMALL -DOPENSSL_NO_SOCK -DOPENSSL_NO_FILESYSTEM -DOPENSSL_NO_POSIX_IO -DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED" \
  "${WASM_BORINGSSL_SOURCE_DIR}"
ninja crypto ssl
'

printf 'BoringSSL wasm artifacts ready\n'
printf '  include: %s\n' "${source_dir}/include"
printf '  lib:     %s\n' "${build_dir}"
