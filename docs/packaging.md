# Packaging

CoQUIC can prepare local C FFI packages without publishing them to a
distribution registry.

Build a backend package with:

```sh
nix develop .#boringssl -c zig build package -Dtls_backend=boringssl -Doptimize=ReleaseFast
nix develop .#quictls -c zig build package -Dtls_backend=quictls -Doptimize=ReleaseFast
```

The package step installs into `zig-out/`:

- `include/coquic/ffi/core.h`
- `lib/libcoquic-boringssl.a` and `lib/libcoquic-boringssl.so`
- `lib/libcoquic-quictls.a` and `lib/libcoquic-quictls.so`
- `lib/pkgconfig/coquic-boringssl.pc` or `coquic-quictls.pc`
- `lib/cmake/coquic-boringssl/` or `lib/cmake/coquic-quictls/`

The C API is shared by both packages. The TLS backend is selected by linking
one backend-specific package:

- CMake targets: `CoQUIC::coquic_boringssl` or `CoQUIC::coquic_quictls`
- pkg-config packages: `coquic-boringssl` or `coquic-quictls`
- static pkg-config packages: `coquic-boringssl-static` or
  `coquic-quictls-static`

Do not link both backend libraries into one process. They export the same C
symbols by design.

The shared libraries hide private implementation symbols and export only the
`coquic_*` C ABI. Both backend shared packages link their TLS backend privately,
so consumers do not depend on a system BoringSSL or QuicTLS ABI.

The default CMake target selects the shared library when it is present:

```cmake
find_package(coquic-boringssl CONFIG REQUIRED)
target_link_libraries(app PRIVATE CoQUIC::coquic_boringssl)
```

Static targets are also generated as `CoQUIC::coquic_boringssl_static` and
`CoQUIC::coquic_quictls_static`. The SDK package archives are built with the
host C++ toolchain and the GNU `libstdc++` ABI, so plain `cc`, CMake, and
pkg-config static consumers work as long as the usual system C++ runtime is
available. The generated CMake and pkg-config metadata records `stdc++`, `m`,
`pthread`, and `dl` as private static link dependencies.

Use the `*-static` pkg-config package when a static link is required. The
regular pkg-config package intentionally uses `-lcoquic-*`, which lets the
platform linker select the shared library when both shared and static libraries
are installed.

The Nix `coquic-quictls` and `coquic-boringssl` packages include the C FFI SDK
artifacts. The `*-musl` packages are for interop and perf endpoint binaries and
do not install the SDK package metadata.

Release packages must include the applicable upstream TLS license and notice
materials for the pinned BoringSSL or QuicTLS dependency.
