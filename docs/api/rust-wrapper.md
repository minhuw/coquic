# Rust Wrapper

The Rust wrapper under `bindings/rust/coquic` builds on the public C FFI. It is
a Cargo crate that owns opaque C handles and maps borrowed C views into Rust
borrows tied to `QueryResult` or HTTP/3 update lifetimes.

The wrapper is still sans-I/O. Rust callers own sockets, timers, routing,
threading, and scheduling.

## Build

Build a C FFI backend package first:

```sh
nix develop .#quictls -c zig build package -Dtls_backend=quictls -Doptimize=ReleaseFast
```

Then run the Rust wrapper tests:

```sh
nix develop -c bash -lc 'LD_LIBRARY_PATH="$PWD/zig-out/lib:$LD_LIBRARY_PATH" cargo test --manifest-path bindings/rust/coquic/Cargo.toml'
```

The Cargo build script searches the repository-local `zig-out/lib/pkgconfig`
directory and then the normal `PKG_CONFIG_PATH`. By default it links
`coquic-quictls`. Set `COQUIC_TLS_BACKEND=boringssl` for
`coquic-boringssl`, or set `COQUIC_PKG_CONFIG_NAME` explicitly.

For manual linking, set:

- `COQUIC_LIB_DIR`: directory containing `libcoquic-*.so` or `libcoquic-*.a`.
- `COQUIC_LIB_NAME`: library name without `lib` or extension.
- `COQUIC_LINK_KIND`: `dylib` or `static`.

## Surface

The crate exposes:

- `Endpoint`, `EndpointConfig`, `OpenConnection`, and transport input helpers.
- `QueryResult`, borrowed `Effect` values, local errors, timers, and send
  continuation state.
- `http3::Client`, `http3::Server`, request builders, HTTP/3 updates, and
  borrowed request/response views.

Input buffers are borrowed for the duration of each call. CoQUIC copies them
before returning.

Output buffers are borrowed from the owning `QueryResult`, `http3::ClientUpdate`,
or `http3::ServerUpdate`. Copy bytes that must outlive that owner.

## Stability

The wrapper tracks `COQUIC_FFI_ABI_VERSION`. Call `check_ffi_abi_version()` at
startup when loading a shared library dynamically or when package provenance is
unclear.

