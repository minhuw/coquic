# CoQUIC Rust Sys Wrapper

This crate provides the low-level Rust wrapper over the public CoQUIC C FFI. It
is still sans-I/O: callers own sockets, timers, routing, and scheduling.

Build a local C FFI package first:

```sh
zig build package -Dtls_backend=quictls
```

Then run the Rust tests:

```sh
cargo test --manifest-path bindings/rust/coquic/Cargo.toml
```

By default the build script looks for `coquic-quictls` through pkg-config and
also checks the repository-local `zig-out/lib/pkgconfig`. Use
`COQUIC_TLS_BACKEND=boringssl` to select the BoringSSL package, or set
`COQUIC_LIB_DIR`, `COQUIC_LIB_NAME`, and `COQUIC_LINK_KIND` for explicit
linking.

Use the sibling `bindings/rust/coquic-rs` crate for the higher-level Rust QUIC
facade.
