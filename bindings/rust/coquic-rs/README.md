# CoQUIC Rust Facade

This crate provides an ergonomic Rust API over `coquic-sys`. It follows the
same sans-I/O model and mirrors the C++ QUIC facade: an `Endpoint` creates
`Connection` handles, and each connection creates `Stream` handles.

Build the C FFI package first:

```sh
zig build package -Dtls_backend=quictls
```

Then run:

```sh
LD_LIBRARY_PATH="$PWD/zig-out/lib:$LD_LIBRARY_PATH" cargo test --manifest-path bindings/rust/coquic-rs/Cargo.toml
```
