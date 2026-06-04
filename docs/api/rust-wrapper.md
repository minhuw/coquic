# Rust Wrappers

The Rust bindings are split into two crates:

- `coquic-sys` under `bindings/rust/coquic`: low-level wrappers over the public
  C FFI. This crate owns opaque C handles and maps borrowed C views into Rust
  borrows tied to `QueryResult` or HTTP/3 update lifetimes.
- `coquic-rs` under `bindings/rust/coquic-rs`: ergonomic Rust facade over
  `coquic-sys`. Its `quic` module mirrors the C++ QUIC facade with `Endpoint`,
  `Connection`, `Stream`, and `ConnectResult`.
- `coquic-rust-perf` under `bench/coquic-rust-perf`: Tokio UDP perf runtime built on
  `coquic-rs`. Its `coquic-rust-perf` binary speaks the same
  `coquic-perf/1` control protocol as `bench/coquic-perf`.

The wrapper crates are still sans-I/O. Rust callers own sockets, timers,
routing, threading, and scheduling. The perf crate is an example runtime that
supplies those pieces with Tokio.

## Build

Build a C FFI backend package first:

```sh
nix develop .#quictls -c zig build package -Dtls_backend=quictls -Doptimize=ReleaseFast
```

Then run the Rust wrapper tests:

```sh
nix develop -c bash -lc 'LD_LIBRARY_PATH="$PWD/zig-out/lib:$LD_LIBRARY_PATH" cargo test --manifest-path bindings/rust/coquic/Cargo.toml'
nix develop -c bash -lc 'LD_LIBRARY_PATH="$PWD/zig-out/lib:$LD_LIBRARY_PATH" cargo test --manifest-path bindings/rust/coquic-rs/Cargo.toml'
nix develop -c bash -lc 'LD_LIBRARY_PATH="$PWD/zig-out/lib:$LD_LIBRARY_PATH" cargo test --manifest-path bench/coquic-rust-perf/Cargo.toml'
```

The `coquic-sys` build script searches the repository-local
`zig-out/lib/pkgconfig` directory and then the normal `PKG_CONFIG_PATH`. By
default it links
`coquic-quictls`. Set `COQUIC_TLS_BACKEND=boringssl` for
`coquic-boringssl`, or set `COQUIC_PKG_CONFIG_NAME` explicitly.

For manual linking, set:

- `COQUIC_LIB_DIR`: directory containing `libcoquic-*.so` or `libcoquic-*.a`.
- `COQUIC_LIB_NAME`: library name without `lib` or extension.
- `COQUIC_LINK_KIND`: `dylib` or `static`.

## Sys Surface

`coquic-sys` exposes:

- `Endpoint`, `EndpointConfig`, `OpenConnection`, and transport input helpers.
- `QueryResult`, borrowed `Effect` values, local errors, timers, and send
  continuation state.
- `http3::Client`, `http3::Server`, request builders, HTTP/3 updates, and
  borrowed request/response views.

Input buffers are borrowed for the duration of each call. CoQUIC copies them
before returning.

Output buffers are borrowed from the owning `QueryResult`, `http3::ClientUpdate`,
or `http3::ServerUpdate`. Copy bytes that must outlive that owner.

## Facade Surface

`coquic-rs` re-exports the low-level value types and adds:

- `quic::Endpoint`, created from `quic::EndpointConfig`.
- `quic::Endpoint::connect()`, returning `quic::ConnectResult`.
- `quic::Connection`, a handle-like object with `send_stream`,
  `send_datagram`, `reset_stream`, `stop_sending`, `close`, and
  `request_key_update`.
- `quic::Stream`, created from a connection and stream ID, with `send`,
  `finish`, `reset`, and `stop_sending`.

The facade uses shared endpoint ownership internally so connection and stream
handles remain lightweight. Mutating calls borrow the endpoint mutably for the
duration of the call and return `COQUIC_STATUS_INVALID_ARGUMENT` if the endpoint
has already been dropped.

## Tokio Perf Runtime

`coquic-rust-perf` accepts the main `bench/coquic-perf` options:

```sh
nix develop .#quictls -c bash -lc 'LD_LIBRARY_PATH="$PWD/zig-out/lib:$LD_LIBRARY_PATH" cargo run --manifest-path bench/coquic-rust-perf/Cargo.toml --bin coquic-rust-perf -- server --host 127.0.0.1 --port 4433'
nix develop .#quictls -c bash -lc 'LD_LIBRARY_PATH="$PWD/zig-out/lib:$LD_LIBRARY_PATH" cargo run --manifest-path bench/coquic-rust-perf/Cargo.toml --bin coquic-rust-perf -- client --host 127.0.0.1 --port 4433 --mode bulk --direction download --total-bytes 1048576'
```

The Tokio runtime maps UDP peer addresses to CoQUIC route handles, feeds
received datagrams into `quic::Endpoint::receive_datagram()`, sends
`Effect::SendDatagram` payloads with `tokio::net::UdpSocket`, and drives
endpoint timers with `tokio::time`.

## Stability

The wrappers track `COQUIC_FFI_ABI_VERSION`. Call `check_ffi_abi_version()` at
startup when loading a shared library dynamically or when package provenance is
unclear.
