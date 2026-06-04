# CoQUIC Documentation

These documents describe the CoQUIC project API and integration model.

Reference material for RAG is stored in Qdrant. The repository does not require
a checked-in RFC corpus for runtime search or QA.

## API Hierarchy

The public C++ API is the compatibility boundary exported from
`include/coquic/`. Inside that boundary, callers choose the lowest layer that
matches how much control they need.

```text
include/coquic/ public C++ API
+-- coquic::core
|   Lowest layer: sans-I/O endpoint, typed inputs, typed effects.
+-- coquic::quic
|   Transport facade: endpoint, connection, and stream handles over core.
+-- coquic::http3
    Application protocol layer: HTTP/3 state that emits QUIC connection inputs.
```

`coquic::quic` wraps `coquic::core`. `coquic::http3` composes with either
`core` or `quic`: it does not own sockets or endpoints, and it feeds work back
to the matching QUIC connection.

Native bindings are separate ABI surfaces built on top of the C++ layers:

```text
include/coquic/ffi/ native binding ABI
+-- C FFI
    C ABI wrappers over the sans-I/O Core, QUIC facade, and HTTP/3 APIs.
bindings/rust/coquic
|-- coquic-sys
|   Low-level safe owners and borrowed views over the C FFI.
|-- coquic-rs
|   Ergonomic Rust QUIC facade over coquic-sys.
bench/coquic-rust-perf
+-- Tokio UDP perf runtime over coquic-rs.
```

## Contents

### API Surface

- [Public API](api/public-api.md): API overview and compatibility boundary.
- [Core API](api/core.md): sans-I/O endpoint, inputs, effects, and timers.
- [QUIC Facade API](api/quic.md): transport facade over the core endpoint.
- [HTTP/3 API](api/http3.md): request/response layer and QUIC input handoff.

### Native Bindings

- [C FFI API](api/c-ffi.md): C ABI, ownership, package names, and event loop.
- [C FFI Reference](api/c-ffi-reference.md): exported C functions and
  per-function semantics.
- [Rust Wrappers](api/rust-wrapper.md): `coquic-sys`, `coquic-rs`, and the
  Tokio Rust perf runtime.

### Runtime

- [Runtime Integration](api/integration.md): event-loop checklist for callers.

## Reference Corpus

RAG search and QA read indexed section payloads from Qdrant. Local source
documents are only needed when explicitly running indexing commands with a
chosen `--source` directory.
