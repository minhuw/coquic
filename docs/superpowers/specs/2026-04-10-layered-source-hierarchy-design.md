# 2026-04-10 Layered Source Hierarchy Redesign

## Goal

Reorganize the production source tree into explicit layered domains so the
repository structure matches the architecture we want to preserve:

- `src/quic/` for QUIC transport/core
- `src/io/` for network I/O backends
- `src/http09/` for HTTP/0.9 protocol and runtime
- `src/http3/` for HTTP/3 protocol and QPACK

This redesign is intended to make ownership clearer, improve navigation, and
enforce hard dependency rules that keep transport, I/O, and application
protocol concerns separated.

## Current Problems

- `src/quic/` currently mixes transport-core code, network I/O, HTTP/0.9
  runtime orchestration, and HTTP/3 protocol code.
- File placement no longer reflects the architectural seams that already exist,
  especially after the recent socket-I/O backend extraction.
- The current layout makes it too easy to add accidental cross-layer
  dependencies because unrelated modules share one directory and one namespace.
- `build.zig`, `src/main.cpp`, `src/coquic.*`, and tests all reference a flat
  `src/quic/*` layout that hides the distinction between transport, I/O, and
  application layers.

## Decision Summary

The repository will adopt a top-level domain layout with matching namespaces:

- `src/quic/` and `coquic::quic`
- `src/io/` and `coquic::io`
- `src/http09/` and `coquic::http09`
- `src/http3/` and `coquic::http3`

This is a single large move. The implementation will not use compatibility
headers, alias namespaces, or temporary shims.

## Alternatives Considered

### Recommended: Top-Level Protocol Domains

- `src/quic/`
- `src/io/`
- `src/http09/`
- `src/http3/`

This is the selected approach because the directory hierarchy and namespace
hierarchy stay aligned and immediately communicate the layering model.

### Not Chosen: Shared `src/http/` Parent

A nested layout such as `src/http/http09/` and `src/http/http3/` was considered.
It would leave room for future shared HTTP code, but it adds structure we do
not currently need and makes the namespace story less direct.

### Not Chosen: Deeper Fine-Grained Splits

Breaking more areas out immediately, such as standalone top-level `src/tls/` or
`src/qlog/`, was rejected for now. Those pieces are still closely tied to QUIC
core and would add churn beyond the current goal.

## Target Architecture

### `src/quic/`

`src/quic/` is the base transport layer. It contains protocol primitives and
transport/core state management only.

Examples:

- `buffer.*`
- `congestion.*`
- `connection.*`
- `core.*`
- `crypto_stream.*`
- `frame.*`
- `packet.*`
- `packet_number.*`
- `plaintext_codec.*`
- `protected_codec.*`
- `recovery.*`
- `resumption.h`
- `streams.*`
- `tls_adapter*`
- `packet_crypto*`
- `transport_parameters.*`
- `varint.*`
- `version.h`
- `qlog/*`

### `src/io/`

`src/io/` owns network-facing abstractions and concrete backend
implementations.

Examples:

- `io_backend.*`
- `io_backend_test_hooks.*`
- `socket_io_backend.*`

### `src/http09/`

`src/http09/` owns HTTP/0.9 application behavior and the HTTP/0.9 interop
runtime.

Examples:

- `http09.*`
- `http09_client.*`
- `http09_server.*`
- `http09_runtime.*`
- `http09_runtime_test_hooks.*`

### `src/http3/`

`src/http3/` owns HTTP/3 application-layer functionality.

Examples:

- `http3.*`
- `http3_protocol.*`
- `http3_qpack.*`

## Dependency Rules

These rules are a hard design constraint for the reorganization.

### `quic` Layer

- `src/quic` may depend only on `src/quic`.
- `coquic::quic` types and functions must not include, reference, or name
  `src/io`, `src/http09`, or `src/http3` modules.

### `io` Layer

- `src/io` may depend on `src/quic`.
- `src/io` must not depend on `src/http09` or `src/http3`.
- `coquic::io` is responsible for real I/O and backend concerns, not
  application protocol policy.

### `http09` And `http3` Layers

- `src/http09` and `src/http3` may depend on `src/quic` and `src/io`.
- `src/http09` and `src/http3` must not depend on each other.
- If shared HTTP utilities are needed later, they should be introduced as a
  deliberate follow-up design rather than by adding ad hoc cross-layer
  references now.

### Entrypoint Code

- `src/main.cpp` and `src/coquic.*` are composition-layer code.
- They may include public headers from `src/quic`, `src/io`, `src/http09`, and
  `src/http3` as needed.

## Namespace Rules

Directory moves and namespace moves happen together.

- Files under `src/quic/` use `coquic::quic`
- Files under `src/io/` use `coquic::io`
- Files under `src/http09/` use `coquic::http09`
- Files under `src/http3/` use `coquic::http3`

No transitional namespace aliases will be kept after the move.

## Concrete Move Map

### Files Staying In `src/quic/`

- `buffer.*`
- `congestion.*`
- `connection.*`
- `connection_test_hooks.h`
- `core.*`
- `crypto_stream.*`
- `frame.*`
- `packet.*`
- `packet_crypto*`
- `packet_number.*`
- `plaintext_codec.*`
- `protected_codec.*`
- `protected_codec_test_hooks.h`
- `qlog/*`
- `recovery.*`
- `resumption.h`
- `streams.*`
- `tls_adapter*`
- `transport_parameters.*`
- `varint.*`
- `version.h`

### Files Moving To `src/io/`

- `io_backend.h`
- `io_backend_test_hooks.h`
- `socket_io_backend.cpp`
- `socket_io_backend.h`

### Files Moving To `src/http09/`

- `http09.cpp`
- `http09.h`
- `http09_client.cpp`
- `http09_client.h`
- `http09_server.cpp`
- `http09_server.h`
- `http09_runtime.cpp`
- `http09_runtime.h`
- `http09_runtime_test_hooks.h`

### Files Moving To `src/http3/`

- `http3.h`
- `http3_protocol.cpp`
- `http3_protocol.h`
- `http3_qpack.cpp`
- `http3_qpack.h`

## Build And Test Impact

The reorganization must update all repository consumers in the same patch:

- `build.zig` source lists
- production include paths
- tests and test-support include paths
- `src/main.cpp`
- `src/coquic.cpp`
- `src/coquic.h`

The include-path rewrite is part of the architecture change, not optional
cleanup.

## Migration Constraints

- This is one atomic repository-wide move.
- No compatibility wrapper headers.
- No duplicate files in old and new locations.
- No namespace aliases left behind for old names.
- If a file violates the target layering after relocation, its dependencies must
  be corrected in the same patch.

## Non-Goals

- No intended protocol behavior changes.
- No redesign of QUIC core APIs beyond what is required by namespace and include
  relocation.
- No new shared HTTP layer in this change.
- No extra architectural splitting beyond `quic`, `io`, `http09`, and `http3`.

## Risks

- Repository-wide path churn can break build wiring or tests if any include path
  is missed.
- Namespace migration can expose assumptions in tests, helper utilities, or
  implementation files that relied on the old `coquic::quic` placement.
- Some files may reveal hidden architectural violations once the move makes the
  layering rules explicit.
- This is a large refactor, so verification must be stricter than for a local
  rename.

## Verification Requirements

The change is not complete until all of the following are true:

- the project builds successfully after the move
- the test suite passes after the move
- repository-wide include scanning confirms:
  - `src/quic` does not reference `src/io`, `src/http09`, or `src/http3`
  - `src/io` does not reference `src/http09` or `src/http3`
  - `src/http09` and `src/http3` depend only downward on `src/io` and
    `src/quic`
- no compatibility headers, shim namespaces, or duplicated moved files remain

## Implementation Ordering

1. Create the target directory layout.
2. Move files into `src/io`, `src/http09`, and `src/http3`.
3. Update namespaces to match the new directories.
4. Rewrite repository-wide include paths.
5. Update `build.zig` and root entrypoint files.
6. Update tests and test-support headers.
7. Run build and test verification.
8. Run include-boundary checks to validate the layering rules.

## Success Criteria

This redesign is successful when a reader can infer the architectural layer of a
module from its path and namespace alone, and when the repository no longer
permits transport, I/O, and HTTP application concerns to blur together behind a
single `src/quic/` umbrella.
