# Full BoringSSL Support Design

## Status

Proposed on 2026-03-20.

## Goal

Add full `BoringSSL` support as a build-time-selectable QUIC TLS backend while
preserving the existing backend-neutral `QuicCore` / `QuicConnection` API and
meeting the repo verification bar for both backends:

- `zig build`
- `zig build test`
- `zig build coverage`
- `clang-format`
- `clang-tidy`

Coverage must reach `100%` for both `quictls` and `boringssl`.

## Current State

The repository already exposes backend selection in `build.zig`, but only the
`quictls` path is actually implemented and verified:

- `src/quic/tls_adapter_quictls.cpp` contains the real TLS adapter.
- `src/quic/tls_adapter_boringssl.cpp` is currently a stub.
- `src/quic/packet_crypto.cpp` uses OpenSSL-style APIs that compile under
  `quictls` but fail under `boringssl`.

The BoringSSL development environment already provides the QUIC TLS hooks needed
for the adapter:

- `SSL_CTX_set_quic_method`
- `SSL_set_quic_method`
- `SSL_provide_quic_data`
- `SSL_process_quic_post_handshake`
- `SSL_set_quic_transport_params`
- `SSL_get_peer_quic_transport_params`

The main implementation gap is backend-specific crypto integration plus the
missing BoringSSL adapter.

## Non-Goals

- Adding runtime backend switching
- Supporting stock OpenSSL as a third handshake backend
- Changing the `QuicCore` or `QuicConnection` public behavior to expose backend
  details
- Relaxing the existing verification or coverage requirements for either
  backend

## Decisions

### 1. Preserve the Existing Backend-Neutral Connection Surface

`QuicConnection` and `QuicCore` will remain backend-agnostic. The existing
`TlsAdapter` seam in `src/quic/tls_adapter.h` stays the only handshake backend
abstraction used by connection code.

This keeps transport logic, packetization, and state handling out of
backend-specific files and avoids coupling connection behavior to a specific TLS
library.

### 2. Keep Separate TLS Adapter Implementations per Backend

`src/quic/tls_adapter_quictls.cpp` and `src/quic/tls_adapter_boringssl.cpp`
will remain separate translation units selected by `-Dtls_backend`.

The BoringSSL adapter must implement the same contract as the quictls adapter:

- handshake start/poll/provide
- per-encryption-level pending TLS byte collection
- available traffic-secret extraction
- peer transport-parameter capture
- handshake completion reporting
- sticky error behavior and fault-injection coverage expected by tests

This is preferable to collapsing both backends into one heavily conditional
source file because the QUIC TLS hooks are similar but not identical enough to
justify hiding the boundary.

### 3. Split Packet Crypto by Backend

`src/quic/packet_crypto.cpp` should no longer be the only concrete crypto
implementation file.

The design is:

- keep `src/quic/packet_crypto.h` as the stable public surface
- keep a minimal shared front door only if needed
- add backend-specific implementations selected at build time:
  - `src/quic/packet_crypto_quictls.cpp`
  - `src/quic/packet_crypto_boringssl.cpp`

The BoringSSL implementation will use the APIs BoringSSL actually exposes:

- `<openssl/hkdf.h>` for HKDF extract/expand
- `<openssl/aead.h>` for AEAD sealing/opening
- `<openssl/chacha.h>` for ChaCha20 header protection

The quictls implementation can keep using the current EVP-oriented primitives.

This avoids spreading backend-specific `#ifdef`s throughout one crypto file and
gives each backend a clean path to full branch coverage.

### 4. Generalize Backend-Specific Test Hooks

Current white-box TLS adapter tests depend on quictls-specific helper code in
`src/quic/tls_adapter_quictls_test_hooks.h`.

To achieve honest `100%` coverage for both backends, the tests need a
backend-neutral hook seam or backend-selected hook implementations that expose
equivalent inspection and fault-injection behavior for both backends.

The tests should continue validating the same adapter contract:

- encryption-level mapping
- cipher-suite detection
- sticky error handling
- initialization and handshake failure paths
- transport-parameter and secret extraction

The implementation may keep shared fault-point enums and shared test APIs, but
backend-specific internals should stay behind backend-specific files.

## Architecture

The implementation is organized into three focused slices:

### TLS Adapter Slice

`tls_adapter_boringssl.cpp` becomes a real peer of the quictls adapter and owns
all BoringSSL handshake integration. It maps BoringSSL QUIC callbacks and state
changes onto the existing `TlsAdapter` contract without changing connection
logic.

### Packet Crypto Slice

Packet protection and key derivation become backend-selected implementations
rather than a single file trying to bridge both API dialects. Shared behavior
stays defined by the existing tests and public function signatures, while the
concrete crypto primitives stay backend-local.

### Test Slice

The contract, core, and packet-crypto tests remain behavior-focused and
backend-neutral at the call site. Where current coverage depends on quictls-only
white-box access, that access will be lifted into a backend-neutral test seam so
the same behavioral and fault-path expectations can run against both backends.

## Data Flow

For both backends, the runtime flow remains:

1. `QuicConnection` creates `TlsAdapter`.
2. `TlsAdapter` drives the TLS handshake through backend-specific QUIC hooks.
3. The adapter emits pending CRYPTO bytes and available traffic secrets.
4. `QuicConnection` installs secrets into packet protection code and exchanges
   CRYPTO data through existing QUIC packet logic.
5. Transport parameters are passed through the adapter as opaque bytes and
   validated by existing transport-parameter code.

Only steps 2 and the crypto primitives used in step 4 become backend-specific.

## Verification Strategy

Verification must be performed per backend, not only on the default backend.

Required acceptance commands:

```bash
nix develop -c zig build -Dtls_backend=quictls
nix develop -c zig build test -Dtls_backend=quictls
nix develop -c zig build coverage -Dtls_backend=quictls

nix develop -c zig build -Dtls_backend=boringssl
nix develop -c zig build test -Dtls_backend=boringssl
nix develop -c zig build coverage -Dtls_backend=boringssl

nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
```

Coverage expectations:

- `quictls` coverage remains at `100%`
- `boringssl` coverage must also reach `100%`
- backend-specific branches must be exercised under their own backend
- tests should not rely on quictls-only internals when asserting backend-neutral
  behavior

## Risks and Mitigations

### Risk: Crypto Behavior Diverges Between Backends

Mitigation:

- keep shared tests as the behavioral source of truth
- run the same packet-crypto and handshake suites under both backends
- avoid conditional behavior at the public API layer

### Risk: Coverage Drops Because Backend-Specific Fault Paths Are Untestable

Mitigation:

- generalize test hooks before or alongside the backend implementation
- keep backend-specific code explicit so each branch can be targeted directly
- preserve fault injection where current tests depend on it

### Risk: Build Logic Becomes Hard to Reason About

Mitigation:

- keep backend selection centralized in `build.zig`
- select complete backend-specific translation units instead of scattering
  preprocessor branches across many files

## Recommended Implementation Shape

1. Make packet crypto backend-selectable and get packet-crypto tests passing
   under both backends.
2. Implement the BoringSSL TLS adapter against the existing adapter contract.
3. Generalize the test hook seam so adapter coverage can be completed on both
   backends.
4. Run the full verification matrix and close any remaining coverage gaps
   backend-by-backend.

This ordering reduces risk because it resolves the compile-time crypto mismatch
before the handshake adapter work depends on it.
