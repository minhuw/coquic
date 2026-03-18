# QUIC Handshake TLS Backend Design Delta

## Status

Approved on 2026-03-18.

## Supersedes

- `docs/superpowers/specs/2026-03-18-quic-handshake-design.md`
- `docs/superpowers/specs/2026-03-18-quic-handshake-design-delta.md`

This delta keeps the approved `QuicCore` / `QuicConnection` handshake
architecture, but changes the TLS backend assumption.

## Context

The original handshake design assumed the repo could keep QUIC packetization in
our own code while using the installed OpenSSL `3.4.3` as a TLS engine behind a
small adapter seam. The backend probe in
`docs/superpowers/specs/2026-03-18-quic-handshake-design-delta.md` showed that
the current stock OpenSSL install does not expose the raw QUIC-TLS control
surface needed for that design.

At the same time, our repo already has a meaningful QUIC implementation surface:

- `src/quic/packet.*`
- `src/quic/frame.*`
- `src/quic/plaintext_codec.*`
- `src/quic/protected_codec.*`
- `src/quic/packet_crypto.*`

So the project direction remains: our code owns QUIC transport packetization and
packet protection, while the TLS backend only supplies handshake logic, traffic
secrets, and opaque transport-parameter bytes.

## Goal

Support a build-time-selectable QUIC-capable TLS backend for the handshake
engine, with:

- `quictls` as the first supported backend
- `BoringSSL` as a second supported backend
- no stock OpenSSL handshake backend path

The resulting handshake engine must preserve the approved public API:

- `QuicCore(config)`
- `receive(std::vector<std::byte>) -> std::vector<std::byte>`
- `is_handshake_complete() const`

## Non-Goals

- Supporting stock OpenSSL `3.4.3` as a handshake backend for custom QUIC
  packetization
- Runtime plugin loading or per-connection backend switching
- Wrapping OpenSSL's own QUIC connection engine as the main implementation path
- Guaranteeing backend ABI compatibility across all future BoringSSL releases

## Decisions

### Backend Model

- Backend choice is optional at build time, not runtime.
- Add a Zig build option conceptually shaped like:

```zig
const tls_backend = b.option([]const u8, "tls_backend",
    "QUIC TLS backend: quictls or boringssl") orelse "quictls";
```

- `quictls` is the default implementation path.
- `boringssl` is supported as a second backend once the backend-neutral contract
  tests pass against it.

### TLS Abstraction Boundary

- Keep one narrow backend-neutral seam inside `src/quic/`, conceptually:

```cpp
class TlsAdapter {
  public:
    explicit TlsAdapter(TlsAdapterConfig config);

    CodecResult<bool> start();
    CodecResult<bool> provide(EncryptionLevel level, std::span<const std::byte> bytes);
    void poll();
    std::vector<std::byte> take_pending(EncryptionLevel level);
    std::vector<AvailableTrafficSecret> take_available_secrets();
    const std::optional<std::vector<std::byte>> &peer_transport_parameters() const;
    bool handshake_complete() const;
};
```

- `QuicConnection` depends only on this seam.
- Concrete backend implementations live behind it:
  - `tls_adapter_quictls.cpp`
  - `tls_adapter_boringssl.cpp`

### QUIC Ownership

- Keep QUIC packet formation, packet protection, connection IDs, CRYPTO stream
  handling, and transport-parameter parsing in our code.
- Do not redesign around an external QUIC connection engine.
- This preserves the value of the existing codec/protection work and keeps the
  handshake architecture aligned with the original project goal.

### Crypto Backend Implications

- `quictls` is expected to be the easier first backend because it stays close to
  the current OpenSSL-style crypto APIs already used in `src/quic/packet_crypto.cpp`.
- `BoringSSL` support might require either:
  - a dedicated `packet_crypto_boringssl.cpp`, or
  - a small compatibility layer that hides crypto API differences.
- This is an implementation concern, not an architectural reason to avoid
  multi-backend support.

### Testing Strategy

- Add backend-neutral contract tests for the TLS seam.
- Run those same tests against each enabled backend.
- The first end-to-end handshake integration target is:
  - client `QuicCore` + server `QuicCore`
  - `quictls` backend
- After that is green, add the same contract coverage for `boringssl`.

## Recommended Execution Order

1. Introduce the backend-neutral TLS seam and build option.
2. Implement `quictls` backend and make the full handshake green.
3. Add `boringssl` backend and extend verification to include it.

This keeps the fastest path to a real handshake while still honoring the
approved requirement to support both backends.
