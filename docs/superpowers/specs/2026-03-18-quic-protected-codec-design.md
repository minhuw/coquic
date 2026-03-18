# QUIC Protected Codec Design

## Status

Approved on 2026-03-18.

## Context

`coquic` now has a plaintext QUIC datagram codec under `src/quic/` that can
serialize and deserialize packet and frame structures before packet protection
is applied. That layer is intentionally crypto-free: it does not derive keys,
encrypt payloads, remove or apply header protection, or reconstruct full packet
numbers from truncated encodings.

RFC 9001 defines packet protection as a separate stage layered on top of packet
formatting. Payload protection uses an AEAD with keys derived from either the
Initial destination connection ID or TLS traffic secrets, and header protection
is then applied over the protected payload sample. On receive, endpoints first
remove header protection, then recover the full packet number, then decrypt the
payload. RFC 9000 Section 17.1 and Appendix A.3 define the packet number
recovery step that depends on the largest successfully authenticated packet in
each packet number space.

The next implementation slice should add a stateless protected-wire codec for
Initial, Handshake, and 1-RTT packets while preserving the plaintext codec as a
lower reusable layer.

## Goal

Add a stateless QUIC protected datagram serializer and deserializer that:

- produces real protected wire images for `Initial`, `Handshake`, and `1-RTT`
  packets;
- removes and applies QUIC header protection;
- performs AEAD payload protection and deprotection;
- derives Initial keys from the client Initial destination connection ID;
- accepts caller-supplied Handshake and 1-RTT traffic secrets; and
- reconstructs full packet numbers from caller-supplied per-space receive
  context.

## Non-Goals

- Replacing or removing the existing plaintext codec
- TLS handshake integration or extracting traffic secrets from a TLS stack
- Automatic packet number length selection from ACK history
- Key updates for 1-RTT traffic
- 0-RTT packet protection in this slice
- Retry integrity tag generation or verification
- Version Negotiation handling in the protected codec
- Transport-state validation beyond what is required to protect or unprotect a
  single packet image

## Decisions

### Layering And Naming

- Keep `src/quic/plaintext_codec.h` and `src/quic/plaintext_codec.cpp` as the
  plaintext packet/frame formatting layer.
- Add a new public protected layer named `protected_codec`, not `crypto codex`.
- The protected codec owns:
  - Initial secret derivation;
  - traffic-secret expansion into QUIC packet protection and header protection
    keys;
  - AEAD payload protection and deprotection;
  - header protection application and removal;
  - packet number reconstruction on receive; and
  - protected datagram slicing and coalesced packet handling.
- The plaintext codec remains the reusable lower layer for packet structure,
  frame parsing, frame validation, and deterministic plaintext serialization.

### Packet Scope

- The first protected slice supports:
  - `Initial`
  - `Handshake`
  - `1-RTT`
- The first protected slice does not support:
  - `0-RTT`
  - `Retry`
  - `VersionNegotiation`
- `Retry` and `VersionNegotiation` remain on the plaintext path because they do
  not use the same protection process as protected QUIC packets.

### Stateless API Boundary

- The protected codec must remain stateless.
- Callers provide all inputs needed to protect or unprotect packets:
  - endpoint role;
  - client Initial destination connection ID;
  - Handshake and 1-RTT traffic secrets;
  - current single active 1-RTT key phase value;
  - largest successfully authenticated packet number per supported packet number
    space on receive; and
  - 1-RTT destination connection ID length for short-header parsing.
- The codec does not cache keys, remember packet numbers, or track key updates.
- This design keeps the implementation easy to test with fixed vectors and
  prevents hidden transport state from leaking into the codec API.

### Cipher Suite Support

- Support these TLS 1.3 cipher suites in the first cut:
  - `TLS_AES_128_GCM_SHA256`
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_CHACHA20_POLY1305_SHA256`
- Model them as a small `CipherSuite` enum in the protected codec API.
- Initial packets always use the QUIC v1 Initial protection process based on
  `AEAD_AES_128_GCM` and SHA-256, regardless of later negotiated Handshake or
  1-RTT cipher suites.
- For Handshake and 1-RTT packets, callers provide a traffic secret plus the
  cipher suite that determines:
  - key length;
  - IV length;
  - header protection algorithm; and
  - HKDF hash function.

### Packet Model

- Keep the existing plaintext `Packet` variants exactly as they are.
- Add protected packet variants that carry full packet numbers:
  - `ProtectedInitialPacket`
  - `ProtectedHandshakePacket`
  - `ProtectedOneRttPacket`
- These protected packet types mirror the plaintext packet payload structures
  and frame lists, but replace `truncated_packet_number` with a full
  `std::uint64_t packet_number`.
- Keep explicit `packet_number_length` in the protected packet model for this
  first cut. The caller chooses the truncated encoding width to send.
- `ProtectedOneRttPacket` retains the short-header `spin_bit` and `key_phase`
  fields. The serializer validates that the packet key phase matches the active
  context key phase because key updates are out of scope.

### Crypto Context Types

- Add a `TrafficSecret` value type:
  - `CipherSuite cipher_suite`
  - `std::vector<std::byte> secret`
- Add a protected serialization context conceptually shaped like:

```cpp
enum class EndpointRole : std::uint8_t {
    client,
    server,
};

struct SerializeProtectionContext {
    EndpointRole local_role;
    ConnectionId client_initial_destination_connection_id;
    std::optional<TrafficSecret> handshake_secret;
    std::optional<TrafficSecret> one_rtt_secret;
    bool one_rtt_key_phase = false;
};
```

- Add a protected deserialization context conceptually shaped like:

```cpp
struct DeserializeProtectionContext {
    EndpointRole peer_role;
    ConnectionId client_initial_destination_connection_id;
    std::optional<TrafficSecret> handshake_secret;
    std::optional<TrafficSecret> one_rtt_secret;
    bool one_rtt_key_phase = false;
    std::optional<std::uint64_t> largest_authenticated_initial_packet_number;
    std::optional<std::uint64_t> largest_authenticated_handshake_packet_number;
    std::optional<std::uint64_t> largest_authenticated_application_packet_number;
    std::size_t one_rtt_destination_connection_id_length = 0;
};
```

- Serialization does not need largest-received packet number context because the
  caller provides both the full packet number and the desired encoded length.
- Deserialization requires largest-authenticated packet number context per
  packet number space because QUIC packet number recovery depends on it.

### Public API Shape

- Keep the current plaintext top-level API untouched:
  - `serialize_datagram(...)`
  - `deserialize_datagram(...)`
- Add a new public header `src/quic/protected_codec.h` with top-level APIs
  conceptually shaped like:

```cpp
using ProtectedPacket =
    std::variant<ProtectedInitialPacket, ProtectedHandshakePacket, ProtectedOneRttPacket>;

CodecResult<std::vector<std::byte>> serialize_protected_datagram(
    std::span<const ProtectedPacket> packets,
    const SerializeProtectionContext& context
);

CodecResult<std::vector<ProtectedPacket>> deserialize_protected_datagram(
    std::span<const std::byte> bytes,
    const DeserializeProtectionContext& context
);
```

- Export the protected codec through `src/coquic.h` alongside the plaintext
  codec.
- Protected datagram serialization and deserialization must support coalesced
  UDP datagrams that contain multiple protected packets of supported types.
- Mixed datagrams that contain unsupported packet types fail explicitly in this
  first cut.

### Internal Module Layout

- Add focused internal modules under `src/quic/`:
  - `src/quic/protected_codec.h`
  - `src/quic/protected_codec.cpp`
  - `src/quic/packet_crypto.h`
  - `src/quic/packet_crypto.cpp`
  - `src/quic/packet_number.h`
  - `src/quic/packet_number.cpp`
- Responsibilities:
  - `protected_codec`: packet slicing, long-header and short-header protected
    flow, top-level datagram APIs
  - `packet_crypto`: Initial secret derivation, HKDF label expansion, AEAD
    sealing/opening, header protection mask generation
  - `packet_number`: truncation validation and full packet number recovery
- Reuse existing packet and frame serialization helpers where doing so preserves
  clear boundaries, but do not contort the plaintext codec into owning crypto
  behavior.

### Protection Flow

- Outbound packet protection flow:
  1. build the plaintext header fields for the packet type;
  2. serialize frames into plaintext payload bytes;
  3. derive or expand the packet protection key, IV, and header protection key;
  4. form the AEAD nonce from the IV and full packet number;
  5. encrypt the plaintext payload with the unprotected header as associated
     data;
  6. append the authentication tag as part of the ciphertext;
  7. sample the ciphertext and apply header protection last.
- Inbound packet processing flow:
  1. parse enough header structure to identify packet type and packet number
     offset;
  2. verify a full header protection sample is available;
  3. remove header protection to recover reserved bits, key phase, and encoded
     packet number length;
  4. recover the full packet number from the truncated field and caller-supplied
     largest-authenticated packet number context;
  5. rebuild the unprotected header as associated data;
  6. derive the nonce and AEAD-decrypt the ciphertext;
  7. parse the resulting plaintext payload into frames.

### Initial, Handshake, And 1-RTT Key Handling

- Initial packets:
  - derive the Initial secret from the client Initial destination connection ID;
  - derive client and server Initial secrets from that PRK;
  - choose send or receive Initial keys based on endpoint role and direction.
- Handshake packets:
  - use caller-supplied Handshake traffic secret and cipher suite;
  - derive `quic key`, `quic iv`, and `quic hp` values from the provided
    secret.
- 1-RTT packets:
  - use caller-supplied 1-RTT traffic secret and cipher suite;
  - support only one active key phase in this slice;
  - reject packets whose protected key phase does not match the active context.

### Packet Number Recovery

- Implement packet number recovery according to RFC 9000 Appendix A.3 using:
  - the caller-supplied largest authenticated packet number in the appropriate
    packet number space;
  - the truncated packet number value; and
  - the decoded packet number length.
- Use separate receive context fields for:
  - Initial space
  - Handshake space
  - application-data space
- Missing packet number context for a packet type is a codec error.
- This slice will not guess or invent a recovery base when the caller omits the
  required packet number state.

### Header Protection Handling

- Implement AES-based header protection for the AES-GCM cipher suites.
- Implement ChaCha20-based header protection for
  `TLS_CHACHA20_POLY1305_SHA256`.
- Sample 16 bytes starting at `pn_offset + 4`, as required by RFC 9001.
- Reject packets that are too short to contain the required sample.
- Long-header packets protect the low 4 bits of the first byte.
- Short-header packets protect the low 5 bits of the first byte, including the
  key phase bit.
- On inbound packets, remove header protection before interpreting the encoded
  packet number length.

### Error Handling

- Extend `CodecErrorCode` with protected-codec failures for at least:
  - `missing_crypto_context`
  - `unsupported_cipher_suite`
  - `packet_number_recovery_failed`
  - `header_protection_sample_too_short`
  - `header_protection_failed`
  - `packet_decryption_failed`
  - `invalid_packet_protection_state`
- Preserve offset reporting where a meaningful byte offset exists, consistent
  with the current plaintext codec.
- AEAD authentication failure is surfaced as a codec failure, not a transport
  error object.
- Wrong secrets, wrong packet number context, or wrong key phase all fail
  explicitly and deterministically.

### Testing

- Add dedicated tests for:
  - Initial secret derivation from the RFC 9001 v1 salt and client Initial DCID
  - HKDF expansion for `quic key`, `quic iv`, and `quic hp`
  - packet number reconstruction against RFC 9000 Appendix A.3 examples
  - AES-based header protection masking and unmasking
  - ChaCha20-based header protection masking and unmasking
  - protected `Initial` round trips
  - protected `Handshake` round trips for all three supported cipher suites
  - protected `1-RTT` round trips for all three supported cipher suites
  - coalesced datagrams containing `Initial` plus `Handshake`
  - missing-secret and missing-context failures
  - too-short sample failures
  - wrong-secret and wrong-largest-packet-number failures
  - short-header destination connection ID length handling
  - key phase mismatch rejection for the single active 1-RTT key phase model
- Keep the existing plaintext codec tests untouched.
- Maintain 100% line coverage for the expanded QUIC codec surface.

## Verification

The completed implementation must pass:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build
nix develop -c zig build test
nix develop -c zig build coverage
```
