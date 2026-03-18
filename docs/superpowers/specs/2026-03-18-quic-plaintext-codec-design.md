# QUIC Plaintext Datagram Codec Design

## Status

Approved on 2026-03-18.

## Context

`coquic` currently has a small C++20 library and test harness, but it does not
yet have any QUIC transport types, packet parsers, frame encoders, or varint
helpers. The first protocol slice should establish those fundamentals without
mixing in packet protection, header protection, packet number reconstruction, or
TLS key handling.

RFC 9000 defines packet formats, packet-type-specific frame restrictions, and
variable-length integer encoding in Sections 12.4, 12.5, 16, 17.2.2, 17.2.3,
17.2.4, and 17.3.1. RFC 9001 adds packet protection and header protection, but
those mechanisms change both the packet boundary and the meaning of several
header fields. To keep the first implementation small and testable, the initial
codec will operate on plaintext QUIC packet images only.

## Goal

Add a plaintext QUIC datagram serializer and deserializer that can encode and
decode the core RFC 9000 packet and frame formats and enforce packet-local
encoding rules, while leaving encryption and header protection to a later layer.

## Non-Goals

- AEAD packet protection, Initial secret derivation, key updates, or header
  protection
- Packet number reconstruction from truncated encodings
- Retry integrity tag verification
- Stateless reset detection
- QUIC extensions outside the RFC 9000 core frame set, such as DATAGRAM
- Transport-state validation that depends on endpoint role, handshake phase, or
  remembered peer limits

## Decisions

### Codec Boundary

- The public top-level API names will be `serialize_datagram(...)` and
  `deserialize_datagram(...)`.
- These APIs operate on plaintext transport images:
  - outbound protected packet types are serialized before packet protection and
    header protection are applied;
  - inbound protected packet types are deserialized after a future crypto layer
    has removed those protections.
- As a result, serialized `Initial`, `0-RTT`, `Handshake`, and `1-RTT` packets
  are intentionally not network-valid on their own yet. They are inputs to a
  later protection layer, not final wire packets.
- `VersionNegotiation` and `Retry` packets are not payload-protected, so this
  layer can serialize and deserialize them in a wire-faithful way.
- A future protected-wire layer will own:
  - raw packet slicing from UDP datagrams,
  - header protection removal and application,
  - packet number reconstruction,
  - payload decryption and encryption,
  - any final long-header length adjustments needed once AEAD tag sizes are in
    play.

### Packet Model

- Represent packets as a tagged sum type with dedicated variants for:
  - `VersionNegotiation`
  - `Retry`
  - `Initial`
  - `ZeroRtt`
  - `Handshake`
  - `OneRtt`
- Protected packet variants (`Initial`, `ZeroRtt`, `Handshake`, `OneRtt`) carry
  a vector of parsed frames as their payload.
- `VersionNegotiation` and `Retry` remain dedicated packet variants without
  frame payloads.
- For protected packet variants, store:
  - `packet_number_length` as an explicit `1..4` byte count
  - `truncated_packet_number` as the decoded integer value of the encoded packet
    number field
- Do not pretend this layer knows the reconstructed full packet number. That
  belongs to the later protected-wire receive path.
- `OneRtt` packets require caller-supplied destination connection ID length when
  deserializing, because the short header does not carry that length on wire.

### Plaintext Length Handling

- For plaintext long-header packet images, the `Length` field is computed and
  validated as:
  - encoded packet number bytes
  - plus plaintext frame payload bytes
- This lets the plaintext codec coalesce multiple packets into a single
  datagram and parse them back deterministically without needing crypto.
- The future protection layer may need to rewrite or reinterpret this field when
  producing real wire packets, because AEAD protection changes the protected
  payload size.

### Frame Model

- Implement the RFC 9000 core frame set from Table 3 in Section 12.4:
  - `PADDING`
  - `PING`
  - `ACK`
  - `RESET_STREAM`
  - `STOP_SENDING`
  - `CRYPTO`
  - `NEW_TOKEN`
  - `STREAM`
  - `MAX_DATA`
  - `MAX_STREAM_DATA`
  - `MAX_STREAMS`
  - `DATA_BLOCKED`
  - `STREAM_DATA_BLOCKED`
  - `STREAMS_BLOCKED`
  - `NEW_CONNECTION_ID`
  - `RETIRE_CONNECTION_ID`
  - `PATH_CHALLENGE`
  - `PATH_RESPONSE`
  - `CONNECTION_CLOSE`
  - `HANDSHAKE_DONE`
- Model frame families with explicit flags instead of leaving callers to decode
  bitfields manually:
  - `ACK` records whether ECN counts are present
  - `STREAM` records the `OFF`, `LEN`, and `FIN` flags and exposes optional
    offset and explicit length fields accordingly
  - `CONNECTION_CLOSE` distinguishes transport and application variants
- Unknown frame types are rejected.

### Validation Rules

- All integer encodings follow RFC 9000 Section 16 varint rules, except for the
  fields RFC 9000 defines outside the varint encoding, such as Version,
  connection ID lengths in long headers, and packet number bytes.
- Frame type varints must use the shortest possible encoding, per RFC 9000
  Section 12.4.
- Packets that contain frames must contain at least one frame.
- Enforce packet-type-specific frame restrictions from RFC 9000 Sections 12.4
  and 12.5:
  - `Initial` only allows `PADDING`, `PING`, `ACK`, `CRYPTO`, and transport
    `CONNECTION_CLOSE`
  - `Handshake` only allows `PADDING`, `PING`, `ACK`, `CRYPTO`, and transport
    `CONNECTION_CLOSE`
  - `ZeroRtt` rejects `ACK`, `CRYPTO`, `HANDSHAKE_DONE`, `NEW_TOKEN`,
    `PATH_RESPONSE`, and `RETIRE_CONNECTION_ID`
  - application-data-only frames are rejected in `Initial` and `Handshake`
- Enforce fixed-bit and header-shape checks for QUIC v1 packet layouts.
- Enforce long-header connection ID length limits of at most 20 bytes for QUIC
  v1.
- Enforce reserved bits as zero in plaintext packet images.
- Do not enforce endpoint-role-dependent rules in this layer, such as:
  - whether an `Initial` came from client or server
  - whether a server `Initial` token length must be zero
  - whether a first client `Initial` must start CRYPTO data at offset 0
  Those checks belong to higher transport logic once direction and connection
  state exist.

### API Shape

- Provide a focused public header for the plaintext codec, plus internal helper
  modules for varints, packet types, frames, and buffer cursors.
- The top-level API should look conceptually like:

```cpp
struct DeserializeOptions {
    std::optional<std::size_t> one_rtt_destination_connection_id_length;
};

Result<std::vector<Packet>, CodecError> deserialize_datagram(
    std::span<const std::byte> bytes,
    const DeserializeOptions& options = {}
);

Result<std::vector<std::byte>, CodecError> serialize_datagram(
    std::span<const Packet> packets
);
```

- Keep packet-level helpers under the hood for composition:
  - `serialize_packet(...)`
  - `deserialize_packet(...)`
- `deserialize_datagram(...)` should parse sequential packets until all bytes
  are consumed, so coalesced long-header datagrams work naturally.
- Serializer output should be deterministic so round-trip tests can assert exact
  bytes, not just structural equivalence.

### Error Handling

- Use a structured error enum or small tagged error type instead of bare strings.
- Cover at least these categories:
  - truncated input
  - invalid varint
  - invalid fixed bit
  - invalid reserved bits
  - unsupported packet type
  - unknown frame type
  - non-shortest frame type encoding
  - packet length mismatch
  - frame not allowed in packet type
  - malformed short-header context
- Errors in this layer are codec failures, not full transport connection errors.
  Higher layers can later map them to QUIC error codes where appropriate.

### File Layout

- Add focused QUIC modules under `src/quic/`:
  - `src/quic/varint.h`
  - `src/quic/varint.cpp`
  - `src/quic/buffer.h`
  - `src/quic/buffer.cpp`
  - `src/quic/frame.h`
  - `src/quic/frame.cpp`
  - `src/quic/packet.h`
  - `src/quic/packet.cpp`
  - `src/quic/plaintext_codec.h`
  - `src/quic/plaintext_codec.cpp`
- Export the codec through a project-facing include so later transport code can
  use it without pulling in unrelated starter helpers.
- Update `build.zig` so the project library compiles the new QUIC sources and
  the test binary builds the dedicated codec tests.

### Testing

- Add dedicated GoogleTest coverage for:
  - varint boundaries and round trips
  - every core frame type
  - `STREAM`, `ACK`, and `CONNECTION_CLOSE` flag variants
  - each packet type
  - coalesced datagrams containing multiple long-header packets
  - `OneRtt` deserialization with caller-supplied destination connection ID
    length
  - invalid frame/packet combinations
  - non-shortest frame type encoding rejection
  - packet truncation and length mismatch handling
- Prefer exact byte fixtures for serializer tests and structural equality checks
  for parser round-trip tests.
- Keep the first implementation strict and deterministic so later crypto work
  can rely on a stable plaintext boundary.

## Verification

The completed implementation must pass:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build
nix develop -c zig build test
nix develop -c zig build coverage
```
