# Bulk Receive Zero-Copy Design

## Goal

Improve the `coquic-perf` bulk-download case used by [perf.yml](/home/minhu/projects/coquic/.github/workflows/perf.yml) by removing avoidable payload allocation and copy work from the protected-packet receive path, without changing QUIC wire behavior, TLS sequencing, or the external stream-delivery API.

## Current State

The current local bulk-download benchmark for the CI-aligned case:

- server: `./zig-out/bin/coquic-perf server --io-backend socket`
- client: `./zig-out/bin/coquic-perf client --mode bulk --direction download --response-bytes 1048576 --streams 4 --connections 1 --requests-in-flight 1 --warmup 0ms --duration 5s`

measured on the current local baseline:

- plain runs around `75-76 MiB/s`
- sampled throughput during `perf record`: `76.529 MiB/s`

The latest server-side `perf` sample shows:

- `_aesni_ctr32_ghash_6x`: `11.50%`
- `memcpy`: `9.45%`
- `_int_malloc`: `3.95%`
- `malloc`: `3.89%`
- `memset`: `2.86%`
- `_int_free`: `2.49%`
- `cfree@GLIBC_2.2.5`: `2.42%`
- `deserialize_frame`: `1.01%`
- `append_varint<SpanBufferWriter>`: `0.92%`
- `process_inbound_application_owned`: `0.88%`

The fixable receive-side overhead is still concentrated in payload ownership churn:

1. [protected_codec.cpp](/home/minhu/projects/coquic/src/quic/protected_codec.cpp) decrypts each protected packet into a fresh plaintext packet image.
2. [packet.cpp](/home/minhu/projects/coquic/src/quic/packet.cpp) and [frame.cpp](/home/minhu/projects/coquic/src/quic/frame.cpp) decode that image through the generic send/serialize-oriented `Frame` model.
3. `deserialize_frame()` materializes `CryptoFrame::crypto_data` and `StreamFrame::stream_data` as per-frame `std::vector<std::byte>`.
4. [connection.cpp](/home/minhu/projects/coquic/src/quic/connection.cpp) immediately hands those payloads to [crypto_stream.cpp](/home/minhu/projects/coquic/src/quic/crypto_stream.cpp), where out-of-order buffering still copies into `std::map<std::uint64_t, std::vector<std::byte>>`.

This means the protected receive path still pays unnecessary allocation and copy cost before application delivery, even though the decrypted packet image already contains the bytes we need.

## Non-Goals

- No change to QUIC packet formats, ACK behavior, recovery semantics, congestion control, or flow-control accounting.
- No send-side refactor of the existing `Frame` type or serializer behavior.
- No change to qlog snapshot representation in this pass.
- No borrowed-data exposure through `QuicCoreReceiveStreamData` in this pass.
- No attempt to eliminate AEAD cost or the final application-delivery copy yet.

## Design Summary

Add a parallel receive-only decode pipeline for protected packets. The new path decodes frame metadata directly from the decrypted packet image and represents stream and crypto payloads as `SharedBytes` views into packet-owned plaintext storage. Upgrade `ReliableReceiveBuffer` to retain shared-backed segments so out-of-order receive buffering no longer clones payload bytes into fresh vectors. Keep the send/serialize `Frame` model and external receive API unchanged.

## Detailed Design

### 1. Add a receive-only frame representation

Keep the existing `Frame` variant unchanged for send, serialization, tests, and qlog. Add a parallel receive-only variant in [frame.h](/home/minhu/projects/coquic/src/quic/frame.h) and [frame.cpp](/home/minhu/projects/coquic/src/quic/frame.cpp).

Structure:

- reuse the existing small control-frame structs where ownership is trivial
- introduce `ReceivedCryptoFrame` with:
  - `offset`
  - `SharedBytes crypto_data`
- introduce `ReceivedStreamFrame` with:
  - `fin`
  - `has_offset`
  - `has_length`
  - `stream_id`
  - `offset`
  - `SharedBytes stream_data`
- define `ReceivedFrame` as a receive-only `std::variant<...>`
- add `ReceivedFrameDecodeResult`
- add `deserialize_received_frame(...)`

`deserialize_received_frame(...)` must preserve the existing validation behavior and error offsets from `deserialize_frame(...)`, but when it encounters stream or crypto payload bytes it should return `SharedBytes` subspans referencing the packet-owned plaintext storage rather than allocating a new `std::vector<std::byte>`.

### 2. Add receive-only protected packet decode types

The protected-packet receive path should stop round-tripping through the generic plaintext packet structs that are optimized for send-side ownership.

In [protected_codec.h](/home/minhu/projects/coquic/src/quic/protected_codec.h) and [protected_codec.cpp](/home/minhu/projects/coquic/src/quic/protected_codec.cpp):

- add receive-only protected packet structs parallel to the current `ProtectedInitialPacket`, `ProtectedHandshakePacket`, `ProtectedZeroRttPacket`, and `ProtectedOneRttPacket`
- each receive-only protected packet owns the decrypted plaintext storage for its payload lifetime
- each receive-only protected packet exposes `std::vector<ReceivedFrame>` instead of `std::vector<Frame>`

Recommended ownership model:

- keep the decrypted plaintext bytes in packet-owned shared storage
- decode payload-bearing frames as `SharedBytes` subranges of that storage
- keep the receive-only protected packet alive only until inbound processing completes

The deserializers for Initial, Handshake, 0-RTT, and 1-RTT should build these receive-only packet objects directly from the decrypted packet image. This ensures the zero-copy benefit applies across all protected packet spaces from the start, not only application packets.

### 3. Upgrade `ReliableReceiveBuffer` to preserve shared-backed segments

The current receive buffer stores buffered out-of-order data as `std::map<std::uint64_t, std::vector<std::byte>>`, which forces a copy even when the source bytes are already in durable packet-owned shared storage.

In [crypto_stream.h](/home/minhu/projects/coquic/src/quic/crypto_stream.h) and [crypto_stream.cpp](/home/minhu/projects/coquic/src/quic/crypto_stream.cpp):

- replace buffered receive storage with shared-backed segments
- add `push(std::uint64_t offset, SharedBytes bytes)`
- preserve the current span and vector overloads as convenience wrappers
- when buffering out-of-order bytes, store trimmed `SharedBytes` segments directly instead of cloning into new vectors
- when contiguous delivery spans a single backing store, allow the fast path to forward that storage without intermediate copy inside the receive buffer
- when contiguous delivery spans multiple unrelated backing stores, coalesce only at the point where a single `std::vector<std::byte>` result is required

This design still allows overlap trimming and duplicate suppression to work as today, but the receive buffer becomes responsible for retaining the shared ownership needed after packet-local processing returns.

### 4. Add receive-only inbound processors in `QuicConnection`

In [connection.h](/home/minhu/projects/coquic/src/quic/connection.h) and [connection.cpp](/home/minhu/projects/coquic/src/quic/connection.cpp):

- keep the existing `process_inbound_crypto(std::span<const Frame>)` and `process_inbound_application(std::span<const Frame>)` entry points if still needed by tests or helper code
- add receive-only inbound paths over `std::span<const ReceivedFrame>`
- route protected-packet receive through the new receive-only entry points

Processing rules:

- ACK, ping, connection close, path validation, and control frames keep the same behavior as today
- crypto payload ingestion passes borrowed spans from `SharedBytes` directly into TLS or into `ReliableReceiveBuffer`
- stream payload ingestion pushes `SharedBytes` directly into `ReliableReceiveBuffer`
- stream final-size validation, flow-control accounting, and FIN delivery remain unchanged

The main behavioral difference is ownership, not protocol semantics.

### 5. Keep the external stream-delivery API unchanged in the first cut

`QuicCoreReceiveStreamData` in [core.h](/home/minhu/projects/coquic/src/quic/core.h) should remain:

- `stream_id`
- `std::vector<std::byte> bytes`
- `fin`

This means:

- internal receive processing can stay zero-copy for packet decode and out-of-order buffering
- the final boundary where the connection hands bytes to the external caller can still materialize a vector
- no borrowed packet-owned storage escapes the connection API in this pass

This keeps the API blast radius low and limits correctness risk while still removing the most obvious receive-path allocation hotspots.

## Correctness Constraints

- `ReceivedFrame` decode must preserve the same frame-type allowlists and error offsets as the current generic decode path.
- Stream and crypto offset overflow validation must remain identical.
- TLS must still receive contiguous bytes in order only.
- `ReliableReceiveBuffer` must retain shared ownership for any bytes that outlive packet-local processing.
- Overlap trimming and duplicate suppression must remain byte-for-byte compatible with the existing receive-buffer behavior.
- Final-size and receive-flow-control accounting must not depend on ownership representation.

## Testing Strategy

### Unit and focused regression coverage

Add or update tests for:

- `deserialize_received_frame(...)` decoding stream and crypto payloads as aliases of packet storage instead of copied vectors
- protected packet deserializers for Initial, Handshake, 0-RTT, and 1-RTT using receive-only frames
- `ReliableReceiveBuffer` contiguous fast path for `SharedBytes`
- out-of-order shared-backed buffering
- overlap trimming and duplicate suppression with shared-backed segments
- multi-segment contiguous coalescing
- application stream receive and crypto receive behavior staying wire-compatible with the current path

### Verification commands

Run:

- `nix develop -c zig build -Doptimize=ReleaseFast`
- the focused QUIC tests already used during this perf investigation:
  - recovery
  - varint/buffer
  - protected codec
  - core stream exchange
  - crypto stream receive behavior
- the local bulk-download harness used for the current perf baseline
- a fresh `sudo perf record` sample on the server side after the change

Success criteria:

- all focused tests stay green
- bulk-download throughput beats the current `75-76 MiB/s` baseline
- allocator and payload-copy symbols drop relative to the current profile
- `deserialize_frame` and receive-buffer copy work shrink in the new samples

## Risks

### Lifetime bugs

If a `SharedBytes` view outlives the packet-owned storage it references, receive processing could read invalid memory. This is mitigated by requiring the receive buffer to adopt shared ownership for any buffered bytes and by keeping borrowed payloads inside connection processing only.

### Representation drift

Adding a parallel receive-only frame and protected-packet representation can drift from the send-side `Frame` path over time. This is mitigated by keeping the new representation limited to protected receive and by reusing the existing small frame structs where possible.

### Limited end-to-end upside

The final application-delivery boundary still returns `std::vector<std::byte>`, and AEAD remains a large bucket. This change should therefore be treated as a targeted receive-path cost reduction, not a complete zero-copy receive design.

## Decision

Proceed with a receive-only protected-packet decode pipeline plus shared-backed receive buffering. This is the lowest-risk deeper data-structure change that directly attacks the current bulk-download receive hotspot cluster while keeping send-side behavior and public APIs stable.
