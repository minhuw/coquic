# Protected Packet Direct Writer Design

## Goal

Reduce packet-assembly overhead in QUIC protected packet serialization by replacing incremental
`std::vector<std::byte>` growth with fixed-size direct writes across all protected packet types,
without changing wire behavior, error behavior, or public serializer APIs.

## Current State

The current local bulk-download benchmark for the CI-shaped case on this branch remains dominated
by crypto plus packet-assembly work. A fresh sampled run of the exact local harness measured:

- throughput: `57.003 MiB/s`
- `_aesni_ctr32_ghash_6x`: `38.05%`
- `append_protected_one_rtt_packet_to_datagram`: `5.67%`
- `memmove`: `4.84%`
- `malloc`: `2.57%`
- `append_bytes`: `2.32%`
- `encode_varint_into`: `2.17%`
- `append_stream_frame_payload_into`: `2.10%`

The dominant non-crypto cost is now protected packet assembly in
[protected_codec.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/protected_codec.cpp):

1. Protected packet serializers build packet plaintext through repeated `push_back`, `insert`,
   `resize`, and helper-driven byte appends into a growable datagram vector.
2. STREAM-heavy paths pay additional overhead in
   `append_stream_frame_payload_into(...)` for small header writes, payload insertion, and vector
   growth bookkeeping even when the final size is already knowable.
3. Varint helpers are called repeatedly into temporary arrays or growing vectors instead of writing
   directly into a final packet span.

This work follows the earlier shared-buffer send changes, which reduced pre-serialization churn but
left packet assembly as the largest remaining transport-side hotspot cluster.

## Non-Goals

- No change to QUIC wire format, packet semantics, ACK behavior, recovery logic, congestion control,
  or key update behavior.
- No change to AEAD sealing or header protection algorithms.
- No public API redesign for `serialize_protected_datagram(...)`,
  `serialize_protected_datagram_with_metadata(...)`, or
  `append_protected_one_rtt_packet_to_datagram(...)`.
- No broad refactor of all plaintext frame or packet serializers outside the protected packet
  assembly path.
- No attempt to optimize kernel send path, UDP batching, or crypto cost in this pass.

## Design Summary

Keep the existing protected serializer entry points, but replace the internal “append into a
growable vector” strategy with a fixed-size direct-writer strategy.

Each protected packet serializer will:

1. validate exactly as it does today
2. compute the exact plaintext or wire size up front
3. extend the output datagram once for the full packet span
4. write packet bytes directly into that final span using a cursor writer over
   `std::span<std::byte>`
5. run AEAD seal and header protection in place
6. roll back to the original datagram size on any failure

This applies across all protected packet types: Initial, Handshake, 0-RTT, and 1-RTT.

## Detailed Design

### 1. Introduce a fixed-size span writer

Add a packet-local writer in:

- [buffer.h](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/buffer.h)
- [buffer.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/buffer.cpp)

This writer will:

- own no memory
- advance through `std::span<std::byte>`
- provide checked `write_byte(...)`
- provide checked `write_bytes(...)`
- expose current offset or remaining space
- support direct varint writes into the output span

It is intentionally narrow in scope: it exists to assemble already-sized packet spans without any
allocation or growth policy.

### 2. Reuse frame serialization logic across writer types

Today [frame.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/frame.cpp)
already centralizes frame serialization through `serialize_frame_into(BufferWriter&, ...)`.

This pass extends that pattern instead of forking frame logic:

- frame serialization should be able to target either the existing growable `BufferWriter` or the
  new fixed-size span writer
- the same serialization logic body should be shared so wire bytes and error behavior remain
  identical
- frame-size helpers should be added only where required to make exact packet sizing possible

The direct-writer path should not create a second independent frame codec.

### 3. Add exact size accounting for protected packet assembly

Protected packet assembly in
[protected_codec.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/protected_codec.cpp)
needs exact up-front sizing before writing.

That size accounting must cover:

- long-header fixed fields
- connection ID bytes
- Initial token bytes and token-length encoding
- long-header payload-length encoding for Initial, Handshake, and 0-RTT packets
- packet number bytes
- serialized frame sizes for non-stream frames
- STREAM frame header sizes plus payload sizes for stream-view and fragment-view paths
- minimum plaintext size requirements for header-protection sampling
- AEAD tag length

The existing STREAM-specific size helper `encoded_stream_frame_payload_size(...)` can be reused or
adapted, but all protected packet types need a complete exact-size path before packet bytes are
written.

### 4. Replace incremental packet assembly with direct writes

Each protected packet serializer should move to the same internal pattern:

1. compute exact packet span size
2. resize the destination datagram once for the packet’s maximum protected size
3. carve out the packet span from the datagram
4. use the span writer to serialize plaintext header and frame bytes directly into the final span
5. seal the plaintext payload into the same packet span
6. shrink the packet span to the exact ciphertext-plus-tag length returned by AEAD sealing
7. apply header protection in place

This replaces the current repeated `push_back`, `insert`, and helper-level vector appends.

### 5. Preserve current per-packet behavior

This refactor is about write strategy only. The following behavior must remain unchanged:

- Initial minimum datagram and plaintext padding rules
- long-header layout and length-field patching
- short-header packet-number and header-protection sample rules
- coalesced datagram packet ordering
- `serialize_protected_datagram_with_metadata(...)` offsets and lengths
- rollback-on-failure behavior
- packet-type-specific frame allowlists and validation
- existing error-code surface for invalid frames, invalid context, and crypto faults

## Components

### Span Writer

Responsibility:

- direct writing into pre-sized byte spans

Files:

- [buffer.h](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/buffer.h)
- [buffer.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/buffer.cpp)

### Shared Frame Serializer Surface

Responsibility:

- write the same frame bytes through either an owning writer or a span writer

Files:

- [frame.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/frame.cpp)
- [frame.h](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/frame.h)

### Protected Packet Size Accounting

Responsibility:

- exact plaintext and wire sizing before serialization

Files:

- [protected_codec.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/protected_codec.cpp)
- [protected_codec.h](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/protected_codec.h)

### Protected Packet Assembly

Responsibility:

- direct-write plaintext assembly and in-place protection for Initial, Handshake, 0-RTT, and 1-RTT

Files:

- [protected_codec.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/src/quic/protected_codec.cpp)

## Data Flow And Error Handling

For each protected packet type, the serializer will:

1. validate packet invariants and crypto context
2. compute exact plaintext or wire size
3. remember the original datagram size for rollback
4. resize the datagram once to the packet’s maximum protected size
5. direct-write the plaintext header and frame bytes into the packet span
6. run AEAD sealing in place over the plaintext payload portion
7. shrink the packet span to the exact ciphertext-plus-tag length returned by AEAD sealing
8. apply header protection in place
9. return the final packet length

On any failure after resizing, the serializer must roll the datagram back to its original size.
This matches the current failure contract and prevents partial packet bytes from leaking into the
output datagram.

## Testing Strategy

Use the existing protected codec suite in
[tests/core/packets/protected_codec_test.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/tests/core/packets/protected_codec_test.cpp)
as the primary regression harness.

### Existing coverage to preserve

- RFC 9001 Initial exact-byte serialization vector
- round-trip protected serialization and deserialization for Initial, Handshake, 0-RTT, and 1-RTT
- one-RTT append-into-existing-datagram behavior for owned, view, and fragment-view packet paths
- metadata parity for coalesced and appended protected datagrams
- seal, header-protection, and plaintext-decode fault propagation

### New focused coverage to add

- parity tests for direct-write protected packet assembly paths against full-vector serialization
- exact-size and rollback tests for the new span writer and packet assembly flow
- a coalesced protected datagram regression that verifies metadata offsets still match actual packet
  layout after the direct-write refactor
- any packet-type-specific regression needed if size accounting differs across Initial, Handshake,
  0-RTT, and 1-RTT

## Verification Plan

After implementation, run:

- a focused protected codec test slice under
  [tests/core/packets/protected_codec_test.cpp](/home/minhu/projects/coquic/.worktrees/perf-bulk-shared-send/tests/core/packets/protected_codec_test.cpp)
- `nix develop -c zig build test`
- `nix develop -c zig build -Doptimize=ReleaseFast`
- the same local bulk-download harness used for `.github/workflows/perf.yml`
- a fresh server-side `perf` sample

Success criteria:

- all protected codec regressions remain green
- no wire-visible behavior changes
- packet-metadata behavior remains unchanged
- the packet-assembly hotspot cluster drops relative to the current profile
- local bulk-download throughput improves measurably or, at minimum, the non-crypto packet
  assembly share falls clearly in the perf profile

## Risks

### Size miscalculation

If the exact-size computation is wrong, direct writes can overflow or force incorrect rollback.
This is mitigated by keeping sizing and writing logic tightly coupled and adding rollback and parity
tests.

### Serializer drift

If growable and fixed-size writers serialize frames differently, wire behavior could diverge. This
is mitigated by reusing shared frame serialization logic rather than maintaining separate code paths.

### Broader blast radius

Applying the new strategy across all protected packet types touches more code than a 1-RTT-only
optimization. This is intentional because the agreed scope is all protected packet types, but it
raises the importance of broad protected codec regression coverage.

## Decision

Proceed with a fixed-size direct-writer refactor for all protected packet serializers. This is the
best match for the current hotspot evidence: it directly attacks packet-assembly overhead without
changing protocol behavior or widening the work into a full codec redesign.
