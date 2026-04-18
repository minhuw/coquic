# Bulk ACK Fast Path Design

## Goal

Improve the `.github/workflows/perf.yml` bulk-download workload by aggressively reducing ACK-path CPU on both sides of the transfer, without changing QUIC wire behavior, ACK semantics, recovery decisions, or observable correctness.

This pass is explicitly optimized for the CI-shaped bulk download case driven by
[perf.yml](/home/minhu/projects/coquic/.github/workflows/perf.yml) and
[bench/run-host-matrix.sh](/home/minhu/projects/coquic/bench/run-host-matrix.sh).
`rr` and `crr` do not need to improve in this pass, but protocol correctness and existing tests must continue to hold.

## Current State

The current CI bulk-transfer tuple is:

- backend: `socket`
- mode: `bulk`
- direction: `download`
- request bytes: `0`
- response bytes: `1048576`
- streams: `4`
- connections: `1`
- requests in flight: `1`
- warmup: `5s`
- duration: `60s`

Fresh local host runs of the same shape using `coquic-perf` measured about `73-77 MiB/s`.

Fresh `perf` samples on the current branch show that the bottleneck has moved out of the old packet-assembly hotspot cluster and into ACK processing:

### Server-side steady-state sample

- `PacketSpaceRecovery::on_ack_received`: about `13.99%` self
- `_aesni_ctr32_ghash_6x`: about `12.59%` self
- `decode_varint`: about `5.26%` self
- `decode_ack_frame`: about `8.58%` children
- `ack_frame_packet_number_ranges`: about `1.24%` self

### Client-side steady-state sample

- `encode_varint_into`: about `16.36%` self
- `CountingBufferWriter::write_varint`: about `10.66%` self
- `SpanBufferWriter::write_varint`: about `8.29%` self
- `serialized_frame_size`: about `4.48%` self and `25.85%` children
- `ReceivedPacketHistory::build_ack_frame`: about `3.56%` self

The main fixable costs are:

1. ACK receive allocates and reshapes decoded ranges before recovery can use them.
2. ACK receive sorts ranges even though the wire format is already structured.
3. ACK send materializes an `AckFrame` with `additional_ranges`, then re-walks it for size accounting and then re-walks it again for actual serialization.
4. The generic varint writer path performs unnecessary byte writes in counting-only cases.

## Non-Goals

- No change to QUIC packet formats, ACK semantics, delayed-ACK policy, recovery thresholds, congestion control, or flow-control behavior.
- No change to TLS, AEAD, or header-protection algorithms.
- No benchmark-specific protocol shortcuts such as intentionally sending fewer ACKs than the existing policy requires.
- No requirement that `rr` or `crr` improve in this pass.
- No broad redesign of the entire frame model beyond what is needed for an ACK-specific fast path.

## Design Summary

Add dedicated ACK fast paths for both receive and send:

1. Decode ACK ranges into a lightweight receive-side representation that recovery can consume directly, without building an intermediate `std::vector<AckPacketNumberRange>` and without sorting.
2. Serialize ACK frames directly from `ReceivedPacketHistory` or an equivalent range view during packet assembly, without first materializing `AckFrame.additional_ranges` and without using the generic double-pass frame serializer for ACK frames.
3. Tighten the writer helpers so counting-only varint writes avoid byte-generation work.

The generic `AckFrame` path remains as the compatibility reference for tests and fallback behavior while the fast path is introduced.

## Detailed Design

### 1. Add a receive-only ACK range view

Today ACK receive takes this path:

1. decode ACK frame fields into `AckFrame`
2. expand that into `std::vector<AckPacketNumberRange>`
3. copy the ranges again inside `PacketSpaceRecovery::on_ack_received(...)`
4. sort them descending
5. walk live recovery slots against the sorted ranges

This creates avoidable allocation and reorder work on the server hot path.

Add a lightweight ACK range iterator or view that can expose ACK ranges in descending order directly from the decoded ACK representation. The receive fast path should:

- preserve all existing ACK validation behavior
- preserve existing error offsets
- avoid allocating `std::vector<AckPacketNumberRange>` in the steady-state case
- avoid sorting when the ranges are already available in descending ACK order

`PacketSpaceRecovery::on_ack_received(...)` should gain an overload or internal helper that consumes this direct ACK range view.

### 2. Remove ACK receive-path sorting and redundant buffering

In
[recovery.cpp](/home/minhu/projects/coquic/src/quic/recovery.cpp),
`PacketSpaceRecovery::on_ack_received(...)` currently copies the input ranges into
`ack_ranges_descending`, sorts them, buffers acked packets in temporary vectors, and then copies
them again into `AckProcessingResult`.

This pass should aggressively trim those steps:

- consume ranges in the required order directly
- avoid the extra sort
- reduce temporary vector churn where result shapes are already known or append order can be controlled directly

The result format of `AckProcessingResult` does not need to change externally, but the internal algorithm should stop paying for transformations that are not needed in the common bulk-transfer case.

### 3. Add an ACK send fast path

Today ACK send takes this path:

1. `ReceivedPacketHistory::build_ack_frame(...)` builds an owned `AckFrame`
2. packet assembly calls `serialized_frame_size(...)` on that `AckFrame`
3. packet assembly calls `serialize_frame_into(...)` on that same `AckFrame`
4. both size and serialize paths run through the generic varint-heavy frame serializer

This makes the client spend a large amount of CPU on ACK bookkeeping instead of stream data movement.

Add an ACK-specific fast path that:

- exposes the current received-packet ranges without materializing `additional_ranges`
- computes encoded ACK size directly from those ranges
- writes ACK bytes directly into the packet payload span during protected packet assembly
- preserves the exact wire encoding produced by the current generic ACK serializer

This fast path should be used only when serializing ACK frames. Other frame types can continue using the generic serializer.

### 4. Special-case ACK frame sizing and writing in protected packet assembly

In
[protected_codec.cpp](/home/minhu/projects/coquic/src/quic/protected_codec.cpp),
packet assembly currently uses the generic `serialized_frame_size(...)` plus `serialize_frame_into(...)`
path for all frames.

For ACK frames:

- bypass the generic frame serializer
- compute size directly from ACK ranges
- write bytes directly into the final payload span

For non-ACK frames:

- keep the current path unchanged in this pass

This isolates the aggressive optimization to the hotspot type instead of refactoring all frame serialization again.

### 5. Tighten varint and counting-writer hot paths

The current counting writer calls `encode_varint_into(...)`, which fully emits bytes into a temporary array even when only the encoded length is needed.

This pass should:

- make `CountingBufferWriter::write_varint(...)` advance by encoded size directly
- keep checked error behavior for invalid values
- avoid temporary byte arrays for counting-only writes

If profiling still shows meaningful varint overhead after the ACK fast path lands, small follow-up cleanups to `SpanBufferWriter` and direct ACK writing helpers are allowed, as long as wire bytes remain unchanged.

### 6. Keep the generic ACK path as the correctness reference

The optimization is intentionally aggressive, so the existing generic path should remain available for:

- unit tests comparing bytes against the old serializer
- differential verification during development
- easier rollback if the fast path exposes a correctness gap

This is an implementation guardrail, not a second production codepath that must remain on the hot path.

## Components

### ACK Receive Fast Path

Responsibilities:

- decode ACK ranges without intermediate range vectors
- feed recovery with direct descending range traversal

Files:

- [frame.cpp](/home/minhu/projects/coquic/src/quic/frame.cpp)
- [frame.h](/home/minhu/projects/coquic/src/quic/frame.h)
- [recovery.cpp](/home/minhu/projects/coquic/src/quic/recovery.cpp)
- [recovery.h](/home/minhu/projects/coquic/src/quic/recovery.h)

### ACK Send Fast Path

Responsibilities:

- expose received ranges for ACK emission
- size and serialize ACK frames directly from packet history

Files:

- [recovery.cpp](/home/minhu/projects/coquic/src/quic/recovery.cpp)
- [recovery.h](/home/minhu/projects/coquic/src/quic/recovery.h)
- [protected_codec.cpp](/home/minhu/projects/coquic/src/quic/protected_codec.cpp)

### Writer Tightening

Responsibilities:

- remove counting-only varint byte generation
- keep checked size and error behavior intact

Files:

- [buffer.cpp](/home/minhu/projects/coquic/src/quic/buffer.cpp)
- [buffer.h](/home/minhu/projects/coquic/src/quic/buffer.h)
- [varint.cpp](/home/minhu/projects/coquic/src/quic/varint.cpp)

## Data Flow

### ACK Receive

1. parse ACK fields from incoming frame bytes
2. expose descending ACK ranges directly
3. hand those ranges to recovery without sorting
4. apply the same recovery bookkeeping and loss logic as today

### ACK Send

1. inspect `ReceivedPacketHistory` ranges
2. compute exact ACK wire size directly
3. write ACK bytes into the final packet payload span
4. continue packet protection and transmission exactly as today

## Correctness Constraints

- ACK wire bytes must remain byte-for-byte identical to the current generic serializer for the same packet history.
- Recovery decisions, including newly acknowledged packets and declared losses, must remain behaviorally identical to the current path.
- ACK validation and error offsets must remain compatible with the current frame decoder.
- No ACK policy change is allowed in this pass.
- The fast path must not change packet ordering, packet protection, or metadata offsets.

## Testing Strategy

### Unit and focused regression coverage

Add or update tests for:

- ACK decode fast path producing the same descending ranges as the current `ack_frame_packet_number_ranges(...)`
- recovery ACK processing producing the same `AckProcessingResult` for representative ACK patterns
- ACK encode fast path producing the same bytes as the current generic frame serializer
- edge cases: single range, multiple gaps, ECN ACKs, invalid ranges, large varints, out-of-order ranges, and duplicate acknowledgments
- protected packet assembly still producing identical packet bytes when ACK frames are present

### Verification commands

Run:

- `nix develop -c zig build -Doptimize=ReleaseFast`
- `nix develop -c zig build test`
- focused perf-relevant tests if faster iteration is needed before the full suite:
  - frame
  - recovery
  - protected codec
  - perf tests that cover bulk behavior

### Performance verification

Re-run the CI-shaped bulk-download workload and compare against the current local baseline:

- server on CPU `2`
- client on CPU `3`
- `--mode bulk --direction download --response-bytes 1048576 --streams 4 --connections 1 --requests-in-flight 1 --warmup 5s --duration 20s`

Take fresh `perf` samples on both server and client after the change.

Success criteria:

- focused and full tests pass
- bulk-download throughput improves measurably over the current local baseline
- server-side ACK receive share drops clearly
- client-side ACK build and varint serialization share drops clearly

## Risks

### Wire-compatibility drift

The ACK fast path could accidentally change encoded ACK bytes. This is mitigated by keeping the old generic serializer as the byte-reference during tests.

### Recovery behavior drift

Removing temporary structures and sorting could subtly change edge-case range handling. This is mitigated by differential tests against the current implementation and by preserving the same descending-range semantics.

### Local maximum optimization

This pass is tuned for the bulk-download benchmark and may not materially improve other benchmark shapes. That is acceptable for this task as long as correctness remains intact.

## Decision

Proceed with an aggressive ACK fast-path rewrite that targets both:

- server-side ACK receive and recovery overhead
- client-side ACK build and serialization overhead

This is the highest-leverage optimization left in the current bulk-transfer profile that can be attacked without changing protocol behavior.
