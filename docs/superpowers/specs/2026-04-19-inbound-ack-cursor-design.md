# Inbound ACK Cursor Design

## Goal

Reduce server-side ACK receive CPU in the `coquic-perf` bulk-download workload by removing
materialized inbound ACK range storage from the hot path, without changing QUIC wire behavior,
malformed-frame handling, recovery decisions, congestion outcomes, or interoperability.

This pass follows the kept recovery fast-result work on `main` and targets the next measured ACK
receive hotspot: inbound ACK decode and range shaping before recovery consumes the ranges.

## Current State

Fresh host-direct profiling on `main` measured the profiled workload at about `173.617 MiB/s`.
The profiled server remains the limiting side, with roughly one fully saturated core while the
client stays below that level.

The current merged-main server profile shows:

- `_aesni_ctr32_ghash_6x`: `29.36%`
- ACK receive decode and apply union: about `16.08%`
- send path union: about `10.67%`

Within the ACK receive bucket, the current decode path still performs avoidable work:

1. [`deserialize_frame`](/home/minhu/projects/coquic/src/quic/frame.cpp#L1129) decodes ACK frames
   into an owned [`AckFrame`](/home/minhu/projects/coquic/src/quic/frame.h#L33).
2. [`decode_ack_frame`](/home/minhu/projects/coquic/src/quic/frame.cpp#L282) appends each decoded
   additional range into `AckFrame.additional_ranges`.
3. [`QuicConnection::process_inbound_ack`](/home/minhu/projects/coquic/src/quic/connection.cpp#L3750)
   immediately rebuilds an [`AckRangeCursor`](/home/minhu/projects/coquic/src/quic/frame.h#L63)
   from that owned vector before handing the ranges to recovery.

That means inbound ACK receive still pays for:

- allocating and populating `additional_ranges`
- preserving an owned representation that the hot path does not need
- a second ACK-range setup step before recovery starts walking ranges

The previous fast-result change reduced recovery-side shaping cost, but it did not remove this
decode-side materialization.

## Non-Goals

- No change to ACK wire encoding.
- No change to malformed ACK rejection or error offsets.
- No change to generic outbound ACK serialization.
- No change to loss-threshold or congestion-control policy.
- No benchmark-specific weakening of ACK processing.
- No direct attempt in this pass to reduce crypto or UDP send cost.

## Design Summary

Introduce a receive-only inbound ACK representation that stores validated header fields and a view
into the encoded additional-range bytes instead of an owned `std::vector<AckRange>`.

The inbound hot path then becomes:

1. decode ACK header fields once
2. validate additional ranges while scanning the encoded bytes
3. retain only the minimal state needed to walk those ranges later
4. hand that receive-only representation directly to connection/recovery

The existing `AckFrame` remains as the owned compatibility representation for generic helpers and
tests that need a materialized range vector.

## Detailed Design

### 1. Add a receive-only ACK representation

In [frame.h](/home/minhu/projects/coquic/src/quic/frame.h), add a new inbound-only ACK type for
received frames. It should contain:

- `largest_acknowledged`
- `ack_delay`
- `first_ack_range`
- a `SharedBytes` or byte-span-backed view covering the encoded additional ranges
- the validated additional-range count
- optional ECN counts

The type must be self-contained enough that callers can safely iterate ranges after frame decode
returns, without copying additional range entries into an owned vector.

### 2. Decode inbound ACK frames without materializing `additional_ranges`

In [frame.cpp](/home/minhu/projects/coquic/src/quic/frame.cpp), add a dedicated inbound ACK decode
helper used by received-frame decoding.

That helper should:

- parse `largest_acknowledged`, `ack_delay`, `ack_range_count`, and `first_ack_range`
- validate every additional range exactly as the current `decode_ack_frame(...)` path does
- preserve current failure codes and offsets
- avoid `std::vector<AckRange>` growth on the hot receive path

During validation, it should walk the encoded additional-range bytes once, confirm each range is
well-formed, and record the subspan needed for later iteration.

### 3. Add a byte-backed inbound ACK cursor

Add a lightweight cursor or iterator helper that can walk validated ACK ranges directly from the
stored encoded bytes in descending wire order.

This cursor should expose the same logical `AckPacketNumberRange` sequence that recovery consumes
today, but it must not require materializing `AckRange` objects or a
`std::vector<AckPacketNumberRange>`.

The cursor is receive-only. It does not need to support generic owned-frame mutation or outbound
serialization use cases.

### 4. Route received ACK processing through the inbound representation

Update [connection.cpp](/home/minhu/projects/coquic/src/quic/connection.cpp#L3750) and any nearby
received-frame dispatch needed so the received ACK path consumes the new inbound ACK representation
directly instead of:

- decoding to `AckFrame`
- calling `make_ack_range_cursor(const AckFrame &)`
- rebuilding state from `additional_ranges`

Recovery should still receive descending ACK ranges and should not need to know whether they came
from owned ranges or an inbound byte-backed cursor.

### 5. Keep the owned `AckFrame` path as the compatibility reference

The current owned `AckFrame` decode and helpers stay available for code that actually needs a
materialized ACK object:

- serialization helpers
- generic frame utilities
- existing compatibility-style tests

If useful, the owned path can be reimplemented on top of the new inbound parser plus explicit
materialization, but the hot receive path must no longer pay for that materialization by default.

### 6. Preserve shared semantics across both paths

The inbound byte-backed path and owned `AckFrame` path must agree on:

- accepted and rejected ACK encodings
- emitted `AckPacketNumberRange` sequence
- ECN counts
- `largest_acknowledged` and `first_ack_range` semantics

This keeps the new path aggressive on allocation cost without creating a second set of protocol
rules.

## Components

### Inbound ACK decode

Responsibilities:

- parse and validate received ACK frame fields
- retain byte-backed additional-range state without owned range vectors

Files:

- [frame.h](/home/minhu/projects/coquic/src/quic/frame.h)
- [frame.cpp](/home/minhu/projects/coquic/src/quic/frame.cpp)

### ACK receive integration

Responsibilities:

- dispatch received ACK frames through the byte-backed representation
- feed recovery with descending ranges directly

Files:

- [connection.cpp](/home/minhu/projects/coquic/src/quic/connection.cpp)
- [recovery.h](/home/minhu/projects/coquic/src/quic/recovery.h)
- [recovery.cpp](/home/minhu/projects/coquic/src/quic/recovery.cpp)

## Correctness Constraints

- Received ACK decode must preserve current rejection behavior and offsets.
- The new cursor must yield the same descending packet-number ranges as the current owned path.
- Recovery, RTT updates, ECN accounting, loss handling, PTO reset, and interop behavior must remain
  unchanged.
- Generic owned `AckFrame` behavior must remain available as a correctness reference.

## Testing Strategy

Add or update focused tests for:

- inbound ACK decode preserving sparse multi-range semantics without owned range materialization
- parity between the owned `AckFrame` cursor and the inbound byte-backed cursor on the same wire
  bytes
- malformed ACK range encodings still failing with the same error code and offset
- connection ACK processing preserving recovery behavior when driven by the new inbound path

Verification commands:

- `nix develop -c zig build -Doptimize=ReleaseFast`
- `nix develop -c zig build test`
- `INTEROP_PEER_IMPL=quic-go INTEROP_PEER_IMAGE=martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424 nix develop -c bash interop/run-official.sh`

Re-run the same host-direct bulk benchmark and `perf` profile on the improved build. Keep the
change only if throughput improves and the ACK receive share drops.

## Risks

### Lifetime mistakes in byte-backed ACK state

If the inbound ACK representation stores a span into temporary decode memory, later iteration could
read invalid bytes. This is mitigated by anchoring the representation to the received `SharedBytes`
storage or an equivalent owner with clear lifetime.

### Validation drift between the inbound and owned paths

If the new inbound parser and the existing owned parser diverge, malformed ACK behavior could split.
This is mitigated by sharing the validation logic and adding parity tests across both paths.

### Limited upside if decode is no longer dominant after landing

If recovery tail work now dominates more than decode materialization, the throughput gain may be
small. This change is still acceptable only if the benchmark measurably improves.

## Decision

Proceed with a byte-backed inbound ACK representation plus a receive-only cursor, keep the owned
`AckFrame` as the compatibility/reference path, and route received ACK handling through the new
inbound form so the server hot path stops materializing `additional_ranges` it does not need.
