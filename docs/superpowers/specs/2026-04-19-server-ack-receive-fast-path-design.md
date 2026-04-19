# Server ACK Receive Fast Path Design

## Goal

Improve the server-side ACK receive cost in the `coquic-perf` bulk-download workload used by
[perf.yml](/home/minhu/projects/coquic/.github/workflows/perf.yml), without changing QUIC wire
behavior, ACK semantics, recovery decisions, congestion outcomes, or interoperability.

This pass is intentionally narrower than the earlier
[bulk ACK fast-path design](/home/minhu/projects/coquic/docs/superpowers/specs/2026-04-18-bulk-ack-fast-path-design.md).
The current bottleneck is on the server receive side, so this design focuses only on that path
first and requires proof that throughput improves before any broader ACK work continues.

## Current State

Fresh host-direct profiling on `main` measured the CI-shaped bulk-download workload at about
`184.461 MiB/s` unprofiled.

The profiled runs show the server is the limiting side:

- server `perf stat`: `14954.24 msec task-clock`, `0.997 CPUs utilized`
- client `perf stat`: `10362.39 msec task-clock`, `0.691 CPUs utilized`

The current top server hotspots are:

- `_aesni_ctr32_ghash_6x`: `28.43%`
- `PacketSpaceRecovery::on_ack_received`: `13.31%`
- `entry_SYSCALL_64_after_hwframe`: `11.82%`

The current client still spends meaningful CPU on ACK send, but it is not the limiting side for
this workload:

- `write_ack_ranges<SpanBufferWriter>`: `23.61%`
- `SpanBufferWriter::write_varint`: `19.02%`

Code inspection shows that the server already avoids the older ACK range expansion path in steady
state, but the recovery fast path still pays significant internal shaping cost:

1. [`PacketSpaceRecovery::on_ack_received`](/home/minhu/projects/coquic/src/quic/recovery.cpp)
   walks ACK ranges in descending order, but buffers newly acked and late-acked packets into
   temporary descending vectors.
2. It snapshots metadata while buffering, then reverses and copies those buffered results into the
   public [`AckProcessingResult`](/home/minhu/projects/coquic/src/quic/recovery.h) lists.
3. [`QuicConnection::process_inbound_ack`](/home/minhu/projects/coquic/src/quic/connection.cpp)
   then walks those handles again to retire acked packets, mark lost packets, update ECN state,
   drive congestion control, emit qlog, and manage PTO state.

The recoverable cost is therefore not ACK range parsing anymore. The remaining hot work is result
materialization and per-batch shaping inside recovery.

## Non-Goals

- No change to ACK wire encoding or parsing rules.
- No change to malformed-ACK handling or error offsets.
- No change to packet-threshold or time-threshold loss detection semantics.
- No benchmark-specific shortcut such as intentionally weakening ACK processing.
- No direct attempt in this pass to reduce server crypto cost.
- No client ACK-send optimization in this pass unless it is required for correctness.

## Design Summary

Split the recovery ACK path into:

1. one shared internal ACK walker that performs the actual recovery state mutations once
2. a compatibility collector that preserves the current `AckProcessingResult` behavior for tests
   and non-hot callers
3. a lighter connection-facing fast path that returns only the handle lists and summary bits that
   `process_inbound_ack` actually needs

This lets the server hot path stop paying for metadata snapshots, reverse-order rebuilds, and other
result shaping that only exists to support the richer compatibility result.

Because the current congestion controller has a subtle dependence on ACK batch order, the design
also hardens congestion accounting so the fast path can safely use native descending traversal
order.

## Detailed Design

### 1. Add one shared internal ACK walker in recovery

In [recovery.cpp](/home/minhu/projects/coquic/src/quic/recovery.cpp), factor the common mutation
logic currently duplicated between the span-based and cursor-based `on_ack_received(...)`
implementations into one internal helper.

That helper owns the following responsibilities:

- update `largest_acked_packet_number_`
- call `track_new_loss_candidates(...)` when the running largest acknowledged packet advances
- walk live recovery slots against descending ACK ranges
- classify matching packets as:
  - newly acked
  - late acked
- perform the in-recovery state mutation for those packets
- perform the existing trailing loss scan and classify newly lost packets
- update `compatibility_version_` when mutation occurred

The helper should not commit to a single public result shape. Instead, it should emit events into a
collector interface or templated callback bundle so recovery can build different output shapes from
the same mutation pass.

### 2. Keep the current compatibility result as a collector

The existing public
[`AckProcessingResult`](/home/minhu/projects/coquic/src/quic/recovery.h)
remains available and keeps its current semantics:

- `acked_packets`, `late_acked_packets`, and `lost_packets`
- metadata snapshots preserved across later retirement
- current ordering expectations used by recovery tests
- `largest_newly_acked_packet`
- `largest_acknowledged_was_newly_acked`
- `has_newly_acked_ack_eliciting`

This compatibility path becomes one collector layered on the shared ACK walker. It is the
correctness reference and remains the easiest path for tests to inspect.

### 3. Add a lighter connection-facing ACK apply result

Add a second recovery result type for the hot connection path. This result should contain only what
[`QuicConnection::process_inbound_ack`](/home/minhu/projects/coquic/src/quic/connection.cpp#L3753)
actually consumes:

- newly acked handles
- late-acked handles
- newly lost handles
- `largest_acknowledged_was_newly_acked`
- `has_newly_acked_ack_eliciting`
- minimal metadata for the largest newly acked packet:
  - packet number
  - sent time

This fast result intentionally does not carry per-packet metadata snapshots for the whole batch.
The connection already fetches full packet state when retiring or marking handles, so duplicating
that metadata in recovery is unnecessary on the server hot path.

### 4. Switch `process_inbound_ack` to the fast result

In [connection.cpp](/home/minhu/projects/coquic/src/quic/connection.cpp), change
`process_inbound_ack(...)` to use the lighter recovery ACK apply path instead of the compatibility
`AckProcessingResult`.

The connection remains responsible for all higher-level side effects it already owns:

- retiring acked packets
- marking packets lost
- ECN accounting
- qlog emission
- RTT updates
- congestion-controller callbacks
- handshake confirmation
- PTO reset logic

This keeps the protocol semantics and ownership boundaries stable while removing unnecessary result
materialization from recovery.

### 5. Allow the fast path to keep native descending order

The recovery walker naturally discovers packets in descending order while traversing ACK ranges
against the live-slot chain.

The fast connection-facing result should preserve that native order instead of paying to reverse it
into ascending order. This removes:

- temporary descending buffers for newly acked packets
- temporary descending buffers for late-acked packets
- reverse-order copy into final result lists

The compatibility collector can still preserve the old observable ordering where tests depend on
it.

### 6. Make congestion ACK processing batch-order-invariant

The current
[`NewRenoCongestionController::on_packets_acked`](/home/minhu/projects/coquic/src/quic/congestion.cpp)
can behave differently depending on ACK batch order because it clears `recovery_start_time_` inside
the loop as soon as it sees an eligible post-recovery packet.

That means descending and ascending batches can produce different congestion growth when the batch
crosses the recovery boundary.

Fix this by making `on_packets_acked(...)` batch-order-invariant:

- snapshot whether the controller is in recovery and the current recovery boundary before iterating
- evaluate every packet in the batch against that fixed boundary
- track whether any eligible post-recovery packet was acknowledged
- clear recovery state only after the loop if the batch should exit recovery

This preserves the intended congestion behavior while removing the accidental dependence on ACK list
ordering.

### 7. Leave the loss-scan policy unchanged in the first pass

The current ACK receive path still includes a tail loss scan after acknowledging packets. That may
remain materially hot after the result shaping work is removed, but it is not the first change in
this design.

For this pass:

- keep the same packet-threshold and time-threshold criteria
- keep the same loss classification timing
- keep the same `lost_packets` output semantics

If follow-up profiling still shows `PacketSpaceRecovery::on_ack_received` is too large after the
fast result lands, the next optimization target is the loss-scan tail.

## Correctness Constraints

- The shared ACK walker must produce the same acked, late-acked, and lost packet sets as the
  current implementation.
- The compatibility collector must preserve the existing `AckProcessingResult` semantics expected by
  recovery tests.
- The fast connection-facing result must preserve RTT updates, ECN accounting, congestion outcomes,
  qlog, and PTO-reset behavior.
- Stable recovery handles and retirement semantics must remain unchanged.
- ACK parsing and malformed-ACK behavior must remain unchanged.
- Congestion outcomes for a logically identical ACK batch must not depend on whether packets are
  presented ascending or descending.

## Testing Strategy

### Focused tests

Add or update tests for:

- recovery differential behavior between the compatibility collector and the fast collector on the
  same ACK input
- preservation of `largest_newly_acked_packet`,
  `largest_acknowledged_was_newly_acked`, and `has_newly_acked_ack_eliciting`
- congestion batch-order invariance across a recovery boundary
- connection ACK processing preserving loss, RTT, PTO-reset, and congestion behavior when driven by
  the fast path

### Verification commands

Run:

- `nix develop -c zig build -Doptimize=ReleaseFast`
- `nix develop -c zig build test`
- `INTEROP_PEER_IMPL=quic-go INTEROP_PEER_IMAGE=martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424 nix develop -c bash interop/run-official.sh`

Re-run the host-direct bulk benchmark on the same workload shape that currently measures about
`184.461 MiB/s` unprofiled, then re-run `perf` on the improved build.

### Acceptance criteria

- all tests pass
- pinned official interop smoke still passes
- host-direct bulk throughput improves on the current baseline
- `PacketSpaceRecovery::on_ack_received` shrinks as a share of server cycles in the follow-up
  profile

## Risks

### Hidden dependence on compatibility result ordering

Some caller or test may depend on the current ascending compatibility ordering more than the hot
path does. This is mitigated by keeping the compatibility collector intact and limiting the
descending native order to the new fast connection path.

### Congestion behavior drift

Changing ACK batch handling in congestion control could accidentally change recovery exit behavior.
This is mitigated by explicitly adding batch-order invariance tests around the recovery boundary.

### Limited upside if the loss scan dominates next

If result materialization is only part of the remaining ACK receive cost, the first pass may reduce
`on_ack_received` without moving total throughput enough. This is acceptable only if the measured
benchmark still improves; otherwise the change should not be kept.

## Decision

Proceed with a shared recovery ACK walker, preserve the current compatibility API, add a lighter
connection-facing ACK apply result, and harden congestion ACK handling so the fast path can safely
use native descending order. This is the smallest aggressive change that directly attacks the
current server ACK receive bottleneck without weakening correctness checks or interop coverage.
