# QUIC Deadline Tracking Design

## Goal

Remove repeated scans over `PacketSpaceState::sent_packets` from the hot wakeup path by maintaining incremental packet-space state for loss and PTO deadline selection.

## Problem

`QuicConnection::next_wakeup()` currently calls `loss_deadline()` and `pto_deadline()`, and both helpers walk `sent_packets` to rediscover the same packet candidates on every poll loop iteration. In the perf benchmark this shows up as measurable CPU in deadline computation rather than payload transfer.

## Design

Extend `PacketSpaceState` with cached anchor state:

- whether any in-flight ACK-eliciting packet exists
- the packet number and sent time of the latest in-flight ACK-eliciting packet
- the packet number and sent time of the earliest in-flight packet that is currently loss-deadline eligible for the latest acknowledged packet

The cache stores packet identity and send time, not absolute deadlines. RTT state and `pto_count_` can change after ACK processing, so `pto_deadline()` and `loss_deadline()` will continue to derive deadline timestamps from the cached anchors and current RTT state.

## Update Strategy

Maintain the cache only at packet-space mutation points:

- `track_sent_packet`
- `retire_acked_packet`
- `mark_lost_packet`
- `process_inbound_ack`
- `rebuild_recovery`
- packet-space discard helpers

Fast-path updates should handle append-style cases incrementally. When the removed or invalidated packet was the cached anchor, recompute that anchor by scanning only that packet space once.

## Testing

Add connection tests that:

- confirm loss and PTO helpers still return the same values as before
- force anchor invalidation by ACKing or losing the currently cached packet
- verify `next_wakeup()` still tracks the earliest deadline after cache updates

## Non-Goals

- No transport behavior changes
- No batching or socket backend changes
- No changes to recovery math
