# Recovery Ledger Live Chain Perf Fix Design

## Goal

Restore bulk download throughput to the `main` baseline while keeping
`PacketSpaceRecovery` as the single owner of sent-packet state.

## Problem

The current sliding-ledger branch regressed the local bulk download harness from
the healthy `main` sample near `59.473 MiB/s` to a catastrophically slow run
that takes minutes to drain.

Perf sampling on the branch shows the hot path inside
`PacketSpaceRecovery::on_ack_received()`. The expensive work is not transport
configuration. It is the recovery ledger's packet-number walking:

- ACK processing probes slot storage for every packet number covered by each ACK
  range.
- Loss processing performs a second dense walk from the ledger base to
  `largest_acked_packet_number_`.
- The sliding representation still carries front-compaction machinery that is no
  longer helpful now that packet numbers are strictly monotonic and extra
  per-packet memory is allowed.

This means cumulative ACKs repeatedly touch large historical packet-number spans
instead of only the packets that are still live.

## Chosen Approach

Replace the sliding window behavior with an append-only packet-number ledger and
add an intrusive ordered chain of live tracked packets.

- Keep `slots_` as the canonical owner of full `SentPacketRecord` state.
- Index `slots_` directly by packet number from the start of each packet space.
- Stop physically erasing retired prefixes from the front of the vector.
- Add per-slot `prev_live_slot` and `next_live_slot` links so recovery can walk
  only live unacknowledged packets in packet-number order.
- Add monotonic cursors for loss-candidate discovery and time-threshold scans so
  recovery stops rescanning historical retired or already-acked spans.

This keeps the "single recovery-owned ledger" architecture, avoids reintroducing
ordered ownership maps, and makes ACK work proportional to live packets instead
of packet-number span width.

## Alternatives Considered

### 1. Secondary ordered map from packet number to slot index

This would reduce some scans, but it reintroduces map-based indexing that the
ledger refactor was intended to remove.

### 2. Block bitmap over the current sliding array

This keeps dense storage, but it adds more machinery than needed and still keeps
the sliding-front bookkeeping that is now unnecessary.

### 3. Recommended: append-only ledger plus live chain

This uses the newly allowed per-packet memory budget to simplify the storage
model and directly targets the measured ACK hotspot.

## Data Model

Each `PacketSpaceRecovery` keeps:

- `slots_`, where `slots_[packet_number]` is the canonical ledger slot for that
  packet number.
- Per-slot state:
  `empty`, `sent`, `declared_lost`, `retired`.
- The full `SentPacketRecord`.
- `acknowledged`.
- `prev_live_slot` and `next_live_slot`.
- Recovery-level heads and tails for the live chain.
- A monotonic cursor for "next packet that might newly become loss-eligible as
  `largest_acked_packet_number_` advances".

Handles continue to use `(packet_number, slot_index)`, but `slot_index` becomes
stable because the vector no longer slides.

## ACK Processing Flow

1. `QuicConnection::process_inbound_ack()` still decodes ACK ranges once.
2. Recovery walks the live chain in descending packet-number order against those
   decoded ranges.
3. Newly acked packets are marked acknowledged, removed from the live chain, and
   returned as handles.
4. Late-acked declared-lost packets are also removed from the live chain and
   returned separately.
5. Loss detection advances its monotonic cursor only across live packets whose
   packet numbers have newly moved below the latest ACK boundary.
6. Time-threshold loss collection walks only the live chain up to the current
   loss boundary instead of scanning raw slot indices.

## Invariants

- Packet numbers are monotonic within each packet space and start from `0`.
- The ledger owns all sent, declared-lost, and not-yet-retired packets.
- Removing a packet from the live chain must not invalidate the stored packet
  record until connection-side retirement or loss handling finishes.
- Late ACK of a previously declared-lost packet remains supported.
- Initial, Handshake, and Application packet spaces all use the same ledger
  layout.

## Expected Outcome

- ACK and loss processing stop paying for historical packet-number gaps.
- Stable slot indices remove the need for front compaction.
- The local bulk download harness should return to the existing `main` baseline
  band instead of draining for minutes.

## Testing

- Add a recovery test that exercises live-chain traversal across cumulative ACKs
  with holes and declared-lost packets.
- Add a recovery test that confirms stable handles across retirements because
  slot indices no longer slide.
- Re-run the targeted `QuicCoreTest` ACK and loss slice already used on this
  branch.
- Re-run the release perf harness sample and compare against the local `main`
  result near `59.473 MiB/s`.
