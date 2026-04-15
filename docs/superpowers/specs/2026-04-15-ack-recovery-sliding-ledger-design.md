# ACK/Recovery Sliding Ledger Design

## Goal

Reduce inbound ACK CPU across all packet spaces by replacing the current
map-heavy, duplicated sent-packet bookkeeping with a single packet-number-indexed
ledger that owns full sent-packet state.

## Problem

Perf sampling on the bulk download server shows a secondary hotspot in
`PacketSpaceRecovery::on_ack_received()` and
`QuicConnection::process_inbound_ack()`.

The current ACK path does the same work multiple times:

- Decode ACK ranges more than once.
- Scan `declared_lost_packets` and `PacketSpaceRecovery::sent_packets_`
  separately.
- Re-look-up packet numbers in `PacketSpaceState::sent_packets` to recover the
  full `SentPacketRecord`.
- Copy full packet records into temporary vectors before retirement and loss
  processing.

This design is correct, but it spends cycles on ordered-map joins and copies
instead of direct packet-number access.

## Chosen Approach

Replace the split ownership model with a shared sliding ledger per packet space.

- `PacketSpaceRecovery` becomes the sole owner of sent-packet state.
- `PacketSpaceState` stops owning separate `sent_packets` and
  `declared_lost_packets` maps.
- `PacketSpaceRecovery` replaces its internal `std::map` with a sliding
  packet-number-indexed storage window that stores the full `SentPacketRecord`
  plus recovery state for each packet.
- ACK processing decodes ACK ranges once and passes the decoded ranges to the
  recovery layer.
- The recovery layer returns lightweight references or handles to acked,
  late-acked, and newly-lost packets so connection-side retirement, ECN, qlog,
  and stream bookkeeping operate on the canonical stored record instead of
  copied values.

## Data Model

Each packet-space ledger stores:

- `base_packet_number`: the first packet number represented by the window.
- A contiguous slot array indexed by `packet_number - base_packet_number`.
- Per-slot state:
  `empty`, `sent`, `declared_lost`, `retired`.
- The full `SentPacketRecord`.
- Recovery flags needed for ACK/loss decisions such as `in_flight`,
  `ack_eliciting`, and `declared_lost`.

Auxiliary ordered indexes remain for deadline-oriented queries:

- Latest in-flight ACK-eliciting packet by sent time.
- Earliest eligible loss packet by sent time.

These indexes point at ledger slots instead of owning duplicate packet records.

## ACK Processing Flow

1. `QuicConnection::process_inbound_ack()` decodes ACK ranges once.
2. The decoded ranges are passed into `PacketSpaceRecovery`.
3. Recovery walks the ledger slots covered by those ranges directly, marking:
   active newly-acked packets, late-acked packets, and packets newly declared
   lost by packet-threshold or time-threshold logic.
4. Recovery updates largest-acked state and auxiliary loss/PTO indexes in place.
5. Connection-side code consumes the returned slot references to apply stream,
   flow-control, ECN, qlog, and congestion side effects, then retires those
   slots.
6. Fully retired slots at the ledger front are compacted by advancing
   `base_packet_number`.

## Invariants

- Packet numbers remain strictly monotonic per packet space.
- Late ACK of a previously lost packet is still supported without a second map.
- Malformed ACK ranges still produce no accidental packet retirement.
- Existing congestion, ECN, delayed-ACK, and qlog behavior stay unchanged.
- The design applies uniformly to Initial, Handshake, and Application packet
  spaces.

## Testing

- Extend recovery tests to cover active ACK, late ACK, stale ACK, malformed ACK
  ranges, packet-threshold loss, and time-threshold loss under the ledger model.
- Extend connection ACK tests to verify late ACK retirement, ECN accounting, and
  stream/frame retirement still behave the same after removing the old maps.
- Re-run the native bulk download perf sample after implementation to compare
  against the restored baseline near `58.760 MiB/s`.
