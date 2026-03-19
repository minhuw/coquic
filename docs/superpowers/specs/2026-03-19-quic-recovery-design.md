# QUIC Recovery Slice Design

## Status

Approved in conversation on 2026-03-19.

## Context

`coquic` now has a poll-based `QuicCore` and `QuicDemoChannel` that can:

- complete a real QUIC + TLS handshake with `quictls`
- exchange post-handshake application data on the demo stream
- drive a socket-backed localhost demo through explicit `advance(...)` calls

That slice intentionally assumed ideal delivery. The current engine sends data
once and then forgets it, ignores recovery in application space, does not emit
ACK frames, and always reports `next_wakeup = std::nullopt`.

The next slice is the minimum non-ideal transport layer beneath the existing
poll API. It adds acknowledgment generation, sent-packet tracking, loss
recovery, and probe timeouts while still sending as fast as possible. This is a
recovery slice, not a congestion-control slice.

The protocol model for this work is grounded in:

- RFC 9000 Section 13.2 and Section 13.2.1 for ACK generation
- RFC 9000 Section 13.3 for retransmission of information instead of packets
- RFC 9000 Section 18.2 for `ack_delay_exponent` and `max_ack_delay`
- RFC 9002 Section 5.1 and Section 5.3 for RTT sampling and RTT estimator state
- RFC 9002 Section 6, Section 6.1, and Section 6.2 for loss detection and PTO
- RFC 9002 Section 6.1.1 and Section 6.1.2 for packet and time thresholds
- RFC 9002 Section 6.2.1, Section 6.2.2, and Section 6.2.4 for PTO behavior

## Goal

Add the smallest useful non-ideal transmission layer that:

- preserves the current `QuicCore::advance(...)` and `QuicDemoChannel::advance(...)`
  interfaces
- generates and processes ACK frames in all active packet number spaces
- tracks sent packets until acknowledged or declared lost
- retransmits CRYPTO and STREAM information in new packets when loss is detected
- drives loss detection and PTO from `next_wakeup`
- tolerates dropped, duplicated, and reordered datagrams in the handshake and
  on the demo stream
- still avoids congestion control, pacing, and general stream scheduling for now

## Non-Goals

- Congestion control, pacing, cwnd, bytes-in-flight limits, or Reno/CUBIC/BBR
- Flow control (`MAX_DATA`, `MAX_STREAM_DATA`, `MAX_STREAMS`) as an enforced
  transport feature
- Multi-stream support or a general stream scheduler
- 0-RTT, Retry, migration, ECN, path validation, or connection ID rotation
- A public recovery API redesign above `QuicCore`
- Perfect ACK decimation or advanced delayed-ACK tuning
- Production-grade transport interoperability beyond this repo's controlled
  client/server tests and demo

## Decisions

### Public Layering And API Stability

- Keep `QuicCore::advance(input, now) -> QuicCoreResult` as the only public
  transport engine entrypoint.
- Keep `QuicDemoChannel::advance(...)` as the only demo wrapper entrypoint.
- Keep the existing effect categories and ordering:
  1. `QuicCoreSendDatagram`
  2. received application data / received demo messages
  3. state events
- Make `QuicCoreTimerExpired` a real transport input instead of a no-op.
- Make `QuicConnection::next_wakeup()` meaningful by returning the earliest
  recovery-related deadline.

This slice changes transport behavior under the existing poll/result contract
instead of introducing another API transition immediately after the poll-API
migration.

### Recovery Scope And Packet Number Spaces

Recovery follows RFC 9002 Section 6 and is tracked per packet number space:

- Initial
- Handshake
- Application Data

Each packet number space gets its own receive-side ACK bookkeeping and its own
sent-packet map. RTT estimation remains path-wide rather than per-space, which
matches RFC 9002 Section 6.

Application PTO is not armed until handshake confirmation, matching RFC 9002
Section 6.2.1.

### ACK Generation

ACK generation follows RFC 9000 Section 13.2 and Section 13.2.1 with a
simplified initial policy:

- every successfully processed packet is recorded in receive-side ACK state
- Initial and Handshake packets are acknowledged immediately
- 1-RTT packets are also acknowledged immediately in this slice
- ACK-only traffic must not create infinite ACK loops; receiving a
  non-ack-eliciting packet must not force an immediate ACK-only response
- when sending any other packet, the sender should piggyback pending ACK frames
  when available

The deliberate simplification is to acknowledge 1-RTT packets immediately rather
than implement delayed-ACK heuristics now. This keeps the first recovery slice
small and aligns with the current "send as fast as possible" goal. A future
slice can add delayed ACK policy without changing the public API.

Each packet space tracks enough information to build ACK frames:

- largest received packet number
- contiguous and non-contiguous received ranges
- whether new ack-eliciting packets are pending acknowledgment
- the receive time of the largest newly acknowledged packet for ACK Delay
  reporting

For this slice, the ACK frame contents should represent the current receive
ranges, not historical ACK snapshots. ACK history pruning from RFC 9000 Section
13.2.4 can be deferred unless it is needed to keep implementation state bounded
inside tests.

### Transport Parameters Needed For Recovery

`TransportParameters` is extended with:

- `ack_delay_exponent`, default `3` per RFC 9000 Section 18.2
- `max_ack_delay`, default `25ms` per RFC 9000 Section 18.2

These parameters are serialized, deserialized, and validated enough for local
recovery use. They are needed to:

- encode `ACK Delay` on outbound ACK frames
- decode inbound `ACK Delay`
- clamp acknowledgment delay after handshake confirmation per RFC 9002 Section
  5.3
- compute PTO per RFC 9002 Section 6.2.1

### Sent-Packet Tracking And Retransmittable Information

Current send state is "flush once, then forget." Recovery requires durable
ownership of sent information until acknowledgment.

Add per-space sent-packet tracking keyed by full packet number. Each tracked sent
packet records at least:

- send time
- whether the packet is ack-eliciting
- whether the packet is still in flight
- whether it has already been declared lost
- the logical information carried in the packet that may require repair

Repair is information-based, following RFC 9000 Section 13.3:

- CRYPTO data is retransmitted as new `CRYPTO` frames
- application stream data is retransmitted as new `STREAM` frames
- packets themselves are never retransmitted verbatim
- ACK, PING, and PADDING do not require repair

To support this, the current write paths are generalized into reliable send
state:

- crypto send state keeps byte ranges pending send, outstanding, and acked
- application stream send state does the same for the single demo stream
- lost ranges become eligible for retransmission before unsent new ranges

Within a packet, the sender may still combine:

- pending ACK frame
- retransmitted CRYPTO frames
- retransmitted STREAM frame data
- new CRYPTO or STREAM data
- `PING` when PTO needs an ack-eliciting probe and no retransmittable/new data
  exists

### Inbound ACK Processing

Inbound ACK processing must:

- parse ACK frames in the packet number space they arrive in, per RFC 9000
  Section 19.3
- mark newly acknowledged packets in that same space
- generate RTT samples only when the largest newly acknowledged packet was
  ack-eliciting, per RFC 9002 Section 5.1
- update `min_rtt`, `latest_rtt`, `smoothed_rtt`, and `rttvar`, per RFC 9002
  Section 5.3
- reset `pto_count` when acknowledgment newly confirms forward progress, subject
  to the RFC 9002 Section 6.2.1 handshake caveat for Initial acknowledgments
- release acknowledged CRYPTO/STREAM ranges from retransmission ownership
- run packet-threshold and time-threshold loss detection after newly processed
  acknowledgments

Use RFC 9002 recommended constants in this slice:

- `kPacketThreshold = 3` from Section 6.1.1
- `kTimeThreshold = 9/8` from Section 6.1.2
- `kGranularity = 1ms` from Section 6.1.2
- `kInitialRtt = 333ms` from Section 6.2.2

Malformed ACK frames remain hard errors.

### RTT, Loss Detection, And PTO Timers

Add connection-wide RTT state:

- `min_rtt`
- `latest_rtt`
- `smoothed_rtt`
- `rttvar`
- `pto_count`

Loss detection follows RFC 9002 Section 6.1:

- packet-threshold loss: a sufficiently older packet is lost once a later packet
  is acknowledged
- time-threshold loss: an older packet is lost once it exceeds
  `max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)`

PTO follows RFC 9002 Section 6.2 and Section 6.2.1:

- arm PTO when ack-eliciting packets are in flight
- use `smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay`
- use `0` for `max_ack_delay` in Initial and Handshake spaces
- exponentially back off PTO through `pto_count`
- do not arm Application PTO before handshake confirmation

When a PTO fires, follow RFC 9002 Section 6.2.4:

- send at least one ack-eliciting probe in the expired packet number space
- prefer new data if available
- otherwise prefer retransmittable lost/outstanding data
- otherwise send `PING`
- do not mark packets lost solely because PTO fired

For this slice, sending one probe datagram per PTO expiration is sufficient.
Sending two probe datagrams is explicitly deferred.

### `next_wakeup` Contract

`QuicConnection::next_wakeup()` returns the earliest transport deadline across:

- immediate ACK send deadlines
- time-threshold loss deadlines
- PTO deadlines

`std::nullopt` means there is no recovery timer to arm. The public poll API does
not change: callers continue treating returned `next_wakeup` as authoritative and
replacing any previously stored deadline.

### Receive-Side Reassembly For Application Data

The current application receive path assumes exactly contiguous in-order stream
bytes. That is incompatible with reordering and retransmission.

Replace it with offset-based reassembly, mirroring the shape of
`CryptoReceiveBuffer`:

- duplicated bytes are ignored
- reordered bytes are buffered by stream offset
- contiguous bytes are released upward only when the current receive gap closes
- application data still targets exactly one stream (`stream_id = 0`)
- `FIN`, non-zero stream IDs, or invalid STREAM flag usage remain hard errors in
  this slice

This preserves the existing message-oriented `QuicDemoChannel` API while making
its underlying stream transport tolerant of non-ideal delivery.

### Send Priority And Fast-Path Behavior

Because this slice intentionally omits congestion control and pacing, the sender
may emit data as soon as it is sendable.

When assembling packets, priority is:

1. pending ACK frame for the packet space
2. retransmission of lost CRYPTO/STREAM information
3. new CRYPTO data
4. new application STREAM data
5. `PING` only when needed to produce an ack-eliciting PTO probe

This keeps recovery responsive while still allowing rapid forward progress under
loss-free conditions.

### Failure Semantics

The failure model stays strict:

Recoverable transport events:

- packet loss
- packet duplication
- packet reordering
- delayed acknowledgments
- ACK loss

Terminal failures:

- malformed ACK frame encoding or impossible ACK ranges
- arithmetic overflow in range tracking or stream/crypto offsets
- invalid frame use for the supported slice
- cryptographic or packet protection failures
- impossible retransmission bookkeeping state
- demo framing violations in `QuicDemoChannel`

After failure, the existing inert semantics remain unchanged:

- no new send effects
- no new receive effects
- no new wakeup
- `failed` state event remains edge-triggered

### Demo Runtime And Tests

`src/main.cpp` can keep its socket-backed poll loop. The more important change is
in deterministic transport tests.

Add scripted tests that feed explicit `(time, input)` stimuli and selectively
manipulate `QuicCoreSendDatagram` effects to simulate:

- dropped Initial or Handshake packets that recover via retransmission/PTO
- dropped first 1-RTT application packet that is retransmitted successfully
- reordered and duplicated 1-RTT packets that do not duplicate app delivery
- ACK processing that clears outstanding retransmission ownership and updates RTT
- PTO wakeups becoming visible through `next_wakeup`

`QuicDemoChannel` tests should continue to validate wrapper behavior while adding
at least one lossy/reordered message-delivery scenario above the new recovery
engine.

## File Shape

Likely touched files in this slice:

- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/crypto_stream.h`
- Modify: `src/quic/crypto_stream.cpp`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/transport_parameters.h`
- Modify: `src/quic/transport_parameters.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_demo_channel_test.cpp`
- Modify: `tests/quic_test_utils.h`
- Possibly create: small recovery helpers under `src/quic/` if packet-space
  state becomes too large for `connection.*`

## Verification

The implementation of this slice must pass:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build -- -Dtls_backend=quictls
nix develop -c zig build test -- -Dtls_backend=quictls
```
