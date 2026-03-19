# QUIC Multi-Stream Flow Control And Congestion Control Design

## Status

Approved in conversation on 2026-03-19.

## Context

`coquic` currently has:

- a real QUIC + TLS handshake using `quictls`
- packet/frame codecs for the relevant transport frames
- recovery for loss, ACK generation, RTT estimation, and PTO
- a poll-based `QuicCore::advance(...)` API
- a `QuicDemoChannel` wrapper that maps one simple demo message flow onto one
  transport stream

The current transport is still intentionally narrow:

- application data is hard-wired to stream `0`
- `FIN`, `RESET_STREAM`, and `STOP_SENDING` are not surfaced as a general
  public transport contract
- flow-control transport parameters are not implemented
- `MAX_DATA`, `MAX_STREAM_DATA`, `MAX_STREAMS`, `DATA_BLOCKED`,
  `STREAM_DATA_BLOCKED`, and `STREAMS_BLOCKED` are codec-level only
- congestion control is absent; the sender currently transmits as fast as
  recovery and local packet assembly allow

That is sufficient for the repo's current self-demo, but it is not sufficient
for a standard multi-stream QUIC transport engine.

The next project is therefore a transport expansion in two ordered slices:

1. multi-stream support + flow control + stream control semantics
2. congestion control using a first-pass NewReno controller

The protocol model for this design is grounded in:

- RFC 9000 Section 3 for stream states and stream lifecycle
- RFC 9000 Section 4 for flow control
- RFC 9000 Section 18.2 for transport parameter definitions
- RFC 9000 Sections 19.4 and 19.5 for `RESET_STREAM` and `STOP_SENDING`
- RFC 9000 Sections 19.9 through 19.14 for `MAX_*` and `*_BLOCKED` frames
- RFC 9000 Section 13.3 for retransmission of information rather than packets
- RFC 9002 Section 7 for NewReno congestion control

## Goal

Expand `coquic` into a transport-facing QUIC core that:

- supports multiple concurrent streams
- exposes stream-aware send/receive/control operations at the `QuicCore` API
- enforces connection-level and stream-level flow control
- supports `FIN`, `RESET_STREAM`, and `STOP_SENDING`
- serializes, parses, and acts on the transport parameters and control frames
  needed for standard flow-control behavior
- preserves the existing poll/result transport engine shape
- adds a repo-local NewReno congestion controller after flow control is in place
- keeps `QuicDemoChannel` usable as a one-stream wrapper above the richer core

## Non-Goals

- designing the final application/session API above `QuicCore`
- HTTP/3, QPACK, or any higher-level protocol semantics
- 0-RTT, Retry, connection migration, ECN, connection ID rotation, or path
  validation
- pacing in the first congestion-control slice
- advanced stream prioritization or a general fairness policy beyond a simple,
  deterministic scheduler
- a first-class interop harness against external QUIC implementations in this
  same slice
- changing the demo framing format or turning `QuicDemoChannel` into the main
  transport API

## Decisions

### Project Split

This work is intentionally split into two sequential slices.

#### Slice 1: Multi-Stream Flow Control

Slice 1 includes:

- a stream-aware public `QuicCore` contract
- internal stream state for bidirectional and unidirectional streams
- transport-parameter support for flow-control and stream-count limits
- processing and generation of `MAX_DATA`, `MAX_STREAM_DATA`, `MAX_STREAMS`,
  `DATA_BLOCKED`, `STREAM_DATA_BLOCKED`, and `STREAMS_BLOCKED`
- support for `FIN`, `RESET_STREAM`, and `STOP_SENDING`
- packetization and retransmission that no longer assumes a single application
  stream

Slice 1 does not include congestion-window limiting.

#### Slice 2: NewReno Congestion Control

Slice 2 adds:

- connection-wide bytes-in-flight accounting
- NewReno slow start, congestion avoidance, recovery, and persistent
  congestion handling
- congestion-window gating on new ack-eliciting sends

Slice 2 must not require another public API redesign.

### Public Layering

- Keep `QuicCore::advance(input, now) -> QuicCoreResult` as the only public
  transport engine entrypoint.
- Keep `QuicDemoChannel` as an optional one-stream convenience wrapper above
  `QuicCore`.
- Treat `QuicCore` as a transport-facing API, not the final application API.
  It may expose raw QUIC concepts such as `stream_id`, `FIN`, and reset/stop
  semantics directly.
- Preserve the current I/O-independent polling model:
  - callers own clocks
  - callers own sockets or packet backends
  - `QuicCore` returns ordered effects and one next wakeup deadline

### Public `QuicCore` Stream API

Replace the current single-stream application-data surface with explicit
stream-aware transport operations.

The public API shape should become:

```cpp
enum class QuicCoreStateChange : std::uint8_t {
    handshake_ready,
    failed,
};

enum class QuicCoreLocalErrorCode : std::uint8_t {
    invalid_stream_id,
    invalid_stream_direction,
    send_side_closed,
    receive_side_closed,
    final_size_conflict,
};

struct QuicCoreLocalError {
    QuicCoreLocalErrorCode code;
    std::optional<std::uint64_t> stream_id;
};

struct QuicCoreStart {};

struct QuicCoreInboundDatagram {
    std::vector<std::byte> bytes;
};

struct QuicCoreSendStreamData {
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

struct QuicCoreResetStream {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct QuicCoreStopSending {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct QuicCoreTimerExpired {};

using QuicCoreInput = std::variant<
    QuicCoreStart,
    QuicCoreInboundDatagram,
    QuicCoreSendStreamData,
    QuicCoreResetStream,
    QuicCoreStopSending,
    QuicCoreTimerExpired>;

struct QuicCoreSendDatagram {
    std::vector<std::byte> bytes;
};

struct QuicCoreReceiveStreamData {
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

struct QuicCorePeerResetStream {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
    std::uint64_t final_size = 0;
};

struct QuicCorePeerStopSending {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct QuicCoreStateEvent {
    QuicCoreStateChange change;
};

using QuicCoreEffect = std::variant<
    QuicCoreSendDatagram,
    QuicCoreReceiveStreamData,
    QuicCorePeerResetStream,
    QuicCorePeerStopSending,
    QuicCoreStateEvent>;

struct QuicCoreResult {
    std::vector<QuicCoreEffect> effects;
    std::optional<QuicCoreTimePoint> next_wakeup;
    std::optional<QuicCoreLocalError> local_error;
};
```

`local_error` is for invalid caller commands only. It must not be used for peer
protocol violations. Peer protocol violations continue to drive connection
failure and the existing terminal `failed` state event.

Effect ordering remains stable:

1. outbound datagrams
2. inbound stream data and peer stream-control effects
3. state events

`local_error` is out-of-band result metadata rather than an ordered effect.

### Stream ID Ownership And Implicit Open

- The caller passes explicit QUIC `stream_id` values to `QuicCore`.
- There is no explicit `OpenStream` operation in this slice.
- A valid local stream opens implicitly on first local transport action that is
  allowed to mention it:
  - `QuicCoreSendStreamData`
  - `QuicCoreResetStream`
- A receive-capable stream may be materialized lazily when local
  `QuicCoreStopSending` or inbound peer frames mention it and that usage is
  legal for the stream's role and directionality.
- Because `QuicCore` is transport-facing rather than app-facing, the caller is
  responsible for choosing stream IDs correctly. This is acceptable in this
  slice and avoids designing a higher-level stream-handle API too early.

### Local Error Semantics

Invalid local commands are non-terminal and report through
`QuicCoreResult.local_error`. They do not fail the connection.

Examples:

- trying to send on a receive-only stream
- trying to `STOP_SENDING` on a send-only stream
- trying to send after the local send side is already closed or reset
- trying to send a conflicting final size
- trying to use a stream ID that is impossible for the local endpoint role

By contrast, normal transport backpressure is not a local API error:

- stream credit exhaustion
- connection credit exhaustion
- peer stream-count exhaustion
- congestion-window exhaustion

Those conditions queue pending work and drive protocol behavior such as
`*_BLOCKED` frames or later sends when credit becomes available.

If a caller submits an invalid local command while unrelated transport work is
already runnable, `advance(...)` still drains that unrelated work normally. The
invalid command itself must not mutate stream state or emit protocol frames.

### Internal Stream Model

Replace the single application send/receive state with a stream table keyed by
`stream_id`.

Each stream record should own:

- stream identity metadata:
  - `stream_id`
  - initiator (local or peer)
  - directionality (bidirectional or unidirectional)
- send-side state:
  - reliable send buffer for queued, sent, acked, and lost bytes
  - whether local `FIN` is queued, sent, or fully closed
  - whether local reset has been requested or sent
  - whether peer `STOP_SENDING` has been received
  - final size, when known for the send side
- receive-side state:
  - reorder buffer for inbound stream bytes
  - whether peer `FIN` has been received
  - whether peer reset has been received
  - final size, when known for the receive side
  - whether a local `STOP_SENDING` request is pending or sent
- flow-control state:
  - peer-advertised send credit for this stream
  - local receive window and last advertised maximum
  - highest sent offset
  - highest received offset
  - bytes delivered to the caller
- pending control-frame flags:
  - `RESET_STREAM`
  - `STOP_SENDING`
  - `MAX_STREAM_DATA`
  - `STREAM_DATA_BLOCKED`

`QuicConnection` should stop owning one global application send buffer and one
global application receive buffer. Those move into the per-stream records.

### Stream State Rules

Implement stream behavior using RFC 9000 Section 3 semantics, but model it with
repo-friendly flags and helpers instead of trying to mirror the RFC diagrams
literally in one enum.

Required behavior includes:

- `FIN` cleanly closes only the sending direction
- `RESET_STREAM` abruptly terminates the sending direction and carries final
  size
- `STOP_SENDING` requests that the peer stop its sending direction
- final size is immutable once known
- receiving data or a reset that conflicts with known final size is a transport
  error
- illegal frame-direction combinations are transport errors

Specific directionality rules to preserve:

- peer `MAX_STREAM_DATA` on a receive-only stream is a transport error
- peer `STOP_SENDING` on a send-only stream is a transport error
- peer `RESET_STREAM` on a receive-only stream is a transport error
- stale lower-valued `MAX_DATA`, `MAX_STREAM_DATA`, and `MAX_STREAMS` are
  ignored rather than treated as errors

### `STOP_SENDING` And `RESET_STREAM` Behavior

The public and internal behavior should be:

- local `QuicCoreStopSending`
  - sends `STOP_SENDING`
  - marks the local receive side as no longer interested in more data
  - does not itself reset the local send side
- inbound peer `STOP_SENDING`
  - emits `QuicCorePeerStopSending`
  - automatically queues the required `RESET_STREAM` response if the local send
    side is still active
  - stops retransmitting abandoned send-side data on that stream once reset is
    committed
- local `QuicCoreResetStream`
  - immediately abandons local send-side delivery for that stream
  - queues `RESET_STREAM`
- inbound peer `RESET_STREAM`
  - emits `QuicCorePeerResetStream`
  - terminates the local receive-side expectation for further bytes on that
    stream
  - validates final size

### Transport Configuration And Transport Parameters

Do not keep growing `QuicConnection`'s ad hoc local transport-parameter
construction. Add explicit transport tuning to `QuicCoreConfig`.

Recommended shape:

```cpp
struct QuicTransportConfig {
    std::uint64_t max_udp_payload_size = 65527;
    std::uint64_t ack_delay_exponent = 3;
    std::uint64_t max_ack_delay = 25;

    std::uint64_t initial_max_data = 1 << 20;                      // 1 MiB
    std::uint64_t initial_max_stream_data_bidi_local = 256 << 10;  // 256 KiB
    std::uint64_t initial_max_stream_data_bidi_remote = 256 << 10; // 256 KiB
    std::uint64_t initial_max_stream_data_uni = 256 << 10;         // 256 KiB
    std::uint64_t initial_max_streams_bidi = 16;
    std::uint64_t initial_max_streams_uni = 16;
};

struct QuicCoreConfig {
    EndpointRole role = EndpointRole::client;
    ConnectionId source_connection_id;
    ConnectionId initial_destination_connection_id;
    bool verify_peer = false;
    std::string server_name = "localhost";
    std::optional<TlsIdentity> identity;
    QuicTransportConfig transport;
};
```

`TransportParameters` should then grow to include the RFC 9000 Section 18.2
flow-control fields in addition to the currently supported values.

Serialization and parsing must support:

- `initial_max_data`
- `initial_max_stream_data_bidi_local`
- `initial_max_stream_data_bidi_remote`
- `initial_max_stream_data_uni`
- `initial_max_streams_bidi`
- `initial_max_streams_uni`

Validation must enforce the RFC constraints for the currently supported
parameters and preserve the current connection-ID validation rules.

The connection should always serialize its configured limits explicitly rather
than relying on "absent means zero".

### Connection-Level And Stream-Level Flow Control

Flow control follows RFC 9000 Section 4.

#### Sender-side rules

- Sending new stream bytes is constrained by:
  - per-stream send credit from peer `MAX_STREAM_DATA` or transport parameters
  - connection send credit from peer `MAX_DATA` or transport parameters
- Retransmission of already-accounted-for stream ranges does not consume new
  flow-control credit.
- New queued bytes may remain buffered even if they are not yet sendable due to
  flow-control limits.
- If sending is blocked by stream credit, queue `STREAM_DATA_BLOCKED`.
- If sending is blocked by connection credit, queue `DATA_BLOCKED`.

#### Receiver-side rules

- The receiver maintains a fixed logical receive window for the connection and
  for each receive-capable stream.
- Because `QuicCore` has no separate "application consumed bytes" callback in
  this slice, bytes are treated as consumed once they are emitted in a
  `QuicCoreReceiveStreamData` effect.
- As bytes are delivered, the receiver refreshes available credit and may queue
  `MAX_DATA` and `MAX_STREAM_DATA` updates.
- Use a simple half-window refresh policy in the first slice:
  - advertise a new `MAX_DATA` or `MAX_STREAM_DATA` when delivered bytes move
    the available window forward by at least half the configured receive window
    or when a peer `*_BLOCKED` frame reveals that progress is waiting on a
    smaller stale limit

This policy is intentionally simple and deterministic for tests.

### Stream Count Limits

Track separate locally usable peer limits for:

- bidirectional streams
- unidirectional streams

Use the standard QUIC stream ID layout to determine:

- initiator
- directionality
- whether a stream counts against the local open limit or the peer's open limit

Required behavior:

- locally initiated streams cannot become send-active until within the peer's
  advertised `MAX_STREAMS` limit of that type
- if a local stream would exceed that limit, keep its pending data buffered and
  queue `STREAMS_BLOCKED`
- receiving peer `MAX_STREAMS` updates may make queued local streams eligible
  for transmission

### Packetization And Stream Scheduling

The current application path assumes one stream and one send buffer. Replace it
with a deterministic scheduler.

Packet assembly priority should be:

1. ACK frames
2. retransmitted CRYPTO data
3. transport control frames with protocol effect:
   - `RESET_STREAM`
   - `STOP_SENDING`
   - `MAX_DATA`
   - `MAX_STREAM_DATA`
   - `MAX_STREAMS`
4. retransmitted stream data
5. blocked-signaling frames
6. new stream data
7. `PING` only when a probe needs ack-eliciting content and nothing else fits

For new stream data, use a simple deterministic round-robin across streams with
pending sendable bytes. Do not add prioritization beyond that.

The scheduler must enforce, in order:

- stream send state legality
- per-stream flow-control credit
- connection flow-control credit
- congestion-window budget once slice 2 lands
- datagram size budget

### Congestion Control Architecture

Congestion control should not be scattered through `QuicConnection`.

Add a dedicated controller unit, for example:

- `src/quic/congestion.h`
- `src/quic/congestion.cpp`

This unit owns:

- `max_datagram_size`
- `congestion_window`
- `ssthresh`
- `bytes_in_flight`
- recovery start marker
- bookkeeping needed for persistent congestion

The controller consumes recovery-relevant events:

- packet sent with bytes-in-flight contribution
- packet acknowledged
- packet declared lost
- persistent congestion detected

`SentPacketRecord` therefore needs one additional transport field:

- the packet's bytes-in-flight contribution in bytes

This must be based on the ack-eliciting packet size contribution used for
congestion accounting, not on logical stream payload length alone.

### NewReno Policy

Use RFC 9002 Section 7's NewReno behavior as the first congestion controller.

Required settings:

- fixed `max_datagram_size = 1200` until path-MTU work exists
- initial window:
  - `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
- minimum congestion window:
  - `2 * max_datagram_size`
- slow start below `ssthresh`
- congestion avoidance above `ssthresh`
- one congestion-window reduction per recovery epoch
- persistent-congestion collapse to the minimum congestion window

Do not add pacing in this slice.

However, the sender must not dump unlimited packets in one batch when not
otherwise constrained. Without pacing, the send loop should still honor cwnd and
produce at most the amount of new ack-eliciting data that fits the currently
available congestion budget, except for RFC-permitted probe behavior.

### Recovery And Congestion Interaction

Recovery remains responsible for:

- RTT state
- packet-threshold loss
- time-threshold loss
- PTO
- retransmission ownership

Congestion control becomes responsible for:

- bytes-in-flight accounting
- gating new ack-eliciting sends
- cwnd growth and reduction

The contract between the two should be explicit:

- when a packet is sent and is ack-eliciting/in-flight, recovery tracks the
  packet and congestion control increments bytes in flight
- when that packet is acknowledged or declared lost, congestion control removes
  its bytes in flight
- when a new loss event begins, congestion control updates `ssthresh`,
  `congestion_window`, and recovery epoch state
- when recovery determines persistent congestion, congestion control collapses
  the window to the configured minimum

### `QuicDemoChannel` Adaptation

`QuicDemoChannel` remains deliberately small.

It should:

- continue to expose one message-queueing wrapper API
- continue to use the existing 4-byte big-endian message framing
- bind itself to one fixed bidirectional transport stream, still stream `0`
- translate:
  - `QuicCoreReceiveStreamData` on stream `0` into demo messages
  - `QuicCoreSendStreamData` internally for outbound demo bytes
- fail the wrapper if:
  - the peer resets the demo stream
  - the peer sends `STOP_SENDING` on the demo stream
  - stream `0` violates the demo framing contract
  - any unexpected demo-visible transport behavior makes the wrapper contract
    ambiguous

The wrapper is not widened into a generic stream multiplexer.

### Testing Strategy

This project should be implemented with TDD in narrow vertical slices.

Test coverage must expand beyond the demo wrapper and target raw transport
behavior directly.

#### Core transport tests

Add or expand tests for:

- transport-parameter round trips and validation for the new fields
- stream ID classification and implicit-open behavior
- legal and illegal direction/state transitions
- `FIN` delivery and final-size handling
- `RESET_STREAM` and `STOP_SENDING` from both local and peer directions
- per-stream and connection flow-control blocking
- `MAX_DATA`, `MAX_STREAM_DATA`, and `MAX_STREAMS` processing
- `DATA_BLOCKED`, `STREAM_DATA_BLOCKED`, and `STREAMS_BLOCKED` generation
- multi-stream reordering and retransmission
- stale `MAX_*` frames being ignored
- receive-only and send-only stream rule enforcement

#### Congestion-control tests

Add dedicated tests for:

- initial cwnd computation
- slow start growth
- congestion avoidance growth
- bytes-in-flight accounting
- cwnd reduction on loss
- no repeated cwnd collapse inside one recovery epoch
- persistent-congestion collapse
- probe behavior when cwnd is otherwise exhausted

#### End-to-end tests

Add multi-stream `QuicCore` integration tests that:

- open multiple local and peer streams
- exchange data concurrently on bidirectional and unidirectional streams
- survive drop, duplication, and reordering with flow control in place
- verify that blocked streams resume once `MAX_*` credit arrives

Keep the socket-backed demo smoke test working as a wrapper-level check, but do
not rely on the demo path as the main proof of correctness for this project.

## File Shape

Expected file changes are:

- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`
- Modify: `src/quic/transport_parameters.h`
- Modify: `src/quic/transport_parameters.cpp`
- Modify: `src/quic/demo_channel.h`
- Modify: `src/quic/demo_channel.cpp`
- Create: `src/quic/streams.h`
- Create: `src/quic/streams.cpp`
- Create: `src/quic/congestion.h`
- Create: `src/quic/congestion.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_demo_channel_test.cpp`
- Modify: `tests/quic_transport_parameters_test.cpp`
- Modify: `tests/quic_recovery_test.cpp`
- Create: `tests/quic_streams_test.cpp`
- Create: `tests/quic_congestion_test.cpp`
- Possibly modify: `tests/quic_test_utils.h`

If the implementation ends up extracting a dedicated flow-control helper in
addition to the stream-state helper, that is acceptable, but it is not required
up front.

## Risks And Constraints

- Multi-stream transport expands state space quickly; the implementation must
  avoid letting `src/quic/connection.cpp` become the only place that knows
  everything.
- The lack of an explicit "application consumed bytes" callback is a deliberate
  simplification for this slice. The design relies on treating emitted receive
  effects as consumed, which must be applied consistently.
- `RESET_STREAM` and final-size handling are easy places to introduce subtle
  protocol bugs; tests must be explicit about final-size invariants.
- Congestion control should remain a separate unit. If cwnd logic leaks into the
  stream scheduler directly, the next transport slice will be harder to evolve.
- This design intentionally does not solve final application ergonomics. It
  favors transport correctness first.

## Recommended Execution Order

1. Refactor the public `QuicCore` API to the stream-aware input/effect/result
   shape while preserving handshake and basic polling behavior.
2. Extend transport configuration and transport-parameter serialization,
   deserialization, and validation.
3. Add internal stream classification and stream table infrastructure.
4. Implement stream state transitions plus `FIN`, `RESET_STREAM`, and
   `STOP_SENDING`.
5. Implement connection-level and stream-level flow control plus `MAX_*` and
   `*_BLOCKED` handling.
6. Adapt packetization and retransmission from one application stream to the
   multi-stream scheduler.
7. Rework `QuicDemoChannel` onto the richer `QuicCore` API while keeping the
   wrapper intentionally one-stream.
8. Add the NewReno controller and wire bytes-in-flight accounting into recovery.
9. Run the full QUIC test suite with the `quictls` backend and close any gaps
   with focused tests before planning the next interop-oriented slice.
