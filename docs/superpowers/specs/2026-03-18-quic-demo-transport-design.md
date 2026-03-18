# QUIC Demo Transport Slice Design

## Status

Approved on 2026-03-18.

## Context

`coquic` now has a handshake-only `QuicCore` that can complete a real QUIC +
TLS 1.3 handshake between two in-process peers using `quictls`. The current
engine stops at handshake completion: it has no application-data path, no
post-handshake packetization for `STREAM` frames, and no demo-facing wrapper
for actual client/server communication.

The next slice is intentionally narrow. The goal is not full QUIC transport.
The goal is to prove a usable post-handshake communication path and validate the
user-facing shape before adding general stream management, ACK/loss behavior, or
flow control.

## Goal

Add the smallest viable post-handshake transport slice that:

- keeps `QuicCore` as the low-level datagram engine
- sends and receives application data after handshake completion
- supports exactly one bidirectional application stream for now
- assumes ideal delivery
- provides a friendly wrapper for demo applications
- includes a tiny demo client/server that can exchange a request and response

## Non-Goals

- General multi-stream QUIC transport
- ACK generation as a transport feature
- Loss recovery, retransmission, PTO, congestion control, or pacing
- Flow control or MAX_DATA / MAX_STREAM_DATA handling
- Stream reset, stop-sending, or graceful close semantics
- 0-RTT, Retry, migration, connection ID rotation, or stateless reset
- Production-ready network API design
- Interoperability with external QUIC stacks for application data

## Decisions

### Public Layering

- Keep `QuicCore` as the public low-level QUIC engine.
- Keep `QuicCore::receive(std::vector<std::byte>) -> std::vector<std::byte>` as
  the network entrypoint.
- Extend `QuicCore` with only the minimum low-level application-data hooks
  needed by a higher-level wrapper:
  - `void queue_application_data(std::vector<std::byte> bytes)`
  - `std::vector<std::byte> take_received_application_data()`
- Continue to use `is_handshake_complete()` as the readiness signal for
  application traffic.
- Add a higher-level wrapper, tentatively `QuicDemoChannel`, for the nicer
  demo-facing API rather than turning `QuicCore` itself into a full app-facing
  transport object.

### Demo Wrapper API

- `QuicDemoChannel` wraps one `QuicCore`.
- The wrapper is message-oriented, not byte-stream-oriented.
- The wrapper API is intentionally small:
  - `send_message(std::vector<std::byte> bytes)`
  - `std::vector<std::byte> on_datagram(std::vector<std::byte> bytes)`
  - `std::vector<std::vector<std::byte>> take_messages()`
  - `bool is_ready() const`
- `on_datagram(...)` is the single network pump:
  - feed one inbound UDP payload image
  - let the wrapper drain any received application bytes from `QuicCore`
  - return at most one outbound UDP payload image
- `on_datagram({})` acts as a poll/flush step when the local side has queued
  handshake or application data to send.
- The drain contract is explicit:
  - one `QuicCore` or `QuicDemoChannel` call returns at most one outbound
    datagram
  - callers must repeatedly call `on_datagram({})` or `receive({})` until an
    empty datagram is returned when they want to fully flush queued output
  - tests and the demo loop must follow this rule instead of assuming one call
    drains all pending work

### Transport Scope

- Support exactly one bidirectional application stream in this slice.
- The client opens stream `0`.
- The server accepts stream `0`.
- No additional stream IDs are used.
- Application data is sent only in `1-RTT` packets after handshake completion.
- `STREAM` frames carry application bytes.
- `CRYPTO` frames remain handshake-only.

### Delivery Model

- Assume ideal delivery throughout this slice:
  - no loss
  - no reordering requirement in the demo path
  - no retransmission
  - no transport-level recovery state
- The engine may continue to ignore transport features not needed by two local
  cooperative peers.
- This keeps the slice focused on interface design and the minimum viable
  post-handshake packet path.

### Message Framing

- Message boundaries live in `QuicDemoChannel`, not in QUIC itself.
- The wrapper frames each message as:
  - 4-byte big-endian payload length
  - payload bytes
- The wrapper reassembles partial bytes until a full framed message is
  available.
- `QuicCore` only deals with raw application stream bytes.

### QuicConnection Behavior

- Extend `QuicConnection` with minimal application send and receive state for
  stream `0`.
- After handshake completion:
  - queued application bytes are packetized into `STREAM` frames
  - inbound `1-RTT` `STREAM` frames for stream `0` are appended to an
    application receive buffer
- Application receive buffering is byte-oriented; message framing is left to the
  wrapper.
- `QuicConnection` should continue to allow handshake and application output to
  share a flush step so `receive({})` can emit any queued post-handshake
  traffic.

### Packet Handling

- In application space, the engine only needs to handle:
  - `STREAM` frames for stream `0`
  - `PADDING`
- In this slice, unrelated application-space frame types are ignored and do not
  terminate the connection.
- Malformed supported frames still remain hard errors.
- Packet generation may produce:
  - a handshake datagram
  - an application-data datagram
  - or a coalesced flush if that falls out naturally from queued output

### Demo Executable

- Extend `src/main.cpp` with a tiny localhost demo mode rather than building a
  larger executable layout in this slice.
- Support two basic roles:
  - demo server: handshake with one client, read one message, send one reply
  - demo client: handshake with server, send one message, print the reply
- The demo uses two real processes over localhost UDP sockets.
- The initial concrete shape is:
  - server binds `127.0.0.1:4444` by default
  - client sends from an OS-assigned ephemeral UDP port
  - both sides use a simple blocking receive/send loop
  - both sides flush pending outbound QUIC work by repeatedly calling the local
    wrapper until it returns an empty datagram
- The demo is a proof-of-shape, not a durable CLI contract.

## Testing

- Add unit coverage for wrapper framing and message reassembly.
- Add an integration test where two `QuicCore` peers:
  - complete the handshake
  - exchange post-handshake application bytes on stream `0`
- Add an integration test where two `QuicDemoChannel` peers:
  - exchange a framed request
  - exchange a framed response
- Keep all tests in the ideal-delivery model.

## File Shape

- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Create: `src/quic/demo_channel.h`
- Create: `src/quic/demo_channel.cpp`
- Modify: `src/coquic.h`
- Modify: `src/main.cpp`
- Modify: `tests/quic_core_test.cpp`
- Create: `tests/quic_demo_channel_test.cpp`
- Modify: `tests/quic_test_utils.h`

## Verification

The implementation of this slice must pass:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build
nix develop -c zig build test -- -Dtls_backend=quictls
```
