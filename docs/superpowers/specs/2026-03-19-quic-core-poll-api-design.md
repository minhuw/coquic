# QUIC Core Poll API Design

## Status

Approved in conversation on 2026-03-19.

## Context

`coquic` currently exposes `QuicCore` through a handshake-era interface shaped
around `receive(std::vector<std::byte>) -> std::vector<std::byte>`, plus
side-channel methods for queued application bytes and readiness checks. That was
sufficient for the first handshake and demo transport slices, but it leaves two
important gaps:

- the runtime has no explicit timer contract
- callers have to synthesize empty-datagram polls to flush pending work

That shape is acceptable for the current localhost UDP demo, but it is not a
clean long-term boundary for I/O-independent integrations such as future XDP or
DPDK backends. The next slice is therefore a transport API redesign, not a
transport feature expansion.

## Goal

Replace the current ad hoc poll/flush surface with a deterministic,
I/O-independent `QuicCore` API that:

- treats `QuicCore` as a pure transport state machine
- accepts one explicit stimulus at a time
- returns all externally visible work as ordered effects
- exposes the next requested wakeup deadline explicitly
- keeps clocks and I/O ownership outside the core
- lets higher-level wrappers such as `QuicDemoChannel` adapt to the same model

## Non-Goals

- Adding loss recovery, PTO, congestion control, pacing, or flow control
- Designing a full executor, reactor, or socket abstraction
- Introducing a batch input API in this slice
- Reworking `QuicConnection` into the same public shape immediately
- Changing the demo framing format or broadening demo scope beyond one simple
  message wrapper
- Adding transport support for XDP or DPDK yet; this slice only makes that
  future integration possible

## Decisions

### Architecture And Layering

- `QuicCore` becomes the public transport engine boundary.
- `QuicCore` does not own sockets, packet sources, event loops, or clocks.
- The runtime or backend owns:
  - datagram receive and send
  - packet batching policy
  - timer scheduling
  - clock reads
- `QuicDemoChannel` remains an optional wrapper above `QuicCore`; runtimes that
  want raw transport control should target `QuicCore` directly.
- `QuicConnection` may remain the lower-level internal state machine for now.
  This redesign does not require a matching public poll API at that layer.

### Public `QuicCore` API

Add a repo-local time alias so the public interface does not repeatedly expose a
long standard-library type spelling:

```cpp
using QuicCoreClock = std::chrono::steady_clock;
using QuicCoreTimePoint = QuicCoreClock::time_point;
```

Replace the current public transport entrypoints with a single-step API:

```cpp
enum class QuicCoreStateChange : std::uint8_t {
    handshake_ready,
    failed,
};

struct QuicCoreStart {};
struct QuicCoreInboundDatagram {
    std::vector<std::byte> bytes;
};
struct QuicCoreQueueApplicationData {
    std::vector<std::byte> bytes;
};
struct QuicCoreTimerExpired {};

using QuicCoreInput = std::variant<
    QuicCoreStart,
    QuicCoreInboundDatagram,
    QuicCoreQueueApplicationData,
    QuicCoreTimerExpired>;

struct QuicCoreSendDatagram {
    std::vector<std::byte> bytes;
};
struct QuicCoreReceiveApplicationData {
    std::vector<std::byte> bytes;
};
struct QuicCoreStateEvent {
    QuicCoreStateChange change;
};

using QuicCoreEffect = std::variant<
    QuicCoreSendDatagram,
    QuicCoreReceiveApplicationData,
    QuicCoreStateEvent>;

struct QuicCoreResult {
    std::vector<QuicCoreEffect> effects;
    std::optional<QuicCoreTimePoint> next_wakeup;
};

QuicCoreResult advance(QuicCoreInput input, QuicCoreTimePoint now);
```

Convenience queries may remain for now:

- `bool is_handshake_complete() const`
- `bool has_failed() const`

Those queries are secondary conveniences. `advance(...)` becomes the primary
engine API.

### Input Semantics

- Each `advance(...)` call consumes exactly one explicit stimulus.
- `QuicCoreStart` kicks off local endpoint work and should be delivered once by
  the runtime at connection startup.
- A redundant `QuicCoreStart` after startup is treated as inert rather than as a
  hard API error.
- `QuicCoreInboundDatagram` carries one received UDP payload image.
- `QuicCoreQueueApplicationData` represents newly available outbound
  application bytes from the local consumer.
- `QuicCoreTimerExpired` indicates that the currently scheduled deadline has
  been reached or passed.
- The `now` argument is authoritative for all time-based decisions. `QuicCore`
  does not read the system clock internally.

### Timer And Scheduling Semantics

- `next_wakeup` is the earliest monotonic deadline when `QuicCore` wants
  another `advance(...)` call if nothing else happens first.
- `std::nullopt` means the core is fully idle and only external input should
  wake it.
- Timer delivery is deadline-driven, not edge-count-driven. If the runtime wakes
  late, one `QuicCoreTimerExpired` input is sufficient because the core can
  compare internal deadlines against the supplied `now`.
- Each `advance(...)` call fully drains all work made runnable by that input
  before returning. The caller should never need to immediately re-issue the
  same timer input to finish work from a single expiry.
- If a datagram arrival or application write happens before the current
  deadline, the runtime should feed that stimulus first and replace any stored
  wakeup with the newly returned `next_wakeup`.
- Callers must treat the returned `next_wakeup` as authoritative and replace any
  previously stored deadline with the new value.

### Effect Semantics And Ordering

- `advance(...)` returns a fully drained batch of effects produced by the input
  and any internal follow-on work that input made runnable.
- Draining includes, as applicable:
  - transport/TLS state updates
  - packet generation
  - newly readable application bytes
  - state transitions
  - recomputation of the next wakeup deadline
- A result may contain no effects, some effects with a wakeup, or some effects
  without a wakeup.
- Effects are ordered by causality using one stable category order:
  1. outbound datagrams
  2. received application data
  3. state events
- State events are edge-triggered and emitted once per transition.
  `handshake_ready` fires once and `failed` fires once.
- After terminal failure:
  - subsequent calls are cheap and inert
  - no new send effects are produced
  - no new application data is delivered
  - `next_wakeup` is always `std::nullopt`
- The runtime owns packet retry, duplication, loss simulation, and external I/O
  policy. `QuicCore` only translates one stimulus into a deterministic result.

### Migration From The Current API

Use a short explicit migration rather than carrying two public transport APIs in
parallel for long:

1. add the new `advance(...)` API and supporting input/effect/result types to
   `QuicCore`
2. move current outbound draining, received-application-data publication, and
   state transition reporting behind the new API
3. update all in-tree callers immediately:
   - `QuicDemoChannel`
   - socket-backed demo loops
   - integration tests
4. remove the old public transport methods:
   - `receive(...)`
   - `queue_application_data(...)`
   - `take_received_application_data()`

`is_handshake_complete()` and `has_failed()` remain temporarily as convenience
queries even though event delivery becomes the primary transition signal.

### `QuicDemoChannel` Adaptation

`QuicDemoChannel` remains a thin optional message wrapper and adopts the same
single-step model.

Its wrapper-level API should:

- expose one `advance(...)` entrypoint shaped like the core API
- add a message-queueing input in place of raw application-byte queueing
- emit wrapper-level received-message effects
- pass through transport send-datagram effects to the runtime
- pass through or translate readiness/failure state in a wrapper-friendly way
- forward the underlying `next_wakeup` unchanged unless the wrapper has already
  entered terminal failure

Wrapper behavior remains intentionally small:

- retain the existing 4-byte big-endian message length prefix
- retain the 64 KiB maximum message payload
- buffer framed messages queued before handshake completion
- if an inbound step completes the handshake, immediately push any buffered
  framed message bytes into `QuicCore` during the same outer call so callers do
  not need an extra poke
- treat framing violations as terminal wrapper failure
- avoid hidden flush loops or synthetic empty-datagram polling

### Runtime And Backend Integration

The runtime contract is intentionally simple:

- call `advance(QuicCoreStart{}, now)` once at startup
- execute returned effects in order
- schedule or clear the current deadline from `result.next_wakeup`
- on datagram arrival, call `advance(QuicCoreInboundDatagram{...}, now)`
- on application write, call `advance(QuicCoreQueueApplicationData{...}, now)`
- on timer expiry, call `advance(QuicCoreTimerExpired{}, now)`

For the current UDP demo this means replacing synthetic flush loops with a real
wait-for-socket-or-deadline loop. For future XDP or DPDK integration the packet
source, send path, and timer facility may change, but the `QuicCore` contract
stays the same.

This slice intentionally does not add a built-in async runtime abstraction.

### Testing And Invariants

Shift transport tests toward deterministic replay-style scripts that feed
explicit `(time, input)` pairs and assert on returned effects and wakeups.

Test coverage should include three layers:

- `QuicCore` unit/integration tests for handshake, post-handshake application
  delivery, timer behavior, and terminal failure semantics
- `QuicDemoChannel` tests for message buffering, framing, and wrapper failure
- one socket-backed demo smoke test to prove the UDP adapter remains usable

Lock down these invariants:

- one input produces one fully drained result
- `handshake_ready` is emitted once
- `failed` is emitted once
- no effects are produced after terminal failure
- `next_wakeup` is monotonic unless cleared to `std::nullopt`
- callers do not need synthetic empty-datagram polling
- app data queued before handshake completion is sent automatically when the
  handshake becomes ready
- late timer delivery is handled by one timer input using the supplied `now`
- wrapper framing errors cause terminal wrapper failure without breaking the
  `QuicCore` contract

## File Shape

Expected implementation touch points:

- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/demo_channel.h`
- Modify: `src/quic/demo_channel.cpp`
- Modify: `src/coquic.h`
- Modify: `src/main.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_demo_channel_test.cpp`
- Add or modify helper coverage for deterministic scripted exchange tests as
  needed

## Verification

The implementation of this slice must pass:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build -- -Dtls_backend=quictls
nix develop -c zig build test -- -Dtls_backend=quictls
```
