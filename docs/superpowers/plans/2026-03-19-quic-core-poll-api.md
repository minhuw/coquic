# QUIC Core Poll API Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework `QuicCore` and `QuicDemoChannel` around a deterministic `advance(input, now) -> {effects, next_wakeup}` API, then update the demo runtime and tests to use that contract without adding new transport features.

**Architecture:** Keep `QuicConnection` as the internal QUIC/TLS state machine, but split its current monolithic `receive()` behavior into explicit start, inbound-datagram, app-queue, outbound-drain, and state-event helpers. Put the public polling surface in `QuicCore`, adapt `QuicDemoChannel` to the same single-step model, and move the UDP demo loop to a real socket-or-deadline pump instead of synthetic empty-datagram flushes. There are still no real transport timers in this slice, so `next_wakeup` should be wired through as `std::nullopt` unless some existing path genuinely needs a deadline.

**Tech Stack:** C++20, `std::variant`, `std::chrono::steady_clock`, Zig build, GoogleTest, QUIC packet/crypto codecs already in `src/quic/`, current TLS backends (`quictls` and `boringssl`), POSIX UDP sockets/polling in `src/main.cpp`

---

## File Map

- Modify: `src/quic/core.h`
  - Replace the old byte-in/byte-out methods with the new time alias, input/effect/result structs, and `advance(...)` declaration while keeping `is_handshake_complete()` and `has_failed()` as convenience queries.
- Modify: `src/quic/core.cpp`
  - Implement `QuicCore::advance(...)` by delegating one stimulus at a time into `QuicConnection`, draining outbound datagrams, received app bytes, and edge-triggered state events into a single ordered `QuicCoreResult`.
- Modify: `src/quic/connection.h`
  - Expose small internal primitives that `QuicCore` can compose: local start, inbound datagram processing, app-byte queueing, outbound datagram draining, app-byte draining, state-event draining, and wakeup querying.
- Modify: `src/quic/connection.cpp`
  - Refactor the current `receive()` path into those primitives, keep handshake/application behavior unchanged, emit `handshake_ready`/`failed` only once, and report `std::nullopt` for `next_wakeup` in this slice.
- Modify: `src/quic/demo_channel.h`
  - Replace `send_message()` / `on_datagram()` / `take_messages()` with a wrapper-level poll API that reuses transport start/datagram/timer inputs and adds one explicit queued-message input.
- Modify: `src/quic/demo_channel.cpp`
  - Frame messages, buffer pre-handshake sends, translate `QuicCore` effects into wrapper effects, and force terminal wrapper failure on framing errors without hidden flush loops.
- Modify: `src/coquic.h`
  - Keep the umbrella public header aligned with the new `QuicCore` and `QuicDemoChannel` poll APIs so downstream includes continue to surface the redesigned types and methods.
- Modify: `src/main.cpp`
  - Replace the current `on_datagram({})` flush loops with a real runtime pump that starts the channel once, processes ordered effects, and waits for either UDP readability or the currently requested wakeup deadline.
- Modify: `tests/quic_test_utils.h`
  - Add deterministic time helpers, effect-extraction helpers, and scripted exchange helpers for the new `advance(...)` APIs.
- Modify: `tests/quic_core_test.cpp`
  - Rewrite the existing handshake/app-data tests to use `advance(...)` and add coverage for edge-triggered state events, inert terminal failure, and authoritative `next_wakeup` replacement.
- Modify: `tests/quic_demo_channel_test.cpp`
  - Rewrite wrapper tests around the new polling model, add same-step buffered-message flush coverage, and add one socket-backed smoke test that drives the wrapper through real UDP sockets without using `src/main.cpp`.

## Execution Notes

- Follow `@superpowers:test-driven-development` in every task: write the failing test first, run it and watch it fail, then implement the minimum code to pass.
- Before every commit or success claim, use `@superpowers:verification-before-completion`.
- Keep the scope exactly on the poll/result API redesign. Do not add ACK logic, retransmission, PTO, congestion control, stream multiplexing, executor abstractions, or real timer scheduling.
- Reuse the public `QuicCoreStateChange` enum internally instead of inventing duplicate state-event types for `QuicConnection`.
- The current slice should not invent fake deadlines. If the refactor does not uncover an existing need for one, `next_wakeup` should stay `std::nullopt` and tests should lock that down.
- Preserve current TLS-backend behavior; the plan targets the public QUIC API shape, not the TLS adapter contract.

### Task 1: Convert `QuicCore` To The Poll/Result API

**Files:**
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/coquic.h`
- Modify: `tests/quic_test_utils.h`
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Add deterministic poll-API test helpers**

Extend `tests/quic_test_utils.h` with fixed-time helpers and result inspectors the
new tests can share:

```cpp
inline coquic::quic::QuicCoreTimePoint test_time(std::int64_t ms = 0) {
    return coquic::quic::QuicCoreTimePoint{} + std::chrono::milliseconds(ms);
}

inline std::vector<std::vector<std::byte>> send_datagrams_from(
    const coquic::quic::QuicCoreResult &result) {
    std::vector<std::vector<std::byte>> out;
    for (const auto &effect : result.effects) {
        if (const auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect)) {
            out.push_back(send->bytes);
        }
    }
    return out;
}

inline std::vector<coquic::quic::QuicCoreStateChange> state_changes_from(
    const coquic::quic::QuicCoreResult &result) {
    std::vector<coquic::quic::QuicCoreStateChange> out;
    for (const auto &effect : result.effects) {
        if (const auto *event = std::get_if<coquic::quic::QuicCoreStateEvent>(&effect)) {
            out.push_back(event->change);
        }
    }
    return out;
}
```

Also add one helper that relays every send-datagram effect from one peer into
`advance(QuicCoreInboundDatagram{...}, now)` on the other peer so tests can keep
handshake scripts readable.

- [ ] **Step 2: Rewrite `QuicCore` tests around the new API and make them fail first**

Replace the current `receive(...)`-style tests in `tests/quic_core_test.cpp`
with poll-style coverage like this:

```cpp
TEST(QuicCoreTest, ClientStartProducesSendEffect) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());

    const auto result = client.advance(coquic::quic::QuicCoreStart{},
                                       coquic::quic::test::test_time());

    ASSERT_EQ(coquic::quic::test::send_datagrams_from(result).size(), 1u);
    EXPECT_TRUE(coquic::quic::test::state_changes_from(result).empty());
    EXPECT_EQ(result.next_wakeup, std::nullopt);
}

TEST(QuicCoreTest, TwoPeersEmitHandshakeReadyExactlyOnce) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
    EXPECT_EQ(coquic::quic::test::count_state_change(client_events,
               coquic::quic::QuicCoreStateChange::handshake_ready), 1);
    EXPECT_EQ(coquic::quic::test::count_state_change(server_events,
               coquic::quic::QuicCoreStateChange::handshake_ready), 1);
}

TEST(QuicCoreTest, FailureEventIsEdgeTriggeredAndLaterCallsAreInert) {
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto failed = server.advance(
        coquic::quic::QuicCoreInboundDatagram{{std::byte{0x01}}},
        coquic::quic::test::test_time());
    const auto after = server.advance(coquic::quic::QuicCoreTimerExpired{},
                                      coquic::quic::test::test_time(1));

    EXPECT_EQ(coquic::quic::test::state_changes_from(failed),
              std::vector{coquic::quic::QuicCoreStateChange::failed});
    EXPECT_TRUE(after.effects.empty());
    EXPECT_EQ(after.next_wakeup, std::nullopt);
}
```

Keep one application-data exchange test that queues app bytes through
`QuicCoreQueueApplicationData` and expects the peer to observe a
`QuicCoreReceiveApplicationData` effect.

- [ ] **Step 3: Run the targeted `QuicCore` tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCoreTest.*
```

Expected: compile errors for missing `QuicCoreTimePoint` / `QuicCoreInput` /
`QuicCoreResult` / `QuicCore::advance(...)`, or test failures showing the old
API shape no longer matches the new contract.

- [ ] **Step 4: Declare the new public `QuicCore` types and surface them through the umbrella header**

Update `src/quic/core.h` to expose the exact public API from the approved spec,
and verify `src/coquic.h` still exports that API cleanly for downstream includes:

```cpp
using QuicCoreClock = std::chrono::steady_clock;
using QuicCoreTimePoint = QuicCoreClock::time_point;

enum class QuicCoreStateChange : std::uint8_t {
    handshake_ready,
    failed,
};

struct QuicCoreStart {};
struct QuicCoreInboundDatagram { std::vector<std::byte> bytes; };
struct QuicCoreQueueApplicationData { std::vector<std::byte> bytes; };
struct QuicCoreTimerExpired {};
using QuicCoreInput = std::variant<
    QuicCoreStart,
    QuicCoreInboundDatagram,
    QuicCoreQueueApplicationData,
    QuicCoreTimerExpired>;

struct QuicCoreSendDatagram { std::vector<std::byte> bytes; };
struct QuicCoreReceiveApplicationData { std::vector<std::byte> bytes; };
struct QuicCoreStateEvent { QuicCoreStateChange change; };
using QuicCoreEffect = std::variant<
    QuicCoreSendDatagram,
    QuicCoreReceiveApplicationData,
    QuicCoreStateEvent>;

struct QuicCoreResult {
    std::vector<QuicCoreEffect> effects;
    std::optional<QuicCoreTimePoint> next_wakeup;
};
```

Delete the old public `receive(...)`, `queue_application_data(...)`, and
`take_received_application_data()` declarations from `QuicCore`, and keep
`src/coquic.h` as the stable umbrella include that exposes the new public type
names without any stale references to the removed API.

- [ ] **Step 5: Split `QuicConnection` into one-stimulus primitives**

Refactor `src/quic/connection.h` / `src/quic/connection.cpp` so the internal
engine exposes small methods that `QuicCore` can compose instead of one giant
`receive()` call. The target shape should be close to:

```cpp
void start();
void process_inbound_datagram(std::span<const std::byte> bytes);
void queue_application_data(std::span<const std::byte> bytes);
std::vector<std::byte> drain_outbound_datagram();
std::vector<std::byte> take_received_application_data();
std::optional<QuicCoreStateChange> take_state_change();
std::optional<QuicCoreTimePoint> next_wakeup() const;
```

Implementation notes:

- move the current client auto-start logic from `receive({})` into `start()`
- move the current non-empty input path into `process_inbound_datagram(...)`
- keep `flush_outbound_datagram()` as the internal serializer/drain helper
- add edge-trigger tracking so `handshake_ready` and `failed` are emitted once
- when any internal path marks the connection failed, stash one pending
  `QuicCoreStateChange::failed`
- while this slice has no real transport timers, make `next_wakeup()` return
  `std::nullopt`

- [ ] **Step 6: Implement `QuicCore::advance(...)` as the only public engine entrypoint**

In `src/quic/core.cpp`, use `std::visit` over `QuicCoreInput` (with a local
`overloaded` helper if you want one) and fully drain work from the connection
into one ordered `QuicCoreResult`:

```cpp
QuicCoreResult QuicCore::advance(QuicCoreInput input, QuicCoreTimePoint now) {
    (void)now;
    std::visit(overloaded{
        [&](const QuicCoreStart &) { connection_->start(); },
        [&](const QuicCoreInboundDatagram &in) {
            connection_->process_inbound_datagram(in.bytes);
        },
        [&](const QuicCoreQueueApplicationData &in) {
            connection_->queue_application_data(in.bytes);
        },
        [&](const QuicCoreTimerExpired &) {
            // No transport timers yet; keep the hook and drain any now-runnable work.
        },
    }, input);

    QuicCoreResult result;
    while (auto datagram = connection_->drain_outbound_datagram(); !datagram.empty()) {
        result.effects.emplace_back(QuicCoreSendDatagram{std::move(datagram)});
    }
    if (auto bytes = connection_->take_received_application_data(); !bytes.empty()) {
        result.effects.emplace_back(QuicCoreReceiveApplicationData{std::move(bytes)});
    }
    while (const auto event = connection_->take_state_change()) {
        result.effects.emplace_back(QuicCoreStateEvent{*event});
    }
    result.next_wakeup = connection_->next_wakeup();
    return result;
}
```

Keep `is_handshake_complete()` and `has_failed()` as thin queries over
`QuicConnection`.

- [ ] **Step 7: Run the targeted `QuicCore` tests again and verify they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCoreTest.*
```

Expected: PASS for the rewritten `QuicCore` tests, including single-emission
`handshake_ready`, app-data delivery through effects, and inert behavior after
terminal failure.

- [ ] **Step 8: Commit the `QuicCore` poll-API refactor**

Run:

```bash
git add src/quic/core.h src/quic/core.cpp src/quic/connection.h src/quic/connection.cpp \
        src/coquic.h tests/quic_test_utils.h tests/quic_core_test.cpp
git commit -m "refactor: redesign QuicCore around poll API"
```

Expected: one commit containing the public `QuicCore` API change and matching
core tests.

### Task 2: Adapt `QuicDemoChannel` To The Same Polling Model

**Files:**
- Modify: `src/quic/demo_channel.h`
- Modify: `src/quic/demo_channel.cpp`
- Modify: `tests/quic_test_utils.h`
- Modify: `tests/quic_demo_channel_test.cpp`

- [ ] **Step 1: Write failing wrapper tests for the new API**

Rewrite `tests/quic_demo_channel_test.cpp` around `advance(...)` and make the
wrapper contract explicit. Cover at least these behaviors:

- `QuicCoreStart` delivered to a client channel produces a send-datagram effect
- `QuicDemoChannelQueueMessage` before handshake completion buffers locally and
  is flushed automatically in the same outer call that makes the channel ready
- received message bytes arrive as a wrapper message effect, not through
  `take_messages()`
- oversized queued messages and oversized inbound length prefixes produce one
  `failed` event and inert later calls

Use a wrapper-side API like this to avoid inventing it during implementation:

```cpp
enum class QuicDemoChannelStateChange : std::uint8_t {
    ready,
    failed,
};

struct QuicDemoChannelQueueMessage {
    std::vector<std::byte> bytes;
};

using QuicDemoChannelInput = std::variant<
    coquic::quic::QuicCoreStart,
    coquic::quic::QuicCoreInboundDatagram,
    QuicDemoChannelQueueMessage,
    coquic::quic::QuicCoreTimerExpired>;

struct QuicDemoChannelReceiveMessage {
    std::vector<std::byte> bytes;
};

struct QuicDemoChannelStateEvent {
    QuicDemoChannelStateChange change;
};

using QuicDemoChannelEffect = std::variant<
    coquic::quic::QuicCoreSendDatagram,
    QuicDemoChannelReceiveMessage,
    QuicDemoChannelStateEvent>;

struct QuicDemoChannelResult {
    std::vector<QuicDemoChannelEffect> effects;
    std::optional<coquic::quic::QuicCoreTimePoint> next_wakeup;
};
```

- [ ] **Step 2: Run the targeted wrapper tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicDemoChannelTest.*
```

Expected: compile errors or failing assertions because `QuicDemoChannel` still
uses `send_message()` / `on_datagram()` / `take_messages()`.

- [ ] **Step 3: Declare the wrapper poll API and remove the old one**

Update `src/quic/demo_channel.h` to expose the wrapper-level input/effect/result
shape from Step 1, plus `advance(...)`, `is_ready()`, and `has_failed()`.
Delete the old `send_message()`, `on_datagram()`, and `take_messages()` public
methods.

- [ ] **Step 4: Implement same-step buffered send flushing and effect translation**

In `src/quic/demo_channel.cpp`, keep the framing logic but route everything
through `QuicCore::advance(...)`.

Key rules to implement:

- `QuicDemoChannelQueueMessage` frames the payload and either queues it in the
  core immediately or buffers it locally until the handshake is ready
- if an inbound datagram produces `QuicCoreStateChange::handshake_ready`, push
  any buffered framed bytes into the core inside the same outer `advance(...)`
  call and merge the resulting send effects before returning
- pass through `QuicCoreSendDatagram` effects unchanged
- translate `QuicCoreReceiveApplicationData` into decoded
  `QuicDemoChannelReceiveMessage` effects
- translate core handshake/failure events into wrapper `ready` / `failed`
  events exactly once
- on wrapper framing failure, clear buffered state, set terminal failure,
  return a single `failed` event, and force `next_wakeup = std::nullopt`

- [ ] **Step 5: Add scripted wrapper helpers and a socket-backed smoke test**

Extend `tests/quic_test_utils.h` with wrapper-side effect extractors similar to
Task 1. Then add one smoke test in `tests/quic_demo_channel_test.cpp` that uses
real localhost UDP sockets plus two in-process `QuicDemoChannel` instances to
prove the new API works with actual datagrams.

The smoke test does not need threads or subprocesses. Use two bound UDP sockets,
call `advance(QuicCoreStart{}, now)` on the client side, forward send effects
with `sendto()`, receive with `recvfrom()`, and keep pumping until the server
observes one `QuicDemoChannelReceiveMessage{"hello"}` effect.

- [ ] **Step 6: Run the targeted wrapper tests again and verify they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicDemoChannelTest.*
```

Expected: PASS for buffered-message flushing, terminal framing failure, and the
socket-backed smoke test.

- [ ] **Step 7: Commit the wrapper migration**

Run:

```bash
git add src/quic/demo_channel.h src/quic/demo_channel.cpp \
        tests/quic_test_utils.h tests/quic_demo_channel_test.cpp
git commit -m "refactor: migrate demo channel to poll API"
```

Expected: one commit containing the wrapper API change and its tests.

### Task 3: Update The Demo UDP Runtime To Use `advance(...)`

**Files:**
- Modify: `src/main.cpp`

- [ ] **Step 1: Replace the current flush helpers with effect-driven runtime helpers**

Refactor `src/main.cpp` so it no longer calls `on_datagram({})` in loops. Add
small helpers instead:

```cpp
using DemoChannel = coquic::quic::QuicDemoChannel;
using DemoTimePoint = coquic::quic::QuicCoreTimePoint;

DemoTimePoint now() {
    return coquic::quic::QuicCoreClock::now();
}

bool send_effect_datagrams(int fd,
                           const std::vector<coquic::quic::QuicDemoChannelEffect> &effects,
                           const sockaddr_storage &peer,
                           socklen_t peer_len);

std::optional<std::vector<std::byte>> take_received_message(
    const std::vector<coquic::quic::QuicDemoChannelEffect> &effects);

bool saw_terminal_failure(
    const std::vector<coquic::quic::QuicDemoChannelEffect> &effects);
```

Keep the runtime deliberately thin: execute effects in order, send datagrams via
`sendto()`, surface the first received message to the CLI flow, and stop on
wrapper failure.

- [ ] **Step 2: Introduce one socket-or-deadline wait helper**

Use `poll(2)` or `select(2)` in `src/main.cpp` to wait for either UDP
readability or the currently stored `next_wakeup` deadline. The helper should
accept `std::optional<DemoTimePoint>` and compute the timeout from `now()`.

Implementation rules:

- if `next_wakeup` is `std::nullopt`, block on socket readability using the
  existing demo timeout as an upper bound
- if `next_wakeup <= now()`, return immediately so the caller can deliver
  `QuicCoreTimerExpired{}`
- when the wait times out because the deadline fired, call
  `advance(QuicCoreTimerExpired{}, now())`
- otherwise read one datagram with `recvfrom()` and deliver it as
  `QuicCoreInboundDatagram{...}`

- [ ] **Step 3: Rewrite the demo client/server loops around explicit inputs and effects**

Update both `run_demo_server(...)` and `run_demo_client(...)` to follow the same
pattern:

1. create the channel
2. deliver `QuicCoreStart{}` once
3. for the client, queue the outbound message with `QuicDemoChannelQueueMessage`
4. process returned send effects immediately
5. maintain `next_wakeup` from each result as the authoritative deadline
6. wait for socket readability or deadline and feed the resulting input back into
   `advance(...)`
7. stop when a message is received or a failure event appears

Do not reintroduce empty datagrams or flush-by-poll loops.

- [ ] **Step 4: Build and run the real demo manually**

Run:

```bash
nix develop -c zig build -- -Dtls_backend=quictls
nix develop -c bash -lc '
  ./zig-out/bin/coquic demo-server >/tmp/coquic-demo-server.log 2>&1 &
  server_pid=$!
  trap "kill $server_pid" EXIT
  sleep 1
  ./zig-out/bin/coquic demo-client hello
  wait $server_pid
  cat /tmp/coquic-demo-server.log
'
```

Expected:

- the client prints `echo: hello`
- the server log contains `received: hello`
- the server log contains `sent: echo: hello`

- [ ] **Step 5: Commit the runtime loop rewrite**

Run:

```bash
git add src/main.cpp
git commit -m "refactor: drive demo runtime with poll effects"
```

Expected: one commit containing the socket runtime rewrite only.

### Task 4: Full Verification

**Files:**
- No new files; only touch code if one of the verification commands exposes a
  real issue.

- [ ] **Step 1: Run formatting checks**

Run:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
```

Expected: PASS with no diffs.

- [ ] **Step 2: Run clang-tidy checks**

Run:

```bash
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
```

Expected: PASS with no warnings promoted to failure.

- [ ] **Step 3: Run the full build and test suite**

Run:

```bash
nix develop -c zig build -- -Dtls_backend=quictls
nix develop -c zig build test -- -Dtls_backend=quictls
```

Expected: successful build and a passing GoogleTest run.

- [ ] **Step 4: Commit any verification-driven fixes**

If Steps 1-3 required code changes, commit them separately:

```bash
git add <exact files>
git commit -m "fix: address poll API verification issues"
```

If no fixes were needed, mark this step complete without creating an extra
commit.
