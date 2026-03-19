# QUIC Multi-Stream Flow Control And Congestion Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `QuicCore` into a stream-aware QUIC transport engine with multi-stream data, `FIN`, `RESET_STREAM`, `STOP_SENDING`, transport-parameter-driven flow control, `MAX_*` / `*_BLOCKED` frame handling, and a first-pass NewReno congestion controller while keeping `QuicDemoChannel` usable as a one-stream wrapper.

**Architecture:** Implement this in two ordered slices inside the existing poll-based architecture. First, migrate the public `QuicCore` contract to explicit stream-aware inputs/effects, add a dedicated stream-state module plus flow-control transport parameters and frame handling, and generalize retransmittable send ownership from one hardcoded application stream to a stream table. Then add a separate congestion-control unit wired to the existing recovery layer via bytes-in-flight accounting and loss/ack events, so `QuicConnection` remains the orchestrator instead of the place where every transport rule lives.

**Tech Stack:** C++20, `std::variant`, `std::optional`, `std::chrono::steady_clock`, GoogleTest, Zig build, `quictls` test backend, existing QUIC codecs in `src/quic/`, existing recovery logic in `src/quic/recovery.*`

---

## File Map

- Modify: `build.zig`
  - Add the new transport source files and tests to the default build graph so new units compile under `zig build test` and `zig build coverage`.
- Modify: `src/coquic.h`
  - Keep the umbrella public header aligned with the new `QuicCore` stream API and the still-thin `QuicDemoChannel` wrapper API.
- Modify: `src/quic/core.h`
  - Replace the old single-stream application-data types with stream-aware input/effect/result types, local non-terminal error reporting, and transport configuration for flow-control limits.
- Modify: `src/quic/core.cpp`
  - Route the new stream-aware inputs into `QuicConnection`, drain stream-aware receive/control effects, and preserve the existing deterministic effect ordering.
- Modify: `src/quic/connection.h`
  - Add stream table, connection flow-control state, congestion-control state, pending peer-control effects, and helper methods used by the new `QuicCore` surface.
- Modify: `src/quic/connection.cpp`
  - Replace the single application-stream logic with stream-aware send/receive scheduling, stream-control semantics, flow-control updates, and congestion-window gating.
- Create: `src/quic/streams.h`
  - Stream ID classification helpers, stream metadata enums, per-stream send/receive/flow-control state, retransmittable stream/control descriptors, and utility APIs for legality/final-size checks.
- Create: `src/quic/streams.cpp`
  - Implement stream helper logic so `connection.cpp` consumes a focused stream module instead of encoding every stream rule inline.
- Create: `src/quic/congestion.h`
  - NewReno congestion-control state, constants, and event handlers for send/ack/loss/persistent-congestion updates.
- Create: `src/quic/congestion.cpp`
  - Implement the congestion-control policy separately from recovery and packetization.
- Modify: `src/quic/recovery.h`
  - Generalize `SentPacketRecord` so ack/loss processing can release bytes in flight and retransmittable descriptors across multiple streams and control frames.
- Modify: `src/quic/recovery.cpp`
  - Keep recovery semantics intact while supporting the expanded sent-packet metadata and persistent-congestion signaling needed by congestion control.
- Modify: `src/quic/transport_parameters.h`
  - Add flow-control and stream-count transport parameters plus a config-friendly representation of local defaults.
- Modify: `src/quic/transport_parameters.cpp`
  - Serialize, parse, and validate the new flow-control transport parameters.
- Modify: `src/quic/demo_channel.h`
  - Keep the wrapper API stable while binding it explicitly to transport stream `0`.
- Modify: `src/quic/demo_channel.cpp`
  - Translate wrapper operations to the stream-aware `QuicCore` API and fail clearly on demo-stream reset/stop/framing violations.
- Modify: `tests/quic_test_utils.h`
  - Add stream-aware effect extraction, relay helpers, and multistream scripts.
- Modify: `tests/quic_core_test.cpp`
  - Cover the new stream-aware public API, multistream delivery, control semantics, flow control, and congestion behavior end to end.
- Modify: `tests/quic_demo_channel_test.cpp`
  - Keep the wrapper tests aligned with the new core contract and verify that stream `0` still powers the socket-backed demo.
- Modify: `tests/quic_transport_parameters_test.cpp`
  - Lock down the new transport-parameter fields and validation rules.
- Modify: `tests/quic_recovery_test.cpp`
  - Cover the expanded sent-packet metadata and recovery/congestion interaction seams.
- Create: `tests/quic_streams_test.cpp`
  - Unit coverage for stream classification, legality, state transitions, final-size checks, and flow-control bookkeeping.
- Create: `tests/quic_congestion_test.cpp`
  - Unit coverage for initial cwnd, slow start, congestion avoidance, recovery-period gating, and persistent congestion.

## Execution Notes

- Follow `@superpowers:test-driven-development` on every task: write the failing tests first, run them and watch them fail for the right reason, then implement the minimum code to pass.
- Before every commit or success claim, use `@superpowers:verification-before-completion`.
- Preserve the poll API shape: `QuicCore::advance(input, now) -> QuicCoreResult` stays the only public engine entrypoint.
- Keep `QuicCore` transport-facing, not app-facing. Exposing raw `stream_id`, `FIN`, `RESET_STREAM`, and `STOP_SENDING` is intentional in this slice.
- `QuicCoreResult.local_error` is for invalid local commands only. Peer protocol violations still fail the connection and emit the terminal `failed` state event.
- Keep `QuicDemoChannel` intentionally narrow: it remains a one-stream message wrapper on stream `0`, not a generic stream multiplexer.
- Keep the ordered slice boundary:
  - Slice 1: stream-aware API + streams + flow control + control frames
  - Slice 2: NewReno congestion control
- Do not add pacing, HTTP/3, 0-RTT, Retry, migration, ECN, connection ID rotation, or application-friendly stream handles in this plan.
- Keep retransmission information-based per RFC 9000 Section 13.3. New `STREAM`, `RESET_STREAM`, `STOP_SENDING`, and `MAX_*` frames are re-emitted as new frames in new packets rather than replaying packets.
- Treat receive effects as consumption for receive-window refresh in this slice. Do not invent a second public “bytes consumed” callback yet.

### Task 1: Migrate `QuicCore` And `QuicDemoChannel` To The Stream-Aware Public API

**Files:**
- Modify: `src/coquic.h`
- Modify: `src/quic/core.h`
- Modify: `src/quic/core.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/demo_channel.h`
- Modify: `src/quic/demo_channel.cpp`
- Modify: `tests/quic_test_utils.h`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_demo_channel_test.cpp`

- [ ] **Step 1: Write failing stream-aware API tests and helpers**

Add stream-aware helpers to `tests/quic_test_utils.h`:

```cpp
inline std::vector<coquic::quic::QuicCoreReceiveStreamData> received_stream_data_from(
    const coquic::quic::QuicCoreResult &result) {
    std::vector<coquic::quic::QuicCoreReceiveStreamData> out;
    for (const auto &effect : result.effects) {
        if (const auto *received =
                std::get_if<coquic::quic::QuicCoreReceiveStreamData>(&effect)) {
            out.push_back(*received);
        }
    }
    return out;
}

inline std::vector<coquic::quic::QuicCorePeerResetStream> peer_resets_from(
    const coquic::quic::QuicCoreResult &result) {
    std::vector<coquic::quic::QuicCorePeerResetStream> out;
    for (const auto &effect : result.effects) {
        if (const auto *reset =
                std::get_if<coquic::quic::QuicCorePeerResetStream>(&effect)) {
            out.push_back(*reset);
        }
    }
    return out;
}
```

Then replace the current single-stream app-data tests in
`tests/quic_core_test.cpp` with stream-aware failing tests like:

```cpp
TEST(QuicCoreTest, TwoPeersExchangeStreamZeroDataThroughEffects) {
    QuicCore client(test::make_client_core_config());
    QuicCore server(test::make_server_core_config());

    test::drive_quic_handshake(client, server, test::test_time());

    const auto send = client.advance(
        QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = test::bytes_from_string("ping"),
            .fin = false,
        },
        test::test_time(1));
    const auto received = test::relay_send_datagrams_to_peer(send, server, test::test_time(1));

    const auto stream_events = test::received_stream_data_from(received);
    ASSERT_EQ(stream_events.size(), 1u);
    EXPECT_EQ(stream_events[0].stream_id, 0u);
    EXPECT_EQ(test::string_from_bytes(stream_events[0].bytes), "ping");
    EXPECT_FALSE(stream_events[0].fin);
}

TEST(QuicCoreTest, InvalidLocalStreamCommandReportsLocalErrorWithoutFailingConnection) {
    QuicCore client(test::make_client_core_config());
    const auto result = client.advance(
        QuicCoreStopSending{
            .stream_id = 0,
            .application_error_code = 7,
        },
        test::test_time());

    ASSERT_TRUE(result.local_error.has_value());
    EXPECT_FALSE(client.has_failed());
}
```

Update `tests/quic_demo_channel_test.cpp` only enough to compile against the
new core contract while keeping wrapper behavior unchanged.

- [ ] **Step 2: Run the targeted API tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCoreTest.*:QuicDemoChannelTest.*
```

Expected: compile errors for missing stream-aware types/effects or failing
assertions because `QuicCore` still exposes the old single-stream API.

- [ ] **Step 3: Implement the new public API minimally with stream-0 compatibility**

Update `src/quic/core.h` to the new public shape:

```cpp
enum class QuicCoreLocalErrorCode : std::uint8_t {
    invalid_stream_id,
    invalid_stream_direction,
    send_side_closed,
    receive_side_closed,
    final_size_conflict,
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

struct QuicCoreReceiveStreamData {
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};
```

Then adapt `src/quic/core.cpp` / `src/quic/connection.*` / `src/quic/demo_channel.*`
minimally:

- keep handshake behavior unchanged
- temporarily map only stream `0` send/receive through the existing internal
  application-data path
- report local non-terminal errors for unsupported stream-aware operations that
  are not implemented yet
- preserve effect ordering:
  1. `QuicCoreSendDatagram`
  2. inbound stream/control effects
  3. `QuicCoreStateEvent`

`src/coquic.h` must export the new public types cleanly.

- [ ] **Step 4: Run the targeted API tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCoreTest.*:QuicDemoChannelTest.*
```

Expected: the suite passes with stream `0` compatibility and the new public API
surface.

- [ ] **Step 5: Commit the public API migration**

Run:

```bash
git add src/coquic.h src/quic/core.h src/quic/core.cpp src/quic/connection.h src/quic/connection.cpp src/quic/demo_channel.h src/quic/demo_channel.cpp tests/quic_test_utils.h tests/quic_core_test.cpp tests/quic_demo_channel_test.cpp
git commit -m "refactor: make QuicCore stream-aware"
```

### Task 2: Add Flow-Control Transport Configuration And Transport Parameters

**Files:**
- Modify: `src/quic/core.h`
- Modify: `src/quic/transport_parameters.h`
- Modify: `src/quic/transport_parameters.cpp`
- Modify: `tests/quic_transport_parameters_test.cpp`
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Write failing transport-parameter tests for the new limits**

Extend `tests/quic_transport_parameters_test.cpp` with round-trip and validation
coverage:

```cpp
TEST(QuicTransportParametersTest, RoundTripsFlowControlAndStreamCountParameters) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .ack_delay_exponent = 4,
        .max_ack_delay = 17,
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 1024,
        .initial_max_stream_data_bidi_remote = 2048,
        .initial_max_stream_data_uni = 512,
        .initial_max_streams_bidi = 9,
        .initial_max_streams_uni = 5,
        .initial_source_connection_id = ConnectionId{std::byte{0xa1}},
    };

    const auto encoded = serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = deserialize_transport_parameters(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->initial_max_data, 4096u);
    EXPECT_EQ(decoded->initial_max_streams_bidi, 9u);
    EXPECT_EQ(decoded->initial_max_streams_uni, 5u);
}

TEST(QuicTransportParametersTest, MissingFlowControlParametersDefaultToZero) {
    const auto decoded = deserialize_transport_parameters(byte_vector({
        0x03, 0x02, 0x44, 0xb0,
        0x0e, 0x01, 0x02,
        0x0f, 0x01, 0x11,
    }));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->initial_max_data, 0u);
    EXPECT_EQ(decoded->initial_max_streams_bidi, 0u);
    EXPECT_EQ(decoded->initial_max_stream_data_uni, 0u);
}
```

Add one `tests/quic_core_test.cpp` assertion that the local config exports the
configured limits into peer-visible transport parameters after handshake.

- [ ] **Step 2: Run the targeted transport-parameter tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicTransportParametersTest.*:QuicCoreTest.*TransportParameters*
```

Expected: missing fields, serialization gaps, or failing assertions.

- [ ] **Step 3: Implement config and transport-parameter support minimally**

Add a transport config block in `src/quic/core.h`:

```cpp
struct QuicTransportConfig {
    std::uint64_t max_udp_payload_size = 65527;
    std::uint64_t ack_delay_exponent = 3;
    std::uint64_t max_ack_delay = 25;
    std::uint64_t initial_max_data = 1 << 20;
    std::uint64_t initial_max_stream_data_bidi_local = 256 << 10;
    std::uint64_t initial_max_stream_data_bidi_remote = 256 << 10;
    std::uint64_t initial_max_stream_data_uni = 256 << 10;
    std::uint64_t initial_max_streams_bidi = 16;
    std::uint64_t initial_max_streams_uni = 16;
};
```

Then:

- thread `config.transport` into local transport-parameter creation
- add the RFC 9000 Section 18.2 parameter IDs:
  - `0x04`, `0x05`, `0x06`, `0x07`, `0x08`, `0x09`
- parse absent values as `0`
- preserve the existing connection-ID validation rules
- do not add unrelated transport parameters in this task

- [ ] **Step 4: Run the targeted transport-parameter tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicTransportParametersTest.*:QuicCoreTest.*TransportParameters*
```

Expected: all new transport-parameter tests pass.

- [ ] **Step 5: Commit the transport-parameter slice**

Run:

```bash
git add src/quic/core.h src/quic/transport_parameters.h src/quic/transport_parameters.cpp tests/quic_transport_parameters_test.cpp tests/quic_core_test.cpp
git commit -m "feat: add QUIC stream flow-control transport parameters"
```

### Task 3: Add A Dedicated Stream-State Module And Build Wiring

**Files:**
- Modify: `build.zig`
- Create: `src/quic/streams.h`
- Create: `src/quic/streams.cpp`
- Create: `tests/quic_streams_test.cpp`

- [ ] **Step 1: Write failing stream helper tests and wire them into the build**

Create `tests/quic_streams_test.cpp` with failing unit tests:

```cpp
TEST(QuicStreamsTest, ClassifiesInitiatorAndDirectionFromStreamId) {
    EXPECT_EQ(classify_stream_id(/*stream_id=*/0, EndpointRole::client).initiator,
              StreamInitiator::local);
    EXPECT_EQ(classify_stream_id(/*stream_id=*/0, EndpointRole::client).direction,
              StreamDirection::bidirectional);
    EXPECT_EQ(classify_stream_id(/*stream_id=*/3, EndpointRole::client).direction,
              StreamDirection::unidirectional);
}

TEST(QuicStreamsTest, RejectsLocalSendOnReceiveOnlyPeerUniStream) {
    auto state = make_implicit_stream_state(/*stream_id=*/3, EndpointRole::server);
    const auto result = state.validate_local_send(/*fin=*/false);
    ASSERT_FALSE(result.has_value());
}

TEST(QuicStreamsTest, FinalSizeCannotChangeOnceKnown) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    ASSERT_TRUE(state.note_peer_final_size(/*final_size=*/5).has_value());
    const auto conflict = state.note_peer_final_size(/*final_size=*/7);
    ASSERT_FALSE(conflict.has_value());
}
```

Update `build.zig` in the same step so the new source/test files are compiled by
`zig build test`, even though they fail initially due to missing implementation.

- [ ] **Step 2: Run the targeted stream-helper tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicStreamsTest.*
```

Expected: compile or link failures for missing stream helper types/functions.

- [ ] **Step 3: Implement the stream helper module minimally**

Create focused types in `src/quic/streams.h` / `src/quic/streams.cpp`:

```cpp
enum class StreamInitiator : std::uint8_t { local, peer };
enum class StreamDirection : std::uint8_t { bidirectional, unidirectional };

struct StreamIdInfo {
    StreamInitiator initiator;
    StreamDirection direction;
    bool local_can_send = false;
    bool local_can_receive = false;
};

struct StreamFrameSendFragment {
    std::uint64_t stream_id = 0;
    std::uint64_t offset = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

struct StreamState {
    StreamIdInfo id_info;
    ReliableSendBuffer send_buffer;
    ReliableReceiveBuffer receive_buffer;
    // send/receive/final-size/flow-control flags
};
```

Also implement:

- `classify_stream_id(...)`
- helpers for implicit-open legality
- final-size tracking helpers
- send/receive direction checks

Keep this task focused on pure stream mechanics, not connection integration.

- [ ] **Step 4: Run the targeted stream-helper tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicStreamsTest.*
```

Expected: `QuicStreamsTest.*` passes.

- [ ] **Step 5: Commit the stream module**

Run:

```bash
git add build.zig src/quic/streams.h src/quic/streams.cpp tests/quic_streams_test.cpp
git commit -m "feat: add QUIC stream state helpers"
```

### Task 4: Generalize Sent-Packet Metadata And Implement Multi-Stream Data + `FIN`

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`
- Modify: `src/quic/streams.h`
- Modify: `src/quic/streams.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_recovery_test.cpp`
- Modify: `tests/quic_streams_test.cpp`
- Modify: `tests/quic_test_utils.h`

- [ ] **Step 1: Write failing tests for multistream delivery, `FIN`, and retransmittable stream metadata**

Add integration tests to `tests/quic_core_test.cpp`:

```cpp
TEST(QuicCoreTest, ClientCanSendOnMultipleBidirectionalStreams) {
    QuicCore client(test::make_client_core_config());
    QuicCore server(test::make_server_core_config());
    test::drive_quic_handshake(client, server, test::test_time());

    const auto first = client.advance(
        QuicCoreSendStreamData{.stream_id = 0, .bytes = test::bytes_from_string("a")},
        test::test_time(1));
    const auto second = client.advance(
        QuicCoreSendStreamData{.stream_id = 4, .bytes = test::bytes_from_string("b")},
        test::test_time(2));

    auto server_first = test::relay_send_datagrams_to_peer(first, server, test::test_time(1));
    auto server_second = test::relay_send_datagrams_to_peer(second, server, test::test_time(2));

    EXPECT_THAT(test::stream_payloads_from(server_first),
                ElementsAre(test::StreamPayload{0, "a", false}));
    EXPECT_THAT(test::stream_payloads_from(server_second),
                ElementsAre(test::StreamPayload{4, "b", false}));
}

TEST(QuicCoreTest, StreamReceiveEffectCarriesFin) {
    // send "hello" on stream 0 with fin=true and expect the peer receive effect
    // to carry fin=true.
}
```

Add a recovery-level test to `tests/quic_recovery_test.cpp` that the sent-packet
metadata preserves stream identity and `FIN`:

```cpp
EXPECT_EQ(result.acked_packets.front().stream_fragments[0].stream_id, 4u);
EXPECT_TRUE(result.acked_packets.front().stream_fragments[0].fin);
```

- [ ] **Step 2: Run the targeted multistream tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCoreTest.*Multiple*:*Fin*:*Stream*QuicRecoveryTest.*
```

Expected: compile failures for missing multistream metadata or runtime failures
because `connection.cpp` still assumes one application stream.

- [ ] **Step 3: Expand recovery metadata and connection send/receive state minimally**

Replace the one-stream pieces with stream-aware structures:

```cpp
struct SentPacketRecord {
    std::uint64_t packet_number = 0;
    QuicCoreTimePoint sent_time{};
    bool ack_eliciting = false;
    bool in_flight = false;
    bool declared_lost = false;
    std::vector<ByteRange> crypto_ranges;
    std::vector<StreamFrameSendFragment> stream_fragments;
    bool has_ping = false;
    std::size_t bytes_in_flight = 0;
};
```

Then in `src/quic/connection.cpp`:

- replace `pending_application_send_` / `pending_application_receive_buffer_` /
  `pending_application_receive_` with a stream table
- allow implicit-open for valid local streams on first send
- emit `QuicCoreReceiveStreamData` per stream instead of one global receive blob
- carry `FIN` through stream send and receive state
- preserve retransmission ownership per stream fragment

Keep this task limited to data + `FIN`; do not implement reset/stop or flow
control yet.

- [ ] **Step 4: Run the targeted multistream tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCoreTest.*Multiple*:*Fin*:*Stream*QuicRecoveryTest.*
```

Expected: multistream data and `FIN` tests pass.

- [ ] **Step 5: Commit the multistream data slice**

Run:

```bash
git add src/quic/connection.h src/quic/connection.cpp src/quic/recovery.h src/quic/recovery.cpp src/quic/streams.h src/quic/streams.cpp tests/quic_core_test.cpp tests/quic_recovery_test.cpp tests/quic_streams_test.cpp tests/quic_test_utils.h
git commit -m "feat: support QUIC multistream data and fin"
```

### Task 5: Implement `RESET_STREAM` And `STOP_SENDING`

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/streams.h`
- Modify: `src/quic/streams.cpp`
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_streams_test.cpp`
- Modify: `tests/quic_recovery_test.cpp`

- [ ] **Step 1: Write failing tests for local and peer reset/stop behavior**

Add stream-level tests in `tests/quic_streams_test.cpp`:

```cpp
TEST(QuicStreamsTest, StopSendingOnSendOnlyStreamIsInvalidLocalCommand) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/2, EndpointRole::client);
    const auto result = state.validate_local_stop_sending();
    ASSERT_FALSE(result.has_value());
}

TEST(QuicStreamsTest, ResetStreamLocksInFinalSize) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    state.send_buffer.append(bytes_from_string("hello"));
    ASSERT_TRUE(state.prepare_local_reset(/*app_error=*/9).has_value());
    EXPECT_EQ(state.local_reset_final_size(), 5u);
}
```

Add core integration tests in `tests/quic_core_test.cpp`:

```cpp
TEST(QuicCoreTest, PeerStopSendingProducesPeerEffectAndLocalResetResponse) {
    // drive handshake, make the server send STOP_SENDING on stream 0,
    // expect the client to emit QuicCorePeerStopSending and later send RESET_STREAM.
}

TEST(QuicCoreTest, PeerResetStreamProducesPeerResetEffectWithFinalSize) {
    // peer sends RESET_STREAM and receiver gets a QuicCorePeerResetStream effect.
}
```

- [ ] **Step 2: Run the targeted reset/stop tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicStreamsTest.*Reset*:*Stop*:*LocalCommand*QuicCoreTest.*Reset*:*Stop*
```

Expected: compile failures for missing helpers/effects or runtime failures
because control semantics are not implemented yet.

- [ ] **Step 3: Implement reset/stop semantics minimally**

In `src/quic/streams.*` add focused helpers for:

```cpp
CodecResult<void> validate_local_reset() const;
CodecResult<void> validate_local_stop_sending() const;
CodecResult<void> note_peer_reset(std::uint64_t final_size, std::uint64_t app_error);
CodecResult<void> note_peer_stop_sending(std::uint64_t app_error);
```

Then in `src/quic/connection.cpp`:

- queue outbound `RESET_STREAM` and `STOP_SENDING` frames from local inputs
- surface inbound peer frames as:
  - `QuicCorePeerResetStream`
  - `QuicCorePeerStopSending`
- automatically queue `RESET_STREAM` when peer `STOP_SENDING` arrives for an
  active local send side
- stop retransmitting abandoned send-side stream data once reset is committed
- treat illegal frame/direction combinations as peer protocol violations

Update `SentPacketRecord` ownership so reset/stop control frames survive loss
and can be re-emitted.

- [ ] **Step 4: Run the targeted reset/stop tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicStreamsTest.*Reset*:*Stop*:*LocalCommand*QuicCoreTest.*Reset*:*Stop*
```

Expected: local invalid-command tests and peer reset/stop integration tests pass.

- [ ] **Step 5: Commit the reset/stop slice**

Run:

```bash
git add src/quic/connection.h src/quic/connection.cpp src/quic/streams.h src/quic/streams.cpp src/quic/recovery.h src/quic/recovery.cpp tests/quic_core_test.cpp tests/quic_streams_test.cpp tests/quic_recovery_test.cpp
git commit -m "feat: support QUIC reset stream and stop sending"
```

### Task 6: Enforce Stream And Connection Flow Control Plus `MAX_*` / `*_BLOCKED`

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/streams.h`
- Modify: `src/quic/streams.cpp`
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_streams_test.cpp`
- Modify: `tests/quic_transport_parameters_test.cpp`

- [ ] **Step 1: Write failing flow-control and stream-count tests**

Add stream helper tests:

```cpp
TEST(QuicStreamsTest, StreamSendBlocksWhenPeerMaxStreamDataIsExhausted) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    state.flow_control.peer_max_stream_data = 4;
    state.queue_send(bytes_from_string("abcdef"), /*fin=*/false);
    EXPECT_EQ(state.sendable_bytes(), 4u);
    EXPECT_TRUE(state.should_send_stream_data_blocked());
}

TEST(QuicStreamsTest, LocalOpenBlocksWhenPeerMaxStreamsIsExhausted) {
    StreamOpenState opens;
    opens.peer_max_bidi = 1;
    EXPECT_TRUE(opens.can_open_local_bidi(/*stream_id=*/0));
    EXPECT_FALSE(opens.can_open_local_bidi(/*stream_id=*/4));
}
```

Add core integration tests:

```cpp
TEST(QuicCoreTest, BlockedStreamResumesWhenPeerMaxStreamDataArrives) {
    // queue more data than the peer initially allows, assert partial delivery,
    // then inject MAX_STREAM_DATA and assert the rest is delivered.
}

TEST(QuicCoreTest, PeerBlockedFrameTriggersEarlierWindowRefresh) {
    // receiver sees STREAM_DATA_BLOCKED and emits MAX_STREAM_DATA promptly.
}
```

- [ ] **Step 2: Run the targeted flow-control tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicStreamsTest.*FlowControl*:*MaxStreams*:*Blocked*QuicCoreTest.*Blocked*:*MaxStreamData*:*MaxData*
```

Expected: flow-control counters and `MAX_*` frame behavior are missing.

- [ ] **Step 3: Implement connection and per-stream flow control minimally**

Add focused state in `src/quic/streams.*`:

```cpp
struct StreamFlowControlState {
    std::uint64_t peer_max_stream_data = 0;
    std::uint64_t local_receive_window = 0;
    std::uint64_t advertised_max_stream_data = 0;
    std::uint64_t highest_sent = 0;
    std::uint64_t highest_received = 0;
    std::uint64_t delivered_bytes = 0;
};
```

And in `src/quic/connection.*` add connection-level flow-control state:

```cpp
struct ConnectionFlowControlState {
    std::uint64_t peer_max_data = 0;
    std::uint64_t local_receive_window = 0;
    std::uint64_t advertised_max_data = 0;
    std::uint64_t highest_sent = 0;
    std::uint64_t delivered_bytes = 0;
};
```

Implementation requirements:

- constrain new sends by both peer `MAX_DATA` and peer `MAX_STREAM_DATA`
- constrain implicit local stream opens by peer `MAX_STREAMS`
- emit and process:
  - `MAX_DATA`
  - `MAX_STREAM_DATA`
  - `MAX_STREAMS`
  - `DATA_BLOCKED`
  - `STREAM_DATA_BLOCKED`
  - `STREAMS_BLOCKED`
- ignore stale lower-valued `MAX_*` frames
- refresh windows after receive-effect delivery using the half-window policy from
  the spec
- make `MAX_*` and `*_BLOCKED` retransmittable metadata, not one-shot frames

- [ ] **Step 4: Run the targeted flow-control tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicStreamsTest.*FlowControl*:*MaxStreams*:*Blocked*QuicCoreTest.*Blocked*:*MaxStreamData*:*MaxData*
```

Expected: stream and connection credit enforcement behaves as designed.

- [ ] **Step 5: Commit the flow-control slice**

Run:

```bash
git add src/quic/connection.h src/quic/connection.cpp src/quic/streams.h src/quic/streams.cpp src/quic/recovery.h src/quic/recovery.cpp tests/quic_core_test.cpp tests/quic_streams_test.cpp tests/quic_transport_parameters_test.cpp
git commit -m "feat: enforce QUIC flow control"
```

### Task 7: Finalize Multi-Stream Scheduling And Rebind `QuicDemoChannel` To Stream `0`

**Files:**
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/demo_channel.h`
- Modify: `src/quic/demo_channel.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_demo_channel_test.cpp`
- Modify: `tests/quic_test_utils.h`

- [ ] **Step 1: Write failing scheduler and demo-wrapper tests**

Add `tests/quic_core_test.cpp` coverage for fair multistream scheduling and
loss/retransmit across multiple streams:

```cpp
TEST(QuicCoreTest, RetransmissionPreservesStreamIdentityAcrossMultipleStreams) {
    // queue stream 0 and stream 4 data, drop the first flight, drive PTO,
    // and assert the repaired delivery still lands on the correct streams.
}

TEST(QuicCoreTest, NewDataSchedulingRoundsRobinAcrossSendableStreams) {
    // queue data on several streams and assert multiple sendable streams
    // appear over successive packets instead of starving later stream IDs.
}
```

Update `tests/quic_demo_channel_test.cpp` with wrapper-specific failures:

```cpp
TEST(QuicDemoChannelTest, PeerResetOnDemoStreamFailsWrapper) {}
TEST(QuicDemoChannelTest, PeerStopSendingOnDemoStreamFailsWrapper) {}
```

- [ ] **Step 2: Run the targeted scheduler and wrapper tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCoreTest.*RoundRobin*:*Retransmission*QuicDemoChannelTest.*Reset*:*StopSending*
```

Expected: the scheduler still behaves like one-stream transport or the wrapper
does not react correctly to demo-stream control events.

- [ ] **Step 3: Implement the scheduler and wrapper adjustments minimally**

In `src/quic/connection.cpp`:

- replace one-stream send assembly with deterministic round-robin across streams
- keep packet priority:
  1. ACK
  2. retransmitted CRYPTO
  3. retransmittable transport control
  4. retransmitted stream data
  5. blocked signals
  6. new stream data
  7. `PING`

In `src/quic/demo_channel.*`:

- bind wrapper traffic explicitly to stream `0`
- use `QuicCoreSendStreamData{.stream_id = 0, ...}`
- translate only `QuicCoreReceiveStreamData` on stream `0`
- treat peer reset/stop on stream `0` as terminal wrapper failure

- [ ] **Step 4: Run the targeted scheduler and wrapper tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCoreTest.*RoundRobin*:*Retransmission*QuicDemoChannelTest.*Reset*:*StopSending*
```

Expected: multistream scheduling and wrapper failure semantics are correct.

- [ ] **Step 5: Commit the scheduler and wrapper slice**

Run:

```bash
git add src/quic/connection.cpp src/quic/demo_channel.h src/quic/demo_channel.cpp tests/quic_core_test.cpp tests/quic_demo_channel_test.cpp tests/quic_test_utils.h
git commit -m "refactor: bind demo channel to stream-aware QUIC core"
```

### Task 8: Add NewReno Congestion Control And Wire It To Recovery

**Files:**
- Modify: `build.zig`
- Create: `src/quic/congestion.h`
- Create: `src/quic/congestion.cpp`
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`
- Create: `tests/quic_congestion_test.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_recovery_test.cpp`

- [ ] **Step 1: Write failing unit and integration tests for NewReno**

Create `tests/quic_congestion_test.cpp` with focused unit tests:

```cpp
TEST(QuicCongestionTest, UsesRfcInitialWindow) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_EQ(controller.congestion_window(), 12000u);
}

TEST(QuicCongestionTest, SlowStartGrowthMatchesAcknowledgedBytes) {
    NewRenoCongestionController controller(1200);
    controller.on_packet_sent(/*bytes_in_flight=*/1200, /*ack_eliciting=*/true);
    controller.on_packet_acked(/*bytes=*/1200, /*app_limited=*/false);
    EXPECT_GT(controller.congestion_window(), 12000u);
}

TEST(QuicCongestionTest, PersistentCongestionCollapsesToMinimumWindow) {
    NewRenoCongestionController controller(1200);
    controller.on_persistent_congestion();
    EXPECT_EQ(controller.congestion_window(), 2400u);
}
```

Add a `tests/quic_core_test.cpp` integration test that cwnd gates new
ack-eliciting sends until ACKs arrive.

- [ ] **Step 2: Run the targeted congestion tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCongestionTest.*:QuicCoreTest.*Congestion*
```

Expected: missing controller types or failing assertions because cwnd is not
enforced yet.

- [ ] **Step 3: Implement the NewReno controller and recovery contract minimally**

Create `src/quic/congestion.h` / `src/quic/congestion.cpp`:

```cpp
class NewRenoCongestionController {
  public:
    explicit NewRenoCongestionController(std::size_t max_datagram_size);

    bool can_send_ack_eliciting(std::size_t bytes) const;
    void on_packet_sent(std::size_t bytes_in_flight, bool ack_eliciting);
    void on_packets_acked(std::span<const SentPacketRecord> packets, bool app_limited);
    void on_loss_event(QuicCoreTimePoint now);
    void on_packets_lost(std::span<const SentPacketRecord> packets);
    void on_persistent_congestion();
};
```

Then wire it into `src/quic/connection.*` / `src/quic/recovery.*`:

- add `bytes_in_flight` contribution to `SentPacketRecord`
- increment/decrement bytes in flight on send/ack/loss
- gate new ack-eliciting sends on cwnd budget
- allow PTO probes to exceed cwnd when RFC-permitted
- reduce `congestion_window` / `ssthresh` once per recovery epoch
- collapse to the minimum window on persistent congestion

- [ ] **Step 4: Run the targeted congestion tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCongestionTest.*:QuicCoreTest.*Congestion*
```

Expected: unit and integration congestion tests pass.

- [ ] **Step 5: Commit the congestion-control slice**

Run:

```bash
git add build.zig src/quic/congestion.h src/quic/congestion.cpp src/quic/connection.h src/quic/connection.cpp src/quic/recovery.h src/quic/recovery.cpp tests/quic_congestion_test.cpp tests/quic_core_test.cpp tests/quic_recovery_test.cpp
git commit -m "feat: add QUIC NewReno congestion control"
```

### Task 9: Run Full Verification And The Socket-Backed Demo

**Files:**
- Modify: `tests/quic_core_test.cpp` (only if final gap-closing tests are needed)
- Modify: `tests/quic_demo_channel_test.cpp` (only if final gap-closing tests are needed)
- Modify: `tests/quic_streams_test.cpp` (only if final gap-closing tests are needed)
- Modify: `tests/quic_congestion_test.cpp` (only if final gap-closing tests are needed)

- [ ] **Step 1: Run the full QUIC test suite**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls
```

Expected: all tests pass with the `quictls` backend.

- [ ] **Step 2: Run coverage to catch untested branches introduced by the new transport units**

Run:

```bash
nix develop -c zig build coverage -- -Dtls_backend=quictls
```

Expected: coverage completes successfully and highlights any remaining new gaps
in `streams.cpp`, `congestion.cpp`, `connection.cpp`, or the updated tests.

- [ ] **Step 3: Close any final targeted gaps with focused tests, then rerun the full suite**

If coverage or the full suite reveals missing branches:

- add one focused failing test
- run the targeted filter and watch it fail
- implement the minimum fix
- rerun the targeted filter
- rerun:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls
nix develop -c zig build coverage -- -Dtls_backend=quictls
```

Do not batch “cleanup” changes without a proving test.

- [ ] **Step 4: Run the real socket-backed demo once**

Run:

```bash
nix develop -c zig build -- -Dtls_backend=quictls
./zig-out/bin/coquic demo-server >/tmp/coquic-demo-server.log 2>&1 &
server_pid=$!
sleep 1
./zig-out/bin/coquic demo-client hello
kill "$server_pid"
cat /tmp/coquic-demo-server.log
```

Expected:

- client completes the handshake and receives the reply
- server logs show the demo still works over UDP sockets with the stream-aware
  core under the wrapper

- [ ] **Step 5: Commit the verification/cleanup pass**

Run:

```bash
git add tests/quic_core_test.cpp tests/quic_demo_channel_test.cpp tests/quic_streams_test.cpp tests/quic_congestion_test.cpp
git commit -m "test: verify QUIC multistream flow and congestion control"
```
