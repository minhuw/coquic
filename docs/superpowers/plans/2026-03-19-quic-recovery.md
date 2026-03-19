# QUIC Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ACK generation, sent-packet tracking, retransmission, loss detection, and PTO to the existing poll-based `QuicCore`/`QuicDemoChannel` stack without adding congestion control or changing the public API.

**Architecture:** Keep `QuicCore::advance(...)` and `QuicDemoChannel::advance(...)` unchanged. Extend transport parameters with ACK-timing values, generalize the current crypto/application byte buffers into reliable range-tracking buffers, introduce small internal recovery helpers for ACK ranges and sent-packet state, and integrate them into `QuicConnection` so `next_wakeup` becomes the authoritative loss/PTO timer. Recovery remains information-based: ACK frames are generated from receive history, CRYPTO/STREAM bytes stay owned until acknowledged, and loss repair emits new frames in new packets rather than retransmitting packets verbatim.

**Tech Stack:** C++20, `std::variant`, `std::optional`, `std::chrono::steady_clock`, GoogleTest, Zig build, QUIC packet/frame codecs in `src/quic/`, `quictls` TLS backend, existing socket demo/runtime in `src/main.cpp`

---

## File Map

- Create: `src/quic/recovery.h`
  - Internal recovery-only types: per-space ACK receive history, sent-packet metadata, RTT estimator state, loss/PTO constants, and helper functions for packet/time-threshold loss detection.
- Create: `src/quic/recovery.cpp`
  - Implement the small internal recovery helpers so `connection.cpp` does not absorb all ACK/range/timer logic directly.
- Create: `tests/quic_recovery_test.cpp`
  - Unit coverage for ACK range building, sent-packet bookkeeping, RTT updates, and loss/PTO helper behavior before wiring them into `QuicConnection`.
- Modify: `src/quic/transport_parameters.h`
  - Add `ack_delay_exponent` and `max_ack_delay` with RFC 9000 defaults.
- Modify: `src/quic/transport_parameters.cpp`
  - Serialize, deserialize, and minimally validate the new recovery-relevant transport parameters.
- Modify: `tests/quic_transport_parameters_test.cpp`
  - Lock down round-tripping, defaults, and invalid-value handling for the new transport parameters.
- Modify: `src/quic/crypto_stream.h`
  - Expand the existing send/receive buffering layer to support reliable range tracking for sent CRYPTO and application bytes, or add clearly named reusable buffer types alongside the current classes.
- Modify: `src/quic/crypto_stream.cpp`
  - Implement range ownership, partial acknowledgment, loss re-queue, and reordered receive reassembly.
- Modify: `tests/quic_crypto_stream_test.cpp`
  - Add focused tests for retransmittable send ranges and reordered/duplicated receive behavior.
- Modify: `src/quic/connection.h`
  - Add recovery state to packet spaces and the connection-wide RTT/PTO estimator, and declare any recovery-driven helper methods used by `advance(...)`.
- Modify: `src/quic/connection.cpp`
  - Generate ACK frames, record sent packets, process inbound ACKs, release acknowledged ranges, detect losses, arm PTO, emit PTO probes, and expose real `next_wakeup()` deadlines.
- Modify: `src/quic/core.cpp`
  - Make `QuicCoreTimerExpired` actually drive recovery work instead of being inert.
- Modify: `tests/quic_test_utils.h`
  - Add deterministic lossy/reordered relay helpers, deadline-driving helpers, and low-level test peers for recovery-focused scripts.
- Modify: `tests/quic_core_test.cpp`
  - Add end-to-end recovery tests for handshake retransmission, application retransmission, ACK-driven progress, reorder tolerance, and timer visibility.
- Modify: `tests/quic_demo_channel_test.cpp`
  - Add wrapper-level message delivery tests under loss/reordering while preserving current framing/failure semantics.
- Optional Modify: `src/main.cpp`
  - Only if recovery integration reveals a runtime bug in the existing socket-or-deadline pump; no CLI redesign is part of this slice.

## Execution Notes

- Follow `@superpowers:test-driven-development` in every task: write the failing test first, run it and watch it fail, then implement the minimum code to pass.
- Before every commit or success claim, use `@superpowers:verification-before-completion`.
- Keep the public poll API stable. Do not add new public `QuicCore` effect types or recovery callbacks in this slice.
- Keep scope tight: no congestion window, pacing, bytes-in-flight gating, flow control enforcement, multi-stream scheduling, 0-RTT, Retry, migration, ECN, or path validation.
- Keep recovery information-based per RFC 9000 Section 13.3: retransmit CRYPTO/STREAM information in new packets, never by replaying old packet numbers or ciphertexts.
- ACK 1-RTT packets immediately in this slice. Delayed-ACK heuristics are a future feature, not part of this plan.
- Use the RFC 9002 constants from the approved spec unless a test proves a codebase-specific adjustment is necessary:
  - `kPacketThreshold = 3`
  - `kTimeThreshold = 9.0 / 8.0`
  - `kGranularity = 1ms`
  - `kInitialRtt = 333ms`
- Do not let `src/main.cpp` drive design. The scripted in-process recovery tests are the source of truth for behavior.

### Task 1: Add Recovery Transport Parameters

**Files:**
- Modify: `src/quic/transport_parameters.h`
- Modify: `src/quic/transport_parameters.cpp`
- Modify: `tests/quic_transport_parameters_test.cpp`

- [ ] **Step 1: Write failing transport-parameter tests for ACK timing values**

Add tests to `tests/quic_transport_parameters_test.cpp` that lock down the new
fields before changing production code:

```cpp
TEST(QuicTransportParametersTest, RoundTripsAckDelayExponentAndMaxAckDelay) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = ConnectionId{std::byte{0xc1}},
        .ack_delay_exponent = 5,
        .max_ack_delay = 42,
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_transport_parameters(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().ack_delay_exponent, 5u);
    EXPECT_EQ(decoded.value().max_ack_delay, 42u);
}

TEST(QuicTransportParametersTest, MissingAckTimingParametersUseRfcDefaults) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({
        0x03, 0x02, 0x44, 0xb0,
        0x0e, 0x01, 0x02,
        0x0f, 0x01, 0x11,
    }));

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().ack_delay_exponent, 3u);
    EXPECT_EQ(decoded.value().max_ack_delay, 25u);
}

TEST(QuicTransportParametersTest, RejectsInvalidAckTimingValues) {
    const auto bad_exponent = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
            .ack_delay_exponent = 21,
        },
        make_validation_context(ConnectionId{std::byte{0xaa}}));
    ASSERT_FALSE(bad_exponent.has_value());

    const auto bad_max_ack_delay = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
            .max_ack_delay = (1u << 14),
        },
        make_validation_context(ConnectionId{std::byte{0xaa}}));
    ASSERT_FALSE(bad_max_ack_delay.has_value());
}
```

- [ ] **Step 2: Run the targeted transport-parameter tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicTransportParametersTest.*
```

Expected: compile errors for missing fields or failing assertions showing the new
values are not serialized/deserialized yet.

- [ ] **Step 3: Implement the new transport parameters minimally**

Update `src/quic/transport_parameters.h` / `src/quic/transport_parameters.cpp`
with RFC-defaulted fields and matching parameter IDs:

```cpp
struct TransportParameters {
    std::optional<ConnectionId> original_destination_connection_id;
    std::uint64_t max_udp_payload_size = 65527;
    std::uint64_t active_connection_id_limit = 2;
    std::uint64_t ack_delay_exponent = 3;
    std::uint64_t max_ack_delay = 25;
    std::optional<ConnectionId> initial_source_connection_id;
    std::optional<ConnectionId> retry_source_connection_id;
};
```

Implementation details:

- serialize parameter `0x0a` for `ack_delay_exponent`
- serialize parameter `0x0b` for `max_ack_delay`
- keep RFC defaults when absent on parse
- reject `ack_delay_exponent > 20`
- reject `max_ack_delay >= 2^14`
- do not add unrelated transport parameters in this slice

- [ ] **Step 4: Run the targeted transport-parameter tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicTransportParametersTest.*
```

Expected: all transport-parameter tests pass, including the new ACK timing
coverage.

- [ ] **Step 5: Commit the transport-parameter slice**

Run:

```bash
git add src/quic/transport_parameters.h src/quic/transport_parameters.cpp tests/quic_transport_parameters_test.cpp
git commit -m "feat: add QUIC recovery transport parameters"
```

### Task 2: Generalize Reliable Byte-Range Buffers

**Files:**
- Modify: `src/quic/crypto_stream.h`
- Modify: `src/quic/crypto_stream.cpp`
- Modify: `tests/quic_crypto_stream_test.cpp`

- [ ] **Step 1: Write failing buffer tests for ACK/loss/reordering behavior**

Extend `tests/quic_crypto_stream_test.cpp` with tests that describe the reusable
recovery buffer behavior before refactoring `QuicConnection`:

```cpp
TEST(QuicCryptoStreamTest, SendBufferRetainsBytesUntilAcknowledged) {
    ReliableSendBuffer buffer;
    buffer.append(std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}});

    const auto first = buffer.take_ranges(2);
    ASSERT_EQ(first.size(), 1u);
    EXPECT_EQ(first[0].offset, 0u);
    EXPECT_EQ(first[0].bytes.size(), 2u);
    EXPECT_TRUE(buffer.has_outstanding_data());

    buffer.acknowledge(0, 2);
    EXPECT_TRUE(buffer.has_pending_data());
}

TEST(QuicCryptoStreamTest, LostRangesBecomeSendableBeforeNewRanges) {
    ReliableSendBuffer buffer;
    buffer.append(bytes);
    const auto first = buffer.take_ranges(2);
    buffer.mark_lost(first[0].offset, first[0].bytes.size());

    const auto retry = buffer.take_ranges(2);
    ASSERT_EQ(retry.size(), 1u);
    EXPECT_EQ(retry[0].offset, first[0].offset);
}

TEST(QuicCryptoStreamTest, ReceiveBufferReleasesReorderedApplicationBytesContiguously) {
    ReliableReceiveBuffer buffer;
    ASSERT_TRUE(buffer.push(4, bytes_from_string("ef")).has_value());
    ASSERT_TRUE(buffer.push(0, bytes_from_string("abcd")).has_value());
    const auto released = buffer.push(6, bytes_from_string("gh"));
    ASSERT_TRUE(released.has_value());
    EXPECT_EQ(released.value(), bytes_from_string("abcdefgh"));
}
```

Use this task to settle names. If `ReliableSendBuffer` / `ReliableReceiveBuffer`
feel too generic, pick clearer repo-local names and use them consistently.

- [ ] **Step 2: Run the targeted buffer tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCryptoStreamTest.*
```

Expected: compile errors for missing methods/types or failures showing the old
send buffer still forgets bytes after one flush.

- [ ] **Step 3: Implement reusable reliable send/receive buffering**

Refactor `src/quic/crypto_stream.h` / `src/quic/crypto_stream.cpp` so they can
serve both CRYPTO and application-data recovery.

A minimal acceptable shape is:

```cpp
struct ByteRange {
    std::uint64_t offset = 0;
    std::vector<std::byte> bytes;
};

class ReliableSendBuffer {
  public:
    void append(std::span<const std::byte> bytes);
    std::vector<ByteRange> take_ranges(std::size_t max_bytes);
    void acknowledge(std::uint64_t offset, std::size_t length);
    void mark_lost(std::uint64_t offset, std::size_t length);
    bool has_pending_data() const;
    bool has_outstanding_data() const;
};

class ReliableReceiveBuffer {
  public:
    CodecResult<std::vector<std::byte>> push(std::uint64_t offset,
                                             std::span<const std::byte> bytes);
};
```

Implementation constraints:

- duplicate received bytes must not be delivered twice
- partial acknowledgments must retire only the acknowledged sub-range
- lost ranges must become sendable ahead of unsent new ranges
- keep the current CRYPTO receive behavior working on top of the new receive
  buffer semantics
- do not add stream-level `FIN` or flow-control handling here

- [ ] **Step 4: Run the targeted buffer tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicCryptoStreamTest.*
```

Expected: the new reliable buffer tests and the existing crypto-buffer tests all
pass.

- [ ] **Step 5: Commit the buffer refactor**

Run:

```bash
git add src/quic/crypto_stream.h src/quic/crypto_stream.cpp tests/quic_crypto_stream_test.cpp
git commit -m "refactor: add reliable QUIC byte-range buffers"
```

### Task 3: Add Internal Recovery Helpers

**Files:**
- Create: `src/quic/recovery.h`
- Create: `src/quic/recovery.cpp`
- Create: `tests/quic_recovery_test.cpp`

- [ ] **Step 1: Write failing unit tests for ACK ranges, RTT updates, and loss/PTO helpers**

Create `tests/quic_recovery_test.cpp` with narrow tests for the internal helper
layer before touching `QuicConnection`:

```cpp
TEST(QuicRecoveryTest, AckHistoryBuildsSingleContiguousAckRange) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/0, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(5));
    history.record_received(1, true, coquic::quic::test::test_time(6));

    const auto ack = history.build_ack_frame(/*ack_delay_exponent=*/3,
                                             coquic::quic::test::test_time(7));
    ASSERT_TRUE(ack.has_value());
    EXPECT_EQ(ack->largest_acknowledged, 1u);
    EXPECT_EQ(ack->first_ack_range, 1u);
}

TEST(QuicRecoveryTest, PacketThresholdLossMarksOlderPacketLost) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(3, true, coquic::quic::test::test_time(1)));

    const auto loss = recovery.on_ack_received(make_ack_frame(/*largest=*/3),
                                               coquic::quic::test::test_time(10));
    EXPECT_TRUE(loss.lost_packet_numbers.contains(0));
}

TEST(QuicRecoveryTest, PtoDeadlineUsesInitialRttBeforeSamples) {
    RecoveryRttState rtt;
    const auto deadline = compute_pto_deadline(rtt, /*max_ack_delay_ms=*/25,
                                               coquic::quic::test::test_time(0));
    EXPECT_EQ(deadline, coquic::quic::test::test_time(999));
}
```

Keep the tests focused on helper behavior instead of connection integration.

- [ ] **Step 2: Run the recovery helper tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicRecoveryTest.*
```

Expected: compile errors because `recovery.*` and the helper types do not exist
yet.

- [ ] **Step 3: Implement the internal recovery helper layer minimally**

Create `src/quic/recovery.h` / `src/quic/recovery.cpp` with just enough
encapsulation to keep `connection.cpp` readable. The layer should provide:

```cpp
struct SentPacketRecord {
    std::uint64_t packet_number = 0;
    QuicCoreTimePoint sent_time{};
    bool ack_eliciting = false;
    bool in_flight = false;
    bool declared_lost = false;
    std::vector<ByteRange> crypto_ranges;
    std::vector<ByteRange> stream_ranges;
    bool has_ping = false;
};

struct RecoveryRttState {
    std::optional<std::chrono::milliseconds> latest_rtt;
    std::optional<std::chrono::milliseconds> min_rtt;
    std::chrono::milliseconds smoothed_rtt{333};
    std::chrono::milliseconds rttvar{166};
    std::uint32_t pto_count = 0;
};

class ReceivedPacketHistory {
  public:
    void record_received(std::uint64_t packet_number, bool ack_eliciting,
                         QuicCoreTimePoint received_time);
    bool has_ack_to_send() const;
    std::optional<AckFrame> build_ack_frame(std::uint64_t ack_delay_exponent,
                                            QuicCoreTimePoint now) const;
    void on_ack_sent();
};
```

Also add helper functions for:

- packet-threshold loss (`kPacketThreshold = 3`)
- time-threshold loss (`kTimeThreshold = 9.0 / 8.0`, `kGranularity = 1ms`)
- PTO deadline calculation using RFC 9002 Section 6.2.1
- RTT update from a newly acknowledged largest ack-eliciting packet

Keep the helpers internal. Do not export them through `src/coquic.h`.

- [ ] **Step 4: Run the helper tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter=QuicRecoveryTest.*
```

Expected: the new recovery unit tests pass cleanly.

- [ ] **Step 5: Commit the recovery helper layer**

Run:

```bash
git add src/quic/recovery.h src/quic/recovery.cpp tests/quic_recovery_test.cpp
git commit -m "feat: add internal QUIC recovery helpers"
```

### Task 4: Integrate ACK Emission And Sent-Packet Ownership Into `QuicConnection`

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_test_utils.h`

- [ ] **Step 1: Write failing integration tests for ACK emission and receive reordering**

Add `QuicCore` integration tests before changing connection behavior:

```cpp
TEST(QuicCoreTest, ReceivingAckElicitingPacketsSchedulesAckResponse) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    auto client_start = client.advance(coquic::quic::QuicCoreStart{},
                                       coquic::quic::test::test_time());
    auto server_step = coquic::quic::test::relay_send_datagrams_to_peer(
        client_start, server, coquic::quic::test::test_time(1));

    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(server_step).empty());
}

TEST(QuicCoreTest, ReorderedApplicationPacketsAreDeliveredOnceContiguous) {
    // handshake both sides, send two application packets, deliver them out of order,
    // assert no failure and one contiguous receive effect once the gap closes.
}
```

Add the minimal helper(s) to `tests/quic_test_utils.h` needed to deliver chosen
send effects out of order instead of always in-order.

- [ ] **Step 2: Run targeted `QuicCore` tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter='QuicCoreTest.ReceivingAckElicitingPacketsSchedulesAckResponse:QuicCoreTest.ReorderedApplicationPacketsAreDeliveredOnceContiguous'
```

Expected: one or both tests fail because ACK frames are not emitted and
application receive still requires perfectly contiguous delivery.

- [ ] **Step 3: Wire packet-space ACK state and reliable buffers into `QuicConnection`**

Update `src/quic/connection.h` to add recovery state to each packet space and to
store application bytes in the new reliable send/receive buffers. A workable
shape is:

```cpp
struct PacketSpaceState {
    std::uint64_t next_send_packet_number = 0;
    std::optional<std::uint64_t> largest_authenticated_packet_number;
    std::optional<TrafficSecret> read_secret;
    std::optional<TrafficSecret> write_secret;
    ReliableSendBuffer send_crypto;
    ReliableReceiveBuffer receive_crypto;
    ReceivedPacketHistory received_packets;
    std::map<std::uint64_t, SentPacketRecord> sent_packets;
};
```

Then update `src/quic/connection.cpp` so outbound packet assembly:

- emits an `ACK` frame when `received_packets.has_ack_to_send()` is true
- records each sent packet in `sent_packets`
- marks packets as ack-eliciting when they contain CRYPTO, STREAM, or PING
- keeps CRYPTO and application stream ranges owned until ACK processing retires
  them
- uses reordered receive reassembly for application STREAM frames instead of
  direct `expected_application_stream_offset_` equality checks

Do not implement loss/PTO behavior in this step yet. This task is only about
ACK emission, reliable ownership, and reordered receive tolerance.

- [ ] **Step 4: Run the targeted `QuicCore` tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter='QuicCoreTest.ReceivingAckElicitingPacketsSchedulesAckResponse:QuicCoreTest.ReorderedApplicationPacketsAreDeliveredOnceContiguous:QuicCoreTest.TwoPeersExchangeApplicationDataThroughEffects'
```

Expected: the new tests pass and the existing happy-path app-data test still
passes.

- [ ] **Step 5: Commit the ACK emission / reliable receive integration**

Run:

```bash
git add src/quic/connection.h src/quic/connection.cpp tests/quic_core_test.cpp tests/quic_test_utils.h
git commit -m "feat: add QUIC ack emission and reliable receive state"
```

### Task 5: Add Inbound ACK Processing, Loss Detection, PTO, And `next_wakeup`

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/core.cpp`
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_test_utils.h`

- [ ] **Step 1: Write failing end-to-end recovery tests**

Add the key scripted recovery tests before implementing timers:

```cpp
TEST(QuicCoreTest, HandshakeRecoversWhenInitialFlightIsDropped) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto dropped = client.advance(coquic::quic::QuicCoreStart{},
                                        coquic::quic::test::test_time());
    EXPECT_TRUE(dropped.next_wakeup.has_value());

    const auto retry = client.advance(coquic::quic::QuicCoreTimerExpired{},
                                      *dropped.next_wakeup);
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(retry).empty());
    // relay retry and complete handshake
}

TEST(QuicCoreTest, ApplicationDataIsRetransmittedAfterLoss) {
    // handshake peers, drop first application datagram, drive timer to PTO,
    // deliver retransmission, and assert one app-data delivery at the peer.
}

TEST(QuicCoreTest, AckProcessingClearsOutstandingDataAndRemovesWakeup) {
    // send one ack-eliciting packet, deliver ACK, assert no retransmission remains
    // and next_wakeup becomes nullopt when idle.
}
```

Extend `tests/quic_test_utils.h` with helpers that:

- drop selected send effects instead of relaying them
- relay only the Nth datagram of a result
- drive the earliest returned `next_wakeup` back into `QuicCoreTimerExpired`

- [ ] **Step 2: Run the targeted recovery tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter='QuicCoreTest.HandshakeRecoversWhenInitialFlightIsDropped:QuicCoreTest.ApplicationDataIsRetransmittedAfterLoss:QuicCoreTest.AckProcessingClearsOutstandingDataAndRemovesWakeup'
```

Expected: failures showing that packets are not retransmitted, `next_wakeup`
remains `std::nullopt`, or ACK processing does not release outstanding data.

- [ ] **Step 3: Implement inbound ACK processing and RTT updates**

Teach `src/quic/connection.cpp` to process inbound `AckFrame` values for every
packet space:

- mark newly acknowledged sent packets in that same space
- identify the largest newly acknowledged packet
- if that packet was ack-eliciting, update RTT per RFC 9002 Sections 5.1 and 5.3
- retire acknowledged CRYPTO/STREAM ranges from the reliable send buffers
- clear sent-packet records once they are no longer needed for loss handling
- reset `pto_count` on forward progress, preserving the RFC 9002 handshake caveat
  for Initial ACKs at the client

Use helper calls from `recovery.*` rather than reimplementing RTT math inline.

- [ ] **Step 4: Implement loss detection, PTO probes, and real `next_wakeup()`**

Finish `src/quic/connection.cpp` and `src/quic/core.cpp` so the timer input now
matters:

```cpp
std::optional<QuicCoreTimePoint> QuicConnection::next_wakeup() const {
    return earliest_of(loss_deadline(), pto_deadline(), ack_deadline());
}
```

Implementation checklist:

- run packet-threshold and time-threshold loss detection after ACK processing
- on loss, mark affected CRYPTO/STREAM ranges lost so they become sendable again
- on PTO expiry, send at least one ack-eliciting probe using:
  1. new data if available
  2. otherwise retransmittable data
  3. otherwise `PING`
- do not declare packets lost solely because PTO fired
- make `QuicCoreTimerExpired` in `src/quic/core.cpp` call into the connection's
  recovery machinery instead of doing nothing
- leave congestion window / pacing absent; if recovery says data is sendable,
  `advance(...)` drains it immediately

- [ ] **Step 5: Run the targeted recovery tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter='QuicCoreTest.HandshakeRecoversWhenInitialFlightIsDropped:QuicCoreTest.ApplicationDataIsRetransmittedAfterLoss:QuicCoreTest.AckProcessingClearsOutstandingDataAndRemovesWakeup'
```

Expected: the dropped-handshake and dropped-application scripts recover and the
idle wakeup clears once outstanding data is acknowledged.

- [ ] **Step 6: Commit the recovery integration**

Run:

```bash
git add src/quic/connection.h src/quic/connection.cpp src/quic/core.cpp tests/quic_core_test.cpp tests/quic_test_utils.h
git commit -m "feat: add QUIC loss detection and PTO recovery"
```

### Task 6: Prove Wrapper-Level Message Delivery Under Loss And Reordering

**Files:**
- Modify: `tests/quic_demo_channel_test.cpp`
- Modify: `tests/quic_test_utils.h`
- Optional Modify: `src/main.cpp`

- [ ] **Step 1: Write failing `QuicDemoChannel` recovery tests**

Add wrapper-level tests that prove the message API benefits from the transport
recovery work without changing the wrapper API:

```cpp
TEST(QuicDemoChannelTest, QueuedMessageIsDeliveredAfterSingleDatagramLoss) {
    coquic::quic::QuicDemoChannel client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicDemoChannel server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_demo_channel_handshake(client, server,
                                                     coquic::quic::test::test_time());
    const auto send = client.advance(
        coquic::quic::QuicDemoChannelQueueMessage{
            .bytes = coquic::quic::test::bytes_from_string("ping"),
        },
        coquic::quic::test::test_time(1));

    // Drop first send, drive client's timer, deliver retransmission, expect one message.
}

TEST(QuicDemoChannelTest, ReorderedTransportDatagramsDoNotDuplicateMessageDelivery) {
    // deliver later datagram before earlier one and assert exactly one message effect.
}
```

Keep the existing framing/failure tests unchanged unless recovery makes one of
those assumptions obsolete.

- [ ] **Step 2: Run the targeted wrapper tests and confirm they fail**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter='QuicDemoChannelTest.QueuedMessageIsDeliveredAfterSingleDatagramLoss:QuicDemoChannelTest.ReorderedTransportDatagramsDoNotDuplicateMessageDelivery'
```

Expected: failure because the current wrapper only succeeds when transport is
ideal.

- [ ] **Step 3: Adjust wrapper/script helpers only as needed**

Use the new lossy relay helpers from `tests/quic_test_utils.h` to keep the
wrapper tests readable. Only touch `src/main.cpp` if the runtime loop mishandles
real `next_wakeup` values under recovery; otherwise leave the demo executable
unchanged.

Acceptable minimal runtime fix if needed:

```cpp
if (next_wakeup.has_value() && *next_wakeup <= now()) {
    auto step = channel.advance(coquic::quic::QuicCoreTimerExpired{}, now());
    // dispatch effects, then replace next_wakeup with step.next_wakeup
}
```

If `src/main.cpp` already behaves correctly, make no production changes in this
step and keep the work test-only.

- [ ] **Step 4: Run the targeted wrapper tests and confirm they pass**

Run:

```bash
nix develop -c zig build test -- -Dtls_backend=quictls --gtest_filter='QuicDemoChannelTest.QueuedMessageIsDeliveredAfterSingleDatagramLoss:QuicDemoChannelTest.ReorderedTransportDatagramsDoNotDuplicateMessageDelivery:QuicDemoChannelTest.SocketBackedPollApiSmokeTestDeliversMessage'
```

Expected: wrapper delivery survives loss/reordering and the existing socket
smoke test still passes.

- [ ] **Step 5: Run full verification and commit the completed slice**

Run:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build -- -Dtls_backend=quictls
nix develop -c zig build test -- -Dtls_backend=quictls
```

Then commit:

```bash
git add src/quic/connection.h src/quic/connection.cpp src/quic/core.cpp src/quic/crypto_stream.h src/quic/crypto_stream.cpp src/quic/recovery.h src/quic/recovery.cpp src/quic/transport_parameters.h src/quic/transport_parameters.cpp tests/quic_core_test.cpp tests/quic_crypto_stream_test.cpp tests/quic_demo_channel_test.cpp tests/quic_recovery_test.cpp tests/quic_test_utils.h src/main.cpp
git commit -m "feat: add QUIC recovery and retransmission"
```
