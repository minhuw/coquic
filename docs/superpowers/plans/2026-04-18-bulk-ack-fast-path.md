# Bulk ACK Fast Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce ACK-path CPU in the CI-shaped bulk-download workload without changing QUIC wire behavior or breaking existing correctness.

**Architecture:** Keep inbound `AckFrame` compatibility, but add reusable ACK range walkers so recovery can consume ranges directly without allocating or sorting. For outbound ACKs, add a send-only `OutboundAckFrame` that references `ReceivedPacketHistory`, then teach frame/protected-packet serialization to size and write ACKs through dedicated helpers instead of the generic ACK materialization path.

**Tech Stack:** C++20, GoogleTest, Zig build, Linux `perf`, `coquic-perf`

---

## File Structure

- Modify: `src/quic/frame.h`
  - Add reusable ACK range/header helper types, declare the send-only `OutboundAckFrame` variant, and expose ACK-specific wire helper declarations.
- Modify: `src/quic/frame.cpp`
  - Implement ACK range cursors, outbound ACK materialization helpers, ACK-specific size/write helpers, and generic frame dispatch that safely handles the new frame variant while preserving existing wire bytes.
- Modify: `src/quic/recovery.h`
  - Expose outbound ACK header/range walking from `ReceivedPacketHistory` and add a direct-ACK overload for `PacketSpaceRecovery::on_ack_received(...)`.
- Modify: `src/quic/recovery.cpp`
  - Remove the ACK receive vector+sort path, add direct range walking for recovery, and implement outbound ACK header construction from receive history.
- Modify: `src/quic/connection.cpp`
  - Route inbound ACK handling through the new direct recovery overload, switch one-RTT outbound ACK production from owned `AckFrame` materialization to `OutboundAckFrame` snapshots, and update frame-classification helpers for the new variant.
- Modify: `src/quic/packet.cpp`
  - Treat `OutboundAckFrame` like `AckFrame` in generic packet-type validation so the new variant cannot slip through forbidden packet spaces.
- Modify: `src/quic/protected_codec.cpp`
  - Replace per-frame ACK size/write calls with the new ACK-aware frame wire helpers in the packet assembly hot path and keep frame-space validation correct for the new variant.
- Modify: `src/quic/buffer.cpp`
  - Make `CountingBufferWriter::write_varint(...)` use `encoded_varint_size(...)` directly instead of generating temporary varint bytes.
- Modify: `src/quic/qlog/json.cpp`
  - Serialize `OutboundAckFrame` as an ACK in qlog output instead of letting the new variant fall through to the handshake-done branch.
- Modify: `tests/core/packets/frame_test.cpp`
  - Add ACK range cursor and ACK wire parity tests.
- Modify: `tests/core/packets/packet_test.cpp`
  - Add packet-type validation coverage that keeps `OutboundAckFrame` aligned with `AckFrame` in forbidden spaces.
- Modify: `tests/core/recovery/recovery_test.cpp`
  - Add differential recovery tests that compare direct ACK processing against the old expanded-range path.
- Modify: `tests/core/connection/handshake_test.cpp`
  - Keep the existing malformed/additional-range inbound ACK regression green after removing connection-side ACK expansion.
- Modify: `tests/core/connection/ack_test.cpp`
  - Add connection-level tests that prove one-RTT outbound ACK packets still encode the same ACK information and still respect delayed-ACK trimming behavior.
- Modify: `tests/core/packets/protected_codec_test.cpp`
  - Add packet serialization parity coverage for `OutboundAckFrame` versus materialized `AckFrame`.
- Modify: `tests/core/packets/buffer_test.cpp`
  - Add boundary tests for the counting-writer fast path.
- Modify: `tests/qlog/qlog_test.cpp`
  - Add qlog coverage that ensures `OutboundAckFrame` still renders as an ACK frame in packet snapshots.

### Task 1: Add Reusable ACK Range Walkers

**Files:**
- Modify: `src/quic/frame.h`
- Modify: `src/quic/frame.cpp`
- Test: `tests/core/packets/frame_test.cpp`

- [ ] **Step 1: Write the failing ACK range walker tests**

```cpp
TEST(QuicFrameTest, AckRangeCursorMatchesAckFramePacketNumberRanges) {
    const coquic::quic::AckFrame ack{
        .largest_acknowledged = 12,
        .ack_delay = 5,
        .first_ack_range = 2,
        .additional_ranges =
            {
                coquic::quic::AckRange{
                    .gap = 1,
                    .range_length = 0,
                },
                coquic::quic::AckRange{
                    .gap = 0,
                    .range_length = 1,
                },
            },
    };

    const auto expected = coquic::quic::ack_frame_packet_number_ranges(ack);
    ASSERT_TRUE(expected.has_value());

    auto cursor = coquic::quic::make_ack_range_cursor(ack);
    ASSERT_TRUE(cursor.has_value());

    std::vector<coquic::quic::AckPacketNumberRange> actual;
    while (const auto range = coquic::quic::next_ack_range(cursor.value())) {
        actual.push_back(*range);
    }

    EXPECT_EQ(actual, expected.value());
}

TEST(QuicFrameTest, AckRangeCursorRejectsInvalidFirstRange) {
    const auto cursor = coquic::quic::make_ack_range_cursor(coquic::quic::AckFrame{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 4,
    });

    ASSERT_FALSE(cursor.has_value());
    EXPECT_EQ(cursor.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}
```

- [ ] **Step 2: Run the focused frame tests to verify they fail**

Run: `nix develop -c zig build test -- --gtest_filter=QuicFrameTest.AckRangeCursorMatchesAckFramePacketNumberRanges:QuicFrameTest.AckRangeCursorRejectsInvalidFirstRange`

Expected: FAIL during compile or link because `make_ack_range_cursor(...)` and `next_ack_range(...)` do not exist yet.

- [ ] **Step 3: Implement the ACK range cursor API**

```cpp
// src/quic/frame.h
struct AckRangeCursor {
    std::uint64_t largest_acknowledged = 0;
    std::uint64_t first_ack_range = 0;
    std::span<const AckRange> additional_ranges;
    std::size_t next_additional_index = 0;
    std::uint64_t previous_smallest = 0;
    bool first_range_pending = true;
};

CodecResult<AckRangeCursor> make_ack_range_cursor(const AckFrame &ack);
std::optional<AckPacketNumberRange> next_ack_range(AckRangeCursor &cursor);
```

```cpp
// src/quic/frame.cpp
CodecResult<AckRangeCursor> make_ack_range_cursor(const AckFrame &ack) {
    if (ack.largest_acknowledged < ack.first_ack_range) {
        return CodecResult<AckRangeCursor>::failure(CodecErrorCode::invalid_varint, 0);
    }

    return CodecResult<AckRangeCursor>::success(AckRangeCursor{
        .largest_acknowledged = ack.largest_acknowledged,
        .first_ack_range = ack.first_ack_range,
        .additional_ranges = std::span<const AckRange>(ack.additional_ranges),
        .previous_smallest = ack.largest_acknowledged - ack.first_ack_range,
        .first_range_pending = true,
    });
}

std::optional<AckPacketNumberRange> next_ack_range(AckRangeCursor &cursor) {
    if (cursor.first_range_pending) {
        cursor.first_range_pending = false;
        return AckPacketNumberRange{
            .smallest = cursor.previous_smallest,
            .largest = cursor.largest_acknowledged,
        };
    }

    if (cursor.next_additional_index >= cursor.additional_ranges.size()) {
        return std::nullopt;
    }

    const auto &range = cursor.additional_ranges[cursor.next_additional_index++];
    if (cursor.previous_smallest < range.gap + 2) {
        return std::nullopt;
    }

    const auto largest = cursor.previous_smallest - range.gap - 2;
    if (largest < range.range_length) {
        return std::nullopt;
    }

    const auto smallest = largest - range.range_length;
    cursor.previous_smallest = smallest;
    return AckPacketNumberRange{
        .smallest = smallest,
        .largest = largest,
    };
}
```

- [ ] **Step 4: Run the focused frame tests to verify they pass**

Run: `nix develop -c zig build test -- --gtest_filter=QuicFrameTest.AckRangeCursorMatchesAckFramePacketNumberRanges:QuicFrameTest.AckRangeCursorRejectsInvalidFirstRange`

Expected: PASS with both tests green.

- [ ] **Step 5: Commit**

```bash
git add src/quic/frame.h src/quic/frame.cpp tests/core/packets/frame_test.cpp
git commit -m "perf: add ACK range cursor helpers"
```

### Task 2: Rewire Recovery To Consume ACKs Directly

**Files:**
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`
- Modify: `src/quic/connection.cpp`
- Test: `tests/core/recovery/recovery_test.cpp`
- Test: `tests/core/connection/handshake_test.cpp`

- [ ] **Step 1: Write the failing direct-recovery differential tests**

```cpp
TEST(QuicRecoveryTest, AckFrameDirectRecoveryMatchesExpandedRangeRecovery) {
    coquic::quic::PacketSpaceRecovery direct_recovery;
    coquic::quic::PacketSpaceRecovery expanded_recovery;

    for (std::uint64_t packet_number = 0; packet_number != 32; ++packet_number) {
        const auto sent = make_sent_packet(packet_number, /*ack_eliciting=*/true,
                                           coquic::quic::test::test_time(packet_number));
        direct_recovery.on_packet_sent(sent);
        expanded_recovery.on_packet_sent(sent);
    }

    const coquic::quic::AckFrame ack{
        .largest_acknowledged = 15,
        .ack_delay = 0,
        .first_ack_range = 1,
        .additional_ranges =
            {
                coquic::quic::AckRange{
                    .gap = 1,
                    .range_length = 0,
                },
            },
    };

    const auto direct = direct_recovery.on_ack_received(ack, coquic::quic::test::test_time(100));
    const auto ranges = coquic::quic::ack_frame_packet_number_ranges(ack);
    ASSERT_TRUE(ranges.has_value());
    const auto expanded = expanded_recovery.on_ack_received(
        std::span<const coquic::quic::AckPacketNumberRange>(ranges.value()),
        ack.largest_acknowledged, coquic::quic::test::test_time(100));

    EXPECT_EQ(packet_numbers_from_handles(direct_recovery, direct.acked_packets.handles()),
              packet_numbers_from_handles(expanded_recovery, expanded.acked_packets.handles()));
    EXPECT_EQ(packet_numbers_from_handles(direct_recovery, direct.lost_packets.handles()),
              packet_numbers_from_handles(expanded_recovery, expanded.lost_packets.handles()));
}
```

- [ ] **Step 2: Run the focused recovery tests to verify they fail**

Run: `nix develop -c zig build test -- --gtest_filter=QuicRecoveryTest.AckFrameDirectRecoveryMatchesExpandedRangeRecovery`

Expected: FAIL because `PacketSpaceRecovery::on_ack_received(const AckFrame&, ...)` still uses the old expanded-range path.

- [ ] **Step 3: Implement direct ACK recovery and remove the connection-side expansion**

```cpp
// src/quic/recovery.h
AckProcessingResult on_ack_received(AckRangeCursor cursor, std::uint64_t largest_acknowledged,
                                    QuicCoreTimePoint now);
```

```cpp
// src/quic/recovery.cpp
AckProcessingResult PacketSpaceRecovery::on_ack_received(AckRangeCursor cursor,
                                                         std::uint64_t largest_acknowledged,
                                                         QuicCoreTimePoint now) {
    AckProcessingResult result;
    struct BufferedAckResult {
        RecoveryPacketHandle handle;
        RecoveryPacketMetadata metadata;
    };
    std::vector<BufferedAckResult> acked_packets_descending;
    std::vector<BufferedAckResult> late_acked_packets_descending;
    bool mutated = false;
    const auto previous_largest_acked = largest_acked_packet_number_;
    largest_acked_packet_number_ = previous_largest_acked.has_value()
                                       ? std::max(*previous_largest_acked, largest_acknowledged)
                                       : largest_acknowledged;
    const auto effective_largest_acked = *largest_acked_packet_number_;
    if (!previous_largest_acked.has_value() || effective_largest_acked > *previous_largest_acked) {
        track_new_loss_candidates(previous_largest_acked, effective_largest_acked);
    }

    const auto previous_live_slot = [this](std::size_t slot_index) -> std::optional<std::size_t> {
        const auto previous = slots_[slot_index].prev_live_slot;
        if (previous == kInvalidLedgerSlotIndex) {
            return std::nullopt;
        }
        return previous;
    };

    auto current = newest_live_slot_at_or_below(largest_acknowledged);
    while (const auto range = next_ack_range(cursor)) {
        while (current.has_value() && *current > range->largest) {
            current = previous_live_slot(*current);
        }
        while (current.has_value() && *current >= range->smallest) {
            const auto slot_index = *current;
            const auto previous = previous_live_slot(slot_index);
            auto &slot = slots_[slot_index];
            const auto handle = packet_handle(slot, slot_index);

            if (slot.state == LedgerSlotState::sent) {
                const auto snapshot = packet_metadata(slot.packet);
                acked_packets_descending.push_back({
                    .handle = handle,
                    .metadata = snapshot,
                });
                if (!result.largest_newly_acked_packet.has_value() ||
                    snapshot.packet_number > result.largest_newly_acked_packet->packet_number) {
                    result.largest_newly_acked_packet.emplace(handle, snapshot);
                }
                if (slot.packet.packet_number == largest_acknowledged) {
                    result.largest_acknowledged_was_newly_acked = true;
                }
                if (slot.packet.ack_eliciting) {
                    result.has_newly_acked_ack_eliciting = true;
                }

                erase_from_tracked_sets(slot.packet);
                unlink_live_slot(slot_index);
                slot.acknowledged = true;
                mutated = true;
            } else if (slot.state == LedgerSlotState::declared_lost) {
                late_acked_packets_descending.push_back({
                    .handle = handle,
                    .metadata = packet_metadata(slot.packet),
                });
                unlink_live_slot(slot_index);
                slot.acknowledged = true;
                mutated = true;
            }

            current = previous;
        }
    }

    result.acked_packets.reserve(acked_packets_descending.size());
    for (auto it = acked_packets_descending.rbegin(); it != acked_packets_descending.rend(); ++it) {
        result.acked_packets.push_back(it->handle, it->metadata);
    }
    result.late_acked_packets.reserve(late_acked_packets_descending.size());
    for (auto it = late_acked_packets_descending.rbegin();
         it != late_acked_packets_descending.rend(); ++it) {
        result.late_acked_packets.push_back(it->handle, it->metadata);
    }

    if (slots_.empty()) {
        return result;
    }

    const auto loss_scan_end =
        std::min<std::size_t>(static_cast<std::size_t>(effective_largest_acked), slots_.size());
    for (auto slot_index = first_live_slot_;
         slot_index != kInvalidLedgerSlotIndex && slot_index < loss_scan_end;) {
        auto &slot = slots_[slot_index];
        const auto next_live_slot = slot.next_live_slot;
        const auto packet_number = slot.packet.packet_number;
        if (slot.state != LedgerSlotState::sent || !slot.packet.in_flight) {
            slot_index = next_live_slot;
            continue;
        }

        if (!is_packet_threshold_lost(packet_number, effective_largest_acked) &&
            !is_time_threshold_lost(rtt_state_, slot.packet.sent_time, now)) {
            slot_index = next_live_slot;
            continue;
        }

        erase_from_tracked_sets(slot.packet);
        slot.state = LedgerSlotState::declared_lost;
        auto metadata = packet_metadata(slot.packet);
        metadata.in_flight = false;
        metadata.declared_lost = true;
        result.lost_packets.push_back(packet_handle(slot, slot_index), metadata);
        mutated = true;
        slot_index = next_live_slot;
    }

    if (mutated) {
        ++compatibility_version_;
    }
    return result;
}

AckProcessingResult PacketSpaceRecovery::on_ack_received(const AckFrame &ack,
                                                         QuicCoreTimePoint now) {
    const auto cursor = make_ack_range_cursor(ack);
    if (!cursor.has_value()) {
        return on_ack_received(std::span<const AckPacketNumberRange>{}, ack.largest_acknowledged,
                               now);
    }
    return on_ack_received(cursor.value(), ack.largest_acknowledged, now);
}
```

```cpp
// src/quic/connection.cpp
packet_space.recovery.rtt_state() = shared_recovery_rtt_state();
auto ack_result = packet_space.recovery.on_ack_received(ack, now);
std::vector<SentPacketRecord> acked_packets;
acked_packets.reserve(ack_result.acked_packets.size());
for (const auto handle : ack_result.acked_packets.handles()) {
    auto retired_packet = retire_acked_packet(packet_space, handle);
    if (!retired_packet.has_value()) {
        continue;
    }
    acked_packets.push_back(*retired_packet);
}
```

- [ ] **Step 4: Run the focused recovery and connection ACK tests**

Run: `nix develop -c zig build test -- --gtest_filter=QuicRecoveryTest.AckFrameDirectRecoveryMatchesExpandedRangeRecovery:QuicCoreTest.ProcessInboundAckAcceptsAdditionalRangesAndLeavesMalformedRangesUnacknowledged`

Expected: PASS with both the new differential recovery test and the existing connection ACK regression test green.

- [ ] **Step 5: Commit**

```bash
git add src/quic/recovery.h src/quic/recovery.cpp src/quic/connection.cpp tests/core/recovery/recovery_test.cpp tests/core/connection/handshake_test.cpp
git commit -m "perf: remove ACK receive expansion and sort"
```

### Task 3: Add Outbound ACK Snapshot Helpers

**Files:**
- Modify: `src/quic/frame.h`
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`
- Test: `tests/core/recovery/recovery_test.cpp`

- [ ] **Step 1: Write the failing outbound-ACK snapshot tests**

```cpp
TEST(QuicRecoveryTest, AckHistoryBuildsOutboundAckHeaderWithoutMaterializingAckRanges) {
    coquic::quic::ReceivedPacketHistory history;
    history.record_received(0, true, coquic::quic::test::test_time(1));
    history.record_received(1, true, coquic::quic::test::test_time(2));
    history.record_received(4, true, coquic::quic::test::test_time(3));

    const auto header =
        history.build_outbound_ack_header(/*ack_delay_exponent=*/3,
                                          coquic::quic::test::test_time(4));
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ(header->largest_acknowledged, 4u);
    EXPECT_EQ(header->first_ack_range, 0u);
    EXPECT_EQ(header->additional_range_count, 1u);
}
```

- [ ] **Step 2: Run the focused ACK history test to verify it fails**

Run: `nix develop -c zig build test -- --gtest_filter=QuicRecoveryTest.AckHistoryBuildsOutboundAckHeaderWithoutMaterializingAckRanges`

Expected: FAIL because `build_outbound_ack_header(...)` does not exist yet.

- [ ] **Step 3: Add outbound ACK header construction and range walking**

```cpp
// src/quic/frame.h
struct OutboundAckHeader {
    std::uint64_t largest_acknowledged = 0;
    std::uint64_t ack_delay = 0;
    std::uint64_t first_ack_range = 0;
    std::size_t additional_range_count = 0;
    std::optional<AckEcnCounts> ecn_counts;
};
```

```cpp
// src/quic/recovery.h
std::optional<OutboundAckHeader> build_outbound_ack_header(std::uint64_t ack_delay_exponent,
                                                           QuicCoreTimePoint now,
                                                           bool allow_non_pending = false) const;

template <typename Callback>
void for_each_additional_ack_range_descending(const OutboundAckHeader &header,
                                              Callback &&callback) const {
    auto it = std::next(ranges_.rbegin());
    auto previous_smallest = header.largest_acknowledged - header.first_ack_range;
    for (; it != ranges_.rend(); ++it) {
        const auto range_start = it->first;
        const auto range_end = it->second.largest_packet_number;
        callback(AckRange{
            .gap = previous_smallest - range_end - 2,
            .range_length = range_end - range_start,
        });
        previous_smallest = range_start;
    }
}
```

```cpp
// src/quic/recovery.cpp
std::optional<OutboundAckHeader>
ReceivedPacketHistory::build_outbound_ack_header(std::uint64_t ack_delay_exponent,
                                                 QuicCoreTimePoint now,
                                                 bool allow_non_pending) const {
    if (ranges_.empty()) {
        return std::nullopt;
    }
    if (!ack_pending_ && !allow_non_pending) {
        return std::nullopt;
    }

    const auto largest_range = ranges_.rbegin();
    const auto largest_received_packet_record =
        largest_received_packet_record_.value_or(ReceivedPacketRecord{
            .received_time = now,
        });
    const auto ack_delay = std::chrono::duration_cast<std::chrono::microseconds>(std::max(
        now - largest_received_packet_record.received_time, QuicCoreClock::duration::zero()));

    return OutboundAckHeader{
        .largest_acknowledged = largest_range->second.largest_packet_number,
        .ack_delay = encode_ack_delay(ack_delay, ack_delay_exponent),
        .first_ack_range = largest_range->second.largest_packet_number - largest_range->first,
        .additional_range_count = ranges_.size() - 1,
        .ecn_counts = ecn_feedback_accessible_ ? std::optional<AckEcnCounts>{ecn_counts_}
                                               : std::nullopt,
    };
}
```

- [ ] **Step 4: Run the focused ACK history tests to verify they pass**

Run: `nix develop -c zig build test -- --gtest_filter=QuicRecoveryTest.AckHistoryBuildsOutboundAckHeaderWithoutMaterializingAckRanges:QuicRecoveryTest.AckHistoryBuildsAckFrameWithEcnCountsForMarkedPackets`

Expected: PASS with the new header snapshot test and the existing ACK history ECN coverage green.

- [ ] **Step 5: Commit**

```bash
git add src/quic/frame.h src/quic/recovery.h src/quic/recovery.cpp tests/core/recovery/recovery_test.cpp
git commit -m "perf: add outbound ACK header snapshots"
```

### Task 4: Special-Case ACK Wire Size And Serialization

**Files:**
- Modify: `src/quic/frame.h`
- Modify: `src/quic/frame.cpp`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/packet.cpp`
- Modify: `src/quic/protected_codec.cpp`
- Modify: `src/quic/qlog/json.cpp`
- Test: `tests/core/packets/frame_test.cpp`
- Test: `tests/core/packets/packet_test.cpp`
- Test: `tests/core/connection/ack_test.cpp`
- Test: `tests/core/packets/protected_codec_test.cpp`
- Test: `tests/qlog/qlog_test.cpp`

- [ ] **Step 1: Write the failing ACK wire parity tests**

```cpp
TEST(QuicFrameTest, OutboundAckFrameWireHelpersMatchMaterializedAckFrame) {
    coquic::quic::ReceivedPacketHistory history;
    history.record_received(0, true, coquic::quic::test::test_time(1));
    history.record_received(1, true, coquic::quic::test::test_time(2));
    history.record_received(4, true, coquic::quic::test::test_time(3));

    const auto header =
        history.build_outbound_ack_header(/*ack_delay_exponent=*/3,
                                          coquic::quic::test::test_time(4));
    ASSERT_TRUE(header.has_value());

    const auto materialized =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(4));
    ASSERT_TRUE(materialized.has_value());

    const auto encoded_materialized =
        coquic::quic::serialize_frame(coquic::quic::Frame{*materialized});
    ASSERT_TRUE(encoded_materialized.has_value());

    std::vector<std::byte> output(encoded_materialized.value().size());
    const auto written = coquic::quic::write_frame_wire_bytes(
        std::span<std::byte>(output),
        coquic::quic::Frame{coquic::quic::OutboundAckFrame{
            .history = &history,
            .header = *header,
        }});

    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(output, encoded_materialized.value());
}
```

```cpp
TEST(QuicProtectedCodecTest, OutboundAckFrameSerializesLikeMaterializedAckFrame) {
    auto history = coquic::quic::ReceivedPacketHistory{};
    history.record_received(0, true, coquic::quic::test::test_time(1));
    history.record_received(3, true, coquic::quic::test::test_time(2));

    const auto header =
        history.build_outbound_ack_header(/*ack_delay_exponent=*/3,
                                          coquic::quic::test::test_time(3));
    ASSERT_TRUE(header.has_value());

    const auto materialized =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(3));
    ASSERT_TRUE(materialized.has_value());

    auto outbound_packet = make_minimal_one_rtt_packet();
    outbound_packet.frames = {
        coquic::quic::Frame{coquic::quic::OutboundAckFrame{
            .history = &history,
            .header = *header,
        }},
    };
    auto materialized_packet = make_minimal_one_rtt_packet();
    materialized_packet.frames = {coquic::quic::Frame{*materialized}};

    const auto context = make_one_rtt_serialize_context(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, 32);
    const auto encoded_view = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{outbound_packet}, context);
    const auto encoded_frame = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{materialized_packet}, context);

    ASSERT_TRUE(encoded_view.has_value());
    ASSERT_TRUE(encoded_frame.has_value());
    EXPECT_EQ(encoded_view.value(), encoded_frame.value());
}
```

```cpp
TEST(QuicPacketTest, RejectsOutboundAckFrameInZeroRttPacket) {
    coquic::quic::ReceivedPacketHistory history;
    history.record_received(5, true, coquic::quic::test::test_time(1));
    const auto header =
        history.build_outbound_ack_header(/*ack_delay_exponent=*/3,
                                          coquic::quic::test::test_time(2));
    ASSERT_TRUE(header.has_value());

    const auto encoded = coquic::quic::serialize_packet(coquic::quic::ZeroRttPacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 7,
        .frames =
            {
                coquic::quic::Frame{coquic::quic::OutboundAckFrame{
                    .history = &history,
                    .header = *header,
                }},
            },
    });

    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
}
```

```cpp
TEST(QuicQlogTest, PacketSnapshotSerializesOutboundAckFrameAsAck) {
    coquic::quic::ReceivedPacketHistory history;
    history.record_received(9, true, coquic::quic::test::test_time(1));
    const auto header =
        history.build_outbound_ack_header(/*ack_delay_exponent=*/3,
                                          coquic::quic::test::test_time(2));
    ASSERT_TRUE(header.has_value());

    const auto snapshot_json = coquic::quic::qlog::serialize_packet_snapshot(
        coquic::quic::qlog::PacketSnapshot{
            .header = coquic::quic::qlog::PacketHeader{.packet_type = "1RTT"},
            .frames =
                {
                    coquic::quic::Frame{coquic::quic::OutboundAckFrame{
                        .history = &history,
                        .header = *header,
                    }},
                },
        });

    EXPECT_NE(snapshot_json.find("\"frame_type\":\"ack\""), std::string::npos);
    EXPECT_NE(snapshot_json.find("\"largest_acknowledged\":9"), std::string::npos);
}
```

```cpp
TEST(QuicCoreTest, LargeAckOnlyHistoryStillEmitsTrimmedAckDatagram) {
    auto connection = make_connected_server_connection();
    for (std::uint64_t packet_number = 0; packet_number != 2048; ++packet_number) {
        connection.application_space_.received_packets.record_received(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
    }
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(4096);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(4096));

    ASSERT_FALSE(datagram.empty());
    EXPECT_TRUE(datagram_has_application_ack(connection, datagram));
}
```

- [ ] **Step 2: Run the focused frame and protected codec tests to verify they fail**

Run: `nix develop -c zig build test -- --gtest_filter=QuicFrameTest.OutboundAckFrameWireHelpersMatchMaterializedAckFrame:QuicProtectedCodecTest.OutboundAckFrameSerializesLikeMaterializedAckFrame:QuicPacketTest.RejectsOutboundAckFrameInZeroRttPacket:QuicQlogTest.PacketSnapshotSerializesOutboundAckFrameAsAck:QuicCoreTest.LargeAckOnlyHistoryStillEmitsTrimmedAckDatagram`

Expected: FAIL because `write_frame_wire_bytes(...)` and ACK-aware protected codec dispatch do not exist yet.

- [ ] **Step 3: Add `OutboundAckFrame`, ACK-specific wire helpers, and safe variant handling**

```cpp
// src/quic/frame.h
class ReceivedPacketHistory;

struct OutboundAckFrame {
    const ReceivedPacketHistory *history = nullptr;
    OutboundAckHeader header;
};

using Frame =
    std::variant<PaddingFrame, PingFrame, AckFrame, ResetStreamFrame, StopSendingFrame,
                 CryptoFrame, NewTokenFrame, StreamFrame, MaxDataFrame, MaxStreamDataFrame,
                 MaxStreamsFrame, DataBlockedFrame, StreamDataBlockedFrame, StreamsBlockedFrame,
                 NewConnectionIdFrame, RetireConnectionIdFrame, PathChallengeFrame,
                 PathResponseFrame, TransportConnectionCloseFrame,
                 ApplicationConnectionCloseFrame, HandshakeDoneFrame, OutboundAckFrame>;

CodecResult<std::size_t> frame_wire_size(const Frame &frame);
CodecResult<std::size_t> write_frame_wire_bytes(std::span<std::byte> output, const Frame &frame);
```

```cpp
// src/quic/frame.cpp
namespace {

template <typename Writer, typename RangeWriter>
std::optional<CodecError> write_ack_fields(Writer &writer, const OutboundAckHeader &header,
                                           RangeWriter &&write_ranges) {
    if (const auto error =
            append_byte(writer, header.ecn_counts.has_value() ? std::byte{0x03} : std::byte{0x02})) {
        return error;
    }
    if (const auto error = append_varint(writer, header.largest_acknowledged)) {
        return error;
    }
    if (const auto error = append_varint(writer, header.ack_delay)) {
        return error;
    }
    if (const auto error = append_varint(writer, header.additional_range_count)) {
        return error;
    }
    if (const auto error = append_varint(writer, header.first_ack_range)) {
        return error;
    }
    if (const auto error = write_ranges(writer)) {
        return error;
    }
    if (header.ecn_counts.has_value()) {
        if (const auto error = append_varint(writer, header.ecn_counts->ect0)) {
            return error;
        }
        if (const auto error = append_varint(writer, header.ecn_counts->ect1)) {
            return error;
        }
        if (const auto error = append_varint(writer, header.ecn_counts->ecn_ce)) {
            return error;
        }
    }
    return std::nullopt;
}

template <typename Writer>
std::optional<CodecError> write_outbound_ack_frame(Writer &writer, const OutboundAckFrame &ack) {
    return write_ack_fields(writer, ack.header, [&](Writer &inner_writer) -> std::optional<CodecError> {
        std::optional<CodecError> first_error;
        ack.history->for_each_additional_ack_range_descending(
            ack.header, [&](const AckRange &range) {
                if (first_error.has_value()) {
                    return;
                }
                if (const auto error = append_varint(inner_writer, range.gap)) {
                    first_error = error;
                    return;
                }
                if (const auto error = append_varint(inner_writer, range.range_length)) {
                    first_error = error;
                }
            });
        return first_error;
    });
}

CodecResult<AckFrame> materialize_outbound_ack_frame(const OutboundAckFrame &ack) {
    AckFrame materialized{
        .largest_acknowledged = ack.header.largest_acknowledged,
        .ack_delay = ack.header.ack_delay,
        .first_ack_range = ack.header.first_ack_range,
        .ecn_counts = ack.header.ecn_counts,
    };
    materialized.additional_ranges.reserve(ack.header.additional_range_count);
    ack.history->for_each_additional_ack_range_descending(
        ack.header, [&](const AckRange &range) { materialized.additional_ranges.push_back(range); });
    return CodecResult<AckFrame>::success(std::move(materialized));
}

CodecResult<std::size_t> serialized_frame_size_legacy(const Frame &frame) {
    CountingBufferWriter writer;
    if (const auto error = serialize_frame_into_writer(writer, frame)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    return CodecResult<std::size_t>::success(writer.offset());
}

CodecResult<std::size_t> serialize_frame_into_legacy(std::span<std::byte> output,
                                                     const Frame &frame) {
    const auto size = serialized_frame_size_legacy(frame);
    if (!size.has_value()) {
        return CodecResult<std::size_t>::failure(size.error().code, size.error().offset);
    }
    if (output.size() < size.value()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0);
    }

    SpanBufferWriter writer(output);
    if (const auto error = serialize_frame_into_writer(writer, frame)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    return CodecResult<std::size_t>::success(writer.offset());
}

} // namespace

CodecResult<std::size_t> frame_wire_size(const Frame &frame) {
    if (const auto *outbound_ack = std::get_if<OutboundAckFrame>(&frame)) {
        CountingBufferWriter writer;
        if (const auto error = write_outbound_ack_frame(writer, *outbound_ack)) {
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
        return CodecResult<std::size_t>::success(writer.offset());
    }
    return serialized_frame_size_legacy(frame);
}

CodecResult<std::size_t> write_frame_wire_bytes(std::span<std::byte> output, const Frame &frame) {
    if (const auto *outbound_ack = std::get_if<OutboundAckFrame>(&frame)) {
        SpanBufferWriter writer(output);
        if (const auto error = write_outbound_ack_frame(writer, *outbound_ack)) {
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
        return CodecResult<std::size_t>::success(writer.offset());
    }
    return serialize_frame_into_legacy(output, frame);
}

CodecResult<std::vector<std::byte>> serialize_frame(const Frame &frame) {
    const auto size = frame_wire_size(frame);
    if (!size.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(size.error().code, size.error().offset);
    }
    std::vector<std::byte> bytes(size.value());
    const auto written = write_frame_wire_bytes(bytes, frame);
    if (!written.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(written.error().code,
                                                            written.error().offset);
    }
    return CodecResult<std::vector<std::byte>>::success(std::move(bytes));
}

CodecResult<std::size_t> serialized_frame_size(const Frame &frame) {
    return frame_wire_size(frame);
}

CodecResult<std::size_t> serialize_frame_into(std::span<std::byte> output, const Frame &frame) {
    return write_frame_wire_bytes(output, frame);
}

CodecResult<std::size_t> append_serialized_frame(std::vector<std::byte> &bytes, const Frame &frame) {
    const auto begin = bytes.size();
    const auto size = frame_wire_size(frame);
    if (!size.has_value()) {
        return CodecResult<std::size_t>::failure(size.error().code, size.error().offset);
    }
    bytes.resize(begin + size.value());
    const auto written = write_frame_wire_bytes(std::span<std::byte>(bytes).subspan(begin), frame);
    if (!written.has_value()) {
        bytes.resize(begin);
        return CodecResult<std::size_t>::failure(written.error().code, written.error().offset);
    }
    return CodecResult<std::size_t>::success(written.value());
}

ReceivedFrame to_received_frame(Frame frame) {
    return std::visit(
        [](auto value) -> ReceivedFrame {
            using Value = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<Value, OutboundAckFrame>) {
                return materialize_outbound_ack_frame(value).value();
            } else if constexpr (std::is_same_v<Value, CryptoFrame>) {
                return ReceivedCryptoFrame{
                    .offset = value.offset,
                    .crypto_data = SharedBytes(std::move(value.crypto_data)),
                };
            } else if constexpr (std::is_same_v<Value, StreamFrame>) {
                return ReceivedStreamFrame{
                    .fin = value.fin,
                    .has_offset = value.has_offset,
                    .has_length = value.has_length,
                    .stream_id = value.stream_id,
                    .offset = value.offset,
                    .stream_data = SharedBytes(std::move(value.stream_data)),
                };
            } else {
                return value;
            }
        },
        std::move(frame));
}
```

```cpp
// src/quic/connection.cpp
static_assert(std::variant_size_v<Frame> == 22,
              "Update process_inbound_application when Frame gains new variants");

constexpr auto kAckElicitingByFrameIndex = std::to_array<bool>({
    false, // PaddingFrame
    true,  // PingFrame
    false, // AckFrame
    true,  // ResetStreamFrame
    true,  // StopSendingFrame
    true,  // CryptoFrame
    true,  // NewTokenFrame
    true,  // StreamFrame
    true,  // MaxDataFrame
    true,  // MaxStreamDataFrame
    true,  // MaxStreamsFrame
    true,  // DataBlockedFrame
    true,  // StreamDataBlockedFrame
    true,  // StreamsBlockedFrame
    true,  // NewConnectionIdFrame
    true,  // RetireConnectionIdFrame
    true,  // PathChallengeFrame
    true,  // PathResponseFrame
    false, // TransportConnectionCloseFrame
    false, // ApplicationConnectionCloseFrame
    true,  // HandshakeDoneFrame
    false, // OutboundAckFrame
});

const auto base_ack_header = use_zero_rtt_packet_protection
                                 ? std::optional<coquic::quic::OutboundAckHeader>{}
                                 : application_space_.received_packets.build_outbound_ack_header(
                                       local_transport_parameters_.ack_delay_exponent, now);

if (base_ack_header.has_value()) {
    frames.emplace_back(coquic::quic::OutboundAckFrame{
        .history = &application_space_.received_packets,
        .header = *base_ack_header,
    });
}
```

```cpp
// src/quic/packet.cpp
const auto is_ack_like = std::holds_alternative<AckFrame>(frame) ||
                         std::holds_alternative<OutboundAckFrame>(frame);
if (packet_type == ProtectedPacketType::one_rtt) {
    return true;
}
if (packet_type == ProtectedPacketType::zero_rtt) {
    return !is_ack_like && !std::holds_alternative<CryptoFrame>(frame) &&
           !std::holds_alternative<HandshakeDoneFrame>(frame) &&
           !std::holds_alternative<NewTokenFrame>(frame) &&
           !std::holds_alternative<PathResponseFrame>(frame) &&
           !std::holds_alternative<RetireConnectionIdFrame>(frame);
}
return std::holds_alternative<PaddingFrame>(frame) || std::holds_alternative<PingFrame>(frame) ||
       is_ack_like || std::holds_alternative<CryptoFrame>(frame) ||
       std::holds_alternative<TransportConnectionCloseFrame>(frame);
```

```cpp
// src/quic/protected_codec.cpp
const auto is_ack_like = std::holds_alternative<AckFrame>(frame) ||
                         std::holds_alternative<OutboundAckFrame>(frame);
if (packet_type == LongHeaderPacketType::zero_rtt) {
    return !is_ack_like && !std::holds_alternative<CryptoFrame>(frame) &&
           !std::holds_alternative<HandshakeDoneFrame>(frame) &&
           !std::holds_alternative<NewTokenFrame>(frame) &&
           !std::holds_alternative<PathResponseFrame>(frame) &&
           !std::holds_alternative<RetireConnectionIdFrame>(frame);
}
return std::holds_alternative<PaddingFrame>(frame) || std::holds_alternative<PingFrame>(frame) ||
       is_ack_like || std::holds_alternative<CryptoFrame>(frame) ||
       std::holds_alternative<TransportConnectionCloseFrame>(frame);
```

```cpp
// src/quic/qlog/json.cpp
} else if constexpr (std::is_same_v<FrameType, OutboundAckFrame>) {
    return "{\"frame_type\":\"ack\",\"largest_acknowledged\":" +
           std::to_string(value.header.largest_acknowledged) +
           ",\"ack_delay\":" + std::to_string(value.header.ack_delay) + "}";
```

```cpp
// src/quic/protected_codec.cpp
const auto encoded = frame_wire_size(packet.frames[frame_index]);
if (!encoded.has_value()) {
    return CodecResult<std::size_t>::failure(encoded.error().code, encoded.error().offset);
}
frame_payload_size += encoded.value();

const auto written = write_frame_wire_bytes(payload_bytes.subspan(payload_written), frame);
if (!written.has_value()) {
    rollback();
    return CodecResult<std::size_t>::failure(written.error().code, written.error().offset);
}
payload_written += written.value();
```

- [ ] **Step 4: Run the focused frame, protected codec, and ACK connection tests**

Run: `nix develop -c zig build test -- --gtest_filter=QuicFrameTest.OutboundAckFrameWireHelpersMatchMaterializedAckFrame:QuicProtectedCodecTest.OutboundAckFrameSerializesLikeMaterializedAckFrame:QuicPacketTest.RejectsOutboundAckFrameInZeroRttPacket:QuicQlogTest.PacketSnapshotSerializesOutboundAckFrameAsAck:QuicCoreTest.ApplicationAckFramesIncludeEcnCountsWhenReceiveMetadataIsAvailable:QuicCoreTest.LargeAckOnlyHistoryStillEmitsTrimmedAckDatagram`

Expected: PASS with byte-for-byte ACK parity across the new direct serializer path.

- [ ] **Step 5: Commit**

```bash
git add src/quic/frame.h src/quic/frame.cpp src/quic/connection.cpp src/quic/packet.cpp src/quic/protected_codec.cpp src/quic/qlog/json.cpp tests/core/packets/frame_test.cpp tests/core/packets/packet_test.cpp tests/core/connection/ack_test.cpp tests/core/packets/protected_codec_test.cpp tests/qlog/qlog_test.cpp
git commit -m "perf: direct-write outbound ACK frames"
```

### Task 5: Tighten Counting Varint Writes

**Files:**
- Modify: `src/quic/buffer.cpp`
- Test: `tests/core/packets/buffer_test.cpp`

- [ ] **Step 1: Write the failing counting-writer boundary test**

```cpp
TEST(QuicBufferTest, CountingBufferWriterUsesEncodedVarintBoundaries) {
    coquic::quic::CountingBufferWriter writer;

    ASSERT_FALSE(writer.write_varint(63).has_value());
    ASSERT_FALSE(writer.write_varint(64).has_value());
    ASSERT_FALSE(writer.write_varint(16383).has_value());
    ASSERT_FALSE(writer.write_varint(16384).has_value());

    EXPECT_EQ(writer.offset(), 1u + 2u + 2u + 4u);
}
```

- [ ] **Step 2: Run the focused buffer tests to verify they fail**

Run: `nix develop -c zig build test -- --gtest_filter=QuicBufferTest.CountingBufferWriterUsesEncodedVarintBoundaries`

Expected: FAIL because the new test is not present yet.

- [ ] **Step 3: Replace counting-writer byte generation with size-only accounting**

```cpp
// src/quic/buffer.cpp
std::optional<CodecError> CountingBufferWriter::write_varint(std::uint64_t value) {
    constexpr std::uint64_t kMaxQuicVarInt = 4611686018427387903ull;
    const auto start_offset = offset_;
    if (value > kMaxQuicVarInt) {
        return CodecError{
            .code = CodecErrorCode::invalid_varint,
            .offset = start_offset,
        };
    }

    offset_ += encoded_varint_size(value);
    return std::nullopt;
}
```

- [ ] **Step 4: Run the focused buffer tests to verify they pass**

Run: `nix develop -c zig build test -- --gtest_filter=QuicBufferTest.CountingBufferWriterUsesEncodedVarintBoundaries:QuicBufferTest.CountingBufferWriterTracksWrittenSizeWithoutStorage`

Expected: PASS with both counting-writer tests green.

- [ ] **Step 5: Commit**

```bash
git add src/quic/buffer.cpp tests/core/packets/buffer_test.cpp
git commit -m "perf: trim counting varint overhead"
```

### Task 6: Full Verification And Perf Re-Measurement

**Files:**
- Verify: `src/quic/frame.h`
- Verify: `src/quic/frame.cpp`
- Verify: `src/quic/recovery.h`
- Verify: `src/quic/recovery.cpp`
- Verify: `src/quic/connection.cpp`
- Verify: `src/quic/packet.cpp`
- Verify: `src/quic/protected_codec.cpp`
- Verify: `src/quic/buffer.cpp`
- Verify: `src/quic/qlog/json.cpp`
- Verify: `tests/core/packets/frame_test.cpp`
- Verify: `tests/core/packets/packet_test.cpp`
- Verify: `tests/core/recovery/recovery_test.cpp`
- Verify: `tests/core/connection/handshake_test.cpp`
- Verify: `tests/core/connection/ack_test.cpp`
- Verify: `tests/core/packets/protected_codec_test.cpp`
- Verify: `tests/core/packets/buffer_test.cpp`
- Verify: `tests/qlog/qlog_test.cpp`

- [ ] **Step 1: Run the release build**

Run: `nix develop -c zig build -Doptimize=ReleaseFast`

Expected: build completes successfully and produces `zig-out/bin/coquic-perf`.

- [ ] **Step 2: Run the full GoogleTest suite**

Run: `nix develop -c zig build test`

Expected: PASS with zero failing GoogleTest binaries.

- [ ] **Step 3: Run the CI-shaped bulk benchmark**

Run:

```bash
port=9448
server_log=$(mktemp)
json_out=$(mktemp --suffix=.json)
cleanup() {
  if [ -n "${server_pid:-}" ]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -f "$server_log" "$json_out"
}
trap cleanup EXIT

taskset -c 2 ./zig-out/bin/coquic-perf server \
  --host 127.0.0.1 \
  --port "$port" \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem \
  --io-backend socket >"$server_log" 2>&1 &
server_pid=$!
sleep 1

taskset -c 3 ./zig-out/bin/coquic-perf client \
  --host 127.0.0.1 \
  --port "$port" \
  --mode bulk \
  --io-backend socket \
  --request-bytes 0 \
  --response-bytes 1048576 \
  --streams 4 \
  --connections 1 \
  --requests-in-flight 1 \
  --direction download \
  --warmup 5s \
  --duration 20s \
  --json-out "$json_out"

cat "$json_out"
```

Expected: `status=ok` and `throughput_mib_per_s` higher than the pre-change local baseline of roughly `73-77 MiB/s`.

- [ ] **Step 4: Capture fresh server and client perf samples**

Run:

```bash
orig_perf=$(cat /proc/sys/kernel/perf_event_paranoid)
orig_kptr=$(cat /proc/sys/kernel/kptr_restrict)
sudo sysctl -q -w kernel.perf_event_paranoid=-1 kernel.kptr_restrict=0

out_dir=".bench-results/perf-analysis-post-ack-fast-path"
mkdir -p "$out_dir"

port=9449
taskset -c 2 ./zig-out/bin/coquic-perf server \
  --host 127.0.0.1 \
  --port "$port" \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem \
  --io-backend socket >"$out_dir/server.log" 2>&1 &
server_pid=$!
sleep 1

taskset -c 3 ./zig-out/bin/coquic-perf client \
  --host 127.0.0.1 \
  --port "$port" \
  --mode bulk \
  --io-backend socket \
  --request-bytes 0 \
  --response-bytes 1048576 \
  --streams 4 \
  --connections 1 \
  --requests-in-flight 1 \
  --direction download \
  --warmup 5s \
  --duration 20s \
  --json-out "$out_dir/client.json" >"$out_dir/client.txt" 2>&1 &
client_pid=$!

sleep 6
sudo perf record -F 799 -g --call-graph dwarf,16384 -p "$server_pid" -o "$out_dir/server.perf.data" -- sleep 10
sudo perf record -F 799 -g --call-graph dwarf,16384 -p "$client_pid" -o "$out_dir/client.perf.data" -- sleep 10
wait "$client_pid"
kill "$server_pid" >/dev/null 2>&1 || true
wait "$server_pid" >/dev/null 2>&1 || true

sudo perf report -f --stdio --no-inline --children --percent-limit 0.5 -i "$out_dir/server.perf.data" >"$out_dir/server.report.txt"
sudo perf report -f --stdio --no-inline --children --percent-limit 0.5 -i "$out_dir/client.perf.data" >"$out_dir/client.report.txt"

sudo sysctl -q -w kernel.perf_event_paranoid="$orig_perf" kernel.kptr_restrict="$orig_kptr"
```

Expected: server report shows `PacketSpaceRecovery::on_ack_received` materially reduced relative to the pre-change sample, and client report shows lower ACK build/serialize share relative to the pre-change sample.

- [ ] **Step 5: Commit**

```bash
git add src/quic/frame.h src/quic/frame.cpp src/quic/recovery.h src/quic/recovery.cpp src/quic/connection.cpp src/quic/packet.cpp src/quic/protected_codec.cpp src/quic/buffer.cpp src/quic/qlog/json.cpp tests/core/packets/frame_test.cpp tests/core/packets/packet_test.cpp tests/core/recovery/recovery_test.cpp tests/core/connection/handshake_test.cpp tests/core/connection/ack_test.cpp tests/core/packets/protected_codec_test.cpp tests/core/packets/buffer_test.cpp tests/qlog/qlog_test.cpp
git commit -m "perf: accelerate bulk ACK paths"
```
