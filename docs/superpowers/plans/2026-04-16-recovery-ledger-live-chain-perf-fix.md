# Recovery Ledger Live Chain Perf Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the bulk-download perf harness to the healthy `main` baseline by removing the recovery ledger's dense historical ACK and loss scans while keeping `PacketSpaceRecovery` as the canonical owner of sent-packet state.

**Architecture:** Convert `PacketSpaceRecovery` from a sliding front-compacted ledger into an append-only packet-number-indexed ledger with stable slot indices. Then add an intrusive live-packet chain plus monotonic loss-scan cursors so ACK handling, tracked-packet queries, and time-threshold loss detection only walk live unacknowledged packets instead of historical packet-number spans.

**Tech Stack:** C++20, Zig build/test, GoogleTest, QUIC recovery and connection code under `src/quic/`.

---

## File Map

- Modify: `src/quic/recovery.h`
  Purpose: remove sliding-front state, define stable slot indexing, and add live-chain/cursor fields.
- Modify: `src/quic/recovery.cpp`
  Purpose: implement append-only slot allocation, stable handle lookup, live-chain traversal, and loss-scan cursor updates.
- Modify: `tests/core/recovery/recovery_test.cpp`
  Purpose: add regression coverage for stable slot indices and tracked-packet removal after ACK and late ACK.

### Task 1: Make Recovery Handles Stable Across Retirement

**Files:**
- Modify: `tests/core/recovery/recovery_test.cpp`
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`

- [ ] **Step 1: Add the failing recovery test for append-only slot numbering**

Add a slot-count peer helper near the existing `PacketSpaceRecoveryTestPeer` and a new test near the existing handle-retirement coverage in `tests/core/recovery/recovery_test.cpp`:

```cpp
struct PacketSpaceRecoveryTestPeer {
    static bool sent_packets_contains(const PacketSpaceRecovery &recovery,
                                      std::uint64_t packet_number) {
        return recovery.sent_packets_.contains(packet_number);
    }

    static const SentPacketRecord &sent_packets_at(const PacketSpaceRecovery &recovery,
                                                   std::uint64_t packet_number) {
        return recovery.sent_packets_.at(packet_number);
    }

    static std::size_t slot_count(const PacketSpaceRecovery &recovery) {
        return recovery.slots_.size();
    }
};

TEST(QuicRecoveryTest, RetiringEarlierPacketsDoesNotRenumberLaterHandles) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));

    const auto handle_before = recovery.handle_for_packet_number(2);
    ASSERT_TRUE(handle_before.has_value());
    ASSERT_EQ(handle_before->slot_index, 2u);

    recovery.retire_packet(0);
    recovery.retire_packet(1);

    const auto handle_after = recovery.handle_for_packet_number(2);
    ASSERT_TRUE(handle_after.has_value());
    EXPECT_EQ(handle_after->slot_index, 2u);
    EXPECT_EQ(handle_after->slot_index, handle_before->slot_index);
    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_count(recovery), 3u);

    const auto *packet = recovery.packet_for_handle(*handle_before);
    ASSERT_NE(packet, nullptr);
    if (packet != nullptr) {
        EXPECT_EQ(packet->packet_number, 2u);
    }
}
```

- [ ] **Step 2: Run the new test to verify the current sliding ledger fails**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicRecoveryTest.RetiringEarlierPacketsDoesNotRenumberLaterHandles'
```

Expected: FAIL because the current `compact_retired_prefix()` logic renumbers packet `2` to slot `0` and shrinks `slots_` to size `1`.

- [ ] **Step 3: Replace front-compacted indexing with direct packet-number indexing in `src/quic/recovery.h`**

Update the private storage declarations so the slot vector is indexed directly by packet number and no longer tracks a sliding base:

```cpp
class PacketSpaceRecovery {
  public:
    // existing public API stays the same in this task

  private:
    struct SentPacketLedgerSlot {
        LedgerSlotState state = LedgerSlotState::empty;
        SentPacketRecord packet;
        bool acknowledged = false;
    };

    static DeadlineTrackedPacket tracked_packet(const SentPacketRecord &packet);
    static RecoveryPacketHandle packet_handle(const SentPacketLedgerSlot &slot,
                                              std::size_t slot_index);
    SentPacketLedgerSlot *slot_for_packet_number(std::uint64_t packet_number);
    const SentPacketLedgerSlot *slot_for_packet_number(std::uint64_t packet_number) const;
    SentPacketLedgerSlot *outstanding_slot_for_packet_number(std::uint64_t packet_number);
    const SentPacketLedgerSlot *
    outstanding_slot_for_packet_number(std::uint64_t packet_number) const;
    void erase_from_tracked_sets(const SentPacketRecord &packet);
    void maybe_track_as_loss_candidate(const SentPacketRecord &packet);
    void track_new_loss_candidates(std::optional<std::uint64_t> previous_largest_acked,
                                   std::uint64_t largest_acked);
    std::size_t ensure_slot_for_packet_number(std::uint64_t packet_number);

    std::vector<SentPacketLedgerSlot> slots_;
    std::set<DeadlineTrackedPacket, DeadlineTrackedPacketLess> in_flight_ack_eliciting_packets_;
    std::set<DeadlineTrackedPacket, DeadlineTrackedPacketLess> eligible_loss_packets_;
    std::optional<std::uint64_t> largest_acked_packet_number_;
    std::uint64_t compatibility_version_ = 0;
    RecoveryRttState rtt_state_;
    SentPacketsView sent_packets_{};
};
```

Delete these sliding-only members and declarations:

```cpp
-    void compact_retired_prefix();
-    std::uint64_t base_packet_number_ = 0;
```

- [ ] **Step 4: Implement append-only slot indexing in `src/quic/recovery.cpp`**

Make the slot vector direct-indexed and stop erasing from the front:

```cpp
std::size_t PacketSpaceRecovery::ensure_slot_for_packet_number(std::uint64_t packet_number) {
    const auto slot_index = static_cast<std::size_t>(packet_number);
    if (slot_index >= slots_.size()) {
        slots_.resize(slot_index + 1);
    }
    return slot_index;
}

const PacketSpaceRecovery::SentPacketLedgerSlot *
PacketSpaceRecovery::slot_for_packet_number(std::uint64_t packet_number) const {
    const auto slot_index = static_cast<std::size_t>(packet_number);
    if (slot_index >= slots_.size()) {
        return nullptr;
    }

    const auto &slot = slots_[slot_index];
    if ((slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost) ||
        slot.packet.packet_number != packet_number) {
        return nullptr;
    }

    return &slot;
}

std::optional<RecoveryPacketHandle>
PacketSpaceRecovery::handle_for_packet_number(std::uint64_t packet_number) const {
    const auto *slot = slot_for_packet_number(packet_number);
    if (slot == nullptr) {
        return std::nullopt;
    }
    return packet_handle(*slot, static_cast<std::size_t>(packet_number));
}

void PacketSpaceRecovery::retire_packet(RecoveryPacketHandle handle) {
    auto current_handle = packet_for_handle(handle) != nullptr
                              ? std::optional{handle}
                              : handle_for_packet_number(handle.packet_number);
    if (!current_handle.has_value()) {
        return;
    }

    auto &slot = slots_[current_handle->slot_index];
    erase_from_tracked_sets(slot.packet);
    slot.packet.in_flight = false;
    slot.packet.bytes_in_flight = 0;
    slot.state = LedgerSlotState::retired;
    slot.acknowledged = true;
    ++compatibility_version_;
}
```

Update every remaining `base_packet_number_` arithmetic site in `track_new_loss_candidates()`,
`collect_time_threshold_losses()`, and `on_ack_received()` to use:

```cpp
const auto scan_end =
    std::min<std::size_t>(static_cast<std::size_t>(largest_acked), slots_.size());
for (std::size_t slot_index = scan_start; slot_index < scan_end; ++slot_index) {
    auto &slot = slots_[slot_index];
    const auto packet_number = static_cast<std::uint64_t>(slot_index);
    // existing slot.state / acknowledged / in_flight checks stay intact
}
```

- [ ] **Step 5: Run the focused recovery tests and verify they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicRecoveryTest.RetiringEarlierPacketsDoesNotRenumberLaterHandles:QuicRecoveryTest.PacketHandlesRemainReadableAfterEarlierRetirementCompactsPrefix:QuicRecoveryTest.TrackedPacketsPreservePacketNumberOrderAcrossLateLosses'
```

Expected: PASS with `3 tests from QuicRecoveryTest`.

- [ ] **Step 6: Commit Task 1**

Run:

```bash
git add tests/core/recovery/recovery_test.cpp src/quic/recovery.h src/quic/recovery.cpp
SKIP=coquic-clang-tidy git commit -m "fix: keep recovery handles stable across retirements"
```

Expected: commit succeeds and `git status --short` is clean.

### Task 2: Walk Only Live Packets During ACK And Loss Processing

**Files:**
- Modify: `tests/core/recovery/recovery_test.cpp`
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`

- [ ] **Step 1: Add the failing recovery test for removing newly acked packets from tracked order**

Add this test near the existing late-ACK coverage in `tests/core/recovery/recovery_test.cpp`:

```cpp
TEST(QuicRecoveryTest, AckProcessingRemovesAckedAndLateAckedPacketsFromTrackedPackets) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));
    recovery.on_packet_declared_lost(1);

    const std::array ack_ranges = {
        AckPacketNumberRange{
            .smallest = 1,
            .largest = 1,
        },
        AckPacketNumberRange{
            .smallest = 2,
            .largest = 2,
        },
    };

    const auto result = recovery.on_ack_received(ack_ranges, /*largest_acknowledged=*/2,
                                                 coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from_handles(recovery, result.acked_packets.handles()),
              (std::vector<std::uint64_t>{2}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.late_acked_packets.handles()),
              (std::vector<std::uint64_t>{1}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, recovery.tracked_packets()),
              (std::vector<std::uint64_t>{0}));
    ASSERT_TRUE(recovery.oldest_tracked_packet().has_value());
    EXPECT_EQ(recovery.oldest_tracked_packet()->packet_number, 0u);
    ASSERT_TRUE(recovery.newest_tracked_packet().has_value());
    EXPECT_EQ(recovery.newest_tracked_packet()->packet_number, 0u);
}
```

- [ ] **Step 2: Run the new test to verify the current dense-scan implementation fails**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicRecoveryTest.AckProcessingRemovesAckedAndLateAckedPacketsFromTrackedPackets'
```

Expected: FAIL because `tracked_packets()` still returns packets `1` and `2` after `on_ack_received()` only marks them `acknowledged`.

- [ ] **Step 3: Add live-chain and monotonic-cursor fields in `src/quic/recovery.h`**

Extend the slot structure and private helpers:

```cpp
class PacketSpaceRecovery {
  private:
    static constexpr std::size_t kInvalidLedgerSlotIndex =
        std::numeric_limits<std::size_t>::max();

    struct SentPacketLedgerSlot {
        LedgerSlotState state = LedgerSlotState::empty;
        SentPacketRecord packet;
        bool acknowledged = false;
        std::size_t prev_live_slot = kInvalidLedgerSlotIndex;
        std::size_t next_live_slot = kInvalidLedgerSlotIndex;
    };

    void link_live_slot(std::size_t slot_index);
    void unlink_live_slot(std::size_t slot_index);
    std::optional<std::size_t> newest_live_slot_at_or_below(std::uint64_t packet_number) const;

    std::vector<SentPacketLedgerSlot> slots_;
    std::set<DeadlineTrackedPacket, DeadlineTrackedPacketLess> in_flight_ack_eliciting_packets_;
    std::set<DeadlineTrackedPacket, DeadlineTrackedPacketLess> eligible_loss_packets_;
    std::optional<std::uint64_t> largest_acked_packet_number_;
    std::size_t first_live_slot_ = kInvalidLedgerSlotIndex;
    std::size_t last_live_slot_ = kInvalidLedgerSlotIndex;
    std::size_t next_loss_candidate_slot_ = 0;
    std::uint64_t compatibility_version_ = 0;
    RecoveryRttState rtt_state_;
    SentPacketsView sent_packets_{};
};
```

- [ ] **Step 4: Implement live-chain traversal in `src/quic/recovery.cpp`**

Link new packets at the tail, unlink packets as soon as they become acked or late acked, and walk the live chain instead of raw slot ranges:

```cpp
void PacketSpaceRecovery::link_live_slot(std::size_t slot_index) {
    auto &slot = slots_[slot_index];
    slot.prev_live_slot = last_live_slot_;
    slot.next_live_slot = kInvalidLedgerSlotIndex;
    if (last_live_slot_ != kInvalidLedgerSlotIndex) {
        slots_[last_live_slot_].next_live_slot = slot_index;
    } else {
        first_live_slot_ = slot_index;
    }
    last_live_slot_ = slot_index;
}

void PacketSpaceRecovery::unlink_live_slot(std::size_t slot_index) {
    auto &slot = slots_[slot_index];
    if (slot.prev_live_slot != kInvalidLedgerSlotIndex) {
        slots_[slot.prev_live_slot].next_live_slot = slot.next_live_slot;
    } else {
        first_live_slot_ = slot.next_live_slot;
    }
    if (slot.next_live_slot != kInvalidLedgerSlotIndex) {
        slots_[slot.next_live_slot].prev_live_slot = slot.prev_live_slot;
    } else {
        last_live_slot_ = slot.prev_live_slot;
    }
    slot.prev_live_slot = kInvalidLedgerSlotIndex;
    slot.next_live_slot = kInvalidLedgerSlotIndex;
}

void PacketSpaceRecovery::on_packet_sent(const SentPacketRecord &packet) {
    auto &slot = slots_[ensure_slot_for_packet_number(packet.packet_number)];
    if (slot.state == LedgerSlotState::sent || slot.state == LedgerSlotState::declared_lost) {
        erase_from_tracked_sets(slot.packet);
        if (!slot.acknowledged) {
            unlink_live_slot(static_cast<std::size_t>(packet.packet_number));
        }
    }

    slot.state = packet.declared_lost ? LedgerSlotState::declared_lost : LedgerSlotState::sent;
    slot.packet = packet;
    slot.packet.declared_lost = packet.declared_lost;
    slot.acknowledged = false;
    link_live_slot(static_cast<std::size_t>(packet.packet_number));
    // existing tracked-set updates stay in place
}
```

Update `tracked_packets()`, `oldest_tracked_packet()`, and `newest_tracked_packet()` to iterate from `first_live_slot_` through `next_live_slot`.

Update `track_new_loss_candidates()` to advance only once:

```cpp
const auto scan_end =
    std::min<std::size_t>(static_cast<std::size_t>(largest_acked), slots_.size());
for (std::size_t slot_index = next_loss_candidate_slot_; slot_index < scan_end; ++slot_index) {
    const auto &slot = slots_[slot_index];
    if ((slot.state == LedgerSlotState::sent || slot.state == LedgerSlotState::declared_lost) &&
        !slot.acknowledged) {
        maybe_track_as_loss_candidate(slot.packet);
    }
}
next_loss_candidate_slot_ = std::max(next_loss_candidate_slot_, scan_end);
```

Rewrite the ACK walk to traverse the live chain in descending order:

```cpp
auto current = newest_live_slot_at_or_below(largest_acknowledged);
for (auto range_it = ack_ranges.rbegin(); range_it != ack_ranges.rend(); ++range_it) {
    while (current.has_value() && *current > range_it->largest) {
        current = slots_[*current].prev_live_slot == kInvalidLedgerSlotIndex
                      ? std::nullopt
                      : std::optional{slots_[*current].prev_live_slot};
    }

    while (current.has_value() && *current >= range_it->smallest) {
        const auto slot_index = *current;
        const auto previous = slots_[slot_index].prev_live_slot == kInvalidLedgerSlotIndex
                                  ? std::nullopt
                                  : std::optional{slots_[slot_index].prev_live_slot};
        auto &slot = slots_[slot_index];

        if (slot.state == LedgerSlotState::sent) {
            const auto snapshot = packet_metadata(slot.packet);
            result.acked_packets.push_back(packet_handle(slot, slot_index), snapshot);
            result.largest_newly_acked_packet.emplace(packet_handle(slot, slot_index), snapshot);
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
            result.late_acked_packets.push_back(packet_handle(slot, slot_index),
                                                packet_metadata(slot.packet));
            unlink_live_slot(slot_index);
            slot.acknowledged = true;
            mutated = true;
        }

        current = previous;
    }
}
```

Rewrite `collect_time_threshold_losses()` to walk from `first_live_slot_` until packet numbers reach `largest_acked_packet_number_`, and update `rebuild_auxiliary_indexes()` to rebuild the live chain plus tracked sets from the slot vector in ascending slot order.

- [ ] **Step 5: Run the focused recovery and connection regression slices**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicRecoveryTest.AckProcessingRemovesAckedAndLateAckedPacketsFromTrackedPackets:QuicRecoveryTest.AckProcessingSeparatesActiveAndLateAckedPacketsInLedger:QuicRecoveryTest.TimeThresholdLossScansLedgerWithoutSentPacketMap:QuicCoreTest.LateAckOfDeclaredLostRetransmissionRetiresApplicationFragment:QuicCoreTest.AckGapsRetransmitLostOffsetsBeforeFreshData:QuicCoreTest.ApplicationSendRemainsContiguousAfterAcknowledgingInitialFlight:QuicCoreTest.ApplicationSendContinuesAcrossCumulativeAckBursts:QuicCoreTest.ApplicationSendDrainsLargePayloadAcrossRepeatedCumulativeAcks:QuicCoreTest.ApplicationSendDrainsLargePayloadAcrossDroppedCumulativeAckRounds:QuicCoreTest.CongestionWindowGatesAckElicitingSendsUntilAckArrives:QuicCoreTest.ConnectionPersistentCongestionPathsAreExercised:QuicCoreTest.AckTriggeredLossUsesLossDetectionTimeForRecoveryBoundary:QuicCoreTest.AckTriggeredLossDoesNotRestartRecoveryForOlderPackets:QuicCoreTest.ClientLargePartialResponseFlowKeepsReceiveCreditStateConsistent:QuicCoreTest.ApplicationSendDrainsLargePayloadAcrossDroppedKeyUpdatedAckDatagrams:QuicCoreTest.AckGapOnLaterMigratedPathRetransmitsLostStreamData:QuicCoreTest.InboundMigratedAckGapDatagramRetransmitsLostStreamData'
```

Expected: PASS with all listed recovery and `QuicCoreTest` cases passing.

- [ ] **Step 6: Rebuild the release binary and re-run the bulk download harness**

Run:

```bash
nix develop -c zig build -Doptimize=ReleaseFast
```

Expected: PASS with exit code `0`.

Run:

```bash
bash -lc 'set -euo pipefail
port=9568
server_log=$(mktemp)
json_out=$(mktemp)
cleanup() {
  if [ -n "${server_pid:-}" ]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
taskset -c 2 ./zig-out/bin/coquic-perf server --host 127.0.0.1 --port "$port" --certificate-chain tests/fixtures/quic-server-cert.pem --private-key tests/fixtures/quic-server-key.pem --io-backend socket >"$server_log" 2>&1 &
server_pid=$!
sleep 1
taskset -c 3 ./zig-out/bin/coquic-perf client --host 127.0.0.1 --port "$port" --mode bulk --io-backend socket --request-bytes 0 --response-bytes 1048576 --streams 4 --connections 1 --requests-in-flight 1 --direction download --warmup 0ms --duration 5s --json-out "$json_out"
cat "$json_out"'
```

Expected: PASS with valid JSON output and throughput back near the local `main` sample around `59.473 MiB/s`.

- [ ] **Step 7: Commit Task 2**

Run:

```bash
git add tests/core/recovery/recovery_test.cpp src/quic/recovery.h src/quic/recovery.cpp
SKIP=coquic-clang-tidy git commit -m "fix: traverse only live recovery packets"
```

Expected: commit succeeds and `git status --short` is clean.
