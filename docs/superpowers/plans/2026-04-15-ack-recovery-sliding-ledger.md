# ACK/Recovery Sliding Ledger Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace split sent-packet ownership with a single recovery-owned sliding ledger so ACK handling, loss detection, and packet retirement stop joining across multiple maps.

**Architecture:** `PacketSpaceRecovery` becomes the canonical owner of every outstanding or declared-lost `SentPacketRecord` in Initial, Handshake, and Application packet spaces. The new ledger stores the full packet record plus slot state, returns lightweight handles for newly acked, late-acked, and newly lost packets, and keeps the existing sent-time ordered indexes only for PTO and loss-deadline queries.

**Tech Stack:** C++20, Zig build/test, GoogleTest, existing QUIC recovery, connection, congestion, ECN, and qlog code in `src/quic/`.

---

## File Map

- Modify: `src/quic/recovery.h`
  Purpose: Replace metadata-only recovery records with ledger slots, handles, and recovery query helpers.
- Modify: `src/quic/recovery.cpp`
  Purpose: Implement ledger slot growth, lookup, ACK walking, late-ACK handling, loss scans, and auxiliary index rebuilds.
- Modify: `src/quic/connection.h`
  Purpose: Remove `PacketSpaceState` packet maps and change ACK/loss helper signatures to operate on recovery handles.
- Modify: `src/quic/connection.cpp`
  Purpose: Switch ACK retirement, loss detection, PTO probe selection, timeout tracing, and qlog packet mutation to recovery-owned packet state.
- Modify: `tests/core/recovery/recovery_test.cpp`
  Purpose: Add direct recovery coverage for active ACKs, late ACKs, ordered handle snapshots, and ledger-backed time-threshold loss.
- Modify: `tests/support/core/connection_test_fixtures.h`
  Purpose: Add shared helpers for reading tracked packets from recovery so packet-space tests stop reaching into removed maps.
- Modify: `tests/core/connection/ack_test.cpp`
  Purpose: Update ACK, loss, PTO, and recovery rebuild tests to ledger helpers and handle-based retirement/loss.
- Modify: `tests/core/connection/handshake_test.cpp`
  Purpose: Keep malformed-range and cross-packet-space late-ACK coverage after removing `declared_lost_packets`.
- Modify: `tests/core/connection/flow_control_test.cpp`
  Purpose: Replace direct sent-packet map inspection with ledger-backed helpers.
- Modify: `tests/core/connection/key_update_test.cpp`
  Purpose: Replace outstanding-packet map assertions with ledger-backed helpers.
- Modify: `tests/core/connection/migration_test.cpp`
  Purpose: Replace last-sent-packet map lookups with ledger-backed helpers.
- Modify: `tests/core/connection/path_validation_test.cpp`
  Purpose: Replace packet-space iteration over `sent_packets` with helper snapshots from recovery.
- Modify: `tests/core/connection/retry_version_test.cpp`
  Purpose: Replace initial/application outstanding packet assertions with recovery-backed helpers.
- Modify: `tests/core/connection/stream_test.cpp`
  Purpose: Replace retransmission and sent-packet assertions that currently read `sent_packets` directly.
- Modify: `tests/core/connection/zero_rtt_test.cpp`
  Purpose: Replace handshake/application sent-packet seeding that currently emplaces directly into `sent_packets`.

### Task 1: Build The Sliding Ledger In `PacketSpaceRecovery`

**Files:**
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`
- Modify: `tests/core/recovery/recovery_test.cpp`

- [ ] **Step 1: Add the failing recovery test for active ACK plus late ACK in one pass**

Add this helper and test near the existing ACK-processing tests in `tests/core/recovery/recovery_test.cpp`:

```cpp
using coquic::quic::AckPacketNumberRange;
using coquic::quic::RecoveryPacketHandle;

std::vector<std::uint64_t>
packet_numbers_from_handles(const PacketSpaceRecovery &recovery,
                            const std::vector<RecoveryPacketHandle> &handles) {
    std::vector<std::uint64_t> packet_numbers;
    packet_numbers.reserve(handles.size());
    for (const auto handle : handles) {
        const auto *packet = recovery.packet_for_handle(handle);
        EXPECT_NE(packet, nullptr);
        if (packet != nullptr) {
            packet_numbers.push_back(packet->packet_number);
        }
    }
    return packet_numbers;
}

TEST(QuicRecoveryTest, AckProcessingSeparatesActiveAndLateAckedPacketsInLedger) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(3)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(5)));
    recovery.on_packet_declared_lost(3);

    const std::array ack_ranges = {
        AckPacketNumberRange{
            .smallest = 3,
            .largest = 3,
        },
        AckPacketNumberRange{
            .smallest = 5,
            .largest = 5,
        },
    };

    const auto result = recovery.on_ack_received(
        ack_ranges, /*largest_acknowledged=*/5, coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from_handles(recovery, result.acked_packets),
              (std::vector<std::uint64_t>{5}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.late_acked_packets),
              (std::vector<std::uint64_t>{3}));
    ASSERT_TRUE(result.largest_newly_acked_packet.has_value());
    EXPECT_EQ(result.largest_newly_acked_packet->packet_number, 5u);
}
```

- [ ] **Step 2: Run the new recovery test to verify it fails**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicRecoveryTest.AckProcessingSeparatesActiveAndLateAckedPacketsInLedger'
```

Expected: FAIL to compile because `RecoveryPacketHandle`,
`late_acked_packets`, `packet_for_handle()`, and the decoded-range overload of
`on_ack_received()` do not exist yet.

- [ ] **Step 3: Add the ledger types and handle-oriented API in `src/quic/recovery.h`**

Replace the metadata-only result shape with ledger handles and add lookup helpers:

```cpp
struct RecoveryPacketHandle {
    std::uint64_t packet_number = 0;
    std::size_t slot_index = 0;
    bool operator==(const RecoveryPacketHandle &) const = default;
};

struct AckProcessingResult {
    std::vector<RecoveryPacketHandle> acked_packets;
    std::vector<RecoveryPacketHandle> late_acked_packets;
    std::vector<RecoveryPacketHandle> lost_packets;
    std::optional<RecoveryPacketHandle> largest_newly_acked_packet;
    bool largest_acknowledged_was_newly_acked = false;
    bool has_newly_acked_ack_eliciting = false;
};

class PacketSpaceRecovery {
  public:
    void on_packet_sent(const SentPacketRecord &packet);
    void on_packet_declared_lost(std::uint64_t packet_number);
    void retire_packet(RecoveryPacketHandle handle);
    AckProcessingResult on_ack_received(std::span<const AckPacketNumberRange> ack_ranges,
                                        std::uint64_t largest_acknowledged,
                                        QuicCoreTimePoint now);
    AckProcessingResult on_ack_received(const AckFrame &ack, QuicCoreTimePoint now);
    std::optional<RecoveryPacketHandle> handle_for_packet_number(std::uint64_t packet_number) const;
    const SentPacketRecord *packet_for_handle(RecoveryPacketHandle handle) const;
    SentPacketRecord *packet_for_handle(RecoveryPacketHandle handle);
    const SentPacketRecord *find_packet(std::uint64_t packet_number) const;
    SentPacketRecord *find_packet(std::uint64_t packet_number);
    std::vector<RecoveryPacketHandle> tracked_packets() const;
    std::size_t tracked_packet_count() const;
    std::optional<RecoveryPacketHandle> oldest_tracked_packet() const;
    std::optional<RecoveryPacketHandle> newest_tracked_packet() const;
    std::optional<std::uint64_t> largest_acked_packet_number() const;
    std::optional<DeadlineTrackedPacket> latest_in_flight_ack_eliciting_packet() const;
    std::optional<DeadlineTrackedPacket> earliest_loss_packet() const;

    RecoveryRttState &rtt_state();
    const RecoveryRttState &rtt_state() const;

  private:
    enum class LedgerSlotState : std::uint8_t {
        empty,
        sent,
        declared_lost,
        retired,
    };

    struct SentPacketLedgerSlot {
        LedgerSlotState state = LedgerSlotState::empty;
        SentPacketRecord packet{};
    };

    static DeadlineTrackedPacket tracked_packet(const SentPacketRecord &packet);
    void erase_from_tracked_sets(const SentPacketRecord &packet);
    void maybe_track_as_loss_candidate(const SentPacketRecord &packet);
    void track_new_loss_candidates(std::optional<std::uint64_t> previous_largest_acked,
                                   std::uint64_t largest_acked);
    void ensure_slot_for_packet_number(std::uint64_t packet_number);
    void compact_retired_prefix();

    std::uint64_t base_packet_number_ = 0;
    std::vector<SentPacketLedgerSlot> slots_;
    std::set<DeadlineTrackedPacket, DeadlineTrackedPacketLess> in_flight_ack_eliciting_packets_;
    std::set<DeadlineTrackedPacket, DeadlineTrackedPacketLess> eligible_loss_packets_;
    std::optional<std::uint64_t> largest_acked_packet_number_;
    RecoveryRttState rtt_state_;
};
```

- [ ] **Step 4: Implement slot growth, lookup, declaration of loss, and retirement**

In `src/quic/recovery.cpp`, replace `sent_packets_` ownership with slot helpers:

```cpp
namespace {

std::size_t slot_index_for_packet_number(std::uint64_t base_packet_number,
                                         std::uint64_t packet_number) {
    return static_cast<std::size_t>(packet_number - base_packet_number);
}

} // namespace

void PacketSpaceRecovery::ensure_slot_for_packet_number(std::uint64_t packet_number) {
    if (slots_.empty()) {
        base_packet_number_ = packet_number;
        slots_.resize(1);
        return;
    }

    if (packet_number < base_packet_number_) {
        const auto prepend = static_cast<std::size_t>(base_packet_number_ - packet_number);
        slots_.insert(slots_.begin(), prepend, SentPacketLedgerSlot{});
        base_packet_number_ = packet_number;
        return;
    }

    const auto required_size = slot_index_for_packet_number(base_packet_number_, packet_number) + 1;
    if (required_size > slots_.size()) {
        slots_.resize(required_size);
    }
}

std::optional<RecoveryPacketHandle>
PacketSpaceRecovery::handle_for_packet_number(std::uint64_t packet_number) const {
    if (slots_.empty() || packet_number < base_packet_number_) {
        return std::nullopt;
    }

    const auto slot_index = slot_index_for_packet_number(base_packet_number_, packet_number);
    if (slot_index >= slots_.size()) {
        return std::nullopt;
    }

    const auto &slot = slots_[slot_index];
    if (slot.packet.packet_number != packet_number ||
        slot.state == LedgerSlotState::empty || slot.state == LedgerSlotState::retired) {
        return std::nullopt;
    }

    return RecoveryPacketHandle{
        .packet_number = packet_number,
        .slot_index = slot_index,
    };
}

const SentPacketRecord *PacketSpaceRecovery::packet_for_handle(RecoveryPacketHandle handle) const {
    if (handle.slot_index >= slots_.size()) {
        return nullptr;
    }
    const auto &slot = slots_[handle.slot_index];
    if (slot.packet.packet_number != handle.packet_number ||
        slot.state == LedgerSlotState::empty || slot.state == LedgerSlotState::retired) {
        return nullptr;
    }
    return &slot.packet;
}

SentPacketRecord *PacketSpaceRecovery::packet_for_handle(RecoveryPacketHandle handle) {
    return const_cast<SentPacketRecord *>(
        std::as_const(*this).packet_for_handle(handle));
}

const SentPacketRecord *PacketSpaceRecovery::find_packet(std::uint64_t packet_number) const {
    const auto handle = handle_for_packet_number(packet_number);
    return handle.has_value() ? packet_for_handle(*handle) : nullptr;
}

SentPacketRecord *PacketSpaceRecovery::find_packet(std::uint64_t packet_number) {
    return const_cast<SentPacketRecord *>(
        std::as_const(*this).find_packet(packet_number));
}

void PacketSpaceRecovery::on_packet_sent(const SentPacketRecord &packet) {
    ensure_slot_for_packet_number(packet.packet_number);
    const auto slot_index = slot_index_for_packet_number(base_packet_number_, packet.packet_number);
    auto &slot = slots_[slot_index];
    if (slot.state == LedgerSlotState::sent || slot.state == LedgerSlotState::declared_lost) {
        erase_from_tracked_sets(slot.packet);
    }
    slot.state = packet.declared_lost ? LedgerSlotState::declared_lost : LedgerSlotState::sent;
    slot.packet = packet;
    if (slot.packet.ack_eliciting && slot.packet.in_flight) {
        in_flight_ack_eliciting_packets_.insert(tracked_packet(slot.packet));
    }
    maybe_track_as_loss_candidate(slot.packet);
}

void PacketSpaceRecovery::on_packet_declared_lost(std::uint64_t packet_number) {
    const auto handle = handle_for_packet_number(packet_number);
    if (!handle.has_value()) {
        return;
    }
    auto &slot = slots_[handle->slot_index];
    erase_from_tracked_sets(slot.packet);
    slot.state = LedgerSlotState::declared_lost;
    slot.packet.declared_lost = true;
    slot.packet.in_flight = false;
    slot.packet.bytes_in_flight = 0;
}

void PacketSpaceRecovery::retire_packet(RecoveryPacketHandle handle) {
    auto *packet = packet_for_handle(handle);
    if (packet == nullptr) {
        return;
    }
    erase_from_tracked_sets(*packet);
    auto &slot = slots_[handle.slot_index];
    slot.state = LedgerSlotState::retired;
    slot.packet = SentPacketRecord{
        .packet_number = handle.packet_number,
    };
    compact_retired_prefix();
}

void PacketSpaceRecovery::compact_retired_prefix() {
    std::size_t retired_prefix = 0;
    while (retired_prefix < slots_.size() &&
           slots_[retired_prefix].state == LedgerSlotState::retired) {
        ++retired_prefix;
    }
    if (retired_prefix == 0) {
        return;
    }
    base_packet_number_ += retired_prefix;
    slots_.erase(slots_.begin(), slots_.begin() + static_cast<std::ptrdiff_t>(retired_prefix));
    if (slots_.empty()) {
        base_packet_number_ = 0;
    }
}
```

- [ ] **Step 5: Implement the decoded-range ACK walk and handle-based loss reporting**

Finish `PacketSpaceRecovery::on_ack_received()` in `src/quic/recovery.cpp` without copying packet records out of recovery:

```cpp
AckProcessingResult PacketSpaceRecovery::on_ack_received(
    std::span<const AckPacketNumberRange> ack_ranges, std::uint64_t largest_acknowledged,
    QuicCoreTimePoint now) {
    AckProcessingResult result;
    const auto previous_largest_acked = largest_acked_packet_number_;
    largest_acked_packet_number_ =
        previous_largest_acked.has_value()
            ? std::max(*previous_largest_acked, largest_acknowledged)
            : largest_acknowledged;
    const auto effective_largest_acked = *largest_acked_packet_number_;

    if (!previous_largest_acked.has_value() || effective_largest_acked > *previous_largest_acked) {
        track_new_loss_candidates(previous_largest_acked, effective_largest_acked);
    }

    for (const auto &range : ack_ranges) {
        if (slots_.empty() || range.largest < base_packet_number_) {
            continue;
        }
        const auto smallest = std::max(range.smallest, base_packet_number_);
        const auto largest =
            std::min(range.largest, base_packet_number_ + slots_.size() - 1);
        for (std::uint64_t packet_number = smallest; packet_number <= largest; ++packet_number) {
            const auto handle = handle_for_packet_number(packet_number);
            if (!handle.has_value()) {
                continue;
            }
            const auto &slot = slots_[handle->slot_index];
            if (slot.state == LedgerSlotState::sent) {
                result.acked_packets.push_back(*handle);
            } else if (slot.state == LedgerSlotState::declared_lost) {
                result.late_acked_packets.push_back(*handle);
            } else {
                continue;
            }

            if (!result.largest_newly_acked_packet.has_value() ||
                handle->packet_number > result.largest_newly_acked_packet->packet_number) {
                result.largest_newly_acked_packet = *handle;
            }
            if (handle->packet_number == largest_acknowledged) {
                result.largest_acknowledged_was_newly_acked = true;
            }
            if (slot.packet.ack_eliciting) {
                result.has_newly_acked_ack_eliciting = true;
            }
        }
    }

    for (std::size_t slot_index = 0; slot_index < slots_.size(); ++slot_index) {
        auto &slot = slots_[slot_index];
        if (slot.state != LedgerSlotState::sent || !slot.packet.in_flight ||
            slot.packet.packet_number >= effective_largest_acked) {
            continue;
        }
        if (!is_packet_threshold_lost(slot.packet.packet_number, effective_largest_acked) &&
            !is_time_threshold_lost(rtt_state_, slot.packet.sent_time, now)) {
            continue;
        }

        erase_from_tracked_sets(slot.packet);
        slot.state = LedgerSlotState::declared_lost;
        slot.packet.declared_lost = true;
        slot.packet.in_flight = false;
        slot.packet.bytes_in_flight = 0;
        result.lost_packets.push_back(RecoveryPacketHandle{
            .packet_number = slot.packet.packet_number,
            .slot_index = slot_index,
        });
    }

    return result;
}

AckProcessingResult PacketSpaceRecovery::on_ack_received(const AckFrame &ack,
                                                         QuicCoreTimePoint now) {
    const auto ack_ranges = ack_frame_packet_number_ranges(ack);
    if (!ack_ranges.has_value()) {
        return AckProcessingResult{};
    }
    return on_ack_received(ack_ranges.value(), ack.largest_acknowledged, now);
}
```

- [ ] **Step 6: Run the focused recovery tests to verify they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicRecoveryTest.AckProcessingSeparatesActiveAndLateAckedPacketsInLedger:QuicRecoveryTest.AckProcessingCanStillAcknowledgeDeclaredLostPackets:QuicRecoveryTest.RecoveryTracksLatestInflightAckElicitingPacketIncrementally'
```

Expected: PASS.

- [ ] **Step 7: Commit the recovery ledger scaffold**

```bash
git add src/quic/recovery.h src/quic/recovery.cpp tests/core/recovery/recovery_test.cpp
git commit -m "refactor: add recovery sliding ledger"
```

### Task 2: Remove `PacketSpaceState` Packet Maps And Move ACK Retirement To Handles

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/recovery.h`
- Modify: `tests/core/connection/ack_test.cpp`
- Modify: `tests/core/connection/handshake_test.cpp`

- [ ] **Step 1: Update the ACK regressions so they fail against the old ownership model**

In `tests/core/connection/ack_test.cpp`, add this regression near the ECN ACK tests:

```cpp
TEST(QuicCoreTest, AckProcessingRetiresLateAckedPacketFromRecoveryLedger) {
    auto connection = make_connected_client_connection();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(3),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 5,
                                     .sent_time = coquic::quic::test::test_time(5),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                 });

    const auto late_handle = optional_value_or_terminate(
        connection.application_space_.recovery.handle_for_packet_number(3));
    EXPECT_TRUE(connection
                    .mark_lost_packet(connection.application_space_, late_handle)
                    .has_value());

    const auto processed =
        connection.process_inbound_ack(connection.application_space_,
                                       coquic::quic::AckFrame{
                                           .largest_acknowledged = 5,
                                           .first_ack_range = 0,
                                           .additional_ranges =
                                               {
                                                   coquic::quic::AckRange{
                                                       .gap = 0,
                                                       .range_length = 0,
                                                   },
                                               },
                                       },
                                       coquic::quic::test::test_time(10),
                                       /*ack_delay_exponent=*/0,
                                       /*max_ack_delay_ms=*/0,
                                       /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.application_space_.recovery.find_packet(3), nullptr);
    EXPECT_EQ(connection.application_space_.recovery.find_packet(5), nullptr);
}
```

In `tests/core/connection/handshake_test.cpp`, update
`ProcessInboundAckAcceptsAdditionalRangesAndLeavesMalformedRangesUnacknowledged`
to seed late packets through recovery instead of `declared_lost_packets`:

```cpp
const auto seed_declared_lost_packet =
    [](coquic::quic::PacketSpaceState &packet_space, std::uint64_t packet_number) {
        packet_space.recovery.on_packet_sent(coquic::quic::SentPacketRecord{
            .packet_number = packet_number,
            .sent_time = coquic::quic::test::test_time(0),
            .ack_eliciting = true,
            .in_flight = false,
            .declared_lost = true,
            .has_ping = true,
            .bytes_in_flight = 0,
        });
        packet_space.recovery.on_packet_declared_lost(packet_number);
    };

seed_declared_lost_packet(connection.application_space_, 2);
seed_declared_lost_packet(connection.application_space_, 5);
seed_declared_lost_packet(connection.application_space_, 8);
```

Replace the old assertions with recovery lookups:

```cpp
EXPECT_EQ(connection.application_space_.recovery.find_packet(2), nullptr);
EXPECT_EQ(connection.application_space_.recovery.find_packet(5), nullptr);
EXPECT_NE(connection.application_space_.recovery.find_packet(8), nullptr);
```

- [ ] **Step 2: Run the focused ACK tests to verify they fail**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.AckProcessingRetiresLateAckedPacketFromRecoveryLedger:QuicCoreTest.ProcessInboundAckAcceptsAdditionalRangesAndLeavesMalformedRangesUnacknowledged'
```

Expected: FAIL to compile because `mark_lost_packet()` and
`retire_acked_packet()` still take full packet records, and
`PacketSpaceState::sent_packets` / `declared_lost_packets` still exist in the
implementation.

- [ ] **Step 3: Remove the packet maps and change helper signatures in `src/quic/connection.h`**

Delete the old maps from `PacketSpaceState` and switch helper APIs to
handle-based ownership:

```cpp
struct PacketSpaceState {
    std::uint64_t next_send_packet_number = 0;
    std::optional<std::uint64_t> largest_authenticated_packet_number;
    std::optional<TrafficSecret> read_secret;
    std::optional<TrafficSecret> write_secret;
    ReliableSendBuffer send_crypto;
    ReliableReceiveBuffer receive_crypto;
    ReceivedPacketHistory received_packets;
    PacketSpaceRecovery recovery;
    std::optional<SentPacketRecord> pending_probe_packet;
    std::optional<QuicCoreTimePoint> pending_ack_deadline;
    bool force_ack_send = false;
};

CodecResult<bool> process_inbound_ack(PacketSpaceState &packet_space, const AckFrame &ack,
                                      QuicCoreTimePoint now, std::uint64_t ack_delay_exponent,
                                      std::uint64_t max_ack_delay_ms, bool suppress_pto_reset);
void track_sent_packet(PacketSpaceState &packet_space, const SentPacketRecord &packet);
std::optional<SentPacketRecord> retire_acked_packet(PacketSpaceState &packet_space,
                                                    RecoveryPacketHandle handle);
std::optional<SentPacketRecord> mark_lost_packet(PacketSpaceState &packet_space,
                                                 RecoveryPacketHandle handle,
                                                 bool already_marked_in_recovery = false);
void rebuild_recovery(PacketSpaceState &packet_space);
```

- [ ] **Step 4: Move `process_inbound_ack()`, retirement, and loss marking onto recovery-owned records**

In `src/quic/connection.cpp`, make the connection read full packets from
recovery before mutating transport, stream, ECN, and congestion state:

```cpp
CodecResult<bool> QuicConnection::process_inbound_ack(PacketSpaceState &packet_space,
                                                      const AckFrame &ack, QuicCoreTimePoint now,
                                                      std::uint64_t ack_delay_exponent,
                                                      std::uint64_t max_ack_delay_ms,
                                                      bool suppress_pto_reset) {
    const auto ack_ranges = ack_frame_packet_number_ranges(ack);
    if (!ack_ranges.has_value()) {
        return CodecResult<bool>::success(true);
    }

    packet_space.recovery.rtt_state() = shared_recovery_rtt_state();
    auto ack_result =
        packet_space.recovery.on_ack_received(ack_ranges.value(), ack.largest_acknowledged, now);

    std::optional<SentPacketRecord> largest_newly_acked_packet;
    if (ack_result.largest_newly_acked_packet.has_value()) {
        if (const auto *packet = packet_space.recovery.packet_for_handle(
                *ack_result.largest_newly_acked_packet);
            packet != nullptr) {
            largest_newly_acked_packet = *packet;
        }
    }

    std::vector<SentPacketRecord> acked_packets;
    for (const auto handle : ack_result.acked_packets) {
        if (auto packet = retire_acked_packet(packet_space, handle); packet.has_value()) {
            acked_packets.push_back(*packet);
        }
    }

    std::vector<SentPacketRecord> late_acked_packets;
    for (const auto handle : ack_result.late_acked_packets) {
        if (auto packet = retire_acked_packet(packet_space, handle); packet.has_value()) {
            late_acked_packets.push_back(*packet);
        }
    }

    std::vector<SentPacketRecord> newly_lost_packets;
    for (const auto handle : ack_result.lost_packets) {
        if (const auto *packet = packet_space.recovery.packet_for_handle(handle); packet != nullptr) {
            const auto trigger =
                is_packet_threshold_lost(packet->packet_number, ack.largest_acknowledged)
                    ? "reordering_threshold"
                    : "time_threshold";
            emit_qlog_packet_lost(*packet, trigger, now);
        }
        if (auto packet =
                mark_lost_packet(packet_space, handle, /*already_marked_in_recovery=*/true);
            packet.has_value()) {
            newly_lost_packets.push_back(*packet);
        }
    }

    if (ack_result.largest_acknowledged_was_newly_acked &&
        ack_result.has_newly_acked_ack_eliciting &&
        largest_newly_acked_packet.has_value()) {
        update_rtt(packet_space.recovery.rtt_state(), now, *largest_newly_acked_packet,
                   decode_ack_delay(ack, ack_delay_exponent),
                   std::chrono::milliseconds(max_ack_delay_ms));
        recovery_rtt_state_ = packet_space.recovery.rtt_state();
        synchronize_recovery_rtt_state();
    }

    // Keep the existing `acked_ecn_by_path` aggregation, `disable_ecn_on_path()`
    // checks, `confirm_handshake()` call, application-space
    // `congestion_controller_.on_loss_event()` / `on_packets_acked()` calls,
    // PTO reset, packet trace logging, and
    // `maybe_emit_qlog_recovery_metrics(now)`, but feed them
    // `acked_packets`, `late_acked_packets`, and `newly_lost_packets`.
    return CodecResult<bool>::success(true);
}

void QuicConnection::track_sent_packet(PacketSpaceState &packet_space,
                                       const SentPacketRecord &packet) {
    packet_space.recovery.on_packet_sent(packet);
    if (is_ect_codepoint(packet.ecn)) {
        auto &path = ensure_path_state(packet.path_id);
        if (packet.ecn == QuicEcnCodepoint::ect0) {
            ++path.ecn.total_sent_ect0;
        } else {
            ++path.ecn.total_sent_ect1;
        }
        if (path.ecn.state == QuicPathEcnState::probing) {
            ++path.ecn.probing_packets_sent;
        }
    }
    if (packet_space_is_application(packet_space, application_space_)) {
        congestion_controller_.on_packet_sent(packet.bytes_in_flight, packet.ack_eliciting);
    }
    maybe_emit_qlog_recovery_metrics(packet.sent_time);
}

std::optional<SentPacketRecord>
QuicConnection::retire_acked_packet(PacketSpaceState &packet_space, RecoveryPacketHandle handle) {
    const auto *stored = packet_space.recovery.packet_for_handle(handle);
    if (stored == nullptr) {
        return std::nullopt;
    }
    const auto packet = *stored;
    // Run the current ACK side effects on `packet`: acknowledge crypto ranges,
    // max-data, max-stream-data, max-streams, data-blocked,
    // stream-data-blocked, stream fragments, reset-stream, stop-sending, and
    // handshake-done before retiring the recovery slot.
    packet_space.recovery.retire_packet(handle);
    return packet;
}

std::optional<SentPacketRecord>
QuicConnection::mark_lost_packet(PacketSpaceState &packet_space, RecoveryPacketHandle handle,
                                 bool already_marked_in_recovery) {
    const auto *stored = packet_space.recovery.packet_for_handle(handle);
    if (stored == nullptr) {
        return std::nullopt;
    }
    const auto packet = *stored;
    // Run the current loss side effects on `packet`: call `on_packets_lost()`,
    // update ECN probing counters, mark crypto ranges lost, mark
    // connection-flow-control frames lost, mark stream-control frames and
    // stream fragments lost, and re-arm handshake-done when needed.
    if (!already_marked_in_recovery) {
        packet_space.recovery.on_packet_declared_lost(packet.packet_number);
    }
    return packet;
}
```

Also update `discard_packet_space_state()` so it stops clearing removed maps:

```cpp
void discard_packet_space_state(PacketSpaceState &packet_space) {
    packet_space.largest_authenticated_packet_number = std::nullopt;
    packet_space.read_secret = std::nullopt;
    packet_space.write_secret = std::nullopt;
    packet_space.send_crypto = ReliableSendBuffer{};
    packet_space.receive_crypto = ReliableReceiveBuffer{};
    packet_space.received_packets = ReceivedPacketHistory{};
    packet_space.recovery = PacketSpaceRecovery{};
    packet_space.pending_probe_packet = std::nullopt;
    packet_space.pending_ack_deadline = std::nullopt;
    packet_space.force_ack_send = false;
}
```

- [ ] **Step 5: Run the focused connection ACK tests to verify they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicCoreTest.AckProcessingRetiresLateAckedPacketFromRecoveryLedger:QuicCoreTest.ProcessInboundAckAcceptsAdditionalRangesAndLeavesMalformedRangesUnacknowledged:QuicCoreTest.AckProcessingDisablesEcnWhenPeerDecreasesEct1OrCeCounts'
```

Expected: PASS.

- [ ] **Step 6: Commit the connection ACK migration**

```bash
git add src/quic/connection.h src/quic/connection.cpp src/quic/recovery.h tests/core/connection/ack_test.cpp tests/core/connection/handshake_test.cpp
git commit -m "refactor: move ACK handling to recovery ledger"
```

### Task 3: Move Loss Scans, PTO Probe Selection, And Qlog Packet Mutation To Recovery Queries

**Files:**
- Modify: `src/quic/recovery.h`
- Modify: `src/quic/recovery.cpp`
- Modify: `src/quic/connection.cpp`
- Modify: `tests/core/recovery/recovery_test.cpp`
- Modify: `tests/core/connection/ack_test.cpp`

- [ ] **Step 1: Add failing tests for ledger-backed ordered snapshots and time-threshold loss**

Add these tests to `tests/core/recovery/recovery_test.cpp`:

```cpp
TEST(QuicRecoveryTest, TrackedPacketsPreservePacketNumberOrderAcrossLateLosses) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/7, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));
    recovery.on_packet_declared_lost(4);

    EXPECT_EQ(packet_numbers_from_handles(recovery, recovery.tracked_packets()),
              (std::vector<std::uint64_t>{2, 4, 7}));
    ASSERT_TRUE(recovery.oldest_tracked_packet().has_value());
    ASSERT_TRUE(recovery.newest_tracked_packet().has_value());
    EXPECT_EQ(recovery.oldest_tracked_packet()->packet_number, 2u);
    EXPECT_EQ(recovery.newest_tracked_packet()->packet_number, 7u);
}

TEST(QuicRecoveryTest, TimeThresholdLossScansLedgerWithoutSentPacketMap) {
    PacketSpaceRecovery recovery;
    recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));

    const auto ack_ranges = std::array{
        AckPacketNumberRange{
            .smallest = 4,
            .largest = 4,
        },
    };
    static_cast<void>(recovery.on_ack_received(ack_ranges, /*largest_acknowledged=*/4,
                                               coquic::quic::test::test_time(2)));

    EXPECT_EQ(packet_numbers_from_handles(
                  recovery, recovery.collect_time_threshold_losses(
                                coquic::quic::test::test_time(20))),
              (std::vector<std::uint64_t>{1}));
}
```

In `tests/core/connection/ack_test.cpp`, update the existing PTO and rebuild
tests so they assert through recovery lookups instead of `sent_packets_`:

```cpp
EXPECT_EQ(connection.initial_space_.recovery.find_packet(0)->declared_lost, true);
EXPECT_EQ(connection.initial_space_.recovery.find_packet(0)->in_flight, false);
EXPECT_EQ(connection.handshake_space_.recovery.find_packet(4)->packet_number, 4u);
EXPECT_EQ(connection.handshake_space_.recovery.find_packet(7)->packet_number, 7u);
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicRecoveryTest.TrackedPacketsPreservePacketNumberOrderAcrossLateLosses:QuicRecoveryTest.TimeThresholdLossScansLedgerWithoutSentPacketMap:QuicCoreTest.DetectLostPacketsMarksCryptoRangesLostAndKeepsRecoveryStateForLateAcks:QuicCoreTest.ApplicationPtoPrefersNewestRetransmittablePacketOverOlderCryptoOnlyPacket:QuicCoreTest.RebuildRecoveryPreservesLargestAckedAndOutstandingPackets'
```

Expected: FAIL to compile because `tracked_packets()`,
`oldest_tracked_packet()`, `newest_tracked_packet()`,
`collect_time_threshold_losses()`, and the remaining connection call sites still
read removed packet maps.

- [ ] **Step 3: Add recovery query helpers for ordered snapshots, mutable lookups, and loss collection**

In `src/quic/recovery.h`, add the missing query helpers:

```cpp
std::vector<RecoveryPacketHandle> tracked_packets() const;
std::size_t tracked_packet_count() const;
std::optional<RecoveryPacketHandle> oldest_tracked_packet() const;
std::optional<RecoveryPacketHandle> newest_tracked_packet() const;
std::vector<RecoveryPacketHandle> collect_time_threshold_losses(QuicCoreTimePoint now);
void rebuild_auxiliary_indexes();
```

Implement them in `src/quic/recovery.cpp`:

```cpp
std::vector<RecoveryPacketHandle> PacketSpaceRecovery::tracked_packets() const {
    std::vector<RecoveryPacketHandle> handles;
    handles.reserve(slots_.size());
    for (std::size_t slot_index = 0; slot_index < slots_.size(); ++slot_index) {
        const auto &slot = slots_[slot_index];
        if (slot.state == LedgerSlotState::empty || slot.state == LedgerSlotState::retired) {
            continue;
        }
        handles.push_back(RecoveryPacketHandle{
            .packet_number = slot.packet.packet_number,
            .slot_index = slot_index,
        });
    }
    return handles;
}

std::size_t PacketSpaceRecovery::tracked_packet_count() const {
    return tracked_packets().size();
}

std::optional<RecoveryPacketHandle> PacketSpaceRecovery::oldest_tracked_packet() const {
    const auto handles = tracked_packets();
    if (handles.empty()) {
        return std::nullopt;
    }
    return handles.front();
}

std::optional<RecoveryPacketHandle> PacketSpaceRecovery::newest_tracked_packet() const {
    const auto handles = tracked_packets();
    if (handles.empty()) {
        return std::nullopt;
    }
    return handles.back();
}

std::vector<RecoveryPacketHandle>
PacketSpaceRecovery::collect_time_threshold_losses(QuicCoreTimePoint now) {
    std::vector<RecoveryPacketHandle> lost_packets;
    if (!largest_acked_packet_number_.has_value()) {
        return lost_packets;
    }

    for (std::size_t slot_index = 0; slot_index < slots_.size(); ++slot_index) {
        const auto &slot = slots_[slot_index];
        if (slot.state != LedgerSlotState::sent || !slot.packet.in_flight ||
            slot.packet.packet_number >= *largest_acked_packet_number_) {
            continue;
        }
        if (!is_time_threshold_lost(rtt_state_, slot.packet.sent_time, now)) {
            continue;
        }
        lost_packets.push_back(RecoveryPacketHandle{
            .packet_number = slot.packet.packet_number,
            .slot_index = slot_index,
        });
    }

    return lost_packets;
}

void PacketSpaceRecovery::rebuild_auxiliary_indexes() {
    in_flight_ack_eliciting_packets_.clear();
    eligible_loss_packets_.clear();
    for (const auto handle : tracked_packets()) {
        const auto *packet = packet_for_handle(handle);
        if (packet == nullptr) {
            continue;
        }
        if (packet->ack_eliciting && packet->in_flight) {
            in_flight_ack_eliciting_packets_.insert(tracked_packet(*packet));
        }
        maybe_track_as_loss_candidate(*packet);
    }
}
```

- [ ] **Step 4: Replace the remaining production `sent_packets` scans in `src/quic/connection.cpp`**

Move `detect_lost_packets()`, PTO probe selection, timeout tracing, qlog packet
mutation, and recovery rebuilds to the new recovery queries:

```cpp
void QuicConnection::detect_lost_packets(PacketSpaceState &packet_space, QuicCoreTimePoint now) {
    const auto handles = packet_space.recovery.collect_time_threshold_losses(now);
    if (handles.empty()) {
        return;
    }

    std::vector<SentPacketRecord> lost_packets;
    for (const auto handle : handles) {
        if (const auto *packet = packet_space.recovery.packet_for_handle(handle); packet != nullptr) {
            emit_qlog_packet_lost(*packet, "time_threshold", now);
        }
        if (auto packet = mark_lost_packet(packet_space, handle); packet.has_value()) {
            lost_packets.push_back(*packet);
        }
    }

    // After building `lost_packets`, keep the current application-space
    // `ack_eliciting_in_flight_losses()`, `congestion_controller_.on_loss_event()`,
    // and `establishes_persistent_congestion()` calls with that vector.
}

std::optional<SentPacketRecord>
QuicConnection::select_pto_probe(const PacketSpaceState &packet_space) const {
    std::optional<SentPacketRecord> ping_fallback;
    std::optional<SentPacketRecord> best_probe;
    int best_probe_priority = -1;
    const auto handles = packet_space.recovery.tracked_packets();
    for (auto it = handles.rbegin(); it != handles.rend(); ++it) {
        const auto *packet = packet_space.recovery.packet_for_handle(*it);
        if (packet == nullptr || !packet->ack_eliciting || !packet->in_flight) {
            continue;
        }

        ping_fallback = ping_fallback.value_or(SentPacketRecord{
            .packet_number = packet->packet_number,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        });

        auto probe = *packet;
        std::erase_if(probe.crypto_ranges, [&](const ByteRange &range) {
            return !packet_space.send_crypto.has_outstanding_range(range.offset,
                                                                   range.bytes.size());
        });
        std::erase_if(probe.reset_stream_frames, [&](const ResetStreamFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }
            return stream->second.reset_state == StreamControlFrameState::acknowledged ||
                   !reset_stream_frame_matches(stream->second.pending_reset_frame, frame);
        });
        std::erase_if(probe.stop_sending_frames, [&](const StopSendingFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }
            return stream->second.stop_sending_state ==
                       StreamControlFrameState::acknowledged ||
                   !stop_sending_frame_matches(stream->second.pending_stop_sending_frame, frame);
        });
        std::erase_if(probe.stream_fragments, [&](const StreamFrameSendFragment &fragment) {
            const auto stream = streams_.find(fragment.stream_id);
            if (stream == streams_.end()) {
                return true;
            }
            return !stream_fragment_is_probe_worthy(stream->second, fragment);
        });

        const auto frame_count = retransmittable_probe_frame_count(probe);
        if (frame_count == 0 && !probe.has_ping) {
            continue;
        }

        int probe_priority = 0;
        if (!probe.stream_fragments.empty()) {
            probe_priority = 3;
        } else if (!probe.crypto_ranges.empty()) {
            probe_priority = 2;
        } else if (frame_count != 0) {
            probe_priority = 1;
        }
        if (probe_priority > best_probe_priority) {
            best_probe = std::move(probe);
            best_probe_priority = probe_priority;
        }
    }

    return best_probe.has_value() ? best_probe : ping_fallback;
}

void QuicConnection::rebuild_recovery(PacketSpaceState &packet_space) {
    packet_space.recovery.rebuild_auxiliary_indexes();
}
```

Port the rest of the existing probe filters directly after the shown block:

```cpp
std::erase_if(probe.max_stream_data_frames, [&](const MaxStreamDataFrame &frame) {
    const auto stream = streams_.find(frame.stream_id);
    if (stream == streams_.end()) {
        return true;
    }
    return stream->second.flow_control.max_stream_data_state ==
               StreamControlFrameState::acknowledged ||
           !max_stream_data_frame_matches(
               stream->second.flow_control.pending_max_stream_data_frame, frame);
});
std::erase_if(probe.max_streams_frames, [&](const MaxStreamsFrame &frame) {
    const bool frame_acknowledged =
        frame.stream_type == StreamLimitType::bidirectional
            ? local_stream_limit_state_.max_streams_bidi_state ==
                  StreamControlFrameState::acknowledged
            : local_stream_limit_state_.max_streams_uni_state ==
                  StreamControlFrameState::acknowledged;
    const auto &pending_frame =
        frame.stream_type == StreamLimitType::bidirectional
            ? *local_stream_limit_state_.pending_max_streams_bidi_frame
            : *local_stream_limit_state_.pending_max_streams_uni_frame;
    return frame_acknowledged ||
           std::tie(pending_frame.stream_type, pending_frame.maximum_streams) !=
               std::tie(frame.stream_type, frame.maximum_streams);
});
std::erase_if(probe.stream_data_blocked_frames, [&](const StreamDataBlockedFrame &frame) {
    const auto stream = streams_.find(frame.stream_id);
    if (stream == streams_.end()) {
        return true;
    }
    return stream->second.flow_control.stream_data_blocked_state ==
               StreamControlFrameState::acknowledged ||
           !stream_data_blocked_frame_matches(
               stream->second.flow_control.pending_stream_data_blocked_frame, frame);
});
if (probe.max_data_frame.has_value() &&
    (connection_flow_control_.max_data_state == StreamControlFrameState::acknowledged ||
     !max_data_frame_matches(connection_flow_control_.pending_max_data_frame,
                             *probe.max_data_frame))) {
    probe.max_data_frame = std::nullopt;
}
if (probe.data_blocked_frame.has_value() &&
    (connection_flow_control_.data_blocked_state == StreamControlFrameState::acknowledged ||
     !data_blocked_frame_matches(connection_flow_control_.pending_data_blocked_frame,
                                 *probe.data_blocked_frame))) {
    probe.data_blocked_frame = std::nullopt;
}
if (probe.has_handshake_done &&
    handshake_done_state_ == StreamControlFrameState::acknowledged) {
    probe.has_handshake_done = false;
}
```

Update the timeout trace count and qlog snapshot attachment with the new
recovery queries:

```cpp
const auto in_flight_ack_eliciting_count = [](const PacketSpaceState &packet_space) {
    const auto handles = packet_space.recovery.tracked_packets();
    return std::count_if(handles.begin(), handles.end(),
                         [&](const RecoveryPacketHandle handle) {
                             const auto *packet = packet_space.recovery.packet_for_handle(handle);
                             return packet != nullptr && packet->ack_eliciting && packet->in_flight;
                         });
};

for (auto *packet_space : {&initial_space_, &handshake_space_, &application_space_}) {
    if (auto *sent = packet_space->recovery.find_packet(packet_number); sent != nullptr) {
        sent->qlog_packet_snapshot = snapshot_ptr;
        sent->qlog_pto_probe = pto_probe_burst_active;
    }
}
```

- [ ] **Step 5: Run the focused loss/PTO tests to verify they pass**

Run:

```bash
nix develop -c zig build test -- --gtest_filter='QuicRecoveryTest.TrackedPacketsPreservePacketNumberOrderAcrossLateLosses:QuicRecoveryTest.TimeThresholdLossScansLedgerWithoutSentPacketMap:QuicCoreTest.DetectLostPacketsMarksCryptoRangesLostAndKeepsRecoveryStateForLateAcks:QuicCoreTest.ApplicationPtoPrefersNewestRetransmittablePacketOverOlderCryptoOnlyPacket:QuicCoreTest.RebuildRecoveryPreservesLargestAckedAndOutstandingPackets:QuicCoreTest.RebuildRecoveryHandlesPacketSpacesWithoutAcknowledgments'
```

Expected: PASS.

- [ ] **Step 6: Commit the recovery-query migration**

```bash
git add src/quic/recovery.h src/quic/recovery.cpp src/quic/connection.cpp tests/core/recovery/recovery_test.cpp tests/core/connection/ack_test.cpp
git commit -m "refactor: move loss and PTO queries to recovery ledger"
```

### Task 4: Migrate Repo-Wide Tests And Fixtures Off `sent_packets` / `declared_lost_packets`

**Files:**
- Modify: `tests/support/core/connection_test_fixtures.h`
- Modify: `tests/core/connection/ack_test.cpp`
- Modify: `tests/core/connection/flow_control_test.cpp`
- Modify: `tests/core/connection/handshake_test.cpp`
- Modify: `tests/core/connection/key_update_test.cpp`
- Modify: `tests/core/connection/migration_test.cpp`
- Modify: `tests/core/connection/path_validation_test.cpp`
- Modify: `tests/core/connection/retry_version_test.cpp`
- Modify: `tests/core/connection/stream_test.cpp`
- Modify: `tests/core/connection/zero_rtt_test.cpp`

- [ ] **Step 1: Add shared packet-space test helpers for the new recovery owner**

In `tests/support/core/connection_test_fixtures.h`, add helpers that replace the
old `.sent_packets` and `.declared_lost_packets` map access patterns:

```cpp
inline std::size_t tracked_packet_count(const PacketSpaceState &packet_space) {
    return packet_space.recovery.tracked_packet_count();
}

inline const SentPacketRecord *
tracked_packet_or_null(const PacketSpaceState &packet_space, std::uint64_t packet_number) {
    return packet_space.recovery.find_packet(packet_number);
}

inline const SentPacketRecord &tracked_packet_or_terminate(const PacketSpaceState &packet_space,
                                                           std::uint64_t packet_number) {
    const auto *packet = tracked_packet_or_null(packet_space, packet_number);
    if (packet == nullptr) {
        std::abort();
    }
    return *packet;
}

inline const SentPacketRecord &first_tracked_packet(const PacketSpaceState &packet_space) {
    const auto handle = optional_value_or_terminate(packet_space.recovery.oldest_tracked_packet());
    const auto *packet = packet_space.recovery.packet_for_handle(handle);
    if (packet == nullptr) {
        std::abort();
    }
    return *packet;
}

inline const SentPacketRecord &last_tracked_packet(const PacketSpaceState &packet_space) {
    const auto handle = optional_value_or_terminate(packet_space.recovery.newest_tracked_packet());
    const auto *packet = packet_space.recovery.packet_for_handle(handle);
    if (packet == nullptr) {
        std::abort();
    }
    return *packet;
}

inline std::vector<SentPacketRecord> tracked_packet_snapshot(const PacketSpaceState &packet_space) {
    std::vector<SentPacketRecord> packets;
    for (const auto handle : packet_space.recovery.tracked_packets()) {
        const auto *packet = packet_space.recovery.packet_for_handle(handle);
        if (packet != nullptr) {
            packets.push_back(*packet);
        }
    }
    return packets;
}
```

- [ ] **Step 2: Replace the remaining direct map usage in every affected test file**

Use the new helpers or existing production helpers at each call site:

```cpp
ASSERT_EQ(connection.application_space_.sent_packets.size(), 1u);
const auto &sent_packet = connection.application_space_.sent_packets.begin()->second;
```

becomes:

```cpp
ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);
const auto &sent_packet = first_tracked_packet(connection.application_space_);
```

```cpp
const auto largest_packet_number = connection.application_space_.sent_packets.rbegin()->first;
const auto retransmit_packet = connection.application_space_.sent_packets.at(largest_packet_number);
```

becomes:

```cpp
const auto &retransmit_packet = last_tracked_packet(connection.application_space_);
const auto largest_packet_number = retransmit_packet.packet_number;
```

```cpp
connection.handshake_space_.sent_packets.emplace(
    9, coquic::quic::SentPacketRecord{
           .packet_number = 9,
           .sent_time = coquic::quic::test::test_time(1),
           .ack_eliciting = true,
           .in_flight = true,
       });
```

becomes:

```cpp
connection.track_sent_packet(connection.handshake_space_,
                             coquic::quic::SentPacketRecord{
                                 .packet_number = 9,
                                 .sent_time = coquic::quic::test::test_time(1),
                                 .ack_eliciting = true,
                                 .in_flight = true,
                             });
```

```cpp
EXPECT_TRUE(connection.application_space_.declared_lost_packets.contains(0));
```

becomes:

```cpp
const auto *packet = tracked_packet_or_null(connection.application_space_, 0);
ASSERT_NE(packet, nullptr);
EXPECT_TRUE(packet->declared_lost);
EXPECT_FALSE(packet->in_flight);
```

Do this cleanup in:

```text
tests/core/connection/ack_test.cpp
tests/core/connection/flow_control_test.cpp
tests/core/connection/handshake_test.cpp
tests/core/connection/key_update_test.cpp
tests/core/connection/migration_test.cpp
tests/core/connection/path_validation_test.cpp
tests/core/connection/retry_version_test.cpp
tests/core/connection/stream_test.cpp
tests/core/connection/zero_rtt_test.cpp
```

- [ ] **Step 3: Verify no production or test code still reaches for the removed maps**

Run:

```bash
rg -n "declared_lost_packets|\\.sent_packets\\b" src/quic tests/core/connection tests/support/core
```

Expected: no `PacketSpaceState` member accesses remain. The only acceptable hit
is the local `sent_packets` variable in `src/quic/connection.cpp` inside
`summarize_packets()`.

- [ ] **Step 4: Run the full test suite after the repo-wide migration**

Run:

```bash
nix develop -c zig build test
```

Expected: PASS with exit code `0`.

- [ ] **Step 5: Commit the test migration**

```bash
git add tests/support/core/connection_test_fixtures.h tests/core/connection/ack_test.cpp tests/core/connection/flow_control_test.cpp tests/core/connection/handshake_test.cpp tests/core/connection/key_update_test.cpp tests/core/connection/migration_test.cpp tests/core/connection/path_validation_test.cpp tests/core/connection/retry_version_test.cpp tests/core/connection/stream_test.cpp tests/core/connection/zero_rtt_test.cpp
git commit -m "test: update connection suites for recovery ledger"
```

### Task 5: Run Release Verification And Re-Measure Bulk Download Throughput

**Files:**
- Modify: none
- Test: `tests/core/recovery/recovery_test.cpp`
- Test: `tests/core/connection/ack_test.cpp`
- Test: `tests/core/connection/handshake_test.cpp`

- [ ] **Step 1: Build the release binary used by the perf harness**

Run:

```bash
nix develop -c zig build -Doptimize=ReleaseFast
```

Expected: PASS with exit code `0`.

- [ ] **Step 2: Run the native bulk download sample that matches the current local harness**

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

Expected: PASS with valid JSON output. Compare the reported throughput against
the restored pre-change baseline near `58.164-58.760 MiB/s`.

- [ ] **Step 3: Re-run once if the first sample is materially slower**

Run the same command from Step 2 one more time only if the first result lands
more than about 5% below `58.164 MiB/s`.

Expected: either the rerun lands back near baseline, or the slowdown reproduces
and needs another optimization pass before calling the refactor complete.

- [ ] **Step 4: Confirm the worktree is clean after the task commits**

Run:

```bash
git status --short
```

Expected: no output.
