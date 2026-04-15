#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <vector>

#include "src/quic/core.h"
#include "src/quic/crypto_stream.h"
#include "src/quic/frame.h"
#include "src/quic/qlog/fwd.h"
#include "src/quic/streams.h"

namespace coquic::quic {

namespace test {
struct ReceivedPacketHistoryTestPeer;
}

inline constexpr std::uint64_t kPacketThreshold = 3;
inline constexpr double kTimeThreshold = 9.0 / 8.0;
inline constexpr std::chrono::milliseconds kGranularity{1};
inline constexpr std::chrono::milliseconds kInitialRtt{333};

struct SentPacketRecord {
    std::uint64_t packet_number = 0;
    QuicCoreTimePoint sent_time{};
    bool ack_eliciting = false;
    bool in_flight = false;
    bool declared_lost = false;
    bool has_handshake_done = false;
    std::vector<ByteRange> crypto_ranges;
    std::vector<ResetStreamFrame> reset_stream_frames;
    std::vector<StopSendingFrame> stop_sending_frames;
    std::optional<MaxDataFrame> max_data_frame;
    std::vector<MaxStreamDataFrame> max_stream_data_frames;
    std::vector<MaxStreamsFrame> max_streams_frames;
    std::optional<DataBlockedFrame> data_blocked_frame;
    std::vector<StreamDataBlockedFrame> stream_data_blocked_frames;
    std::vector<StreamFrameSendFragment> stream_fragments;
    std::shared_ptr<qlog::PacketSnapshot> qlog_packet_snapshot;
    bool qlog_pto_probe = false;
    bool has_ping = false;
    std::size_t bytes_in_flight = 0;
    bool force_ack = false;
    QuicPathId path_id = 0;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
};

struct RecoveryRttState {
    std::optional<std::chrono::milliseconds> latest_rtt;
    std::optional<std::chrono::milliseconds> min_rtt;
    std::chrono::milliseconds smoothed_rtt{333};
    std::chrono::milliseconds rttvar{166};
};

struct DeadlineTrackedPacket {
    std::uint64_t packet_number = 0;
    QuicCoreTimePoint sent_time{};
    bool operator==(const DeadlineTrackedPacket &) const = default;
};

struct DeadlineTrackedPacketLess {
    bool operator()(const DeadlineTrackedPacket &lhs, const DeadlineTrackedPacket &rhs) const;
};

class ReceivedPacketHistory {
  public:
    bool contains(std::uint64_t packet_number) const;
    void record_received(std::uint64_t packet_number, bool ack_eliciting,
                         QuicCoreTimePoint received_time,
                         QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable);
    bool has_ack_to_send() const;
    bool requests_immediate_ack() const;
    std::optional<AckFrame> build_ack_frame(std::uint64_t ack_delay_exponent, QuicCoreTimePoint now,
                                            bool allow_non_pending = false) const;
    void on_ack_sent();

  private:
    struct ReceivedPacketRange {
        std::uint64_t largest_packet_number = 0;
    };

    struct ReceivedPacketRecord {
        bool ack_eliciting = false;
        QuicCoreTimePoint received_time{};
    };

    std::map<std::uint64_t, ReceivedPacketRange> ranges_;
    bool ack_pending_ = false;
    bool immediate_ack_requested_ = false;
    std::uint64_t ack_eliciting_packets_since_last_ack_ = 0;
    std::optional<std::uint64_t> largest_received_packet_number_;
    std::optional<std::uint64_t> largest_received_ack_eliciting_packet_number_;
    std::optional<ReceivedPacketRecord> largest_received_packet_record_;
    bool ecn_feedback_accessible_ = false;
    AckEcnCounts ecn_counts_{};

    friend struct test::ReceivedPacketHistoryTestPeer;
};

struct RecoveryPacketMetadata {
    std::uint64_t packet_number = 0;
    QuicCoreTimePoint sent_time{};
    bool ack_eliciting = false;
    bool in_flight = false;
    bool declared_lost = false;
};

class PacketSpaceRecovery;

struct RecoveryPacketHandle {
    std::uint64_t packet_number = 0;
    std::size_t slot_index = 0;
};

class RecoveryPacketHandleList {
  public:
    class const_iterator {
      public:
        using iterator_category = std::forward_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using value_type = RecoveryPacketMetadata;

        const_iterator(const PacketSpaceRecovery *recovery,
                       std::vector<RecoveryPacketHandle>::const_iterator it);

        value_type operator*() const;
        const_iterator &operator++();
        const_iterator operator++(int);
        bool operator==(const const_iterator &other) const = default;

      private:
        const PacketSpaceRecovery *recovery_ = nullptr;
        std::vector<RecoveryPacketHandle>::const_iterator it_;
    };

    explicit RecoveryPacketHandleList(const PacketSpaceRecovery *recovery = nullptr);

    void reserve(std::size_t count);
    void push_back(RecoveryPacketHandle handle);
    bool empty() const;
    std::size_t size() const;
    RecoveryPacketMetadata front() const;
    RecoveryPacketMetadata back() const;
    std::span<const RecoveryPacketHandle> handles() const;
    const_iterator begin() const;
    const_iterator end() const;

  private:
    const PacketSpaceRecovery *recovery_ = nullptr;
    std::vector<RecoveryPacketHandle> handles_;
};

class RecoveryPacketHandleOptional {
  public:
    explicit RecoveryPacketHandleOptional(const PacketSpaceRecovery *recovery = nullptr);

    RecoveryPacketHandleOptional &operator=(RecoveryPacketHandle handle);
    bool has_value() const;
    RecoveryPacketMetadata value() const;
    const RecoveryPacketMetadata *operator->() const;

  private:
    const PacketSpaceRecovery *recovery_ = nullptr;
    std::optional<RecoveryPacketHandle> handle_;
    mutable std::optional<RecoveryPacketMetadata> cached_metadata_;
};

struct AckProcessingResult {
    explicit AckProcessingResult(const PacketSpaceRecovery *recovery = nullptr);

    RecoveryPacketHandleList acked_packets;
    RecoveryPacketHandleList late_acked_packets;
    RecoveryPacketHandleList lost_packets;
    RecoveryPacketHandleOptional largest_newly_acked_packet;
    bool largest_acknowledged_was_newly_acked = false;
    bool has_newly_acked_ack_eliciting = false;
};

class PacketSpaceRecovery {
  public:
    PacketSpaceRecovery();
    PacketSpaceRecovery(const PacketSpaceRecovery &other);
    PacketSpaceRecovery(PacketSpaceRecovery &&other) noexcept;
    PacketSpaceRecovery &operator=(const PacketSpaceRecovery &other);
    PacketSpaceRecovery &operator=(PacketSpaceRecovery &&other) noexcept;

    void on_packet_sent(const SentPacketRecord &packet);
    void on_packet_declared_lost(std::uint64_t packet_number);
    void retire_packet(RecoveryPacketHandle handle);
    void retire_packet(std::uint64_t packet_number);
    AckProcessingResult on_ack_received(std::span<const AckPacketNumberRange> ack_ranges,
                                        std::uint64_t largest_acknowledged, QuicCoreTimePoint now);
    AckProcessingResult on_ack_received(const AckFrame &ack, QuicCoreTimePoint now);
    std::optional<RecoveryPacketHandle> handle_for_packet_number(std::uint64_t packet_number) const;
    SentPacketRecord *packet_for_handle(RecoveryPacketHandle handle);
    const SentPacketRecord *packet_for_handle(RecoveryPacketHandle handle) const;
    SentPacketRecord *find_packet(std::uint64_t packet_number);
    const SentPacketRecord *find_packet(std::uint64_t packet_number) const;
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
    struct SentPacketsView {
        const PacketSpaceRecovery *owner = nullptr;

        bool contains(std::uint64_t packet_number) const;
        const SentPacketRecord &at(std::uint64_t packet_number) const;
        std::size_t size() const;
    };

    enum class LedgerSlotState {
        empty,
        sent,
        declared_lost,
        retired,
    };

    struct SentPacketLedgerSlot {
        LedgerSlotState state = LedgerSlotState::empty;
        SentPacketRecord packet;
        bool acknowledged = false;
    };

    static DeadlineTrackedPacket tracked_packet(const SentPacketRecord &packet);
    static RecoveryPacketHandle packet_handle(const SentPacketLedgerSlot &slot,
                                              std::size_t slot_index);
    void erase_from_tracked_sets(const SentPacketRecord &packet);
    void maybe_track_as_loss_candidate(const SentPacketRecord &packet);
    void track_new_loss_candidates(std::optional<std::uint64_t> previous_largest_acked,
                                   std::uint64_t largest_acked);
    std::size_t ensure_slot_for_packet_number(std::uint64_t packet_number);
    void compact_retired_prefix();

    std::uint64_t base_packet_number_ = 0;
    std::vector<SentPacketLedgerSlot> slots_;
    std::set<DeadlineTrackedPacket, DeadlineTrackedPacketLess> in_flight_ack_eliciting_packets_;
    std::set<DeadlineTrackedPacket, DeadlineTrackedPacketLess> eligible_loss_packets_;
    std::optional<std::uint64_t> largest_acked_packet_number_;
    RecoveryRttState rtt_state_;
    SentPacketsView sent_packets_{};
};

bool is_packet_threshold_lost(std::uint64_t packet_number, std::uint64_t largest_acked);
QuicCoreTimePoint compute_time_threshold_deadline(const RecoveryRttState &rtt,
                                                  QuicCoreTimePoint sent_time);
bool is_time_threshold_lost(const RecoveryRttState &rtt, QuicCoreTimePoint sent_time,
                            QuicCoreTimePoint now);
QuicCoreTimePoint compute_pto_deadline(const RecoveryRttState &rtt,
                                       std::chrono::milliseconds max_ack_delay,
                                       QuicCoreTimePoint now, std::uint32_t pto_count);
void update_rtt(RecoveryRttState &rtt, QuicCoreTimePoint ack_receive_time,
                const SentPacketRecord &largest_newly_acked_packet,
                std::chrono::milliseconds ack_delay, std::chrono::milliseconds max_ack_delay);

} // namespace coquic::quic
