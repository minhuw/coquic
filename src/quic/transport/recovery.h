#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <vector>

#include "src/quic/core.h"
#include "src/quic/crypto/crypto_stream.h"
#include "src/quic/codec/frame.h"
#include "src/quic/qlog/fwd.h"
#include "src/quic/transport/streams.h"

namespace coquic::quic {

namespace test {
struct ReceivedPacketHistoryTestPeer;
struct PacketSpaceRecoveryTestPeer;
} // namespace test

//= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.1
// # The RECOMMENDED initial value for the packet reordering threshold
// # (kPacketThreshold) is 3, based on best practices for TCP loss
// # detection [RFC5681] [RFC6675].
//= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.1
// # In order to remain similar to TCP, implementations SHOULD NOT use a
// # packet threshold less than 3; see [RFC5681].
inline constexpr std::uint64_t kPacketThreshold = 3;
//= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
// # The RECOMMENDED time threshold (kTimeThreshold), expressed as an RTT
// # multiplier, is 9/8.
inline constexpr double kTimeThreshold = 9.0 / 8.0;
//= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
// # The RECOMMENDED value of the timer granularity
// # (kGranularity) is 1 millisecond.
inline constexpr QuicCoreDuration kGranularity{1000};
//= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.2
// # When no previous RTT is available, the initial RTT
// # SHOULD be set to 333 milliseconds.
inline constexpr QuicCoreDuration kInitialRtt{333000};
inline constexpr std::size_t kMaxTrackedAckRanges = 64;

struct SentPacketRecord { // NOLINT(clang-analyzer-optin.performance.Padding)
    std::uint64_t packet_number = 0;
    QuicCoreTimePoint sent_time{};
    std::uint64_t congestion_send_sequence = 0;
    bool ack_eliciting = false;
    bool in_flight = false;
    bool declared_lost = false;
    bool has_handshake_done = false;
    std::vector<ByteRange> crypto_ranges;
    std::vector<NewTokenFrame> new_token_frames;
    std::vector<ResetStreamFrame> reset_stream_frames;
    std::vector<StopSendingFrame> stop_sending_frames;
    std::vector<NewConnectionIdFrame> new_connection_id_frames;
    std::vector<RetireConnectionIdFrame> retire_connection_id_frames;
    std::optional<MaxDataFrame> max_data_frame;
    std::vector<MaxStreamDataFrame> max_stream_data_frames;
    std::vector<MaxStreamsFrame> max_streams_frames;
    std::vector<StreamsBlockedFrame> streams_blocked_frames;
    std::optional<DataBlockedFrame> data_blocked_frame;
    std::vector<StreamDataBlockedFrame> stream_data_blocked_frames;
    std::optional<StreamFrameSendMetadata> first_stream_frame_metadata;
    std::vector<StreamFrameSendMetadata> stream_frame_metadata;
    std::vector<StreamFrameSendFragment> stream_fragments;
    std::shared_ptr<qlog::PacketSnapshot> qlog_packet_snapshot;
    bool qlog_pto_probe = false;
    bool has_ping = false;
    std::size_t bytes_in_flight = 0;
    bool force_ack = false;
    std::optional<std::uint64_t> largest_received_packet_number_acked;
    QuicPathId path_id = 0;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
    std::uint64_t delivered = 0;
    QuicCoreTimePoint delivered_time{};
    QuicCoreTimePoint first_sent_time{};
    std::size_t tx_in_flight = 0;
    std::uint64_t lost = 0;
    bool app_limited = false;
    bool is_pmtu_probe = false;
    std::size_t pmtu_probe_size = 0;
    std::uint64_t protection_key_update_generation = 0;
    bool lost_by_packet_threshold = false;
    std::uint64_t packet_threshold_largest_acked = 0;
    bool lost_by_time_threshold = false;
    QuicCoreTimePoint time_threshold_loss_time{};
};

struct SimpleStreamSentPacketRecord {
    std::uint64_t packet_number = 0;
    QuicCoreTimePoint sent_time{};
    std::uint64_t congestion_send_sequence = 0;
    std::optional<StreamFrameSendMetadata> first_stream_frame_metadata;
    std::vector<StreamFrameSendMetadata> stream_frame_metadata;
    std::size_t bytes_in_flight = 0;
    QuicPathId path_id = 0;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
    std::uint64_t delivered = 0;
    QuicCoreTimePoint delivered_time{};
    QuicCoreTimePoint first_sent_time{};
    std::size_t tx_in_flight = 0;
    std::uint64_t lost = 0;
    bool app_limited = false;
    std::uint64_t protection_key_update_generation = 0;
};

struct AckedStreamPacketSample {
    std::uint64_t packet_number = 0;
    QuicCoreTimePoint sent_time{};
    std::uint64_t congestion_send_sequence = 0;
    std::size_t bytes_in_flight = 0;
    QuicPathId path_id = 0;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
    std::uint64_t delivered = 0;
    QuicCoreTimePoint delivered_time{};
    QuicCoreTimePoint first_sent_time{};
    std::size_t tx_in_flight = 0;
    std::uint64_t lost = 0;
    bool app_limited = false;
};

struct AckedStreamPacketAggregate {
    std::size_t packet_count = 0;
    std::size_t bytes_in_flight = 0;
    std::uint64_t largest_packet_number = 0;
    QuicCoreTimePoint earliest_sent_time{};
    QuicCoreTimePoint latest_sent_time{};
    std::uint64_t smallest_congestion_send_sequence = 0;
    std::uint64_t largest_congestion_send_sequence = 0;

    bool empty() const {
        return packet_count == 0;
    }
};

SentPacketRecord
sent_packet_record_from_simple_stream_packet(const SimpleStreamSentPacketRecord &packet,
                                             bool declared_lost = false);

inline bool sent_packet_has_stream_frames(const SentPacketRecord &packet) {
    return packet.first_stream_frame_metadata.has_value() ||
           !packet.stream_frame_metadata.empty() || !packet.stream_fragments.empty();
}

struct RecoveryRttState {
    std::optional<QuicCoreDuration> latest_rtt;
    std::optional<QuicCoreDuration> latest_adjusted_rtt;
    std::optional<QuicCoreDuration> min_rtt;
    std::optional<QuicCoreDuration> latest_rtt_sample;
    std::optional<QuicCoreDuration> latest_adjusted_rtt_sample;
    std::optional<QuicCoreDuration> latest_ack_delay_compensated_rtt_sample;
    std::optional<QuicCoreDuration> min_rtt_sample;
    QuicCoreDuration smoothed_rtt{333000};
    QuicCoreDuration rttvar{166000};
};

struct RttAckDelayAdjustment {
    std::chrono::microseconds ack_delay{0};
    std::chrono::microseconds max_ack_delay{0};
    bool ignore_max_ack_delay = false;
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
    bool should_ignore(std::uint64_t packet_number) const;
    void record_received(std::uint64_t packet_number, bool ack_eliciting,
                         QuicCoreTimePoint received_time,
                         QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable,
                         std::uint64_t ack_eliciting_threshold = 2);
    bool has_ack_to_send() const;
    bool requests_immediate_ack() const;
    std::optional<OutboundAckHeader>
    build_outbound_ack_header(std::uint64_t ack_delay_exponent, QuicCoreTimePoint now,
                              bool allow_non_pending = false) const;

    template <typename Callback>
    void for_each_additional_ack_range_descending(const OutboundAckHeader &header,
                                                  Callback &&callback) const {
        for (const auto &range : header.additional_ranges) {
            callback(range);
        }
    }

    std::optional<AckFrame> build_ack_frame(std::uint64_t ack_delay_exponent, QuicCoreTimePoint now,
                                            bool allow_non_pending = false) const;
    void on_ack_sent();
    void retire_acknowledged_ranges_up_to(std::uint64_t largest_acknowledged);

  private:
    struct ReceivedPacketRange {
        std::uint64_t largest_packet_number = 0;
    };

    struct ReceivedPacketRecord {
        bool ack_eliciting = false;
        QuicCoreTimePoint received_time{};
    };

    std::map<std::uint64_t, ReceivedPacketRange> ranges_;
    void trim_old_ack_ranges();
    std::uint64_t least_untracked_packet_number_ = 0;
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

        explicit const_iterator(std::vector<RecoveryPacketMetadata>::const_iterator it);

        value_type operator*() const;
        const_iterator &operator++();
        const_iterator operator++(int);
        bool operator==(const const_iterator &other) const = default;

      private:
        std::vector<RecoveryPacketMetadata>::const_iterator it_;
    };

    void reserve(std::size_t count);
    void push_back(RecoveryPacketHandle handle, RecoveryPacketMetadata metadata);
    bool empty() const;
    std::size_t size() const;
    RecoveryPacketMetadata front() const;
    RecoveryPacketMetadata back() const;
    std::span<const RecoveryPacketHandle> handles() const;
    const_iterator begin() const;
    const_iterator end() const;

  private:
    std::vector<RecoveryPacketHandle> handles_;
    std::vector<RecoveryPacketMetadata> metadata_;
};

class RecoveryPacketHandleOptional {
  public:
    void emplace(RecoveryPacketHandle handle, RecoveryPacketMetadata metadata);
    bool has_value() const;
    RecoveryPacketMetadata value() const;
    const RecoveryPacketMetadata *operator->() const;

  private:
    std::optional<RecoveryPacketHandle> handle_;
    std::optional<RecoveryPacketMetadata> metadata_;
};

class RecoveryPacketHandleSmallList {
  public:
    using iterator = RecoveryPacketHandle *;
    using const_iterator = const RecoveryPacketHandle *;

    void push_back(RecoveryPacketHandle handle);
    bool empty() const;
    std::size_t size() const;
    RecoveryPacketHandle front() const;
    std::span<const RecoveryPacketHandle> handles() const;
    iterator begin();
    iterator end();
    const_iterator begin() const;
    const_iterator end() const;

  private:
    static constexpr std::size_t kInlineCapacity = 4;

    RecoveryPacketHandle *mutable_data();
    const RecoveryPacketHandle *data() const;

    std::array<RecoveryPacketHandle, kInlineCapacity> inline_handles_{};
    std::vector<RecoveryPacketHandle> heap_handles_;
    std::size_t size_ = 0;
    bool heap_backed_ = false;
};

struct AckProcessingResult {
    RecoveryPacketHandleList acked_packets;
    RecoveryPacketHandleList late_acked_packets;
    RecoveryPacketHandleList lost_packets;
    RecoveryPacketHandleOptional largest_newly_acked_packet;
    bool largest_acknowledged_was_newly_acked = false;
    bool has_newly_acked_ack_eliciting = false;
};

struct AckApplyLargestNewlyAckedPacket {
    RecoveryPacketHandle handle;
    std::uint64_t packet_number = 0;
    QuicCoreTimePoint sent_time{};
};

struct AckApplyResult {
    RecoveryPacketHandleSmallList acked_packets;
    RecoveryPacketHandleSmallList late_acked_packets;
    RecoveryPacketHandleSmallList lost_packets;
    std::optional<AckApplyLargestNewlyAckedPacket> largest_newly_acked_packet;
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
    void on_packet_sent(SentPacketRecord &&packet);
    void on_simple_stream_packet_sent(SimpleStreamSentPacketRecord &&packet);
    void on_simple_stream_packets_sent(std::span<SimpleStreamSentPacketRecord> packets);
    void on_packet_declared_lost(std::uint64_t packet_number);
    void retire_packet(RecoveryPacketHandle handle);
    void retire_packet(std::uint64_t packet_number);
    bool retire_packet_if_present(RecoveryPacketHandle handle);
    std::optional<SentPacketRecord> take_retired_packet(RecoveryPacketHandle handle);
    std::optional<SentPacketRecord> take_retired_packet_if_present(RecoveryPacketHandle handle);
    AckApplyResult apply_ack_received(AckRangeCursor cursor, std::uint64_t largest_acknowledged,
                                      QuicCoreTimePoint now);
    AckProcessingResult on_ack_received(std::span<const AckPacketNumberRange> ack_ranges,
                                        std::uint64_t largest_acknowledged, QuicCoreTimePoint now);
    AckProcessingResult on_ack_received(AckRangeCursor cursor, std::uint64_t largest_acknowledged,
                                        QuicCoreTimePoint now);
    AckProcessingResult on_ack_received(const AckFrame &ack, QuicCoreTimePoint now);
    std::optional<RecoveryPacketHandle> handle_for_packet_number(std::uint64_t packet_number) const;
    SentPacketRecord *packet_for_handle(RecoveryPacketHandle handle);
    const SentPacketRecord *packet_for_handle(RecoveryPacketHandle handle) const;
    const SimpleStreamSentPacketRecord *
    simple_stream_packet_for_handle(RecoveryPacketHandle handle) const;
    std::optional<SimpleStreamSentPacketRecord>
    take_simple_stream_packet_if_present(RecoveryPacketHandle handle);
    std::size_t
    retire_simple_stream_packets_if_present(std::span<const RecoveryPacketHandle> handles);
    SentPacketRecord *find_packet(std::uint64_t packet_number);
    const SentPacketRecord *find_packet(std::uint64_t packet_number) const;
    const SentPacketRecord *find_newly_ackable_packet(std::uint64_t packet_number) const;
    bool ack_ranges_include_newly_ackable_ack_eliciting_packet(AckRangeCursor cursor) const;
    std::vector<RecoveryPacketHandle> tracked_packets() const;
    std::size_t tracked_packet_count() const;
    std::optional<RecoveryPacketHandle> oldest_tracked_packet() const;
    std::optional<RecoveryPacketHandle> newest_tracked_packet() const;
    std::vector<RecoveryPacketHandle> collect_time_threshold_losses(QuicCoreTimePoint now);
    std::optional<std::uint64_t> largest_acked_packet_number() const;
    std::optional<DeadlineTrackedPacket> latest_in_flight_ack_eliciting_packet() const;
    std::optional<DeadlineTrackedPacket> earliest_loss_packet() const;
    QuicCoreTimePoint time_threshold_deadline(QuicCoreTimePoint sent_time) const;
    std::optional<DeadlineTrackedPacket> earliest_pmtu_probe_packet() const;
    std::vector<RecoveryPacketHandle> collect_pmtu_probe_timeouts(QuicCoreTimePoint now) const;
    void rebuild_auxiliary_indexes();
    void note_packet_metadata_updated();
    std::uint64_t compatibility_version() const;

    RecoveryRttState &rtt_state();
    const RecoveryRttState &rtt_state() const;

  private:
    struct SentPacketsView {
        const PacketSpaceRecovery *owner = nullptr;

        bool contains(std::uint64_t packet_number) const;
        const SentPacketRecord &at(std::uint64_t packet_number) const;
        std::size_t size() const;
    };

    enum class LedgerSlotState : std::uint8_t {
        empty,
        sent,
        declared_lost,
        retired,
    };

    struct AckApplyState {
        AckApplyResult result;
        std::size_t current_live_slot = kInvalidLedgerSlotIndex;
        std::optional<std::uint64_t> previous_largest_acked;
        std::uint64_t largest_acknowledged = 0;
        std::uint64_t effective_largest_acked = 0;
        QuicCoreTimePoint now{};
        bool largest_acked_advanced = false;
        bool mutated = false;
    };

    static constexpr std::size_t kInvalidLedgerSlotIndex = std::numeric_limits<std::size_t>::max();
    static constexpr std::size_t kMaxSentPacketRecordPoolSize = 8192;

    struct SentPacketLedgerSlot {
        SentPacketLedgerSlot() = default;
        SentPacketLedgerSlot(const SentPacketLedgerSlot &other);
        SentPacketLedgerSlot(SentPacketLedgerSlot &&other) noexcept = default;
        SentPacketLedgerSlot &operator=(const SentPacketLedgerSlot &other);
        SentPacketLedgerSlot &operator=(SentPacketLedgerSlot &&other) noexcept = default;

        LedgerSlotState state = LedgerSlotState::empty;
        std::uint64_t packet_number = 0;
        std::unique_ptr<SentPacketRecord> packet;
        std::optional<SimpleStreamSentPacketRecord> simple_stream_packet;
        bool acknowledged = false;
    };

    struct LiveSlotLink {
        std::size_t prev = kInvalidLedgerSlotIndex;
        std::size_t next = kInvalidLedgerSlotIndex;
    };

    static DeadlineTrackedPacket tracked_packet(const SentPacketRecord &packet);
    static SentPacketRecord *slot_packet_or_null(SentPacketLedgerSlot &slot);
    static const SentPacketRecord *slot_packet_or_null(const SentPacketLedgerSlot &slot);
    static SentPacketRecord &slot_packet(SentPacketLedgerSlot &slot);
    static const SentPacketRecord &slot_packet(const SentPacketLedgerSlot &slot);
    static bool slot_has_packet_record(const SentPacketLedgerSlot &slot);
    static std::uint64_t slot_packet_number(const SentPacketLedgerSlot &slot);
    static QuicCoreTimePoint slot_sent_time(const SentPacketLedgerSlot &slot);
    static bool slot_ack_eliciting(const SentPacketLedgerSlot &slot);
    static bool slot_in_flight(const SentPacketLedgerSlot &slot);
    static bool slot_declared_lost(const SentPacketLedgerSlot &slot);
    static bool slot_is_pmtu_probe(const SentPacketLedgerSlot &slot);
    static DeadlineTrackedPacket tracked_packet(const SentPacketLedgerSlot &slot);
    RecoveryPacketHandle packet_handle(const SentPacketLedgerSlot &slot,
                                       std::size_t slot_index) const;
    static void reclaim_retired_packet_storage(SentPacketRecord &packet);
    std::optional<std::size_t> slot_index_for_packet_number(std::uint64_t packet_number) const;
    std::optional<std::size_t> slot_index_for_handle(RecoveryPacketHandle handle) const;
    std::size_t absolute_slot_index(std::size_t relative_slot_index) const;
    std::size_t relative_slot_index(std::size_t absolute_slot_index) const;
    SentPacketLedgerSlot *slot_for_handle(RecoveryPacketHandle handle);
    const SentPacketLedgerSlot *slot_for_handle(RecoveryPacketHandle handle) const;
    void compact_retired_prefix();
    void prepend_slots_for_packet_number(std::uint64_t packet_number);
    std::unique_ptr<SentPacketRecord> acquire_packet_record(SentPacketRecord &&packet);
    void recycle_packet_record(std::unique_ptr<SentPacketRecord> packet);
    SentPacketRecord &materialize_slot_packet(SentPacketLedgerSlot &slot);
    void link_live_slot(std::size_t slot_index);
    void ensure_live_link_slot(std::size_t slot_index);
    void set_live_link(std::size_t slot_index, LiveSlotLink link);
    void set_live_slot_bit(std::size_t slot_index);
    void clear_live_slot_bit(std::size_t slot_index);
    std::size_t previous_live_slot(std::size_t slot_index) const;
    std::size_t next_live_slot(std::size_t slot_index) const;
    void unlink_live_slot(std::size_t slot_index);
    void note_live_slot_sent_time_order(std::size_t slot_index);
    void note_live_packet_removed_from_tracking(std::size_t slot_index);
    std::size_t newest_live_slot_at_or_below(std::uint64_t packet_number) const;
    SentPacketLedgerSlot *slot_for_packet_number(std::uint64_t packet_number);
    const SentPacketLedgerSlot *slot_for_packet_number(std::uint64_t packet_number) const;
    SentPacketLedgerSlot *outstanding_slot_for_packet_number(std::uint64_t packet_number);
    const SentPacketLedgerSlot *
    outstanding_slot_for_packet_number(std::uint64_t packet_number) const;
    const SentPacketLedgerSlot *slot_for_tracked_packet(const DeadlineTrackedPacket &packet) const;
    bool is_valid_in_flight_ack_eliciting_tracked_packet(const DeadlineTrackedPacket &packet) const;
    bool is_valid_eligible_loss_tracked_packet(const DeadlineTrackedPacket &packet) const;
    void maybe_track_latest_in_flight_ack_eliciting_packet(const SentPacketRecord &packet) const;
    void maybe_track_latest_in_flight_ack_eliciting_packet(const SentPacketLedgerSlot &slot) const;
    void refresh_latest_in_flight_ack_eliciting_packet() const;
    void prune_stale_eligible_loss_packets() const;
    void erase_from_tracked_sets(const SentPacketRecord &packet);
    void erase_from_tracked_sets(const SentPacketLedgerSlot &slot);
    void maybe_track_as_loss_candidate(const SentPacketRecord &packet);
    void maybe_track_as_loss_candidate(const SentPacketLedgerSlot &slot);
    void track_new_loss_candidates(std::optional<std::uint64_t> previous_largest_acked,
                                   std::uint64_t largest_acked);
    bool is_packet_threshold_lost(std::uint64_t packet_number, std::uint64_t largest_acked) const;
    bool is_time_threshold_lost(QuicCoreTimePoint sent_time, QuicCoreTimePoint now) const;
    void note_packet_threshold_loss(SentPacketRecord &packet, std::uint64_t largest_acked);
    void note_time_threshold_loss(SentPacketRecord &packet, QuicCoreTimePoint now);
    void clear_loss_cause(SentPacketRecord &packet);
    void maybe_adapt_reordering_thresholds_from_spurious_loss(const SentPacketRecord &packet,
                                                              QuicCoreTimePoint now);
    std::size_t ensure_slot_for_packet_number(std::uint64_t packet_number);
    void rebuild_auxiliary_indexes(bool release_auxiliary_storage);
    AckApplyState begin_ack_received_apply(std::uint64_t largest_acknowledged);
    void apply_ack_range_descending(AckApplyState &state, const AckPacketNumberRange &range);
    AckApplyResult finish_ack_received_apply(AckApplyState &state, QuicCoreTimePoint now);
    AckApplyResult
    apply_ack_received_descending(std::span<const AckPacketNumberRange> ack_ranges_descending,
                                  std::uint64_t largest_acknowledged, QuicCoreTimePoint now);
    AckProcessingResult ack_processing_result_from_apply(const AckApplyResult &apply_result) const;

    std::deque<SentPacketLedgerSlot> slots_;
    std::vector<std::unique_ptr<SentPacketRecord>> packet_record_pool_;
    std::vector<LiveSlotLink> live_links_;
    std::vector<std::uint64_t> live_slot_words_;
    mutable std::optional<DeadlineTrackedPacket> latest_in_flight_ack_eliciting_packet_;
    mutable std::set<DeadlineTrackedPacket, DeadlineTrackedPacketLess> eligible_loss_packets_;
    std::optional<std::uint64_t> largest_acked_packet_number_;
    std::uint64_t first_slot_packet_number_ = 0;
    std::size_t first_live_slot_ = kInvalidLedgerSlotIndex;
    std::size_t last_live_slot_ = kInvalidLedgerSlotIndex;
    bool live_sent_times_monotonic_ = true;
    std::size_t next_loss_candidate_slot_ = 0;
    std::size_t next_packet_threshold_loss_slot_ = 0;
    std::uint64_t packet_reordering_threshold_ = kPacketThreshold;
    QuicCoreDuration time_reordering_threshold_{};
    std::uint64_t compatibility_version_ = 0;
    RecoveryRttState rtt_state_;
    SentPacketsView sent_packets_{};
    mutable std::optional<SentPacketRecord> packet_view_scratch_;

    friend struct test::PacketSpaceRecoveryTestPeer;
};

bool is_packet_threshold_lost(std::uint64_t packet_number, std::uint64_t largest_acked);
bool is_packet_threshold_lost(std::uint64_t packet_number, std::uint64_t largest_acked,
                              std::uint64_t packet_threshold);
QuicCoreTimePoint compute_time_threshold_deadline(const RecoveryRttState &rtt_state,
                                                  QuicCoreTimePoint sent_time);
bool is_time_threshold_lost(const RecoveryRttState &rtt_state, QuicCoreTimePoint sent_time,
                            QuicCoreTimePoint now);
QuicCoreTimePoint compute_pto_deadline(const RecoveryRttState &rtt_state,
                                       QuicCoreDuration max_ack_delay, QuicCoreTimePoint now,
                                       std::uint32_t pto_count);
void update_rtt(RecoveryRttState &rtt_state, QuicCoreTimePoint ack_receive_time,
                const SentPacketRecord &largest_newly_acked_packet,
                std::chrono::microseconds ack_delay, std::chrono::microseconds max_ack_delay);
void update_rtt(RecoveryRttState &rtt_state, QuicCoreTimePoint ack_receive_time,
                const SentPacketRecord &largest_newly_acked_packet,
                RttAckDelayAdjustment ack_delay);

} // namespace coquic::quic
