#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
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

struct AckProcessingResult {
    std::vector<SentPacketRecord> acked_packets;
    std::vector<SentPacketRecord> lost_packets;
    std::optional<SentPacketRecord> largest_newly_acked_packet;
    bool largest_acknowledged_was_newly_acked = false;
    bool has_newly_acked_ack_eliciting = false;
};

class PacketSpaceRecovery {
  public:
    void on_packet_sent(SentPacketRecord packet);
    AckProcessingResult on_ack_received(const AckFrame &ack, QuicCoreTimePoint now);
    std::optional<std::uint64_t> largest_acked_packet_number() const;

    RecoveryRttState &rtt_state();
    const RecoveryRttState &rtt_state() const;

  private:
    std::map<std::uint64_t, SentPacketRecord> sent_packets_;
    std::optional<std::uint64_t> largest_acked_packet_number_;
    RecoveryRttState rtt_state_;
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
