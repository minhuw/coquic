#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "src/quic/core.h"
#include "src/quic/crypto_stream.h"
#include "src/quic/frame.h"

namespace coquic::quic {

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

  private:
    struct ReceivedPacketRecord {
        bool ack_eliciting = false;
        QuicCoreTimePoint received_time{};
    };

    std::map<std::uint64_t, ReceivedPacketRecord> packets_;
    bool ack_pending_ = false;
    std::optional<QuicCoreTimePoint> latest_ack_eliciting_received_time_;
};

struct AckProcessingResult {
    std::vector<SentPacketRecord> acked_packets;
    std::vector<SentPacketRecord> lost_packets;
    std::optional<SentPacketRecord> largest_newly_acked_ack_eliciting;
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
QuicCoreTimePoint compute_pto_deadline(const RecoveryRttState &rtt, std::uint64_t max_ack_delay_ms,
                                       QuicCoreTimePoint now);
void update_rtt(RecoveryRttState &rtt, QuicCoreTimePoint ack_receive_time,
                const SentPacketRecord &largest_acked_ack_eliciting_packet,
                std::chrono::milliseconds ack_delay, std::chrono::milliseconds max_ack_delay);

} // namespace coquic::quic
