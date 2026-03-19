#include "src/quic/recovery.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace coquic::quic {

namespace {

std::uint64_t encode_ack_delay(std::chrono::microseconds ack_delay,
                               std::uint64_t ack_delay_exponent) {
    if (ack_delay.count() <= 0) {
        return 0;
    }

    if (ack_delay_exponent >= std::numeric_limits<std::uint64_t>::digits) {
        return 0;
    }

    return static_cast<std::uint64_t>(ack_delay.count()) >> ack_delay_exponent;
}

bool ack_frame_acks_packet(const AckFrame &ack, std::uint64_t packet_number) {
    if (packet_number > ack.largest_acknowledged) {
        return false;
    }
    if (ack.largest_acknowledged < ack.first_ack_range) {
        return false;
    }

    auto range_largest = ack.largest_acknowledged;
    auto range_smallest = ack.largest_acknowledged - ack.first_ack_range;
    if (packet_number >= range_smallest && packet_number <= range_largest) {
        return true;
    }

    auto previous_smallest = range_smallest;
    for (const auto &range : ack.additional_ranges) {
        if (previous_smallest < range.gap + 2) {
            return false;
        }

        range_largest = previous_smallest - range.gap - 2;
        if (range_largest < range.range_length) {
            return false;
        }
        range_smallest = range_largest - range.range_length;
        if (packet_number >= range_smallest && packet_number <= range_largest) {
            return true;
        }

        previous_smallest = range_smallest;
    }

    return false;
}

std::chrono::milliseconds latest_loss_delay(const RecoveryRttState &rtt) {
    const auto base_rtt =
        rtt.latest_rtt.has_value() ? std::max(*rtt.latest_rtt, rtt.smoothed_rtt) : kInitialRtt;
    const auto rounded_up_loss_delay = std::chrono::milliseconds((base_rtt.count() * 9 + 7) / 8);
    return std::max(kGranularity, rounded_up_loss_delay);
}

} // namespace

void ReceivedPacketHistory::record_received(std::uint64_t packet_number, bool ack_eliciting,
                                            QuicCoreTimePoint received_time) {
    packets_[packet_number] = ReceivedPacketRecord{
        .ack_eliciting = ack_eliciting,
        .received_time = received_time,
    };

    if (ack_eliciting) {
        ack_pending_ = true;
        latest_ack_eliciting_received_time_ = received_time;
    }
}

bool ReceivedPacketHistory::has_ack_to_send() const {
    return ack_pending_;
}

std::optional<AckFrame> ReceivedPacketHistory::build_ack_frame(std::uint64_t ack_delay_exponent,
                                                               QuicCoreTimePoint now) const {
    if (!ack_pending_ || packets_.empty()) {
        return std::nullopt;
    }

    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
    auto it = packets_.rbegin();
    while (it != packets_.rend()) {
        const auto range_end = it->first;
        auto range_start = range_end;
        auto previous_packet_number = range_end;
        ++it;
        while (it != packets_.rend() && it->first + 1 == previous_packet_number) {
            range_start = it->first;
            previous_packet_number = it->first;
            ++it;
        }
        ranges.emplace_back(range_start, range_end);
    }

    AckFrame ack{
        .largest_acknowledged = ranges.front().second,
        .first_ack_range = ranges.front().second - ranges.front().first,
    };

    const auto largest_acknowledged_it = packets_.find(ack.largest_acknowledged);
    if (largest_acknowledged_it != packets_.end() &&
        now >= largest_acknowledged_it->second.received_time) {
        const auto ack_delay = std::chrono::duration_cast<std::chrono::microseconds>(
            now - largest_acknowledged_it->second.received_time);
        ack.ack_delay = encode_ack_delay(ack_delay, ack_delay_exponent);
    }

    auto previous_smallest = ranges.front().first;
    for (std::size_t index = 1; index < ranges.size(); ++index) {
        const auto [range_start, range_end] = ranges[index];
        ack.additional_ranges.push_back(AckRange{
            .gap = previous_smallest - range_end - 2,
            .range_length = range_end - range_start,
        });
        previous_smallest = range_start;
    }

    return ack;
}

void ReceivedPacketHistory::on_ack_sent() {
    ack_pending_ = false;
}

void PacketSpaceRecovery::on_packet_sent(SentPacketRecord packet) {
    sent_packets_[packet.packet_number] = std::move(packet);
}

AckProcessingResult PacketSpaceRecovery::on_ack_received(const AckFrame &ack,
                                                         QuicCoreTimePoint now) {
    AckProcessingResult result;
    largest_acked_packet_number_ =
        largest_acked_packet_number_.has_value()
            ? std::max(*largest_acked_packet_number_, ack.largest_acknowledged)
            : ack.largest_acknowledged;
    const auto effective_largest_acked = *largest_acked_packet_number_;
    std::vector<std::uint64_t> acked_packet_numbers;

    for (const auto &[packet_number, packet] : sent_packets_) {
        if (!ack_frame_acks_packet(ack, packet_number)) {
            continue;
        }

        acked_packet_numbers.push_back(packet_number);
        result.acked_packets.push_back(packet);
        if (packet.ack_eliciting &&
            (!result.largest_newly_acked_ack_eliciting.has_value() ||
             packet.packet_number > result.largest_newly_acked_ack_eliciting->packet_number)) {
            result.largest_newly_acked_ack_eliciting = packet;
        }
    }

    for (const auto packet_number : acked_packet_numbers) {
        sent_packets_.erase(packet_number);
    }

    std::vector<std::uint64_t> lost_packet_numbers;
    for (const auto &[packet_number, packet] : sent_packets_) {
        if (packet.declared_lost || !packet.in_flight ||
            packet.packet_number >= effective_largest_acked) {
            continue;
        }

        if (!is_packet_threshold_lost(packet.packet_number, effective_largest_acked) &&
            !is_time_threshold_lost(rtt_state_, packet.sent_time, now)) {
            continue;
        }

        lost_packet_numbers.push_back(packet_number);
        result.lost_packets.push_back(packet);
    }

    for (const auto packet_number : lost_packet_numbers) {
        sent_packets_.erase(packet_number);
    }

    return result;
}

std::optional<std::uint64_t> PacketSpaceRecovery::largest_acked_packet_number() const {
    return largest_acked_packet_number_;
}

RecoveryRttState &PacketSpaceRecovery::rtt_state() {
    return rtt_state_;
}

const RecoveryRttState &PacketSpaceRecovery::rtt_state() const {
    return rtt_state_;
}

bool is_packet_threshold_lost(std::uint64_t packet_number, std::uint64_t largest_acked) {
    return largest_acked > packet_number && largest_acked - packet_number >= kPacketThreshold;
}

QuicCoreTimePoint compute_time_threshold_deadline(const RecoveryRttState &rtt,
                                                  QuicCoreTimePoint sent_time) {
    return sent_time + latest_loss_delay(rtt);
}

bool is_time_threshold_lost(const RecoveryRttState &rtt, QuicCoreTimePoint sent_time,
                            QuicCoreTimePoint now) {
    return now >= compute_time_threshold_deadline(rtt, sent_time);
}

QuicCoreTimePoint compute_pto_deadline(const RecoveryRttState &rtt, std::uint64_t max_ack_delay_ms,
                                       QuicCoreTimePoint now) {
    std::chrono::milliseconds timeout = kInitialRtt * 3;
    if (rtt.latest_rtt.has_value()) {
        timeout = rtt.smoothed_rtt + std::max(rtt.rttvar * 4, kGranularity) +
                  std::chrono::milliseconds(max_ack_delay_ms);
    }

    for (std::uint32_t count = 0; count < rtt.pto_count; ++count) {
        timeout *= 2;
    }

    return now + timeout;
}

void update_rtt(RecoveryRttState &rtt, QuicCoreTimePoint ack_receive_time,
                const SentPacketRecord &largest_acked_ack_eliciting_packet,
                std::chrono::milliseconds ack_delay, std::chrono::milliseconds max_ack_delay) {
    const auto latest_sample = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::max(ack_receive_time - largest_acked_ack_eliciting_packet.sent_time,
                 QuicCoreClock::duration::zero()));
    const auto first_sample = !rtt.latest_rtt.has_value();

    rtt.latest_rtt = latest_sample;
    rtt.min_rtt = rtt.min_rtt.has_value() ? std::min(*rtt.min_rtt, latest_sample) : latest_sample;

    if (first_sample) {
        rtt.smoothed_rtt = latest_sample;
        rtt.rttvar = latest_sample / 2;
        return;
    }

    const auto bounded_ack_delay = std::min(ack_delay, max_ack_delay);
    auto adjusted_rtt = latest_sample;
    if (rtt.min_rtt.has_value() && latest_sample >= *rtt.min_rtt + bounded_ack_delay) {
        adjusted_rtt = latest_sample - bounded_ack_delay;
    }

    const auto rtt_sample_delta = rtt.smoothed_rtt > adjusted_rtt ? rtt.smoothed_rtt - adjusted_rtt
                                                                  : adjusted_rtt - rtt.smoothed_rtt;
    rtt.rttvar = (rtt.rttvar * 3 + rtt_sample_delta) / 4;
    rtt.smoothed_rtt = (rtt.smoothed_rtt * 7 + adjusted_rtt) / 8;
}

} // namespace coquic::quic
