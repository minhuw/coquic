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

    auto range_smallest = ack.largest_acknowledged - ack.first_ack_range;
    if (packet_number >= range_smallest) {
        return true;
    }

    auto previous_smallest = range_smallest;
    for (const auto &range : ack.additional_ranges) {
        if (previous_smallest < range.gap + 2) {
            return false;
        }

        const auto range_largest = previous_smallest - range.gap - 2;
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

bool ReceivedPacketHistory::contains(std::uint64_t packet_number) const {
    const auto next = ranges_.upper_bound(packet_number);
    if (next != ranges_.begin()) {
        const auto previous = std::prev(next);
        if (packet_number <= previous->second.largest_packet_number) {
            return true;
        }
    }

    return false;
}

void ReceivedPacketHistory::record_received(std::uint64_t packet_number, bool ack_eliciting,
                                            QuicCoreTimePoint received_time) {
    if (contains(packet_number)) {
        if (ack_eliciting) {
            ack_pending_ = true;
        }
        return;
    }

    const auto next = ranges_.upper_bound(packet_number);
    const auto extends_previous =
        next != ranges_.begin() &&
        std::prev(next)->second.largest_packet_number + 1 == packet_number;
    const auto extends_next = next != ranges_.end() && packet_number + 1 == next->first;

    if (extends_previous && extends_next) {
        auto previous = std::prev(next);
        previous->second.largest_packet_number = next->second.largest_packet_number;
        ranges_.erase(next);
    } else if (extends_previous) {
        std::prev(next)->second.largest_packet_number = packet_number;
    } else if (extends_next) {
        const auto largest_packet_number = next->second.largest_packet_number;
        ranges_.erase(next);
        ranges_.emplace(packet_number, ReceivedPacketRange{
                                           .largest_packet_number = largest_packet_number,
                                       });
    } else {
        ranges_.emplace(packet_number, ReceivedPacketRange{
                                           .largest_packet_number = packet_number,
                                       });
    }

    if (!largest_received_packet_number_.has_value() ||
        packet_number > *largest_received_packet_number_) {
        largest_received_packet_number_ = packet_number;
        largest_received_packet_record_ = ReceivedPacketRecord{
            .ack_eliciting = ack_eliciting,
            .received_time = received_time,
        };
    }

    if (ack_eliciting) {
        ack_pending_ = true;
    }
}

bool ReceivedPacketHistory::has_ack_to_send() const {
    return ack_pending_;
}

std::optional<AckFrame> ReceivedPacketHistory::build_ack_frame(std::uint64_t ack_delay_exponent,
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

    AckFrame ack{
        .largest_acknowledged = largest_range->second.largest_packet_number,
        .first_ack_range = largest_range->second.largest_packet_number - largest_range->first,
    };

    const auto ack_delay = std::chrono::duration_cast<std::chrono::microseconds>(std::max(
        now - largest_received_packet_record.received_time, QuicCoreClock::duration::zero()));
    ack.ack_delay = encode_ack_delay(ack_delay, ack_delay_exponent);

    auto previous_smallest = largest_range->first;
    for (auto it = std::next(ranges_.rbegin()); it != ranges_.rend(); ++it) {
        const auto range_start = it->first;
        const auto range_end = it->second.largest_packet_number;
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
        result.largest_newly_acked_packet = packet;
        if (packet.packet_number == ack.largest_acknowledged) {
            result.largest_acknowledged_was_newly_acked = true;
        }
        if (packet.ack_eliciting) {
            result.has_newly_acked_ack_eliciting = true;
        }
    }

    for (const auto packet_number : acked_packet_numbers) {
        sent_packets_.erase(packet_number);
    }

    for (auto &[packet_number, packet] : sent_packets_) {
        if (packet.declared_lost || !packet.in_flight ||
            packet.packet_number >= effective_largest_acked) {
            continue;
        }

        if (!is_packet_threshold_lost(packet.packet_number, effective_largest_acked) &&
            !is_time_threshold_lost(rtt_state_, packet.sent_time, now)) {
            continue;
        }

        result.lost_packets.push_back(packet);
        packet.declared_lost = true;
        packet.in_flight = false;
        packet.bytes_in_flight = 0;
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

QuicCoreTimePoint compute_pto_deadline(const RecoveryRttState &rtt,
                                       std::chrono::milliseconds max_ack_delay,
                                       QuicCoreTimePoint now, std::uint32_t pto_count) {
    std::chrono::milliseconds timeout = kInitialRtt * 3;
    if (rtt.latest_rtt.has_value()) {
        timeout = rtt.smoothed_rtt + std::max(rtt.rttvar * 4, kGranularity) + max_ack_delay;
    }

    for (std::uint32_t count = 0; count < pto_count; ++count) {
        timeout *= 2;
    }

    return now + timeout;
}

void update_rtt(RecoveryRttState &rtt, QuicCoreTimePoint ack_receive_time,
                const SentPacketRecord &largest_newly_acked_packet,
                std::chrono::milliseconds ack_delay, std::chrono::milliseconds max_ack_delay) {
    const auto latest_sample = std::chrono::duration_cast<std::chrono::milliseconds>(std::max(
        ack_receive_time - largest_newly_acked_packet.sent_time, QuicCoreClock::duration::zero()));
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
    if (latest_sample >= *rtt.min_rtt + bounded_ack_delay) {
        adjusted_rtt = latest_sample - bounded_ack_delay;
    }

    const auto rtt_sample_delta = rtt.smoothed_rtt > adjusted_rtt ? rtt.smoothed_rtt - adjusted_rtt
                                                                  : adjusted_rtt - rtt.smoothed_rtt;
    rtt.rttvar = (rtt.rttvar * 3 + rtt_sample_delta) / 4;
    rtt.smoothed_rtt = (rtt.smoothed_rtt * 7 + adjusted_rtt) / 8;
}

} // namespace coquic::quic
