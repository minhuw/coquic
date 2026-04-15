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

std::chrono::milliseconds latest_loss_delay(const RecoveryRttState &rtt) {
    const auto base_rtt =
        rtt.latest_rtt.has_value() ? std::max(*rtt.latest_rtt, rtt.smoothed_rtt) : kInitialRtt;
    const auto rounded_up_loss_delay = std::chrono::milliseconds((base_rtt.count() * 9 + 7) / 8);
    return std::max(kGranularity, rounded_up_loss_delay);
}

void note_received_ecn(AckEcnCounts &counts, QuicEcnCodepoint ecn) {
    switch (ecn) {
    case QuicEcnCodepoint::ect0:
        ++counts.ect0;
        break;
    case QuicEcnCodepoint::ect1:
        ++counts.ect1;
        break;
    case QuicEcnCodepoint::ce:
        ++counts.ecn_ce;
        break;
    case QuicEcnCodepoint::unavailable:
    case QuicEcnCodepoint::not_ect:
        break;
    }
}

} // namespace

bool DeadlineTrackedPacketLess::operator()(const DeadlineTrackedPacket &lhs,
                                           const DeadlineTrackedPacket &rhs) const {
    if (lhs.sent_time != rhs.sent_time) {
        return lhs.sent_time < rhs.sent_time;
    }
    return lhs.packet_number < rhs.packet_number;
}

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
                                            QuicCoreTimePoint received_time, QuicEcnCodepoint ecn) {
    const bool duplicate = contains(packet_number);
    const bool has_prior_ack_eliciting_packet =
        ack_eliciting && largest_received_ack_eliciting_packet_number_.has_value();
    const bool ack_eliciting_out_of_order =
        has_prior_ack_eliciting_packet &&
        packet_number < *largest_received_ack_eliciting_packet_number_;
    const bool ack_eliciting_creates_gap = ack_eliciting &&
                                           largest_received_packet_number_.has_value() &&
                                           packet_number > *largest_received_packet_number_ + 1;

    if (duplicate) {
        if (ack_eliciting) {
            ack_pending_ = true;
            immediate_ack_requested_ = true;
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
        ++ack_eliciting_packets_since_last_ack_;
        immediate_ack_requested_ = immediate_ack_requested_ || ack_eliciting_out_of_order ||
                                   ack_eliciting_creates_gap ||
                                   ack_eliciting_packets_since_last_ack_ >= 2;
        largest_received_ack_eliciting_packet_number_ = std::max(
            largest_received_ack_eliciting_packet_number_.value_or(packet_number), packet_number);
        ack_pending_ = true;
    }
    if (ecn != QuicEcnCodepoint::unavailable) {
        ecn_feedback_accessible_ = true;
    }
    note_received_ecn(ecn_counts_, ecn);
}

bool ReceivedPacketHistory::has_ack_to_send() const {
    return ack_pending_;
}

bool ReceivedPacketHistory::requests_immediate_ack() const {
    return immediate_ack_requested_;
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
    if (ecn_feedback_accessible_) {
        ack.ecn_counts = ecn_counts_;
    }

    return ack;
}

void ReceivedPacketHistory::on_ack_sent() {
    ack_pending_ = false;
    immediate_ack_requested_ = false;
    ack_eliciting_packets_since_last_ack_ = 0;
}

DeadlineTrackedPacket PacketSpaceRecovery::tracked_packet(const SentPacketRecoveryRecord &packet) {
    return DeadlineTrackedPacket{
        .packet_number = packet.packet_number,
        .sent_time = packet.sent_time,
    };
}

RecoveryPacketMetadata
PacketSpaceRecovery::packet_metadata(const SentPacketRecoveryRecord &packet) {
    return RecoveryPacketMetadata{
        .packet_number = packet.packet_number,
        .sent_time = packet.sent_time,
        .ack_eliciting = packet.ack_eliciting,
        .in_flight = packet.in_flight,
        .declared_lost = packet.declared_lost,
    };
}

void PacketSpaceRecovery::erase_from_tracked_sets(const SentPacketRecoveryRecord &packet) {
    const auto tracked = tracked_packet(packet);
    in_flight_ack_eliciting_packets_.erase(tracked);
    eligible_loss_packets_.erase(tracked);
}

void PacketSpaceRecovery::maybe_track_as_loss_candidate(const SentPacketRecoveryRecord &packet) {
    if (!largest_acked_packet_number_.has_value() ||
        packet.packet_number >= *largest_acked_packet_number_ || !packet.in_flight ||
        packet.declared_lost) {
        return;
    }

    eligible_loss_packets_.insert(tracked_packet(packet));
}

void PacketSpaceRecovery::track_new_loss_candidates(
    std::optional<std::uint64_t> previous_largest_acked, std::uint64_t largest_acked) {
    auto it = previous_largest_acked.has_value()
                  ? sent_packets_.lower_bound(*previous_largest_acked)
                  : sent_packets_.begin();
    for (; it != sent_packets_.end() && it->first < largest_acked; ++it) {
        maybe_track_as_loss_candidate(it->second);
    }
}

void PacketSpaceRecovery::on_packet_sent(const SentPacketRecord &packet) {
    if (const auto existing = sent_packets_.find(packet.packet_number);
        existing != sent_packets_.end()) {
        erase_from_tracked_sets(existing->second);
        sent_packets_.erase(existing);
    }

    auto &tracked = sent_packets_[packet.packet_number];
    tracked = SentPacketRecoveryRecord{
        .packet_number = packet.packet_number,
        .sent_time = packet.sent_time,
        .ack_eliciting = packet.ack_eliciting,
        .in_flight = packet.in_flight,
        .declared_lost = packet.declared_lost,
    };
    if (tracked.ack_eliciting && tracked.in_flight) {
        in_flight_ack_eliciting_packets_.insert(tracked_packet(tracked));
    }
    maybe_track_as_loss_candidate(tracked);
}

void PacketSpaceRecovery::on_packet_declared_lost(std::uint64_t packet_number) {
    const auto packet_it = sent_packets_.find(packet_number);
    if (packet_it == sent_packets_.end()) {
        return;
    }

    erase_from_tracked_sets(packet_it->second);
    packet_it->second.in_flight = false;
    packet_it->second.declared_lost = true;
}

void PacketSpaceRecovery::retire_packet(std::uint64_t packet_number) {
    const auto packet_it = sent_packets_.find(packet_number);
    if (packet_it == sent_packets_.end()) {
        return;
    }

    erase_from_tracked_sets(packet_it->second);
    sent_packets_.erase(packet_it);
}

AckProcessingResult PacketSpaceRecovery::on_ack_received(const AckFrame &ack,
                                                         QuicCoreTimePoint now) {
    AckProcessingResult result;
    const auto previous_largest_acked = largest_acked_packet_number_;
    largest_acked_packet_number_ = previous_largest_acked.has_value()
                                       ? std::max(*previous_largest_acked, ack.largest_acknowledged)
                                       : ack.largest_acknowledged;
    const auto effective_largest_acked = *largest_acked_packet_number_;
    if (!previous_largest_acked.has_value() || effective_largest_acked > *previous_largest_acked) {
        track_new_loss_candidates(previous_largest_acked, effective_largest_acked);
    }

    std::vector<std::uint64_t> acked_packet_numbers;
    const auto ack_ranges = ack_frame_packet_number_ranges(ack);
    if (ack_ranges.has_value()) {
        for (auto range_it = ack_ranges.value().rbegin(); range_it != ack_ranges.value().rend();
             ++range_it) {
            const auto ack_begin = sent_packets_.lower_bound(range_it->smallest);
            const auto ack_end = sent_packets_.upper_bound(range_it->largest);
            for (auto it = ack_begin; it != ack_end; ++it) {
                acked_packet_numbers.push_back(it->first);
                result.acked_packets.push_back(packet_metadata(it->second));
                result.largest_newly_acked_packet = result.acked_packets.back();
                if (it->second.packet_number == ack.largest_acknowledged) {
                    result.largest_acknowledged_was_newly_acked = true;
                }
                if (it->second.ack_eliciting) {
                    result.has_newly_acked_ack_eliciting = true;
                }
            }
        }
    }

    for (const auto packet_number : acked_packet_numbers) {
        retire_packet(packet_number);
    }

    const auto loss_scan_end = sent_packets_.lower_bound(effective_largest_acked);
    for (auto it = sent_packets_.begin(); it != loss_scan_end; ++it) {
        auto &packet = it->second;
        if (packet.declared_lost || !packet.in_flight) {
            continue;
        }

        if (!is_packet_threshold_lost(packet.packet_number, effective_largest_acked) &&
            !is_time_threshold_lost(rtt_state_, packet.sent_time, now)) {
            continue;
        }

        erase_from_tracked_sets(packet);
        packet.declared_lost = true;
        packet.in_flight = false;
        result.lost_packets.push_back(packet_metadata(packet));
    }

    return result;
}

std::optional<std::uint64_t> PacketSpaceRecovery::largest_acked_packet_number() const {
    return largest_acked_packet_number_;
}

std::optional<DeadlineTrackedPacket>
PacketSpaceRecovery::latest_in_flight_ack_eliciting_packet() const {
    if (in_flight_ack_eliciting_packets_.empty()) {
        return std::nullopt;
    }

    return *in_flight_ack_eliciting_packets_.rbegin();
}

std::optional<DeadlineTrackedPacket> PacketSpaceRecovery::earliest_loss_packet() const {
    if (eligible_loss_packets_.empty()) {
        return std::nullopt;
    }

    return *eligible_loss_packets_.begin();
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
