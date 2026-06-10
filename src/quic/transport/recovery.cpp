#include "src/quic/transport/recovery.h"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <limits>
#include <stdexcept>
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

QuicCoreDuration latest_loss_delay(const RecoveryRttState &recovery_rtt_state) {
    const auto base_rtt =
        recovery_rtt_state.latest_rtt.has_value()
            ? std::max(*recovery_rtt_state.latest_rtt, recovery_rtt_state.smoothed_rtt)
            : kInitialRtt;
    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
    // # max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)
    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
    // # To avoid declaring
    // # packets as lost too early, this time threshold MUST be set to at
    // # least the local timer granularity, as indicated by the kGranularity
    // # constant.
    const auto rounded_up_loss_delay = QuicCoreDuration((base_rtt.count() * 9 + 7) / 8);
    return std::max(kGranularity, rounded_up_loss_delay);
}

std::size_t packet_threshold_loss_scan_end(std::uint64_t largest_acked,
                                           std::uint64_t packet_threshold, std::size_t slot_count) {
    if (largest_acked < packet_threshold) {
        return 0;
    }

    return std::min<std::size_t>(static_cast<std::size_t>(largest_acked - packet_threshold + 1),
                                 slot_count);
}

void note_received_ecn(AckEcnCounts &counts, QuicEcnCodepoint ecn) {
    if (ecn == QuicEcnCodepoint::ect0) {
        ++counts.ect0;
        return;
    }
    if (ecn == QuicEcnCodepoint::ect1) {
        ++counts.ect1;
        return;
    }
    if (ecn == QuicEcnCodepoint::ce) {
        ++counts.ecn_ce;
    }
}

[[noreturn]] void fail_bad_optional_access() {
#if defined(__EXCEPTIONS)
    throw std::bad_optional_access();
#else
    __builtin_trap();
#endif
}

[[noreturn]] void fail_out_of_range(const char *message) {
#if defined(__EXCEPTIONS)
    throw std::out_of_range(message);
#else
    static_cast<void>(message);
    __builtin_trap();
#endif
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

bool ReceivedPacketHistory::should_ignore(std::uint64_t packet_number) const {
    return packet_number < least_untracked_packet_number_ || contains(packet_number);
}

void ReceivedPacketHistory::record_received(std::uint64_t packet_number, bool ack_eliciting,
                                            QuicCoreTimePoint received_time, QuicEcnCodepoint ecn,
                                            std::uint64_t ack_eliciting_threshold) {
    const auto note_new_packet_recorded = [&](bool ack_eliciting_out_of_order,
                                              bool ack_eliciting_creates_gap) {
        if (!largest_received_packet_number_.has_value() ||
            packet_number > *largest_received_packet_number_) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
            //# Receivers can discard all ACK Ranges, but they MUST retain the
            //# largest packet number that has been successfully processed, as
            //# that is used to recover packet numbers from subsequent packets;
            //# see Section 17.1.
            largest_received_packet_number_ = packet_number;
            largest_received_packet_record_ = ReceivedPacketRecord{
                .ack_eliciting = ack_eliciting,
                .received_time = received_time,
            };
        }
        trim_old_ack_ranges();

        if (ack_eliciting) {
            ++ack_eliciting_packets_since_last_ack_;
            const auto effective_ack_eliciting_threshold =
                std::max<std::uint64_t>(1, ack_eliciting_threshold);
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.2
            // # A receiver SHOULD send an ACK frame after receiving at least
            // # two ack-eliciting packets.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
            // # In order to assist loss detection at the sender, an endpoint SHOULD
            // # generate and send an ACK frame without delay when it receives an ack-
            // # eliciting packet either:
            // # *  when the received packet has a packet number less than another
            // #    ack-eliciting packet that has been received, or
            // # *  when the packet has a packet number larger than the highest-
            // #    numbered ack-eliciting packet that has been received and there are
            // #    missing packets between that packet and this packet.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
            // # the more out of order the packets are, the more important it is to send
            // # an updated ACK frame quickly, to prevent the peer from declaring a packet
            // # as lost and spuriously retransmitting the frames it contains.
            immediate_ack_requested_ =
                immediate_ack_requested_ || ack_eliciting_out_of_order ||
                ack_eliciting_creates_gap ||
                ack_eliciting_packets_since_last_ack_ >= effective_ack_eliciting_threshold;
            largest_received_ack_eliciting_packet_number_ =
                std::max(largest_received_ack_eliciting_packet_number_.value_or(packet_number),
                         packet_number);
            ack_pending_ = true;
        }
        if (ecn != QuicEcnCodepoint::unavailable) {
            ecn_feedback_accessible_ = true;
        }
        note_received_ecn(ecn_counts_, ecn);
    };

    if (!ranges_.empty()) {
        auto largest_range = std::prev(ranges_.end());
        if (largest_range->second.largest_packet_number !=
                std::numeric_limits<std::uint64_t>::max() &&
            packet_number == largest_range->second.largest_packet_number + 1) {
            largest_range->second.largest_packet_number = packet_number;
            note_new_packet_recorded(/*ack_eliciting_out_of_order=*/false,
                                     /*ack_eliciting_creates_gap=*/false);
            return;
        }
    }

    const bool duplicate = should_ignore(packet_number);
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

    note_new_packet_recorded(ack_eliciting_out_of_order, ack_eliciting_creates_gap);
}

void ReceivedPacketHistory::trim_old_ack_ranges() {
    while (ranges_.size() > kMaxTrackedAckRanges) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
        // # A receiver MUST retain an ACK Range unless it can ensure that it will
        // # not subsequently accept packets with numbers in that range.
        // # Maintaining a minimum packet number that increases as ranges are
        // # discarded is one way to achieve this with minimal state.
        least_untracked_packet_number_ = std::max(
            least_untracked_packet_number_, ranges_.begin()->second.largest_packet_number + 1);
        ranges_.erase(ranges_.begin());
    }
}

bool ReceivedPacketHistory::has_ack_to_send() const {
    return ack_pending_;
}

bool ReceivedPacketHistory::requests_immediate_ack() const {
    return immediate_ack_requested_;
}

std::optional<OutboundAckHeader> ReceivedPacketHistory::build_outbound_ack_header(
    std::uint64_t ack_delay_exponent, QuicCoreTimePoint now, bool allow_non_pending) const {
    if (ranges_.empty()) {
        return std::nullopt;
    }
    if (!ack_pending_ && !allow_non_pending) {
        return std::nullopt;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
    // # A receiver SHOULD include an ACK Range containing the largest
    // # received packet number in every ACK frame.
    const auto largest_range = ranges_.rbegin();
    const auto largest_received_packet_record =
        largest_received_packet_record_.value_or(ReceivedPacketRecord{
            .received_time = now,
        });
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.5
    // # An endpoint MUST NOT include delays that it does not control when
    // # populating the ACK Delay field in an ACK frame.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.5
    // # When the measured acknowledgment delay is larger than its
    // # max_ack_delay, an endpoint SHOULD report the measured delay.
    const auto ack_delay = std::chrono::duration_cast<std::chrono::microseconds>(std::max(
        now - largest_received_packet_record.received_time, QuicCoreClock::duration::zero()));
    OutboundAckHeader header{
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
        // # ACK frames SHOULD always acknowledge the most recently received
        // # packets, and the
        .largest_acknowledged = largest_range->second.largest_packet_number,
        .ack_delay = encode_ack_delay(ack_delay, ack_delay_exponent),
        .first_ack_range = largest_range->second.largest_packet_number - largest_range->first,
        .additional_range_count = 0,
        .additional_ranges = {},
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.4.1
        // # Even if an endpoint does not set an ECT field in packets it sends,
        // # the endpoint MUST provide feedback about ECN markings it receives,
        // # if these are accessible.
        .ecn_counts =
            ecn_feedback_accessible_ ? std::optional<AckEcnCounts>{ecn_counts_} : std::nullopt,
    };
    header.additional_ranges.reserve(ranges_.size() - 1);

    auto previous_smallest = largest_range->first;
    for (auto it = std::next(ranges_.rbegin()); it != ranges_.rend(); ++it) {
        const auto range_start = it->first;
        const auto range_end = it->second.largest_packet_number;
        header.additional_ranges.push_back(AckRange{
            .gap = previous_smallest - range_end - 2,
            .range_length = range_end - range_start,
        });
        previous_smallest = range_start;
    }
    header.additional_range_count = header.additional_ranges.size();

    return header;
}

std::optional<AckFrame> ReceivedPacketHistory::build_ack_frame(std::uint64_t ack_delay_exponent,
                                                               QuicCoreTimePoint now,
                                                               bool allow_non_pending) const {
    const auto header = build_outbound_ack_header(ack_delay_exponent, now, allow_non_pending);
    if (!header.has_value()) {
        return std::nullopt;
    }

    AckFrame ack{
        .largest_acknowledged = header->largest_acknowledged,
        .ack_delay = header->ack_delay,
        .first_ack_range = header->first_ack_range,
        .additional_ranges = {},
        .ecn_counts = header->ecn_counts,
    };
    ack.additional_ranges.reserve(header->additional_ranges.size());
    for_each_additional_ack_range_descending(
        *header, [&](AckRange range) { ack.additional_ranges.push_back(range); });

    return ack;
}

void ReceivedPacketHistory::on_ack_sent() {
    ack_pending_ = false;
    immediate_ack_requested_ = false;
    ack_eliciting_packets_since_last_ack_ = 0;
}

void ReceivedPacketHistory::retire_acknowledged_ranges_up_to(std::uint64_t largest_acknowledged) {
    const auto retired_floor = largest_acknowledged == std::numeric_limits<std::uint64_t>::max()
                                   ? std::numeric_limits<std::uint64_t>::max()
                                   : largest_acknowledged + 1;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
    // # After receiving acknowledgments for an ACK frame, the receiver SHOULD
    // # stop tracking those acknowledged ACK Ranges.
    least_untracked_packet_number_ = std::max(least_untracked_packet_number_, retired_floor);

    for (auto it = ranges_.begin(); it != ranges_.end();) {
        if (it->second.largest_packet_number <= largest_acknowledged) {
            it = ranges_.erase(it);
            continue;
        }
        if (it->first <= largest_acknowledged) {
            auto range = it->second;
            ranges_.erase(it);
            ranges_.emplace(retired_floor, range);
            break;
        }
        break;
    }
}

PacketSpaceRecovery::PacketSpaceRecovery() : sent_packets_{this} {
}

PacketSpaceRecovery::PacketSpaceRecovery(const PacketSpaceRecovery &other)
    : slots_(other.slots_), packet_record_pool_(), live_links_(other.live_links_),
      live_slot_words_(other.live_slot_words_),
      latest_in_flight_ack_eliciting_packet_(other.latest_in_flight_ack_eliciting_packet_),
      eligible_loss_packets_(other.eligible_loss_packets_),
      largest_acked_packet_number_(other.largest_acked_packet_number_),
      first_slot_packet_number_(other.first_slot_packet_number_),
      first_live_slot_(other.first_live_slot_), last_live_slot_(other.last_live_slot_),
      live_sent_times_monotonic_(other.live_sent_times_monotonic_),
      next_loss_candidate_slot_(other.next_loss_candidate_slot_),
      next_packet_threshold_loss_slot_(other.next_packet_threshold_loss_slot_),
      packet_reordering_threshold_(other.packet_reordering_threshold_),
      time_reordering_threshold_(other.time_reordering_threshold_),
      compatibility_version_(other.compatibility_version_), rtt_state_(other.rtt_state_),
      sent_packets_{this} {
}

PacketSpaceRecovery::PacketSpaceRecovery(PacketSpaceRecovery &&other) noexcept
    : slots_(std::move(other.slots_)), packet_record_pool_(std::move(other.packet_record_pool_)),
      live_links_(std::move(other.live_links_)),
      live_slot_words_(std::move(other.live_slot_words_)),
      latest_in_flight_ack_eliciting_packet_(other.latest_in_flight_ack_eliciting_packet_),
      eligible_loss_packets_(std::move(other.eligible_loss_packets_)),
      largest_acked_packet_number_(other.largest_acked_packet_number_),
      first_slot_packet_number_(other.first_slot_packet_number_),
      first_live_slot_(other.first_live_slot_), last_live_slot_(other.last_live_slot_),
      live_sent_times_monotonic_(other.live_sent_times_monotonic_),
      next_loss_candidate_slot_(other.next_loss_candidate_slot_),
      next_packet_threshold_loss_slot_(other.next_packet_threshold_loss_slot_),
      packet_reordering_threshold_(other.packet_reordering_threshold_),
      time_reordering_threshold_(other.time_reordering_threshold_),
      compatibility_version_(other.compatibility_version_), rtt_state_(other.rtt_state_),
      sent_packets_{this} {
    other.packet_view_scratch_.reset();
}

PacketSpaceRecovery &PacketSpaceRecovery::operator=(const PacketSpaceRecovery &other) {
    if (this == &other) {
        return *this;
    }

    slots_ = other.slots_;
    packet_record_pool_.clear();
    live_links_ = other.live_links_;
    live_slot_words_ = other.live_slot_words_;
    latest_in_flight_ack_eliciting_packet_ = other.latest_in_flight_ack_eliciting_packet_;
    eligible_loss_packets_ = other.eligible_loss_packets_;
    largest_acked_packet_number_ = other.largest_acked_packet_number_;
    first_slot_packet_number_ = other.first_slot_packet_number_;
    first_live_slot_ = other.first_live_slot_;
    last_live_slot_ = other.last_live_slot_;
    live_sent_times_monotonic_ = other.live_sent_times_monotonic_;
    next_loss_candidate_slot_ = other.next_loss_candidate_slot_;
    next_packet_threshold_loss_slot_ = other.next_packet_threshold_loss_slot_;
    packet_reordering_threshold_ = other.packet_reordering_threshold_;
    time_reordering_threshold_ = other.time_reordering_threshold_;
    compatibility_version_ = other.compatibility_version_;
    rtt_state_ = other.rtt_state_;
    sent_packets_.owner = this;
    return *this;
}

PacketSpaceRecovery &PacketSpaceRecovery::operator=(PacketSpaceRecovery &&other) noexcept {
    if (this == &other) {
        return *this;
    }

    slots_ = std::move(other.slots_);
    packet_record_pool_ = std::move(other.packet_record_pool_);
    live_links_ = std::move(other.live_links_);
    live_slot_words_ = std::move(other.live_slot_words_);
    latest_in_flight_ack_eliciting_packet_ = other.latest_in_flight_ack_eliciting_packet_;
    eligible_loss_packets_ = std::move(other.eligible_loss_packets_);
    largest_acked_packet_number_ = other.largest_acked_packet_number_;
    first_slot_packet_number_ = other.first_slot_packet_number_;
    first_live_slot_ = other.first_live_slot_;
    last_live_slot_ = other.last_live_slot_;
    live_sent_times_monotonic_ = other.live_sent_times_monotonic_;
    next_loss_candidate_slot_ = other.next_loss_candidate_slot_;
    next_packet_threshold_loss_slot_ = other.next_packet_threshold_loss_slot_;
    packet_reordering_threshold_ = other.packet_reordering_threshold_;
    time_reordering_threshold_ = other.time_reordering_threshold_;
    compatibility_version_ = other.compatibility_version_;
    rtt_state_ = other.rtt_state_;
    sent_packets_.owner = this;
    return *this;
}

PacketSpaceRecovery::SentPacketLedgerSlot::SentPacketLedgerSlot(const SentPacketLedgerSlot &other)
    : state(other.state), packet_number(other.packet_number),
      packet(other.packet ? std::make_unique<SentPacketRecord>(*other.packet) : nullptr),
      simple_stream_packet(other.simple_stream_packet), acknowledged(other.acknowledged) {
}

PacketSpaceRecovery::SentPacketLedgerSlot &
PacketSpaceRecovery::SentPacketLedgerSlot::operator=(const SentPacketLedgerSlot &other) {
    if (this == &other) {
        return *this;
    }

    state = other.state;
    packet_number = other.packet_number;
    packet = other.packet ? std::make_unique<SentPacketRecord>(*other.packet) : nullptr;
    simple_stream_packet = other.simple_stream_packet;
    acknowledged = other.acknowledged;
    return *this;
}

RecoveryPacketMetadata resolved_packet_metadata(const PacketSpaceRecovery *recovery,
                                                RecoveryPacketHandle handle) {
    RecoveryPacketMetadata metadata{
        .packet_number = handle.packet_number,
    };
    if (recovery == nullptr) {
        return metadata;
    }

    const auto *packet_record = recovery->packet_for_handle(handle);
    if (packet_record == nullptr) {
        return metadata;
    }

    metadata.sent_time = packet_record->sent_time;
    metadata.ack_eliciting = packet_record->ack_eliciting;
    metadata.in_flight = packet_record->in_flight;
    metadata.declared_lost = packet_record->declared_lost;
    return metadata;
}

RecoveryPacketMetadata packet_metadata(const SentPacketRecord &packet_record) {
    return RecoveryPacketMetadata{
        .packet_number = packet_record.packet_number,
        .sent_time = packet_record.sent_time,
        .ack_eliciting = packet_record.ack_eliciting,
        .in_flight = packet_record.in_flight,
        .declared_lost = packet_record.declared_lost,
    };
}

RecoveryPacketMetadata packet_metadata(const SimpleStreamSentPacketRecord &packet_record,
                                       bool declared_lost = false) {
    return RecoveryPacketMetadata{
        .packet_number = packet_record.packet_number,
        .sent_time = packet_record.sent_time,
        .ack_eliciting = true,
        .in_flight = !declared_lost,
        .declared_lost = declared_lost,
    };
}

SentPacketRecord
sent_packet_record_from_simple_stream_packet(const SimpleStreamSentPacketRecord &packet,
                                             bool declared_lost) {
    SentPacketRecord record{
        .packet_number = packet.packet_number,
        .sent_time = packet.sent_time,
        .congestion_send_sequence = packet.congestion_send_sequence,
        .ack_eliciting = true,
        .in_flight = !declared_lost,
        .declared_lost = declared_lost,
        .first_stream_frame_metadata = packet.first_stream_frame_metadata,
        .bytes_in_flight = declared_lost ? 0 : packet.bytes_in_flight,
        .path_id = packet.path_id,
        .ecn = packet.ecn,
        .delivered = packet.delivered,
        .delivered_time = packet.delivered_time,
        .first_sent_time = packet.first_sent_time,
        .tx_in_flight = packet.tx_in_flight,
        .lost = packet.lost,
        .app_limited = packet.app_limited,
        .protection_key_update_generation = packet.protection_key_update_generation,
    };
    record.stream_frame_metadata = packet.stream_frame_metadata;
    return record;
}

RecoveryPacketHandleList::const_iterator::const_iterator(
    std::vector<RecoveryPacketMetadata>::const_iterator it)
    : it_(it) {
}

RecoveryPacketMetadata RecoveryPacketHandleList::const_iterator::operator*() const {
    return *it_;
}

RecoveryPacketHandleList::const_iterator &RecoveryPacketHandleList::const_iterator::operator++() {
    ++it_;
    return *this;
}

RecoveryPacketHandleList::const_iterator RecoveryPacketHandleList::const_iterator::operator++(int) {
    auto copy = *this;
    ++(*this);
    return copy;
}

void RecoveryPacketHandleList::reserve(std::size_t count) {
    handles_.reserve(count);
    metadata_.reserve(count);
}

void RecoveryPacketHandleList::push_back(RecoveryPacketHandle handle,
                                         RecoveryPacketMetadata metadata) {
    handles_.push_back(handle);
    metadata_.push_back(metadata);
}

bool RecoveryPacketHandleList::empty() const {
    return handles_.empty();
}

std::size_t RecoveryPacketHandleList::size() const {
    return handles_.size();
}

RecoveryPacketMetadata RecoveryPacketHandleList::front() const {
    return metadata_.front();
}

RecoveryPacketMetadata RecoveryPacketHandleList::back() const {
    return metadata_.back();
}

std::span<const RecoveryPacketHandle> RecoveryPacketHandleList::handles() const {
    return handles_;
}

RecoveryPacketHandleList::const_iterator RecoveryPacketHandleList::begin() const {
    return const_iterator{metadata_.begin()};
}

RecoveryPacketHandleList::const_iterator RecoveryPacketHandleList::end() const {
    return const_iterator{metadata_.end()};
}

void RecoveryPacketHandleOptional::emplace(RecoveryPacketHandle handle,
                                           RecoveryPacketMetadata metadata) {
    handle_ = handle;
    metadata_ = metadata;
}

bool RecoveryPacketHandleOptional::has_value() const {
    return handle_.has_value();
}

RecoveryPacketMetadata RecoveryPacketHandleOptional::value() const {
    if (!metadata_.has_value()) {
        fail_bad_optional_access();
    }
    return *metadata_;
}

const RecoveryPacketMetadata *RecoveryPacketHandleOptional::operator->() const {
    if (!metadata_.has_value()) {
        fail_bad_optional_access();
    }
    return &*metadata_;
}

void RecoveryPacketHandleSmallList::push_back(RecoveryPacketHandle handle) {
    if (!heap_backed_ && size_ < kInlineCapacity) {
        inline_handles_[size_] = handle;
        ++size_;
        return;
    }

    if (!heap_backed_) {
        heap_handles_.reserve(kInlineCapacity * 2);
        heap_handles_.insert(heap_handles_.end(), inline_handles_.begin(),
                             inline_handles_.begin() + static_cast<std::ptrdiff_t>(size_));
        heap_backed_ = true;
    }

    heap_handles_.push_back(handle);
    size_ = heap_handles_.size();
}

bool RecoveryPacketHandleSmallList::empty() const {
    return size_ == 0;
}

std::size_t RecoveryPacketHandleSmallList::size() const {
    return size_;
}

RecoveryPacketHandle RecoveryPacketHandleSmallList::front() const {
    return data()[0];
}

std::span<const RecoveryPacketHandle> RecoveryPacketHandleSmallList::handles() const {
    return {data(), size_};
}

RecoveryPacketHandleSmallList::iterator RecoveryPacketHandleSmallList::begin() {
    return mutable_data();
}

RecoveryPacketHandleSmallList::iterator RecoveryPacketHandleSmallList::end() {
    return mutable_data() + size_;
}

RecoveryPacketHandleSmallList::const_iterator RecoveryPacketHandleSmallList::begin() const {
    return data();
}

RecoveryPacketHandleSmallList::const_iterator RecoveryPacketHandleSmallList::end() const {
    return data() + size_;
}

RecoveryPacketHandle *RecoveryPacketHandleSmallList::mutable_data() {
    return heap_backed_ ? heap_handles_.data() : inline_handles_.data();
}

const RecoveryPacketHandle *RecoveryPacketHandleSmallList::data() const {
    return heap_backed_ ? heap_handles_.data() : inline_handles_.data();
}

bool PacketSpaceRecovery::SentPacketsView::contains(std::uint64_t packet_number) const {
    return owner != nullptr && owner->outstanding_slot_for_packet_number(packet_number) != nullptr;
}

const SentPacketRecord &
PacketSpaceRecovery::SentPacketsView::at(std::uint64_t packet_number) const {
    if (owner == nullptr) {
        fail_out_of_range("packet recovery view is detached");
    }

    const auto *slot = owner->outstanding_slot_for_packet_number(packet_number);
    if (slot == nullptr) {
        fail_out_of_range("packet number is not tracked");
    }
    if (slot->packet != nullptr) {
        return slot_packet(*slot);
    }
    if (slot->simple_stream_packet.has_value()) {
        owner->packet_view_scratch_ = sent_packet_record_from_simple_stream_packet(
            *slot->simple_stream_packet, slot->state == LedgerSlotState::declared_lost);
        return *owner->packet_view_scratch_;
    }
    fail_out_of_range("packet number has no packet record");
}

std::size_t PacketSpaceRecovery::SentPacketsView::size() const {
    if (owner == nullptr) {
        return 0;
    }

    return static_cast<std::size_t>(std::count_if(
        owner->slots_.begin(), owner->slots_.end(), [](const SentPacketLedgerSlot &slot) {
            return (slot.state == LedgerSlotState::sent ||
                    slot.state == LedgerSlotState::declared_lost) &&
                   !slot.acknowledged && slot_has_packet_record(slot);
        }));
}

DeadlineTrackedPacket PacketSpaceRecovery::tracked_packet(const SentPacketRecord &packet) {
    return DeadlineTrackedPacket{
        .packet_number = packet.packet_number,
        .sent_time = packet.sent_time,
    };
}

SentPacketRecord *PacketSpaceRecovery::slot_packet_or_null(SentPacketLedgerSlot &slot) {
    return slot.packet.get();
}

const SentPacketRecord *PacketSpaceRecovery::slot_packet_or_null(const SentPacketLedgerSlot &slot) {
    return slot.packet.get();
}

SentPacketRecord &PacketSpaceRecovery::slot_packet(SentPacketLedgerSlot &slot) {
    return *slot.packet;
}

const SentPacketRecord &PacketSpaceRecovery::slot_packet(const SentPacketLedgerSlot &slot) {
    return *slot.packet;
}

bool PacketSpaceRecovery::slot_has_packet_record(const SentPacketLedgerSlot &slot) {
    return slot.packet != nullptr || slot.simple_stream_packet.has_value();
}

std::uint64_t PacketSpaceRecovery::slot_packet_number(const SentPacketLedgerSlot &slot) {
    if (slot.simple_stream_packet.has_value()) {
        return slot.simple_stream_packet->packet_number;
    }
    return slot_packet(slot).packet_number;
}

QuicCoreTimePoint PacketSpaceRecovery::slot_sent_time(const SentPacketLedgerSlot &slot) {
    if (slot.simple_stream_packet.has_value()) {
        return slot.simple_stream_packet->sent_time;
    }
    return slot_packet(slot).sent_time;
}

bool PacketSpaceRecovery::slot_ack_eliciting(const SentPacketLedgerSlot &slot) {
    return slot.simple_stream_packet.has_value() || slot_packet(slot).ack_eliciting;
}

bool PacketSpaceRecovery::slot_in_flight(const SentPacketLedgerSlot &slot) {
    if (slot.simple_stream_packet.has_value()) {
        return slot.state == LedgerSlotState::sent;
    }
    return slot_packet(slot).in_flight;
}

bool PacketSpaceRecovery::slot_declared_lost(const SentPacketLedgerSlot &slot) {
    if (slot.simple_stream_packet.has_value()) {
        return slot.state == LedgerSlotState::declared_lost;
    }
    return slot_packet(slot).declared_lost;
}

bool PacketSpaceRecovery::slot_is_pmtu_probe(const SentPacketLedgerSlot &slot) {
    return !slot.simple_stream_packet.has_value() && slot_packet(slot).is_pmtu_probe;
}

DeadlineTrackedPacket PacketSpaceRecovery::tracked_packet(const SentPacketLedgerSlot &slot) {
    return DeadlineTrackedPacket{
        .packet_number = slot_packet_number(slot),
        .sent_time = slot_sent_time(slot),
    };
}

RecoveryPacketHandle PacketSpaceRecovery::packet_handle(const SentPacketLedgerSlot &slot,
                                                        std::size_t slot_index) const {
    return RecoveryPacketHandle{
        .packet_number = slot.packet_number,
        .slot_index = absolute_slot_index(slot_index),
    };
}

void PacketSpaceRecovery::reclaim_retired_packet_storage(SentPacketRecord &packet) {
    std::vector<ByteRange>().swap(packet.crypto_ranges);
    std::vector<ResetStreamFrame>().swap(packet.reset_stream_frames);
    std::vector<StopSendingFrame>().swap(packet.stop_sending_frames);
    packet.max_data_frame.reset();
    std::vector<MaxStreamDataFrame>().swap(packet.max_stream_data_frames);
    std::vector<MaxStreamsFrame>().swap(packet.max_streams_frames);
    std::vector<StreamsBlockedFrame>().swap(packet.streams_blocked_frames);
    packet.data_blocked_frame.reset();
    std::vector<StreamDataBlockedFrame>().swap(packet.stream_data_blocked_frames);
    packet.first_stream_frame_metadata.reset();
    std::vector<StreamFrameSendMetadata>().swap(packet.stream_frame_metadata);
    std::vector<StreamFrameSendFragment>().swap(packet.stream_fragments);
    packet.qlog_packet_snapshot.reset();
    packet.largest_received_packet_number_acked.reset();
}

std::optional<std::size_t>
PacketSpaceRecovery::slot_index_for_packet_number(std::uint64_t packet_number) const {
    if (packet_number < first_slot_packet_number_) {
        return std::nullopt;
    }

    const auto relative = packet_number - first_slot_packet_number_;
    if (relative > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return std::nullopt;
    }
    const auto slot_index = static_cast<std::size_t>(relative);
    if (slot_index >= slots_.size()) {
        return std::nullopt;
    }
    return slot_index;
}

std::optional<std::size_t>
PacketSpaceRecovery::slot_index_for_handle(RecoveryPacketHandle handle) const {
    const auto relative_from_handle = relative_slot_index(handle.slot_index);
    if (relative_from_handle != kInvalidLedgerSlotIndex) {
        const auto &slot = slots_[relative_from_handle];
        if (slot.packet_number == handle.packet_number) {
            return relative_from_handle;
        }
    }

    return slot_index_for_packet_number(handle.packet_number);
}

std::size_t PacketSpaceRecovery::absolute_slot_index(std::size_t relative_slot_index) const {
    return static_cast<std::size_t>(first_slot_packet_number_) + relative_slot_index;
}

std::size_t PacketSpaceRecovery::relative_slot_index(std::size_t absolute_slot_index) const {
    const auto base = static_cast<std::size_t>(first_slot_packet_number_);
    if (absolute_slot_index < base) {
        return kInvalidLedgerSlotIndex;
    }
    const auto relative = absolute_slot_index - base;
    return relative < slots_.size() ? relative : kInvalidLedgerSlotIndex;
}

PacketSpaceRecovery::SentPacketLedgerSlot *
PacketSpaceRecovery::slot_for_handle(RecoveryPacketHandle handle) {
    return const_cast<SentPacketLedgerSlot *>(std::as_const(*this).slot_for_handle(handle));
}

const PacketSpaceRecovery::SentPacketLedgerSlot *
PacketSpaceRecovery::slot_for_handle(RecoveryPacketHandle handle) const {
    const auto relative_from_handle = relative_slot_index(handle.slot_index);
    if (relative_from_handle != kInvalidLedgerSlotIndex) {
        const auto &slot = slots_[relative_from_handle];
        if (slot.packet_number == handle.packet_number) {
            return &slot;
        }
    }

    const auto relative_from_packet = slot_index_for_packet_number(handle.packet_number);
    if (!relative_from_packet.has_value()) {
        return nullptr;
    }
    const auto &slot = slots_[*relative_from_packet];
    return slot.packet_number == handle.packet_number ? &slot : nullptr;
}

void PacketSpaceRecovery::compact_retired_prefix() {
    std::size_t removable = 0;
    while (removable < slots_.size()) {
        const auto &slot = slots_[removable];
        if (slot.state != LedgerSlotState::empty && slot.state != LedgerSlotState::retired) {
            break;
        }
        ++removable;
    }
    if (removable == 0) {
        return;
    }

    slots_.erase(slots_.begin(), slots_.begin() + static_cast<std::ptrdiff_t>(removable));
    first_slot_packet_number_ += static_cast<std::uint64_t>(removable);
    rebuild_auxiliary_indexes(/*release_auxiliary_storage=*/true);
}

void PacketSpaceRecovery::prepend_slots_for_packet_number(std::uint64_t packet_number) {
    if (packet_number >= first_slot_packet_number_) {
        return;
    }

    const auto missing = first_slot_packet_number_ - packet_number;
    if (missing > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        fail_out_of_range("packet number is too far before recovery ledger");
    }

    slots_.insert(slots_.begin(), static_cast<std::size_t>(missing), SentPacketLedgerSlot{});
    first_slot_packet_number_ = packet_number;
    rebuild_auxiliary_indexes(/*release_auxiliary_storage=*/false);
}

std::unique_ptr<SentPacketRecord>
PacketSpaceRecovery::acquire_packet_record(SentPacketRecord &&packet) {
    if (!packet_record_pool_.empty()) {
        auto record = std::move(packet_record_pool_.back());
        packet_record_pool_.pop_back();
        *record = std::move(packet);
        return record;
    }

    return std::make_unique<SentPacketRecord>(std::move(packet));
}

void PacketSpaceRecovery::recycle_packet_record(std::unique_ptr<SentPacketRecord> packet) {
    if (packet == nullptr) {
        return;
    }

    reclaim_retired_packet_storage(*packet);
    if (packet_record_pool_.size() >= kMaxSentPacketRecordPoolSize) {
        return;
    }

    packet_record_pool_.push_back(std::move(packet));
}

SentPacketRecord &PacketSpaceRecovery::materialize_slot_packet(SentPacketLedgerSlot &slot) {
    if (slot.packet == nullptr && slot.simple_stream_packet.has_value()) {
        slot.packet = acquire_packet_record(sent_packet_record_from_simple_stream_packet(
            *slot.simple_stream_packet, slot.state == LedgerSlotState::declared_lost));
        slot.simple_stream_packet.reset();
    }
    return slot_packet(slot);
}

void PacketSpaceRecovery::ensure_live_link_slot(std::size_t slot_index) {
    if (slot_index >= live_links_.size()) {
        live_links_.resize(slot_index + 1);
    }
}

void PacketSpaceRecovery::set_live_link(std::size_t slot_index, LiveSlotLink link) {
    ensure_live_link_slot(slot_index);
    live_links_[slot_index] = link;
}

void PacketSpaceRecovery::set_live_slot_bit(std::size_t slot_index) {
    const auto word_index = slot_index / 64;
    if (word_index >= live_slot_words_.size()) {
        live_slot_words_.resize(word_index + 1);
    }
    live_slot_words_[word_index] |= std::uint64_t{1} << (slot_index % 64);
}

void PacketSpaceRecovery::clear_live_slot_bit(std::size_t slot_index) {
    const auto word_index = slot_index / 64;
    if (word_index < live_slot_words_.size()) {
        live_slot_words_[word_index] &= ~(std::uint64_t{1} << (slot_index % 64));
    }
}

std::size_t PacketSpaceRecovery::previous_live_slot(std::size_t slot_index) const {
    return live_links_[slot_index].prev;
}

std::size_t PacketSpaceRecovery::next_live_slot(std::size_t slot_index) const {
    return live_links_[slot_index].next;
}

void PacketSpaceRecovery::link_live_slot(std::size_t slot_index) {
    ensure_live_link_slot(slot_index);
    set_live_link(slot_index, LiveSlotLink{});
    set_live_slot_bit(slot_index);

    if (last_live_slot_ == kInvalidLedgerSlotIndex) {
        first_live_slot_ = slot_index;
        last_live_slot_ = slot_index;
        return;
    }

    if (last_live_slot_ < slot_index) {
        set_live_link(slot_index, LiveSlotLink{
                                      .prev = last_live_slot_,
                                      .next = kInvalidLedgerSlotIndex,
                                  });
        set_live_link(last_live_slot_, LiveSlotLink{
                                           .prev = previous_live_slot(last_live_slot_),
                                           .next = slot_index,
                                       });
        last_live_slot_ = slot_index;
        return;
    }

    if (slot_index < first_live_slot_) {
        set_live_link(slot_index, LiveSlotLink{
                                      .prev = kInvalidLedgerSlotIndex,
                                      .next = first_live_slot_,
                                  });
        set_live_link(first_live_slot_, LiveSlotLink{
                                            .prev = slot_index,
                                            .next = next_live_slot(first_live_slot_),
                                        });
        first_live_slot_ = slot_index;
        return;
    }

    auto next_slot = first_live_slot_;
    while (next_slot != kInvalidLedgerSlotIndex && next_slot < slot_index) {
        next_slot = next_live_slot(next_slot);
    }
    if (next_slot == kInvalidLedgerSlotIndex) {
        set_live_link(slot_index, LiveSlotLink{
                                      .prev = last_live_slot_,
                                      .next = kInvalidLedgerSlotIndex,
                                  });
        set_live_link(last_live_slot_, LiveSlotLink{
                                           .prev = previous_live_slot(last_live_slot_),
                                           .next = slot_index,
                                       });
        last_live_slot_ = slot_index;
        return;
    }

    const auto previous_slot = previous_live_slot(next_slot);
    set_live_link(slot_index, LiveSlotLink{
                                  .prev = previous_slot,
                                  .next = next_slot,
                              });
    set_live_link(previous_slot, LiveSlotLink{
                                     .prev = previous_live_slot(previous_slot),
                                     .next = slot_index,
                                 });
    set_live_link(next_slot, LiveSlotLink{
                                 .prev = slot_index,
                                 .next = next_live_slot(next_slot),
                             });
}

void PacketSpaceRecovery::unlink_live_slot(std::size_t slot_index) {
    const auto link = live_links_[slot_index];
    if (link.prev != kInvalidLedgerSlotIndex) {
        live_links_[link.prev].next = link.next;
    } else {
        first_live_slot_ = link.next;
    }
    if (link.next != kInvalidLedgerSlotIndex) {
        live_links_[link.next].prev = link.prev;
    } else {
        last_live_slot_ = link.prev;
    }
    live_links_[slot_index] = LiveSlotLink{};
    clear_live_slot_bit(slot_index);
}

void PacketSpaceRecovery::note_live_slot_sent_time_order(std::size_t slot_index) {
    if (!live_sent_times_monotonic_) {
        return;
    }

    const auto sent_time = slot_sent_time(slots_[slot_index]);
    const auto previous = previous_live_slot(slot_index);
    if (previous != kInvalidLedgerSlotIndex && slot_sent_time(slots_[previous]) > sent_time) {
        live_sent_times_monotonic_ = false;
    }

    const auto next = next_live_slot(slot_index);
    if (next != kInvalidLedgerSlotIndex && sent_time > slot_sent_time(slots_[next])) {
        live_sent_times_monotonic_ = false;
    }
}

void PacketSpaceRecovery::note_live_packet_removed_from_tracking(std::size_t slot_index) {
    const auto &slot = slots_[slot_index];
    if (!slot_has_packet_record(slot)) {
        return;
    }

    const auto tracked = tracked_packet(slot);
    const bool was_latest_in_flight_ack_eliciting =
        latest_in_flight_ack_eliciting_packet_.has_value() &&
        *latest_in_flight_ack_eliciting_packet_ == tracked;
    if (!was_latest_in_flight_ack_eliciting) {
        eligible_loss_packets_.erase(tracked);
        return;
    }

    eligible_loss_packets_.erase(tracked);
    latest_in_flight_ack_eliciting_packet_.reset();
    if (!live_sent_times_monotonic_) {
        return;
    }

    auto previous = previous_live_slot(slot_index);
    while (previous != kInvalidLedgerSlotIndex) {
        const auto &previous_slot = slots_[previous];
        if (previous_slot.state == LedgerSlotState::sent) {
            maybe_track_latest_in_flight_ack_eliciting_packet(previous_slot);
            if (latest_in_flight_ack_eliciting_packet_.has_value()) {
                return;
            }
        }
        previous = previous_live_slot(previous);
    }
}

std::size_t PacketSpaceRecovery::newest_live_slot_at_or_below(std::uint64_t packet_number) const {
    if (packet_number < first_slot_packet_number_) {
        return kInvalidLedgerSlotIndex;
    }
    const auto relative = packet_number - first_slot_packet_number_;
    const auto upper_bound =
        relative > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())
            ? std::numeric_limits<std::size_t>::max()
            : static_cast<std::size_t>(relative);
    if (upper_bound >= slots_.size()) {
        return last_live_slot_;
    }

    auto word_index = upper_bound / 64;
    if (word_index >= live_slot_words_.size()) {
        word_index = live_slot_words_.size();
    } else {
        const auto bit_limit = upper_bound % 64;
        const auto word = live_slot_words_[word_index] & (~std::uint64_t{0} >> (63 - bit_limit));
        if (word != 0) {
            return word_index * 64 +
                   static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::digits - 1 -
                                            std::countl_zero(word));
        }
    }

    while (word_index != 0) {
        --word_index;
        const auto word = live_slot_words_[word_index];
        if (word != 0) {
            return word_index * 64 +
                   static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::digits - 1 -
                                            std::countl_zero(word));
        }
    }

    return kInvalidLedgerSlotIndex;
}

PacketSpaceRecovery::SentPacketLedgerSlot *
PacketSpaceRecovery::slot_for_packet_number(std::uint64_t packet_number) {
    return const_cast<SentPacketLedgerSlot *>(
        std::as_const(*this).slot_for_packet_number(packet_number));
}

const PacketSpaceRecovery::SentPacketLedgerSlot *
PacketSpaceRecovery::slot_for_packet_number(std::uint64_t packet_number) const {
    const auto slot_index = slot_index_for_packet_number(packet_number);
    if (!slot_index.has_value()) {
        return nullptr;
    }

    const auto &slot = slots_[*slot_index];
    if ((slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost) ||
        slot.packet_number != packet_number || !slot_has_packet_record(slot)) {
        return nullptr;
    }

    return &slot;
}

PacketSpaceRecovery::SentPacketLedgerSlot *
PacketSpaceRecovery::outstanding_slot_for_packet_number(std::uint64_t packet_number) {
    return const_cast<SentPacketLedgerSlot *>(
        std::as_const(*this).outstanding_slot_for_packet_number(packet_number));
}

const PacketSpaceRecovery::SentPacketLedgerSlot *
PacketSpaceRecovery::outstanding_slot_for_packet_number(std::uint64_t packet_number) const {
    const auto *slot = slot_for_packet_number(packet_number);
    if (slot == nullptr || slot->acknowledged) {
        return nullptr;
    }
    return slot;
}

const PacketSpaceRecovery::SentPacketLedgerSlot *
PacketSpaceRecovery::slot_for_tracked_packet(const DeadlineTrackedPacket &packet) const {
    const auto *slot = slot_for_packet_number(packet.packet_number);
    if (slot == nullptr) {
        return nullptr;
    }
    if (slot->acknowledged) {
        return nullptr;
    }
    if (slot_sent_time(*slot) != packet.sent_time) {
        return nullptr;
    }

    return slot;
}

bool PacketSpaceRecovery::is_valid_in_flight_ack_eliciting_tracked_packet(
    const DeadlineTrackedPacket &packet) const {
    const auto *slot = slot_for_tracked_packet(packet);
    if (slot == nullptr) {
        return false;
    }
    if (slot->state != LedgerSlotState::sent) {
        return false;
    }
    if (!slot_ack_eliciting(*slot)) {
        return false;
    }
    if (!slot_in_flight(*slot)) {
        return false;
    }
    return !slot_declared_lost(*slot);
}

bool PacketSpaceRecovery::is_valid_eligible_loss_tracked_packet(
    const DeadlineTrackedPacket &packet) const {
    const auto *slot = slot_for_tracked_packet(packet);
    if (slot == nullptr) {
        return false;
    }
    if (slot->state != LedgerSlotState::sent) {
        return false;
    }
    if (!slot_in_flight(*slot)) {
        return false;
    }
    return !slot_declared_lost(*slot);
}

void PacketSpaceRecovery::maybe_track_latest_in_flight_ack_eliciting_packet(
    const SentPacketRecord &packet) const {
    if (!packet.ack_eliciting || !packet.in_flight || packet.declared_lost) {
        return;
    }

    const auto tracked = tracked_packet(packet);
    if (!latest_in_flight_ack_eliciting_packet_.has_value() ||
        DeadlineTrackedPacketLess{}(*latest_in_flight_ack_eliciting_packet_, tracked)) {
        latest_in_flight_ack_eliciting_packet_ = tracked;
    }
}

void PacketSpaceRecovery::maybe_track_latest_in_flight_ack_eliciting_packet(
    const SentPacketLedgerSlot &slot) const {
    if (!slot_ack_eliciting(slot) || !slot_in_flight(slot) || slot_declared_lost(slot)) {
        return;
    }

    const auto tracked = tracked_packet(slot);
    if (!latest_in_flight_ack_eliciting_packet_.has_value() ||
        DeadlineTrackedPacketLess{}(*latest_in_flight_ack_eliciting_packet_, tracked)) {
        latest_in_flight_ack_eliciting_packet_ = tracked;
    }
}

void PacketSpaceRecovery::refresh_latest_in_flight_ack_eliciting_packet() const {
    if (latest_in_flight_ack_eliciting_packet_.has_value() &&
        is_valid_in_flight_ack_eliciting_tracked_packet(*latest_in_flight_ack_eliciting_packet_)) {
        return;
    }

    latest_in_flight_ack_eliciting_packet_.reset();
    for (auto slot_index = first_live_slot_; slot_index != kInvalidLedgerSlotIndex;
         slot_index = next_live_slot(slot_index)) {
        const auto &slot = slots_[slot_index];
        maybe_track_latest_in_flight_ack_eliciting_packet(slot);
    }
}

void PacketSpaceRecovery::prune_stale_eligible_loss_packets() const {
    while (!eligible_loss_packets_.empty()) {
        const auto it = eligible_loss_packets_.begin();
        if (is_valid_eligible_loss_tracked_packet(*it)) {
            break;
        }

        eligible_loss_packets_.erase(it);
    }
}

void PacketSpaceRecovery::erase_from_tracked_sets(const SentPacketRecord &packet) {
    const auto tracked = tracked_packet(packet);
    if (latest_in_flight_ack_eliciting_packet_.has_value() &&
        *latest_in_flight_ack_eliciting_packet_ == tracked) {
        latest_in_flight_ack_eliciting_packet_.reset();
    }
    eligible_loss_packets_.erase(tracked);
}

void PacketSpaceRecovery::erase_from_tracked_sets(const SentPacketLedgerSlot &slot) {
    const auto tracked = tracked_packet(slot);
    if (latest_in_flight_ack_eliciting_packet_.has_value() &&
        *latest_in_flight_ack_eliciting_packet_ == tracked) {
        latest_in_flight_ack_eliciting_packet_.reset();
    }
    eligible_loss_packets_.erase(tracked);
}

void PacketSpaceRecovery::maybe_track_as_loss_candidate(const SentPacketRecord &packet) {
    if (!largest_acked_packet_number_.has_value() ||
        packet.packet_number >= *largest_acked_packet_number_ || !packet.in_flight ||
        packet.declared_lost) {
        return;
    }

    eligible_loss_packets_.insert(tracked_packet(packet));
}

void PacketSpaceRecovery::maybe_track_as_loss_candidate(const SentPacketLedgerSlot &slot) {
    if (!largest_acked_packet_number_.has_value() ||
        slot_packet_number(slot) >= *largest_acked_packet_number_ || !slot_in_flight(slot) ||
        slot_declared_lost(slot)) {
        return;
    }

    eligible_loss_packets_.insert(tracked_packet(slot));
}

void PacketSpaceRecovery::track_new_loss_candidates(
    std::optional<std::uint64_t> previous_largest_acked, std::uint64_t largest_acked) {
    static_cast<void>(previous_largest_acked);
    if (slots_.empty() || next_loss_candidate_slot_ >= slots_.size()) {
        return;
    }

    const auto scan_end =
        largest_acked <= first_slot_packet_number_
            ? std::size_t{0}
            : std::min<std::size_t>(
                  static_cast<std::size_t>(largest_acked - first_slot_packet_number_),
                  slots_.size());
    for (std::size_t slot_index = next_loss_candidate_slot_; slot_index < scan_end; ++slot_index) {
        const auto &slot = slots_[slot_index];
        if ((slot.state == LedgerSlotState::sent || slot.state == LedgerSlotState::declared_lost) &&
            !slot.acknowledged) {
            maybe_track_as_loss_candidate(slot);
        }
    }
    next_loss_candidate_slot_ = std::max(next_loss_candidate_slot_, scan_end);
}

std::size_t PacketSpaceRecovery::ensure_slot_for_packet_number(std::uint64_t packet_number) {
    if (slots_.empty()) {
        first_slot_packet_number_ = packet_number;
    } else if (packet_number < first_slot_packet_number_) {
        prepend_slots_for_packet_number(packet_number);
    }
    const auto slot_index = static_cast<std::size_t>(packet_number - first_slot_packet_number_);
    if (slot_index >= slots_.size()) {
        slots_.resize(slot_index + 1);
    }
    return slot_index;
}

std::optional<RecoveryPacketHandle>
PacketSpaceRecovery::handle_for_packet_number(std::uint64_t packet_number) const {
    const auto *slot = slot_for_packet_number(packet_number);
    if (slot == nullptr) {
        return std::nullopt;
    }

    const auto slot_index = slot_index_for_packet_number(packet_number);
    return packet_handle(*slot, slot_index.value_or(0));
}

SentPacketRecord *PacketSpaceRecovery::packet_for_handle(RecoveryPacketHandle handle) {
    return const_cast<SentPacketRecord *>(std::as_const(*this).packet_for_handle(handle));
}

const SentPacketRecord *PacketSpaceRecovery::packet_for_handle(RecoveryPacketHandle handle) const {
    const auto *slot = slot_for_handle(handle);
    if (slot == nullptr) {
        return nullptr;
    }
    if (slot->state != LedgerSlotState::sent && slot->state != LedgerSlotState::declared_lost) {
        return nullptr;
    }
    if (slot->packet != nullptr) {
        return slot_packet_or_null(*slot);
    }
    if (slot->simple_stream_packet.has_value()) {
        packet_view_scratch_ = sent_packet_record_from_simple_stream_packet(
            *slot->simple_stream_packet, slot->state == LedgerSlotState::declared_lost);
        return &*packet_view_scratch_;
    }
    return nullptr;
}

const SimpleStreamSentPacketRecord *
PacketSpaceRecovery::simple_stream_packet_for_handle(RecoveryPacketHandle handle) const {
    const auto *slot = slot_for_handle(handle);
    if (slot == nullptr ||
        (slot->state != LedgerSlotState::sent && slot->state != LedgerSlotState::declared_lost)) {
        return nullptr;
    }
    return slot != nullptr && slot->simple_stream_packet.has_value() ? &*slot->simple_stream_packet
                                                                     : nullptr;
}

std::optional<SimpleStreamSentPacketRecord>
PacketSpaceRecovery::take_simple_stream_packet_if_present(RecoveryPacketHandle handle) {
    const auto slot_index = slot_index_for_handle(handle);
    if (!slot_index.has_value()) {
        return std::nullopt;
    }

    auto &slot = slots_[*slot_index];
    if (slot.packet_number != handle.packet_number || !slot.simple_stream_packet.has_value() ||
        (slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost)) {
        return std::nullopt;
    }

    if (!slot.acknowledged) {
        note_live_packet_removed_from_tracking(*slot_index);
        unlink_live_slot(*slot_index);
    }

    auto packet = std::move(slot.simple_stream_packet);
    slot.simple_stream_packet.reset();
    slot.state = LedgerSlotState::retired;
    slot.acknowledged = true;
    ++compatibility_version_;
    compact_retired_prefix();
    return packet;
}

std::size_t PacketSpaceRecovery::retire_simple_stream_packets_if_present(
    std::span<const RecoveryPacketHandle> handles) {
    if (handles.empty()) {
        return 0;
    }

    std::size_t retired = 0;
    bool mutated = false;
    for (const auto handle : handles) {
        const auto slot_index = slot_index_for_handle(handle);
        if (!slot_index.has_value()) {
            continue;
        }

        auto &slot = slots_[*slot_index];
        if (slot.packet_number != handle.packet_number || !slot.simple_stream_packet.has_value() ||
            (slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost)) {
            continue;
        }

        if (!slot.acknowledged) {
            note_live_packet_removed_from_tracking(*slot_index);
            unlink_live_slot(*slot_index);
        }
        slot.simple_stream_packet.reset();
        slot.state = LedgerSlotState::retired;
        slot.acknowledged = true;
        ++retired;
        mutated = true;
    }

    if (mutated) {
        ++compatibility_version_;
        compact_retired_prefix();
    }
    return retired;
}

SentPacketRecord *PacketSpaceRecovery::find_packet(std::uint64_t packet_number) {
    auto *slot = slot_for_packet_number(packet_number);
    return slot == nullptr ? nullptr : &materialize_slot_packet(*slot);
}

const SentPacketRecord *PacketSpaceRecovery::find_packet(std::uint64_t packet_number) const {
    const auto *slot = slot_for_packet_number(packet_number);
    if (slot == nullptr) {
        return nullptr;
    }
    if (slot->packet != nullptr) {
        return slot_packet_or_null(*slot);
    }
    if (slot->simple_stream_packet.has_value()) {
        packet_view_scratch_ = sent_packet_record_from_simple_stream_packet(
            *slot->simple_stream_packet, slot->state == LedgerSlotState::declared_lost);
        return &*packet_view_scratch_;
    }
    return nullptr;
}

const SentPacketRecord *
PacketSpaceRecovery::find_newly_ackable_packet(std::uint64_t packet_number) const {
    const auto *slot = outstanding_slot_for_packet_number(packet_number);
    if (slot == nullptr || slot->state != LedgerSlotState::sent) {
        return nullptr;
    }
    if (slot->packet != nullptr) {
        return slot_packet_or_null(*slot);
    }
    if (slot->simple_stream_packet.has_value()) {
        packet_view_scratch_ =
            sent_packet_record_from_simple_stream_packet(*slot->simple_stream_packet, false);
        return &*packet_view_scratch_;
    }
    return nullptr;
}

bool PacketSpaceRecovery::ack_ranges_include_newly_ackable_ack_eliciting_packet(
    AckRangeCursor cursor) const {
    while (const auto range = next_ack_range(cursor)) {
        auto current_live_slot = newest_live_slot_at_or_below(range->largest);
        while (current_live_slot != kInvalidLedgerSlotIndex) {
            const auto &slot = slots_[current_live_slot];
            const auto packet_number = slot_packet_number(slot);
            if (packet_number < range->smallest) {
                break;
            }
            if (packet_number <= range->largest && slot.state == LedgerSlotState::sent &&
                !slot.acknowledged && slot_ack_eliciting(slot)) {
                return true;
            }
            current_live_slot = previous_live_slot(current_live_slot);
        }
    }
    return false;
}

std::vector<RecoveryPacketHandle> PacketSpaceRecovery::tracked_packets() const {
    std::vector<RecoveryPacketHandle> packets;
    packets.reserve(tracked_packet_count());
    for (auto slot_index = first_live_slot_; slot_index != kInvalidLedgerSlotIndex;
         slot_index = next_live_slot(slot_index)) {
        const auto &slot = slots_[slot_index];
        packets.push_back(packet_handle(slot, slot_index));
    }
    return packets;
}

std::size_t PacketSpaceRecovery::tracked_packet_count() const {
    std::size_t count = 0;
    for (auto slot_index = first_live_slot_; slot_index != kInvalidLedgerSlotIndex;
         slot_index = next_live_slot(slot_index)) {
        ++count;
    }
    return count;
}

std::optional<RecoveryPacketHandle> PacketSpaceRecovery::oldest_tracked_packet() const {
    if (first_live_slot_ != kInvalidLedgerSlotIndex) {
        const auto &slot = slots_[first_live_slot_];
        return packet_handle(slot, first_live_slot_);
    }
    return std::nullopt;
}

std::optional<RecoveryPacketHandle> PacketSpaceRecovery::newest_tracked_packet() const {
    if (last_live_slot_ != kInvalidLedgerSlotIndex) {
        const auto &slot = slots_[last_live_slot_];
        return packet_handle(slot, last_live_slot_);
    }
    return std::nullopt;
}

std::vector<RecoveryPacketHandle>
PacketSpaceRecovery::collect_time_threshold_losses(QuicCoreTimePoint now) {
    std::vector<RecoveryPacketHandle> lost_packets;
    if (!largest_acked_packet_number_.has_value() || slots_.empty()) {
        return lost_packets;
    }

    const auto loss_scan_end =
        *largest_acked_packet_number_ <= first_slot_packet_number_
            ? std::size_t{0}
            : std::min<std::size_t>(static_cast<std::size_t>(*largest_acked_packet_number_ -
                                                             first_slot_packet_number_),
                                    slots_.size());
    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
    // # Once a later packet within the same packet number space has been
    // # acknowledged, an endpoint SHOULD declare an earlier packet lost if it
    // # was sent a threshold amount of time in the past.
    for (auto slot_index = first_live_slot_;
         slot_index != kInvalidLedgerSlotIndex && slot_index < loss_scan_end;
         slot_index = next_live_slot(slot_index)) {
        const auto &slot = slots_[slot_index];
        if (slot.state != LedgerSlotState::sent || !slot_in_flight(slot)) {
            continue;
        }

        if (!is_time_threshold_lost(slot_sent_time(slot), now)) {
            continue;
        }

        lost_packets.push_back(packet_handle(slot, slot_index));
    }

    return lost_packets;
}

std::vector<RecoveryPacketHandle>
PacketSpaceRecovery::collect_pmtu_probe_timeouts(QuicCoreTimePoint now) const {
    std::vector<RecoveryPacketHandle> timed_out_packets;
    for (auto slot_index = first_live_slot_;
         slot_index != kInvalidLedgerSlotIndex && slot_index < slots_.size();
         slot_index = next_live_slot(slot_index)) {
        const auto &slot = slots_[slot_index];
        if (slot.state != LedgerSlotState::sent || !slot_is_pmtu_probe(slot)) {
            continue;
        }
        if (!coquic::quic::is_time_threshold_lost(rtt_state_, slot_sent_time(slot), now)) {
            continue;
        }

        timed_out_packets.push_back(packet_handle(slot, slot_index));
    }
    return timed_out_packets;
}

void PacketSpaceRecovery::on_packet_sent(const SentPacketRecord &packet) {
    auto packet_copy = packet;
    on_packet_sent(std::move(packet_copy));
}

void PacketSpaceRecovery::on_packet_sent(SentPacketRecord &&packet) {
    const auto slot_index = ensure_slot_for_packet_number(packet.packet_number);
    auto &slot = slots_[slot_index];
    if (slot.state == LedgerSlotState::sent || slot.state == LedgerSlotState::declared_lost) {
        erase_from_tracked_sets(slot);
        if (!slot.acknowledged) {
            unlink_live_slot(slot_index);
        }
        recycle_packet_record(std::move(slot.packet));
        slot.simple_stream_packet.reset();
    }

    slot.state = packet.declared_lost ? LedgerSlotState::declared_lost : LedgerSlotState::sent;
    const bool declared_lost = packet.declared_lost;
    slot.packet_number = packet.packet_number;
    slot.packet = acquire_packet_record(std::move(packet));
    slot.simple_stream_packet.reset();
    auto &stored_packet = slot_packet(slot);
    stored_packet.declared_lost = declared_lost;
    if (slot.state == LedgerSlotState::declared_lost) {
        stored_packet.in_flight = false;
        stored_packet.bytes_in_flight = 0;
    }
    slot.acknowledged = false;
    link_live_slot(slot_index);
    note_live_slot_sent_time_order(slot_index);

    maybe_track_latest_in_flight_ack_eliciting_packet(stored_packet);
    maybe_track_as_loss_candidate(stored_packet);
    ++compatibility_version_;
}

void PacketSpaceRecovery::on_simple_stream_packet_sent(SimpleStreamSentPacketRecord &&packet) {
    const auto next_append_packet_number =
        first_slot_packet_number_ + static_cast<std::uint64_t>(slots_.size());
    const auto append_slot_index = slots_.size();
    if (packet.packet_number == next_append_packet_number) {
        const auto sent_time = packet.sent_time;
        slots_.emplace_back();
        auto &slot = slots_.back();
        slot.state = LedgerSlotState::sent;
        slot.packet_number = packet.packet_number;
        slot.packet.reset();
        slot.simple_stream_packet = std::move(packet);
        slot.acknowledged = false;

        ensure_live_link_slot(append_slot_index);
        live_links_[append_slot_index] = LiveSlotLink{
            .prev = last_live_slot_,
            .next = kInvalidLedgerSlotIndex,
        };
        if (last_live_slot_ == kInvalidLedgerSlotIndex) {
            first_live_slot_ = append_slot_index;
        } else {
            if (live_sent_times_monotonic_ && slot_sent_time(slots_[last_live_slot_]) > sent_time) {
                live_sent_times_monotonic_ = false;
            }
            live_links_[last_live_slot_].next = append_slot_index;
        }
        last_live_slot_ = append_slot_index;
        set_live_slot_bit(append_slot_index);

        const auto tracked = tracked_packet(slot);
        if (!latest_in_flight_ack_eliciting_packet_.has_value() ||
            DeadlineTrackedPacketLess{}(*latest_in_flight_ack_eliciting_packet_, tracked)) {
            latest_in_flight_ack_eliciting_packet_ = tracked;
        }
        if (largest_acked_packet_number_.has_value() &&
            slot.packet_number < *largest_acked_packet_number_) {
            eligible_loss_packets_.insert(tracked);
        }
        ++compatibility_version_;
        return;
    }

    const auto slot_index = ensure_slot_for_packet_number(packet.packet_number);
    auto &slot = slots_[slot_index];
    if (slot.state == LedgerSlotState::sent || slot.state == LedgerSlotState::declared_lost) {
        erase_from_tracked_sets(slot);
        if (!slot.acknowledged) {
            unlink_live_slot(slot_index);
        }
        recycle_packet_record(std::move(slot.packet));
        slot.simple_stream_packet.reset();
    }

    slot.state = LedgerSlotState::sent;
    slot.packet_number = packet.packet_number;
    slot.packet.reset();
    slot.simple_stream_packet = std::move(packet);
    slot.acknowledged = false;
    link_live_slot(slot_index);
    note_live_slot_sent_time_order(slot_index);

    maybe_track_latest_in_flight_ack_eliciting_packet(slot);
    maybe_track_as_loss_candidate(slot);
    ++compatibility_version_;
}

void PacketSpaceRecovery::on_simple_stream_packets_sent(
    std::span<SimpleStreamSentPacketRecord> packets) {
    if (packets.empty()) {
        return;
    }

    const auto first_slot_index = slots_.size();
    const auto next_append_packet_number =
        first_slot_packet_number_ + static_cast<std::uint64_t>(slots_.size());
    if (packets.front().packet_number != next_append_packet_number) {
        for (auto &packet : packets) {
            on_simple_stream_packet_sent(std::move(packet));
        }
        return;
    }

    bool append_only_contiguous = true;
    bool monotonic_sent_time = true;
    for (std::size_t index = 0; index < packets.size(); ++index) {
        append_only_contiguous =
            append_only_contiguous &&
            packets[index].packet_number == packets.front().packet_number + index;
        monotonic_sent_time = monotonic_sent_time && (index == 0 || packets[index - 1].sent_time <=
                                                                        packets[index].sent_time);
    }
    if (!append_only_contiguous) {
        for (auto &packet : packets) {
            on_simple_stream_packet_sent(std::move(packet));
        }
        return;
    }

    const auto previous_last_live_slot = last_live_slot_;
    const auto first_packet_number = packets.front().packet_number;
    const auto first_sent_time = packets.front().sent_time;
    const auto last_sent_time = packets.back().sent_time;
    slots_.resize(slots_.size() + packets.size());
    ensure_live_link_slot(slots_.size() - 1);

    for (std::size_t index = 0; index < packets.size(); ++index) {
        const auto slot_index = first_slot_index + index;
        auto &slot = slots_[slot_index];
        slot.state = LedgerSlotState::sent;
        slot.packet_number = packets[index].packet_number;
        slot.packet.reset();
        slot.simple_stream_packet = std::move(packets[index]);
        slot.acknowledged = false;
        live_links_[slot_index] = LiveSlotLink{
            .prev = index == 0 ? previous_last_live_slot : slot_index - 1,
            .next = index + 1 == packets.size() ? kInvalidLedgerSlotIndex : slot_index + 1,
        };
        set_live_slot_bit(slot_index);
    }

    if (previous_last_live_slot == kInvalidLedgerSlotIndex) {
        first_live_slot_ = first_slot_index;
    } else {
        live_links_[previous_last_live_slot].next = first_slot_index;
        if (live_sent_times_monotonic_ &&
            slot_sent_time(slots_[previous_last_live_slot]) > first_sent_time) {
            live_sent_times_monotonic_ = false;
        }
    }
    if (live_sent_times_monotonic_ && (!monotonic_sent_time || first_sent_time > last_sent_time)) {
        live_sent_times_monotonic_ = false;
    }
    last_live_slot_ = first_slot_index + packets.size() - 1;

    const auto tracked = tracked_packet(slots_[last_live_slot_]);
    if (!latest_in_flight_ack_eliciting_packet_.has_value() ||
        DeadlineTrackedPacketLess{}(*latest_in_flight_ack_eliciting_packet_, tracked)) {
        latest_in_flight_ack_eliciting_packet_ = tracked;
    }

    if (largest_acked_packet_number_.has_value() &&
        first_packet_number < *largest_acked_packet_number_) {
        for (std::size_t index = 0; index < packets.size(); ++index) {
            auto &slot = slots_[first_slot_index + index];
            if (slot.packet_number >= *largest_acked_packet_number_) {
                break;
            }
            eligible_loss_packets_.insert(tracked_packet(slot));
        }
    }
    ++compatibility_version_;
}

void PacketSpaceRecovery::on_packet_declared_lost(std::uint64_t packet_number) {
    auto *slot = slot_for_packet_number(packet_number);
    if (slot == nullptr) {
        return;
    }

    erase_from_tracked_sets(*slot);
    if (slot->packet != nullptr) {
        auto &packet = slot_packet(*slot);
        packet.in_flight = false;
        packet.declared_lost = true;
        packet.bytes_in_flight = 0;
    }
    slot->state = LedgerSlotState::declared_lost;
    ++compatibility_version_;
}

void PacketSpaceRecovery::retire_packet(RecoveryPacketHandle handle) {
    auto current_handle = packet_for_handle(handle) != nullptr
                              ? std::optional{handle}
                              : handle_for_packet_number(handle.packet_number);
    if (!current_handle.has_value()) {
        return;
    }

    const auto slot_index = slot_index_for_handle(*current_handle);
    if (!slot_index.has_value()) {
        return;
    }

    auto &slot = slots_[*slot_index];
    if (!slot.acknowledged) {
        note_live_packet_removed_from_tracking(*slot_index);
        unlink_live_slot(*slot_index);
    }
    if (auto packet = std::move(slot.packet); packet != nullptr) {
        packet->in_flight = false;
        packet->bytes_in_flight = 0;
        recycle_packet_record(std::move(packet));
    }
    slot.simple_stream_packet.reset();
    slot.state = LedgerSlotState::retired;
    slot.acknowledged = true;
    ++compatibility_version_;
    compact_retired_prefix();
}

void PacketSpaceRecovery::retire_packet(std::uint64_t packet_number) {
    const auto handle = handle_for_packet_number(packet_number);
    if (!handle.has_value()) {
        return;
    }
    retire_packet(*handle);
}

bool PacketSpaceRecovery::retire_packet_if_present(RecoveryPacketHandle handle) {
    const auto slot_index = slot_index_for_handle(handle);
    if (!slot_index.has_value()) {
        return false;
    }

    auto &slot = slots_[*slot_index];
    if (slot.packet_number != handle.packet_number || !slot_has_packet_record(slot) ||
        (slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost)) {
        return false;
    }

    if (!slot.acknowledged) {
        note_live_packet_removed_from_tracking(*slot_index);
        unlink_live_slot(*slot_index);
    }

    if (auto packet = std::move(slot.packet); packet != nullptr) {
        packet->in_flight = false;
        packet->bytes_in_flight = 0;
        recycle_packet_record(std::move(packet));
    }
    slot.simple_stream_packet.reset();
    slot.state = LedgerSlotState::retired;
    slot.acknowledged = true;
    ++compatibility_version_;
    compact_retired_prefix();
    return true;
}

std::optional<SentPacketRecord>
PacketSpaceRecovery::take_retired_packet(RecoveryPacketHandle handle) {
    auto current_handle = packet_for_handle(handle) != nullptr
                              ? std::optional{handle}
                              : handle_for_packet_number(handle.packet_number);
    if (!current_handle.has_value()) {
        return std::nullopt;
    }

    const auto slot_index = slot_index_for_handle(*current_handle);
    if (!slot_index.has_value()) {
        return std::nullopt;
    }

    auto &slot = slots_[*slot_index];
    if (!slot.acknowledged) {
        note_live_packet_removed_from_tracking(*slot_index);
        unlink_live_slot(*slot_index);
    }

    auto packet_record = std::move(slot.packet);
    if (packet_record == nullptr && slot.simple_stream_packet.has_value()) {
        packet_record = acquire_packet_record(sent_packet_record_from_simple_stream_packet(
            *slot.simple_stream_packet, slot.state == LedgerSlotState::declared_lost));
    }
    auto packet = std::move(*packet_record);
    slot.packet_number = packet.packet_number;
    recycle_packet_record(std::move(packet_record));
    slot.simple_stream_packet.reset();
    slot.state = LedgerSlotState::retired;
    slot.acknowledged = true;
    ++compatibility_version_;
    compact_retired_prefix();
    return packet;
}

std::optional<SentPacketRecord>
PacketSpaceRecovery::take_retired_packet_if_present(RecoveryPacketHandle handle) {
    const auto slot_index = slot_index_for_handle(handle);
    if (!slot_index.has_value()) {
        return std::nullopt;
    }
    auto &slot = slots_[*slot_index];
    if (slot.packet_number != handle.packet_number || !slot_has_packet_record(slot) ||
        (slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost)) {
        return std::nullopt;
    }

    if (!slot.acknowledged) {
        note_live_packet_removed_from_tracking(*slot_index);
        unlink_live_slot(*slot_index);
    }

    auto packet_record = std::move(slot.packet);
    if (packet_record == nullptr && slot.simple_stream_packet.has_value()) {
        packet_record = acquire_packet_record(sent_packet_record_from_simple_stream_packet(
            *slot.simple_stream_packet, slot.state == LedgerSlotState::declared_lost));
    }
    auto packet = std::move(*packet_record);
    slot.packet_number = packet.packet_number;
    recycle_packet_record(std::move(packet_record));
    slot.simple_stream_packet.reset();
    slot.state = LedgerSlotState::retired;
    slot.acknowledged = true;
    ++compatibility_version_;
    compact_retired_prefix();
    return packet;
}

PacketSpaceRecovery::AckApplyState
PacketSpaceRecovery::begin_ack_received_apply(std::uint64_t largest_acknowledged) {
    AckApplyState state;
    const auto previous_largest_acked = largest_acked_packet_number_;
    largest_acked_packet_number_ = previous_largest_acked.has_value()
                                       ? std::max(*previous_largest_acked, largest_acknowledged)
                                       : largest_acknowledged;
    state.previous_largest_acked = previous_largest_acked;
    state.effective_largest_acked = *largest_acked_packet_number_;
    state.largest_acked_advanced = !previous_largest_acked.has_value() ||
                                   state.effective_largest_acked > *previous_largest_acked;
    state.largest_acknowledged = largest_acknowledged;
    state.current_live_slot = newest_live_slot_at_or_below(largest_acknowledged);
    return state;
}

void PacketSpaceRecovery::apply_ack_range_descending(AckApplyState &state,
                                                     const AckPacketNumberRange &range) {
    auto current_live_slot = state.current_live_slot;
    while (current_live_slot != kInvalidLedgerSlotIndex &&
           slot_packet_number(slots_[current_live_slot]) > range.largest) {
        current_live_slot = previous_live_slot(current_live_slot);
    }

    while (current_live_slot != kInvalidLedgerSlotIndex) {
        const auto slot_index = current_live_slot;
        auto &slot = slots_[slot_index];
        const auto previous = previous_live_slot(slot_index);
        const auto handle = packet_handle(slot, slot_index);
        const auto packet_number = slot_packet_number(slot);
        const auto sent_time = slot_sent_time(slot);

        if (packet_number < range.smallest) {
            break;
        }
        if (packet_number > range.largest) {
            current_live_slot = previous;
            continue;
        }

        if (slot.state == LedgerSlotState::sent) {
            state.result.acked_packets.push_back(handle);
            //= https://www.rfc-editor.org/rfc/rfc9002#section-5.1
            // # To avoid generating multiple RTT samples for a single packet, an ACK
            // # frame SHOULD NOT be used to update RTT estimates if it does not newly
            // # acknowledge the largest acknowledged packet.
            if (!state.result.largest_newly_acked_packet.has_value()) {
                state.result.largest_newly_acked_packet = AckApplyLargestNewlyAckedPacket{
                    .handle = handle,
                    .packet_number = packet_number,
                    .sent_time = sent_time,
                };
            }
            if (packet_number == state.largest_acknowledged) {
                state.result.largest_acknowledged_was_newly_acked = true;
            }
            //= https://www.rfc-editor.org/rfc/rfc9002#section-5.1
            // # An RTT sample MUST NOT be generated on receiving an ACK frame that
            // # does not newly acknowledge at least one ack-eliciting packet.
            if (slot_ack_eliciting(slot)) {
                state.result.has_newly_acked_ack_eliciting = true;
            }

            note_live_packet_removed_from_tracking(slot_index);
            unlink_live_slot(slot_index);
            slot.acknowledged = true;
            state.mutated = true;
        } else if (slot.state == LedgerSlotState::declared_lost) {
            state.result.late_acked_packets.push_back(handle);
            maybe_adapt_reordering_thresholds_from_spurious_loss(materialize_slot_packet(slot),
                                                                 state.now);
            note_live_packet_removed_from_tracking(slot_index);
            unlink_live_slot(slot_index);
            slot.acknowledged = true;
            state.mutated = true;
        }

        current_live_slot = previous;
    }
    state.current_live_slot = current_live_slot;
}

AckApplyResult PacketSpaceRecovery::finish_ack_received_apply(AckApplyState &state,
                                                              QuicCoreTimePoint now) {
    if (state.result.acked_packets.size() > 1) {
        std::reverse(state.result.acked_packets.begin(), state.result.acked_packets.end());
    }
    if (state.result.late_acked_packets.size() > 1) {
        std::reverse(state.result.late_acked_packets.begin(),
                     state.result.late_acked_packets.end());
    }

    if (slots_.empty()) {
        return std::move(state.result);
    }

    if (state.largest_acked_advanced) {
        track_new_loss_candidates(state.previous_largest_acked, state.effective_largest_acked);
    }

    const auto relative_effective_largest_acked =
        state.effective_largest_acked < first_slot_packet_number_
            ? std::uint64_t{0}
            : state.effective_largest_acked - first_slot_packet_number_;
    const auto packet_threshold_scan_end = packet_threshold_loss_scan_end(
        relative_effective_largest_acked, packet_reordering_threshold_, slots_.size());
    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.1
    // # In order to remain similar to TCP,
    // # implementations SHOULD NOT use a packet threshold less than 3;
    for (std::size_t slot_index = next_packet_threshold_loss_slot_;
         slot_index < packet_threshold_scan_end; ++slot_index) {
        auto &slot = slots_[slot_index];
        if (slot.state != LedgerSlotState::sent || slot.acknowledged) {
            continue;
        }
        if (!slot_in_flight(slot)) {
            continue;
        }
        if (!is_packet_threshold_lost(slot_packet_number(slot), state.effective_largest_acked)) {
            continue;
        }

        // Keep the live packet metadata unchanged until connection-level loss handling consumes it.
        note_packet_threshold_loss(materialize_slot_packet(slot), state.effective_largest_acked);
        slot.state = LedgerSlotState::declared_lost;
        state.result.lost_packets.push_back(packet_handle(slot, slot_index));
        state.mutated = true;
    }
    next_packet_threshold_loss_slot_ =
        std::max(next_packet_threshold_loss_slot_, packet_threshold_scan_end);

    std::vector<std::size_t> time_threshold_loss_slots;
    while (!eligible_loss_packets_.empty()) {
        prune_stale_eligible_loss_packets();
        if (eligible_loss_packets_.empty()) {
            break;
        }

        const auto tracked = *eligible_loss_packets_.begin();
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
        // # If packets sent prior to the largest acknowledged packet cannot yet
        // # be declared lost, then a timer SHOULD be set for the remaining time.
        if (!is_time_threshold_lost(tracked.sent_time, now)) {
            break;
        }

        eligible_loss_packets_.erase(eligible_loss_packets_.begin());
        // `prune_stale_eligible_loss_packets()` guarantees the remaining front entry still
        // resolves to a live sent in-flight slot with matching packet metadata.
        const auto slot_index = slot_index_for_packet_number(tracked.packet_number);
        if (slot_index.has_value()) {
            time_threshold_loss_slots.push_back(*slot_index);
        }
    }

    if (time_threshold_loss_slots.size() > 1) {
        std::sort(time_threshold_loss_slots.begin(), time_threshold_loss_slots.end());
    }
    for (const auto slot_index : time_threshold_loss_slots) {
        auto &slot = slots_[slot_index];
        // Keep the live packet metadata unchanged until connection-level loss handling consumes it.
        note_time_threshold_loss(materialize_slot_packet(slot), now);
        slot.state = LedgerSlotState::declared_lost;
        state.result.lost_packets.push_back(packet_handle(slot, slot_index));
        state.mutated = true;
    }

    if (state.mutated) {
        ++compatibility_version_;
    }

    return std::move(state.result);
}

AckApplyResult PacketSpaceRecovery::apply_ack_received_descending(
    std::span<const AckPacketNumberRange> ack_ranges_descending, std::uint64_t largest_acknowledged,
    QuicCoreTimePoint now) {
    auto state = begin_ack_received_apply(largest_acknowledged);
    state.now = now;
    for (const auto &range : ack_ranges_descending) {
        apply_ack_range_descending(state, range);
    }
    return finish_ack_received_apply(state, now);
}

AckApplyResult PacketSpaceRecovery::apply_ack_received(AckRangeCursor cursor,
                                                       std::uint64_t largest_acknowledged,
                                                       QuicCoreTimePoint now) {
    auto state = begin_ack_received_apply(largest_acknowledged);
    state.now = now;

    if (cursor.first_range_pending) {
        cursor.first_range_pending = false;
        apply_ack_range_descending(state, AckPacketNumberRange{
                                              .smallest = cursor.previous_smallest,
                                              .largest = cursor.largest_acknowledged,
                                          });
    }

    if ((cursor.uses_encoded_additional_ranges &&
         cursor.next_additional_index >= cursor.additional_range_count) ||
        (!cursor.uses_encoded_additional_ranges &&
         cursor.next_additional_index >= cursor.additional_ranges.size())) {
        return finish_ack_received_apply(state, now);
    }

    while (const auto range = next_ack_range(cursor)) {
        apply_ack_range_descending(state, *range);
    }
    return finish_ack_received_apply(state, now);
}

AckProcessingResult
PacketSpaceRecovery::ack_processing_result_from_apply(const AckApplyResult &apply_result) const {
    AckProcessingResult result;
    result.acked_packets.reserve(apply_result.acked_packets.size());
    for (const auto handle : apply_result.acked_packets) {
        RecoveryPacketMetadata metadata{
            .packet_number = handle.packet_number,
        };
        if (const auto *simple = simple_stream_packet_for_handle(handle); simple != nullptr) {
            metadata = packet_metadata(*simple);
        } else if (const auto *packet = packet_for_handle(handle); packet != nullptr) {
            metadata = packet_metadata(*packet);
        }
        result.acked_packets.push_back(handle, metadata);
    }

    result.late_acked_packets.reserve(apply_result.late_acked_packets.size());
    for (const auto handle : apply_result.late_acked_packets) {
        RecoveryPacketMetadata metadata{
            .packet_number = handle.packet_number,
        };
        if (const auto *simple = simple_stream_packet_for_handle(handle); simple != nullptr) {
            metadata = packet_metadata(*simple, /*declared_lost=*/true);
        } else if (const auto *packet = packet_for_handle(handle); packet != nullptr) {
            metadata = packet_metadata(*packet);
        }
        result.late_acked_packets.push_back(handle, metadata);
    }

    result.lost_packets.reserve(apply_result.lost_packets.size());
    for (const auto handle : apply_result.lost_packets) {
        RecoveryPacketMetadata metadata{
            .packet_number = handle.packet_number,
            .in_flight = false,
            .declared_lost = true,
        };
        if (const auto *simple = simple_stream_packet_for_handle(handle); simple != nullptr) {
            // Compatibility snapshots synthesize loss flags from the apply result itself.
            metadata = packet_metadata(*simple, /*declared_lost=*/true);
        } else if (const auto *packet = packet_for_handle(handle); packet != nullptr) {
            // Compatibility snapshots synthesize loss flags from the apply result itself.
            metadata = packet_metadata(*packet);
            metadata.in_flight = false;
            metadata.declared_lost = true;
        }
        result.lost_packets.push_back(handle, metadata);
    }

    if (apply_result.largest_newly_acked_packet.has_value()) {
        const auto &largest = *apply_result.largest_newly_acked_packet;
        RecoveryPacketMetadata metadata{
            .packet_number = largest.packet_number,
            .sent_time = largest.sent_time,
        };
        if (const auto *simple = simple_stream_packet_for_handle(largest.handle);
            simple != nullptr) {
            metadata.ack_eliciting = true;
            metadata.in_flight = true;
            metadata.declared_lost = false;
        } else if (const auto *packet = packet_for_handle(largest.handle); packet != nullptr) {
            metadata.ack_eliciting = packet->ack_eliciting;
            metadata.in_flight = packet->in_flight;
            metadata.declared_lost = packet->declared_lost;
        }
        result.largest_newly_acked_packet.emplace(largest.handle, metadata);
    }
    result.largest_acknowledged_was_newly_acked = apply_result.largest_acknowledged_was_newly_acked;
    result.has_newly_acked_ack_eliciting = apply_result.has_newly_acked_ack_eliciting;

    return result;
}

AckProcessingResult
PacketSpaceRecovery::on_ack_received(std::span<const AckPacketNumberRange> ack_ranges,
                                     std::uint64_t largest_acknowledged, QuicCoreTimePoint now) {
    std::vector<AckPacketNumberRange> ack_ranges_descending(ack_ranges.begin(), ack_ranges.end());
    std::sort(ack_ranges_descending.begin(), ack_ranges_descending.end(),
              [](const AckPacketNumberRange &lhs, const AckPacketNumberRange &rhs) {
                  if (lhs.largest != rhs.largest) {
                      return lhs.largest > rhs.largest;
                  }
                  return lhs.smallest > rhs.smallest;
              });
    const auto apply_result = apply_ack_received_descending(
        std::span<const AckPacketNumberRange>(ack_ranges_descending), largest_acknowledged, now);
    return ack_processing_result_from_apply(apply_result);
}

AckProcessingResult PacketSpaceRecovery::on_ack_received(AckRangeCursor cursor,
                                                         std::uint64_t largest_acknowledged,
                                                         QuicCoreTimePoint now) {
    const auto apply_result = apply_ack_received(cursor, largest_acknowledged, now);
    return ack_processing_result_from_apply(apply_result);
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

std::optional<std::uint64_t> PacketSpaceRecovery::largest_acked_packet_number() const {
    return largest_acked_packet_number_;
}

std::optional<DeadlineTrackedPacket>
PacketSpaceRecovery::latest_in_flight_ack_eliciting_packet() const {
    refresh_latest_in_flight_ack_eliciting_packet();
    if (!latest_in_flight_ack_eliciting_packet_.has_value()) {
        return std::nullopt;
    }

    return latest_in_flight_ack_eliciting_packet_;
}

std::optional<DeadlineTrackedPacket> PacketSpaceRecovery::earliest_loss_packet() const {
    prune_stale_eligible_loss_packets();
    if (eligible_loss_packets_.empty()) {
        return std::nullopt;
    }

    return *eligible_loss_packets_.begin();
}

QuicCoreTimePoint PacketSpaceRecovery::time_threshold_deadline(QuicCoreTimePoint sent_time) const {
    return sent_time + std::max(latest_loss_delay(rtt_state_), time_reordering_threshold_);
}

std::optional<DeadlineTrackedPacket> PacketSpaceRecovery::earliest_pmtu_probe_packet() const {
    std::optional<DeadlineTrackedPacket> earliest;
    for (auto slot_index = first_live_slot_;
         slot_index != kInvalidLedgerSlotIndex && slot_index < slots_.size();
         slot_index = next_live_slot(slot_index)) {
        const auto &slot = slots_[slot_index];
        if (slot.state != LedgerSlotState::sent || !slot_is_pmtu_probe(slot)) {
            continue;
        }

        const auto tracked = tracked_packet(slot);
        if (!earliest.has_value() || DeadlineTrackedPacketLess{}(tracked, *earliest)) {
            earliest = tracked;
        }
    }
    return earliest;
}

void PacketSpaceRecovery::rebuild_auxiliary_indexes() {
    rebuild_auxiliary_indexes(/*release_auxiliary_storage=*/false);
}

void PacketSpaceRecovery::rebuild_auxiliary_indexes(bool release_auxiliary_storage) {
    latest_in_flight_ack_eliciting_packet_.reset();
    eligible_loss_packets_.clear();
    first_live_slot_ = kInvalidLedgerSlotIndex;
    last_live_slot_ = kInvalidLedgerSlotIndex;
    next_loss_candidate_slot_ =
        largest_acked_packet_number_.has_value()
            ? (*largest_acked_packet_number_ <= first_slot_packet_number_
                   ? std::size_t{0}
                   : std::min<std::size_t>(static_cast<std::size_t>(*largest_acked_packet_number_ -
                                                                    first_slot_packet_number_),
                                           slots_.size()))
            : 0;
    next_packet_threshold_loss_slot_ = 0;
    packet_reordering_threshold_ = std::max(packet_reordering_threshold_, kPacketThreshold);
    time_reordering_threshold_ = std::max(time_reordering_threshold_, QuicCoreDuration{});
    if (release_auxiliary_storage) {
        std::vector<LiveSlotLink>(slots_.size()).swap(live_links_);
        std::vector<std::uint64_t>((slots_.size() + 63) / 64).swap(live_slot_words_);
    } else {
        live_links_.clear();
        live_links_.resize(slots_.size());
        live_slot_words_.clear();
        live_slot_words_.resize((slots_.size() + 63) / 64);
    }
    for (std::size_t slot_index = 0; slot_index < slots_.size(); ++slot_index) {
        auto &slot = slots_[slot_index];
        if ((slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost) ||
            slot.acknowledged) {
            continue;
        }

        link_live_slot(slot_index);
        maybe_track_latest_in_flight_ack_eliciting_packet(slot);
        maybe_track_as_loss_candidate(slot);
    }
}

void PacketSpaceRecovery::note_packet_metadata_updated() {
    ++compatibility_version_;
}

std::uint64_t PacketSpaceRecovery::compatibility_version() const {
    return compatibility_version_;
}

RecoveryRttState &PacketSpaceRecovery::rtt_state() {
    return rtt_state_;
}

const RecoveryRttState &PacketSpaceRecovery::rtt_state() const {
    return rtt_state_;
}

bool PacketSpaceRecovery::is_packet_threshold_lost(std::uint64_t packet_number,
                                                   std::uint64_t largest_acked) const {
    return coquic::quic::is_packet_threshold_lost(packet_number, largest_acked,
                                                  packet_reordering_threshold_);
}

bool PacketSpaceRecovery::is_time_threshold_lost(QuicCoreTimePoint sent_time,
                                                 QuicCoreTimePoint now) const {
    return now >= time_threshold_deadline(sent_time);
}

void PacketSpaceRecovery::note_packet_threshold_loss(SentPacketRecord &packet,
                                                     std::uint64_t largest_acked) {
    clear_loss_cause(packet);
    packet.lost_by_packet_threshold = true;
    packet.packet_threshold_largest_acked = largest_acked;
}

void PacketSpaceRecovery::note_time_threshold_loss(SentPacketRecord &packet,
                                                   QuicCoreTimePoint now) {
    clear_loss_cause(packet);
    packet.lost_by_time_threshold = true;
    packet.time_threshold_loss_time = now;
}

void PacketSpaceRecovery::clear_loss_cause(SentPacketRecord &packet) {
    packet.lost_by_packet_threshold = false;
    packet.packet_threshold_largest_acked = 0;
    packet.lost_by_time_threshold = false;
    packet.time_threshold_loss_time = {};
}

void PacketSpaceRecovery::maybe_adapt_reordering_thresholds_from_spurious_loss(
    const SentPacketRecord &packet, QuicCoreTimePoint now) {
    if (!packet.lost_by_packet_threshold ||
        packet.packet_threshold_largest_acked <= packet.packet_number) {
    } else {
        const auto observed_reordering =
            packet.packet_threshold_largest_acked - packet.packet_number + 1;
        const auto adapted_threshold =
            std::max(packet_reordering_threshold_, std::max(observed_reordering, kPacketThreshold));
        if (adapted_threshold > packet_reordering_threshold_) {
            packet_reordering_threshold_ = adapted_threshold;
            next_packet_threshold_loss_slot_ =
                std::min(next_packet_threshold_loss_slot_,
                         largest_acked_packet_number_.has_value()
                             ? packet_threshold_loss_scan_end(
                                   *largest_acked_packet_number_ < first_slot_packet_number_
                                       ? std::uint64_t{0}
                                       : *largest_acked_packet_number_ - first_slot_packet_number_,
                                   packet_reordering_threshold_, slots_.size())
                             : std::size_t{0});
        }
    }

    if (packet.lost_by_time_threshold && now > packet.sent_time) {
        const auto observed_delay =
            std::chrono::ceil<QuicCoreDuration>(now - packet.sent_time + kGranularity);
        time_reordering_threshold_ = std::max(time_reordering_threshold_, observed_delay);
    }
}

bool is_packet_threshold_lost(std::uint64_t packet_number, std::uint64_t largest_acked) {
    return is_packet_threshold_lost(packet_number, largest_acked, kPacketThreshold);
}

bool is_packet_threshold_lost(std::uint64_t packet_number, std::uint64_t largest_acked,
                              std::uint64_t packet_threshold) {
    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.1
    // # A packet is declared lost if it meets all of the following
    // # conditions:
    return largest_acked > packet_number && largest_acked - packet_number >= packet_threshold;
}

QuicCoreTimePoint compute_time_threshold_deadline(const RecoveryRttState &rtt_state,
                                                  QuicCoreTimePoint sent_time) {
    //= https://www.rfc-editor.org/rfc/rfc9002#section-6.1.2
    // # The time threshold is:
    // # max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)
    return sent_time + latest_loss_delay(rtt_state);
}

bool is_time_threshold_lost(const RecoveryRttState &rtt_state, QuicCoreTimePoint sent_time,
                            QuicCoreTimePoint now) {
    return now >= compute_time_threshold_deadline(rtt_state, sent_time);
}

QuicCoreTimePoint compute_pto_deadline(const RecoveryRttState &rtt_state,
                                       QuicCoreDuration max_ack_delay, QuicCoreTimePoint now,
                                       std::uint32_t pto_count) {
    auto timeout = kInitialRtt * 3;
    if (rtt_state.latest_rtt.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
        // # PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
        timeout =
            rtt_state.smoothed_rtt + std::max(rtt_state.rttvar * 4, kGranularity) + max_ack_delay;
    }

    for (std::uint32_t count = 0; count < pto_count; ++count) {
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.1
        // # When a PTO timer expires, the PTO backoff MUST be increased,
        // # resulting in the PTO period being set to twice its current value.
        timeout *= 2;
    }

    return now + timeout;
}

void update_rtt(RecoveryRttState &rtt_state, QuicCoreTimePoint ack_receive_time,
                const SentPacketRecord &largest_newly_acked_packet,
                std::chrono::microseconds ack_delay, std::chrono::microseconds max_ack_delay) {
    update_rtt(rtt_state, ack_receive_time, largest_newly_acked_packet,
               RttAckDelayAdjustment{
                   .ack_delay = ack_delay,
                   .max_ack_delay = max_ack_delay,
               });
}

void update_rtt(RecoveryRttState &rtt_state, QuicCoreTimePoint ack_receive_time,
                const SentPacketRecord &largest_newly_acked_packet,
                RttAckDelayAdjustment ack_delay) {
    //= https://www.rfc-editor.org/rfc/rfc9002#section-5.1
    // # The RTT sample, latest_rtt, is generated as the time elapsed since
    // # the largest acknowledged packet was sent:
    const auto latest_sample_duration = std::max(
        ack_receive_time - largest_newly_acked_packet.sent_time, QuicCoreClock::duration::zero());
    const auto latest_sample = std::chrono::duration_cast<QuicCoreDuration>(latest_sample_duration);
    const auto first_sample = !rtt_state.latest_rtt.has_value();
    auto previous_min_rtt_sample = rtt_state.min_rtt_sample;
    if (!previous_min_rtt_sample.has_value() && rtt_state.min_rtt.has_value()) {
        previous_min_rtt_sample = *rtt_state.min_rtt;
    }
    const auto effective_ack_delay =
        ack_delay.ignore_max_ack_delay ? ack_delay.ack_delay
                                       : std::min(ack_delay.ack_delay, ack_delay.max_ack_delay);
    const auto ack_delay_compensated_rtt =
        latest_sample > effective_ack_delay ? latest_sample - effective_ack_delay : latest_sample;

    rtt_state.latest_rtt = latest_sample;
    rtt_state.latest_rtt_sample = latest_sample;
    //= https://www.rfc-editor.org/rfc/rfc9002#section-5.2
    // # min_rtt MUST be set to the latest_rtt on the first RTT sample.
    //= https://www.rfc-editor.org/rfc/rfc9002#section-5.2
    // # min_rtt MUST be set to the lesser of min_rtt and latest_rtt
    // # (Section 5.1) on all other samples.
    rtt_state.min_rtt =
        rtt_state.min_rtt.has_value() ? std::min(*rtt_state.min_rtt, latest_sample) : latest_sample;
    rtt_state.min_rtt_sample = previous_min_rtt_sample.has_value()
                                   ? std::min(*previous_min_rtt_sample, latest_sample)
                                   : latest_sample;

    if (first_sample) {
        const auto first_smoothed_rtt =
            ack_delay.ignore_max_ack_delay ? ack_delay_compensated_rtt : latest_sample;
        rtt_state.smoothed_rtt = first_smoothed_rtt;
        rtt_state.rttvar = first_smoothed_rtt / 2;
        if (first_smoothed_rtt != latest_sample) {
            rtt_state.latest_adjusted_rtt = first_smoothed_rtt;
            rtt_state.latest_adjusted_rtt_sample = first_smoothed_rtt;
            rtt_state.latest_ack_delay_compensated_rtt_sample = first_smoothed_rtt;
        } else {
            rtt_state.latest_adjusted_rtt.reset();
            rtt_state.latest_adjusted_rtt_sample.reset();
            rtt_state.latest_ack_delay_compensated_rtt_sample.reset();
        }
        return;
    }

    auto adjusted_rtt = latest_sample;
    //= https://www.rfc-editor.org/rfc/rfc9002#section-5.3
    // # *  MUST use the lesser of the acknowledgment delay and the peer's
    // # max_ack_delay after the handshake is confirmed; and
    //= https://www.rfc-editor.org/rfc/rfc9002#section-5.3
    // # *  MUST NOT subtract the acknowledgment delay from the RTT sample if
    // # the resulting value is smaller than the min_rtt.
    if (latest_sample >= *rtt_state.min_rtt + effective_ack_delay) {
        adjusted_rtt = latest_sample - effective_ack_delay;
    }
    rtt_state.latest_adjusted_rtt = adjusted_rtt;

    auto adjusted_rtt_us = latest_sample;
    if (latest_sample >= *rtt_state.min_rtt_sample + effective_ack_delay) {
        adjusted_rtt_us = latest_sample - effective_ack_delay;
    }
    rtt_state.latest_adjusted_rtt_sample = adjusted_rtt_us;
    rtt_state.latest_ack_delay_compensated_rtt_sample =
        ack_delay_compensated_rtt;

    rtt_state.rttvar = (rtt_state.rttvar * 3 + (rtt_state.smoothed_rtt > adjusted_rtt
                                                    ? rtt_state.smoothed_rtt - adjusted_rtt
                                                    : adjusted_rtt - rtt_state.smoothed_rtt)) /
                       4;
    rtt_state.smoothed_rtt = (rtt_state.smoothed_rtt * 7 + adjusted_rtt) / 8;
}

} // namespace coquic::quic
