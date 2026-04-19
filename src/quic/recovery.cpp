#include "src/quic/recovery.h"

#include <algorithm>
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

std::optional<OutboundAckHeader> ReceivedPacketHistory::build_outbound_ack_header(
    std::uint64_t ack_delay_exponent, QuicCoreTimePoint now, bool allow_non_pending) const {
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
    const auto ack_delay = std::chrono::duration_cast<std::chrono::microseconds>(std::max(
        now - largest_received_packet_record.received_time, QuicCoreClock::duration::zero()));
    OutboundAckHeader header{
        .largest_acknowledged = largest_range->second.largest_packet_number,
        .ack_delay = encode_ack_delay(ack_delay, ack_delay_exponent),
        .first_ack_range = largest_range->second.largest_packet_number - largest_range->first,
        .additional_range_count = 0,
        .additional_ranges = {},
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

PacketSpaceRecovery::PacketSpaceRecovery() : sent_packets_{this} {
}

PacketSpaceRecovery::PacketSpaceRecovery(const PacketSpaceRecovery &other)
    : slots_(other.slots_),
      in_flight_ack_eliciting_packets_(other.in_flight_ack_eliciting_packets_),
      eligible_loss_packets_(other.eligible_loss_packets_),
      largest_acked_packet_number_(other.largest_acked_packet_number_),
      first_live_slot_(other.first_live_slot_), last_live_slot_(other.last_live_slot_),
      next_loss_candidate_slot_(other.next_loss_candidate_slot_),
      compatibility_version_(other.compatibility_version_), rtt_state_(other.rtt_state_),
      sent_packets_{this} {
}

PacketSpaceRecovery::PacketSpaceRecovery(PacketSpaceRecovery &&other) noexcept
    : slots_(std::move(other.slots_)),
      in_flight_ack_eliciting_packets_(std::move(other.in_flight_ack_eliciting_packets_)),
      eligible_loss_packets_(std::move(other.eligible_loss_packets_)),
      largest_acked_packet_number_(other.largest_acked_packet_number_),
      first_live_slot_(other.first_live_slot_), last_live_slot_(other.last_live_slot_),
      next_loss_candidate_slot_(other.next_loss_candidate_slot_),
      compatibility_version_(other.compatibility_version_), rtt_state_(other.rtt_state_),
      sent_packets_{this} {
}

PacketSpaceRecovery &PacketSpaceRecovery::operator=(const PacketSpaceRecovery &other) {
    if (this == &other) {
        return *this;
    }

    slots_ = other.slots_;
    in_flight_ack_eliciting_packets_ = other.in_flight_ack_eliciting_packets_;
    eligible_loss_packets_ = other.eligible_loss_packets_;
    largest_acked_packet_number_ = other.largest_acked_packet_number_;
    first_live_slot_ = other.first_live_slot_;
    last_live_slot_ = other.last_live_slot_;
    next_loss_candidate_slot_ = other.next_loss_candidate_slot_;
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
    in_flight_ack_eliciting_packets_ = std::move(other.in_flight_ack_eliciting_packets_);
    eligible_loss_packets_ = std::move(other.eligible_loss_packets_);
    largest_acked_packet_number_ = other.largest_acked_packet_number_;
    first_live_slot_ = other.first_live_slot_;
    last_live_slot_ = other.last_live_slot_;
    next_loss_candidate_slot_ = other.next_loss_candidate_slot_;
    compatibility_version_ = other.compatibility_version_;
    rtt_state_ = other.rtt_state_;
    sent_packets_.owner = this;
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

    const auto *packet = recovery->packet_for_handle(handle);
    if (packet == nullptr) {
        return metadata;
    }

    metadata.sent_time = packet->sent_time;
    metadata.ack_eliciting = packet->ack_eliciting;
    metadata.in_flight = packet->in_flight;
    metadata.declared_lost = packet->declared_lost;
    return metadata;
}

RecoveryPacketMetadata packet_metadata(const SentPacketRecord &packet) {
    return RecoveryPacketMetadata{
        .packet_number = packet.packet_number,
        .sent_time = packet.sent_time,
        .ack_eliciting = packet.ack_eliciting,
        .in_flight = packet.in_flight,
        .declared_lost = packet.declared_lost,
    };
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
        throw std::bad_optional_access();
    }
    return *metadata_;
}

const RecoveryPacketMetadata *RecoveryPacketHandleOptional::operator->() const {
    if (!metadata_.has_value()) {
        throw std::bad_optional_access();
    }
    return &*metadata_;
}

bool PacketSpaceRecovery::SentPacketsView::contains(std::uint64_t packet_number) const {
    return owner != nullptr && owner->outstanding_slot_for_packet_number(packet_number) != nullptr;
}

const SentPacketRecord &
PacketSpaceRecovery::SentPacketsView::at(std::uint64_t packet_number) const {
    if (owner == nullptr) {
        throw std::out_of_range("packet recovery view is detached");
    }

    const auto *slot = owner->outstanding_slot_for_packet_number(packet_number);
    if (slot == nullptr) {
        throw std::out_of_range("packet number is not tracked");
    }
    return slot->packet;
}

std::size_t PacketSpaceRecovery::SentPacketsView::size() const {
    if (owner == nullptr) {
        return 0;
    }

    return static_cast<std::size_t>(std::count_if(
        owner->slots_.begin(), owner->slots_.end(), [](const SentPacketLedgerSlot &slot) {
            return (slot.state == LedgerSlotState::sent ||
                    slot.state == LedgerSlotState::declared_lost) &&
                   !slot.acknowledged;
        }));
}

DeadlineTrackedPacket PacketSpaceRecovery::tracked_packet(const SentPacketRecord &packet) {
    return DeadlineTrackedPacket{
        .packet_number = packet.packet_number,
        .sent_time = packet.sent_time,
    };
}

RecoveryPacketHandle PacketSpaceRecovery::packet_handle(const SentPacketLedgerSlot &slot,
                                                        std::size_t slot_index) {
    return RecoveryPacketHandle{
        .packet_number = slot.packet.packet_number,
        .slot_index = slot_index,
    };
}

void PacketSpaceRecovery::reclaim_retired_packet_storage(SentPacketRecord &packet) {
    std::vector<ByteRange>().swap(packet.crypto_ranges);
    std::vector<ResetStreamFrame>().swap(packet.reset_stream_frames);
    std::vector<StopSendingFrame>().swap(packet.stop_sending_frames);
    packet.max_data_frame.reset();
    std::vector<MaxStreamDataFrame>().swap(packet.max_stream_data_frames);
    std::vector<MaxStreamsFrame>().swap(packet.max_streams_frames);
    packet.data_blocked_frame.reset();
    std::vector<StreamDataBlockedFrame>().swap(packet.stream_data_blocked_frames);
    std::vector<StreamFrameSendFragment>().swap(packet.stream_fragments);
    packet.qlog_packet_snapshot.reset();
}

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

std::optional<std::size_t>
PacketSpaceRecovery::newest_live_slot_at_or_below(std::uint64_t packet_number) const {
    auto current = last_live_slot_;
    const auto upper_bound = static_cast<std::size_t>(packet_number);
    while (current != kInvalidLedgerSlotIndex && current > upper_bound) {
        current = slots_[current].prev_live_slot;
    }
    if (current == kInvalidLedgerSlotIndex) {
        return std::nullopt;
    }
    return current;
}

PacketSpaceRecovery::SentPacketLedgerSlot *
PacketSpaceRecovery::slot_for_packet_number(std::uint64_t packet_number) {
    return const_cast<SentPacketLedgerSlot *>(
        std::as_const(*this).slot_for_packet_number(packet_number));
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

void PacketSpaceRecovery::erase_from_tracked_sets(const SentPacketRecord &packet) {
    const auto tracked = tracked_packet(packet);
    in_flight_ack_eliciting_packets_.erase(tracked);
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

void PacketSpaceRecovery::track_new_loss_candidates(
    std::optional<std::uint64_t> previous_largest_acked, std::uint64_t largest_acked) {
    static_cast<void>(previous_largest_acked);
    if (slots_.empty() || next_loss_candidate_slot_ >= slots_.size()) {
        return;
    }

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
}

std::size_t PacketSpaceRecovery::ensure_slot_for_packet_number(std::uint64_t packet_number) {
    const auto slot_index = static_cast<std::size_t>(packet_number);
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

    return packet_handle(*slot, static_cast<std::size_t>(packet_number));
}

SentPacketRecord *PacketSpaceRecovery::packet_for_handle(RecoveryPacketHandle handle) {
    return const_cast<SentPacketRecord *>(std::as_const(*this).packet_for_handle(handle));
}

const SentPacketRecord *PacketSpaceRecovery::packet_for_handle(RecoveryPacketHandle handle) const {
    if (handle.slot_index < slots_.size()) {
        const auto &slot = slots_[handle.slot_index];
        if ((slot.state == LedgerSlotState::sent || slot.state == LedgerSlotState::declared_lost) &&
            slot.packet.packet_number == handle.packet_number) {
            return &slot.packet;
        }
    }

    const auto *slot = slot_for_packet_number(handle.packet_number);
    return slot == nullptr ? nullptr : &slot->packet;
}

SentPacketRecord *PacketSpaceRecovery::find_packet(std::uint64_t packet_number) {
    auto *slot = slot_for_packet_number(packet_number);
    return slot == nullptr ? nullptr : &slot->packet;
}

const SentPacketRecord *PacketSpaceRecovery::find_packet(std::uint64_t packet_number) const {
    const auto *slot = slot_for_packet_number(packet_number);
    return slot == nullptr ? nullptr : &slot->packet;
}

std::vector<RecoveryPacketHandle> PacketSpaceRecovery::tracked_packets() const {
    std::vector<RecoveryPacketHandle> packets;
    packets.reserve(tracked_packet_count());
    for (auto slot_index = first_live_slot_; slot_index != kInvalidLedgerSlotIndex;
         slot_index = slots_[slot_index].next_live_slot) {
        const auto &slot = slots_[slot_index];
        packets.push_back(packet_handle(slot, slot_index));
    }
    return packets;
}

std::size_t PacketSpaceRecovery::tracked_packet_count() const {
    std::size_t count = 0;
    for (auto slot_index = first_live_slot_; slot_index != kInvalidLedgerSlotIndex;
         slot_index = slots_[slot_index].next_live_slot) {
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

    const auto loss_scan_end = std::min<std::size_t>(
        static_cast<std::size_t>(*largest_acked_packet_number_), slots_.size());
    for (auto slot_index = first_live_slot_;
         slot_index != kInvalidLedgerSlotIndex && slot_index < loss_scan_end;
         slot_index = slots_[slot_index].next_live_slot) {
        const auto &slot = slots_[slot_index];
        if (slot.state != LedgerSlotState::sent || !slot.packet.in_flight) {
            continue;
        }

        if (!is_time_threshold_lost(rtt_state_, slot.packet.sent_time, now)) {
            continue;
        }

        lost_packets.push_back(packet_handle(slot, slot_index));
    }

    return lost_packets;
}

void PacketSpaceRecovery::on_packet_sent(const SentPacketRecord &packet) {
    const auto slot_index = ensure_slot_for_packet_number(packet.packet_number);
    auto &slot = slots_[slot_index];
    if (slot.state == LedgerSlotState::sent || slot.state == LedgerSlotState::declared_lost) {
        erase_from_tracked_sets(slot.packet);
        if (!slot.acknowledged) {
            unlink_live_slot(slot_index);
        }
    }

    slot.state = packet.declared_lost ? LedgerSlotState::declared_lost : LedgerSlotState::sent;
    slot.packet = packet;
    slot.packet.declared_lost = packet.declared_lost;
    if (slot.state == LedgerSlotState::declared_lost) {
        slot.packet.in_flight = false;
        slot.packet.bytes_in_flight = 0;
    }
    slot.acknowledged = false;
    link_live_slot(slot_index);

    if (slot.packet.ack_eliciting && slot.packet.in_flight) {
        in_flight_ack_eliciting_packets_.insert(tracked_packet(slot.packet));
    }
    maybe_track_as_loss_candidate(slot.packet);
    ++compatibility_version_;
}

void PacketSpaceRecovery::on_packet_declared_lost(std::uint64_t packet_number) {
    auto *packet = find_packet(packet_number);
    if (packet == nullptr) {
        return;
    }

    erase_from_tracked_sets(*packet);
    packet->in_flight = false;
    packet->declared_lost = true;
    packet->bytes_in_flight = 0;

    if (const auto handle = handle_for_packet_number(packet_number); handle.has_value()) {
        slots_[handle->slot_index].state = LedgerSlotState::declared_lost;
    }
    ++compatibility_version_;
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
    if (!slot.acknowledged) {
        unlink_live_slot(current_handle->slot_index);
    }
    slot.packet.in_flight = false;
    slot.packet.bytes_in_flight = 0;
    reclaim_retired_packet_storage(slot.packet);
    slot.state = LedgerSlotState::retired;
    slot.acknowledged = true;
    ++compatibility_version_;
}

void PacketSpaceRecovery::retire_packet(std::uint64_t packet_number) {
    const auto handle = handle_for_packet_number(packet_number);
    if (!handle.has_value()) {
        return;
    }
    retire_packet(*handle);
}

PacketSpaceRecovery::AckApplyState
PacketSpaceRecovery::begin_ack_received_apply(std::uint64_t largest_acknowledged) {
    AckApplyState state;
    const auto previous_largest_acked = largest_acked_packet_number_;
    largest_acked_packet_number_ = previous_largest_acked.has_value()
                                       ? std::max(*previous_largest_acked, largest_acknowledged)
                                       : largest_acknowledged;
    state.effective_largest_acked = *largest_acked_packet_number_;
    if (!previous_largest_acked.has_value() ||
        state.effective_largest_acked > *previous_largest_acked) {
        track_new_loss_candidates(previous_largest_acked, state.effective_largest_acked);
    }
    state.largest_acknowledged = largest_acknowledged;
    state.current_live_slot = newest_live_slot_at_or_below(largest_acknowledged);
    return state;
}

void PacketSpaceRecovery::apply_ack_range_descending(AckApplyState &state,
                                                     const AckPacketNumberRange &range) {
    const auto previous_live_slot = [this](std::size_t slot_index) -> std::optional<std::size_t> {
        const auto previous = slots_[slot_index].prev_live_slot;
        if (previous == kInvalidLedgerSlotIndex) {
            return std::nullopt;
        }
        return previous;
    };

    while (state.current_live_slot.has_value() && *state.current_live_slot > range.largest) {
        state.current_live_slot = previous_live_slot(*state.current_live_slot);
    }

    while (state.current_live_slot.has_value() && *state.current_live_slot >= range.smallest) {
        const auto slot_index = *state.current_live_slot;
        const auto previous = previous_live_slot(slot_index);
        auto &slot = slots_[slot_index];
        const auto handle = packet_handle(slot, slot_index);

        if (slot.state == LedgerSlotState::sent) {
            state.result.acked_packets.push_back(handle);
            if (!state.result.largest_newly_acked_packet.has_value() ||
                slot.packet.packet_number >
                    state.result.largest_newly_acked_packet->packet_number) {
                state.result.largest_newly_acked_packet = AckApplyLargestNewlyAckedPacket{
                    .handle = handle,
                    .packet_number = slot.packet.packet_number,
                    .sent_time = slot.packet.sent_time,
                };
            }
            if (slot.packet.packet_number == state.largest_acknowledged) {
                state.result.largest_acknowledged_was_newly_acked = true;
            }
            if (slot.packet.ack_eliciting) {
                state.result.has_newly_acked_ack_eliciting = true;
            }

            erase_from_tracked_sets(slot.packet);
            unlink_live_slot(slot_index);
            slot.acknowledged = true;
            state.mutated = true;
        } else if (slot.state == LedgerSlotState::declared_lost) {
            state.result.late_acked_packets.push_back(handle);
            unlink_live_slot(slot_index);
            slot.acknowledged = true;
            state.mutated = true;
        }

        state.current_live_slot = previous;
    }
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

    const auto loss_scan_end = std::min<std::size_t>(
        static_cast<std::size_t>(state.effective_largest_acked), slots_.size());
    for (auto slot_index = first_live_slot_;
         slot_index != kInvalidLedgerSlotIndex && slot_index < loss_scan_end;) {
        auto &slot = slots_[slot_index];
        const auto next_live_slot = slot.next_live_slot;
        const auto packet_number = slot.packet.packet_number;
        if (slot.state != LedgerSlotState::sent || !slot.packet.in_flight) {
            slot_index = next_live_slot;
            continue;
        }

        if (!is_packet_threshold_lost(packet_number, state.effective_largest_acked) &&
            !is_time_threshold_lost(rtt_state_, slot.packet.sent_time, now)) {
            slot_index = next_live_slot;
            continue;
        }

        // Keep the live packet metadata unchanged until connection-level loss handling consumes it.
        erase_from_tracked_sets(slot.packet);
        slot.state = LedgerSlotState::declared_lost;
        state.result.lost_packets.push_back(packet_handle(slot, slot_index));
        state.mutated = true;
        slot_index = next_live_slot;
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
    for (const auto &range : ack_ranges_descending) {
        apply_ack_range_descending(state, range);
    }
    return finish_ack_received_apply(state, now);
}

AckApplyResult PacketSpaceRecovery::apply_ack_received(AckRangeCursor cursor,
                                                       std::uint64_t largest_acknowledged,
                                                       QuicCoreTimePoint now) {
    auto state = begin_ack_received_apply(largest_acknowledged);
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
        if (const auto *packet = packet_for_handle(handle); packet != nullptr) {
            metadata = packet_metadata(*packet);
        }
        result.acked_packets.push_back(handle, metadata);
    }

    result.late_acked_packets.reserve(apply_result.late_acked_packets.size());
    for (const auto handle : apply_result.late_acked_packets) {
        RecoveryPacketMetadata metadata{
            .packet_number = handle.packet_number,
        };
        if (const auto *packet = packet_for_handle(handle); packet != nullptr) {
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
        if (const auto *packet = packet_for_handle(handle); packet != nullptr) {
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
        if (const auto *packet = packet_for_handle(largest.handle); packet != nullptr) {
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

void PacketSpaceRecovery::rebuild_auxiliary_indexes() {
    in_flight_ack_eliciting_packets_.clear();
    eligible_loss_packets_.clear();
    first_live_slot_ = kInvalidLedgerSlotIndex;
    last_live_slot_ = kInvalidLedgerSlotIndex;
    next_loss_candidate_slot_ =
        largest_acked_packet_number_.has_value()
            ? std::min<std::size_t>(static_cast<std::size_t>(*largest_acked_packet_number_),
                                    slots_.size())
            : 0;
    for (std::size_t slot_index = 0; slot_index < slots_.size(); ++slot_index) {
        auto &slot = slots_[slot_index];
        slot.prev_live_slot = kInvalidLedgerSlotIndex;
        slot.next_live_slot = kInvalidLedgerSlotIndex;
        if ((slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost) ||
            slot.acknowledged) {
            continue;
        }

        link_live_slot(slot_index);
        if (slot.packet.ack_eliciting && slot.packet.in_flight) {
            in_flight_ack_eliciting_packets_.insert(tracked_packet(slot.packet));
        }
        maybe_track_as_loss_candidate(slot.packet);
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
