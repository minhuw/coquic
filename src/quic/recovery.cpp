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

PacketSpaceRecovery::PacketSpaceRecovery() : sent_packets_{this} {
}

PacketSpaceRecovery::PacketSpaceRecovery(const PacketSpaceRecovery &other)
    : base_packet_number_(other.base_packet_number_), slots_(other.slots_),
      in_flight_ack_eliciting_packets_(other.in_flight_ack_eliciting_packets_),
      eligible_loss_packets_(other.eligible_loss_packets_),
      largest_acked_packet_number_(other.largest_acked_packet_number_),
      compatibility_version_(other.compatibility_version_), rtt_state_(other.rtt_state_),
      sent_packets_{this} {
}

PacketSpaceRecovery::PacketSpaceRecovery(PacketSpaceRecovery &&other) noexcept
    : base_packet_number_(other.base_packet_number_), slots_(std::move(other.slots_)),
      in_flight_ack_eliciting_packets_(std::move(other.in_flight_ack_eliciting_packets_)),
      eligible_loss_packets_(std::move(other.eligible_loss_packets_)),
      largest_acked_packet_number_(other.largest_acked_packet_number_),
      compatibility_version_(other.compatibility_version_), rtt_state_(other.rtt_state_),
      sent_packets_{this} {
}

PacketSpaceRecovery &PacketSpaceRecovery::operator=(const PacketSpaceRecovery &other) {
    if (this == &other) {
        return *this;
    }

    base_packet_number_ = other.base_packet_number_;
    slots_ = other.slots_;
    in_flight_ack_eliciting_packets_ = other.in_flight_ack_eliciting_packets_;
    eligible_loss_packets_ = other.eligible_loss_packets_;
    largest_acked_packet_number_ = other.largest_acked_packet_number_;
    compatibility_version_ = other.compatibility_version_;
    rtt_state_ = other.rtt_state_;
    sent_packets_.owner = this;
    return *this;
}

PacketSpaceRecovery &PacketSpaceRecovery::operator=(PacketSpaceRecovery &&other) noexcept {
    if (this == &other) {
        return *this;
    }

    base_packet_number_ = other.base_packet_number_;
    slots_ = std::move(other.slots_);
    in_flight_ack_eliciting_packets_ = std::move(other.in_flight_ack_eliciting_packets_);
    eligible_loss_packets_ = std::move(other.eligible_loss_packets_);
    largest_acked_packet_number_ = other.largest_acked_packet_number_;
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

PacketSpaceRecovery::SentPacketLedgerSlot *
PacketSpaceRecovery::slot_for_packet_number(std::uint64_t packet_number) {
    return const_cast<SentPacketLedgerSlot *>(
        std::as_const(*this).slot_for_packet_number(packet_number));
}

const PacketSpaceRecovery::SentPacketLedgerSlot *
PacketSpaceRecovery::slot_for_packet_number(std::uint64_t packet_number) const {
    if (slots_.empty() || packet_number < base_packet_number_) {
        return nullptr;
    }

    const auto slot_index = static_cast<std::size_t>(packet_number - base_packet_number_);
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
    if (slots_.empty() || largest_acked <= base_packet_number_) {
        return;
    }

    const auto scan_start =
        std::max(previous_largest_acked.value_or(base_packet_number_), base_packet_number_);
    const auto scan_end =
        std::min(largest_acked, base_packet_number_ + static_cast<std::uint64_t>(slots_.size()));
    for (auto packet_number = scan_start; packet_number < scan_end; ++packet_number) {
        const auto slot_index = static_cast<std::size_t>(packet_number - base_packet_number_);
        const auto &slot = slots_[slot_index];
        if (slot.state != LedgerSlotState::sent || slot.acknowledged) {
            continue;
        }
        maybe_track_as_loss_candidate(slot.packet);
    }
}

std::size_t PacketSpaceRecovery::ensure_slot_for_packet_number(std::uint64_t packet_number) {
    if (slots_.empty()) {
        base_packet_number_ = packet_number;
        slots_.resize(1);
        return 0;
    }

    if (packet_number < base_packet_number_) {
        const auto prepend_count = static_cast<std::size_t>(base_packet_number_ - packet_number);
        slots_.insert(slots_.begin(), prepend_count, SentPacketLedgerSlot{});
        base_packet_number_ = packet_number;
        return 0;
    }

    const auto slot_index = static_cast<std::size_t>(packet_number - base_packet_number_);
    if (slot_index >= slots_.size()) {
        slots_.resize(slot_index + 1);
    }
    return slot_index;
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
    if (retired_prefix == slots_.size()) {
        slots_.clear();
        base_packet_number_ = 0;
        return;
    }

    slots_.erase(slots_.begin(), slots_.begin() + static_cast<std::ptrdiff_t>(retired_prefix));
    base_packet_number_ += retired_prefix;
}

std::optional<RecoveryPacketHandle>
PacketSpaceRecovery::handle_for_packet_number(std::uint64_t packet_number) const {
    const auto *slot = slot_for_packet_number(packet_number);
    if (slot == nullptr) {
        return std::nullopt;
    }

    const auto slot_index = static_cast<std::size_t>(slot - slots_.data());
    return packet_handle(*slot, slot_index);
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
    for (std::size_t slot_index = 0; slot_index < slots_.size(); ++slot_index) {
        const auto &slot = slots_[slot_index];
        if (slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost) {
            continue;
        }
        packets.push_back(packet_handle(slot, slot_index));
    }
    return packets;
}

std::size_t PacketSpaceRecovery::tracked_packet_count() const {
    return static_cast<std::size_t>(
        std::count_if(slots_.begin(), slots_.end(), [](const SentPacketLedgerSlot &slot) {
            return slot.state == LedgerSlotState::sent ||
                   slot.state == LedgerSlotState::declared_lost;
        }));
}

std::optional<RecoveryPacketHandle> PacketSpaceRecovery::oldest_tracked_packet() const {
    for (std::size_t slot_index = 0; slot_index < slots_.size(); ++slot_index) {
        const auto &slot = slots_[slot_index];
        if (slot.state == LedgerSlotState::sent || slot.state == LedgerSlotState::declared_lost) {
            return packet_handle(slot, slot_index);
        }
    }
    return std::nullopt;
}

std::optional<RecoveryPacketHandle> PacketSpaceRecovery::newest_tracked_packet() const {
    for (std::size_t slot_index = slots_.size(); slot_index > 0; --slot_index) {
        const auto &slot = slots_[slot_index - 1];
        if (slot.state == LedgerSlotState::sent || slot.state == LedgerSlotState::declared_lost) {
            return packet_handle(slot, slot_index - 1);
        }
    }
    return std::nullopt;
}

std::vector<RecoveryPacketHandle>
PacketSpaceRecovery::collect_time_threshold_losses(QuicCoreTimePoint now) {
    std::vector<RecoveryPacketHandle> lost_packets;
    if (!largest_acked_packet_number_.has_value() || slots_.empty() ||
        *largest_acked_packet_number_ <= base_packet_number_) {
        return lost_packets;
    }

    const auto loss_scan_end =
        std::min(*largest_acked_packet_number_,
                 base_packet_number_ + static_cast<std::uint64_t>(slots_.size()));
    for (auto packet_number = base_packet_number_; packet_number < loss_scan_end; ++packet_number) {
        const auto slot_index = static_cast<std::size_t>(packet_number - base_packet_number_);
        const auto &slot = slots_[slot_index];
        if (slot.state != LedgerSlotState::sent || slot.acknowledged || !slot.packet.in_flight) {
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
    auto &slot = slots_[ensure_slot_for_packet_number(packet.packet_number)];
    if (slot.state == LedgerSlotState::sent || slot.state == LedgerSlotState::declared_lost) {
        erase_from_tracked_sets(slot.packet);
    }

    slot.state = packet.declared_lost ? LedgerSlotState::declared_lost : LedgerSlotState::sent;
    slot.packet = packet;
    slot.packet.declared_lost = packet.declared_lost;
    if (slot.state == LedgerSlotState::declared_lost) {
        slot.packet.in_flight = false;
        slot.packet.bytes_in_flight = 0;
    }
    slot.acknowledged = false;

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
    slot.packet.in_flight = false;
    slot.packet.bytes_in_flight = 0;
    slot.state = LedgerSlotState::retired;
    slot.acknowledged = true;
    compact_retired_prefix();
    ++compatibility_version_;
}

void PacketSpaceRecovery::retire_packet(std::uint64_t packet_number) {
    const auto handle = handle_for_packet_number(packet_number);
    if (!handle.has_value()) {
        return;
    }
    retire_packet(*handle);
}

AckProcessingResult
PacketSpaceRecovery::on_ack_received(std::span<const AckPacketNumberRange> ack_ranges,
                                     std::uint64_t largest_acknowledged, QuicCoreTimePoint now) {
    AckProcessingResult result;
    bool mutated = false;
    const auto previous_largest_acked = largest_acked_packet_number_;
    largest_acked_packet_number_ = previous_largest_acked.has_value()
                                       ? std::max(*previous_largest_acked, largest_acknowledged)
                                       : largest_acknowledged;
    const auto effective_largest_acked = *largest_acked_packet_number_;
    if (!previous_largest_acked.has_value() || effective_largest_acked > *previous_largest_acked) {
        track_new_loss_candidates(previous_largest_acked, effective_largest_acked);
    }

    for (auto range_it = ack_ranges.rbegin(); range_it != ack_ranges.rend(); ++range_it) {
        for (auto packet_number = range_it->smallest; packet_number <= range_it->largest;
             ++packet_number) {
            const auto handle = handle_for_packet_number(packet_number);
            if (!handle.has_value()) {
                continue;
            }

            auto &slot = slots_[handle->slot_index];
            if (slot.acknowledged) {
                continue;
            }

            if (slot.state == LedgerSlotState::sent) {
                const auto snapshot = packet_metadata(slot.packet);
                result.acked_packets.push_back(packet_handle(slot, handle->slot_index), snapshot);
                result.largest_newly_acked_packet.emplace(*handle, snapshot);
                if (packet_number == largest_acknowledged) {
                    result.largest_acknowledged_was_newly_acked = true;
                }
                if (slot.packet.ack_eliciting) {
                    result.has_newly_acked_ack_eliciting = true;
                }

                erase_from_tracked_sets(slot.packet);
                slot.acknowledged = true;
                mutated = true;
            } else if (slot.state == LedgerSlotState::declared_lost) {
                result.late_acked_packets.push_back(packet_handle(slot, handle->slot_index),
                                                    packet_metadata(slot.packet));
                slot.acknowledged = true;
                mutated = true;
            }
        }
    }

    if (slots_.empty() || effective_largest_acked <= base_packet_number_) {
        return result;
    }

    const auto loss_scan_end = std::min(
        effective_largest_acked, base_packet_number_ + static_cast<std::uint64_t>(slots_.size()));
    for (auto packet_number = base_packet_number_; packet_number < loss_scan_end; ++packet_number) {
        auto &slot = slots_[static_cast<std::size_t>(packet_number - base_packet_number_)];
        if (slot.state != LedgerSlotState::sent || slot.acknowledged || !slot.packet.in_flight) {
            continue;
        }

        if (!is_packet_threshold_lost(packet_number, effective_largest_acked) &&
            !is_time_threshold_lost(rtt_state_, slot.packet.sent_time, now)) {
            continue;
        }

        erase_from_tracked_sets(slot.packet);
        slot.state = LedgerSlotState::declared_lost;
        auto metadata = packet_metadata(slot.packet);
        metadata.in_flight = false;
        metadata.declared_lost = true;
        result.lost_packets.push_back(packet_handle(slot, packet_number - base_packet_number_),
                                      metadata);
        mutated = true;
    }

    if (mutated) {
        ++compatibility_version_;
    }

    return result;
}

AckProcessingResult PacketSpaceRecovery::on_ack_received(const AckFrame &ack,
                                                         QuicCoreTimePoint now) {
    const auto ack_ranges = ack_frame_packet_number_ranges(ack);
    if (!ack_ranges.has_value()) {
        return on_ack_received(std::span<const AckPacketNumberRange>{}, ack.largest_acknowledged,
                               now);
    }
    return on_ack_received(std::span<const AckPacketNumberRange>(ack_ranges.value()),
                           ack.largest_acknowledged, now);
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
