#include "src/quic/recovery.h"

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

    if (!largest_received_packet_number_.has_value() ||
        packet_number > *largest_received_packet_number_) {
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
        immediate_ack_requested_ =
            immediate_ack_requested_ || ack_eliciting_out_of_order || ack_eliciting_creates_gap ||
            ack_eliciting_packets_since_last_ack_ >= effective_ack_eliciting_threshold;
        largest_received_ack_eliciting_packet_number_ = std::max(
            largest_received_ack_eliciting_packet_number_.value_or(packet_number), packet_number);
        ack_pending_ = true;
    }
    if (ecn != QuicEcnCodepoint::unavailable) {
        ecn_feedback_accessible_ = true;
    }
    note_received_ecn(ecn_counts_, ecn);
}

void ReceivedPacketHistory::trim_old_ack_ranges() {
    while (ranges_.size() > kMaxTrackedAckRanges) {
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
    : slots_(other.slots_), packet_record_pool_(), live_links_(other.live_links_),
      live_slot_words_(other.live_slot_words_),
      latest_in_flight_ack_eliciting_packet_(other.latest_in_flight_ack_eliciting_packet_),
      eligible_loss_packets_(other.eligible_loss_packets_),
      largest_acked_packet_number_(other.largest_acked_packet_number_),
      first_live_slot_(other.first_live_slot_), last_live_slot_(other.last_live_slot_),
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
      first_live_slot_(other.first_live_slot_), last_live_slot_(other.last_live_slot_),
      next_loss_candidate_slot_(other.next_loss_candidate_slot_),
      next_packet_threshold_loss_slot_(other.next_packet_threshold_loss_slot_),
      packet_reordering_threshold_(other.packet_reordering_threshold_),
      time_reordering_threshold_(other.time_reordering_threshold_),
      compatibility_version_(other.compatibility_version_), rtt_state_(other.rtt_state_),
      sent_packets_{this} {
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
    first_live_slot_ = other.first_live_slot_;
    last_live_slot_ = other.last_live_slot_;
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
    first_live_slot_ = other.first_live_slot_;
    last_live_slot_ = other.last_live_slot_;
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
      acknowledged(other.acknowledged) {
}

PacketSpaceRecovery::SentPacketLedgerSlot &
PacketSpaceRecovery::SentPacketLedgerSlot::operator=(const SentPacketLedgerSlot &other) {
    if (this == &other) {
        return *this;
    }

    state = other.state;
    packet_number = other.packet_number;
    packet = other.packet ? std::make_unique<SentPacketRecord>(*other.packet) : nullptr;
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
    return slot_packet(*slot);
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

RecoveryPacketHandle PacketSpaceRecovery::packet_handle(const SentPacketLedgerSlot &slot,
                                                        std::size_t slot_index) {
    return RecoveryPacketHandle{
        .packet_number = slot.packet_number,
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
    packet.first_stream_frame_metadata.reset();
    std::vector<StreamFrameSendMetadata>().swap(packet.stream_frame_metadata);
    std::vector<StreamFrameSendFragment>().swap(packet.stream_fragments);
    packet.qlog_packet_snapshot.reset();
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

std::size_t PacketSpaceRecovery::newest_live_slot_at_or_below(std::uint64_t packet_number) const {
    const auto upper_bound = static_cast<std::size_t>(packet_number);
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
    const auto slot_index = static_cast<std::size_t>(packet_number);
    if (slot_index >= slots_.size()) {
        return nullptr;
    }

    const auto &slot = slots_[slot_index];
    if ((slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost) ||
        slot.packet_number != packet_number || slot.packet == nullptr) {
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
    if (slot_packet(*slot).sent_time != packet.sent_time) {
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
    if (!slot_packet(*slot).ack_eliciting) {
        return false;
    }
    if (!slot_packet(*slot).in_flight) {
        return false;
    }
    return !slot_packet(*slot).declared_lost;
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
    if (!slot_packet(*slot).in_flight) {
        return false;
    }
    return !slot_packet(*slot).declared_lost;
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

void PacketSpaceRecovery::refresh_latest_in_flight_ack_eliciting_packet() const {
    if (latest_in_flight_ack_eliciting_packet_.has_value() &&
        is_valid_in_flight_ack_eliciting_tracked_packet(*latest_in_flight_ack_eliciting_packet_)) {
        return;
    }

    latest_in_flight_ack_eliciting_packet_.reset();
    for (auto slot_index = first_live_slot_; slot_index != kInvalidLedgerSlotIndex;
         slot_index = next_live_slot(slot_index)) {
        const auto &slot = slots_[slot_index];
        maybe_track_latest_in_flight_ack_eliciting_packet(slot_packet(slot));
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
            maybe_track_as_loss_candidate(slot_packet(slot));
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
            slot.packet_number == handle.packet_number) {
            return slot_packet_or_null(slot);
        }
    }

    const auto *slot = slot_for_packet_number(handle.packet_number);
    return slot == nullptr ? nullptr : slot_packet_or_null(*slot);
}

SentPacketRecord *PacketSpaceRecovery::find_packet(std::uint64_t packet_number) {
    auto *slot = slot_for_packet_number(packet_number);
    return slot == nullptr ? nullptr : slot_packet_or_null(*slot);
}

const SentPacketRecord *PacketSpaceRecovery::find_packet(std::uint64_t packet_number) const {
    const auto *slot = slot_for_packet_number(packet_number);
    return slot == nullptr ? nullptr : slot_packet_or_null(*slot);
}

const SentPacketRecord *
PacketSpaceRecovery::find_newly_ackable_packet(std::uint64_t packet_number) const {
    const auto *slot = outstanding_slot_for_packet_number(packet_number);
    if (slot == nullptr || slot->state != LedgerSlotState::sent) {
        return nullptr;
    }
    return slot_packet_or_null(*slot);
}

bool PacketSpaceRecovery::ack_ranges_include_newly_ackable_ack_eliciting_packet(
    AckRangeCursor cursor) const {
    while (const auto range = next_ack_range(cursor)) {
        auto current_live_slot = newest_live_slot_at_or_below(range->largest);
        while (current_live_slot != kInvalidLedgerSlotIndex) {
            const auto &slot = slots_[current_live_slot];
            const auto &packet = slot_packet(slot);
            if (packet.packet_number < range->smallest) {
                break;
            }
            if (packet.packet_number <= range->largest && slot.state == LedgerSlotState::sent &&
                !slot.acknowledged && packet.ack_eliciting) {
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

    const auto loss_scan_end = std::min<std::size_t>(
        static_cast<std::size_t>(*largest_acked_packet_number_), slots_.size());
    for (auto slot_index = first_live_slot_;
         slot_index != kInvalidLedgerSlotIndex && slot_index < loss_scan_end;
         slot_index = next_live_slot(slot_index)) {
        const auto &slot = slots_[slot_index];
        const auto &packet = slot_packet(slot);
        if (slot.state != LedgerSlotState::sent || !packet.in_flight) {
            continue;
        }

        if (!is_time_threshold_lost(packet.sent_time, now)) {
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
        const auto &packet = slot_packet(slot);
        if (slot.state != LedgerSlotState::sent || !packet.is_pmtu_probe) {
            continue;
        }
        if (!coquic::quic::is_time_threshold_lost(rtt_state_, packet.sent_time, now)) {
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
        erase_from_tracked_sets(slot_packet(slot));
        if (!slot.acknowledged) {
            unlink_live_slot(slot_index);
        }
        recycle_packet_record(std::move(slot.packet));
    }

    slot.state = packet.declared_lost ? LedgerSlotState::declared_lost : LedgerSlotState::sent;
    const bool declared_lost = packet.declared_lost;
    slot.packet_number = packet.packet_number;
    slot.packet = acquire_packet_record(std::move(packet));
    auto &stored_packet = slot_packet(slot);
    stored_packet.declared_lost = declared_lost;
    if (slot.state == LedgerSlotState::declared_lost) {
        stored_packet.in_flight = false;
        stored_packet.bytes_in_flight = 0;
    }
    slot.acknowledged = false;
    link_live_slot(slot_index);

    maybe_track_latest_in_flight_ack_eliciting_packet(stored_packet);
    maybe_track_as_loss_candidate(stored_packet);
    ++compatibility_version_;
}

void PacketSpaceRecovery::on_packet_declared_lost(std::uint64_t packet_number) {
    auto *slot = slot_for_packet_number(packet_number);
    if (slot == nullptr) {
        return;
    }

    auto &packet = slot_packet(*slot);
    erase_from_tracked_sets(packet);
    packet.in_flight = false;
    packet.declared_lost = true;
    packet.bytes_in_flight = 0;
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

    auto &slot = slots_[current_handle->slot_index];
    if (!slot.acknowledged) {
        unlink_live_slot(current_handle->slot_index);
    }
    if (auto packet = std::move(slot.packet); packet != nullptr) {
        packet->in_flight = false;
        packet->bytes_in_flight = 0;
        recycle_packet_record(std::move(packet));
    }
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

bool PacketSpaceRecovery::retire_packet_if_present(RecoveryPacketHandle handle) {
    if (handle.slot_index >= slots_.size()) {
        return false;
    }

    auto &slot = slots_[handle.slot_index];
    if (slot.packet_number != handle.packet_number || slot.packet == nullptr ||
        (slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost)) {
        return false;
    }

    if (!slot.acknowledged) {
        unlink_live_slot(handle.slot_index);
    }

    auto packet = std::move(slot.packet);
    packet->in_flight = false;
    packet->bytes_in_flight = 0;
    recycle_packet_record(std::move(packet));
    slot.state = LedgerSlotState::retired;
    slot.acknowledged = true;
    ++compatibility_version_;
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

    auto &slot = slots_[current_handle->slot_index];
    if (!slot.acknowledged) {
        unlink_live_slot(current_handle->slot_index);
    }

    auto packet_record = std::move(slot.packet);
    auto packet = std::move(*packet_record);
    slot.packet_number = packet.packet_number;
    recycle_packet_record(std::move(packet_record));
    slot.state = LedgerSlotState::retired;
    slot.acknowledged = true;
    ++compatibility_version_;
    return packet;
}

std::optional<SentPacketRecord>
PacketSpaceRecovery::take_retired_packet_if_present(RecoveryPacketHandle handle) {
    if (handle.slot_index >= slots_.size()) {
        return std::nullopt;
    }
    auto &slot = slots_[handle.slot_index];
    if (slot.packet_number != handle.packet_number || slot.packet == nullptr ||
        (slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost)) {
        return std::nullopt;
    }

    if (!slot.acknowledged) {
        unlink_live_slot(handle.slot_index);
    }

    auto packet_record = std::move(slot.packet);
    auto packet = std::move(*packet_record);
    slot.packet_number = packet.packet_number;
    recycle_packet_record(std::move(packet_record));
    slot.state = LedgerSlotState::retired;
    slot.acknowledged = true;
    ++compatibility_version_;
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
    while (current_live_slot != kInvalidLedgerSlotIndex && current_live_slot > range.largest) {
        current_live_slot = previous_live_slot(current_live_slot);
    }

    while (current_live_slot != kInvalidLedgerSlotIndex && current_live_slot >= range.smallest) {
        const auto slot_index = current_live_slot;
        auto &slot = slots_[slot_index];
        const auto previous = previous_live_slot(slot_index);
        const auto handle = packet_handle(slot, slot_index);
        auto &packet = slot_packet(slot);

        if (slot.state == LedgerSlotState::sent) {
            state.result.acked_packets.push_back(handle);
            if (!state.result.largest_newly_acked_packet.has_value()) {
                state.result.largest_newly_acked_packet = AckApplyLargestNewlyAckedPacket{
                    .handle = handle,
                    .packet_number = packet.packet_number,
                    .sent_time = packet.sent_time,
                };
            }
            if (packet.packet_number == state.largest_acknowledged) {
                state.result.largest_acknowledged_was_newly_acked = true;
            }
            if (packet.ack_eliciting) {
                state.result.has_newly_acked_ack_eliciting = true;
            }

            unlink_live_slot(slot_index);
            slot.acknowledged = true;
            state.mutated = true;
        } else if (slot.state == LedgerSlotState::declared_lost) {
            state.result.late_acked_packets.push_back(handle);
            maybe_adapt_reordering_thresholds_from_spurious_loss(packet, state.now);
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

    const auto packet_threshold_scan_end = packet_threshold_loss_scan_end(
        state.effective_largest_acked, packet_reordering_threshold_, slots_.size());
    for (std::size_t slot_index = next_packet_threshold_loss_slot_;
         slot_index < packet_threshold_scan_end; ++slot_index) {
        auto &slot = slots_[slot_index];
        if (slot.state != LedgerSlotState::sent || slot.acknowledged) {
            continue;
        }
        auto &packet = slot_packet(slot);
        if (!packet.in_flight) {
            continue;
        }
        if (!is_packet_threshold_lost(packet.packet_number, state.effective_largest_acked)) {
            continue;
        }

        // Keep the live packet metadata unchanged until connection-level loss handling consumes it.
        note_packet_threshold_loss(packet, state.effective_largest_acked);
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
        if (!is_time_threshold_lost(tracked.sent_time, now)) {
            break;
        }

        eligible_loss_packets_.erase(eligible_loss_packets_.begin());
        // `prune_stale_eligible_loss_packets()` guarantees the remaining front entry still
        // resolves to a live sent in-flight slot with matching packet metadata.
        time_threshold_loss_slots.push_back(static_cast<std::size_t>(tracked.packet_number));
    }

    if (time_threshold_loss_slots.size() > 1) {
        std::sort(time_threshold_loss_slots.begin(), time_threshold_loss_slots.end());
    }
    for (const auto slot_index : time_threshold_loss_slots) {
        auto &slot = slots_[slot_index];
        auto &packet = slot_packet(slot);
        // Keep the live packet metadata unchanged until connection-level loss handling consumes it.
        note_time_threshold_loss(packet, now);
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
        const auto &packet = slot_packet(slot);
        if (slot.state != LedgerSlotState::sent || !packet.is_pmtu_probe) {
            continue;
        }

        const auto tracked = tracked_packet(packet);
        if (!earliest.has_value() || DeadlineTrackedPacketLess{}(tracked, *earliest)) {
            earliest = tracked;
        }
    }
    return earliest;
}

void PacketSpaceRecovery::rebuild_auxiliary_indexes() {
    latest_in_flight_ack_eliciting_packet_.reset();
    eligible_loss_packets_.clear();
    first_live_slot_ = kInvalidLedgerSlotIndex;
    last_live_slot_ = kInvalidLedgerSlotIndex;
    next_loss_candidate_slot_ =
        largest_acked_packet_number_.has_value()
            ? std::min<std::size_t>(static_cast<std::size_t>(*largest_acked_packet_number_),
                                    slots_.size())
            : 0;
    next_packet_threshold_loss_slot_ = 0;
    packet_reordering_threshold_ = std::max(packet_reordering_threshold_, kPacketThreshold);
    time_reordering_threshold_ = std::max(time_reordering_threshold_, QuicCoreDuration{});
    live_links_.clear();
    live_links_.resize(slots_.size());
    live_slot_words_.clear();
    live_slot_words_.resize((slots_.size() + 63) / 64);
    for (std::size_t slot_index = 0; slot_index < slots_.size(); ++slot_index) {
        auto &slot = slots_[slot_index];
        if ((slot.state != LedgerSlotState::sent && slot.state != LedgerSlotState::declared_lost) ||
            slot.acknowledged) {
            continue;
        }

        link_live_slot(slot_index);
        const auto &packet = slot_packet(slot);
        maybe_track_latest_in_flight_ack_eliciting_packet(packet);
        maybe_track_as_loss_candidate(packet);
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
            next_packet_threshold_loss_slot_ = std::min(
                next_packet_threshold_loss_slot_,
                largest_acked_packet_number_.has_value()
                    ? packet_threshold_loss_scan_end(*largest_acked_packet_number_,
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
    return largest_acked > packet_number && largest_acked - packet_number >= packet_threshold;
}

QuicCoreTimePoint compute_time_threshold_deadline(const RecoveryRttState &rtt_state,
                                                  QuicCoreTimePoint sent_time) {
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
        timeout =
            rtt_state.smoothed_rtt + std::max(rtt_state.rttvar * 4, kGranularity) + max_ack_delay;
    }

    for (std::uint32_t count = 0; count < pto_count; ++count) {
        timeout *= 2;
    }

    return now + timeout;
}

void update_rtt(RecoveryRttState &rtt_state, QuicCoreTimePoint ack_receive_time,
                const SentPacketRecord &largest_newly_acked_packet,
                std::chrono::microseconds ack_delay, std::chrono::microseconds max_ack_delay) {
    const auto latest_sample_duration = std::max(
        ack_receive_time - largest_newly_acked_packet.sent_time, QuicCoreClock::duration::zero());
    const auto latest_sample = std::chrono::duration_cast<QuicCoreDuration>(latest_sample_duration);
    const auto first_sample = !rtt_state.latest_rtt.has_value();
    auto previous_min_rtt_sample = rtt_state.min_rtt_sample;
    if (!previous_min_rtt_sample.has_value() && rtt_state.min_rtt.has_value()) {
        previous_min_rtt_sample = *rtt_state.min_rtt;
    }

    rtt_state.latest_rtt = latest_sample;
    rtt_state.latest_rtt_sample = latest_sample;
    rtt_state.min_rtt =
        rtt_state.min_rtt.has_value() ? std::min(*rtt_state.min_rtt, latest_sample) : latest_sample;
    rtt_state.min_rtt_sample = previous_min_rtt_sample.has_value()
                                   ? std::min(*previous_min_rtt_sample, latest_sample)
                                   : latest_sample;

    if (first_sample) {
        rtt_state.smoothed_rtt = latest_sample;
        rtt_state.rttvar = latest_sample / 2;
        rtt_state.latest_adjusted_rtt.reset();
        rtt_state.latest_adjusted_rtt_sample.reset();
        rtt_state.latest_ack_delay_compensated_rtt_sample.reset();
        return;
    }

    const auto bounded_ack_delay = std::min(ack_delay, max_ack_delay);
    auto adjusted_rtt = latest_sample;
    if (latest_sample >= *rtt_state.min_rtt + bounded_ack_delay) {
        adjusted_rtt = latest_sample - bounded_ack_delay;
    }
    rtt_state.latest_adjusted_rtt = adjusted_rtt;

    auto adjusted_rtt_us = latest_sample;
    if (latest_sample >= *rtt_state.min_rtt_sample + bounded_ack_delay) {
        adjusted_rtt_us = latest_sample - bounded_ack_delay;
    }
    rtt_state.latest_adjusted_rtt_sample = adjusted_rtt_us;
    rtt_state.latest_ack_delay_compensated_rtt_sample =
        latest_sample > bounded_ack_delay ? latest_sample - bounded_ack_delay : latest_sample;

    const auto rtt_sample_delta = rtt_state.smoothed_rtt > adjusted_rtt
                                      ? rtt_state.smoothed_rtt - adjusted_rtt
                                      : adjusted_rtt - rtt_state.smoothed_rtt;
    rtt_state.rttvar = (rtt_state.rttvar * 3 + rtt_sample_delta) / 4;
    rtt_state.smoothed_rtt = (rtt_state.smoothed_rtt * 7 + adjusted_rtt) / 8;
}

} // namespace coquic::quic
