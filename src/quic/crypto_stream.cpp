#include "src/quic/crypto_stream.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <vector>

namespace {

using coquic::quic::CodecErrorCode;
using coquic::quic::CodecResult;
using coquic::quic::CryptoFrame;
using coquic::quic::ReliableSendBuffer;

constexpr std::uint64_t maximum_stream_offset = (std::uint64_t{1} << 62) - 1;

CodecResult<std::vector<std::byte>> crypto_stream_failure() {
    return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
}

std::uint64_t range_end(std::uint64_t offset, std::size_t length) {
    const auto max_uint64 = std::numeric_limits<std::uint64_t>::max();
    if (length > static_cast<std::size_t>(max_uint64 - offset)) {
        return max_uint64;
    }

    return offset + static_cast<std::uint64_t>(length);
}

} // namespace

namespace coquic::quic {

void ReliableSendBuffer::append(const std::vector<std::byte> &bytes) {
    append(std::span<const std::byte>(bytes));
}

void ReliableSendBuffer::append(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return;
    }

    auto storage = std::make_shared<std::vector<std::byte>>(bytes.begin(), bytes.end());
    append(SharedBytes{std::move(storage), 0, bytes.size()});
}

void ReliableSendBuffer::append(SharedBytes bytes) {
    if (bytes.empty()) {
        return;
    }

    segments_.emplace(next_append_offset_, Segment{
                                               .state = SegmentState::unsent,
                                               .storage = bytes.storage(),
                                               .begin = bytes.begin_offset(),
                                               .end = bytes.end_offset(),
                                           });
    next_append_offset_ += static_cast<std::uint64_t>(bytes.size());
    merge_adjacent_segments();
}

std::vector<ByteRange>
ReliableSendBuffer::take_ranges_by_state(SegmentState state, std::size_t &remaining_bytes,
                                         std::optional<std::uint64_t> max_offset) {
    std::vector<ByteRange> ranges;
    if (max_offset.has_value()) {
        split_at(*max_offset);
    }

    const auto segment_length = [](const Segment &segment) { return segment.end - segment.begin; };

    for (auto it = segments_.begin(); it != segments_.end() && remaining_bytes > 0; ++it) {
        if (max_offset.has_value() && it->first >= *max_offset) {
            break;
        }
        if (it->second.state != state) {
            continue;
        }

        const auto available_bytes = segment_length(it->second);
        const auto chunk_size = std::min(remaining_bytes, available_bytes);
        auto range = ByteRange{
            .offset = it->first,
            .bytes =
                SharedBytes{
                    it->second.storage,
                    it->second.begin,
                    it->second.begin + chunk_size,
                },
        };
        ranges.push_back(std::move(range));

        if (chunk_size == available_bytes) {
            it->second.state = SegmentState::sent;
            remaining_bytes -= chunk_size;
            continue;
        }

        const auto tail_offset = it->first + static_cast<std::uint64_t>(chunk_size);
        auto tail = Segment{
            .state = state,
            .storage = it->second.storage,
            .begin = it->second.begin + chunk_size,
            .end = it->second.end,
        };
        it->second.end = it->second.begin + chunk_size;
        it->second.state = SegmentState::sent;
        segments_.emplace(tail_offset, std::move(tail));
        remaining_bytes -= chunk_size;
    }

    return ranges;
}

std::vector<ByteRange> ReliableSendBuffer::take_ranges(std::size_t max_bytes) {
    std::vector<ByteRange> ranges;
    if (max_bytes == 0) {
        return ranges;
    }

    auto remaining_bytes = max_bytes;
    auto lost_ranges = take_ranges_by_state(SegmentState::lost, remaining_bytes);
    ranges.insert(ranges.end(), std::make_move_iterator(lost_ranges.begin()),
                  std::make_move_iterator(lost_ranges.end()));

    auto unsent_ranges = take_ranges_by_state(SegmentState::unsent, remaining_bytes);
    ranges.insert(ranges.end(), std::make_move_iterator(unsent_ranges.begin()),
                  std::make_move_iterator(unsent_ranges.end()));
    merge_adjacent_segments();
    return ranges;
}

std::vector<ByteRange>
ReliableSendBuffer::take_lost_ranges(std::size_t max_bytes,
                                     std::optional<std::uint64_t> max_offset) {
    if (max_bytes == 0) {
        return {};
    }

    auto remaining_bytes = max_bytes;
    auto ranges = take_ranges_by_state(SegmentState::lost, remaining_bytes, max_offset);
    merge_adjacent_segments();
    return ranges;
}

std::vector<ByteRange>
ReliableSendBuffer::take_unsent_ranges(std::size_t max_bytes,
                                       std::optional<std::uint64_t> max_offset) {
    if (max_bytes == 0) {
        return {};
    }

    auto remaining_bytes = max_bytes;
    auto ranges = take_ranges_by_state(SegmentState::unsent, remaining_bytes, max_offset);
    merge_adjacent_segments();
    return ranges;
}

void ReliableSendBuffer::split_at(std::uint64_t offset) {
    const auto candidate = segments_.upper_bound(offset);
    if (candidate == segments_.begin()) {
        return;
    }

    auto it = candidate;
    --it;

    const auto segment_offset = it->first;
    const auto segment_end =
        segment_offset + static_cast<std::uint64_t>(it->second.end - it->second.begin);
    if (offset <= segment_offset || offset >= segment_end) {
        return;
    }

    const auto split_index = static_cast<std::size_t>(offset - segment_offset);
    auto tail = Segment{
        .state = it->second.state,
        .storage = it->second.storage,
        .begin = it->second.begin + split_index,
        .end = it->second.end,
    };
    it->second.end = it->second.begin + split_index;
    segments_.emplace(offset, std::move(tail));
}

void ReliableSendBuffer::merge_adjacent_segments() {
    const auto segment_length = [](const Segment &segment) { return segment.end - segment.begin; };

    auto it = segments_.begin();
    while (it != segments_.end()) {
        auto next = std::next(it);
        if (next == segments_.end()) {
            break;
        }

        const auto expected_next_offset =
            it->first + static_cast<std::uint64_t>(segment_length(it->second));
        if (it->second.state != next->second.state || expected_next_offset != next->first) {
            it = next;
            continue;
        }

        if (it->second.storage == next->second.storage && it->second.end == next->second.begin) {
            it->second.end = next->second.end;
            segments_.erase(next);
            continue;
        }
        it = next;
    }
}

void ReliableSendBuffer::acknowledge(std::uint64_t offset, std::size_t length) {
    if (length == 0) {
        return;
    }

    const auto end = range_end(offset, length);
    split_at(offset);
    split_at(end);

    for (auto it = segments_.lower_bound(offset); it != segments_.end() && it->first < end;) {
        it = segments_.erase(it);
    }
    merge_adjacent_segments();
}

void ReliableSendBuffer::mark_lost(std::uint64_t offset, std::size_t length) {
    if (length == 0) {
        return;
    }

    const auto end = range_end(offset, length);
    split_at(offset);
    split_at(end);

    for (auto it = segments_.lower_bound(offset); it != segments_.end() && it->first < end; ++it) {
        if (it->second.state == SegmentState::sent) {
            it->second.state = SegmentState::lost;
        }
    }
    merge_adjacent_segments();
}

void ReliableSendBuffer::mark_unsent(std::uint64_t offset, std::size_t length) {
    if (length == 0) {
        return;
    }

    const auto end = range_end(offset, length);
    split_at(offset);
    split_at(end);

    for (auto it = segments_.lower_bound(offset); it != segments_.end() && it->first < end; ++it) {
        if (it->second.state == SegmentState::sent) {
            it->second.state = SegmentState::unsent;
        }
    }
    merge_adjacent_segments();
}

void ReliableSendBuffer::mark_sent(std::uint64_t offset, std::size_t length) {
    if (length == 0) {
        return;
    }

    const auto end = range_end(offset, length);
    split_at(offset);
    split_at(end);

    for (auto it = segments_.lower_bound(offset); it != segments_.end() && it->first < end; ++it) {
        if (it->second.state == SegmentState::lost) {
            it->second.state = SegmentState::sent;
        }
    }
    merge_adjacent_segments();
}

bool ReliableSendBuffer::has_pending_data() const {
    for (const auto &[offset, segment] : segments_) {
        static_cast<void>(offset);
        if (segment.state == SegmentState::unsent || segment.state == SegmentState::lost) {
            return true;
        }
    }

    return false;
}

bool ReliableSendBuffer::has_outstanding_data() const {
    for (const auto &[offset, segment] : segments_) {
        static_cast<void>(offset);
        if (segment.state == SegmentState::sent || segment.state == SegmentState::lost) {
            return true;
        }
    }

    return false;
}

bool ReliableSendBuffer::has_outstanding_range(std::uint64_t offset, std::size_t length) const {
    if (length == 0) {
        return false;
    }

    const auto end = range_end(offset, length);
    const auto segment_length = [](const Segment &segment) { return segment.end - segment.begin; };
    auto it = segments_.upper_bound(offset);
    if (it != segments_.begin()) {
        --it;
    }

    auto covered_until = offset;
    for (; it != segments_.end() && covered_until < end; ++it) {
        const auto segment_offset = it->first;
        const auto segment_end =
            segment_offset + static_cast<std::uint64_t>(segment_length(it->second));
        if (segment_end <= covered_until) {
            continue;
        }
        if (segment_offset > covered_until) {
            return false;
        }
        if (it->second.state != SegmentState::sent && it->second.state != SegmentState::lost) {
            return false;
        }

        covered_until = std::min(end, segment_end);
    }

    return covered_until >= end;
}

bool ReliableSendBuffer::has_lost_data() const {
    for (const auto &[offset, segment] : segments_) {
        static_cast<void>(offset);
        if (segment.state == SegmentState::lost) {
            return true;
        }
    }

    return false;
}

void CryptoSendBuffer::append(std::span<const std::byte> bytes) {
    reliable_.append(bytes);
}

std::vector<CryptoFrame> CryptoSendBuffer::take_frames(std::size_t max_frame_payload_size) {
    std::vector<CryptoFrame> frames;
    if (max_frame_payload_size == 0) {
        return frames;
    }

    while (true) {
        const auto ranges = reliable_.take_ranges(max_frame_payload_size);
        if (ranges.empty()) {
            break;
        }

        for (const auto &range : ranges) {
            frames.push_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
    }

    return frames;
}

bool CryptoSendBuffer::empty() const {
    return !reliable_.has_pending_data();
}

CodecResult<std::vector<std::byte>> ReliableReceiveBuffer::push(std::uint64_t offset,
                                                                std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return CodecResult<std::vector<std::byte>>::success({});
    }
    if (offset > maximum_stream_offset || bytes.size() - 1 > maximum_stream_offset - offset) {
        return crypto_stream_failure();
    }

    const auto end = range_end(offset, bytes.size());
    const auto start = std::max(offset, next_contiguous_offset_);
    if (start < end) {
        const auto buffer_offset = static_cast<std::size_t>(start - offset);
        buffer_range(start, bytes.subspan(buffer_offset));
    }

    return CodecResult<std::vector<std::byte>>::success(take_contiguous_buffered_bytes());
}

void ReliableReceiveBuffer::buffer_range(std::uint64_t offset, std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return;
    }

    auto cursor = offset;
    const auto end = range_end(offset, bytes.size());
    auto next_buffered = buffered_bytes_.lower_bound(offset);
    if (next_buffered != buffered_bytes_.begin()) {
        auto previous = std::prev(next_buffered);
        if (range_end(previous->first, previous->second.size()) > offset) {
            next_buffered = previous;
        }
    }

    while (true) {
        while (next_buffered != buffered_bytes_.end() &&
               range_end(next_buffered->first, next_buffered->second.size()) <= cursor) {
            ++next_buffered;
        }

        auto next_gap_end = end;
        if (next_buffered != buffered_bytes_.end() && next_buffered->first < next_gap_end) {
            next_gap_end = next_buffered->first;
        }

        if (cursor < next_gap_end) {
            const auto begin_index = static_cast<std::size_t>(cursor - offset);
            const auto byte_count = static_cast<std::size_t>(next_gap_end - cursor);
            const auto begin = bytes.begin() + static_cast<std::ptrdiff_t>(begin_index);
            const auto end_it = begin + static_cast<std::ptrdiff_t>(byte_count);
            buffered_bytes_.emplace(cursor, std::vector<std::byte>(begin, end_it));
            cursor = next_gap_end;
            continue;
        }

        if (next_buffered == buffered_bytes_.end()) {
            break;
        }

        cursor = std::max(cursor, range_end(next_buffered->first, next_buffered->second.size()));
        if (cursor >= end) {
            break;
        }
        ++next_buffered;
    }
}

std::vector<std::byte> ReliableReceiveBuffer::take_contiguous_buffered_bytes() {
    std::vector<std::byte> contiguous;

    while (!buffered_bytes_.empty()) {
        auto next = buffered_bytes_.begin();
        const auto segment_offset = next->first;
        const auto segment_end = range_end(segment_offset, next->second.size());
        if (segment_offset > next_contiguous_offset_) {
            break;
        }

        const auto already_delivered =
            static_cast<std::size_t>(next_contiguous_offset_ - segment_offset);
        if (already_delivered < next->second.size()) {
            contiguous.insert(contiguous.end(),
                              next->second.begin() + static_cast<std::ptrdiff_t>(already_delivered),
                              next->second.end());
            next_contiguous_offset_ = segment_end;
        }

        buffered_bytes_.erase(next);
    }

    return contiguous;
}

CodecResult<std::vector<std::byte>> CryptoReceiveBuffer::push(std::uint64_t offset,
                                                              std::span<const std::byte> bytes) {
    return reliable_.push(offset, bytes);
}

} // namespace coquic::quic
