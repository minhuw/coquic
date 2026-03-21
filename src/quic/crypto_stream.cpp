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

void ReliableSendBuffer::append(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return;
    }

    auto storage = std::make_shared<std::vector<std::byte>>(bytes.begin(), bytes.end());
    segments_.emplace(next_append_offset_, Segment{
                                               .state = SegmentState::unsent,
                                               .storage = std::move(storage),
                                               .begin = 0,
                                               .end = bytes.size(),
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
    const auto copy_segment_bytes = [](const Segment &segment, std::size_t count) {
        const auto begin = segment.storage->begin() + static_cast<std::ptrdiff_t>(segment.begin);
        return std::vector<std::byte>(begin, begin + static_cast<std::ptrdiff_t>(count));
    };

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
            .bytes = copy_segment_bytes(it->second, chunk_size),
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
            frames.push_back(CryptoFrame{.offset = range.offset, .crypto_data = range.bytes});
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

    std::vector<std::byte> contiguous;
    if (offset <= next_contiguous_offset_) {
        const auto already_delivered = next_contiguous_offset_ - offset;
        if (already_delivered < bytes.size()) {
            const auto start = bytes.begin() + static_cast<std::ptrdiff_t>(already_delivered);
            contiguous.insert(contiguous.end(), start, bytes.end());

            const auto previous_next_contiguous = next_contiguous_offset_;
            next_contiguous_offset_ += static_cast<std::uint64_t>(bytes.size() - already_delivered);
            buffered_bytes_.erase(buffered_bytes_.lower_bound(previous_next_contiguous),
                                  buffered_bytes_.lower_bound(next_contiguous_offset_));
        }
    } else {
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            const auto position = offset + i;
            buffered_bytes_.try_emplace(position, bytes[i]);
        }
    }

    while (true) {
        const auto next = buffered_bytes_.find(next_contiguous_offset_);
        if (next == buffered_bytes_.end()) {
            break;
        }

        contiguous.push_back(next->second);
        buffered_bytes_.erase(next);
        ++next_contiguous_offset_;
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(contiguous));
}

CodecResult<std::vector<std::byte>> CryptoReceiveBuffer::push(std::uint64_t offset,
                                                              std::span<const std::byte> bytes) {
    return reliable_.push(offset, bytes);
}

} // namespace coquic::quic
