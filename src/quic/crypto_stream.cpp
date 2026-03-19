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

    segments_.emplace(next_append_offset_,
                      Segment{
                          .state = SegmentState::unsent,
                          .bytes = std::vector<std::byte>(bytes.begin(), bytes.end()),
                      });
    next_append_offset_ += static_cast<std::uint64_t>(bytes.size());
    merge_adjacent_segments();
}

std::vector<ByteRange> ReliableSendBuffer::take_ranges_by_state(SegmentState state,
                                                                std::size_t &remaining_bytes) {
    std::vector<ByteRange> ranges;
    for (auto it = segments_.begin(); it != segments_.end() && remaining_bytes > 0; ++it) {
        if (it->second.state != state) {
            continue;
        }

        const auto chunk_size = std::min(remaining_bytes, it->second.bytes.size());
        const auto chunk_size_difference = static_cast<std::ptrdiff_t>(chunk_size);
        auto range = ByteRange{
            .offset = it->first,
            .bytes = std::vector<std::byte>(it->second.bytes.begin(),
                                            it->second.bytes.begin() + chunk_size_difference),
        };
        ranges.push_back(std::move(range));

        if (chunk_size == it->second.bytes.size()) {
            it->second.state = SegmentState::sent;
            remaining_bytes -= chunk_size;
            continue;
        }

        std::vector<std::byte> tail(it->second.bytes.begin() + chunk_size_difference,
                                    it->second.bytes.end());
        const auto tail_offset = it->first + static_cast<std::uint64_t>(chunk_size);
        it->second.bytes.resize(chunk_size);
        it->second.state = SegmentState::sent;
        segments_.emplace(tail_offset, Segment{.state = state, .bytes = std::move(tail)});
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

void ReliableSendBuffer::split_at(std::uint64_t offset) {
    const auto candidate = segments_.upper_bound(offset);
    if (candidate == segments_.begin()) {
        return;
    }

    auto it = candidate;
    --it;

    const auto segment_offset = it->first;
    const auto segment_end = segment_offset + static_cast<std::uint64_t>(it->second.bytes.size());
    if (offset <= segment_offset || offset >= segment_end) {
        return;
    }

    const auto split_index = static_cast<std::size_t>(offset - segment_offset);
    const auto split_index_difference = static_cast<std::ptrdiff_t>(split_index);
    auto tail = Segment{
        .state = it->second.state,
        .bytes = std::vector<std::byte>(it->second.bytes.begin() + split_index_difference,
                                        it->second.bytes.end()),
    };
    it->second.bytes.resize(split_index);
    segments_.emplace(offset, std::move(tail));
}

void ReliableSendBuffer::merge_adjacent_segments() {
    auto it = segments_.begin();
    while (it != segments_.end()) {
        auto next = std::next(it);
        if (next == segments_.end()) {
            break;
        }

        const auto expected_next_offset =
            it->first + static_cast<std::uint64_t>(it->second.bytes.size());
        if (it->second.state != next->second.state || expected_next_offset != next->first) {
            it = next;
            continue;
        }

        it->second.bytes.insert(it->second.bytes.end(), next->second.bytes.begin(),
                                next->second.bytes.end());
        segments_.erase(next);
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

    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const auto position = offset + i;
        if (position < next_contiguous_offset_) {
            continue;
        }

        buffered_bytes_.try_emplace(position, bytes[i]);
    }

    std::vector<std::byte> contiguous;
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
