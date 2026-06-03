#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "src/quic/frame.h"
#include "src/quic/shared_bytes.h"
#include "src/quic/varint.h"

namespace coquic::quic {

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

struct ByteRange {
    std::uint64_t offset = 0;
    SharedBytes bytes;
};

struct ContiguousReceiveBytes {
    SharedBytes shared;
    std::vector<std::byte> owned;

    bool empty() const {
        return shared.empty() && owned.empty();
    }

    std::span<const std::byte> span() const {
        return shared.empty() ? std::span<const std::byte>(owned) : shared.span();
    }

    std::vector<std::byte> to_vector() const {
        return shared.empty() ? owned : shared.to_vector();
    }
};

class ReliableSendBuffer {
  public:
    void append(const std::vector<std::byte> &bytes);
    void append(std::span<const std::byte> bytes);
    void append(const SharedBytes &bytes);
    std::vector<ByteRange> take_ranges(std::size_t max_bytes);
    std::vector<ByteRange> take_lost_ranges(std::size_t max_bytes,
                                            std::optional<std::uint64_t> max_offset = std::nullopt);
    std::vector<ByteRange>
    take_unsent_ranges(std::size_t max_bytes,
                       std::optional<std::uint64_t> max_offset = std::nullopt);
    template <typename Callback>
    COQUIC_NO_PROFILE void consume_lost_ranges(std::size_t &remaining_bytes,
                                               std::optional<std::uint64_t> max_offset,
                                               Callback &&callback) {
        if (remaining_bytes == 0 ||
            segment_state_counts_[segment_state_index(SegmentState::lost)] == 0) {
            return;
        }

        if (consume_ranges_by_extending_previous_sent(SegmentState::lost, remaining_bytes,
                                                      max_offset, callback)) {
            return;
        }
        consume_ranges_by_state(SegmentState::lost, remaining_bytes, max_offset,
                                std::forward<Callback>(callback));
        merge_adjacent_segments();
    }
    template <typename Callback>
    COQUIC_NO_PROFILE void consume_unsent_ranges(std::size_t &remaining_bytes,
                                                 std::optional<std::uint64_t> max_offset,
                                                 Callback &&callback) {
        if (remaining_bytes == 0 ||
            segment_state_counts_[segment_state_index(SegmentState::unsent)] == 0) {
            return;
        }

        if (consume_ranges_by_extending_previous_sent(SegmentState::unsent, remaining_bytes,
                                                      max_offset, callback)) {
            return;
        }
        consume_ranges_by_state(SegmentState::unsent, remaining_bytes, max_offset,
                                std::forward<Callback>(callback));
        merge_adjacent_segments();
    }
    void acknowledge(std::uint64_t offset, std::size_t length);
    void mark_lost(std::uint64_t offset, std::size_t length);
    void mark_unsent(std::uint64_t offset, std::size_t length);
    void mark_sent(std::uint64_t offset, std::size_t length);
    std::optional<SharedBytes> bytes_for_range(std::uint64_t offset, std::size_t length) const;
    bool has_pending_data() const;
    bool has_outstanding_data() const;
    bool has_outstanding_range(std::uint64_t offset, std::size_t length) const;
    bool has_lost_data() const;
    std::optional<std::uint64_t> first_lost_offset() const;
    std::optional<std::uint64_t> first_unsent_offset() const;

  private:
    enum class SegmentState : std::uint8_t {
        unsent,
        sent,
        lost,
    };

    struct Segment {
        SegmentState state = SegmentState::unsent;
        std::shared_ptr<std::vector<std::byte>> storage;
        std::size_t begin = 0;
        std::size_t end = 0;
    };

    static constexpr std::size_t segment_state_index(SegmentState state) {
        return static_cast<std::size_t>(state);
    }

    void note_segment_inserted(const Segment &segment);
    void note_segment_erased(const Segment &segment);
    void transition_segment_state(Segment &segment, SegmentState new_state);
    std::vector<ByteRange>
    take_ranges_by_state(SegmentState state, std::size_t &remaining_bytes,
                         std::optional<std::uint64_t> max_offset = std::nullopt);
    std::optional<std::uint64_t> first_offset_by_state(SegmentState state) const;
    bool acknowledge_leading_sent_range(std::uint64_t offset, std::uint64_t end);
    template <typename Callback>
    COQUIC_NO_PROFILE bool
    consume_ranges_by_extending_previous_sent(SegmentState state, std::size_t &remaining_bytes,
                                              std::optional<std::uint64_t> max_offset,
                                              Callback &&callback) {
        const auto segment_length = [](const Segment &segment) {
            return segment.end - segment.begin;
        };

        for (auto it = segments_.begin(); it != segments_.end() && remaining_bytes > 0;) {
            if (it->second.state != state) {
                ++it;
                continue;
            }
            if (max_offset.has_value() && it->first >= *max_offset) {
                return true;
            }
            if (it == segments_.begin()) {
                return false;
            }

            auto previous = std::prev(it);
            const auto previous_end_offset =
                previous->first + static_cast<std::uint64_t>(segment_length(previous->second));
            const bool can_extend_previous_sent = previous->second.state == SegmentState::sent &&
                                                  previous_end_offset == it->first &&
                                                  previous->second.storage == it->second.storage &&
                                                  previous->second.end == it->second.begin;
            if (!can_extend_previous_sent) {
                return false;
            }

            const auto available_bytes = segment_length(it->second);
            const auto capped_available_bytes =
                max_offset.has_value()
                    ? static_cast<std::size_t>(std::min<std::uint64_t>(
                          static_cast<std::uint64_t>(available_bytes), *max_offset - it->first))
                    : available_bytes;
            if (capped_available_bytes == 0) {
                return true;
            }
            const auto chunk_size = std::min(remaining_bytes, capped_available_bytes);
            callback(ByteRange{
                .offset = it->first,
                .bytes =
                    SharedBytes{
                        it->second.storage,
                        it->second.begin,
                        it->second.begin + chunk_size,
                    },
            });

            previous->second.end = it->second.begin + chunk_size;
            remaining_bytes -= chunk_size;
            if (chunk_size == available_bytes) {
                note_segment_erased(it->second);
                it = segments_.erase(it);
                continue;
            }

            auto node = segments_.extract(it);
            node.key() += static_cast<std::uint64_t>(chunk_size);
            node.mapped().begin += chunk_size;
            segments_.insert(std::move(node));
            return true;
        }

        return true;
    }
    template <typename Callback>
    COQUIC_NO_PROFILE void consume_ranges_by_state(SegmentState state, std::size_t &remaining_bytes,
                                                   std::optional<std::uint64_t> max_offset,
                                                   Callback &&callback) {
        if (max_offset.has_value()) {
            split_at(*max_offset);
        }

        const auto segment_length = [](const Segment &segment) {
            return segment.end - segment.begin;
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
                .bytes =
                    SharedBytes{
                        it->second.storage,
                        it->second.begin,
                        it->second.begin + chunk_size,
                    },
            };
            callback(std::move(range));

            if (chunk_size == available_bytes) {
                transition_segment_state(it->second, SegmentState::sent);
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
            transition_segment_state(it->second, SegmentState::sent);
            const auto [tail_it, tail_inserted] = segments_.emplace(tail_offset, std::move(tail));
            if (tail_inserted) {
                note_segment_inserted(tail_it->second);
            }
            remaining_bytes -= chunk_size;
        }
    }
    void split_at(std::uint64_t offset);
    void merge_adjacent_segments();

    std::map<std::uint64_t, Segment> segments_;
    std::array<std::size_t, 3> segment_state_counts_{};
    std::uint64_t next_append_offset_ = 0;
};

class ReliableReceiveBuffer {
  public:
    CodecResult<ContiguousReceiveBytes> push_shared(std::uint64_t offset, const SharedBytes &bytes);
    CodecResult<std::vector<std::byte>> push(std::uint64_t offset, std::vector<std::byte> &&bytes);
    CodecResult<std::vector<std::byte>> push(std::uint64_t offset,
                                             std::span<const std::byte> bytes);

  private:
    void buffer_range(std::uint64_t offset, const SharedBytes &bytes);
    ContiguousReceiveBytes take_contiguous_buffered_bytes(ContiguousReceiveBytes contiguous);
    std::vector<std::byte> take_contiguous_buffered_bytes();

    std::uint64_t next_contiguous_offset_ = 0;
    std::map<std::uint64_t, SharedBytes> buffered_bytes_;
};

class CryptoSendBuffer {
  public:
    void append(std::span<const std::byte> bytes);
    std::vector<CryptoFrame> take_frames(std::size_t max_frame_payload_size);
    bool empty() const;

  private:
    ReliableSendBuffer reliable_;
};

class CryptoReceiveBuffer {
  public:
    CodecResult<std::vector<std::byte>> push(std::uint64_t offset,
                                             std::span<const std::byte> bytes);

  private:
    ReliableReceiveBuffer reliable_;
};

} // namespace coquic::quic
