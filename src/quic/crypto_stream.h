#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "src/quic/frame.h"
#include "src/quic/shared_bytes.h"
#include "src/quic/varint.h"

namespace coquic::quic {

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
    void append(SharedBytes bytes);
    std::vector<ByteRange> take_ranges(std::size_t max_bytes);
    std::vector<ByteRange> take_lost_ranges(std::size_t max_bytes,
                                            std::optional<std::uint64_t> max_offset = std::nullopt);
    std::vector<ByteRange>
    take_unsent_ranges(std::size_t max_bytes,
                       std::optional<std::uint64_t> max_offset = std::nullopt);
    void acknowledge(std::uint64_t offset, std::size_t length);
    void mark_lost(std::uint64_t offset, std::size_t length);
    void mark_unsent(std::uint64_t offset, std::size_t length);
    void mark_sent(std::uint64_t offset, std::size_t length);
    bool has_pending_data() const;
    bool has_outstanding_data() const;
    bool has_outstanding_range(std::uint64_t offset, std::size_t length) const;
    bool has_lost_data() const;

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

    std::vector<ByteRange>
    take_ranges_by_state(SegmentState state, std::size_t &remaining_bytes,
                         std::optional<std::uint64_t> max_offset = std::nullopt);
    void split_at(std::uint64_t offset);
    void merge_adjacent_segments();

    std::map<std::uint64_t, Segment> segments_;
    std::uint64_t next_append_offset_ = 0;
};

class ReliableReceiveBuffer {
  public:
    CodecResult<ContiguousReceiveBytes> push_shared(std::uint64_t offset, SharedBytes bytes);
    CodecResult<std::vector<std::byte>> push(std::uint64_t offset, std::vector<std::byte> &&bytes);
    CodecResult<std::vector<std::byte>> push(std::uint64_t offset,
                                             std::span<const std::byte> bytes);

  private:
    void buffer_range(std::uint64_t offset, SharedBytes bytes);
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
