#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

#include "src/quic/shared_bytes.h"
#include "src/quic/varint.h"

namespace coquic::quic {

struct PaddingFrame {
    std::size_t length = 1;
};

struct PingFrame {};

struct AckRange {
    std::uint64_t gap = 0;
    std::uint64_t range_length = 0;
};

struct AckEcnCounts {
    std::uint64_t ect0 = 0;
    std::uint64_t ect1 = 0;
    std::uint64_t ecn_ce = 0;
};

struct AckFrame {
    std::uint64_t largest_acknowledged = 0;
    std::uint64_t ack_delay = 0;
    std::uint64_t first_ack_range = 0;
    std::vector<AckRange> additional_ranges;
    std::optional<AckEcnCounts> ecn_counts;
};

struct ReceivedAckFrame {
    std::uint64_t largest_acknowledged = 0;
    std::uint64_t ack_delay = 0;
    std::uint64_t first_ack_range = 0;
    std::uint64_t additional_range_count = 0;
    SharedBytes additional_range_bytes;
    bool additional_ranges_validated = false;
    std::optional<AckEcnCounts> ecn_counts;
};

struct OutboundAckHeader {
    std::uint64_t largest_acknowledged = 0;
    std::uint64_t ack_delay = 0;
    std::uint64_t first_ack_range = 0;
    std::size_t additional_range_count = 0;
    std::vector<AckRange> additional_ranges;
    std::optional<AckEcnCounts> ecn_counts;
};

class ReceivedPacketHistory;

struct OutboundAckFrame {
    const ReceivedPacketHistory *history = nullptr;
    OutboundAckHeader header;
};

struct AckPacketNumberRange {
    std::uint64_t smallest = 0;
    std::uint64_t largest = 0;
    bool operator==(const AckPacketNumberRange &) const = default;
};

struct AckRangeCursor {
    std::uint64_t largest_acknowledged = 0;
    std::uint64_t first_ack_range = 0;
    std::span<const AckRange> additional_ranges;
    std::span<const std::byte> encoded_additional_ranges;
    std::size_t next_additional_index = 0;
    std::size_t next_encoded_offset = 0;
    std::uint64_t additional_range_count = 0;
    std::uint64_t previous_smallest = 0;
    bool first_range_pending = true;
    bool uses_encoded_additional_ranges = false;
};

struct ResetStreamFrame {
    std::uint64_t stream_id = 0;
    std::uint64_t application_protocol_error_code = 0;
    std::uint64_t final_size = 0;
};

struct StopSendingFrame {
    std::uint64_t stream_id = 0;
    std::uint64_t application_protocol_error_code = 0;
};

struct CryptoFrame {
    std::uint64_t offset = 0;
    std::vector<std::byte> crypto_data;
};

struct NewTokenFrame {
    std::vector<std::byte> token;
};

struct StreamFrame {
    bool fin = false;
    bool has_offset = false;
    bool has_length = false;
    std::uint64_t stream_id = 0;
    std::optional<std::uint64_t> offset;
    std::vector<std::byte> stream_data;
};

struct ReceivedCryptoFrame {
    std::uint64_t offset = 0;
    SharedBytes crypto_data;
};

struct ReceivedStreamFrame {
    bool fin = false;
    bool has_offset = false;
    bool has_length = false;
    std::uint64_t stream_id = 0;
    std::optional<std::uint64_t> offset;
    SharedBytes stream_data;
};

struct DatagramFrame {
    bool has_length = true;
    std::vector<std::byte> data;
};

struct ReceivedDatagramFrame {
    bool has_length = true;
    SharedBytes data;
};

struct MaxDataFrame {
    std::uint64_t maximum_data = 0;
};

struct MaxStreamDataFrame {
    std::uint64_t stream_id = 0;
    std::uint64_t maximum_stream_data = 0;
};

enum class StreamLimitType : std::uint8_t {
    bidirectional,
    unidirectional,
};

struct MaxStreamsFrame {
    StreamLimitType stream_type = StreamLimitType::bidirectional;
    std::uint64_t maximum_streams = 0;
};

struct DataBlockedFrame {
    std::uint64_t maximum_data = 0;
};

struct StreamDataBlockedFrame {
    std::uint64_t stream_id = 0;
    std::uint64_t maximum_stream_data = 0;
};

struct StreamsBlockedFrame {
    StreamLimitType stream_type = StreamLimitType::bidirectional;
    std::uint64_t maximum_streams = 0;
};

struct NewConnectionIdFrame {
    std::uint64_t sequence_number = 0;
    std::uint64_t retire_prior_to = 0;
    std::vector<std::byte> connection_id;
    std::array<std::byte, 16> stateless_reset_token{};
};

struct RetireConnectionIdFrame {
    std::uint64_t sequence_number = 0;
};

struct PathChallengeFrame {
    std::array<std::byte, 8> data{};
};

struct PathResponseFrame {
    std::array<std::byte, 8> data{};
};

struct ConnectionCloseReason {
    std::vector<std::byte> bytes;
};

struct TransportConnectionCloseFrame {
    std::uint64_t error_code = 0;
    std::uint64_t frame_type = 0;
    ConnectionCloseReason reason;
};

struct ApplicationConnectionCloseFrame {
    std::uint64_t error_code = 0;
    ConnectionCloseReason reason;
};

struct HandshakeDoneFrame {};

using Frame =
    std::variant<PaddingFrame, PingFrame, AckFrame, ResetStreamFrame, StopSendingFrame, CryptoFrame,
                 NewTokenFrame, StreamFrame, DatagramFrame, MaxDataFrame, MaxStreamDataFrame,
                 MaxStreamsFrame, DataBlockedFrame, StreamDataBlockedFrame, StreamsBlockedFrame,
                 NewConnectionIdFrame, RetireConnectionIdFrame, PathChallengeFrame,
                 PathResponseFrame, TransportConnectionCloseFrame, ApplicationConnectionCloseFrame,
                 HandshakeDoneFrame, OutboundAckFrame>;

using ReceivedFrame =
    std::variant<PaddingFrame, PingFrame, ReceivedAckFrame, ResetStreamFrame, StopSendingFrame,
                 ReceivedCryptoFrame, NewTokenFrame, ReceivedStreamFrame, ReceivedDatagramFrame,
                 MaxDataFrame, MaxStreamDataFrame, MaxStreamsFrame, DataBlockedFrame,
                 StreamDataBlockedFrame, StreamsBlockedFrame, NewConnectionIdFrame,
                 RetireConnectionIdFrame, PathChallengeFrame, PathResponseFrame,
                 TransportConnectionCloseFrame, ApplicationConnectionCloseFrame,
                 HandshakeDoneFrame>;

class ReceivedFrameList {
  public:
    ReceivedFrameList() = default;

    ReceivedFrameList(std::initializer_list<ReceivedFrame> frames) {
        *this = frames;
    }

    explicit ReceivedFrameList(std::vector<ReceivedFrame> frames) {
        *this = std::move(frames);
    }

    ReceivedFrameList &operator=(std::initializer_list<ReceivedFrame> frames) {
        clear();
        if (frames.size() == 0) {
            return *this;
        }
        if (frames.size() == 1) {
            inline_frame_ = *frames.begin();
            size_ = 1;
            return *this;
        }
        overflow_frames_.assign(frames.begin(), frames.end());
        size_ = overflow_frames_.size();
        return *this;
    }

    ReceivedFrameList &operator=(const std::vector<ReceivedFrame> &frames) {
        clear();
        if (frames.empty()) {
            return *this;
        }
        if (frames.size() == 1) {
            inline_frame_ = frames.front();
            size_ = 1;
            return *this;
        }
        overflow_frames_ = frames;
        size_ = overflow_frames_.size();
        return *this;
    }

    ReceivedFrameList &operator=(std::vector<ReceivedFrame> &&frames) {
        clear();
        if (frames.empty()) {
            return *this;
        }
        if (frames.size() == 1) {
            inline_frame_ = std::move(frames.front());
            size_ = 1;
            return *this;
        }
        overflow_frames_ = std::move(frames);
        size_ = overflow_frames_.size();
        return *this;
    }

    bool empty() const {
        return size() == 0;
    }

    std::size_t size() const {
        return overflow_frames_.empty() ? size_ : overflow_frames_.size();
    }

    void clear() {
        overflow_frames_.clear();
        size_ = 0;
    }

    void reserve(std::size_t capacity) {
        if (capacity <= 1) {
            return;
        }
        ensure_overflow();
        overflow_frames_.reserve(capacity);
    }

    void push_back(const ReceivedFrame &frame) {
        emplace_back(frame);
    }

    void push_back(ReceivedFrame &&frame) {
        emplace_back(std::move(frame));
    }

    template <typename... Args> ReceivedFrame &emplace_back(Args &&...args) {
        if (overflow_frames_.empty() && size_ == 0) {
            inline_frame_ = ReceivedFrame(std::forward<Args>(args)...);
            size_ = 1;
            return inline_frame_;
        }

        ensure_overflow();
        auto &frame = overflow_frames_.emplace_back(std::forward<Args>(args)...);
        size_ = overflow_frames_.size();
        return frame;
    }

    ReceivedFrame &front() {
        return (*this)[0];
    }

    const ReceivedFrame &front() const {
        return (*this)[0];
    }

    ReceivedFrame &operator[](std::size_t index) {
        return data()[index];
    }

    const ReceivedFrame &operator[](std::size_t index) const {
        return data()[index];
    }

    ReceivedFrame *data() {
        return overflow_frames_.empty() ? &inline_frame_ : overflow_frames_.data();
    }

    const ReceivedFrame *data() const {
        return overflow_frames_.empty() ? &inline_frame_ : overflow_frames_.data();
    }

    ReceivedFrame *begin() {
        return data();
    }

    const ReceivedFrame *begin() const {
        return data();
    }

    const ReceivedFrame *cbegin() const {
        return begin();
    }

    ReceivedFrame *end() {
        return data() + size();
    }

    const ReceivedFrame *end() const {
        return data() + size();
    }

    const ReceivedFrame *cend() const {
        return end();
    }

    std::span<ReceivedFrame> span() {
        return {data(), size()};
    }

    std::span<const ReceivedFrame> span() const {
        return {data(), size()};
    }

    operator std::span<const ReceivedFrame>() const {
        return span();
    }

    operator std::vector<ReceivedFrame>() const {
        return {begin(), end()};
    }

  private:
    void ensure_overflow() {
        if (!overflow_frames_.empty()) {
            return;
        }
        if (size_ == 1) {
            overflow_frames_.push_back(std::move(inline_frame_));
        }
    }

    ReceivedFrame inline_frame_;
    std::size_t size_ = 0;
    std::vector<ReceivedFrame> overflow_frames_;
};

struct FrameDecodeResult {
    Frame frame;
    std::size_t bytes_consumed = 0;
};

struct ReceivedFrameDecodeResult {
    ReceivedFrame frame;
    std::size_t bytes_consumed = 0;
};

struct ReceivedAckFrameDecodeResult {
    ReceivedAckFrame frame;
    std::size_t bytes_consumed = 0;
};

CodecResult<std::vector<AckPacketNumberRange>> ack_frame_packet_number_ranges(const AckFrame &ack);
CodecResult<AckRangeCursor> make_ack_range_cursor(const AckFrame &ack);
CodecResult<AckRangeCursor> make_ack_range_cursor(AckFrame &&ack) = delete;
CodecResult<AckRangeCursor> make_ack_range_cursor(const AckFrame &&ack) = delete;
CodecResult<AckRangeCursor> make_ack_range_cursor(const ReceivedAckFrame &ack);
CodecResult<AckRangeCursor> make_ack_range_cursor(ReceivedAckFrame &&ack) = delete;
std::optional<AckPacketNumberRange> next_ack_range(AckRangeCursor &cursor);
CodecResult<std::size_t> frame_wire_size(const Frame &frame);
CodecResult<std::size_t> write_frame_wire_bytes(std::span<std::byte> output, const Frame &frame);
CodecResult<std::size_t> serialized_frame_size(const Frame &frame);
CodecResult<std::size_t> serialize_frame_into(std::span<std::byte> output, const Frame &frame);
CodecResult<std::vector<std::byte>> serialize_frame(const Frame &frame);
CodecResult<std::size_t> append_serialized_frame(std::vector<std::byte> &bytes, const Frame &frame);
CodecResult<FrameDecodeResult> deserialize_frame(std::span<const std::byte> bytes);
CodecResult<ReceivedFrameDecodeResult> deserialize_received_frame(const SharedBytes &bytes);
CodecResult<ReceivedAckFrameDecodeResult> deserialize_received_ack_frame(const SharedBytes &bytes);

} // namespace coquic::quic
