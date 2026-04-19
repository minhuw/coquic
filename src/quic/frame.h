#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
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

struct OutboundAckHeader {
    std::uint64_t largest_acknowledged = 0;
    std::uint64_t ack_delay = 0;
    std::uint64_t first_ack_range = 0;
    std::size_t additional_range_count = 0;
    std::vector<AckRange> additional_ranges;
    std::optional<AckEcnCounts> ecn_counts;
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
    std::size_t next_additional_index = 0;
    std::uint64_t previous_smallest = 0;
    bool first_range_pending = true;
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
                 NewTokenFrame, StreamFrame, MaxDataFrame, MaxStreamDataFrame, MaxStreamsFrame,
                 DataBlockedFrame, StreamDataBlockedFrame, StreamsBlockedFrame,
                 NewConnectionIdFrame, RetireConnectionIdFrame, PathChallengeFrame,
                 PathResponseFrame, TransportConnectionCloseFrame, ApplicationConnectionCloseFrame,
                 HandshakeDoneFrame>;

using ReceivedFrame =
    std::variant<PaddingFrame, PingFrame, AckFrame, ResetStreamFrame, StopSendingFrame,
                 ReceivedCryptoFrame, NewTokenFrame, ReceivedStreamFrame, MaxDataFrame,
                 MaxStreamDataFrame, MaxStreamsFrame, DataBlockedFrame, StreamDataBlockedFrame,
                 StreamsBlockedFrame, NewConnectionIdFrame, RetireConnectionIdFrame,
                 PathChallengeFrame, PathResponseFrame, TransportConnectionCloseFrame,
                 ApplicationConnectionCloseFrame, HandshakeDoneFrame>;

struct FrameDecodeResult {
    Frame frame;
    std::size_t bytes_consumed = 0;
};

struct ReceivedFrameDecodeResult {
    ReceivedFrame frame;
    std::size_t bytes_consumed = 0;
};

CodecResult<std::vector<AckPacketNumberRange>> ack_frame_packet_number_ranges(const AckFrame &ack);
CodecResult<AckRangeCursor> make_ack_range_cursor(const AckFrame &ack);
CodecResult<AckRangeCursor> make_ack_range_cursor(AckFrame &&ack) = delete;
CodecResult<AckRangeCursor> make_ack_range_cursor(const AckFrame &&ack) = delete;
std::optional<AckPacketNumberRange> next_ack_range(AckRangeCursor &cursor);
CodecResult<std::size_t> serialized_frame_size(const Frame &frame);
CodecResult<std::size_t> serialize_frame_into(std::span<std::byte> output, const Frame &frame);
CodecResult<std::vector<std::byte>> serialize_frame(const Frame &frame);
CodecResult<std::size_t> append_serialized_frame(std::vector<std::byte> &bytes, const Frame &frame);
CodecResult<FrameDecodeResult> deserialize_frame(std::span<const std::byte> bytes);
CodecResult<ReceivedFrameDecodeResult> deserialize_received_frame(const SharedBytes &bytes);

} // namespace coquic::quic
