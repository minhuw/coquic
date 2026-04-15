#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/frame.h"

namespace {

using coquic::quic::AckEcnCounts;
using coquic::quic::AckFrame;
using coquic::quic::AckRange;
using coquic::quic::ApplicationConnectionCloseFrame;
using coquic::quic::CodecErrorCode;
using coquic::quic::ConnectionCloseReason;
using coquic::quic::CryptoFrame;
using coquic::quic::DataBlockedFrame;
using coquic::quic::Frame;
using coquic::quic::HandshakeDoneFrame;
using coquic::quic::MaxDataFrame;
using coquic::quic::MaxStreamDataFrame;
using coquic::quic::MaxStreamsFrame;
using coquic::quic::NewConnectionIdFrame;
using coquic::quic::NewTokenFrame;
using coquic::quic::PaddingFrame;
using coquic::quic::PathChallengeFrame;
using coquic::quic::PathResponseFrame;
using coquic::quic::PingFrame;
using coquic::quic::ResetStreamFrame;
using coquic::quic::RetireConnectionIdFrame;
using coquic::quic::StopSendingFrame;
using coquic::quic::StreamDataBlockedFrame;
using coquic::quic::StreamFrame;
using coquic::quic::StreamLimitType;
using coquic::quic::StreamsBlockedFrame;
using coquic::quic::TransportConnectionCloseFrame;

constexpr std::uint64_t kMaxQuicVarInt = 4611686018427387903ull;
constexpr std::uint64_t kInvalidQuicVarInt = kMaxQuicVarInt + 1;

template <std::size_t N> std::span<const std::byte> as_span(const std::array<std::byte, N> &bytes) {
    return std::span<const std::byte>(bytes.data(), bytes.size());
}

void expect_decode_error(std::span<const std::byte> bytes, CodecErrorCode code) {
    const auto decoded = coquic::quic::deserialize_frame(bytes);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, code);
}

void expect_serialize_error(const Frame &frame, CodecErrorCode code) {
    const auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, code);
}

TEST(QuicFrameTest, AppendSerializedFrameMatchesStandaloneSerialization) {
    const std::vector<Frame> frames = {
        AckFrame{
            .largest_acknowledged = 42,
            .ack_delay = 7,
            .first_ack_range = 3,
            .additional_ranges =
                {
                    AckRange{
                        .gap = 1,
                        .range_length = 0,
                    },
                },
        },
        CryptoFrame{
            .offset = 9,
            .crypto_data = {std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}},
        },
        MaxDataFrame{
            .maximum_data = 4096,
        },
        NewConnectionIdFrame{
            .sequence_number = 3,
            .retire_prior_to = 1,
            .connection_id = {std::byte{0x10}, std::byte{0x11}, std::byte{0x12}},
            .stateless_reset_token =
                {
                    std::byte{0x00},
                    std::byte{0x01},
                    std::byte{0x02},
                    std::byte{0x03},
                    std::byte{0x04},
                    std::byte{0x05},
                    std::byte{0x06},
                    std::byte{0x07},
                    std::byte{0x08},
                    std::byte{0x09},
                    std::byte{0x0a},
                    std::byte{0x0b},
                    std::byte{0x0c},
                    std::byte{0x0d},
                    std::byte{0x0e},
                    std::byte{0x0f},
                },
        },
        ApplicationConnectionCloseFrame{
            .error_code = 0x1234,
            .reason =
                ConnectionCloseReason{
                    .bytes = {std::byte{0x61}, std::byte{0x62}, std::byte{0x63}},
                },
        },
        HandshakeDoneFrame{},
    };

    std::vector<std::byte> appended_bytes;
    std::vector<std::byte> standalone_bytes;
    for (const auto &frame : frames) {
        const auto appended = coquic::quic::append_serialized_frame(appended_bytes, frame);
        ASSERT_TRUE(appended.has_value());

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());
        standalone_bytes.insert(standalone_bytes.end(), encoded.value().begin(),
                                encoded.value().end());
    }

    EXPECT_EQ(appended_bytes, standalone_bytes);
}

TEST(QuicFrameTest, SerializesAndDeserializesPing) {
    Frame frame = PingFrame{};

    auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());
    ASSERT_EQ(encoded.value().size(), 1u);
    EXPECT_EQ(encoded.value()[0], std::byte{0x01});

    auto decoded = coquic::quic::deserialize_frame(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<PingFrame>(decoded.value().frame));
}

TEST(QuicFrameTest, CoalescesPaddingRuns) {
    std::array<std::byte, 3> bytes{
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x00},
    };

    auto decoded = coquic::quic::deserialize_frame(bytes);
    ASSERT_TRUE(decoded.has_value());
    const auto *padding = std::get_if<PaddingFrame>(&decoded.value().frame);
    ASSERT_NE(padding, nullptr);
    EXPECT_EQ(padding->length, 3u);

    auto reencoded = coquic::quic::serialize_frame(decoded.value().frame);
    ASSERT_TRUE(reencoded.has_value());
    EXPECT_EQ(reencoded.value(), std::vector<std::byte>(bytes.begin(), bytes.end()));
}

TEST(QuicFrameTest, DeserializesSingleBytePaddingRun) {
    const std::array<std::byte, 1> bytes{std::byte{0x00}};

    const auto decoded = coquic::quic::deserialize_frame(bytes);
    ASSERT_TRUE(decoded.has_value());

    const auto *padding = std::get_if<PaddingFrame>(&decoded.value().frame);
    ASSERT_NE(padding, nullptr);
    EXPECT_EQ(padding->length, 1u);
    EXPECT_EQ(decoded.value().bytes_consumed, 1u);
}

TEST(QuicFrameTest, StopsPaddingRunBeforeNextFrameType) {
    std::array<std::byte, 3> bytes{
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x01},
    };

    auto decoded = coquic::quic::deserialize_frame(bytes);
    ASSERT_TRUE(decoded.has_value());

    const auto *padding = std::get_if<PaddingFrame>(&decoded.value().frame);
    ASSERT_NE(padding, nullptr);
    EXPECT_EQ(padding->length, 2u);
    EXPECT_EQ(decoded.value().bytes_consumed, 2u);
}

TEST(QuicFrameTest, RoundTripsAckWithoutEcn) {
    Frame frame = AckFrame{
        .largest_acknowledged = 42,
        .ack_delay = 7,
        .first_ack_range = 3,
        .additional_ranges =
            {
                AckRange{
                    .gap = 1,
                    .range_length = 0,
                },
            },
    };

    auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_frame(encoded.value());
    ASSERT_TRUE(decoded.has_value());

    const auto *ack = std::get_if<AckFrame>(&decoded.value().frame);
    ASSERT_NE(ack, nullptr);
    EXPECT_FALSE(ack->ecn_counts.has_value());
    EXPECT_EQ(ack->largest_acknowledged, 42u);
    ASSERT_EQ(ack->additional_ranges.size(), 1u);
    EXPECT_EQ(ack->additional_ranges[0].gap, 1u);
}

TEST(QuicFrameTest, RoundTripsAckWithEcn) {
    Frame frame = AckFrame{
        .largest_acknowledged = 12,
        .ack_delay = 1,
        .first_ack_range = 0,
        .ecn_counts =
            AckEcnCounts{
                .ect0 = 5,
                .ect1 = 6,
                .ecn_ce = 7,
            },
    };

    auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_frame(encoded.value());
    ASSERT_TRUE(decoded.has_value());

    const auto *ack = std::get_if<AckFrame>(&decoded.value().frame);
    ASSERT_NE(ack, nullptr);
    if (!ack->ecn_counts.has_value()) {
        FAIL() << "expected ECN counts";
    }
    const auto ecn_counts = *ack->ecn_counts;
    EXPECT_EQ(ecn_counts.ect0, 5u);
    EXPECT_EQ(ecn_counts.ect1, 6u);
    EXPECT_EQ(ecn_counts.ecn_ce, 7u);
}

TEST(QuicFrameTest, RoundTripsCryptoFrame) {
    Frame frame = CryptoFrame{
        .offset = 9,
        .crypto_data = {std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}},
    };

    auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_frame(encoded.value());
    ASSERT_TRUE(decoded.has_value());

    const auto *crypto = std::get_if<CryptoFrame>(&decoded.value().frame);
    ASSERT_NE(crypto, nullptr);
    EXPECT_EQ(crypto->offset, 9u);
    EXPECT_EQ(crypto->crypto_data.size(), 3u);
}

TEST(QuicFrameTest, RoundTripsStreamFrameWithFlags) {
    Frame frame = StreamFrame{
        .fin = true,
        .has_offset = true,
        .has_length = true,
        .stream_id = 5,
        .offset = 11,
        .stream_data = {std::byte{0x10}, std::byte{0x11}},
    };

    auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_frame(encoded.value());
    ASSERT_TRUE(decoded.has_value());

    const auto *stream = std::get_if<StreamFrame>(&decoded.value().frame);
    ASSERT_NE(stream, nullptr);
    EXPECT_TRUE(stream->fin);
    EXPECT_TRUE(stream->has_offset);
    EXPECT_TRUE(stream->has_length);
    if (!stream->offset.has_value()) {
        FAIL() << "expected stream offset";
    }
    const auto offset = *stream->offset;
    EXPECT_EQ(offset, 11u);
    EXPECT_EQ(stream->stream_data.size(), 2u);
}

TEST(QuicFrameTest, RoundTripsStreamFrameWithoutOffsetOrLength) {
    Frame frame = StreamFrame{
        .stream_id = 7,
        .stream_data = {std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}},
    };

    auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_frame(encoded.value());
    ASSERT_TRUE(decoded.has_value());

    const auto *stream = std::get_if<StreamFrame>(&decoded.value().frame);
    ASSERT_NE(stream, nullptr);
    EXPECT_FALSE(stream->fin);
    EXPECT_FALSE(stream->has_offset);
    EXPECT_FALSE(stream->has_length);
    EXPECT_FALSE(stream->offset.has_value());
    EXPECT_EQ(stream->stream_data,
              (std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}}));
}

TEST(QuicFrameTest, RoundTripsTransportConnectionClose) {
    Frame frame = TransportConnectionCloseFrame{
        .error_code = 3,
        .frame_type = 0x06,
        .reason =
            ConnectionCloseReason{
                .bytes = {std::byte{'b'}, std::byte{'a'}, std::byte{'d'}},
            },
    };

    auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_frame(encoded.value());
    ASSERT_TRUE(decoded.has_value());

    const auto *close = std::get_if<TransportConnectionCloseFrame>(&decoded.value().frame);
    ASSERT_NE(close, nullptr);
    EXPECT_EQ(close->frame_type, 0x06u);
    EXPECT_EQ(close->reason.bytes.size(), 3u);
}

TEST(QuicFrameTest, RoundTripsApplicationConnectionClose) {
    Frame frame = ApplicationConnectionCloseFrame{
        .error_code = 9,
        .reason =
            ConnectionCloseReason{
                .bytes = {std::byte{'n'}, std::byte{'o'}},
            },
    };

    auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_frame(encoded.value());
    ASSERT_TRUE(decoded.has_value());

    const auto *close = std::get_if<ApplicationConnectionCloseFrame>(&decoded.value().frame);
    ASSERT_NE(close, nullptr);
    EXPECT_EQ(close->error_code, 9u);
    EXPECT_EQ(close->reason.bytes.size(), 2u);
}

TEST(QuicFrameTest, RoundTripsNewConnectionId) {
    Frame frame = NewConnectionIdFrame{
        .sequence_number = 4,
        .retire_prior_to = 1,
        .connection_id = {std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}},
        .stateless_reset_token = {std::byte{0x00}, std::byte{0x01}, std::byte{0x02},
                                  std::byte{0x03}, std::byte{0x04}, std::byte{0x05},
                                  std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
                                  std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
                                  std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e},
                                  std::byte{0x0f}},
    };

    auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_frame(encoded.value());
    ASSERT_TRUE(decoded.has_value());

    const auto *connection_id = std::get_if<NewConnectionIdFrame>(&decoded.value().frame);
    ASSERT_NE(connection_id, nullptr);
    EXPECT_EQ(connection_id->connection_id.size(), 3u);
    EXPECT_EQ(connection_id->retire_prior_to, 1u);
}

TEST(QuicFrameTest, RoundTripsPathChallenge) {
    Frame frame = PathChallengeFrame{
        .data = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                 std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}},
    };

    auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_frame(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<PathChallengeFrame>(decoded.value().frame));
}

TEST(QuicFrameTest, RoundTripsHandshakeDone) {
    Frame frame = HandshakeDoneFrame{};

    auto encoded = coquic::quic::serialize_frame(frame);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_frame(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<HandshakeDoneFrame>(decoded.value().frame));
}

TEST(QuicFrameTest, RejectsNonShortestFrameTypeEncoding) {
    std::array<std::byte, 2> bytes{std::byte{0x40}, std::byte{0x01}};
    auto decoded = coquic::quic::deserialize_frame(bytes);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::non_shortest_frame_type_encoding);
}

TEST(QuicFrameTest, RoundTripsResetAndStopSendingFrames) {
    {
        Frame frame = ResetStreamFrame{
            .stream_id = 7,
            .application_protocol_error_code = 11,
            .final_size = 13,
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *reset_stream = std::get_if<ResetStreamFrame>(&decoded.value().frame);
        ASSERT_NE(reset_stream, nullptr);
        EXPECT_EQ(reset_stream->stream_id, 7u);
        EXPECT_EQ(reset_stream->application_protocol_error_code, 11u);
        EXPECT_EQ(reset_stream->final_size, 13u);
    }

    {
        Frame frame = StopSendingFrame{
            .stream_id = 5,
            .application_protocol_error_code = 17,
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *stop_sending = std::get_if<StopSendingFrame>(&decoded.value().frame);
        ASSERT_NE(stop_sending, nullptr);
        EXPECT_EQ(stop_sending->stream_id, 5u);
        EXPECT_EQ(stop_sending->application_protocol_error_code, 17u);
    }
}

TEST(QuicFrameTest, RoundTripsTokenAndFlowControlFrames) {
    {
        Frame frame = NewTokenFrame{
            .token = {std::byte{0xa1}, std::byte{0xa2}},
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *new_token = std::get_if<NewTokenFrame>(&decoded.value().frame);
        ASSERT_NE(new_token, nullptr);
        EXPECT_EQ(new_token->token, (std::vector<std::byte>{std::byte{0xa1}, std::byte{0xa2}}));
    }

    {
        Frame frame = MaxDataFrame{
            .maximum_data = 123,
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *max_data = std::get_if<MaxDataFrame>(&decoded.value().frame);
        ASSERT_NE(max_data, nullptr);
        EXPECT_EQ(max_data->maximum_data, 123u);
    }

    {
        Frame frame = MaxStreamDataFrame{
            .stream_id = 3,
            .maximum_stream_data = 321,
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *max_stream_data = std::get_if<MaxStreamDataFrame>(&decoded.value().frame);
        ASSERT_NE(max_stream_data, nullptr);
        EXPECT_EQ(max_stream_data->stream_id, 3u);
        EXPECT_EQ(max_stream_data->maximum_stream_data, 321u);
    }

    {
        Frame frame = MaxStreamsFrame{
            .stream_type = StreamLimitType::bidirectional,
            .maximum_streams = 9,
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *max_streams = std::get_if<MaxStreamsFrame>(&decoded.value().frame);
        ASSERT_NE(max_streams, nullptr);
        EXPECT_EQ(max_streams->stream_type, StreamLimitType::bidirectional);
        EXPECT_EQ(max_streams->maximum_streams, 9u);
    }

    {
        Frame frame = MaxStreamsFrame{
            .stream_type = StreamLimitType::unidirectional,
            .maximum_streams = 10,
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *max_streams = std::get_if<MaxStreamsFrame>(&decoded.value().frame);
        ASSERT_NE(max_streams, nullptr);
        EXPECT_EQ(max_streams->stream_type, StreamLimitType::unidirectional);
        EXPECT_EQ(max_streams->maximum_streams, 10u);
    }

    {
        Frame frame = DataBlockedFrame{
            .maximum_data = 777,
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *data_blocked = std::get_if<DataBlockedFrame>(&decoded.value().frame);
        ASSERT_NE(data_blocked, nullptr);
        EXPECT_EQ(data_blocked->maximum_data, 777u);
    }

    {
        Frame frame = StreamDataBlockedFrame{
            .stream_id = 8,
            .maximum_stream_data = 999,
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *stream_data_blocked =
            std::get_if<StreamDataBlockedFrame>(&decoded.value().frame);
        ASSERT_NE(stream_data_blocked, nullptr);
        EXPECT_EQ(stream_data_blocked->stream_id, 8u);
        EXPECT_EQ(stream_data_blocked->maximum_stream_data, 999u);
    }

    {
        Frame frame = StreamsBlockedFrame{
            .stream_type = StreamLimitType::bidirectional,
            .maximum_streams = 12,
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *streams_blocked = std::get_if<StreamsBlockedFrame>(&decoded.value().frame);
        ASSERT_NE(streams_blocked, nullptr);
        EXPECT_EQ(streams_blocked->stream_type, StreamLimitType::bidirectional);
        EXPECT_EQ(streams_blocked->maximum_streams, 12u);
    }

    {
        Frame frame = StreamsBlockedFrame{
            .stream_type = StreamLimitType::unidirectional,
            .maximum_streams = 13,
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *streams_blocked = std::get_if<StreamsBlockedFrame>(&decoded.value().frame);
        ASSERT_NE(streams_blocked, nullptr);
        EXPECT_EQ(streams_blocked->stream_type, StreamLimitType::unidirectional);
        EXPECT_EQ(streams_blocked->maximum_streams, 13u);
    }
}

TEST(QuicFrameTest, RoundTripsRetireConnectionIdAndPathResponseFrames) {
    {
        Frame frame = RetireConnectionIdFrame{
            .sequence_number = 6,
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *retire = std::get_if<RetireConnectionIdFrame>(&decoded.value().frame);
        ASSERT_NE(retire, nullptr);
        EXPECT_EQ(retire->sequence_number, 6u);
    }

    {
        Frame frame = PathResponseFrame{
            .data = {std::byte{0x10}, std::byte{0x11}, std::byte{0x12}, std::byte{0x13},
                     std::byte{0x14}, std::byte{0x15}, std::byte{0x16}, std::byte{0x17}},
        };

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());

        const auto *path_response = std::get_if<PathResponseFrame>(&decoded.value().frame);
        ASSERT_NE(path_response, nullptr);
        EXPECT_EQ(path_response->data[7], std::byte{0x17});
    }
}

TEST(QuicFrameTest, DeserializesStreamFrameWithoutLengthUsingRemainingBytes) {
    const std::array<std::byte, 6> bytes{
        std::byte{0x0d}, std::byte{0x05}, std::byte{0x03},
        std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc},
    };

    const auto decoded = coquic::quic::deserialize_frame(bytes);
    ASSERT_TRUE(decoded.has_value());

    const auto *stream = std::get_if<StreamFrame>(&decoded.value().frame);
    ASSERT_NE(stream, nullptr);
    EXPECT_TRUE(stream->fin);
    EXPECT_TRUE(stream->has_offset);
    EXPECT_FALSE(stream->has_length);
    ASSERT_TRUE(stream->offset.has_value());
    EXPECT_EQ(stream->offset.value_or(0), 3u);
    EXPECT_EQ(stream->stream_data,
              (std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}}));
}

TEST(QuicFrameTest, RoundTripsStreamFramesAcrossFlagVariants) {
    struct StreamVariantCase {
        std::byte expected_type;
        StreamFrame frame;
    };

    const std::array<StreamVariantCase, 7> cases{{
        {
            .expected_type = std::byte{0x08},
            .frame =
                StreamFrame{
                    .stream_id = 1,
                    .stream_data = {std::byte{0xaa}, std::byte{0xbb}},
                },
        },
        {
            .expected_type = std::byte{0x09},
            .frame =
                StreamFrame{
                    .fin = true,
                    .stream_id = 2,
                    .stream_data = {std::byte{0xaa}},
                },
        },
        {
            .expected_type = std::byte{0x0a},
            .frame =
                StreamFrame{
                    .has_length = true,
                    .stream_id = 3,
                    .stream_data = {std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}},
                },
        },
        {
            .expected_type = std::byte{0x0b},
            .frame =
                StreamFrame{
                    .fin = true,
                    .has_length = true,
                    .stream_id = 4,
                    .stream_data = {std::byte{0xaa}, std::byte{0xbb}},
                },
        },
        {
            .expected_type = std::byte{0x0c},
            .frame =
                StreamFrame{
                    .has_offset = true,
                    .stream_id = 5,
                    .offset = 7,
                    .stream_data = {std::byte{0xaa}, std::byte{0xbb}},
                },
        },
        {
            .expected_type = std::byte{0x0d},
            .frame =
                StreamFrame{
                    .fin = true,
                    .has_offset = true,
                    .stream_id = 6,
                    .offset = 8,
                    .stream_data = {std::byte{0xaa}},
                },
        },
        {
            .expected_type = std::byte{0x0e},
            .frame =
                StreamFrame{
                    .has_offset = true,
                    .has_length = true,
                    .stream_id = 7,
                    .offset = 9,
                    .stream_data = {std::byte{0xaa}, std::byte{0xbb}},
                },
        },
    }};

    for (const auto &test_case : cases) {
        const Frame frame = test_case.frame;

        const auto encoded = coquic::quic::serialize_frame(frame);
        ASSERT_TRUE(encoded.has_value());
        ASSERT_FALSE(encoded.value().empty());
        EXPECT_EQ(encoded.value().front(), test_case.expected_type);

        const auto decoded = coquic::quic::deserialize_frame(encoded.value());
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(decoded.value().bytes_consumed, encoded.value().size());

        const auto *stream = std::get_if<StreamFrame>(&decoded.value().frame);
        ASSERT_NE(stream, nullptr);
        EXPECT_EQ(stream->fin, test_case.frame.fin);
        EXPECT_EQ(stream->has_offset, test_case.frame.has_offset);
        EXPECT_EQ(stream->has_length, test_case.frame.has_length);
        EXPECT_EQ(stream->stream_id, test_case.frame.stream_id);
        EXPECT_EQ(stream->offset, test_case.frame.offset);
        EXPECT_EQ(stream->stream_data, test_case.frame.stream_data);
    }
}

TEST(QuicFrameTest, RejectsMalformedAckFrames) {
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x02}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x02}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 3>{std::byte{0x02}, std::byte{0x00}, std::byte{0x00}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 4>{std::byte{0x02}, std::byte{0x00},
                                                         std::byte{0x00}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0x02}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x02}}),
        CodecErrorCode::invalid_varint);
    expect_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0x02}, std::byte{0x02}, std::byte{0x00},
                                         std::byte{0x01}, std::byte{0x00}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0x02}, std::byte{0x02}, std::byte{0x00},
                                         std::byte{0x01}, std::byte{0x00}, std::byte{0x00}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 7>{
                            std::byte{0x02}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
                            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}}),
                        CodecErrorCode::invalid_varint);
    expect_decode_error(as_span(std::array<std::byte, 7>{
                            std::byte{0x02}, std::byte{0x03}, std::byte{0x00}, std::byte{0x01},
                            std::byte{0x00}, std::byte{0x00}, std::byte{0x02}}),
                        CodecErrorCode::invalid_varint);
    expect_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0x03}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0x03}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 7>{
                            std::byte{0x03}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
}

TEST(QuicFrameTest, RejectsInvalidAckFrameSerializationInputs) {
    expect_serialize_error(
        AckFrame{
            .largest_acknowledged = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        AckFrame{
            .largest_acknowledged = 1,
            .ack_delay = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        AckFrame{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        AckFrame{
            .largest_acknowledged = 1,
            .first_ack_range = 2,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        AckFrame{
            .largest_acknowledged = 1,
            .first_ack_range = 0,
            .additional_ranges =
                {
                    AckRange{
                        .gap = 0,
                        .range_length = 0,
                    },
                },
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        AckFrame{
            .largest_acknowledged = 3,
            .first_ack_range = 0,
            .additional_ranges =
                {
                    AckRange{
                        .gap = 0,
                        .range_length = 2,
                    },
                },
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        AckFrame{
            .largest_acknowledged = 1,
            .ecn_counts =
                AckEcnCounts{
                    .ect0 = kInvalidQuicVarInt,
                },
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        AckFrame{
            .largest_acknowledged = 1,
            .ecn_counts =
                AckEcnCounts{
                    .ect0 = 0,
                    .ect1 = kInvalidQuicVarInt,
                },
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        AckFrame{
            .largest_acknowledged = 1,
            .ecn_counts =
                AckEcnCounts{
                    .ect0 = 0,
                    .ect1 = 0,
                    .ecn_ce = kInvalidQuicVarInt,
                },
        },
        CodecErrorCode::invalid_varint);
}

TEST(QuicFrameTest, RejectsMalformedResetAndStopSendingFrames) {
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x04}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x04}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 3>{std::byte{0x04}, std::byte{0x00}, std::byte{0x00}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x05}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x05}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
}

TEST(QuicFrameTest, RejectsMalformedCryptoTokenAndStreamFrames) {
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x06}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 3>{std::byte{0x06}, std::byte{0x00}, std::byte{0x01}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 11>{
                            std::byte{0x06},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0x01},
                            std::byte{0xaa},
                        }),
                        CodecErrorCode::invalid_varint);
    expect_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x07}, std::byte{0x00}}),
                        CodecErrorCode::invalid_varint);
    expect_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x07}, std::byte{0x40}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x08}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x0c}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 3>{std::byte{0x0a}, std::byte{0x00}, std::byte{0x01}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 12>{
                            std::byte{0x0e},
                            std::byte{0x00},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0xff},
                            std::byte{0x01},
                            std::byte{0xaa},
                        }),
                        CodecErrorCode::invalid_varint);
}

TEST(QuicFrameTest, RejectsMalformedFlowControlConnectionIdAndCloseFrames) {
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x10}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x11}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x11}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 3>{std::byte{0x12}, std::byte{0xc0}, std::byte{0x00}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 9>{std::byte{0x12}, std::byte{0xd0}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x01}}),
        CodecErrorCode::invalid_varint);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x14}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x15}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x15}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 9>{std::byte{0x16}, std::byte{0xd0}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x01}}),
        CodecErrorCode::invalid_varint);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x18}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x18}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 3>{std::byte{0x18}, std::byte{0x00}, std::byte{0x00}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 4>{std::byte{0x18}, std::byte{0x00},
                                                         std::byte{0x00}, std::byte{0x00}}),
                        CodecErrorCode::invalid_varint);
    expect_decode_error(as_span(std::array<std::byte, 4>{std::byte{0x18}, std::byte{0x00},
                                                         std::byte{0x00}, std::byte{0x15}}),
                        CodecErrorCode::invalid_varint);
    expect_decode_error(as_span(std::array<std::byte, 4>{std::byte{0x18}, std::byte{0x01},
                                                         std::byte{0x02}, std::byte{0x01}}),
                        CodecErrorCode::invalid_varint);
    expect_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0x18}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x02}, std::byte{0xaa}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 7>{
                            std::byte{0x18}, std::byte{0x01}, std::byte{0x00}, std::byte{0x02},
                            std::byte{0xaa}, std::byte{0xbb}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x19}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 8>{
                            std::byte{0x1a}, std::byte{0x00}, std::byte{0x01}, std::byte{0x02},
                            std::byte{0x03}, std::byte{0x04}, std::byte{0x05}, std::byte{0x06}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 8>{
                            std::byte{0x1b}, std::byte{0x00}, std::byte{0x01}, std::byte{0x02},
                            std::byte{0x03}, std::byte{0x04}, std::byte{0x05}, std::byte{0x06}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x1c}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x1c}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(
        as_span(std::array<std::byte, 3>{std::byte{0x1c}, std::byte{0x00}, std::byte{0x00}}),
        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x1d}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x1d}, std::byte{0x00}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 0>{}), CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x16}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x40}}),
                        CodecErrorCode::truncated_input);
    expect_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x1f}}),
                        CodecErrorCode::unknown_frame_type);
}

TEST(QuicFrameTest, RejectsInvalidSerializationInputsAcrossFrameFamilies) {
    expect_serialize_error(
        PaddingFrame{
            .length = 0,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        CryptoFrame{
            .offset = kMaxQuicVarInt,
            .crypto_data = {std::byte{0x01}},
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        NewTokenFrame{
            .token = {},
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        StreamFrame{
            .stream_id = kInvalidQuicVarInt,
            .stream_data = {std::byte{0x01}},
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        StreamFrame{
            .has_offset = true,
            .offset = kMaxQuicVarInt,
            .stream_data = {std::byte{0x01}},
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        MaxStreamDataFrame{
            .stream_id = kInvalidQuicVarInt,
            .maximum_stream_data = 1,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        MaxStreamDataFrame{
            .stream_id = 1,
            .maximum_stream_data = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        MaxDataFrame{
            .maximum_data = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        MaxStreamsFrame{
            .maximum_streams = (1ull << 60) + 1,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        DataBlockedFrame{
            .maximum_data = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        StreamDataBlockedFrame{
            .stream_id = kInvalidQuicVarInt,
            .maximum_stream_data = 1,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        StreamDataBlockedFrame{
            .stream_id = 1,
            .maximum_stream_data = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        StreamsBlockedFrame{
            .maximum_streams = (1ull << 60) + 1,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        NewConnectionIdFrame{
            .connection_id = {},
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        NewConnectionIdFrame{
            .connection_id = std::vector<std::byte>(21, std::byte{0xaa}),
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        NewConnectionIdFrame{
            .sequence_number = 0,
            .retire_prior_to = 1,
            .connection_id = {std::byte{0xaa}},
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        NewConnectionIdFrame{
            .sequence_number = kInvalidQuicVarInt,
            .retire_prior_to = 0,
            .connection_id = {std::byte{0xaa}},
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        ResetStreamFrame{
            .stream_id = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        ResetStreamFrame{
            .stream_id = 0,
            .application_protocol_error_code = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        ResetStreamFrame{
            .stream_id = 0,
            .application_protocol_error_code = 0,
            .final_size = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        StopSendingFrame{
            .stream_id = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        StopSendingFrame{
            .stream_id = 0,
            .application_protocol_error_code = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        RetireConnectionIdFrame{
            .sequence_number = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        TransportConnectionCloseFrame{
            .error_code = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        TransportConnectionCloseFrame{
            .error_code = 1,
            .frame_type = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
    expect_serialize_error(
        ApplicationConnectionCloseFrame{
            .error_code = kInvalidQuicVarInt,
        },
        CodecErrorCode::invalid_varint);
}

} // namespace
