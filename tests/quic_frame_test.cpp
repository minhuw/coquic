#include <array>
#include <cstddef>
#include <variant>

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
using coquic::quic::Frame;
using coquic::quic::HandshakeDoneFrame;
using coquic::quic::NewConnectionIdFrame;
using coquic::quic::PaddingFrame;
using coquic::quic::PathChallengeFrame;
using coquic::quic::PingFrame;
using coquic::quic::StreamFrame;
using coquic::quic::TransportConnectionCloseFrame;

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

} // namespace
