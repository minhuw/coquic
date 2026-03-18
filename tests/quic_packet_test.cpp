#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/packet.h"

namespace {

using coquic::quic::AckFrame;
using coquic::quic::CodecErrorCode;
using coquic::quic::CryptoFrame;
using coquic::quic::HandshakePacket;
using coquic::quic::InitialPacket;
using coquic::quic::NewTokenFrame;
using coquic::quic::OneRttPacket;
using coquic::quic::Packet;
using coquic::quic::PaddingFrame;
using coquic::quic::PathChallengeFrame;
using coquic::quic::PingFrame;
using coquic::quic::RetryPacket;
using coquic::quic::StreamFrame;
using coquic::quic::TransportConnectionCloseFrame;
using coquic::quic::VersionNegotiationPacket;
using coquic::quic::ZeroRttPacket;

constexpr std::uint64_t kInvalidQuicVarInt = 4611686018427387904ull;

template <std::size_t N> std::span<const std::byte> as_span(const std::array<std::byte, N> &bytes) {
    return std::span<const std::byte>(bytes.data(), bytes.size());
}

void expect_packet_decode_error(std::span<const std::byte> bytes,
                                const coquic::quic::DeserializeOptions &options,
                                CodecErrorCode code) {
    const auto decoded = coquic::quic::deserialize_packet(bytes, options);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, code);
}

void expect_packet_decode_error(const std::vector<std::byte> &bytes,
                                const coquic::quic::DeserializeOptions &options,
                                CodecErrorCode code) {
    expect_packet_decode_error(std::span<const std::byte>(bytes.data(), bytes.size()), options,
                               code);
}

void expect_packet_serialize_error(const Packet &packet, CodecErrorCode code) {
    const auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, code);
}

TEST(QuicPacketTest, SerializesInitialPacketHeaderAndPayloadLength) {
    InitialPacket packet{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}, std::byte{0xbb}},
        .source_connection_id = {std::byte{0xcc}},
        .token = {},
        .packet_number_length = 2,
        .truncated_packet_number = 0x1234,
        .frames = {CryptoFrame{
            .offset = 0,
            .crypto_data = {std::byte{0x01}},
        }},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_packet(encoded.value(), {});
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<InitialPacket>(decoded.value().packet));
}

TEST(QuicPacketTest, RoundTripsVersionNegotiationPacket) {
    VersionNegotiationPacket packet{
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .supported_versions = {1u, 0x6b3343cfu},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_packet(encoded.value(), {});
    ASSERT_TRUE(decoded.has_value());
    const auto *version_negotiation =
        std::get_if<VersionNegotiationPacket>(&decoded.value().packet);
    ASSERT_NE(version_negotiation, nullptr);
    ASSERT_EQ(version_negotiation->supported_versions.size(), 2u);
    EXPECT_EQ(version_negotiation->supported_versions[1], 0x6b3343cfu);
}

TEST(QuicPacketTest, RoundTripsRetryPacket) {
    RetryPacket packet{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}, std::byte{0xbb}},
        .source_connection_id = {std::byte{0xcc}},
        .retry_token = {std::byte{0x10}, std::byte{0x11}},
        .retry_integrity_tag = {std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
                                std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
                                std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
                                std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f}},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_packet(encoded.value(), {});
    ASSERT_TRUE(decoded.has_value());
    const auto *retry = std::get_if<RetryPacket>(&decoded.value().packet);
    ASSERT_NE(retry, nullptr);
    EXPECT_EQ(retry->retry_token.size(), 2u);
    EXPECT_EQ(retry->retry_integrity_tag[15], std::byte{0x0f});
}

TEST(QuicPacketTest, RejectsAckFrameInZeroRttPacket) {
    ZeroRttPacket packet{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 7,
        .frames = {AckFrame{}},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, CodecErrorCode::frame_not_allowed_in_packet_type);
}

TEST(QuicPacketTest, AllowsHandshakeSafeFrameSubsetInHandshakePackets) {
    HandshakePacket packet{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames =
            {
                PingFrame{},
                CryptoFrame{
                    .offset = 0,
                    .crypto_data = {std::byte{0x01}},
                },
                AckFrame{},
                TransportConnectionCloseFrame{},
            },
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_packet(encoded.value(), {});
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<HandshakePacket>(decoded.value().packet));
}

TEST(QuicPacketTest, ParsesOneRttPacketWithContextLength) {
    coquic::quic::OneRttPacket packet{
        .spin_bit = true,
        .key_phase = true,
        .destination_connection_id = {std::byte{0xde}, std::byte{0xad}},
        .packet_number_length = 1,
        .truncated_packet_number = 9,
        .frames = {PathChallengeFrame{
            .data = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                     std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}},
        }},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_packet(
        encoded.value(), coquic::quic::DeserializeOptions{
                             .one_rtt_destination_connection_id_length = 2,
                         });
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<coquic::quic::OneRttPacket>(decoded.value().packet));
}

TEST(QuicPacketTest, RejectsReservedBitsInPlaintextPacketImage) {
    std::vector<std::byte> bytes{
        std::byte{0xcd}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x01}, std::byte{0xaa}, std::byte{0x01}, std::byte{0xbb}, std::byte{0x00},
        std::byte{0x02}, std::byte{0x01}, std::byte{0x01},
    };

    auto decoded = coquic::quic::deserialize_packet(bytes, {});
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::invalid_reserved_bits);
}

TEST(QuicPacketTest, RejectsLongHeaderConnectionIdOverLimit) {
    InitialPacket packet{
        .version = 1,
        .destination_connection_id = std::vector<std::byte>(21, std::byte{0xaa}),
        .source_connection_id = {std::byte{0xbb}},
        .token = {},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {CryptoFrame{
            .offset = 0,
            .crypto_data = {std::byte{0x01}},
        }},
    };

    auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicPacketTest, RejectsPacketNumberLengthsAboveFourBytes) {
    expect_packet_serialize_error(
        HandshakePacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 5,
            .truncated_packet_number = 1,
            .frames = {CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }},
        },
        CodecErrorCode::invalid_varint);
}

TEST(QuicPacketTest, RoundTripsZeroRttPacketWithAllowedFrames) {
    ZeroRttPacket packet{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 4,
        .truncated_packet_number = 0x12345678,
        .frames =
            {
                PingFrame{},
            },
    };

    const auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_packet(encoded.value(), {});
    ASSERT_TRUE(decoded.has_value());

    const auto *zero_rtt = std::get_if<ZeroRttPacket>(&decoded.value().packet);
    ASSERT_NE(zero_rtt, nullptr);
    EXPECT_EQ(zero_rtt->packet_number_length, 4u);
    EXPECT_EQ(zero_rtt->truncated_packet_number, 0x12345678u);
}

TEST(QuicPacketTest, AllowsNonTerminalStreamFramesWhenTheyCarryExplicitLengths) {
    OneRttPacket packet{
        .destination_connection_id = {std::byte{0xaa}},
        .packet_number_length = 1,
        .truncated_packet_number = 7,
        .frames =
            {
                StreamFrame{
                    .has_length = true,
                    .stream_id = 0,
                    .stream_data = {std::byte{0x01}},
                },
                PingFrame{},
            },
    };

    const auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());
}

TEST(QuicPacketTest, AllowsTerminalStreamFramesWithoutLength) {
    OneRttPacket packet{
        .destination_connection_id = {std::byte{0xaa}},
        .packet_number_length = 1,
        .truncated_packet_number = 7,
        .frames =
            {
                StreamFrame{
                    .has_length = false,
                    .stream_id = 0,
                    .stream_data = {std::byte{0x01}},
                },
            },
    };

    const auto encoded = coquic::quic::serialize_packet(packet);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_packet(
        encoded.value(), coquic::quic::DeserializeOptions{
                             .one_rtt_destination_connection_id_length = 1,
                         });
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<OneRttPacket>(decoded.value().packet));
}

TEST(QuicPacketTest, RejectsInvalidPacketSerializationInputs) {
    expect_packet_serialize_error(
        VersionNegotiationPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .supported_versions = {},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        RetryPacket{
            .version = 0,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        InitialPacket{
            .version = 0,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames = {CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }},
        },
        CodecErrorCode::unsupported_packet_type);
    expect_packet_serialize_error(
        InitialPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = std::vector<std::byte>(21, std::byte{0xbb}),
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames = {CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        InitialPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0xaa}},
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 0,
            .truncated_packet_number = 1,
            .frames = {CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }},
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        OneRttPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames = {},
        },
        CodecErrorCode::empty_packet_payload);
    expect_packet_serialize_error(
        OneRttPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames =
                {
                    StreamFrame{
                        .has_length = false,
                        .stream_id = 0,
                        .stream_data = {std::byte{0x01}},
                    },
                    PingFrame{},
                },
        },
        CodecErrorCode::packet_length_mismatch);
    expect_packet_serialize_error(
        OneRttPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames =
                {
                    PaddingFrame{
                        .length = 0,
                    },
                },
        },
        CodecErrorCode::invalid_varint);
    expect_packet_serialize_error(
        OneRttPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .packet_number_length = 1,
            .truncated_packet_number = 0x100,
            .frames =
                {
                    PingFrame{},
                },
        },
        CodecErrorCode::invalid_varint);
}

TEST(QuicPacketTest, RejectsMalformedVersionNegotiationPackets) {
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 7>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}}),
        {}, CodecErrorCode::packet_length_mismatch);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 8>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::packet_length_mismatch);
}

TEST(QuicPacketTest, RejectsMalformedInitialPackets) {
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x15}}),
        {}, CodecErrorCode::invalid_varint);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 7>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 7>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 8>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x02}}),
        {}, CodecErrorCode::packet_length_mismatch);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 8>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 9>{std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x00}, std::byte{0x00}}),
        {}, CodecErrorCode::packet_length_mismatch);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 10>{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00}}),
        {}, CodecErrorCode::empty_packet_payload);
}

TEST(QuicPacketTest, RejectsMalformedZeroRttAndHandshakePackets) {
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xd0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xe0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
}

TEST(QuicPacketTest, RejectsForbiddenFramesAndFrameDecodeErrorsInLongHeaders) {
    const auto forbidden_payload = coquic::quic::serialize_frame(NewTokenFrame{
        .token = {std::byte{0x01}},
    });
    ASSERT_TRUE(forbidden_payload.has_value());

    std::vector<std::byte> initial_with_forbidden_frame{
        std::byte{0xc0},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x01},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x00},
        static_cast<std::byte>(1 + forbidden_payload.value().size()),
        std::byte{0x00},
    };
    initial_with_forbidden_frame.insert(initial_with_forbidden_frame.end(),
                                        forbidden_payload.value().begin(),
                                        forbidden_payload.value().end());
    expect_packet_decode_error(initial_with_forbidden_frame, {},
                               CodecErrorCode::frame_not_allowed_in_packet_type);

    expect_packet_decode_error(
        std::vector<std::byte>{
            std::byte{0xc0},
            std::byte{0x00},
            std::byte{0x00},
            std::byte{0x00},
            std::byte{0x01},
            std::byte{0x00},
            std::byte{0x00},
            std::byte{0x00},
            std::byte{0x02},
            std::byte{0x00},
            std::byte{0x1f},
        },
        {}, CodecErrorCode::unknown_frame_type);
}

TEST(QuicPacketTest, RejectsMalformedRetryAndShortHeaderPackets) {
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xf0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 6>{std::byte{0xf0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00}}),
        {}, CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 7>{std::byte{0xf0}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
                                         std::byte{0x00}}),
        {}, CodecErrorCode::packet_length_mismatch);

    expect_packet_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x00}}), {},
                               CodecErrorCode::invalid_fixed_bit);
    expect_packet_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x58}}), {},
                               CodecErrorCode::invalid_reserved_bits);
    expect_packet_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x40}, std::byte{0xaa}}),
                               coquic::quic::DeserializeOptions{
                                   .one_rtt_destination_connection_id_length = 2,
                               },
                               CodecErrorCode::malformed_short_header_context);
    expect_packet_decode_error(as_span(std::array<std::byte, 2>{std::byte{0x40}, std::byte{0xaa}}),
                               coquic::quic::DeserializeOptions{
                                   .one_rtt_destination_connection_id_length = 1,
                               },
                               CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 3>{std::byte{0x40}, std::byte{0xaa}, std::byte{0x01}}),
        coquic::quic::DeserializeOptions{
            .one_rtt_destination_connection_id_length = 1,
        },
        CodecErrorCode::empty_packet_payload);
    expect_packet_decode_error(as_span(std::array<std::byte, 4>{std::byte{0x40}, std::byte{0xaa},
                                                                std::byte{0x01}, std::byte{0x1f}}),
                               coquic::quic::DeserializeOptions{
                                   .one_rtt_destination_connection_id_length = 1,
                               },
                               CodecErrorCode::unknown_frame_type);
}

TEST(QuicPacketTest, RejectsMalformedGenericPacketHeaders) {
    expect_packet_decode_error(as_span(std::array<std::byte, 0>{}), {},
                               CodecErrorCode::truncated_input);
    expect_packet_decode_error(as_span(std::array<std::byte, 1>{std::byte{0x80}}), {},
                               CodecErrorCode::truncated_input);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0x80}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::invalid_fixed_bit);
    expect_packet_decode_error(
        as_span(std::array<std::byte, 5>{std::byte{0xcc}, std::byte{0x00}, std::byte{0x00},
                                         std::byte{0x00}, std::byte{0x01}}),
        {}, CodecErrorCode::invalid_reserved_bits);
}

} // namespace
