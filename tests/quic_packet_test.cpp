#include <array>
#include <cstddef>
#include <cstdint>
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
using coquic::quic::Packet;
using coquic::quic::PathChallengeFrame;
using coquic::quic::PingFrame;
using coquic::quic::RetryPacket;
using coquic::quic::TransportConnectionCloseFrame;
using coquic::quic::VersionNegotiationPacket;
using coquic::quic::ZeroRttPacket;

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

} // namespace
