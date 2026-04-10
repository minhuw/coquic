#include <cstddef>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/core.h"
#include "src/quic/plaintext_codec.h"

namespace {

TEST(QuicPlaintextCodecTest, RoundTripsCoalescedLongHeaderDatagram) {
    std::vector<coquic::quic::Packet> packets;
    packets.push_back(coquic::quic::InitialPacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .token = {},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {coquic::quic::CryptoFrame{
            .offset = 0,
            .crypto_data = {std::byte{0x01}},
        }},
    });
    packets.push_back(coquic::quic::HandshakePacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .packet_number_length = 1,
        .truncated_packet_number = 2,
        .frames = {coquic::quic::AckFrame{}},
    });

    auto encoded = coquic::quic::serialize_datagram(packets);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_datagram(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 2u);
}

TEST(QuicPlaintextCodecTest, RequiresShortHeaderContextForOneRtt) {
    const std::vector<coquic::quic::Packet> packets{
        coquic::quic::OneRttPacket{
            .destination_connection_id = {std::byte{0xaa}, std::byte{0xbb}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames = {coquic::quic::PingFrame{}},
        },
    };

    auto encoded = coquic::quic::serialize_datagram(packets);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = coquic::quic::deserialize_datagram(encoded.value());
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::malformed_short_header_context);
}

TEST(QuicPlaintextCodecTest, RejectsEmptyDatagrams) {
    const std::vector<std::byte> bytes;
    const auto decoded = coquic::quic::deserialize_datagram(bytes);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
    EXPECT_EQ(decoded.error().offset, 0u);
}

TEST(QuicPlaintextCodecTest, PropagatesPacketSerializationFailures) {
    const std::vector<coquic::quic::Packet> packets{
        coquic::quic::OneRttPacket{
            .destination_connection_id = {std::byte{0xaa}},
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames =
                {
                    coquic::quic::PaddingFrame{
                        .length = 0,
                    },
                },
        },
    };

    const auto encoded = coquic::quic::serialize_datagram(packets);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicPlaintextCodecTest, PropagatesPacketDeserializationOffsets) {
    const auto first_packet = coquic::quic::serialize_packet(coquic::quic::InitialPacket{
        .version = 1,
        .destination_connection_id = {std::byte{0xaa}},
        .source_connection_id = {std::byte{0xbb}},
        .token = {},
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {coquic::quic::CryptoFrame{
            .offset = 0,
            .crypto_data = {std::byte{0x01}},
        }},
    });
    ASSERT_TRUE(first_packet.has_value());

    std::vector<std::byte> datagram = first_packet.value();
    datagram.push_back(std::byte{0x00});

    const auto decoded = coquic::quic::deserialize_datagram(datagram);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::invalid_fixed_bit);
    EXPECT_EQ(decoded.error().offset, first_packet.value().size());
}

} // namespace
