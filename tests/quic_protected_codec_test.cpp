#include <cstddef>
#include <vector>

#include <gtest/gtest.h>

#include "src/coquic.h"

namespace {

TEST(QuicProtectedCodecTest, DeclaresInitialRoundTripApi) {
    const std::vector<coquic::quic::ProtectedPacket> packets{
        coquic::quic::ProtectedInitialPacket{
            .version = 1,
            .destination_connection_id = {std::byte{0x83}, std::byte{0x94}},
            .source_connection_id = {},
            .token = {},
            .packet_number_length = 4,
            .packet_number = 2,
            .frames = {coquic::quic::CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}},
            }},
        },
    };

    const coquic::quic::SerializeProtectionContext serialize_context{
        .local_role = coquic::quic::EndpointRole::client,
        .client_initial_destination_connection_id =
            {
                std::byte{0x83},
                std::byte{0x94},
                std::byte{0xc8},
                std::byte{0xf0},
                std::byte{0x3e},
                std::byte{0x51},
                std::byte{0x57},
                std::byte{0x08},
            },
    };

    const auto encoded = coquic::quic::serialize_protected_datagram(packets, serialize_context);
    EXPECT_TRUE(encoded.has_value());

    const coquic::quic::DeserializeProtectionContext deserialize_context{
        .peer_role = coquic::quic::EndpointRole::client,
        .client_initial_destination_connection_id =
            {
                std::byte{0x83},
                std::byte{0x94},
                std::byte{0xc8},
                std::byte{0xf0},
                std::byte{0x3e},
                std::byte{0x51},
                std::byte{0x57},
                std::byte{0x08},
            },
    };

    const std::vector<std::byte> encoded_bytes{};
    const auto decoded =
        coquic::quic::deserialize_protected_datagram(encoded_bytes, deserialize_context);
    EXPECT_TRUE(decoded.has_value());
}

} // namespace
