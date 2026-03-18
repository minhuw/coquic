#include <gtest/gtest.h>

#include "src/coquic.h"
#include "src/quic/protected_codec.h"
#include "tests/quic_test_utils.h"

namespace {

TEST(QuicCoreTest, ClientStartsHandshakeFromEmptyInput) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    const auto config = coquic::quic::test::make_client_core_config();

    const auto datagram = client.receive({});
    ASSERT_GE(datagram.size(), 1200u);
    EXPECT_FALSE(client.is_handshake_complete());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        datagram,
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = config.initial_destination_connection_id,
        });
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedInitialPacket>(&decoded.value()[0]), nullptr);
}

TEST(QuicCoreTest, ServerDoesNotEmitUntilItReceivesBytes) {
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    EXPECT_TRUE(server.receive({}).empty());
    EXPECT_FALSE(server.is_handshake_complete());
}

} // namespace
