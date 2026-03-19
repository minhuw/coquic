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

TEST(QuicCoreTest, ServerProcessesClientInitialAndEmitsHandshakeFlight) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto client_initial = client.receive({});
    const auto server_flight = server.receive(client_initial);

    EXPECT_FALSE(server_flight.empty());
    EXPECT_FALSE(server.is_handshake_complete());
}

TEST(QuicCoreTest, TwoPeersCompleteHandshake) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server);

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
}

TEST(QuicCoreTest, TwoPeersExchangeApplicationDataAfterHandshake) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server);
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    client.queue_application_data(coquic::quic::test::bytes_from_string("ping"));
    coquic::quic::test::flush_pending_datagrams(client, server);

    EXPECT_EQ(coquic::quic::test::string_from_bytes(server.take_received_application_data()),
              "ping");
}

TEST(QuicCoreTest, InboundApplicationStreamRequiresOffsetAndLengthFlags) {
    coquic::quic::QuicConnection missing_offset_connection(
        coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        missing_offset_connection, coquic::quic::HandshakeStatus::connected);
    const auto missing_offset_ok =
        coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            missing_offset_connection,
            {coquic::quic::StreamFrame{
                .fin = false,
                .has_offset = false,
                .has_length = true,
                .stream_id = 0,
                .offset = std::nullopt,
                .stream_data = coquic::quic::test::bytes_from_string("a"),
            }});
    EXPECT_FALSE(missing_offset_ok);
    EXPECT_TRUE(missing_offset_connection.has_failed());

    coquic::quic::QuicConnection missing_length_connection(
        coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        missing_length_connection, coquic::quic::HandshakeStatus::connected);
    const auto missing_length_ok =
        coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            missing_length_connection,
            {coquic::quic::StreamFrame{
                .fin = false,
                .has_offset = true,
                .has_length = false,
                .stream_id = 0,
                .offset = 0,
                .stream_data = coquic::quic::test::bytes_from_string("b"),
            }});
    EXPECT_FALSE(missing_length_ok);
    EXPECT_TRUE(missing_length_connection.has_failed());
}

TEST(QuicCoreTest, InboundApplicationStreamFailsBeforeHandshakeConnected) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::in_progress);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::StreamFrame{
                        .fin = false,
                        .has_offset = true,
                        .has_length = true,
                        .stream_id = 0,
                        .offset = 0,
                        .stream_data = coquic::quic::test::bytes_from_string("ping"),
                    }});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.take_received_application_data().empty());
}

} // namespace
