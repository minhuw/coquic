#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::http09::test_support;

TEST(QuicHttp09RuntimeTest, RuntimeAssignsStablePathIdsPerPeerTuple) {
    EXPECT_TRUE(coquic::http09::test::runtime_assigns_stable_path_ids_for_tests());
}

TEST(QuicHttp09RuntimeTest, DriveEndpointUsesTransportSelectedPathAndSocket) {
    EXPECT_TRUE(coquic::http09::test::drive_endpoint_uses_transport_selected_path_for_tests());
}

TEST(QuicHttp09RuntimeTest, DeferredReplayPreservesIndividualBufferedPathIds) {
    coquic::quic::QuicConnection connection(coquic::quic::QuicCoreConfig{
        .role = coquic::quic::EndpointRole::client,
        .source_connection_id = {std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x02}},
    });
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;

    const auto first_deferred = std::vector<std::byte>{
        std::byte{0x40}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
    };
    const auto second_deferred = std::vector<std::byte>{
        std::byte{0x40}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
    };
    connection.process_inbound_datagram(first_deferred, coquic::quic::test::test_time(1),
                                        /*path_id=*/11);
    connection.process_inbound_datagram(second_deferred, coquic::quic::test::test_time(2),
                                        /*path_id=*/22);
    ASSERT_GE(connection.deferred_protected_packets_.size(), 2u);

    connection.current_send_path_id_.reset();
    connection.replay_deferred_protected_packets(coquic::quic::test::test_time(3));

    ASSERT_TRUE(connection.current_send_path_id_.has_value());
    EXPECT_EQ(connection.current_send_path_id_.value_or(0), 11u);
}

TEST(QuicHttp09RuntimeTest, DeferredReplayKeepsDistinctPathsForIdenticalPayloads) {
    coquic::quic::QuicConnection connection(coquic::quic::QuicCoreConfig{
        .role = coquic::quic::EndpointRole::client,
        .source_connection_id = {std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x02}},
    });
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;

    const auto deferred = std::vector<std::byte>{
        std::byte{0x40}, std::byte{0x0a}, std::byte{0x0b}, std::byte{0x0c}, std::byte{0x0d},
    };
    connection.process_inbound_datagram(deferred, coquic::quic::test::test_time(1), /*path_id=*/11);
    connection.process_inbound_datagram(deferred, coquic::quic::test::test_time(2), /*path_id=*/22);

    ASSERT_EQ(connection.deferred_protected_packets_.size(), 2u);
    EXPECT_EQ(connection.deferred_protected_packets_[0].bytes, deferred);
    EXPECT_EQ(connection.deferred_protected_packets_[0].path_id, 11u);
    EXPECT_EQ(connection.deferred_protected_packets_[1].bytes, deferred);
    EXPECT_EQ(connection.deferred_protected_packets_[1].path_id, 22u);
}

TEST(QuicHttp09RuntimeTest, CoreVersionNegotiationRestartPreservesInboundPathIds) {
    EXPECT_TRUE(coquic::http09::test::core_version_negotiation_restart_preserves_inbound_path_ids_for_tests());
}

TEST(QuicHttp09RuntimeTest, CoreRetryRestartPreservesInboundPathIds) {
    EXPECT_TRUE(coquic::http09::test::core_retry_restart_preserves_inbound_path_ids_for_tests());
}

TEST(QuicHttp09RuntimeTest, DriveEndpointRejectsUnknownTransportSelectedPath) {
    EXPECT_TRUE(
        coquic::http09::test::drive_endpoint_rejects_unknown_transport_selected_path_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeProcessesPolicyInputsBeforeTerminalSuccess) {
    EXPECT_TRUE(
        coquic::http09::test::runtime_policy_core_inputs_advance_before_terminal_success_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeRegistersAllServerCoreConnectionIdsForRouting) {
    EXPECT_TRUE(coquic::http09::test::runtime_registers_all_server_core_connection_ids_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeMiscInternalCoverageHooksExerciseFallbackPaths) {
    testing::internal::CaptureStderr();
    const bool covered = coquic::http09::test::runtime_misc_internal_coverage_for_tests();
    const auto stderr_output = testing::internal::GetCapturedStderr();
    EXPECT_TRUE(covered) << stderr_output;
}

TEST(QuicHttp09RuntimeTest, RuntimeInternalCoverageHooksExerciseRemainingBranches) {
    testing::internal::CaptureStderr();
    const bool covered = coquic::http09::test::runtime_additional_internal_coverage_for_tests();
    const auto stderr_output = testing::internal::GetCapturedStderr();
    EXPECT_TRUE(covered) << stderr_output;
}

TEST(QuicHttp09RuntimeTest, RuntimeRestartFailureHooksExerciseRestartFailures) {
    EXPECT_TRUE(coquic::http09::test::runtime_restart_failure_paths_for_tests());
}

TEST(QuicHttp09RuntimeTest, ExistingServerSessionRouteHelperErasesFailedSession) {
    const auto make_peer = [](std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(port);
        ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return peer;
    };
    const auto make_secret = [](std::byte fill) {
        return coquic::quic::TrafficSecret{
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .secret = std::vector<std::byte>(32, fill),
        };
    };
    const auto make_connected_runtime_server_connection =
        [&](const coquic::quic::QuicCoreConfig &config) {
            coquic::quic::QuicConnection connection(config);
            connection.started_ = true;
            connection.status_ = coquic::quic::HandshakeStatus::connected;
            connection.handshake_confirmed_ = true;
            connection.peer_address_validated_ = true;
            connection.peer_source_connection_id_ = make_runtime_connection_id(std::byte{0xc1}, 3);
            connection.client_initial_destination_connection_id_ =
                make_runtime_connection_id(std::byte{0x83}, 2);
            connection.local_transport_parameters_ = coquic::quic::TransportParameters{
                .original_destination_connection_id =
                    connection.client_initial_destination_connection_id_,
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.config_.source_connection_id,
            };
            connection.initialize_local_flow_control();
            connection.application_space_.read_secret = make_secret(std::byte{0x21});
            connection.application_space_.write_secret = make_secret(std::byte{0x31});
            connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.peer_source_connection_id_,
            };
            connection.peer_transport_parameters_validated_ = true;
            connection.initialize_peer_flow_control_from_transport_parameters();
            return connection;
        };

    auto core_config =
        coquic::http09::make_http09_server_core_config(coquic::http09::Http09RuntimeConfig{
            .mode = coquic::http09::Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = coquic::http09::QuicHttp09Testcase::rebind_addr,
        });
    core_config.source_connection_id = make_runtime_connection_id(std::byte{0x53}, 1);

    coquic::quic::QuicCore server(core_config);
    server.connection_ = std::make_unique<coquic::quic::QuicConnection>(
        make_connected_runtime_server_connection(core_config));
    auto &connection = *server.connection_;

    const auto local_connection_id = connection.config_.source_connection_id;
    const auto initial_destination_connection_id =
        connection.client_initial_destination_connection_id();
    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = connection.application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 77,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 0,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.mark_failed();

    const auto peer = make_peer(39968);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    const auto route = coquic::http09::test::route_existing_server_session_datagram_for_tests(
        server, /*established_socket_fd=*/31, peer, peer_len, local_connection_id,
        initial_destination_connection_id, /*inbound_socket_fd=*/31, peer, peer_len,
        encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(route.processed);
    EXPECT_TRUE(route.erased);
}

} // namespace
