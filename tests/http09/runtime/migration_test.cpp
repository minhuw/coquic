#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerBindsPreferredSocketAndPollsBothSockets) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const ScopedServerSocketPollTraceReset trace_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .socket_fn = &record_server_socket_then_succeed,
            .bind_fn = &record_server_bind_then_succeed,
            .poll_fn = &record_poll_descriptor_count_then_cancel,
            .setsockopt_fn = [](int, int, int, const void *, socklen_t) { return 0; },
            .recvfrom_fn = &would_block_recvfrom,
        },
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::connectionmigration,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
    ASSERT_EQ(g_server_socket_poll_trace.opened_sockets.size(), 2u);
    ASSERT_EQ(g_server_socket_poll_trace.bound_ports.size(), 2u);
    EXPECT_EQ(g_server_socket_poll_trace.bound_ports[0], port);
    EXPECT_EQ(g_server_socket_poll_trace.bound_ports[1], port + 1);
    ASSERT_FALSE(g_server_socket_poll_trace.poll_descriptor_counts.empty());
    EXPECT_EQ(g_server_socket_poll_trace.poll_descriptor_counts.front(), 2u);
}

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerConfigAdvertisesPreferredAddress) {
    EXPECT_TRUE(
        coquic::quic::test::server_connectionmigration_preferred_address_config_for_tests());
}

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerConfigIncludesPreferredAddressResetToken) {
    const auto core =
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::connectionmigration,
        });

    ASSERT_TRUE(core.transport.preferred_address.has_value());
    const auto preferred_address =
        core.transport.preferred_address.value_or(coquic::quic::PreferredAddress{});
    EXPECT_FALSE(std::all_of(preferred_address.stateless_reset_token.begin(),
                             preferred_address.stateless_reset_token.end(),
                             [](std::byte byte) { return byte == std::byte{0x00}; }));
}

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerConfigUsesConcreteAddressForWildcardHost) {
    ScopedEnvVar hostname("HOSTNAME", "interop-server-host");
    ScopedFreeaddrinfoCounterReset freeaddrinfo_counter;
    ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops(
        coquic::io::test::SocketIoBackendOpsOverride{
            .getaddrinfo_fn = hostname_ipv6_getaddrinfo,
            .freeaddrinfo_fn = counting_freeaddrinfo,
        });

    const auto core =
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "::",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::connectionmigration,
        });

    ASSERT_TRUE(core.transport.preferred_address.has_value());
    const auto preferred_address =
        core.transport.preferred_address.value_or(coquic::quic::PreferredAddress{});
    EXPECT_EQ(g_last_getaddrinfo_family, AF_INET6);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
    EXPECT_EQ(preferred_address.ipv6_port, 444);
    EXPECT_EQ(preferred_address.ipv6_address, (std::array<std::byte, 16>{
                                                  std::byte{0x20},
                                                  std::byte{0x01},
                                                  std::byte{0x0d},
                                                  std::byte{0xb8},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x09},
                                              }));
}

TEST(QuicHttp09RuntimeTest, RuntimeConnectionMigrationFailureHooksExerciseFalseBranches) {
    EXPECT_TRUE(coquic::quic::test::runtime_connectionmigration_failure_paths_for_tests());
}

TEST(QuicHttp09RuntimeTest, ExistingServerSessionRoutesLiveLikeMigrationRetransmitOnNewPath) {
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
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::rebind_addr,
        });
    core_config.source_connection_id = make_runtime_connection_id(std::byte{0x53}, 1);

    coquic::quic::QuicCore server(core_config);
    server.connection_ = std::make_unique<coquic::quic::QuicConnection>(
        make_connected_runtime_server_connection(core_config));
    auto &connection = *server.connection_;
    connection.application_space_.next_send_packet_number = 8241;
    connection.last_validated_path_id_ = 1;
    connection.current_send_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(1).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(0,
                                       coquic::quic::test::bytes_from_string(
                                           std::string(static_cast<std::size_t>(512) * 1024u, 'm')),
                                       false)
                    .has_value());

    for (std::size_t i = 0; i < 131; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(i) + 1));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 1u);
    }
    for (std::size_t i = 0; i < 22; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(132 + static_cast<std::int64_t>(i)));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 1u);
    }

    const auto first_gap_packet = connection.application_space_.sent_packets.at(8372);
    ASSERT_FALSE(first_gap_packet.stream_fragments.empty());
    const auto tracked_gap_offset = first_gap_packet.stream_fragments.front().offset;

    ASSERT_TRUE(connection
                    .process_inbound_application(
                        std::vector<coquic::quic::Frame>{
                            coquic::quic::AckFrame{
                                .largest_acknowledged = 8371,
                                .first_ack_range = 8371 - 8241,
                            },
                        },
                        coquic::quic::test::test_time(99), /*allow_preconnected_frames=*/false,
                        /*path_id=*/2)
                    .has_value());
    connection.ensure_path_state(2).anti_amplification_received_bytes = 4000;

    const auto migration_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(100));
    ASSERT_FALSE(migration_datagram.empty());
    ASSERT_EQ(connection.last_drained_path_id(), std::optional<coquic::quic::QuicPathId>{2});
    ASSERT_TRUE(connection.paths_.contains(2));
    ASSERT_TRUE(connection.paths_.at(2).outstanding_challenge.has_value());
    const auto challenge = optional_ref_or_terminate(connection.paths_.at(2).outstanding_challenge);
    ASSERT_EQ(std::prev(connection.application_space_.sent_packets.end())->first, 8394u);

    const auto local_connection_id = connection.config_.source_connection_id;
    const auto initial_destination_connection_id =
        connection.client_initial_destination_connection_id();
    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = connection.application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 1759,
                .frames =
                    {
                        coquic::quic::PathResponseFrame{.data = challenge},
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 8394,
                            .first_ack_range = 0,
                            .additional_ranges =
                                {
                                    coquic::quic::AckRange{
                                        .gap = 21,
                                        .range_length = 8371 - 8241,
                                    },
                                },
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

    const auto old_peer = make_peer(39968);
    const auto new_peer = make_peer(38910);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    const auto route = coquic::quic::test::route_existing_server_session_datagram_for_tests(
        server, /*established_socket_fd=*/31, old_peer, peer_len, local_connection_id,
        initial_destination_connection_id, /*inbound_socket_fd=*/77, new_peer, peer_len,
        encoded.value(), coquic::quic::test::test_time(101));

    ASSERT_TRUE(route.processed);
    EXPECT_FALSE(route.erased);
    EXPECT_TRUE(route.has_migrated_path_route);
    EXPECT_EQ(route.migrated_path_socket_fd, 77);
    EXPECT_GT(route.sendto_calls, 0);
    EXPECT_EQ(route.sendto_socket_fd, 77);
    EXPECT_EQ(route.sendto_peer_port, 38910);

    const auto &post_connection = *server.connection_;
    EXPECT_EQ(post_connection.current_send_path_id_, std::optional<coquic::quic::QuicPathId>{2});

    bool saw_retransmit_for_gap_offset = false;
    for (const auto &[packet_number, packet] : post_connection.application_space_.sent_packets) {
        static_cast<void>(packet_number);
        for (const auto &fragment : packet.stream_fragments) {
            if (fragment.offset == tracked_gap_offset) {
                saw_retransmit_for_gap_offset = true;
            }
        }
    }

    EXPECT_TRUE(saw_retransmit_for_gap_offset);
}

TEST(QuicHttp09RuntimeTest, ExistingServerSessionRoutesSecondRebindToLatestIpv6Peer) {
    const auto make_peer = [](std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
        ipv6.sin6_family = AF_INET6;
        ipv6.sin6_port = htons(port);
        ipv6.sin6_addr = in6addr_loopback;
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
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "::1",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::rebind_port,
        });
    core_config.source_connection_id = make_runtime_connection_id(std::byte{0x53}, 1);

    coquic::quic::QuicCore server(core_config);
    server.connection_ = std::make_unique<coquic::quic::QuicConnection>(
        make_connected_runtime_server_connection(core_config));
    auto &connection = *server.connection_;
    connection.application_space_.next_send_packet_number = 900;
    connection.last_validated_path_id_ = 2;
    connection.current_send_path_id_ = 2;
    connection.previous_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(2).validated = true;
    connection.ensure_path_state(2).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(4096, 'r')), false)
                    .has_value());
    connection.ensure_path_state(2).anti_amplification_received_bytes = 4000;

    const auto path2_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(path2_datagram.empty());
    ASSERT_EQ(connection.last_drained_path_id(), std::optional<coquic::quic::QuicPathId>{2});

    ASSERT_FALSE(connection.application_space_.sent_packets.empty());
    const auto largest_sent_packet =
        std::prev(connection.application_space_.sent_packets.end())->first;

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
                            .largest_acknowledged = largest_sent_packet,
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

    const auto original_peer = make_peer(38910);
    const auto first_rebind_peer = make_peer(39968);
    const auto second_rebind_peer = make_peer(40926);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in6));
    const std::array seeded_paths{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto route = coquic::quic::test::route_existing_server_session_datagram_for_tests(
        server, seeded_paths, local_connection_id, initial_destination_connection_id,
        /*inbound_socket_fd=*/77, second_rebind_peer, peer_len, encoded.value(),
        coquic::quic::test::test_time(2));

    ASSERT_TRUE(route.processed);
    EXPECT_FALSE(route.erased);
    EXPECT_GT(route.sendto_calls, 0);
    EXPECT_EQ(route.sendto_socket_fd, 77);
    EXPECT_EQ(route.sendto_peer_port, 40926);

    ASSERT_TRUE(server.connection_->paths_.contains(3));
    ASSERT_TRUE(server.connection_->paths_.at(3).outstanding_challenge.has_value());
    const auto second_rebind_challenge =
        optional_ref_or_terminate(server.connection_->paths_.at(3).outstanding_challenge);
    const auto largest_sent_after_second_rebind =
        std::prev(server.connection_->application_space_.sent_packets.end())->first;

    const auto path_response_encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = server.connection_->application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 78,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = largest_sent_after_second_rebind,
                            .first_ack_range = 0,
                        },
                        coquic::quic::PathResponseFrame{
                            .data = second_rebind_challenge,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = server.connection_->application_space_.read_secret,
            .one_rtt_key_phase = server.connection_->application_read_key_phase_,
        });
    ASSERT_TRUE(path_response_encoded.has_value());

    const std::array seeded_paths_after_second_rebind{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = second_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto path_response_route =
        coquic::quic::test::route_existing_server_session_datagram_for_tests(
            server, seeded_paths_after_second_rebind, local_connection_id,
            initial_destination_connection_id, /*inbound_socket_fd=*/77, second_rebind_peer,
            peer_len, path_response_encoded.value(), coquic::quic::test::test_time(3));

    ASSERT_TRUE(path_response_route.processed);
    EXPECT_FALSE(path_response_route.erased);
    EXPECT_GT(path_response_route.sendto_calls, 0);
    EXPECT_EQ(path_response_route.sendto_socket_fd, 77);
    EXPECT_EQ(path_response_route.sendto_peer_port, 40926);
    ASSERT_TRUE(server.connection_->paths_.contains(3));
    EXPECT_TRUE(server.connection_->paths_.at(3).validated);
    EXPECT_EQ(server.connection_->current_send_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
    EXPECT_EQ(server.connection_->last_validated_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
}

TEST(QuicHttp09RuntimeTest, ExistingServerSessionRoutesSecondRebindToLatestV4MappedPeer) {
    const auto make_peer = [](std::array<std::uint8_t, 4> ipv4_octets, std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
        ipv6.sin6_family = AF_INET6;
        ipv6.sin6_port = htons(port);
        ipv6.sin6_addr = IN6ADDR_ANY_INIT;
        ipv6.sin6_addr.s6_addr[10] = 0xff;
        ipv6.sin6_addr.s6_addr[11] = 0xff;
        ipv6.sin6_addr.s6_addr[12] = ipv4_octets[0];
        ipv6.sin6_addr.s6_addr[13] = ipv4_octets[1];
        ipv6.sin6_addr.s6_addr[14] = ipv4_octets[2];
        ipv6.sin6_addr.s6_addr[15] = ipv4_octets[3];
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
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "::",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::rebind_port,
        });
    core_config.source_connection_id = make_runtime_connection_id(std::byte{0x53}, 1);

    coquic::quic::QuicCore server(core_config);
    server.connection_ = std::make_unique<coquic::quic::QuicConnection>(
        make_connected_runtime_server_connection(core_config));
    auto &connection = *server.connection_;
    connection.application_space_.next_send_packet_number = 900;
    connection.last_validated_path_id_ = 2;
    connection.current_send_path_id_ = 2;
    connection.previous_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(2).validated = true;
    connection.ensure_path_state(2).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(4096, 'r')), false)
                    .has_value());
    connection.ensure_path_state(2).anti_amplification_received_bytes = 4000;

    const auto path2_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(path2_datagram.empty());
    ASSERT_EQ(connection.last_drained_path_id(), std::optional<coquic::quic::QuicPathId>{2});

    ASSERT_FALSE(connection.application_space_.sent_packets.empty());
    const auto largest_sent_packet =
        std::prev(connection.application_space_.sent_packets.end())->first;

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
                            .largest_acknowledged = largest_sent_packet,
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

    const auto original_peer = make_peer({193, 167, 0, 100}, 38910);
    const auto first_rebind_peer = make_peer({193, 167, 0, 100}, 57607);
    const auto second_rebind_peer = make_peer({193, 167, 0, 100}, 59022);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in6));
    const std::array seeded_paths{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto route = coquic::quic::test::route_existing_server_session_datagram_for_tests(
        server, seeded_paths, local_connection_id, initial_destination_connection_id,
        /*inbound_socket_fd=*/77, second_rebind_peer, peer_len, encoded.value(),
        coquic::quic::test::test_time(2));

    ASSERT_TRUE(route.processed);
    EXPECT_FALSE(route.erased);
    EXPECT_GT(route.sendto_calls, 0);
    EXPECT_EQ(route.sendto_socket_fd, 77);
    EXPECT_EQ(route.sendto_peer_port, 59022);
    ASSERT_EQ(route.sendto_socket_fds.size(), route.sendto_peer_ports.size());
    for (const auto socket_fd : route.sendto_socket_fds) {
        EXPECT_EQ(socket_fd, 77);
    }
    for (const auto peer_port : route.sendto_peer_ports) {
        EXPECT_EQ(peer_port, 59022);
    }

    ASSERT_TRUE(server.connection_->paths_.contains(3));
    ASSERT_TRUE(server.connection_->paths_.at(3).outstanding_challenge.has_value());
    const auto second_rebind_challenge =
        optional_ref_or_terminate(server.connection_->paths_.at(3).outstanding_challenge);
    const auto largest_sent_after_second_rebind =
        std::prev(server.connection_->application_space_.sent_packets.end())->first;

    const auto path_response_encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = server.connection_->application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 78,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = largest_sent_after_second_rebind,
                            .first_ack_range = 0,
                        },
                        coquic::quic::PathResponseFrame{
                            .data = second_rebind_challenge,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = server.connection_->application_space_.read_secret,
            .one_rtt_key_phase = server.connection_->application_read_key_phase_,
        });
    ASSERT_TRUE(path_response_encoded.has_value());

    const std::array seeded_paths_after_second_rebind{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = second_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto path_response_route =
        coquic::quic::test::route_existing_server_session_datagram_for_tests(
            server, seeded_paths_after_second_rebind, local_connection_id,
            initial_destination_connection_id, /*inbound_socket_fd=*/77, second_rebind_peer,
            peer_len, path_response_encoded.value(), coquic::quic::test::test_time(3));

    ASSERT_TRUE(path_response_route.processed);
    EXPECT_FALSE(path_response_route.erased);
    EXPECT_GT(path_response_route.sendto_calls, 0);
    EXPECT_EQ(path_response_route.sendto_socket_fd, 77);
    EXPECT_EQ(path_response_route.sendto_peer_port, 59022);
    ASSERT_EQ(path_response_route.sendto_socket_fds.size(),
              path_response_route.sendto_peer_ports.size());
    for (const auto socket_fd : path_response_route.sendto_socket_fds) {
        EXPECT_EQ(socket_fd, 77);
    }
    for (const auto peer_port : path_response_route.sendto_peer_ports) {
        EXPECT_EQ(peer_port, 59022);
    }
    ASSERT_TRUE(server.connection_->paths_.contains(3));
    EXPECT_TRUE(server.connection_->paths_.at(3).validated);
    EXPECT_EQ(server.connection_->current_send_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
    EXPECT_EQ(server.connection_->last_validated_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
}

TEST(QuicHttp09RuntimeTest, ExistingServerSessionRoutesSecondRebindAddrToLatestV4MappedPeer) {
    const auto make_peer = [](std::array<std::uint8_t, 4> ipv4_octets, std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
        ipv6.sin6_family = AF_INET6;
        ipv6.sin6_port = htons(port);
        ipv6.sin6_addr = IN6ADDR_ANY_INIT;
        ipv6.sin6_addr.s6_addr[10] = 0xff;
        ipv6.sin6_addr.s6_addr[11] = 0xff;
        ipv6.sin6_addr.s6_addr[12] = ipv4_octets[0];
        ipv6.sin6_addr.s6_addr[13] = ipv4_octets[1];
        ipv6.sin6_addr.s6_addr[14] = ipv4_octets[2];
        ipv6.sin6_addr.s6_addr[15] = ipv4_octets[3];
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
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "::",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::rebind_addr,
        });
    core_config.source_connection_id = make_runtime_connection_id(std::byte{0x53}, 1);

    coquic::quic::QuicCore server(core_config);
    server.connection_ = std::make_unique<coquic::quic::QuicConnection>(
        make_connected_runtime_server_connection(core_config));
    auto &connection = *server.connection_;
    connection.application_space_.next_send_packet_number = 900;
    connection.last_validated_path_id_ = 2;
    connection.current_send_path_id_ = 2;
    connection.previous_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(2).validated = true;
    connection.ensure_path_state(2).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(4096, 'r')), false)
                    .has_value());
    connection.ensure_path_state(2).anti_amplification_received_bytes = 4000;

    const auto path2_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(path2_datagram.empty());
    ASSERT_EQ(connection.last_drained_path_id(), std::optional<coquic::quic::QuicPathId>{2});

    ASSERT_FALSE(connection.application_space_.sent_packets.empty());
    const auto largest_sent_packet =
        std::prev(connection.application_space_.sent_packets.end())->first;

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
                            .largest_acknowledged = largest_sent_packet,
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

    const auto original_peer = make_peer({193, 167, 0, 100}, 38910);
    const auto first_rebind_peer = make_peer({193, 167, 0, 71}, 39968);
    const auto second_rebind_peer = make_peer({193, 167, 0, 3}, 38910);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in6));
    const std::array seeded_paths{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto route = coquic::quic::test::route_existing_server_session_datagram_for_tests(
        server, seeded_paths, local_connection_id, initial_destination_connection_id,
        /*inbound_socket_fd=*/77, second_rebind_peer, peer_len, encoded.value(),
        coquic::quic::test::test_time(2));

    ASSERT_TRUE(route.processed);
    EXPECT_FALSE(route.erased);
    EXPECT_GT(route.sendto_calls, 0);
    EXPECT_EQ(route.sendto_socket_fd, 77);
    EXPECT_EQ(route.sendto_peer_port, 38910);
    ASSERT_EQ(route.sendto_socket_fds.size(), route.sendto_peer_ports.size());
    for (const auto socket_fd : route.sendto_socket_fds) {
        EXPECT_EQ(socket_fd, 77);
    }
    for (const auto peer_port : route.sendto_peer_ports) {
        EXPECT_EQ(peer_port, 38910);
    }

    ASSERT_TRUE(server.connection_->paths_.contains(3));
    ASSERT_TRUE(server.connection_->paths_.at(3).outstanding_challenge.has_value());
    const auto second_rebind_challenge =
        optional_ref_or_terminate(server.connection_->paths_.at(3).outstanding_challenge);
    const auto largest_sent_after_second_rebind =
        std::prev(server.connection_->application_space_.sent_packets.end())->first;

    const auto path_response_encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = server.connection_->application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 78,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = largest_sent_after_second_rebind,
                            .first_ack_range = 0,
                        },
                        coquic::quic::PathResponseFrame{
                            .data = second_rebind_challenge,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = server.connection_->application_space_.read_secret,
            .one_rtt_key_phase = server.connection_->application_read_key_phase_,
        });
    ASSERT_TRUE(path_response_encoded.has_value());

    const std::array seeded_paths_after_second_rebind{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = second_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto path_response_route =
        coquic::quic::test::route_existing_server_session_datagram_for_tests(
            server, seeded_paths_after_second_rebind, local_connection_id,
            initial_destination_connection_id, /*inbound_socket_fd=*/77, second_rebind_peer,
            peer_len, path_response_encoded.value(), coquic::quic::test::test_time(3));

    ASSERT_TRUE(path_response_route.processed);
    EXPECT_FALSE(path_response_route.erased);
    EXPECT_GT(path_response_route.sendto_calls, 0);
    EXPECT_EQ(path_response_route.sendto_socket_fd, 77);
    EXPECT_EQ(path_response_route.sendto_peer_port, 38910);
    ASSERT_EQ(path_response_route.sendto_socket_fds.size(),
              path_response_route.sendto_peer_ports.size());
    for (const auto socket_fd : path_response_route.sendto_socket_fds) {
        EXPECT_EQ(socket_fd, 77);
    }
    for (const auto peer_port : path_response_route.sendto_peer_ports) {
        EXPECT_EQ(peer_port, 38910);
    }
    ASSERT_TRUE(server.connection_->paths_.contains(3));
    EXPECT_TRUE(server.connection_->paths_.at(3).validated);
    EXPECT_EQ(server.connection_->current_send_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
    EXPECT_EQ(server.connection_->last_validated_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
}

} // namespace
