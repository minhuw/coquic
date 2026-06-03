#include <gtest/gtest.h>
#include "tests/support/core/connection_handshake_test_support.h"

namespace {

TEST(QuicCoreTest,
     ProcessInboundDatagramDiscardsShortHeaderPacketLengthMismatchWithoutFailingConnection) {
    auto connection = make_connected_server_connection();

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 79,
                .frames =
                    {
                        coquic::quic::StreamFrame{
                            .fin = true,
                            .has_offset = true,
                            .has_length = true,
                            .stream_id = 0,
                            .offset = 0,
                            .stream_data = coquic::quic::test::bytes_from_string("GET /\r\n"),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    {
        const coquic::quic::test::ScopedProtectedCodecFaultInjector fault(
            coquic::quic::test::ProtectedCodecFaultPoint::
                remove_short_header_packet_length_mismatch);
        connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));
    }

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(2));

    ASSERT_FALSE(connection.has_failed());
    const auto received_stream_data = connection.take_received_stream_data();
    if (!received_stream_data.has_value()) {
        FAIL() << "expected received stream data";
        return;
    }

    const auto &received_value = optional_ref_or_terminate(received_stream_data);
    EXPECT_EQ(received_value.stream_id, 0u);
    EXPECT_EQ(received_value.bytes, coquic::quic::test::bytes_from_string("GET /\r\n"));
    EXPECT_TRUE(received_value.fin);
}

TEST(QuicCoreTest, ProcessInboundAckMalformedRangesDoNotMutateOutstandingInFlightRecoveryState) {
    auto connection = make_connected_client_connection();
    const auto seed_outstanding_packet = [](coquic::quic::PacketSpaceState &packet_space,
                                            std::uint64_t packet_number,
                                            coquic::quic::QuicCoreTimePoint sent_time) {
        packet_space.recovery.on_packet_sent(coquic::quic::SentPacketRecord{
            .packet_number = packet_number,
            .sent_time = sent_time,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .bytes_in_flight = 1200,
        });
    };

    seed_outstanding_packet(connection.application_space_, 0, coquic::quic::test::test_time(0));
    seed_outstanding_packet(connection.application_space_, 1, coquic::quic::test::test_time(1));
    seed_outstanding_packet(connection.application_space_, 2, coquic::quic::test::test_time(2));

    EXPECT_EQ(connection.application_space_.recovery.tracked_packet_count(), 3u);
    EXPECT_FALSE(connection.application_space_.recovery.largest_acked_packet_number().has_value());

    const auto result = connection.process_inbound_ack(connection.application_space_,
                                                       coquic::quic::AckFrame{
                                                           .largest_acknowledged = 4,
                                                           .first_ack_range = 5,
                                                       },
                                                       coquic::quic::test::test_time(30),
                                                       /*ack_delay_exponent=*/0,
                                                       /*max_ack_delay_ms=*/0,
                                                       /*suppress_pto_reset=*/false);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(connection.application_space_.recovery.tracked_packet_count(), 3u);
    EXPECT_FALSE(connection.application_space_.recovery.largest_acked_packet_number().has_value());
    for (const auto packet_number : std::array<std::uint64_t, 3>{0, 1, 2}) {
        EXPECT_NE(connection.application_space_.recovery.find_packet(packet_number), nullptr);
        const auto &packet =
            tracked_packet_or_terminate(connection.application_space_, packet_number);
        EXPECT_TRUE(packet.in_flight);
        EXPECT_FALSE(packet.declared_lost);
    }
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenSyncTlsStateFailsAfterValidPacket) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.start_client_if_needed();
    ASSERT_TRUE(connection.tls_.has_value());
    auto &tls = optional_ref_or_terminate(connection.tls_);
    connection.peer_transport_parameters_.reset();
    connection.peer_transport_parameters_validated_ = false;
    ASSERT_FALSE(connection.peer_source_connection_id_.has_value());
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        tls, coquic::quic::test::sample_transport_parameters());

    const auto handshake_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.read_secret = handshake_secret;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 78,
                .frames =
                    {
                        coquic::quic::PingFrame{},
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = handshake_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresLaterHandshakePacketFailure) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.application_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51});

    const auto first_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 20,
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
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(first_packet.has_value());

    const auto second_protected_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 21,
                .frames =
                    {
                        coquic::quic::PingFrame{},
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(second_protected_packet.has_value());

    auto datagram = first_packet.value();
    datagram.insert(datagram.end(), second_protected_packet.value().begin(),
                    second_protected_packet.value().end());

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_ints({0xaa}));
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresLaterHandshakeCryptoFailure) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto first_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 30,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(first_packet.has_value());

    const auto second_protected_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 31,
                .frames =
                    {
                        coquic::quic::CryptoFrame{
                            .offset = 0,
                            .crypto_data = bytes_from_ints({0x01}),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(second_protected_packet.has_value());

    auto datagram = first_packet.value();
    datagram.insert(datagram.end(), second_protected_packet.value().begin(),
                    second_protected_packet.value().end());

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_ints({0xaa}));
}

TEST(QuicCoreTest, ProcessInboundDatagramReturnsWhenReplayFailsAfterCurrentPacketSucceeds) {
    auto connection = make_connected_client_connection();
    connection.deferred_protected_packets_.push_back(coquic::quic::DeferredProtectedDatagram(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x11, 0x01, 0x22, 0x00, 0x00})));

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 79,
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
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ConnectionMoveConstructionPreservesConnectionStartBehavior) {
    coquic::quic::QuicConnection source(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicConnection moved(std::move(source));

    moved.start(coquic::quic::test::test_time(1));
    const auto datagram = moved.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
}

TEST(QuicCoreTest, ConnectionMoveAssignmentPreservesConnectionStartBehavior) {
    coquic::quic::QuicConnection source(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicConnection destination(coquic::quic::test::make_client_core_config());
    destination = std::move(source);

    destination.start(coquic::quic::test::test_time(1));
    const auto datagram = destination.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
}

TEST(QuicCoreTest, ConnectionRemoteQlogParametersAreEmittedAtMostOnce) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.config_.initial_destination_connection_id, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.qlog_session_ != nullptr);

    connection.maybe_emit_remote_qlog_parameters(coquic::quic::test::test_time(1));
    connection.maybe_emit_remote_qlog_parameters(coquic::quic::test::test_time(2));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:parameters_set"), 1u);
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathFailsWhenOneRttReadSecretCachePrimeFails) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, optional_ref_or_terminate(connection.application_space_.read_secret), 186);
    ASSERT_FALSE(encoded.empty());

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    connection.handshake_space_.read_secret.reset();
    connection.zero_rtt_space_.read_secret.reset();
    connection.application_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xa3});

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathDiscardsUnreadablePacketWithoutNextKeyPhaseRetry) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    connection.application_space_.write_secret.reset();

    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xa4});
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(connection, unrelated_secret, 187);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathDefersProtectedApplicationPacketUntilConnected) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.application_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
    connection.application_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});
    enable_qlog_session_for_test(connection, qlog_dir.path());

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 188,
                .frames =
                    {
                        coquic::quic::MaxStreamDataFrame{
                            .stream_id = 0,
                            .maximum_stream_data = 1,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), encoded.value());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathServerDefersShortHeaderBeforeHandshakeCompletes) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_packet_space_discarded_ = false;
    enable_qlog_session_for_test(connection, qlog_dir.path());

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 195,
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
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), encoded.value());
    EXPECT_EQ(connection.deferred_protected_packets_.front().datagram_id, 0u);
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathFailsWhenApplicationPacketProcessingFails) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_server_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());

    const auto invalid_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 189,
                .frames = {coquic::quic::test::make_inbound_application_stream_frame("x", 0, 3)},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(invalid_packet.has_value());

    connection.process_inbound_datagram(invalid_packet.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramKeepsPreviousReadSecretAfterOldPhasePacket) {
    auto connection = make_connected_client_connection();
    const auto old_secret = optional_ref_or_terminate(connection.application_space_.read_secret);
    const auto next_secret = coquic::quic::derive_next_traffic_secret(old_secret);
    ASSERT_TRUE(next_secret.has_value());
    if (!next_secret.has_value()) {
        return;
    }

    connection.previous_application_read_secret_ = old_secret;
    connection.previous_application_read_key_phase_ = connection.application_read_key_phase_;
    connection.application_space_.read_secret = next_secret.value();
    connection.application_read_key_phase_ = !connection.application_read_key_phase_;
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, old_secret, 190, connection.previous_application_read_key_phase_);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 190u);
    EXPECT_TRUE(connection.previous_application_read_secret_.has_value());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathKeepsPreviousReadSecretAfterOldPhasePacket) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    const auto old_secret = optional_ref_or_terminate(connection.application_space_.read_secret);
    const auto next_secret = coquic::quic::derive_next_traffic_secret(old_secret);
    ASSERT_TRUE(next_secret.has_value());
    if (!next_secret.has_value()) {
        return;
    }

    connection.previous_application_read_secret_ = old_secret;
    connection.previous_application_read_key_phase_ = connection.application_read_key_phase_;
    connection.application_space_.read_secret = next_secret.value();
    connection.application_read_key_phase_ = !connection.application_read_key_phase_;
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, old_secret, 190, connection.previous_application_read_key_phase_);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 190u);
    EXPECT_TRUE(connection.previous_application_read_secret_.has_value());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathFailsWhenSyncTlsStateFailsAfterValidPacket) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.start_client_if_needed();
    ASSERT_TRUE(connection.tls_.has_value());
    enable_qlog_session_for_test(connection, qlog_dir.path());
    auto &tls = optional_ref_or_terminate(connection.tls_);
    connection.peer_transport_parameters_.reset();
    connection.peer_transport_parameters_validated_ = false;
    ASSERT_FALSE(connection.peer_source_connection_id_.has_value());
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        tls, coquic::quic::test::sample_transport_parameters());

    const auto handshake_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x42});
    connection.handshake_space_.read_secret = handshake_secret;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 191,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = handshake_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathFailsWhenPreviousReadSecretContextPrimeFails) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    const auto current_secret =
        optional_ref_or_terminate(connection.application_space_.read_secret);
    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xb1});

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    ASSERT_TRUE(coquic::quic::expand_traffic_secret_cached(current_secret).has_value());

    connection.application_space_.read_secret.reset();
    connection.previous_application_read_secret_ = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xb2});
    connection.previous_application_read_key_phase_ = connection.application_read_key_phase_;
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(connection, unrelated_secret, 192);
    ASSERT_FALSE(encoded.empty());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathAcceptsPeerKeyUpdatePacket) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    if (!connection.application_space_.read_secret.has_value()) {
        return;
    }

    const auto original_read_key_phase = connection.application_read_key_phase_;
    const auto original_write_key_phase = connection.application_write_key_phase_;
    const auto next_read_secret =
        coquic::quic::derive_next_traffic_secret(connection.application_space_.read_secret.value());
    ASSERT_TRUE(next_read_secret.has_value());
    if (!next_read_secret.has_value()) {
        return;
    }

    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, next_read_secret.value(), 193, !original_read_key_phase);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 193u);
    EXPECT_EQ(connection.application_read_key_phase_, !original_read_key_phase);
    EXPECT_EQ(connection.application_write_key_phase_, !original_write_key_phase);
}

TEST(QuicCoreTest,
     ProcessInboundDatagramQlogPathDiscardsPacketWhenPreviousReadSecretRetryStillFails) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    connection.previous_application_read_secret_ = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.previous_application_read_key_phase_ = connection.application_read_key_phase_;
    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x61});

    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, unrelated_secret, 193, connection.application_read_key_phase_);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest,
     ProcessInboundDatagramQlogPathDefersShortHeaderPacketWhenApplicationReadSecretMissing) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    connection.application_space_.read_secret.reset();

    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection,
        make_test_traffic_secret(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
                                 std::byte{0xb3}),
        194);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), encoded);
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest,
     ProcessInboundDatagramQlogPathFailsOnMalformedLongHeaderPacketAfterLengthParsing) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xb4});
    enable_qlog_session_for_test(connection, qlog_dir.path());

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 195,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedProtectedCodecFaultInjector fault(
        coquic::quic::test::ProtectedCodecFaultPoint::remove_long_header_packet_length_mismatch);
    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
    EXPECT_EQ(connection.handshake_space_.largest_authenticated_packet_number, std::nullopt);
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathTracesDiscardedUnreadableShortHeaderPacket) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");

    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    connection.application_space_.write_secret.reset();

    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xb5});
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(connection, unrelated_secret, 196);
    ASSERT_FALSE(encoded.empty());

    testing::internal::CaptureStderr();
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));
    const auto stderr_output = testing::internal::GetCapturedStderr();

    EXPECT_FALSE(connection.has_failed());
    EXPECT_NE(stderr_output.find("quic-packet-trace discard scid=c101"), std::string::npos);
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathIgnoresLaterHandshakeCryptoFailure) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x43});
    enable_qlog_session_for_test(connection, qlog_dir.path());

    const auto first_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 197,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(first_packet.has_value());

    const auto second_protected_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 198,
                .frames = {coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = bytes_from_ints({0x01}),
                }},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(second_protected_packet.has_value());

    auto datagram = first_packet.value();
    datagram.insert(datagram.end(), second_protected_packet.value().begin(),
                    second_protected_packet.value().end());

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_ints({0xaa}));
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathTracesOneRttProcessingFailure) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");

    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_server_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());

    const auto invalid_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 199,
                .frames = {coquic::quic::test::make_inbound_application_stream_frame("x", 0, 3)},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(invalid_packet.has_value());

    testing::internal::CaptureStderr();
    connection.process_inbound_datagram(invalid_packet.value(), coquic::quic::test::test_time(1));
    const auto trace_stderr_output = testing::internal::GetCapturedStderr();

    EXPECT_TRUE(connection.has_failed());
    EXPECT_NE(trace_stderr_output.find("quic-packet-trace fail scid=5301"), std::string::npos);
}

TEST(QuicCoreTest,
     ProcessInboundDatagramDiscardsUnreadablePacketWithoutNextKeyPhaseRetryWhenWriteSecretMissing) {
    auto connection = make_connected_client_connection();
    connection.application_space_.write_secret.reset();

    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xb6});
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(connection, unrelated_secret, 200);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ConnectionDeferredProtectedPacketEqualityDependsOnDatagramId) {
    const auto bytes = bytes_from_ints({0xaa, 0xbb, 0xcc});

    const auto datagram = static_cast<coquic::quic::DeferredProtectedDatagram>(
        coquic::quic::DeferredProtectedPacket(bytes));
    EXPECT_FALSE(datagram.datagram_id.has_value());
    EXPECT_TRUE(coquic::quic::DeferredProtectedPacket(bytes) == bytes);
    EXPECT_TRUE(bytes == coquic::quic::DeferredProtectedPacket(bytes));
    EXPECT_FALSE(coquic::quic::DeferredProtectedPacket(bytes, 7) == bytes);
}

TEST(QuicCoreTest, ProcessInboundDatagramDiscardsShortHeaderPacketWithHeaderProtectionFailure) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 80,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new);
    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramDiscardsCorruptedLongHeaderPacket) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.process_inbound_datagram(bytes_from_ints({0x80, 0x00, 0x00, 0x00, 0x01}),
                                        coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramDiscardsShortHeaderPacketWithTooShortHeaderSample) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 81,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());
    ASSERT_GT(encoded.value().size(), 7u);
    auto truncated = encoded.value();
    truncated.resize(7);

    connection.process_inbound_datagram(truncated, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramDiscardsShortHeaderPacketWithPayloadDecryptFailure) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 82,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::open_payload_update);
    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenHandshakeReadSecretCachePrimeFails) {
    auto connection = make_connected_client_connection();
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, optional_ref_or_terminate(connection.application_space_.read_secret), 83);
    ASSERT_FALSE(encoded.empty());

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x91});

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup, 2);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenZeroRttReadSecretCachePrimeFails) {
    auto connection = make_connected_client_connection();
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, optional_ref_or_terminate(connection.application_space_.read_secret), 84);
    ASSERT_FALSE(encoded.empty());

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    connection.handshake_space_.read_secret.reset();
    connection.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x92});

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenOneRttReadSecretCachePrimeFails) {
    auto connection = make_connected_client_connection();
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, optional_ref_or_terminate(connection.application_space_.read_secret), 85);
    ASSERT_FALSE(encoded.empty());

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    connection.handshake_space_.read_secret.reset();
    connection.zero_rtt_space_.read_secret.reset();
    connection.application_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x93});

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenPreviousReadSecretContextPrimeFails) {
    auto connection = make_connected_client_connection();
    const auto current_secret =
        optional_ref_or_terminate(connection.application_space_.read_secret);
    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x61});

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    ASSERT_TRUE(coquic::quic::expand_traffic_secret_cached(current_secret).has_value());

    connection.application_space_.read_secret.reset();
    connection.previous_application_read_secret_ = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x94});
    connection.previous_application_read_key_phase_ = connection.application_read_key_phase_;
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(connection, unrelated_secret, 87);
    ASSERT_FALSE(encoded.empty());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenNextKeyPhaseContextPrimeFails) {
    bool saw_faulted_failure = false;
    for (std::size_t occurrence = 1; occurrence <= 8; ++occurrence) {
        auto connection = make_connected_client_connection();
        const auto current_secret =
            optional_ref_or_terminate(connection.application_space_.read_secret);
        const auto next_read_secret = coquic::quic::derive_next_traffic_secret(current_secret);
        ASSERT_TRUE(next_read_secret.has_value());
        if (!next_read_secret.has_value()) {
            return;
        }

        const auto encoded = serialize_one_rtt_ack_datagram_for_test(
            connection, next_read_secret.value(), 89, !connection.application_read_key_phase_);
        ASSERT_FALSE(encoded.empty());

        coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
        connection.handshake_space_.read_secret.reset();
        connection.zero_rtt_space_.read_secret.reset();
        ASSERT_TRUE(coquic::quic::expand_traffic_secret_cached(current_secret).has_value());

        const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
            coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup, occurrence);
        try {
            connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));
        } catch (const std::bad_variant_access &) {
            continue;
        }
        saw_faulted_failure = saw_faulted_failure || connection.has_failed();
    }

    EXPECT_TRUE(saw_faulted_failure);
}

TEST(QuicCoreTest, PacketTraceLogsAppEmptyWhenHandshakePacketFinalizesWithoutApplicationPayload) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");

    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.config_.max_outbound_datagram_size = 50;
    optional_ref_or_terminate(connection.peer_transport_parameters_).max_udp_payload_size = 50;
    connection.anti_amplification_received_bytes_ = 1200;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x95});
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 13,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.application_space_.received_packets.record_received(
            packet_number, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

    testing::internal::CaptureStderr();
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    const auto trace_stderr_output = testing::internal::GetCapturedStderr();

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto trace_packets = decode_sender_datagram(connection, datagram);
    if (trace_packets.size() != 1u) {
        FAIL() << "packet trace datagram did not contain one packet";
    }
    EXPECT_NE(std::get_if<coquic::quic::ProtectedHandshakePacket>(&trace_packets.front()), nullptr);
    EXPECT_NE(trace_stderr_output.find("quic-packet-trace app-empty scid="), std::string::npos);
}

TEST(QuicCoreTest, PacketTraceFilterMatchesExactSourceConnectionId) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");
    ScopedEnvVar filter("COQUIC_PACKET_TRACE_SCID", "5301");

    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.config_.max_outbound_datagram_size = 50;
    optional_ref_or_terminate(connection.peer_transport_parameters_).max_udp_payload_size = 50;
    connection.anti_amplification_received_bytes_ = 1200;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x96});
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 15,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.application_space_.received_packets.record_received(
            packet_number, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

    testing::internal::CaptureStderr();
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    const auto trace_stderr_output = testing::internal::GetCapturedStderr();

    ASSERT_FALSE(datagram.empty());
    EXPECT_NE(trace_stderr_output.find("quic-packet-trace app-empty scid=5301"), std::string::npos);
}

TEST(QuicCoreTest, PacketTraceFilterSuppressesNonMatchingSourceConnectionId) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");
    ScopedEnvVar filter("COQUIC_PACKET_TRACE_SCID", "deadbeef");

    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.config_.max_outbound_datagram_size = 50;
    optional_ref_or_terminate(connection.peer_transport_parameters_).max_udp_payload_size = 50;
    connection.anti_amplification_received_bytes_ = 1200;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x97});
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 17,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.application_space_.received_packets.record_received(
            packet_number, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

    testing::internal::CaptureStderr();
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    const auto trace_stderr_output = testing::internal::GetCapturedStderr();

    ASSERT_FALSE(datagram.empty());
    EXPECT_TRUE(trace_stderr_output.empty());
}

TEST(QuicCoreTest, PacketTraceLogsDiscardFailureReceiveAndSendPaths) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");

    testing::internal::CaptureStderr();

    {
        auto connection = make_connected_client_connection();
        connection.handshake_confirmed_ = false;

        const auto encoded = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = 79,
                    .frames = {coquic::quic::AckFrame{}},
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret = connection.application_space_.read_secret,
            });
        ASSERT_TRUE(encoded.has_value());

        const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
            coquic::quic::test::PacketCryptoFaultPoint::open_set_tag);
        connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));
        EXPECT_FALSE(connection.has_failed());
    }

    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::connected;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.application_space_.read_secret = make_test_traffic_secret();

        const auto invalid_packet = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = 0,
                    .frames =
                        {
                            coquic::quic::test::make_inbound_application_stream_frame("x", 0, 3),
                        },
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::client,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret = connection.application_space_.read_secret,
            });
        ASSERT_TRUE(invalid_packet.has_value());

        connection.process_inbound_datagram(invalid_packet.value(),
                                            coquic::quic::test::test_time(2));
        EXPECT_TRUE(connection.has_failed());
    }

    {
        auto connection = make_connected_server_connection();
        ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            connection,
            {coquic::quic::test::make_inbound_application_stream_frame("GET /trace\r\n",
                                                                       /*offset=*/0,
                                                                       /*stream_id=*/0,
                                                                       /*fin=*/true)},
            /*packet_number=*/1));
        const auto received = connection.take_received_stream_data();
        ASSERT_TRUE(received.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        ASSERT_TRUE(
            connection
                .queue_stream_send(0, coquic::quic::test::bytes_from_string("trace-send"), false)
                .has_value());
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
        ASSERT_FALSE(datagram.empty());
    }

    const auto stderr_output = testing::internal::GetCapturedStderr();
    EXPECT_NE(stderr_output.find("quic-packet-trace discard scid=c101"), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace fail scid=5301"), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace stream scid=5301"), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace send scid=c101"), std::string::npos);
}

} // namespace
