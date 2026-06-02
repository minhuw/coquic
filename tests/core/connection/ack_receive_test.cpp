#include "tests/support/core/connection_ack_test_support.h"

namespace {

TEST(QuicCoreTest, ApplicationAckFramesIncludeEcnCountsWhenReceiveMetadataIsAvailable) {
    auto connection = make_connected_server_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/7, /*ack_eliciting=*/true, coquic::quic::test::test_time(1),
        coquic::quic::QuicEcnCodepoint::ce);
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(1);

    const auto ack_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(ack_datagram.empty());
    auto packets = decode_sender_datagram(connection, ack_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    const auto ack_it =
        std::find_if(application->frames.begin(), application->frames.end(), [](const auto &frame) {
            return std::holds_alternative<coquic::quic::AckFrame>(frame);
        });
    ASSERT_NE(ack_it, application->frames.end());
    const auto &ack_frame = std::get<coquic::quic::AckFrame>(*ack_it);
    ASSERT_TRUE(ack_frame.ecn_counts.has_value());
    const auto &ecn_counts = optional_ref_or_terminate(ack_frame.ecn_counts);
    EXPECT_EQ(ecn_counts.ect0, 0u);
    EXPECT_EQ(ecn_counts.ect1, 0u);
    EXPECT_EQ(ecn_counts.ecn_ce, 1u);
}

TEST(QuicCoreTest, PacketInspectionQueuesDecodedOutboundOneRttPackets) {
    auto connection = make_connected_client_connection();
    connection.config_.enable_packet_inspection = true;
    ASSERT_TRUE(connection.peer_source_connection_id_.has_value());
    const auto &peer_source_connection_id =
        optional_ref_or_terminate(connection.peer_source_connection_id_);
    constexpr std::array<std::byte, 5> kPayload{
        std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'},
    };
    ASSERT_TRUE(connection.queue_stream_send(0, kPayload, false).has_value());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_packet_inspection_datagram_id(), 1u);
    auto inspection = connection.take_packet_inspection();
    ASSERT_TRUE(inspection.has_value());
    const auto &inspection_value = optional_ref_or_terminate(inspection);
    EXPECT_EQ(inspection_value.direction,
              coquic::quic::QuicCorePacketInspectionDirection::outbound);
    EXPECT_EQ(inspection_value.packet_type,
              coquic::quic::QuicCorePacketInspectionPacketType::one_rtt);
    EXPECT_EQ(inspection_value.datagram_id, 1u);
    EXPECT_EQ(inspection_value.datagram_length, datagram.size());
    EXPECT_EQ(inspection_value.datagram_offset, 0u);
    EXPECT_EQ(inspection_value.packet_length, datagram.size());
    EXPECT_EQ(inspection_value.packet_number, 0u);
    EXPECT_EQ(inspection_value.destination_connection_id, peer_source_connection_id);
    EXPECT_EQ(inspection_value.encrypted_packet.size(), datagram.size());
    ASSERT_FALSE(inspection_value.frames.empty());
    auto stream_it = std::find_if(
        inspection_value.frames.begin(), inspection_value.frames.end(), [](const auto &frame) {
            return std::holds_alternative<coquic::quic::ReceivedStreamFrame>(frame);
        });
    ASSERT_NE(stream_it, inspection_value.frames.end());
    const auto &stream = std::get<coquic::quic::ReceivedStreamFrame>(*stream_it);
    EXPECT_EQ(stream.stream_id, 0u);
    EXPECT_EQ(stream.offset, 0u);
    EXPECT_FALSE(stream.fin);
    EXPECT_EQ(stream.stream_data.to_vector(),
              std::vector<std::byte>(kPayload.begin(), kPayload.end()));
    EXPECT_FALSE(connection.take_packet_inspection().has_value());
}

TEST(QuicCoreTest, LatencySpinBitIsDisabledUnlessConfigured) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.spin.disabled = false;
    path.spin.value = true;

    EXPECT_FALSE(connection.outbound_spin_bit_for_path(0));

    connection.update_spin_bit_on_receive(0, /*peer_spin_bit=*/false, /*packet_number=*/1);
    EXPECT_TRUE(path.spin.value);
    EXPECT_FALSE(path.spin.largest_peer_packet_number.has_value());
}

TEST(QuicCoreTest, LatencySpinBitFollowsPeerOnPrimaryPathWhenEnabled) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.transport.enable_latency_spin_bit = true;
    coquic::quic::QuicConnection client(std::move(client_config));
    client.latency_spin_bit_disabled_ = false;
    client.current_send_path_id_ = 0;
    auto &client_path = client.ensure_path_state(0);
    client_path.spin.disabled = false;

    EXPECT_FALSE(client.outbound_spin_bit_for_path(0));
    client.update_spin_bit_on_receive(0, /*peer_spin_bit=*/false, /*packet_number=*/1);
    EXPECT_TRUE(client.outbound_spin_bit_for_path(0));
    client.update_spin_bit_on_receive(0, /*peer_spin_bit=*/true, /*packet_number=*/1);
    EXPECT_TRUE(client.outbound_spin_bit_for_path(0));

    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.transport.enable_latency_spin_bit = true;
    coquic::quic::QuicConnection server(std::move(server_config));
    server.latency_spin_bit_disabled_ = false;
    server.current_send_path_id_ = 0;
    auto &server_path = server.ensure_path_state(0);
    server_path.spin.disabled = false;

    server.update_spin_bit_on_receive(0, /*peer_spin_bit=*/true, /*packet_number=*/1);
    EXPECT_TRUE(server.outbound_spin_bit_for_path(0));
    server.update_spin_bit_on_receive(0, /*peer_spin_bit=*/false, /*packet_number=*/2);
    EXPECT_FALSE(server.outbound_spin_bit_for_path(0));
}

TEST(QuicCoreTest, LatencySpinBitResetsWhenPathConnectionIdChanges) {
    auto config = coquic::quic::test::make_client_core_config();
    config.transport.enable_latency_spin_bit = true;
    coquic::quic::QuicConnection connection(std::move(config));
    connection.latency_spin_bit_disabled_ = false;
    connection.current_send_path_id_ = 0;
    auto &path = connection.ensure_path_state(0);
    path.spin.disabled = false;

    connection.update_spin_bit_on_receive(0, /*peer_spin_bit=*/false, /*packet_number=*/1);
    ASSERT_TRUE(connection.outbound_spin_bit_for_path(0));
    ASSERT_TRUE(path.spin.largest_peer_packet_number.has_value());

    coquic::quic::QuicConnection::set_path_peer_connection_id_sequence(path, 4);

    EXPECT_FALSE(connection.outbound_spin_bit_for_path(0));
    EXPECT_FALSE(path.spin.largest_peer_packet_number.has_value());
}

TEST(QuicCoreTest, PacketInspectionQueuesDecodedOutboundLongHeaderPackets) {
    auto connection = make_connected_client_connection();
    connection.config_.enable_packet_inspection = true;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51});
    ASSERT_TRUE(connection.peer_source_connection_id_.has_value());
    const auto &peer_source_connection_id =
        optional_ref_or_terminate(connection.peer_source_connection_id_);

    const auto encoded = coquic::quic::serialize_protected_datagram_with_metadata(
        std::array<coquic::quic::ProtectedPacket, 2>{
            coquic::quic::ProtectedHandshakePacket{
                .version = coquic::quic::kQuicVersion1,
                .destination_connection_id = peer_source_connection_id,
                .source_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 2,
                .frames =
                    {
                        coquic::quic::CryptoFrame{
                            .offset = 0,
                            .crypto_data = bytes_from_ints({0x16, 0x03}),
                        },
                    },
            },
            coquic::quic::ProtectedZeroRttPacket{
                .version = coquic::quic::kQuicVersion1,
                .destination_connection_id = peer_source_connection_id,
                .source_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 3,
                .packet_number = 3,
                .frames =
                    {
                        coquic::quic::StreamFrame{
                            .stream_id = 0,
                            .stream_data = bytes_from_ints({0x65, 0x61, 0x72, 0x6c, 0x79}),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = connection.config_.role,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.write_secret,
            .zero_rtt_secret = connection.zero_rtt_space_.write_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    EXPECT_EQ(connection.queue_outbound_packet_inspections(encoded.value(), 17), 2u);

    auto handshake = connection.take_packet_inspection();
    ASSERT_TRUE(handshake.has_value());
    const auto &handshake_value = optional_ref_or_terminate(handshake);
    EXPECT_EQ(handshake_value.packet_type,
              coquic::quic::QuicCorePacketInspectionPacketType::handshake);
    EXPECT_EQ(handshake_value.datagram_id, 17u);
    EXPECT_EQ(handshake_value.datagram_offset, 0u);
    EXPECT_EQ(handshake_value.packet_length, encoded.value().packet_metadata.at(0).length);
    EXPECT_EQ(handshake_value.packet_number_length, 2u);
    EXPECT_EQ(handshake_value.packet_number, 2u);
    EXPECT_EQ(handshake_value.version, coquic::quic::kQuicVersion1);
    EXPECT_EQ(handshake_value.destination_connection_id, peer_source_connection_id);
    EXPECT_EQ(handshake_value.source_connection_id, connection.config_.source_connection_id);
    EXPECT_FALSE(handshake_value.plaintext_payload.empty());
    ASSERT_FALSE(handshake_value.frames.empty());
    EXPECT_NE(std::find_if(handshake_value.frames.begin(), handshake_value.frames.end(),
                           [](const auto &frame) {
                               return std::holds_alternative<coquic::quic::ReceivedCryptoFrame>(
                                   frame);
                           }),
              handshake_value.frames.end());

    auto zero_rtt = connection.take_packet_inspection();
    ASSERT_TRUE(zero_rtt.has_value());
    const auto &zero_rtt_value = optional_ref_or_terminate(zero_rtt);
    EXPECT_EQ(zero_rtt_value.packet_type,
              coquic::quic::QuicCorePacketInspectionPacketType::zero_rtt);
    EXPECT_EQ(zero_rtt_value.datagram_id, 17u);
    EXPECT_EQ(zero_rtt_value.datagram_offset, encoded.value().packet_metadata.at(1).offset);
    EXPECT_EQ(zero_rtt_value.packet_length, encoded.value().packet_metadata.at(1).length);
    EXPECT_EQ(zero_rtt_value.packet_number_length, 3u);
    EXPECT_EQ(zero_rtt_value.packet_number, 3u);
    EXPECT_EQ(zero_rtt_value.version, coquic::quic::kQuicVersion1);
    EXPECT_EQ(zero_rtt_value.destination_connection_id, peer_source_connection_id);
    EXPECT_EQ(zero_rtt_value.source_connection_id, connection.config_.source_connection_id);
    EXPECT_FALSE(zero_rtt_value.plaintext_payload.empty());
    ASSERT_FALSE(zero_rtt_value.frames.empty());
    EXPECT_NE(std::find_if(zero_rtt_value.frames.begin(), zero_rtt_value.frames.end(),
                           [](const auto &frame) {
                               return std::holds_alternative<coquic::quic::ReceivedStreamFrame>(
                                   frame);
                           }),
              zero_rtt_value.frames.end());
    EXPECT_FALSE(connection.take_packet_inspection().has_value());
}

TEST(QuicCoreTest, PacketInspectionSkipsDisabledMalformedAndUndecodableDatagrams) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection.peer_source_connection_id_.has_value());
    const auto &peer_source_connection_id =
        optional_ref_or_terminate(connection.peer_source_connection_id_);
    const auto valid_packet = std::array<coquic::quic::ProtectedPacket, 1>{
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = peer_source_connection_id,
            .packet_number = 3,
            .frames = {coquic::quic::PingFrame{}},
        },
    };
    const auto serialized = coquic::quic::serialize_protected_datagram_with_metadata(
        valid_packet, coquic::quic::SerializeProtectionContext{
                          .local_role = connection.config_.role,
                          .client_initial_destination_connection_id =
                              connection.client_initial_destination_connection_id(),
                          .one_rtt_secret = connection.application_space_.write_secret,
                      });
    ASSERT_TRUE(serialized.has_value());

    EXPECT_EQ(connection.queue_outbound_packet_inspections(serialized.value(), 7), 0u);
    EXPECT_FALSE(connection.take_packet_inspection().has_value());

    connection.config_.enable_packet_inspection = true;
    auto malformed_metadata = serialized.value();
    malformed_metadata.packet_metadata = {
        coquic::quic::SerializedProtectedPacketMetadata{
            .offset = malformed_metadata.bytes.size() + 1,
            .length = 1,
        },
        coquic::quic::SerializedProtectedPacketMetadata{
            .offset = 0,
            .length = malformed_metadata.bytes.size() + 1,
        },
    };
    EXPECT_EQ(connection.queue_outbound_packet_inspections(malformed_metadata, 8), 0u);

    auto undecodable = serialized.value();
    undecodable.bytes.span()[0] = std::byte{0xff};
    EXPECT_EQ(connection.queue_outbound_packet_inspections(undecodable, 9), 0u);
    EXPECT_FALSE(connection.take_packet_inspection().has_value());
}

TEST(QuicCoreTest, PacketInspectionSkipsDecodedPacketsWithoutPlaintextStorage) {
    coquic::quic::test::ScopedConnectionDrainTestHookReset reset_hooks;

    auto connection = make_connected_client_connection();
    connection.config_.enable_packet_inspection = true;
    ASSERT_TRUE(connection.peer_source_connection_id_.has_value());
    const auto &peer_source_connection_id =
        optional_ref_or_terminate(connection.peer_source_connection_id_);
    const auto serialized = coquic::quic::serialize_protected_datagram_with_metadata(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = peer_source_connection_id,
                .packet_number = 5,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = connection.config_.role,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.write_secret,
        });
    ASSERT_TRUE(serialized.has_value());

    coquic::quic::test::connection_set_force_packet_inspection_missing_plaintext_storage_for_tests(
        true);
    EXPECT_EQ(connection.queue_outbound_packet_inspections(serialized.value(), 10), 1u);
    coquic::quic::test::connection_set_force_packet_inspection_missing_plaintext_storage_for_tests(
        false);

    auto inspection = connection.take_packet_inspection();
    ASSERT_TRUE(inspection.has_value());
    EXPECT_TRUE(optional_ref_or_terminate(inspection).plaintext_payload.empty());
    EXPECT_FALSE(connection.take_packet_inspection().has_value());
}

TEST(QuicCoreTest, PacketInspectionSkipsMalformedMetadataAfterQueuedInspection) {
    auto connection = make_connected_client_connection();
    connection.config_.enable_packet_inspection = true;
    ASSERT_TRUE(connection.peer_source_connection_id_.has_value());
    const auto &peer_source_connection_id =
        optional_ref_or_terminate(connection.peer_source_connection_id_);
    auto serialized = coquic::quic::serialize_protected_datagram_with_metadata(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = peer_source_connection_id,
                .packet_number = 6,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = connection.config_.role,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.write_secret,
        });
    ASSERT_TRUE(serialized.has_value());
    serialized.value().packet_metadata.push_back(coquic::quic::SerializedProtectedPacketMetadata{
        .offset = serialized.value().bytes.size() + 1,
        .length = 1,
    });

    EXPECT_EQ(connection.queue_outbound_packet_inspections(serialized.value(), 11), 1u);
    EXPECT_TRUE(connection.take_packet_inspection().has_value());
    EXPECT_FALSE(connection.take_packet_inspection().has_value());
}

TEST(QuicCoreTest, ConnectionDiagnosticsExposeTransportRecoveryFlowAndStreamState) {
    auto connection = make_connected_client_connection();
    connection.processed_peer_packet_ = true;
    connection.handshake_ready_emitted_ = true;
    connection.handshake_confirmed_emitted_ = true;
    connection.anti_amplification_received_bytes_ = 1200;
    connection.anti_amplification_sent_bytes_ = 100;
    connection.initial_space_.largest_authenticated_packet_number = 3;
    connection.initial_space_.read_secret = make_test_traffic_secret();
    connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
    connection.initial_space_.pending_ack_deadline = coquic::quic::test::test_time(2);
    connection.initial_space_.force_ack_send = true;
    connection.application_space_.recovery.on_packet_sent(coquic::quic::SentPacketRecord{
        .packet_number = 4,
        .sent_time = coquic::quic::test::test_time(1),
        .ack_eliciting = true,
        .in_flight = true,
        .bytes_in_flight = 33,
    });
    connection.application_space_.recovery.on_packet_declared_lost(4);
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 5,
        .ack_eliciting = true,
    };
    auto &recovery_rtt = connection.application_space_.recovery.rtt_state();
    recovery_rtt.latest_rtt = std::chrono::milliseconds(25);
    recovery_rtt.min_rtt = std::chrono::milliseconds(12);
    recovery_rtt.smoothed_rtt = std::chrono::milliseconds(19);
    recovery_rtt.rttvar = std::chrono::milliseconds(7);
    connection.connection_flow_control_.highest_sent = 55;
    connection.connection_flow_control_.delivered_bytes = 13;
    connection.connection_flow_control_.received_committed = 21;
    auto &stream = connection.streams_
                       .emplace(0, coquic::quic::make_implicit_stream_state(
                                       0, coquic::quic::EndpointRole::client))
                       .first->second;
    stream.send_buffer.append(std::vector<std::byte>{std::byte{0x41}, std::byte{0x42}});
    stream.send_flow_control_committed = 2;
    stream.flow_control.peer_max_stream_data = 2;
    stream.send_flow_control_limit = 2;
    connection.refresh_stream_sendable_byte_caches();
    stream.highest_received_offset = 1;
    stream.receive_flow_control_consumed = 1;
    stream.reset_state = coquic::quic::StreamControlFrameState::pending;
    stream.stop_sending_state = coquic::quic::StreamControlFrameState::pending;
    stream.send_closed = true;

    auto diagnostics = connection.diagnostics(42);

    EXPECT_EQ(diagnostics.handle, 42u);
    EXPECT_TRUE(diagnostics.started);
    EXPECT_TRUE(diagnostics.processed_peer_packet);
    EXPECT_TRUE(diagnostics.handshake_ready_emitted);
    EXPECT_TRUE(diagnostics.handshake_confirmed);
    EXPECT_TRUE(diagnostics.handshake_confirmed_emitted);
    EXPECT_TRUE(diagnostics.peer_transport_parameters_validated);
    EXPECT_EQ(diagnostics.current_version, coquic::quic::kQuicVersion1);
    EXPECT_EQ(diagnostics.anti_amplification_received_bytes, 1200u);
    EXPECT_EQ(diagnostics.anti_amplification_sent_bytes, 100u);
    EXPECT_EQ(diagnostics.active_paths, 1u);
    ASSERT_TRUE(diagnostics.current_send_path_id.has_value());
    EXPECT_EQ(optional_value_or_terminate(diagnostics.current_send_path_id), 0u);
    EXPECT_EQ(diagnostics.initial_space.largest_authenticated_packet_number, 3u);
    EXPECT_TRUE(diagnostics.initial_space.read_secret_available);
    EXPECT_FALSE(diagnostics.initial_space.write_secret_available);
    EXPECT_TRUE(diagnostics.initial_space.pending_crypto);
    ASSERT_TRUE(diagnostics.initial_space.pending_ack_deadline.has_value());
    EXPECT_TRUE(diagnostics.initial_space.force_ack);
    EXPECT_TRUE(diagnostics.application_space.read_secret_available);
    EXPECT_TRUE(diagnostics.application_space.write_secret_available);
    EXPECT_EQ(diagnostics.application_space.declared_lost_packets, 1u);
    EXPECT_TRUE(diagnostics.application_space.pending_probe);
    EXPECT_EQ(diagnostics.recovery.algorithm,
              coquic::quic::QuicCongestionControlAlgorithm::newreno);
    EXPECT_TRUE(diagnostics.recovery.congestion_window > 0);
    EXPECT_EQ(diagnostics.recovery.latest_rtt_ms, 25u);
    EXPECT_EQ(diagnostics.recovery.min_rtt_ms, 12u);
    EXPECT_EQ(diagnostics.recovery.smoothed_rtt_ms, 19u);
    EXPECT_EQ(diagnostics.recovery.rttvar_ms, 7u);
    EXPECT_EQ(diagnostics.flow_control.peer_max_data,
              connection.connection_flow_control_.peer_max_data);
    EXPECT_EQ(diagnostics.flow_control.highest_sent, 55u);
    EXPECT_EQ(diagnostics.flow_control.delivered_bytes, 13u);
    EXPECT_EQ(diagnostics.flow_control.received_committed, 21u);
    EXPECT_EQ(diagnostics.stream_limits.peer_max_bidirectional,
              connection.stream_open_limits_.peer_max_bidirectional);
    ASSERT_EQ(diagnostics.streams.size(), 1u);
    const auto &stream_diagnostics = diagnostics.streams.front();
    EXPECT_EQ(stream_diagnostics.stream_id, 0u);
    EXPECT_EQ(stream_diagnostics.initiator,
              static_cast<std::uint8_t>(coquic::quic::StreamInitiator::local));
    EXPECT_TRUE(stream_diagnostics.local_can_send);
    EXPECT_TRUE(stream_diagnostics.local_can_receive);
    EXPECT_TRUE(stream_diagnostics.send_closed);
    EXPECT_TRUE(stream_diagnostics.pending_send);
    EXPECT_EQ(stream_diagnostics.sendable_bytes, 2u);
    EXPECT_EQ(stream_diagnostics.highest_received_offset, 1u);
}

TEST(QuicCoreTest, LargeAckOnlyHistoryStillEmitsTrimmedAckDatagram) {
    auto connection = make_connected_server_connection();
    for (std::uint64_t packet_number = 0; packet_number != 2048; ++packet_number) {
        connection.application_space_.received_packets.record_received(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
    }
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(4096);

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(4096));

    ASSERT_FALSE(datagram.empty());
    EXPECT_TRUE(datagram_has_application_ack(connection, datagram));
}

TEST(QuicCoreTest, ServerProcessesOneRttPingBeforeHandshakeCompletesWhenApplicationKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());

    auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .key_phase = false,
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 1,
            .packet_number = 7,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(processed.has_value());

    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ApplicationSendCanCarryBlockedControlFrames) {
    auto connection = make_connected_client_connection();
    connection.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 12};
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;
    auto &stream = connection.streams_
                       .emplace(0, coquic::quic::make_implicit_stream_state(
                                       0, coquic::quic::EndpointRole::client))
                       .first->second;
    stream.flow_control.pending_stream_data_blocked_frame = coquic::quic::StreamDataBlockedFrame{
        .stream_id = 0,
        .maximum_stream_data = 6,
    };
    stream.flow_control.stream_data_blocked_state = coquic::quic::StreamControlFrameState::pending;

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_data_blocked = false;
    bool saw_stream_data_blocked = false;
    for (const auto &frame : application->frames) {
        if (const auto *data_blocked = std::get_if<coquic::quic::DataBlockedFrame>(&frame)) {
            saw_data_blocked = true;
            EXPECT_EQ(data_blocked->maximum_data, 12u);
        }
        if (const auto *stream_data_blocked =
                std::get_if<coquic::quic::StreamDataBlockedFrame>(&frame)) {
            saw_stream_data_blocked = true;
            EXPECT_EQ(stream_data_blocked->stream_id, 0u);
            EXPECT_EQ(stream_data_blocked->maximum_stream_data, 6u);
        }
    }
    EXPECT_TRUE(saw_data_blocked);
    EXPECT_TRUE(saw_stream_data_blocked);

    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);
    const auto &sent_packet = first_tracked_packet(connection.application_space_);
    ASSERT_TRUE(sent_packet.data_blocked_frame.has_value());
    if (sent_packet.data_blocked_frame.has_value()) {
        EXPECT_EQ(sent_packet.data_blocked_frame->maximum_data, 12u);
    }
    ASSERT_EQ(sent_packet.stream_data_blocked_frames.size(), 1u);
    EXPECT_EQ(sent_packet.stream_data_blocked_frames[0].stream_id, 0u);
}

TEST(QuicCoreTest, ApplicationProbePacketCanCarryAllControlFrames) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 11,
        .ack_eliciting = true,
        .in_flight = true,
        .reset_stream_frames =
            {
                coquic::quic::ResetStreamFrame{
                    .stream_id = 0,
                    .application_protocol_error_code = 1,
                    .final_size = 2,
                },
            },
        .stop_sending_frames =
            {
                coquic::quic::StopSendingFrame{
                    .stream_id = 0,
                    .application_protocol_error_code = 3,
                },
            },
        .max_data_frame = coquic::quic::MaxDataFrame{.maximum_data = 20},
        .max_stream_data_frames =
            {
                coquic::quic::MaxStreamDataFrame{
                    .stream_id = 0,
                    .maximum_stream_data = 21,
                },
            },
        .data_blocked_frame = coquic::quic::DataBlockedFrame{.maximum_data = 22},
        .stream_data_blocked_frames =
            {
                coquic::quic::StreamDataBlockedFrame{
                    .stream_id = 0,
                    .maximum_stream_data = 23,
                },
            },
    };

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_max_data = false;
    bool saw_max_stream_data = false;
    bool saw_reset = false;
    bool saw_stop = false;
    bool saw_data_blocked = false;
    bool saw_stream_data_blocked = false;
    bool saw_ping = false;
    for (const auto &frame : application->frames) {
        saw_max_data = saw_max_data || std::holds_alternative<coquic::quic::MaxDataFrame>(frame);
        saw_max_stream_data =
            saw_max_stream_data || std::holds_alternative<coquic::quic::MaxStreamDataFrame>(frame);
        saw_reset = saw_reset || std::holds_alternative<coquic::quic::ResetStreamFrame>(frame);
        saw_stop = saw_stop || std::holds_alternative<coquic::quic::StopSendingFrame>(frame);
        saw_data_blocked =
            saw_data_blocked || std::holds_alternative<coquic::quic::DataBlockedFrame>(frame);
        saw_stream_data_blocked =
            saw_stream_data_blocked ||
            std::holds_alternative<coquic::quic::StreamDataBlockedFrame>(frame);
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_max_data);
    EXPECT_TRUE(saw_max_stream_data);
    EXPECT_TRUE(saw_reset);
    EXPECT_TRUE(saw_stop);
    EXPECT_TRUE(saw_data_blocked);
    EXPECT_TRUE(saw_stream_data_blocked);
    EXPECT_FALSE(saw_ping);
}

TEST(QuicCoreTest, CorruptedOneRttAckOnlyPacketsDoNotFailServerConnection) {
    auto base_connection = make_connected_server_connection();

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = false,
                .destination_connection_id = base_connection.config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = 7,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 3,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                base_connection.client_initial_destination_connection_id(),
            .one_rtt_secret =
                optional_ref_or_terminate(base_connection.application_space_.read_secret),
        });
    ASSERT_TRUE(encoded.has_value());
    if (!encoded.has_value()) {
        return;
    }

    const auto &datagram = encoded.value();
    ASSERT_FALSE(datagram.empty());
    for (std::size_t index = 0; index < datagram.size(); ++index) {
        auto connection = make_connected_server_connection();
        auto corrupted = datagram;
        corrupted[index] ^= std::byte{0x01};

        connection.process_inbound_datagram(corrupted, coquic::quic::test::test_time(1));

        EXPECT_FALSE(connection.has_failed()) << "corruption index=" << index;
    }
}

TEST(QuicCoreTest, AuthenticationFailureLimitClosesWithAeadLimitReached) {
    coquic::quic::test::ScopedConnectionDrainTestHookReset reset_hooks;

    auto base_connection = make_connected_server_connection();
    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = false,
                .destination_connection_id = base_connection.config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = 7,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                base_connection.client_initial_destination_connection_id(),
            .one_rtt_secret =
                optional_ref_or_terminate(base_connection.application_space_.read_secret),
        });
    ASSERT_TRUE(encoded.has_value());
    ASSERT_FALSE(encoded.value().empty());

    auto corrupted = encoded.value();
    corrupted.back() ^= std::byte{0x01};
    coquic::quic::test::connection_set_force_aead_integrity_limit_for_tests(true);

    base_connection.process_inbound_datagram(corrupted, coquic::quic::test::test_time(1));

    EXPECT_EQ(base_connection.close_mode_, coquic::quic::QuicConnectionCloseMode::closing);
    ASSERT_TRUE(base_connection.pending_transport_close_.has_value());
    EXPECT_EQ(optional_ref_or_terminate(base_connection.pending_transport_close_).error_code,
              static_cast<std::uint64_t>(coquic::quic::QuicTransportErrorCode::aead_limit_reached));
}

TEST(QuicCoreTest, CorruptedOneRttAckOnlyHeaderBitFlipsDoNotFailServerConnection) {
    auto base_connection = make_connected_server_connection();

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = false,
                .destination_connection_id = base_connection.config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = 7,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 3,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                base_connection.client_initial_destination_connection_id(),
            .one_rtt_secret =
                optional_ref_or_terminate(base_connection.application_space_.read_secret),
        });
    ASSERT_TRUE(encoded.has_value());
    if (!encoded.has_value()) {
        return;
    }

    const auto &datagram = encoded.value();
    ASSERT_FALSE(datagram.empty());
    for (const std::byte mask : {std::byte{0x02}, std::byte{0x04}, std::byte{0x08}, std::byte{0x10},
                                 std::byte{0x20}, std::byte{0x40}, std::byte{0x80}}) {
        auto connection = make_connected_server_connection();
        auto corrupted = datagram;
        corrupted.front() ^= mask;

        connection.process_inbound_datagram(corrupted, coquic::quic::test::test_time(1));

        EXPECT_FALSE(connection.has_failed())
            << "first-byte mask=" << static_cast<unsigned>(std::to_integer<std::uint8_t>(mask));
    }
}

TEST(QuicCoreTest,
     ServerEmitsHandshakeCryptoAfterOutOfOrderClientInitialRecoveryWithEmptyClientScid) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.source_connection_id = {};
    client_config.server_name = "server4";

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto start_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_EQ(start_datagrams.size(), 1u);

    const auto client_packets =
        decode_sender_datagram(*client.connection_, start_datagrams.front());
    ASSERT_EQ(client_packets.size(), 1u);
    const auto *client_initial =
        std::get_if<coquic::quic::ProtectedInitialPacket>(&client_packets.front());
    ASSERT_NE(client_initial, nullptr);

    std::size_t client_hello_size = 0;
    for (const auto &frame : client_initial->frames) {
        const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame);
        if (crypto == nullptr) {
            continue;
        }

        client_hello_size = std::max(client_hello_size, static_cast<std::size_t>(crypto->offset) +
                                                            crypto->crypto_data.size());
    }
    ASSERT_GT(client_hello_size, 128u);

    auto client_hello = std::vector<std::byte>(client_hello_size, std::byte{0x00});
    for (const auto &frame : client_initial->frames) {
        const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame);
        if (crypto == nullptr) {
            continue;
        }

        std::copy(crypto->crypto_data.begin(), crypto->crypto_data.end(),
                  client_hello.begin() + static_cast<std::ptrdiff_t>(crypto->offset));
    }

    std::size_t prefix = 63u;
    std::size_t crypto_gap = 4u;
    std::size_t tail_offset = 1230u;
    if (client_hello.size() <= tail_offset) {
        prefix = std::min<std::size_t>(63u, client_hello.size() / 4u);
        crypto_gap = 1u;
        tail_offset = prefix + crypto_gap + ((client_hello.size() - (prefix + crypto_gap)) / 2u);
    }
    ASSERT_LT(prefix + crypto_gap, tail_offset);
    ASSERT_LT(tail_offset, client_hello.size());

    const auto slice_bytes = [&](std::size_t begin, std::size_t end) {
        return std::vector<std::byte>(client_hello.begin() + static_cast<std::ptrdiff_t>(begin),
                                      client_hello.begin() + static_cast<std::ptrdiff_t>(end));
    };

    coquic::quic::ProtectedInitialPacket delivered_packet_one{
        .version = client_initial->version,
        .destination_connection_id = client_initial->destination_connection_id,
        .source_connection_id = client_initial->source_connection_id,
        .token = client_initial->token,
        .packet_number_length = client_initial->packet_number_length,
        .packet_number = 1,
        .frames =
            {
                coquic::quic::CryptoFrame{
                    .offset = static_cast<std::uint64_t>(prefix),
                    .crypto_data = slice_bytes(prefix, prefix + crypto_gap),
                },
                coquic::quic::CryptoFrame{
                    .offset = static_cast<std::uint64_t>(tail_offset),
                    .crypto_data = slice_bytes(tail_offset, client_hello.size()),
                },
            },
    };
    coquic::quic::ProtectedInitialPacket delivered_packet_two{
        .version = client_initial->version,
        .destination_connection_id = client_initial->destination_connection_id,
        .source_connection_id = client_initial->source_connection_id,
        .token = client_initial->token,
        .packet_number_length = client_initial->packet_number_length,
        .packet_number = 2,
        .frames =
            {
                coquic::quic::CryptoFrame{
                    .offset = static_cast<std::uint64_t>(prefix + crypto_gap),
                    .crypto_data = slice_bytes(prefix + crypto_gap, tail_offset),
                },
                coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = slice_bytes(0u, prefix),
                },
            },
    };

    const auto pad_initial = [&](const coquic::quic::ProtectedInitialPacket &input_packet) {
        auto packet = input_packet;
        auto encoded = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{packet},
            coquic::quic::SerializeProtectionContext{
                .local_role = client.connection_->config_.role,
                .client_initial_destination_connection_id =
                    client.connection_->client_initial_destination_connection_id(),
                .handshake_secret = client.connection_->handshake_space_.write_secret,
                .one_rtt_secret = client.connection_->application_space_.write_secret,
                .one_rtt_key_phase = client.connection_->application_write_key_phase_,
            });
        EXPECT_TRUE(encoded.has_value());
        if (!encoded.has_value()) {
            return std::vector<std::byte>{};
        }
        if (encoded.value().size() < 1200u) {
            packet.frames.emplace_back(coquic::quic::PaddingFrame{
                .length = 1200u - encoded.value().size(),
            });
        }
        auto padded = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{std::move(packet)},
            coquic::quic::SerializeProtectionContext{
                .local_role = client.connection_->config_.role,
                .client_initial_destination_connection_id =
                    client.connection_->client_initial_destination_connection_id(),
                .handshake_secret = client.connection_->handshake_space_.write_secret,
                .one_rtt_secret = client.connection_->application_space_.write_secret,
                .one_rtt_key_phase = client.connection_->application_write_key_phase_,
            });
        EXPECT_TRUE(padded.has_value());
        if (!padded.has_value()) {
            return std::vector<std::byte>{};
        }
        return padded.value();
    };

    const auto first_datagram = pad_initial(delivered_packet_one);
    auto server_after_first = server.advance(coquic::quic::QuicCoreInboundDatagram{first_datagram},
                                             coquic::quic::test::test_time(1));
    EXPECT_FALSE(server.has_failed());

    const auto first_response_datagrams =
        coquic::quic::test::send_datagrams_from(server_after_first);
    ASSERT_FALSE(first_response_datagrams.empty());
    for (const auto &datagram : first_response_datagrams) {
        auto packets = decode_sender_datagram(*server.connection_, datagram);
        for (const auto &packet : packets) {
            const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packet);
            if (initial == nullptr) {
                continue;
            }
            for (const auto &frame : initial->frames) {
                EXPECT_FALSE(std::holds_alternative<coquic::quic::CryptoFrame>(frame));
            }
        }
    }

    const auto second_datagram = pad_initial(delivered_packet_two);
    auto server_after_second = server.advance(
        coquic::quic::QuicCoreInboundDatagram{second_datagram}, coquic::quic::test::test_time(2));
    EXPECT_FALSE(server.has_failed());

    const auto response_datagrams = coquic::quic::test::send_datagrams_from(server_after_second);
    ASSERT_FALSE(response_datagrams.empty());

    bool saw_initial_crypto = false;
    bool saw_handshake_crypto = false;
    for (const auto &datagram : response_datagrams) {
        auto packets = decode_sender_datagram(*server.connection_, datagram);
        for (const auto &packet : packets) {
            if (const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packet)) {
                for (const auto &frame : initial->frames) {
                    if (std::holds_alternative<coquic::quic::CryptoFrame>(frame)) {
                        saw_initial_crypto = true;
                    }
                }
                continue;
            }

            const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packet);
            if (handshake == nullptr) {
                continue;
            }

            for (const auto &frame : handshake->frames) {
                if (std::holds_alternative<coquic::quic::CryptoFrame>(frame)) {
                    saw_handshake_crypto = true;
                }
            }
        }
    }

    EXPECT_TRUE(saw_initial_crypto);
    EXPECT_TRUE(saw_handshake_crypto);
}

TEST(QuicCoreTest, ApplicationPtoWaitsForClientHandshakeConfirmation) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());
    client.connection_->handshake_confirmed_ = false;
    client.connection_->discard_initial_packet_space();
    client.connection_->discard_handshake_packet_space();

    const auto server_send = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("server-probe"),
        },
        coquic::quic::test::test_time(1));
    EXPECT_TRUE(server_send.next_wakeup.has_value());

    const auto client_before_confirmation = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("client-probe"),
        },
        coquic::quic::test::test_time(2));
    EXPECT_EQ(client_before_confirmation.next_wakeup, std::nullopt);

    auto server_after_client_probe = coquic::quic::test::relay_send_datagrams_to_peer(
        client_before_confirmation, server, coquic::quic::test::test_time(3));
    if (coquic::quic::test::send_datagrams_from(server_after_client_probe).empty()) {
        const auto ack_deadline = server.connection_->next_wakeup();
        ASSERT_TRUE(ack_deadline.has_value());
        server_after_client_probe = server.advance(coquic::quic::QuicCoreTimerExpired{},
                                                   optional_value_or_terminate(ack_deadline));
    }
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(server_after_client_probe).empty());

    const auto client_after_ack = coquic::quic::test::relay_send_datagrams_to_peer(
        server_after_client_probe, client, coquic::quic::test::test_time(4));
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(client_after_ack).empty());

    auto client_after_confirmation = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("client-after-ack"),
        },
        coquic::quic::test::test_time(5));
    EXPECT_TRUE(client_after_confirmation.next_wakeup.has_value());
}

TEST(QuicCoreTest, ServerApplicationPtoRunsBeforeHandshakeConfirmation) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::sent;
    connection.discard_initial_packet_space();
    connection.discard_handshake_packet_space();

    ASSERT_TRUE(
        connection
            .queue_stream_send(0, coquic::quic::test::bytes_from_string("server-probe"), false)
            .has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());

    const auto next_wakeup = connection.next_wakeup();
    ASSERT_TRUE(next_wakeup.has_value());
    if (!next_wakeup.has_value()) {
        return;
    }

    connection.on_timeout(*next_wakeup);
    auto probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(probe_datagram.empty());

    auto packets = decode_sender_datagram(connection, probe_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }
    EXPECT_TRUE(saw_stream);
}

TEST(QuicCoreTest, AckProcessingClearsOutstandingDataAndKeepsReceiveKeepaliveWakeup) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto confirm = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("confirm"),
        },
        coquic::quic::test::test_time(1));
    const auto confirm_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        confirm, server, coquic::quic::test::test_time(2));
    const auto confirm_acked = coquic::quic::test::relay_send_datagrams_to_peer(
        confirm_delivered, client, coquic::quic::test::test_time(3));
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(confirm_acked).empty());

    const auto sent = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ack-clear"),
        },
        coquic::quic::test::test_time(4));
    EXPECT_TRUE(sent.next_wakeup.has_value());
    ASSERT_NE(tracked_packet_count(client.connection_->application_space_), 0u);
    ASSERT_TRUE(client.connection_->streams_.contains(0));
    EXPECT_TRUE(client.connection_->streams_.at(0).has_outstanding_send());

    const auto server_step = coquic::quic::test::relay_send_datagrams_to_peer(
        sent, server, coquic::quic::test::test_time(5));
    const auto client_step = coquic::quic::test::relay_send_datagrams_to_peer(
        server_step, client, coquic::quic::test::test_time(6));

    EXPECT_FALSE(client.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(client_step).empty());
    EXPECT_EQ(tracked_packet_count(client.connection_->application_space_), 0u);
    EXPECT_FALSE(client.connection_->streams_.at(0).has_pending_send());
    EXPECT_FALSE(client.connection_->streams_.at(0).has_outstanding_send());
    EXPECT_EQ(client_step.next_wakeup, client.connection_->next_wakeup());
    EXPECT_TRUE(client_step.next_wakeup.has_value());
}

TEST(QuicCoreTest, CompletedBidirectionalStreamRetiresAfterLocalFinAckAndPeerFinDelivery) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto request = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 4,
            .bytes = coquic::quic::test::bytes_from_string("request"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    const auto request_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        request, server, coquic::quic::test::test_time(2));
    EXPECT_EQ(coquic::quic::test::received_application_data_from(request_delivered),
              coquic::quic::test::bytes_from_string("request"));

    const auto request_acked = coquic::quic::test::relay_send_datagrams_to_peer(
        request_delivered, client, coquic::quic::test::test_time(3));
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(request_acked).empty());
    ASSERT_TRUE(client.connection_->streams_.contains(4));

    auto response = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 4,
            .bytes = coquic::quic::test::bytes_from_string("response"),
            .fin = true,
        },
        coquic::quic::test::test_time(4));
    const auto response_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        response, client, coquic::quic::test::test_time(5));
    EXPECT_EQ(coquic::quic::test::received_application_data_from(response_delivered),
              coquic::quic::test::bytes_from_string("response"));
    EXPECT_FALSE(client.connection_->streams_.contains(4));
}

TEST(QuicCoreTest, AckProcessingUsesLargestNewlyAcknowledgedPacketForRttSample) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(10),
                                     .ack_eliciting = false,
                                     .in_flight = false,
                                 });

    auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 2,
            .first_ack_range = 1,
        },
        coquic::quic::test::test_time(70), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().latest_rtt,
              std::optional{std::chrono::milliseconds(60)});
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().smoothed_rtt,
              std::chrono::milliseconds(60));
}

TEST(QuicCoreTest, AckProcessingClampsAckDelayWhenExponentIsTooLarge) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });

    auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 1,
            .ack_delay = 1,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(40), std::numeric_limits<std::uint64_t>::digits,
        /*max_ack_delay_ms=*/25, /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().latest_rtt,
              std::optional{std::chrono::milliseconds(40)});
}

TEST(QuicCoreTest, OptimisticAckMitigationSkipsPacketNumbersAndRejectsAcksForThem) {
    auto config = coquic::quic::test::make_client_core_config();
    config.transport.enable_optimistic_ack_mitigation = true;
    coquic::quic::QuicConnection connection(std::move(config));

    std::vector<std::uint64_t> sent_packet_numbers;
    for (std::int64_t index = 0; index < 16; ++index) {
        const auto packet_number = connection.reserve_packet_number(connection.application_space_);
        sent_packet_numbers.push_back(packet_number);
        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = packet_number,
                                         .sent_time = coquic::quic::test::test_time(index),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                     });
    }

    ASSERT_EQ(sent_packet_numbers.back(), 16u);
    EXPECT_EQ(connection.application_space_.next_send_packet_number, 18u);
    EXPECT_EQ(connection.application_space_.recovery.find_packet(8), nullptr);
    EXPECT_EQ(connection.application_space_.recovery.find_packet(17), nullptr);

    auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 8,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(40), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);

    EXPECT_FALSE(processed.has_value());
    EXPECT_EQ(connection.close_mode_, coquic::quic::QuicConnectionCloseMode::closing);
    ASSERT_TRUE(connection.pending_transport_close_.has_value());
    EXPECT_EQ(optional_ref_or_terminate(connection.pending_transport_close_).error_code,
              static_cast<std::uint64_t>(coquic::quic::QuicTransportErrorCode::protocol_violation));
}

TEST(QuicCoreTest, AckProcessingDisablesEcnWhenAckOmitsCountsForNewlyAckedEct0Packets) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::probing;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::ect0,
                                 });

    auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 1,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(10), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::failed);
}

TEST(QuicCoreTest, AckProcessingTreatsCeCounterGrowthAsSingleCongestionEvent) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::capable;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::ect0,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(2),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::ect0,
                                 });

    auto first = connection.process_inbound_ack(connection.application_space_,
                                                coquic::quic::AckFrame{
                                                    .largest_acknowledged = 1,
                                                    .first_ack_range = 0,
                                                    .ecn_counts =
                                                        coquic::quic::AckEcnCounts{
                                                            .ect0 = 0,
                                                            .ect1 = 0,
                                                            .ecn_ce = 1,
                                                        },
                                                },
                                                coquic::quic::test::test_time(10),
                                                /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
                                                /*suppress_pto_reset=*/false);
    ASSERT_TRUE(first.has_value());
    auto first_reduction = connection.congestion_controller_.congestion_window();

    auto second = connection.process_inbound_ack(connection.application_space_,
                                                 coquic::quic::AckFrame{
                                                     .largest_acknowledged = 2,
                                                     .first_ack_range = 0,
                                                     .ecn_counts =
                                                         coquic::quic::AckEcnCounts{
                                                             .ect0 = 1,
                                                             .ect1 = 0,
                                                             .ecn_ce = 1,
                                                         },
                                                 },
                                                 coquic::quic::test::test_time(12),
                                                 /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
                                                 /*suppress_pto_reset=*/false);

    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(connection.congestion_controller_.congestion_window(), first_reduction);
}

TEST(QuicCoreTest, AckProcessingValidatesEct1CountsIndependently) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::probing;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect1;

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::ect1,
                                 });

    auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 1,
            .first_ack_range = 0,
            .ecn_counts =
                coquic::quic::AckEcnCounts{
                    .ect0 = 0,
                    .ect1 = 1,
                    .ecn_ce = 0,
                },
        },
        coquic::quic::test::test_time(10), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::capable);
}

TEST(QuicCoreTest, StaleLargestAcknowledgedPacketDoesNotGenerateRttSample) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(10),
                                     .ack_eliciting = false,
                                     .in_flight = false,
                                 });

    auto first = connection.process_inbound_ack(connection.application_space_,
                                                coquic::quic::AckFrame{
                                                    .largest_acknowledged = 2,
                                                    .first_ack_range = 0,
                                                },
                                                coquic::quic::test::test_time(20),
                                                /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
                                                /*suppress_pto_reset=*/false);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().latest_rtt, std::nullopt);

    auto second = connection.process_inbound_ack(connection.application_space_,
                                                 coquic::quic::AckFrame{
                                                     .largest_acknowledged = 2,
                                                     .first_ack_range = 1,
                                                 },
                                                 coquic::quic::test::test_time(70),
                                                 /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
                                                 /*suppress_pto_reset=*/false);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().latest_rtt, std::nullopt);
}

TEST(QuicCoreTest, PtoBackoffIsConnectionWideAcrossPacketSpaces) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });

    ASSERT_EQ(connection.pto_deadline(), coquic::quic::test::test_time(999));

    connection.on_timeout(coquic::quic::test::test_time(999));

    EXPECT_EQ(connection.pto_deadline(), std::optional{coquic::quic::test::test_time(1998)});
}

TEST(QuicCoreTest, HandshakePtoUsesConnectionRttSampleFromInitialSpace) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.pto_count_ = 3;

    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);

    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(100),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });

    EXPECT_EQ(connection.pto_deadline(), std::optional{coquic::quic::test::test_time(340)});
}

TEST(QuicCoreTest, HandshakePtoProbeDoesNotCapClientBackoffOutsideInitialSpace) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.pto_count_ = 3;

    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);

    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(100),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });

    connection.arm_pto_probe(coquic::quic::test::test_time(220));

    EXPECT_EQ(connection.pto_count_, 3u);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, DiscardingInitialPacketSpaceResetsPtoBackoff) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.pto_count_ = 3;

    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);

    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(80),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(100),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = 1200,
                                 });

    ASSERT_EQ(connection.congestion_controller_.bytes_in_flight(), 2400u);

    connection.discard_initial_packet_space();

    EXPECT_EQ(connection.congestion_controller_.bytes_in_flight(), 1200u);
    EXPECT_EQ(connection.pto_count_, 0u);
    EXPECT_EQ(connection.pto_deadline(), std::optional{coquic::quic::test::test_time(130)});
}

TEST(QuicCoreTest, NewlyAcknowledgedNonAckElicitingPacketsResetPtoBackoff) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.pto_count_ = 3;

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 7,
                                     .sent_time = coquic::quic::test::test_time(10),
                                     .ack_eliciting = false,
                                     .in_flight = false,
                                 });

    auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 7,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(40), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 0u);
}

TEST(QuicCoreTest, DetectLostPacketsMarksCryptoRangesLostAndKeepsRecoveryStateForLateAcks) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.initial_space_.recovery.largest_acked_packet_number_ = 5;
    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);

    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("init"));
    const auto crypto_ranges = connection.initial_space_.send_crypto.take_ranges(4);
    ASSERT_EQ(crypto_ranges.size(), 1u);

    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .crypto_ranges = crypto_ranges,
                                 });

    connection.detect_lost_packets(connection.initial_space_, coquic::quic::test::test_time(20));

    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 1u);
    EXPECT_TRUE(connection.initial_space_.send_crypto.has_pending_data());
    EXPECT_EQ(connection.initial_space_.recovery.largest_acked_packet_number(),
              std::optional<std::uint64_t>{5});
    auto initial_packet = &tracked_packet_or_terminate(connection.initial_space_, 0);
    EXPECT_TRUE(initial_packet->declared_lost);
    EXPECT_FALSE(initial_packet->in_flight);
}

TEST(QuicCoreTest, DetectLostApplicationPacketsRequeuesApplicationCryptoRanges) {
    auto connection = make_connected_server_connection();
    connection.application_space_.recovery.largest_acked_packet_number_ = 5;
    connection.application_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.application_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.application_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.application_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);

    connection.application_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("app-crypto"));
    const auto crypto_ranges = connection.application_space_.send_crypto.take_ranges(10);
    ASSERT_EQ(crypto_ranges.size(), 1u);

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .crypto_ranges = crypto_ranges,
                                 });

    connection.detect_lost_packets(connection.application_space_,
                                   coquic::quic::test::test_time(20));

    EXPECT_EQ(tracked_packet_count(connection.application_space_), 1u);
    EXPECT_TRUE(connection.application_space_.send_crypto.has_pending_data());
    EXPECT_EQ(connection.application_space_.recovery.largest_acked_packet_number(),
              std::optional<std::uint64_t>{5});
    const auto &application_packet = tracked_packet_or_terminate(connection.application_space_, 0);
    EXPECT_TRUE(application_packet.declared_lost);
    EXPECT_FALSE(application_packet.in_flight);
}

TEST(QuicCoreTest, DetectLostPacketsLeavesPacketsQueuedWhenNoLossThresholdIsMet) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.initial_space_.recovery.largest_acked_packet_number_ = 4;
    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);

    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 4,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(9),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = false,
                                     .in_flight = false,
                                 });

    connection.detect_lost_packets(connection.initial_space_, coquic::quic::test::test_time(10));

    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 3u);
}

TEST(QuicCoreTest, RebuildRecoveryPreservesLargestAckedAndOutstandingPackets) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.recovery.largest_acked_packet_number_ = 9;
    connection.handshake_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(8);
    connection.handshake_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(8);
    connection.handshake_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(8);
    connection.handshake_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(4);

    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 4,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 7,
                                     .sent_time = coquic::quic::test::test_time(2),
                                     .ack_eliciting = false,
                                     .in_flight = false,
                                 });

    connection.rebuild_recovery(connection.handshake_space_);

    EXPECT_EQ(connection.handshake_space_.recovery.largest_acked_packet_number(),
              std::optional<std::uint64_t>{9});
    EXPECT_EQ(connection.handshake_space_.recovery.rtt_state().latest_rtt,
              std::optional{std::chrono::milliseconds(8)});
    EXPECT_EQ(connection.handshake_space_.recovery.tracked_packet_count(), 2u);
    ASSERT_NE(connection.handshake_space_.recovery.find_packet(4), nullptr);
    ASSERT_NE(connection.handshake_space_.recovery.find_packet(7), nullptr);
    EXPECT_EQ(connection.handshake_space_.recovery.find_packet(4)->packet_number, 4u);
    EXPECT_EQ(connection.handshake_space_.recovery.find_packet(7)->packet_number, 7u);
}

TEST(QuicCoreTest, RebuildRecoveryHandlesPacketSpacesWithoutAcknowledgments) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });

    connection.rebuild_recovery(connection.application_space_);

    EXPECT_EQ(connection.application_space_.recovery.largest_acked_packet_number(), std::nullopt);
    ASSERT_NE(connection.application_space_.recovery.find_packet(1), nullptr);
    EXPECT_EQ(connection.application_space_.recovery.find_packet(1)->packet_number, 1u);
}

} // namespace
