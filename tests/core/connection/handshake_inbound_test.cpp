#include "tests/support/core/connection_handshake_test_support.h"

namespace {

TEST(QuicCoreTest, UnexpectedFirstInboundDatagramsFailAndLaterCallsAreInert) {
    coquic::quic::QuicConnection client(coquic::quic::test::make_client_core_config());
    client.process_inbound_datagram(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00}),
                                    coquic::quic::test::test_time());
    EXPECT_TRUE(client.has_failed());

    client.start();
    ASSERT_TRUE(client.queue_stream_send(0, coquic::quic::test::bytes_from_string("ignored"), false)
                    .has_value());
    client.status_ = coquic::quic::HandshakeStatus::idle;
    ASSERT_TRUE(client.queue_stream_send(0, {}, false).has_value());
    EXPECT_FALSE(client.streams_.contains(0));
    client.status_ = coquic::quic::HandshakeStatus::failed;
    client.process_inbound_datagram(std::span<const std::byte>{}, coquic::quic::test::test_time(1));
    EXPECT_FALSE(client.drain_outbound_datagram(coquic::quic::test::test_time(2)).empty());
    EXPECT_TRUE(client.drain_outbound_datagram(coquic::quic::test::test_time(3)).empty());
    EXPECT_FALSE(client.take_received_stream_data().has_value());

    coquic::quic::QuicConnection server(coquic::quic::test::make_server_core_config());
    server.process_inbound_datagram(std::span<const std::byte>{}, coquic::quic::test::test_time(3));
    EXPECT_FALSE(server.has_failed());

    server.process_inbound_datagram(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x04}),
                                    coquic::quic::test::test_time(4));
    EXPECT_TRUE(server.has_failed());
}

TEST(QuicCoreTest, ServerStartupFailureReturnsAfterStartingTls) {
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.identity.reset();
    coquic::quic::QuicConnection server(std::move(server_config));

    server.process_inbound_datagram(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x02}),
        coquic::quic::test::test_time());

    EXPECT_TRUE(server.has_failed());
}

TEST(QuicCoreTest, ConnectionProcessInboundCryptoCoversErrorBranches) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    expect_codec_failure(connection.process_inbound_crypto(
                             coquic::quic::EncryptionLevel::initial,
                             std::array<coquic::quic::Frame, 1>{
                                 coquic::quic::test::make_inbound_application_stream_frame("x")},
                             coquic::quic::test::test_time()),
                         coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);

    expect_codec_success(connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial,
        std::array<coquic::quic::Frame, 1>{coquic::quic::CryptoFrame{}},
        coquic::quic::test::test_time(1)));

    expect_codec_failure(
        connection.process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                          std::array<coquic::quic::Frame, 1>{
                                              coquic::quic::CryptoFrame{
                                                  .offset = (std::uint64_t{1} << 62),
                                                  .crypto_data = {std::byte{0x01}},
                                              },
                                          },
                                          coquic::quic::test::test_time(2)),
        coquic::quic::CodecErrorCode::invalid_varint);

    expect_codec_failure(connection.process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                                           std::array<coquic::quic::Frame, 1>{
                                                               coquic::quic::CryptoFrame{
                                                                   .offset = 0,
                                                                   .crypto_data = {std::byte{0x01}},
                                                               },
                                                           },
                                                           coquic::quic::test::test_time(3)),
                         coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    connection.start_client_if_needed();
    auto &connection_tls = connection.tls_;
    if (!connection_tls.has_value()) {
        ADD_FAILURE() << "expected client startup to initialize TLS state";
        return;
    }
    coquic::quic::test::TlsAdapterTestPeer::set_sticky_error(
        *connection_tls, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
    expect_codec_failure(connection.process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                                           std::array<coquic::quic::Frame, 1>{
                                                               coquic::quic::CryptoFrame{
                                                                   .offset = 1,
                                                                   .crypto_data = {std::byte{0x02}},
                                                               },
                                                           },
                                                           coquic::quic::test::test_time(4)),
                         coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicCoreTest, ConnectionProcessInboundCryptoAcceptsPingBeforeCryptoFrames) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    expect_codec_success(connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial,
        std::array<coquic::quic::Frame, 2>{coquic::quic::PingFrame{}, coquic::quic::CryptoFrame{}},
        coquic::quic::test::test_time()));

    expect_codec_success(connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::handshake,
        std::array<coquic::quic::Frame, 2>{coquic::quic::PingFrame{}, coquic::quic::CryptoFrame{}},
        coquic::quic::test::test_time(1)));
}

TEST(QuicCoreTest, ProcessInboundPacketLeavesInitialAndHandshakeStateUntouchedOnFailure) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    const coquic::quic::CodecResult<bool> initial_failure = connection.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .version = 1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = {std::byte{0xaa}},
            .packet_number_length = 2,
            .packet_number = 0,
            .frames = {coquic::quic::test::make_inbound_application_stream_frame("x")},
        },
        coquic::quic::test::test_time());
    ASSERT_FALSE(initial_failure.has_value());
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());

    connection.handshake_space_.write_secret = make_test_traffic_secret();
    const coquic::quic::CodecResult<bool> handshake_failure = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .version = 1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 2,
            .packet_number = 1,
            .frames = {coquic::quic::test::make_inbound_application_stream_frame("y")},
        },
        coquic::quic::test::test_time(1));
    ASSERT_FALSE(handshake_failure.has_value());
    EXPECT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundPacketIgnoresInitialPacketAfterInitialSpaceDiscard) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.initial_packet_space_discarded_ = true;

    const coquic::quic::CodecResult<bool> processed = connection.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = {std::byte{0x44}},
            .packet_number_length = 1,
            .packet_number = 1,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(processed.value());
    EXPECT_FALSE(connection.initial_space_.largest_authenticated_packet_number.has_value());
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ConnectionProcessInboundApplicationCoversAckReorderAndErrorBranches) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const coquic::quic::CodecResult<bool> ack_and_padding = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 3>{
            coquic::quic::AckFrame{},
            coquic::quic::PaddingFrame{.length = 2},
            coquic::quic::test::make_inbound_application_stream_frame("ok"),
        },
        coquic::quic::test::test_time());
    ASSERT_TRUE(ack_and_padding.has_value());
    const std::optional<coquic::quic::QuicCoreReceiveStreamData> first_received =
        connection.take_received_stream_data();
    ASSERT_TRUE(first_received.has_value());
    if (!first_received.has_value()) {
        return;
    }
    const auto &first_stream = *first_received;
    EXPECT_EQ(coquic::quic::test::string_from_bytes(first_stream.bytes), "ok");

    const coquic::quic::CodecResult<bool> reordered = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("x", 4),
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(reordered.has_value());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    const coquic::quic::CodecResult<bool> gap_filled = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("yz", 2),
        },
        coquic::quic::test::test_time(2));
    ASSERT_TRUE(gap_filled.has_value());
    const std::optional<coquic::quic::QuicCoreReceiveStreamData> gap_filled_received =
        connection.take_received_stream_data();
    ASSERT_TRUE(gap_filled_received.has_value());
    if (!gap_filled_received.has_value()) {
        return;
    }
    const auto &gap_filled_stream = *gap_filled_received;
    EXPECT_EQ(coquic::quic::test::string_from_bytes(gap_filled_stream.bytes), "yzx");

    const coquic::quic::CodecResult<bool> overflow = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("x", std::uint64_t{1} << 62),
        },
        coquic::quic::test::test_time(3));
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const coquic::quic::CodecResult<bool> missing_offset_value =
        connection.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{
                coquic::quic::StreamFrame{
                    .fin = false,
                    .has_offset = true,
                    .has_length = true,
                    .stream_id = 0,
                    .offset = std::nullopt,
                    .stream_data = {std::byte{'x'}},
                },
            },
            coquic::quic::test::test_time(4));
    ASSERT_FALSE(missing_offset_value.has_value());
    EXPECT_EQ(missing_offset_value.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest, ConnectionPacketLengthParserRejectsRemainingMalformedInputs) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());

    const coquic::quic::CodecResult<std::size_t> truncated_version =
        connection.peek_next_packet_length(bytes_from_ints({0xc0, 0x00, 0x00}));
    ASSERT_FALSE(truncated_version.has_value());
    EXPECT_EQ(truncated_version.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const coquic::quic::CodecResult<std::size_t> missing_dcid_length =
        connection.peek_next_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01}));
    ASSERT_FALSE(missing_dcid_length.has_value());
    EXPECT_EQ(missing_dcid_length.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const coquic::quic::CodecResult<std::size_t> oversized_dcid =
        connection.peek_next_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x15}));
    ASSERT_FALSE(oversized_dcid.has_value());
    EXPECT_EQ(oversized_dcid.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const coquic::quic::CodecResult<std::size_t> truncated_scid =
        connection.peek_next_packet_length(
            bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x02, 0x03}));
    ASSERT_FALSE(truncated_scid.has_value());
    EXPECT_EQ(truncated_scid.error().code, coquic::quic::CodecErrorCode::truncated_input);

    expect_codec_failure(connection.peek_next_packet_length(bytes_from_ints(
                             {0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02})),
                         coquic::quic::CodecErrorCode::truncated_input);

    expect_codec_failure(connection.peek_next_packet_length(bytes_from_ints(
                             {0xe0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02})),
                         coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicCoreTest, ConnectionStartupHelpersCoverReentryAndTlsFailure) {
    coquic::quic::QuicConnection server(coquic::quic::test::make_server_core_config());
    server.start_client_if_needed();
    EXPECT_FALSE(server.started_);

    coquic::quic::QuicConnection client(coquic::quic::test::make_client_core_config());
    client.start_client_if_needed();
    ASSERT_TRUE(client.started_);
    const auto original_status = client.status_;
    client.start_client_if_needed();
    EXPECT_EQ(client.status_, original_status);

    const coquic::quic::test::ScopedTlsAdapterFaultInjector injector(
        coquic::quic::test::TlsAdapterFaultPoint::initialize_ctx_new);
    coquic::quic::QuicConnection failing_client(coquic::quic::test::make_client_core_config());
    failing_client.start_client_if_needed();
    EXPECT_TRUE(failing_client.has_failed());

    coquic::quic::QuicConnection second_server(coquic::quic::test::make_server_core_config());
    second_server.start_server_if_needed({std::byte{0x01}, std::byte{0x02}});
    ASSERT_TRUE(second_server.started_);
    const auto initial_dcid = second_server.client_initial_destination_connection_id_;
    second_server.start_server_if_needed({std::byte{0x03}});
    EXPECT_EQ(second_server.client_initial_destination_connection_id_, initial_dcid);
}

TEST(QuicCoreTest, ServerStartupRetainsUnsupportedClientVersionWithoutCompatibleFallback) {
    auto config = coquic::quic::test::make_server_core_config();
    config.supported_versions = {coquic::quic::kQuicVersion1};

    coquic::quic::QuicConnection connection(std::move(config));
    connection.start_server_if_needed({std::byte{0x01}, std::byte{0x02}}, 0xa1b2c3d4u);

    EXPECT_TRUE(connection.started_);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.original_version_, 0xa1b2c3d4u);
    EXPECT_EQ(connection.current_version_, 0xa1b2c3d4u);
}

TEST(QuicCoreTest, DeferredProtectedPacketVectorEqualityRejectsMismatchedBytesAndNonzeroIds) {
    const auto bytes = bytes_from_ints({0x01, 0x02});
    EXPECT_FALSE(coquic::quic::DeferredProtectedPacket(bytes, 7) == bytes);
    EXPECT_FALSE(bytes == coquic::quic::DeferredProtectedPacket(bytes, 7));
    EXPECT_FALSE(coquic::quic::DeferredProtectedPacket(bytes, 0) == bytes_from_ints({0x01, 0x03}));
}

TEST(QuicCoreTest, QueueApplicationCloseReturnsSuccessWhenConnectionAlreadyFailed) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::failed;

    const coquic::quic::StreamStateResult<bool> result = connection.queue_application_close({
        .application_error_code = 7,
        .reason_phrase = "ignored",
    });

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
    EXPECT_FALSE(connection.pending_application_close_.has_value());
}

TEST(QuicCoreTest, ServerCreatedFromRetriedInitialKeepsOriginalVersionValidationContext) {
    auto server_config = coquic::quic::test::make_server_core_config();
    const auto retry_source_connection_id = bytes_from_hex("5300000000000001");
    const auto original_destination_connection_id = bytes_from_hex("8394c8f03e515708");
    const auto client_source_connection_id = bytes_from_hex("1d84ffd8036c94a5");
    server_config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};
    server_config.initial_destination_connection_id = retry_source_connection_id;
    server_config.original_destination_connection_id = original_destination_connection_id;
    server_config.retry_source_connection_id = retry_source_connection_id;

    coquic::quic::QuicConnection server(std::move(server_config));
    server.start_server_if_needed(retry_source_connection_id, coquic::quic::kQuicVersion1);

    EXPECT_EQ(server.original_version_, coquic::quic::kQuicVersion1);
    EXPECT_EQ(server.current_version_, coquic::quic::kQuicVersion1);
    EXPECT_FALSE(server.local_transport_parameters_.version_information.has_value());

    server.peer_source_connection_id_ = client_source_connection_id;
    const auto context = server.peer_transport_parameters_validation_context();
    ASSERT_TRUE(context.has_value());
    const auto &context_value = optional_ref_or_terminate(context);
    EXPECT_FALSE(context_value.expected_version_information.has_value());

    expect_codec_success(coquic::quic::validate_peer_transport_parameters(
        coquic::quic::EndpointRole::client,
        coquic::quic::TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 8,
            .initial_source_connection_id = client_source_connection_id,
        },
        context_value));
}

TEST(QuicCoreTest, ConnectionStartupRejectsInvalidLocalTransportParameters) {
    auto bad_client_config = coquic::quic::test::make_client_core_config();
    bad_client_config.transport.ack_delay_exponent = 21;
    coquic::quic::QuicConnection bad_client(std::move(bad_client_config));
    bad_client.start_client_if_needed();
    EXPECT_TRUE(bad_client.started_);
    EXPECT_TRUE(bad_client.has_failed());
    EXPECT_FALSE(bad_client.tls_.has_value());

    auto bad_server_config = coquic::quic::test::make_server_core_config();
    bad_server_config.transport.max_ack_delay = (1u << 14);
    coquic::quic::QuicConnection bad_server(std::move(bad_server_config));
    bad_server.start_server_if_needed({std::byte{0x01}});
    EXPECT_TRUE(bad_server.started_);
    EXPECT_TRUE(bad_server.has_failed());
    EXPECT_FALSE(bad_server.tls_.has_value());
}

TEST(QuicCoreTest, ConnectionStartupRejectsUnserializableLocalTransportParameters) {
    auto bad_client_config = coquic::quic::test::make_client_core_config();
    bad_client_config.transport.initial_max_data = (std::uint64_t{1} << 62);
    coquic::quic::QuicConnection bad_client(std::move(bad_client_config));
    bad_client.start_client_if_needed();
    EXPECT_TRUE(bad_client.started_);
    EXPECT_TRUE(bad_client.has_failed());
    EXPECT_FALSE(bad_client.tls_.has_value());

    auto bad_server_config = coquic::quic::test::make_server_core_config();
    bad_server_config.transport.initial_max_stream_data_uni = (std::uint64_t{1} << 62);
    coquic::quic::QuicConnection bad_server(std::move(bad_server_config));
    bad_server.start_server_if_needed({std::byte{0x01}});
    EXPECT_TRUE(bad_server.started_);
    EXPECT_TRUE(bad_server.has_failed());
    EXPECT_FALSE(bad_server.tls_.has_value());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsForDecodeAndPacketProcessingErrors) {
    coquic::quic::QuicConnection decode_failure(coquic::quic::test::make_client_core_config());
    decode_failure.start_client_if_needed();
    decode_failure.process_inbound_datagram(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x11, 0x01, 0x22, 0x00, 0x00}),
        coquic::quic::test::test_time());
    EXPECT_TRUE(decode_failure.has_failed());

    coquic::quic::QuicConnection packet_failure(coquic::quic::test::make_server_core_config());
    packet_failure.started_ = true;
    packet_failure.status_ = coquic::quic::HandshakeStatus::connected;
    packet_failure.client_initial_destination_connection_id_ =
        packet_failure.config_.initial_destination_connection_id;
    packet_failure.application_space_.read_secret = make_test_traffic_secret();

    const coquic::quic::CodecResult<std::vector<std::byte>> invalid_packet =
        coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = packet_failure.config_.source_connection_id,
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
                    packet_failure.client_initial_destination_connection_id(),
                .handshake_secret = std::nullopt,
                .one_rtt_secret = packet_failure.application_space_.read_secret,
            });
    ASSERT_TRUE(invalid_packet.has_value());
    packet_failure.process_inbound_datagram(invalid_packet.value(),
                                            coquic::quic::test::test_time(1));
    EXPECT_TRUE(packet_failure.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramDropsHandshakePacketWithoutReadSecret) {
    coquic::quic::QuicConnection connection(make_connected_client_connection());
    const auto handshake_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const coquic::quic::CodecResult<std::vector<std::byte>> packet =
        coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedHandshakePacket{
                    .version = 1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = {std::byte{0xaa}},
                    .packet_number_length = 2,
                    .packet_number = 0,
                    .frames = {coquic::quic::AckFrame{}},
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = handshake_secret,
                .one_rtt_secret = std::nullopt,
            });
    ASSERT_TRUE(packet.has_value());

    connection.process_inbound_datagram(packet.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::connected);
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresInitialPacketsAfterDiscardingInitialSpace) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const coquic::quic::QuicCoreResult to_server =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const coquic::quic::QuicCoreResult to_client = coquic::quic::test::relay_send_datagrams_to_peer(
        to_server, server, coquic::quic::test::test_time(1));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(to_client).empty());

    const coquic::quic::QuicCoreResult client_handshake =
        coquic::quic::test::relay_send_datagrams_to_peer(to_client, client,
                                                         coquic::quic::test::test_time(2));
    EXPECT_FALSE(client.has_failed());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(client_handshake).empty());
    ASSERT_NE(client.connection_, nullptr);
    EXPECT_FALSE(client.connection_->initial_space_.read_secret.has_value());
    EXPECT_FALSE(client.connection_->initial_space_.write_secret.has_value());

    const coquic::quic::QuicCoreResult replayed = coquic::quic::test::relay_send_datagrams_to_peer(
        to_client, client, coquic::quic::test::test_time(3));

    EXPECT_FALSE(client.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(replayed).empty());
    ASSERT_NE(client.connection_, nullptr);
    EXPECT_TRUE(client.connection_->deferred_protected_packets_.empty());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresHandshakePacketsAfterDiscardingHandshakeSpace) {
    auto connection = make_connected_client_connection();
    connection.discard_handshake_packet_space();

    const coquic::quic::CodecResult<std::vector<std::byte>> late_handshake =
        coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedHandshakePacket{
                    .version = coquic::quic::kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = bytes_from_hex("0011223344556677"),
                    .packet_number_length = 2,
                    .packet_number = 1,
                    .frames = {coquic::quic::PingFrame{}},
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = make_test_traffic_secret(
                    coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51}),
                .one_rtt_secret = connection.application_space_.read_secret,
                .one_rtt_key_phase = connection.application_read_key_phase_,
            });
    ASSERT_TRUE(late_handshake.has_value());

    connection.process_inbound_datagram(late_handshake.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
}

std::vector<std::byte> captured_quic_go_server_first_flight() {
    return bytes_from_hex(
        "c30000000108c10000000000002504c516a3560041cc1deadd79519b2fb4b57443729da026692a0dc7f"
        "4495ca82f945e2dc0ac9a1d8392619cf89b43a7142506dfb58efea1be1331363abac7357ea84a30941b"
        "ec1f9d1b8bd312eb7a2a42fe440a1ddc22c50ab227a566d5364c387804206ae94926141c11a1ecc4517"
        "d7bf4120900bd2dfb914964c2e893b6294a3856990fb9699ff830a5eaf6feb19e6f6d8d920559a3bf78"
        "36f8fe5bdb3762c82b3ea148eb9de532a355460abb753cde6f06e6f2883be9c19a377755f06a3d8232e"
        "ded0c04fd25acdb84d78052a1890517f9db4ff5c634f28b254c19971aaa1c94a6424b2b5c9fa34e4c41"
        "b730ea60e4621dedc2a11060e15d3bf4e788a9763f4791e9f2f2d32738220a0dc97da2253172a77377a"
        "be9c67c21c6e7013cbd372b2259db0b7c50427b4bf6be5320ff41acf1b38e25d5f5e95ecbcde9755eb2"
        "d31fb4c69de9fc4b48af6868a360e5aa064945faaed1ffd478cbf422a6ca712a107c9f449fa682d0757"
        "5624d07929c38fc9937f1b794272a743ef0917c7a7b81a194b22f89fa121ae4e8e8814404f10f238f87"
        "af1930ac85c7533768a1e44e241c6b1117ecb4524132e6c9d86a08e5f8ea9f70b3cdff0f0211be98aa6"
        "380017b98a42b79539b87564e1494057a8240915462c68f7600e50000000108c10000000000002504c5"
        "16a35642d69c355c6679ac9a9f79e36c4ce9ed05c4950c3d96f8f3538294ba93c6570c3c7af1609d4e2"
        "68878ad02bcb4ec6d3d6726810ee4353734bc91e8d24d57b7a9b9d56e815b834eaf85f6fc005a52d6f49"
        "bbe14cfd83bac593dd2805efddc614e5cdceaabdf4ed2558d61118776ec50f9cf0ec65364543cf27ddf"
        "71ab38aa94fc6a4d20e5c239be9bfa3bc1768d3bda0e898c0718411040bc71f8708119ee7240886cf1c"
        "5a01204efaa120c056ed30777d0c64b024c7704142892f54caf3787924ba6256acecf00e2fd08cfe96d"
        "efe0f790578963c1450e8ad395ad892aca310b59b58cca60685a3cea2cf3242ec072c6b8b905ecddc4c"
        "0d08121c184d906752399c9fdc9334b557c20b47d7b5d6ac3580fab59a76fd3d605855e2cc963c67318"
        "4694e141d251075538289546cb6a713454850c22dd308fa8f8cacee9a50a2494b5d995b9a736cc437a1"
        "ae3aac1376083952befcac0d89235969d92cb3f8b832d3af74c1c04a95f1b8feec48fd7f40b0e1ac7fc"
        "b09584d436085c3e279a946ffff9714a359e63c1727f4b6f3d2b140ad3f37666e49d343da95b28f68a3"
        "9c3f59b8a1605941b2af21dfbbfa7ec8a31d8364a6d6663d1d5d052a046dc453e80a6089e0792e78cb7"
        "37c50e835bc50bb1e054b088517e5fed5cd78454a5fd06fdba2602e16438e84b44d3d66cab42897a382"
        "d1c407f2d773b774f8145b790e6aa8b309ec3bdfabc007a2deb984a1c436971be35907cfb024515d4ae"
        "ce019ce45543bde728c9deb8fa640c633388dcae74dee123e08d67cb0e0f190e255eb9826f94ccfbf8b"
        "e65c7b760df36697e315a979a01919e6a80e3f1f7e9f17836cfdc9a552ace0fae5629882bb97acfa1ce"
        "b73863edcd96e34e527fcac22821c129820d8644601727d903ac746411f11854b1067681116bce36620"
        "d3fc12d1e53c0bba977ee8ec08d27057fcf0cdd909b142a97ad547f3432785048cb646c78f5c945484e"
        "ddca1a7164e021e7f5d6e17d12dee1a07f5e1eb7b47901cf9554c100000000000025497da86827cf8147"
        "6875e5177ad6778c56fcc61d249695ffa7f085554cd4d61755fabd13ade985796962");
}

TEST(QuicCoreTest, ProcessCapturedQuicGoServerInitialInstallsHandshakeSecrets) {
    auto config = coquic::quic::test::make_client_core_config();
    config.source_connection_id = bytes_from_hex("c100000000000025");
    config.initial_destination_connection_id = bytes_from_hex("8300000000000024");

    coquic::quic::QuicConnection connection(config);
    connection.start_client_if_needed();
    connection.initial_space_.next_send_packet_number = 1;
    ASSERT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());

    const auto server_first_flight = captured_quic_go_server_first_flight();

    const auto initial_packet_bytes = std::span<const std::byte>(server_first_flight).first(482);
    const auto handshake_packet_bytes =
        std::span<const std::byte>(server_first_flight).subspan(482, 747);
    const coquic::quic::CodecResult<std::vector<coquic::quic::ProtectedPacket>> initial_decode =
        coquic::quic::deserialize_protected_datagram(
            initial_packet_bytes, coquic::quic::DeserializeProtectionContext{
                                      .peer_role = coquic::quic::EndpointRole::server,
                                      .client_initial_destination_connection_id =
                                          config.initial_destination_connection_id,
                                  });
    ASSERT_TRUE(initial_decode.has_value());
    ASSERT_EQ(initial_decode.value().size(), 1u);
    ASSERT_TRUE(std::holds_alternative<coquic::quic::ProtectedInitialPacket>(
        initial_decode.value().front()));

    auto probe_connection = coquic::quic::QuicConnection(config);
    probe_connection.start_client_if_needed();
    ASSERT_FALSE(probe_connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());
    probe_connection.process_inbound_datagram(initial_packet_bytes,
                                              coquic::quic::test::test_time(1));
    ASSERT_FALSE(probe_connection.has_failed());
    ASSERT_TRUE(probe_connection.handshake_space_.read_secret.has_value());
    ASSERT_TRUE(probe_connection.handshake_space_.write_secret.has_value());
    EXPECT_EQ(optional_ref_or_terminate(probe_connection.handshake_space_.read_secret).cipher_suite,
              coquic::quic::CipherSuite::tls_aes_128_gcm_sha256);
    EXPECT_EQ(
        optional_ref_or_terminate(probe_connection.handshake_space_.write_secret).cipher_suite,
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256);
    EXPECT_EQ(
        optional_ref_or_terminate(probe_connection.handshake_space_.read_secret).secret.size(),
        32u);
    EXPECT_EQ(
        optional_ref_or_terminate(probe_connection.handshake_space_.write_secret).secret.size(),
        32u);

    expect_protected_datagram_starts_with_handshake(coquic::quic::deserialize_protected_datagram(
        handshake_packet_bytes,
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                probe_connection.client_initial_destination_connection_id(),
            .handshake_secret =
                coquic::quic::TrafficSecret{
                    .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
                    .secret = bytes_from_hex(
                        "9f8d726a3e3d755a0a0e1af69344628c46fe4db9c573c554966b35b3ceaa14b1"),
                },
        }));

    // The client handshake secrets are derived from an ephemeral key share, so a captured server
    // flight only stays stable through the Initial packet. Verify those stable Initial-packet
    // properties here, and keep the captured Handshake packet as a fixed codec vector above.
    connection.process_inbound_datagram(initial_packet_bytes, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_hex("c516a356"));
    ASSERT_TRUE(connection.handshake_space_.write_secret.has_value());

    const coquic::quic::DatagramBuffer response =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(response.empty());

    const std::vector<coquic::quic::ProtectedPacket> packets =
        decode_sender_datagram(connection, response);
    const std::vector<coquic::quic::ProtectedPacket>::const_iterator initial_packet =
        std::find_if(packets.begin(), packets.end(), [](const auto &packet) {
            return std::holds_alternative<coquic::quic::ProtectedInitialPacket>(packet);
        });

    EXPECT_NE(initial_packet, packets.end());
    EXPECT_FALSE(connection.initial_packet_space_discarded_);
}

TEST(QuicCoreTest, ClientSendsStandaloneHandshakeAckBeforeHandshakeFlight) {
    auto config = coquic::quic::test::make_client_core_config();
    config.source_connection_id = bytes_from_hex("c100000000000025");
    config.initial_destination_connection_id = bytes_from_hex("8300000000000024");

    coquic::quic::QuicConnection connection(config);
    connection.start_client_if_needed();
    connection.initial_space_.next_send_packet_number = 1;
    ASSERT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());

    const auto server_first_flight = captured_quic_go_server_first_flight();
    const auto initial_packet_bytes = std::span<const std::byte>(server_first_flight).first(482);

    connection.process_inbound_datagram(initial_packet_bytes, coquic::quic::test::test_time(1));
    ASSERT_FALSE(connection.has_failed());
    ASSERT_TRUE(connection.handshake_space_.read_secret.has_value());
    ASSERT_TRUE(connection.handshake_space_.write_secret.has_value());

    ASSERT_NE(tracked_packet_count(connection.initial_space_), 0u);
    const auto initial_packet_number =
        first_tracked_packet(connection.initial_space_).packet_number;
    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.initial_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = initial_packet_number,
                                             .first_ack_range = 0,
                                         },
                                         coquic::quic::test::test_time(1),
                                         /*ack_delay_exponent=*/0,
                                         /*max_ack_delay_ms=*/0,
                                         /*suppress_pto_reset=*/true)
                    .has_value());

    expect_codec_success(connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .source_connection_id = bytes_from_hex("0011223344556677"),
            .packet_number = 1,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(2)));

    const coquic::quic::DatagramBuffer response =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(response.empty());
    EXPECT_TRUE(connection.initial_packet_space_discarded_);

    const std::vector<coquic::quic::ProtectedPacket> response_packets =
        decode_sender_datagram(connection, response);
    EXPECT_NE(std::find_if(
                  response_packets.begin(), response_packets.end(),
                  [](const auto &packet) {
                      return std::holds_alternative<coquic::quic::ProtectedHandshakePacket>(packet);
                  }),
              response_packets.end());
}

TEST(QuicCoreTest, ClientKeepsPtoArmedAfterServerInitialAckWithoutHandshakeFlight) {
    auto config = coquic::quic::test::make_client_core_config();
    config.source_connection_id = bytes_from_hex("c100000000000025");
    config.initial_destination_connection_id = bytes_from_hex("8300000000000024");

    coquic::quic::QuicConnection connection(config);
    connection.start_client_if_needed();
    connection.initial_space_.next_send_packet_number = 1;
    ASSERT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());

    const auto server_first_flight = captured_quic_go_server_first_flight();
    const auto initial_packet_bytes = std::span<const std::byte>(server_first_flight).first(482);

    connection.process_inbound_datagram(initial_packet_bytes, coquic::quic::test::test_time(1));
    ASSERT_FALSE(connection.has_failed());
    ASSERT_TRUE(connection.handshake_space_.read_secret.has_value());
    ASSERT_TRUE(connection.handshake_space_.write_secret.has_value());

    ASSERT_NE(tracked_packet_count(connection.initial_space_), 0u);
    const auto initial_packet_number =
        first_tracked_packet(connection.initial_space_).packet_number;
    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.initial_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = initial_packet_number,
                                             .first_ack_range = 0,
                                         },
                                         coquic::quic::test::test_time(1),
                                         /*ack_delay_exponent=*/0,
                                         /*max_ack_delay_ms=*/0,
                                         /*suppress_pto_reset=*/true)
                    .has_value());
    EXPECT_FALSE(std::ranges::any_of(
        tracked_packet_snapshot(connection.initial_space_),
        [](const auto &packet) { return packet.ack_eliciting && packet.in_flight; }));
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);

    const coquic::quic::DatagramBuffer response =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(response.empty());

    const std::vector<coquic::quic::ProtectedPacket> response_packets =
        decode_sender_datagram(connection, response);
    EXPECT_NE(std::find_if(response_packets.begin(), response_packets.end(),
                           [](const auto &packet) {
                               return std::holds_alternative<coquic::quic::ProtectedInitialPacket>(
                                   packet);
                           }),
              response_packets.end());
    EXPECT_EQ(std::count_if(
                  response_packets.begin(), response_packets.end(),
                  [](const auto &packet) {
                      return std::holds_alternative<coquic::quic::ProtectedHandshakePacket>(packet);
                  }),
              0);
    EXPECT_FALSE(std::ranges::any_of(
        tracked_packet_snapshot(connection.initial_space_),
        [](const auto &packet) { return packet.ack_eliciting && packet.in_flight; }));
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);

    const std::optional<coquic::quic::QuicCoreTimePoint> next_wakeup = connection.next_wakeup();
    ASSERT_TRUE(next_wakeup.has_value());
}

TEST(QuicCoreTest, ClientKeepsHandshakeKeepaliveArmedAfterAckOnlyHandshakeDiscardedInitialSpace) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.initial_packet_space_discarded_ = true;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51});

    const std::optional<coquic::quic::QuicCoreTimePoint> deadline_opt = connection.pto_deadline();
    ASSERT_TRUE(deadline_opt.has_value());
    const coquic::quic::QuicCoreTimePoint deadline =
        deadline_opt.value_or(coquic::quic::test::test_time());

    connection.arm_pto_probe(deadline);

    ASSERT_TRUE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());

    const coquic::quic::DatagramBuffer probe = connection.drain_outbound_datagram(deadline);
    ASSERT_FALSE(probe.empty());

    const std::vector<coquic::quic::ProtectedPacket> probe_packets =
        decode_sender_datagram(connection, probe);
    ASSERT_EQ(probe_packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&probe_packets[0]);
    ASSERT_NE(handshake, nullptr);
    EXPECT_NE(std::find_if(handshake->frames.begin(), handshake->frames.end(),
                           [](const auto &frame) {
                               return std::holds_alternative<coquic::quic::PingFrame>(frame);
                           }),
              handshake->frames.end());
    EXPECT_EQ(connection.last_client_handshake_keepalive_probe_time_, std::optional{deadline});
}

TEST(QuicCoreTest, ProcessInboundDatagramDefersLaterMissingContextPacketAfterValidInitial) {
    auto config = coquic::quic::test::make_client_core_config();
    config.source_connection_id = bytes_from_hex("c100000000000025");
    config.initial_destination_connection_id = bytes_from_hex("8300000000000024");

    coquic::quic::QuicConnection connection(config);
    connection.start_client_if_needed();
    connection.initial_space_.next_send_packet_number = 1;
    ASSERT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());

    const auto server_first_flight = captured_quic_go_server_first_flight();
    const auto initial_packet_bytes = std::span<const std::byte>(server_first_flight).first(482);
    const coquic::quic::CodecResult<std::vector<std::byte>> buffered_packet =
        coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = 0,
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
                .one_rtt_secret = make_test_traffic_secret(
                    coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51}),
            });
    ASSERT_TRUE(buffered_packet.has_value()) << static_cast<int>(buffered_packet.error().code);

    std::vector<std::byte> datagram(initial_packet_bytes.begin(), initial_packet_bytes.end());
    datagram.insert(datagram.end(), buffered_packet.value().begin(), buffered_packet.value().end());

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::in_progress);
    EXPECT_TRUE(connection.handshake_space_.read_secret.has_value());
    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), buffered_packet.value());
}

std::vector<std::byte> captured_picoquic_client_initial_datagram() {
    return bytes_from_hex(
        "ce00000001085398e92f19c3659808825ff16a7a5d8b9f0041409c471d3fbfe46c43389ad82ab17702dc"
        "9686e7157b4dcceaeecc13f61aef037f58b15e94c06417a351f30d50cf1152098bb49ce2b69c3ba80bd5"
        "cb9e1086f9a7f6d2f854b5b5638b23486d23ad1651202d87997ba51cb9f7a14d20bb430b4e6b5e25b940"
        "16b0d7ad981ae8e883a49a461444a531929c5d24044b6964cfeb5b2132e0053a434ecdd0ea2ae8adb8ca"
        "274e2ee7e6d680ea6d4756e4c37268970177613d2f31b6db1cb0799bb2f506830c96de55b72228253a6c"
        "f4d0f3512e5d93b7d8cb262a471ca0ec44eba3ceadd500870849b5cf00782bbb38188c49c95b776c97ae"
        "0fecd918f499525b6b9a61d900fb43844de41cc805abbef8c99b5727003a094b22955c2e582a45057521"
        "9cac4d4b3c51be3a436bae6e032b619c5773547abebf9f63ad9ab519f19c6813411b76e9b040d48c9d94"
        "ef16dd17aaca9bf3cd862e27007aec392281967ec218de253c37c2bc45aec40570b5c1aad297b56e3fcf"
        "aaea35a0bc7c53de7e3d5fe4a7786a02a205421d5aa9a40a4dfcc7df3415d42a96256ed422dfdeda4322"
        "8c84f714b0f312521fd34edb356fd1fc12a5c49e6b77e16cf6198a29e196a0d7afe26a8fb46ecd1215f1"
        "7125619b579e9b13e0a982faaa42605f50f992140560e3011a64248df0a6a7ac87a4b500c70206618c8c"
        "1df51145aebd76773470ca88b8cb2fb2f47bfbeb92736837d9d94dfcc7df3415d42ab2fb517033e41d7e"
        "49f54b4fddd99742ea55c6f02aea1cd3e8e4327f860d7c18c6c455b78b0f5245e98165442b45d00b4272"
        "ca77bae3d14f7e3b68f2a426ef3429eca95eb24cd1ba7c55c7ff46bae3f2614ede6e8b679bde2d52f465"
        "ab4ee9d6a72efd6b9974c9a8cad66100d27e107a7bc695cfb229120dcd21c583eae090e5164faff7db96"
        "1e139012e71c657a89b5b9770e24bbcce8b5f7f9c2a9c0146cbf1512d156bbd182301c01a7eb252a0133"
        "83bcd866859e51ff2e4322839f64f0d0357213b2d610f696fe1bc3b48fa3ad8fd349e1426c6d6c6fec01"
        "acd9304cba80bcfd4bde751f4c76cabd262fee0c15bbfbfccd0c7a547857cd813a4977f6befab20399e8"
        "62e65c0eb81f95e27387f233ef0c82823c62f61da922b268caa09bc585ee26a645b56f735231bf8ca7fe"
        "3f65387fa669c229e7f4ac0115d6da7a5ab3c84c9633a67d8b00bcae2898b8203d9d7d7e04664bc2a782"
        "672ac79f3f8de8bd3cd89730557b0a94ae103b715f221a4713cf04b42b0dd948e9089cedaf267bbbcb40"
        "e06180aa90932ede76825f3e6d6badc2542cc8746986368ce3038a36782c60cf8da7279859cbd92033d6"
        "294238f2fa3a780f5141350c9994ac0ce4814653a4d8acad56eeeeb857cf6e97a5e4542f5e3e56f9f06b"
        "0b351a0cc6bb2a7ed3af43fd69e576e20bf4fb578b83bebb79c984c3f167bb065c745cb0d6e1e83cb620"
        "e9427e6352d431fe3c0fe6a8507155c6c6117cdea8048b6637546140320447dc4b4ce533bde22778023a"
        "6e94413981afd021b3d3d6e34cc91786e95414083731cf1e8efb8e6497734a67021d7e3174391d616388"
        "da325bd70449c0f3f823f1da82c67add7701068e673ef0dba9d912082ffde7aefba917324ace49e22202"
        "fe73854a4d994a2c60696815a474a2510bca2bdec845fe96333be55b5d59e068223510494d812491b7ff"
        "cbb9abb1db0b1dbec9b72a644bf39ef778a68cec4d70120c56d9b3fa7eea849e980f");
}

TEST(QuicCoreTest, ProcessCapturedPicoquicClientInitialPacketStartsServerHandshake) {
    auto datagram = captured_picoquic_client_initial_datagram();

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.client_initial_destination_connection_id(),
              bytes_from_hex("5398e92f19c36598"));
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_hex("825ff16a7a5d8b9f"));
    EXPECT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
}

TEST(QuicCoreTest, ServerHandshakeFlightStaysWithinAmplificationBudgetBeforeValidation) {
    auto datagram = captured_picoquic_client_initial_datagram();
    const auto initial_packet_bytes = std::span<const std::byte>(datagram).first(346);

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(initial_packet_bytes, coquic::quic::test::test_time(1));
    connection.anti_amplification_received_bytes_ = initial_packet_bytes.size();
    connection.anti_amplification_sent_bytes_ = 0;

    ASSERT_FALSE(connection.has_failed());

    std::size_t total_sent = 0;
    while (true) {
        const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (response.empty()) {
            break;
        }
        total_sent += response.size();
    }

    EXPECT_LE(total_sent, initial_packet_bytes.size() * 3u);
}

TEST(QuicCoreTest, ServerPtoProbeStaysWithinAmplificationBudgetBeforeValidation) {
    auto datagram = captured_picoquic_client_initial_datagram();
    const auto initial_packet_bytes = std::span<const std::byte>(datagram).first(346);

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(initial_packet_bytes, coquic::quic::test::test_time(1));
    connection.anti_amplification_received_bytes_ = initial_packet_bytes.size();
    connection.anti_amplification_sent_bytes_ = 0;

    ASSERT_FALSE(connection.has_failed());

    std::size_t total_sent = 0;
    while (true) {
        const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (response.empty()) {
            break;
        }
        total_sent += response.size();
    }

    const auto wakeup = connection.next_wakeup();
    ASSERT_TRUE(wakeup.has_value());
    if (!wakeup.has_value()) {
        return;
    }

    connection.on_timeout(*wakeup);
    while (true) {
        const auto response = connection.drain_outbound_datagram(*wakeup);
        if (response.empty()) {
            break;
        }
        total_sent += response.size();
    }

    EXPECT_LE(total_sent, initial_packet_bytes.size() * 3u);
}

TEST(QuicCoreTest, DuplicatePicoquicClientInitialRetransmitsHandshakeFlight) {
    auto datagram = captured_picoquic_client_initial_datagram();

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));
    ASSERT_FALSE(connection.has_failed());

    auto first_responses = std::vector<std::vector<std::byte>>{};
    while (true) {
        const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (response.empty()) {
            break;
        }
        first_responses.push_back(response);
    }
    ASSERT_FALSE(first_responses.empty());
    const auto first_handshake_packet_count = tracked_packet_count(connection.handshake_space_);
    ASSERT_GT(first_handshake_packet_count, 0u);
    const auto first_handshake_next_packet_number =
        connection.handshake_space_.next_send_packet_number;

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(2));
    ASSERT_FALSE(connection.has_failed());

    auto second_responses = std::vector<std::vector<std::byte>>{};
    while (true) {
        const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
        if (response.empty()) {
            break;
        }
        second_responses.push_back(response);
    }
    ASSERT_FALSE(second_responses.empty());
    EXPECT_GT(tracked_packet_count(connection.handshake_space_), first_handshake_packet_count);
    EXPECT_GT(connection.handshake_space_.next_send_packet_number,
              first_handshake_next_packet_number);
}

TEST(QuicCoreTest, AntiAmplificationAccountingIgnoresZeroByteDatagrams) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 12;
    connection.anti_amplification_sent_bytes_ = 15;

    connection.note_inbound_datagram_bytes(0);
    connection.note_outbound_datagram_bytes(0);

    EXPECT_EQ(connection.anti_amplification_received_bytes_, 12u);
    EXPECT_EQ(connection.anti_amplification_sent_bytes_, 15u);
}

TEST(QuicCoreTest, ConnectedServerWithoutValidatedPeerStillUsesInitialAmplificationBudget) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 1252;
    connection.anti_amplification_sent_bytes_ = 2880;
    connection.current_send_path_id_ = 0;
    connection.ensure_path_state(0).validated = false;
    connection.ensure_path_state(0).anti_amplification_received_bytes = 9000;

    const auto remaining_budget = connection.outbound_datagram_size_limit();
    EXPECT_EQ(remaining_budget, 876u);

    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x64});
    connection.handshake_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(1400), std::byte{0x31}));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_LE(datagram.size(), remaining_budget);
    EXPECT_EQ(connection.anti_amplification_sent_bytes_, 2880u + datagram.size());
    EXPECT_EQ(connection.ensure_path_state(0).anti_amplification_sent_bytes, 0u);
    EXPECT_EQ(connection.outbound_datagram_size_limit(), remaining_budget - datagram.size());
    EXPECT_TRUE(connection.handshake_space_.send_crypto.has_pending_data());
}

TEST(QuicCoreTest, ConnectedServerWithoutValidatedPeerDoesNotArmPtoAtAmplificationLimit) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 1252;
    connection.anti_amplification_sent_bytes_ = 3756;
    connection.current_send_path_id_ = 0;
    connection.ensure_path_state(0).validated = false;
    connection.ensure_path_state(0).anti_amplification_received_bytes = 9000;
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = 100,
                                 });

    EXPECT_FALSE(connection.pto_deadline().has_value());

    connection.on_timeout(coquic::quic::test::test_time(100000));

    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_EQ(connection.pto_count_, 0u);
}

TEST(QuicCoreTest, FirstServerInitialCanBeBlockedByAmplificationLimit) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 10;
    connection.anti_amplification_sent_bytes_ = 0;
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 7,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 0u);
    EXPECT_EQ(connection.initial_space_.next_send_packet_number, 0u);
}

TEST(QuicCoreTest, ProcessCapturedPicoquicClientInitialPacketEmitsInitialCrypto) {
    auto datagram = captured_picoquic_client_initial_datagram();

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    const auto outbound = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(outbound.empty());
    ASSERT_NE(tracked_packet_count(connection.initial_space_), 0u);
    EXPECT_FALSE(first_tracked_packet(connection.initial_space_).crypto_ranges.empty());
}

TEST(QuicCoreTest, InitialPacketIncreasesSharedBytesInFlight) {
    auto datagram = captured_picoquic_client_initial_datagram();

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    const auto outbound = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(outbound.empty());
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);
    EXPECT_GT(connection.congestion_controller_.bytes_in_flight(), 0u);
}

TEST(QuicCoreTest, InitialAckUpdatesSharedCongestionController) {
    auto datagram = captured_picoquic_client_initial_datagram();

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    const auto outbound = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(outbound.empty());
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);
    const auto packet_number = first_tracked_packet(connection.initial_space_).packet_number;
    ASSERT_GT(connection.congestion_controller_.bytes_in_flight(), 0u);

    const auto bytes_in_flight_before_ack = connection.congestion_controller_.bytes_in_flight();
    const auto acked = connection.process_inbound_ack(connection.initial_space_,
                                                      coquic::quic::AckFrame{
                                                          .largest_acknowledged = packet_number,
                                                          .first_ack_range = 0,
                                                      },
                                                      coquic::quic::test::test_time(2),
                                                      /*ack_delay_exponent=*/0,
                                                      /*max_ack_delay_ms=*/0,
                                                      /*suppress_pto_reset=*/false);

    ASSERT_TRUE(acked.has_value());
    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 0u);
    EXPECT_LT(connection.congestion_controller_.bytes_in_flight(), bytes_in_flight_before_ack);
}

TEST(QuicCoreTest, ClientFirstHandshakeSendDiscardsInitialBeforeCongestionCheck) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.peer_source_connection_id_ = bytes_from_ints({0x53, 0x01});
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.send_crypto.append(bytes_from_ints({0x01, 0x02, 0x03}));
    connection.congestion_controller_.congestion_window_ = 1200;
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.initial_space_.next_send_packet_number = 1;
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 0,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    ASSERT_EQ(connection.congestion_controller_.bytes_in_flight(), 1200u);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_TRUE(connection.initial_packet_space_discarded_);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 0u);
    expect_single_packet_kind(datagram, ProtectedPacketKind::handshake);
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 1u);
}

TEST(QuicCoreTest, ProcessCapturedPicoquicClientInitialIgnoresTrailingDatagramPadding) {
    auto datagram = captured_picoquic_client_initial_datagram();

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.client_initial_destination_connection_id(),
              bytes_from_hex("5398e92f19c36598"));
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_hex("825ff16a7a5d8b9f"));
    EXPECT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresMalformedTrailingFragmentAfterValidPacket) {
    auto datagram = captured_picoquic_client_initial_datagram();
    datagram.resize(346);
    const auto trailing_fragment =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x01});
    datagram.insert(datagram.end(), trailing_fragment.begin(), trailing_fragment.end());

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.client_initial_destination_connection_id(),
              bytes_from_hex("5398e92f19c36598"));
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_hex("825ff16a7a5d8b9f"));
    EXPECT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresUndecryptableTrailingFragmentAfterValidPacket) {
    auto datagram = captured_picoquic_client_initial_datagram();
    datagram.resize(346);
    const auto trailing_fragment =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x01, 0x00});
    datagram.insert(datagram.end(), trailing_fragment.begin(), trailing_fragment.end());

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.client_initial_destination_connection_id(),
              bytes_from_hex("5398e92f19c36598"));
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_hex("825ff16a7a5d8b9f"));
    EXPECT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenTlsSyncValidationFails) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::connected;
    connection.client_initial_destination_connection_id_ = connection.config_.source_connection_id;
    connection.peer_source_connection_id_ = {std::byte{0xaa}};
    connection.application_space_.read_secret = make_test_traffic_secret();
    connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::server,
        .verify_peer = false,
        .server_name = "localhost",
        .identity = connection.config_.identity,
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(*connection.tls_,
                                                                          {std::byte{0x40}});

    const coquic::quic::CodecResult<std::vector<std::byte>> sync_failure_packet =
        coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = 0,
                    .frames = {coquic::quic::AckFrame{}},
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::client,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = std::nullopt,
                .one_rtt_secret = connection.application_space_.read_secret,
            });
    ASSERT_TRUE(sync_failure_packet.has_value());
    connection.process_inbound_datagram(sync_failure_packet.value(),
                                        coquic::quic::test::test_time());

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ConnectionTlsAndValidationHelpersCoverRemainingBranches) {
    coquic::quic::QuicConnection no_tls_validation(coquic::quic::test::make_client_core_config());
    EXPECT_TRUE(no_tls_validation.validate_peer_transport_parameters_if_ready().has_value());

    coquic::quic::QuicConnection no_tls_connection(coquic::quic::test::make_client_core_config());
    no_tls_connection.install_available_secrets();
    no_tls_connection.collect_pending_tls_bytes();
    EXPECT_FALSE(no_tls_connection.initial_space_.send_crypto.has_pending_data());
    EXPECT_FALSE(no_tls_connection.initial_space_.send_crypto.has_outstanding_data());

    coquic::quic::QuicConnection malformed_params_connection(
        coquic::quic::test::make_client_core_config());
    malformed_params_connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    malformed_params_connection.peer_source_connection_id_ = {std::byte{0x01}};
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        *malformed_params_connection.tls_, {std::byte{0x40}});
    const auto malformed_params =
        malformed_params_connection.validate_peer_transport_parameters_if_ready();
    ASSERT_FALSE(malformed_params.has_value());
    EXPECT_EQ(malformed_params.error().code, coquic::quic::CodecErrorCode::truncated_input);
    EXPECT_TRUE(malformed_params.error().has_transport_error_code);
    EXPECT_EQ(malformed_params.error().transport_error_code, 0x08u);
    expect_codec_failure(malformed_params_connection.sync_tls_state(),
                         coquic::quic::CodecErrorCode::truncated_input);

    coquic::quic::QuicConnection missing_context_connection(
        coquic::quic::test::make_client_core_config());
    missing_context_connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        *missing_context_connection.tls_, coquic::quic::test::sample_transport_parameters());
    EXPECT_TRUE(
        missing_context_connection.validate_peer_transport_parameters_if_ready().has_value());
    EXPECT_FALSE(missing_context_connection.peer_transport_parameters_validated_);

    coquic::quic::QuicConnection validation_failure_connection(
        coquic::quic::test::make_client_core_config());
    validation_failure_connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    validation_failure_connection.peer_source_connection_id_ = {std::byte{0x33}};
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        *validation_failure_connection.tls_, coquic::quic::test::sample_transport_parameters());
    const auto validation_failure =
        validation_failure_connection.validate_peer_transport_parameters_if_ready();
    ASSERT_FALSE(validation_failure.has_value());
    EXPECT_EQ(validation_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    coquic::quic::QuicConnection preloaded_parameters_connection(
        coquic::quic::test::make_client_core_config());
    preloaded_parameters_connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    preloaded_parameters_connection.peer_source_connection_id_ = {std::byte{0x44}};
    preloaded_parameters_connection.client_initial_destination_connection_id_ =
        preloaded_parameters_connection.config_.initial_destination_connection_id;
    preloaded_parameters_connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .original_destination_connection_id =
            preloaded_parameters_connection.client_initial_destination_connection_id_,
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = preloaded_parameters_connection.peer_source_connection_id_,
    };
    preloaded_parameters_connection.decoded_resumption_state_ =
        coquic::quic::StoredClientResumptionState{
            .tls_state = {},
            .quic_version = coquic::quic::kQuicVersion1,
            .application_protocol = preloaded_parameters_connection.config_.application_protocol,
            .peer_transport_parameters =
                *preloaded_parameters_connection.peer_transport_parameters_,
            .application_context = {},
        };
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        *preloaded_parameters_connection.tls_, coquic::quic::test::sample_transport_parameters());
    EXPECT_TRUE(
        preloaded_parameters_connection.validate_peer_transport_parameters_if_ready().has_value());
    EXPECT_FALSE(preloaded_parameters_connection.peer_transport_parameters_validated_);

    coquic::quic::QuicConnection idle_connection(coquic::quic::test::make_client_core_config());
    idle_connection.update_handshake_status();
    EXPECT_EQ(idle_connection.status_, coquic::quic::HandshakeStatus::idle);

    coquic::quic::QuicConnection missing_tls_connection(
        coquic::quic::test::make_client_core_config());
    missing_tls_connection.started_ = true;
    missing_tls_connection.update_handshake_status();
    EXPECT_EQ(missing_tls_connection.status_, coquic::quic::HandshakeStatus::idle);

    coquic::quic::QuicConnection failed_connection(coquic::quic::test::make_client_core_config());
    failed_connection.status_ = coquic::quic::HandshakeStatus::failed;
    failed_connection.started_ = true;
    failed_connection.update_handshake_status();
    EXPECT_EQ(failed_connection.status_, coquic::quic::HandshakeStatus::failed);

    coquic::quic::QuicCore connected_client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore connected_server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(connected_client, connected_server,
                                             coquic::quic::test::test_time());
    auto &connected_tls = connected_client.connection_->tls_;
    if (!connected_tls.has_value()) {
        ADD_FAILURE() << "expected handshake to retain TLS state";
        return;
    }
    ASSERT_TRUE(connected_tls->handshake_complete());
    const auto read_secret = connected_client.connection_->application_space_.read_secret;
    const auto write_secret = connected_client.connection_->application_space_.write_secret;

    connected_client.connection_->status_ = coquic::quic::HandshakeStatus::in_progress;
    connected_client.connection_->peer_transport_parameters_validated_ = false;
    connected_client.connection_->update_handshake_status();
    EXPECT_EQ(connected_client.connection_->status_, coquic::quic::HandshakeStatus::in_progress);

    connected_client.connection_->peer_transport_parameters_validated_ = true;
    connected_client.connection_->application_space_.read_secret.reset();
    connected_client.connection_->update_handshake_status();
    EXPECT_EQ(connected_client.connection_->status_, coquic::quic::HandshakeStatus::in_progress);

    connected_client.connection_->application_space_.read_secret = read_secret;
    connected_client.connection_->application_space_.write_secret.reset();
    connected_client.connection_->update_handshake_status();
    EXPECT_EQ(connected_client.connection_->status_, coquic::quic::HandshakeStatus::in_progress);

    connected_client.connection_->application_space_.write_secret = write_secret;
}

TEST(QuicCoreTest, ServerHandshakeStatusUpdateConfirmsHandshakeOnTlsCompletion) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    auto &connection = *server.connection_;
    ASSERT_TRUE(connection.tls_.has_value());
    if (!connection.tls_.has_value()) {
        return;
    }

    ASSERT_TRUE(connection.tls_->handshake_complete());
    ASSERT_TRUE(connection.peer_transport_parameters_validated_);
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    ASSERT_TRUE(connection.application_space_.write_secret.has_value());

    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::none;
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51});
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 9,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });

    connection.update_handshake_status();

    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::connected);
    EXPECT_EQ(connection.handshake_done_state_, coquic::quic::StreamControlFrameState::pending);
    EXPECT_TRUE(connection.handshake_confirmed_);
    EXPECT_FALSE(connection.handshake_space_.read_secret.has_value());
    EXPECT_FALSE(connection.handshake_space_.write_secret.has_value());
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);
}

TEST(QuicCoreTest, ClientHandshakeMarksEstablishedPathValidated) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    ASSERT_TRUE(client.connection_ != nullptr);
    ASSERT_EQ(client.connection_->status_, coquic::quic::HandshakeStatus::connected);
    ASSERT_TRUE(client.connection_->current_send_path_id_.has_value());

    const auto path_id = optional_value_or_terminate(client.connection_->current_send_path_id_);
    ASSERT_TRUE(client.connection_->paths_.contains(path_id));
    ASSERT_TRUE(client.connection_->last_validated_path_id_.has_value());
    EXPECT_TRUE(client.connection_->peer_address_validated_);
    EXPECT_TRUE(client.connection_->paths_.at(path_id).validated);
    EXPECT_EQ(optional_value_or_terminate(client.connection_->last_validated_path_id_), path_id);
}

TEST(QuicCoreTest, ValidatePeerTransportParametersWaitsForTlsBytesWhenNoneAreAvailable) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.start_client_if_needed();

    ASSERT_TRUE(connection.tls_.has_value());
    EXPECT_FALSE(connection.peer_transport_parameters_.has_value());
    EXPECT_TRUE(connection.validate_peer_transport_parameters_if_ready().has_value());
    EXPECT_FALSE(connection.peer_transport_parameters_validated_);
}

TEST(QuicCoreTest, ProcessInboundCryptoApplicationHandshakeDoneConfirmsHandshake) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_packet_space_discarded_ = false;
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });

    const auto processed =
        connection.process_inbound_crypto(coquic::quic::EncryptionLevel::application,
                                          std::array<coquic::quic::Frame, 1>{
                                              coquic::quic::HandshakeDoneFrame{},
                                          },
                                          coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(connection.handshake_confirmed_);
    EXPECT_TRUE(connection.handshake_packet_space_discarded_);
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);
}

TEST(QuicCoreTest, ConnectedApplicationControlFramesDoNotTripPreconnectedGuards) {
    const auto run_connected_frame = [](const coquic::quic::Frame &frame) {
        auto connection = make_connected_server_connection();
        const auto processed = connection.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{frame}, coquic::quic::test::test_time(1));
        EXPECT_TRUE(processed.has_value());
    };

    run_connected_frame(coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 7,
        .final_size = 0,
    });
    run_connected_frame(coquic::quic::StopSendingFrame{
        .stream_id = 0,
        .application_protocol_error_code = 9,
    });
    run_connected_frame(coquic::quic::MaxDataFrame{.maximum_data = 4096});
    run_connected_frame(coquic::quic::MaxStreamDataFrame{
        .stream_id = 0,
        .maximum_stream_data = 2048,
    });
    run_connected_frame(coquic::quic::MaxStreamsFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 4,
    });
    run_connected_frame(coquic::quic::DataBlockedFrame{.maximum_data = 0});
    run_connected_frame(coquic::quic::StreamDataBlockedFrame{
        .stream_id = 0,
        .maximum_stream_data = 0,
    });
    run_connected_frame(coquic::quic::StreamsBlockedFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 1,
    });
}

TEST(QuicCoreTest, ValidatePeerTransportParametersUsesPreloadedParametersWhenTlsBytesAreAbsent) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.start_client_if_needed();

    ASSERT_TRUE(connection.tls_.has_value());
    if (!connection.tls_.has_value()) {
        return;
    }
    auto &tls = connection.tls_.value();
    connection.peer_source_connection_id_ = {std::byte{0x44}};
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .original_destination_connection_id = connection.client_initial_destination_connection_id_,
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = connection.peer_source_connection_id_,
    };
    coquic::quic::test::TlsAdapterTestPeer::clear_peer_transport_parameters(tls);

    const auto validated = connection.validate_peer_transport_parameters_if_ready();

    ASSERT_TRUE(validated.has_value());
    EXPECT_TRUE(connection.peer_transport_parameters_validated_);
}

TEST(QuicCoreTest, ConnectedOnlyApplicationFramesFailBeforeHandshakeCompletes) {
    const auto run_in_progress_frame = [](const coquic::quic::Frame &frame) {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        const auto processed = connection.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{frame}, coquic::quic::test::test_time(1));
        ASSERT_FALSE(processed.has_value());
        EXPECT_EQ(processed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
    };

    run_in_progress_frame(coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 7,
        .final_size = 0,
    });
    run_in_progress_frame(coquic::quic::StopSendingFrame{
        .stream_id = 0,
        .application_protocol_error_code = 9,
    });
    run_in_progress_frame(coquic::quic::MaxDataFrame{.maximum_data = 4096});
    run_in_progress_frame(coquic::quic::MaxStreamDataFrame{
        .stream_id = 0,
        .maximum_stream_data = 2048,
    });
    run_in_progress_frame(coquic::quic::MaxStreamsFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 4,
    });
    run_in_progress_frame(coquic::quic::DataBlockedFrame{.maximum_data = 0});
    run_in_progress_frame(coquic::quic::StreamDataBlockedFrame{
        .stream_id = 0,
        .maximum_stream_data = 0,
    });
    run_in_progress_frame(coquic::quic::StreamsBlockedFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 1,
    });
}

TEST(QuicCoreTest, FlushOutboundDatagramReturnsEmptyWhenNothingIsPending) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_ack_deadline = std::nullopt;

    EXPECT_TRUE(connection.flush_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresDiscardablePacketLengthErrorsAfterStart) {
    auto connection = make_connected_client_connection();

    connection.process_inbound_datagram(bytes_from_ints({0x80, 0x00, 0x00, 0x00, 0x01}),
                                        coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsForNonDiscardablePacketLengthErrorsAfterStart) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.start_client_if_needed();
    ASSERT_TRUE(connection.started_);

    connection.process_inbound_datagram(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00}),
                                        coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresHandshakePacketsForDiscardedSpace) {
    auto connection = make_connected_client_connection();
    connection.handshake_packet_space_discarded_ = true;
    connection.handshake_space_.read_secret.reset();

    const auto datagram = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = coquic::quic::kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_ints({0x11, 0x22}),
                .packet_number_length = 2,
                .packet_number = 1,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = make_test_traffic_secret(
                coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x23}),
        });
    ASSERT_TRUE(datagram.has_value());

    connection.process_inbound_datagram(datagram.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ConnectionFailureAndStateChangeGuardsAreEdgeTriggered) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.queue_state_change(coquic::quic::QuicCoreStateChange::handshake_ready);
    connection.queue_state_change(coquic::quic::QuicCoreStateChange::handshake_ready);
    EXPECT_EQ(connection.pending_state_changes_.size(), 1u);

    connection.queue_state_change(coquic::quic::QuicCoreStateChange::handshake_confirmed);
    connection.queue_state_change(coquic::quic::QuicCoreStateChange::handshake_confirmed);
    EXPECT_EQ(connection.pending_state_changes_.size(), 2u);

    connection.queue_state_change(coquic::quic::QuicCoreStateChange::failed);
    connection.queue_state_change(coquic::quic::QuicCoreStateChange::failed);
    EXPECT_EQ(connection.pending_state_changes_.size(), 3u);

    connection.mark_failed();
    const auto first_failure_events = connection.pending_state_changes_.size();
    connection.mark_failed();
    EXPECT_EQ(connection.pending_state_changes_.size(), first_failure_events);
}

TEST(QuicCoreTest, FlushOutboundDatagramMarksFailuresForSerializationErrors) {
    auto candidate_failure = make_connected_client_connection();
    ASSERT_TRUE(candidate_failure
                    .queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
                    .has_value());
    {
        const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
            coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);
        EXPECT_TRUE(
            candidate_failure.flush_outbound_datagram(coquic::quic::test::test_time()).empty());
    }
    EXPECT_TRUE(candidate_failure.has_failed());

    coquic::quic::QuicConnection final_failure(coquic::quic::test::make_client_core_config());
    final_failure.started_ = true;
    final_failure.status_ = coquic::quic::HandshakeStatus::in_progress;
    final_failure.handshake_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hs"));
    final_failure.handshake_space_.write_secret = make_test_traffic_secret();
    {
        const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
            coquic::quic::test::PacketCryptoFaultPoint::seal_length_guard);
        EXPECT_TRUE(
            final_failure.flush_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    }
    EXPECT_TRUE(final_failure.has_failed());

    coquic::quic::QuicConnection missing_handshake_secret(
        coquic::quic::test::make_client_core_config());
    missing_handshake_secret.started_ = true;
    missing_handshake_secret.status_ = coquic::quic::HandshakeStatus::in_progress;
    missing_handshake_secret.handshake_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("hs"));
    EXPECT_TRUE(
        missing_handshake_secret.flush_outbound_datagram(coquic::quic::test::test_time(2)).empty());
    EXPECT_TRUE(missing_handshake_secret.has_failed());

    auto missing_application_secret = make_connected_client_connection();
    missing_application_secret.application_space_.write_secret.reset();
    ASSERT_TRUE(missing_application_secret
                    .queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
                    .has_value());
    EXPECT_TRUE(missing_application_secret.flush_outbound_datagram(coquic::quic::test::test_time(3))
                    .empty());
    EXPECT_FALSE(missing_application_secret.has_failed());

    coquic::quic::QuicConnection padding_failure(coquic::quic::test::make_client_core_config());
    padding_failure.started_ = true;
    padding_failure.status_ = coquic::quic::HandshakeStatus::in_progress;
    padding_failure.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hi"));
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_length_guard, 2);
    EXPECT_TRUE(padding_failure.flush_outbound_datagram(coquic::quic::test::test_time(4)).empty());
    EXPECT_TRUE(padding_failure.has_failed());
}

TEST(QuicCoreTest, FlushOutboundDatagramReusesAcceptedApplicationCandidateSerialization) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
            .has_value());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 3);
    const auto datagram = connection.flush_outbound_datagram(coquic::quic::test::test_time(5));

    EXPECT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, OneRttSendClosesWithAeadLimitReachedWhenConfidentialityLimitIsReached) {
    ScopedConnectionDrainTestHookReset reset_hooks;

    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
            .has_value());
    coquic::quic::test::connection_set_force_aead_confidentiality_limit_for_tests(true);

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());

    EXPECT_EQ(connection.close_mode_, coquic::quic::QuicConnectionCloseMode::closing);
    ASSERT_TRUE(connection.pending_transport_close_.has_value());
    EXPECT_EQ(optional_ref_or_terminate(connection.pending_transport_close_).error_code,
              static_cast<std::uint64_t>(coquic::quic::QuicTransportErrorCode::aead_limit_reached));
}

TEST(QuicCoreTest, CoalescedInitialAndHandshakeCandidateSerializationFailureMarksConnectionFailed) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("init"));
    connection.handshake_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hs"));
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, InitialTrimReserializationFailureMarksConnectionFailed) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.initial_space_.send_crypto.append(std::vector<std::byte>(1500, std::byte{0x5a}));
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, HandshakeTrimReserializationFailureMarksConnectionFailedAfterDroppingRange) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 400;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x64});
    connection.handshake_space_.send_crypto.append(std::vector<std::byte>(1400, std::byte{0x5b}));
    const auto sent_crypto = connection.handshake_space_.send_crypto.take_ranges(1400);
    ASSERT_EQ(sent_crypto.size(), 1u);
    connection.handshake_space_.send_crypto.mark_lost(0, 1300);
    connection.handshake_space_.send_crypto.mark_unsent(1350, 50);
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, DrainOutboundDatagramFailsWhenTrackedPacketMetadataIsMissing) {
    ScopedConnectionDrainTestHookReset reset_hooks;

    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
            .has_value());
    coquic::quic::test::connection_set_force_missing_packet_metadata_for_tests(true);

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, DrainOutboundDatagramFailsWhenFallbackTrackedPacketLengthIsMissing) {
    ScopedConnectionDrainTestHookReset reset_hooks;

    bool saw_failure = false;
    for (std::size_t occurrence = 1; occurrence <= 6 && !saw_failure; ++occurrence) {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("init"));
        connection.handshake_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hs"));
        connection.handshake_space_.write_secret = make_test_traffic_secret();
        coquic::quic::test::connection_set_force_missing_fallback_packet_length_for_tests(true);
        const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
            coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, occurrence);

        static_cast<void>(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)));
        saw_failure =
            connection.has_failed() && connection.initial_space_.next_send_packet_number > 0;
    }

    EXPECT_TRUE(saw_failure);
}

TEST(QuicCoreTest, InitialCongestionBlockRestoresInitialCryptoRanges) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("init"));
    connection.congestion_controller_.congestion_window_ = 1199;

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.initial_space_.send_crypto.has_pending_data());
    EXPECT_EQ(connection.initial_space_.next_send_packet_number, 0u);
}

TEST(QuicCoreTest, HandshakeCongestionBlockFinalizesQueuedInitialPacket) {
    bool finalized_initial_before_handshake = false;

    for (std::size_t handshake_crypto_size = 64;
         handshake_crypto_size <= 2048 && !finalized_initial_before_handshake;
         handshake_crypto_size += 64) {
        auto config = coquic::quic::test::make_client_core_config();
        config.max_outbound_datagram_size = 4096;
        config.transport.pmtud_enabled = false;
        coquic::quic::QuicConnection connection(std::move(config));
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("init"));
        connection.handshake_space_.send_crypto.append(
            std::vector<std::byte>(handshake_crypto_size, std::byte{0x5b}));
        connection.handshake_space_.write_secret = make_test_traffic_secret();
        connection.congestion_controller_.congestion_window_ = 1200;

        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty() || connection.has_failed()) {
            continue;
        }
        if (!connection.handshake_space_.send_crypto.has_pending_data() ||
            connection.handshake_space_.next_send_packet_number != 0u) {
            continue;
        }

        const auto packets = decode_sender_datagram(connection, datagram);
        if (packets.size() != 1u) {
            continue;
        }
        if (!std::holds_alternative<coquic::quic::ProtectedInitialPacket>(packets.front())) {
            continue;
        }

        finalized_initial_before_handshake = true;
    }

    EXPECT_TRUE(finalized_initial_before_handshake);
}

TEST(QuicCoreTest, HasPendingCongestionControlledSendIncludesRetireCidAndApplicationCrypto) {
    auto connection = make_connected_client_connection();
    EXPECT_FALSE(connection.has_pending_application_send());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(connection.pending_new_connection_id_frames_.empty());
    EXPECT_TRUE(connection.pending_retire_connection_id_frames_.empty());
    EXPECT_FALSE(connection.application_space_.send_crypto.has_pending_data());
    EXPECT_FALSE(connection.has_pending_congestion_controlled_send());

    connection.pending_retire_connection_id_frames_.push_back(
        coquic::quic::RetireConnectionIdFrame{.sequence_number = 1});
    EXPECT_TRUE(connection.has_pending_congestion_controlled_send());

    connection.pending_retire_connection_id_frames_.clear();
    connection.application_space_.send_crypto.append(coquic::quic::test::bytes_from_string("x"));
    EXPECT_TRUE(connection.has_pending_congestion_controlled_send());
}

TEST(QuicCoreTest, PacketTraceLogsPacingSendBlockedWhenApplicationPacingDefersSend) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");

    auto connection = make_connected_client_connection();
    connection.congestion_controller_ = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::bbr,
        std::max<std::size_t>(1200, connection.config_.max_outbound_datagram_size));
    auto &bbr =
        std::get<coquic::quic::BbrCongestionController>(connection.congestion_controller_.storage_);
    bbr.mode_ = coquic::quic::BbrCongestionController::Mode::probe_bw_cruise;
    bbr.max_bandwidth_bytes_per_second_ = 120000.0;
    bbr.bandwidth_bytes_per_second_ = 120000.0;
    bbr.pacing_rate_bytes_per_second_ = 120000.0;
    bbr.min_rtt_ = std::chrono::milliseconds{100};

    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(8u) * 1024u, std::byte{0x55});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto send_time = coquic::quic::test::test_time(1);
    ASSERT_FALSE(connection.drain_outbound_datagram(send_time).empty());
    ASSERT_FALSE(connection.drain_outbound_datagram(send_time).empty());

    expect_blocked_drain_trace_contains(connection, send_time,
                                        "quic-packet-trace send-blocked scid=", "reason=pacing");
}

TEST(QuicCoreTest, NonPacedApplicationSendLimitsAckElicitingBurst) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");

    constexpr std::size_t kConnectionCredit = std::size_t{64} * 1024u;
    constexpr std::size_t kCongestionWindow = std::size_t{1024} * 1024u;
    constexpr std::size_t kPayloadSize = std::size_t{32} * 1024u;

    auto connection = make_connected_client_connection();
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = kConnectionCredit;
    peer_transport_parameters.initial_max_stream_data_bidi_remote = kConnectionCredit;
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = kCongestionWindow;
    ASSERT_TRUE(
        connection
            .queue_stream_send(0, std::vector<std::byte>(kPayloadSize, std::byte{0x41}), false)
            .has_value());

    const auto now = coquic::quic::test::test_time(1);
    for (std::size_t index = 0; index < 10; ++index) {
        EXPECT_FALSE(connection.drain_outbound_datagram(now).empty()) << "index=" << index;
    }

    expect_blocked_drain_trace_contains(connection, now, "reason=burst");
    EXPECT_TRUE(connection.has_pending_application_send());
}

TEST(QuicCoreTest, ConnectionProcessInboundApplicationCoversRemainingValidationBranches) {
    auto flow_overflow = make_connected_client_connection();
    flow_overflow.connection_flow_control_.advertised_max_data = 0;
    expect_codec_failure(flow_overflow.process_inbound_application(
                             std::array<coquic::quic::Frame, 1>{
                                 coquic::quic::test::make_inbound_application_stream_frame("x"),
                             },
                             coquic::quic::test::test_time()),
                         coquic::quic::CodecErrorCode::invalid_varint);

    auto buffer_failure = make_connected_client_connection();
    auto &buffer_stream = buffer_failure.streams_
                              .emplace(0, coquic::quic::make_implicit_stream_state(
                                              /*stream_id=*/0, buffer_failure.config_.role))
                              .first->second;
    buffer_failure.initialize_stream_flow_control(buffer_stream);
    buffer_stream.flow_control.advertised_max_stream_data =
        std::numeric_limits<std::uint64_t>::max();
    buffer_stream.receive_flow_control_limit = std::numeric_limits<std::uint64_t>::max();
    buffer_failure.connection_flow_control_.advertised_max_data =
        std::numeric_limits<std::uint64_t>::max();
    expect_codec_failure(buffer_failure.process_inbound_application(
                             std::array<coquic::quic::Frame, 1>{
                                 coquic::quic::test::make_inbound_application_stream_frame(
                                     "xy", (std::uint64_t{1} << 62) - 1),
                             },
                             coquic::quic::test::test_time(1)),
                         coquic::quic::CodecErrorCode::invalid_varint);

    coquic::quic::QuicConnection gated_connection(coquic::quic::test::make_client_core_config());
    gated_connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    for (const auto &frame : std::vector<coquic::quic::Frame>{
             coquic::quic::ResetStreamFrame{
                 .stream_id = 0,
                 .application_protocol_error_code = 1,
                 .final_size = 0,
             },
             coquic::quic::StopSendingFrame{
                 .stream_id = 0,
                 .application_protocol_error_code = 1,
             },
             coquic::quic::MaxDataFrame{.maximum_data = 1},
             coquic::quic::MaxStreamDataFrame{
                 .stream_id = 0,
                 .maximum_stream_data = 1,
             },
             coquic::quic::MaxStreamsFrame{
                 .stream_type = coquic::quic::StreamLimitType::bidirectional,
                 .maximum_streams = 1,
             },
             coquic::quic::DataBlockedFrame{.maximum_data = 1},
             coquic::quic::StreamDataBlockedFrame{
                 .stream_id = 0,
                 .maximum_stream_data = 1,
             },
             coquic::quic::StreamsBlockedFrame{
                 .stream_type = coquic::quic::StreamLimitType::bidirectional,
                 .maximum_streams = 1,
             },
         }) {
        expect_codec_failure(
            gated_connection.process_inbound_application(std::array<coquic::quic::Frame, 1>{frame},
                                                         coquic::quic::test::test_time(2)),
            coquic::quic::CodecErrorCode::invalid_varint);
    }

    coquic::quic::QuicConnection preconnected_controls(
        coquic::quic::test::make_client_core_config());
    preconnected_controls.status_ = coquic::quic::HandshakeStatus::in_progress;
    for (const auto &frame : std::vector<coquic::quic::Frame>{
             coquic::quic::NewConnectionIdFrame{
                 .sequence_number = 1,
                 .retire_prior_to = 0,
                 .connection_id = bytes_from_ints({0x10, 0x11, 0x12, 0x13}),
                 .stateless_reset_token =
                     {
                         std::byte{0x00},
                         std::byte{0x01},
                         std::byte{0x02},
                         std::byte{0x03},
                         std::byte{0x04},
                         std::byte{0x05},
                         std::byte{0x06},
                         std::byte{0x07},
                         std::byte{0x08},
                         std::byte{0x09},
                         std::byte{0x0a},
                         std::byte{0x0b},
                         std::byte{0x0c},
                         std::byte{0x0d},
                         std::byte{0x0e},
                         std::byte{0x0f},
                     },
             },
             coquic::quic::HandshakeDoneFrame{},
         }) {
        expect_codec_success(preconnected_controls.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{frame}, coquic::quic::test::test_time(2)));
    }

    auto preconnected_retire_without_application_secret = make_connected_server_connection();
    preconnected_retire_without_application_secret.status_ =
        coquic::quic::HandshakeStatus::in_progress;
    preconnected_retire_without_application_secret.handshake_confirmed_ = false;
    preconnected_retire_without_application_secret.application_space_.read_secret.reset();
    expect_codec_success(preconnected_retire_without_application_secret.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::RetireConnectionIdFrame{
                .sequence_number = 1,
            },
        },
        coquic::quic::test::test_time(2)));

    auto preconnected_retire_allowed = make_connected_server_connection();
    preconnected_retire_allowed.status_ = coquic::quic::HandshakeStatus::in_progress;
    preconnected_retire_allowed.handshake_confirmed_ = false;
    preconnected_retire_allowed.issue_spare_connection_ids();
    expect_codec_success(preconnected_retire_allowed.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::RetireConnectionIdFrame{
                .sequence_number = 1,
            },
        },
        coquic::quic::test::test_time(2)));

    auto connected = make_connected_client_connection();
    connected.connection_flow_control_.advertised_max_data = 10;
    connected.connection_flow_control_.delivered_bytes = 10;
    connected.connection_flow_control_.local_receive_window = 4;
    auto &receive_stream = connected.streams_
                               .emplace(0, coquic::quic::make_implicit_stream_state(
                                               /*stream_id=*/0, connected.config_.role))
                               .first->second;
    connected.initialize_stream_flow_control(receive_stream);
    receive_stream.flow_control.advertised_max_stream_data = 9;
    receive_stream.flow_control.delivered_bytes = 9;
    receive_stream.flow_control.local_receive_window = 3;
    expect_codec_success(connected.process_inbound_application(
        std::array<coquic::quic::Frame, 4>{
            coquic::quic::MaxStreamsFrame{
                .stream_type = coquic::quic::StreamLimitType::bidirectional,
                .maximum_streams = 32,
            },
            coquic::quic::DataBlockedFrame{.maximum_data = 10},
            coquic::quic::StreamDataBlockedFrame{
                .stream_id = 0,
                .maximum_stream_data = 9,
            },
            coquic::quic::StreamsBlockedFrame{
                .stream_type = coquic::quic::StreamLimitType::bidirectional,
                .maximum_streams = 32,
            },
        },
        coquic::quic::test::test_time(3)));
    EXPECT_EQ(connected.stream_open_limits_.peer_max_bidirectional, 32u);
    ASSERT_TRUE(connected.connection_flow_control_.pending_max_data_frame.has_value());
    if (connected.connection_flow_control_.pending_max_data_frame.has_value()) {
        EXPECT_EQ(connected.connection_flow_control_.pending_max_data_frame->maximum_data, 14u);
    }
    ASSERT_TRUE(receive_stream.flow_control.pending_max_stream_data_frame.has_value());
    if (receive_stream.flow_control.pending_max_stream_data_frame.has_value()) {
        EXPECT_EQ(receive_stream.flow_control.pending_max_stream_data_frame->maximum_stream_data,
                  12u);
    }

    auto invalid_max_stream_data = make_connected_client_connection();
    expect_codec_failure(invalid_max_stream_data.process_inbound_application(
                             std::array<coquic::quic::Frame, 1>{
                                 coquic::quic::MaxStreamDataFrame{
                                     .stream_id = 3,
                                     .maximum_stream_data = 1,
                                 },
                             },
                             coquic::quic::test::test_time(4)),
                         coquic::quic::CodecErrorCode::invalid_varint);

    auto invalid_stream_data_blocked = make_connected_client_connection();
    expect_codec_failure(invalid_stream_data_blocked.process_inbound_application(
                             std::array<coquic::quic::Frame, 1>{
                                 coquic::quic::StreamDataBlockedFrame{
                                     .stream_id = 2,
                                     .maximum_stream_data = 1,
                                 },
                             },
                             coquic::quic::test::test_time(5)),
                         coquic::quic::CodecErrorCode::invalid_varint);

    auto reset_conflict = make_connected_client_connection();
    auto &conflict_stream = reset_conflict.streams_
                                .emplace(0, coquic::quic::make_implicit_stream_state(
                                                /*stream_id=*/0, reset_conflict.config_.role))
                                .first->second;
    reset_conflict.initialize_stream_flow_control(conflict_stream);
    conflict_stream.highest_received_offset = 6;
    expect_codec_failure(reset_conflict.process_inbound_application(
                             std::array<coquic::quic::Frame, 1>{
                                 coquic::quic::ResetStreamFrame{
                                     .stream_id = 0,
                                     .application_protocol_error_code = 1,
                                     .final_size = 5,
                                 },
                             },
                             coquic::quic::test::test_time(6)),
                         coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest, ConnectionProcessInboundApplicationCoversOvercommitAndDuplicateFinBranches) {
    auto overcommitted = make_connected_client_connection();
    overcommitted.connection_flow_control_.advertised_max_data = 1;
    overcommitted.connection_flow_control_.received_committed = 2;
    const auto overcommit_failure = overcommitted.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("", 0, 1, true),
        },
        coquic::quic::test::test_time());
    ASSERT_FALSE(overcommit_failure.has_value());
    EXPECT_EQ(overcommit_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto duplicate_fin = make_connected_client_connection();
    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        duplicate_fin, {coquic::quic::test::make_inbound_application_stream_frame("", 0, 1, true)},
        /*packet_number=*/1));
    ASSERT_EQ(duplicate_fin.pending_stream_receive_effects_.size(), 1u);
    EXPECT_TRUE(duplicate_fin.pending_stream_receive_effects_.front().fin);

    duplicate_fin.pending_stream_receive_effects_.clear();
    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        duplicate_fin, {coquic::quic::test::make_inbound_application_stream_frame("", 0, 1, true)},
        /*packet_number=*/2));
    EXPECT_TRUE(duplicate_fin.pending_stream_receive_effects_.empty());
}

TEST(QuicCoreTest, ConnectionProcessInboundApplicationCoversApplicationCryptoBranches) {
    auto offset_overflow = make_connected_client_connection();
    expect_codec_failure(offset_overflow.process_inbound_application(
                             std::array<coquic::quic::Frame, 1>{
                                 coquic::quic::CryptoFrame{
                                     .offset = (std::uint64_t{1} << 62) - 1,
                                     .crypto_data = bytes_from_ints({0x01, 0x02}),
                                 },
                             },
                             coquic::quic::test::test_time(1)),
                         coquic::quic::CodecErrorCode::invalid_varint);

    coquic::quic::QuicConnection missing_tls(coquic::quic::test::make_client_core_config());
    missing_tls.started_ = true;
    missing_tls.status_ = coquic::quic::HandshakeStatus::in_progress;
    const auto missing_tls_failure = missing_tls.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::CryptoFrame{
                .offset = 0,
                .crypto_data = bytes_from_ints({0x03}),
            },
        },
        coquic::quic::test::test_time(2));
    ASSERT_FALSE(missing_tls_failure.has_value());
    EXPECT_EQ(missing_tls_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    auto connected_without_tls = make_connected_client_connection();
    connected_without_tls.tls_.reset();
    expect_codec_success(connected_without_tls.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::CryptoFrame{
                .offset = 0,
                .crypto_data = bytes_from_ints({0x04}),
            },
        },
        coquic::quic::test::test_time(3)));
    EXPECT_FALSE(connected_without_tls.has_failed());

    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time(4));
    ASSERT_NE(client.connection_, nullptr);
    auto &post_handshake = *client.connection_;
    ASSERT_TRUE(post_handshake.tls_.has_value());
    post_handshake.application_space_.receive_crypto = coquic::quic::ReliableReceiveBuffer{};
    const coquic::quic::test::ScopedTlsAdapterFaultInjector injector(
        coquic::quic::test::TlsAdapterFaultPoint::provide_post_handshake);
    const auto provide_failure = post_handshake.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::CryptoFrame{
                .offset = 0,
                .crypto_data = bytes_from_ints({0x05}),
            },
        },
        coquic::quic::test::test_time(5));
    ASSERT_FALSE(provide_failure.has_value());
    EXPECT_EQ(provide_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicCoreTest, ConnectionProcessInboundReceivedApplicationCoversValidationAndControlBranches) {
    const auto make_received_stream_frame = [](std::string_view text,
                                               std::optional<std::uint64_t> offset = 0,
                                               std::uint64_t stream_id = 0, bool fin = false) {
        return coquic::quic::ReceivedStreamFrame{
            .fin = fin,
            .has_offset = offset.has_value(),
            .has_length = true,
            .stream_id = stream_id,
            .offset = offset,
            .stream_data = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string(text)),
        };
    };
    const auto make_challenge_data = [](std::uint8_t fill) {
        std::array<std::byte, 8> data{};
        data.fill(static_cast<std::byte>(fill));
        return data;
    };
    const auto make_reset_token = [](std::uint8_t fill) {
        std::array<std::byte, 16> token{};
        token[0] = static_cast<std::byte>(fill);
        return token;
    };

    auto flow_overflow = make_connected_client_connection();
    flow_overflow.connection_flow_control_.advertised_max_data = 0;
    expect_codec_failure(
        flow_overflow.process_inbound_received_application(
            std::vector<coquic::quic::ReceivedFrame>{make_received_stream_frame("x")},
            coquic::quic::test::test_time(), /*allow_preconnected_frames=*/false,
            /*path_id=*/0),
        coquic::quic::CodecErrorCode::invalid_varint);

    auto overcommitted = make_connected_client_connection();
    overcommitted.connection_flow_control_.advertised_max_data = 1;
    overcommitted.connection_flow_control_.received_committed = 2;
    expect_codec_failure(overcommitted.process_inbound_received_application(
                             std::vector<coquic::quic::ReceivedFrame>{
                                 make_received_stream_frame("", /*offset=*/0, /*stream_id=*/0,
                                                            /*fin=*/true)},
                             coquic::quic::test::test_time(1),
                             /*allow_preconnected_frames=*/false, /*path_id=*/0),
                         coquic::quic::CodecErrorCode::invalid_varint);

    auto buffer_failure = make_connected_client_connection();
    auto &buffer_stream = buffer_failure.streams_
                              .emplace(0, coquic::quic::make_implicit_stream_state(
                                              /*stream_id=*/0, buffer_failure.config_.role))
                              .first->second;
    buffer_failure.initialize_stream_flow_control(buffer_stream);
    buffer_stream.flow_control.advertised_max_stream_data =
        std::numeric_limits<std::uint64_t>::max();
    buffer_stream.receive_flow_control_limit = std::numeric_limits<std::uint64_t>::max();
    buffer_failure.connection_flow_control_.advertised_max_data =
        std::numeric_limits<std::uint64_t>::max();
    expect_codec_failure(
        buffer_failure.process_inbound_received_application(
            std::vector<coquic::quic::ReceivedFrame>{
                make_received_stream_frame("xy", /*offset=*/(std::uint64_t{1} << 62) - 1)},
            coquic::quic::test::test_time(2), /*allow_preconnected_frames=*/false, /*path_id=*/0),
        coquic::quic::CodecErrorCode::invalid_varint);

    const std::array<std::byte, 8> gated_validation_data = make_challenge_data(0x2a);
    const auto run_gated_frame = [&](const coquic::quic::ReceivedFrame &frame) {
        coquic::quic::QuicConnection gate_connection(coquic::quic::test::make_client_core_config());
        gate_connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        expect_codec_failure(gate_connection.process_inbound_received_application(
                                 std::vector<coquic::quic::ReceivedFrame>{frame},
                                 coquic::quic::test::test_time(3),
                                 /*allow_preconnected_frames=*/false, /*path_id=*/0),
                             coquic::quic::CodecErrorCode::invalid_varint);
    };
    for (const auto &frame : std::vector<coquic::quic::ReceivedFrame>{
             coquic::quic::ResetStreamFrame{
                 .stream_id = 0,
                 .application_protocol_error_code = 1,
                 .final_size = 0,
             },
             coquic::quic::StopSendingFrame{
                 .stream_id = 0,
                 .application_protocol_error_code = 1,
             },
             coquic::quic::MaxDataFrame{.maximum_data = 1},
             coquic::quic::MaxStreamDataFrame{
                 .stream_id = 0,
                 .maximum_stream_data = 1,
             },
             coquic::quic::MaxStreamsFrame{
                 .stream_type = coquic::quic::StreamLimitType::bidirectional,
                 .maximum_streams = 1,
             },
             coquic::quic::DataBlockedFrame{.maximum_data = 1},
             coquic::quic::StreamDataBlockedFrame{
                 .stream_id = 0,
                 .maximum_stream_data = 1,
             },
             coquic::quic::StreamsBlockedFrame{
                 .stream_type = coquic::quic::StreamLimitType::bidirectional,
                 .maximum_streams = 1,
             },
             coquic::quic::PingFrame{},
             coquic::quic::PathChallengeFrame{.data = gated_validation_data},
             coquic::quic::PathResponseFrame{.data = gated_validation_data},
             make_received_stream_frame("x"),
         }) {
        run_gated_frame(frame);
    }

    auto preconnected_controls = make_connected_client_connection();
    preconnected_controls.status_ = coquic::quic::HandshakeStatus::in_progress;
    preconnected_controls.handshake_confirmed_ = false;

    expect_codec_success(preconnected_controls.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{coquic::quic::PingFrame{}},
        coquic::quic::test::test_time(4), /*allow_preconnected_frames=*/false, /*path_id=*/0));

    expect_codec_success(preconnected_controls.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{make_received_stream_frame("late")},
        coquic::quic::test::test_time(5), /*allow_preconnected_frames=*/false, /*path_id=*/0));
    ASSERT_EQ(preconnected_controls.pending_stream_receive_effects_.size(), 1u);
    EXPECT_EQ(preconnected_controls.pending_stream_receive_effects_.front().bytes,
              coquic::quic::test::bytes_from_string("late"));

    const std::array<std::byte, 8> preconnected_challenge_data = make_challenge_data(0x6b);
    expect_codec_success(preconnected_controls.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::PathChallengeFrame{.data = preconnected_challenge_data},
        },
        coquic::quic::test::test_time(6), /*allow_preconnected_frames=*/false, /*path_id=*/1));
    ASSERT_TRUE(preconnected_controls.paths_.contains(1));
    auto &pending_response_opt = preconnected_controls.paths_.at(1).pending_response;
    if (!pending_response_opt.has_value()) {
        FAIL() << "expected pending path response";
        return;
    }
    const auto &pending_response = *pending_response_opt;
    EXPECT_EQ(pending_response, preconnected_challenge_data);

    expect_codec_success(preconnected_controls.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::PathResponseFrame{.data = preconnected_challenge_data},
        },
        coquic::quic::test::test_time(7), /*allow_preconnected_frames=*/false, /*path_id=*/1));

    auto connected = make_connected_client_connection();
    connected.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 0};
    connected.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;
    connected.connection_flow_control_.advertised_max_data = 10;
    connected.connection_flow_control_.delivered_bytes = 10;
    connected.connection_flow_control_.local_receive_window = 4;
    auto &receive_stream = connected.streams_
                               .emplace(0, coquic::quic::make_implicit_stream_state(
                                               /*stream_id=*/0, connected.config_.role))
                               .first->second;
    connected.initialize_stream_flow_control(receive_stream);
    receive_stream.flow_control.advertised_max_stream_data = 9;
    receive_stream.flow_control.delivered_bytes = 9;
    receive_stream.flow_control.local_receive_window = 3;
    expect_codec_success(connected.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::MaxDataFrame{.maximum_data = 10},
            coquic::quic::MaxStreamsFrame{
                .stream_type = coquic::quic::StreamLimitType::bidirectional,
                .maximum_streams = 32,
            },
            coquic::quic::DataBlockedFrame{.maximum_data = 10},
            coquic::quic::StreamDataBlockedFrame{
                .stream_id = 0,
                .maximum_stream_data = 9,
            },
            coquic::quic::StreamsBlockedFrame{
                .stream_type = coquic::quic::StreamLimitType::bidirectional,
                .maximum_streams = 32,
            },
        },
        coquic::quic::test::test_time(8), /*allow_preconnected_frames=*/false, /*path_id=*/0));
    EXPECT_EQ(connected.stream_open_limits_.peer_max_bidirectional, 32u);
    EXPECT_FALSE(connected.connection_flow_control_.pending_data_blocked_frame.has_value());
    EXPECT_EQ(connected.connection_flow_control_.data_blocked_state,
              coquic::quic::StreamControlFrameState::none);
    ASSERT_TRUE(connected.connection_flow_control_.pending_max_data_frame.has_value());
    if (connected.connection_flow_control_.pending_max_data_frame.has_value()) {
        EXPECT_EQ(connected.connection_flow_control_.pending_max_data_frame->maximum_data, 14u);
    }
    ASSERT_TRUE(receive_stream.flow_control.pending_max_stream_data_frame.has_value());
    if (receive_stream.flow_control.pending_max_stream_data_frame.has_value()) {
        EXPECT_EQ(receive_stream.flow_control.pending_max_stream_data_frame->maximum_stream_data,
                  12u);
    }

    auto invalid_reset_stream = make_connected_client_connection();
    expect_codec_failure(invalid_reset_stream.process_inbound_received_application(
                             std::vector<coquic::quic::ReceivedFrame>{
                                 coquic::quic::ResetStreamFrame{
                                     .stream_id = 2,
                                     .application_protocol_error_code = 1,
                                     .final_size = 0,
                                 },
                             },
                             coquic::quic::test::test_time(9),
                             /*allow_preconnected_frames=*/false, /*path_id=*/0),
                         coquic::quic::CodecErrorCode::invalid_varint);

    auto reset_conflict = make_connected_client_connection();
    auto &conflict_stream = reset_conflict.streams_
                                .emplace(0, coquic::quic::make_implicit_stream_state(
                                                /*stream_id=*/0, reset_conflict.config_.role))
                                .first->second;
    reset_conflict.initialize_stream_flow_control(conflict_stream);
    conflict_stream.highest_received_offset = 6;
    expect_codec_failure(reset_conflict.process_inbound_received_application(
                             std::vector<coquic::quic::ReceivedFrame>{
                                 coquic::quic::ResetStreamFrame{
                                     .stream_id = 0,
                                     .application_protocol_error_code = 1,
                                     .final_size = 5,
                                 },
                             },
                             coquic::quic::test::test_time(10),
                             /*allow_preconnected_frames=*/false, /*path_id=*/0),
                         coquic::quic::CodecErrorCode::invalid_varint);

    auto invalid_stop_sending = make_connected_client_connection();
    expect_codec_failure(invalid_stop_sending.process_inbound_received_application(
                             std::vector<coquic::quic::ReceivedFrame>{
                                 coquic::quic::StopSendingFrame{
                                     .stream_id = 3,
                                     .application_protocol_error_code = 1,
                                 },
                             },
                             coquic::quic::test::test_time(11),
                             /*allow_preconnected_frames=*/false, /*path_id=*/0),
                         coquic::quic::CodecErrorCode::invalid_varint);

    auto invalid_max_stream_data = make_connected_client_connection();
    expect_codec_failure(invalid_max_stream_data.process_inbound_received_application(
                             std::vector<coquic::quic::ReceivedFrame>{
                                 coquic::quic::MaxStreamDataFrame{
                                     .stream_id = 3,
                                     .maximum_stream_data = 1,
                                 },
                             },
                             coquic::quic::test::test_time(12), /*allow_preconnected_frames=*/false,
                             /*path_id=*/0),
                         coquic::quic::CodecErrorCode::invalid_varint);

    auto invalid_stream_data_blocked = make_connected_client_connection();
    expect_codec_failure(invalid_stream_data_blocked.process_inbound_received_application(
                             std::vector<coquic::quic::ReceivedFrame>{
                                 coquic::quic::StreamDataBlockedFrame{
                                     .stream_id = 2,
                                     .maximum_stream_data = 1,
                                 },
                             },
                             coquic::quic::test::test_time(13), /*allow_preconnected_frames=*/false,
                             /*path_id=*/0),
                         coquic::quic::CodecErrorCode::invalid_varint);

    auto invalid_new_connection_id = make_connected_client_connection();
    expect_codec_failure(invalid_new_connection_id.process_inbound_received_application(
                             std::vector<coquic::quic::ReceivedFrame>{
                                 coquic::quic::NewConnectionIdFrame{
                                     .sequence_number = 1,
                                     .retire_prior_to = 2,
                                     .connection_id = bytes_from_ints({0x10, 0x11}),
                                     .stateless_reset_token = make_reset_token(0x10),
                                 },
                             },
                             coquic::quic::test::test_time(14), /*allow_preconnected_frames=*/false,
                             /*path_id=*/0),
                         coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest,
     ConnectionProcessInboundReceivedApplicationCoversCryptoTraceAndTerminalBranches) {
    const auto make_received_crypto_frame = [](std::initializer_list<std::uint8_t> bytes,
                                               std::uint64_t offset = 0) {
        return coquic::quic::ReceivedCryptoFrame{
            .offset = offset,
            .crypto_data = coquic::quic::SharedBytes(bytes_from_ints(bytes)),
        };
    };
    const auto make_received_stream_frame = [](std::string_view text,
                                               std::optional<std::uint64_t> offset = 0,
                                               std::uint64_t stream_id = 0, bool fin = false) {
        return coquic::quic::ReceivedStreamFrame{
            .fin = fin,
            .has_offset = offset.has_value(),
            .has_length = true,
            .stream_id = stream_id,
            .offset = offset,
            .stream_data = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string(text)),
        };
    };
    const auto make_challenge_data = [](std::uint8_t fill) {
        std::array<std::byte, 8> data{};
        data.fill(static_cast<std::byte>(fill));
        return data;
    };

    auto offset_overflow = make_connected_client_connection();
    expect_codec_failure(
        offset_overflow.process_inbound_received_application(
            std::vector<coquic::quic::ReceivedFrame>{
                make_received_crypto_frame({0x01, 0x02}, (std::uint64_t{1} << 62) - 1)},
            coquic::quic::test::test_time(1), /*allow_preconnected_frames=*/false, /*path_id=*/0),
        coquic::quic::CodecErrorCode::invalid_varint);

    coquic::quic::QuicConnection missing_tls(coquic::quic::test::make_client_core_config());
    missing_tls.started_ = true;
    missing_tls.status_ = coquic::quic::HandshakeStatus::in_progress;
    const auto missing_tls_failure = missing_tls.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{make_received_crypto_frame({0x03})},
        coquic::quic::test::test_time(2), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(missing_tls_failure.has_value());
    EXPECT_EQ(missing_tls_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    auto connected_without_tls = make_connected_client_connection();
    connected_without_tls.tls_.reset();
    expect_codec_success(connected_without_tls.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{make_received_crypto_frame({0x04})},
        coquic::quic::test::test_time(3), /*allow_preconnected_frames=*/false, /*path_id=*/0));
    EXPECT_FALSE(connected_without_tls.has_failed());

    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time(4));
    ASSERT_NE(client.connection_, nullptr);
    auto &post_handshake = *client.connection_;
    ASSERT_TRUE(post_handshake.tls_.has_value());
    post_handshake.application_space_.receive_crypto = coquic::quic::ReliableReceiveBuffer{};
    const coquic::quic::test::ScopedTlsAdapterFaultInjector injector(
        coquic::quic::test::TlsAdapterFaultPoint::provide_post_handshake);
    const auto provide_failure = post_handshake.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{make_received_crypto_frame({0x05})},
        coquic::quic::test::test_time(5), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(provide_failure.has_value());
    EXPECT_EQ(provide_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    auto traced = make_connected_server_connection();
    traced.current_send_path_id_ = 1;
    traced.previous_path_id_ = 0;
    traced.last_validated_path_id_ = 0;
    auto &current_path = traced.ensure_path_state(1);
    current_path.validated = false;
    current_path.is_current_send_path = true;
    const std::array<std::byte, 8> trace_challenge_data = make_challenge_data(0x44);
    auto &inbound_path = traced.ensure_path_state(2);
    inbound_path.validated = true;
    inbound_path.outstanding_challenge = trace_challenge_data;
    inbound_path.challenge_pending = true;
    inbound_path.validation_deadline = coquic::quic::test::test_time(10);

    testing::internal::CaptureStderr();
    const ScopedEnvVar packet_trace("COQUIC_PACKET_TRACE", "1");
    expect_codec_success(traced.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::PathResponseFrame{.data = trace_challenge_data},
            make_received_stream_frame("x"),
        },
        coquic::quic::test::test_time(6), /*allow_preconnected_frames=*/false, /*path_id=*/2));
    const std::string captured_stderr = testing::internal::GetCapturedStderr();
    if (!traced.current_send_path_id_.has_value()) {
        FAIL() << "expected current send path id";
        return;
    }
    EXPECT_EQ(*traced.current_send_path_id_, 2u);
    if (!traced.last_validated_path_id_.has_value()) {
        FAIL() << "expected validated path id";
        return;
    }
    EXPECT_EQ(*traced.last_validated_path_id_, 2u);
    EXPECT_FALSE(traced.paths_.at(2).outstanding_challenge.has_value());
    ASSERT_EQ(traced.pending_stream_receive_effects_.size(), 1u);
    EXPECT_EQ(traced.pending_stream_receive_effects_.front().bytes,
              coquic::quic::test::bytes_from_string("x"));
    EXPECT_NE(captured_stderr.find("quic-packet-trace recv-app scid="), std::string::npos);
    EXPECT_NE(captured_stderr.find("quic-packet-trace path-response scid="), std::string::npos);
    EXPECT_NE(captured_stderr.find("quic-packet-trace stream scid="), std::string::npos);

    auto server_new_token = make_connected_server_connection();
    expect_codec_failure(server_new_token.process_inbound_received_application(
                             std::vector<coquic::quic::ReceivedFrame>{
                                 coquic::quic::NewTokenFrame{
                                     .token = bytes_from_ints({0xaa, 0xbb}),
                                 },
                             },
                             coquic::quic::test::test_time(7), /*allow_preconnected_frames=*/false,
                             /*path_id=*/0),
                         coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);

    auto closing = make_connected_client_connection();
    expect_codec_success(closing.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::ApplicationConnectionCloseFrame{
                .error_code = 1,
                .reason =
                    {
                        .bytes = coquic::quic::test::bytes_from_string("bye"),
                    },
            },
        },
        coquic::quic::test::test_time(8), /*allow_preconnected_frames=*/false, /*path_id=*/0));
    EXPECT_TRUE(closing.has_failed());
    EXPECT_TRUE(closing.close_state_active());
    EXPECT_TRUE(closing.next_wakeup().has_value());

    auto server_handshake_done = make_connected_server_connection();
    server_handshake_done.handshake_confirmed_ = false;
    server_handshake_done.handshake_packet_space_discarded_ = false;
    expect_codec_failure(
        server_handshake_done.process_inbound_received_application(
            std::vector<coquic::quic::ReceivedFrame>{coquic::quic::HandshakeDoneFrame{}},
            coquic::quic::test::test_time(9), /*allow_preconnected_frames=*/false, /*path_id=*/0),
        coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
    EXPECT_FALSE(server_handshake_done.handshake_confirmed_);
    EXPECT_FALSE(server_handshake_done.handshake_packet_space_discarded_);

    auto invalid_retire = make_connected_client_connection();
    expect_codec_failure(invalid_retire.process_inbound_received_application(
                             std::vector<coquic::quic::ReceivedFrame>{
                                 coquic::quic::RetireConnectionIdFrame{
                                     .sequence_number = 99,
                                 },
                             },
                             coquic::quic::test::test_time(10),
                             /*allow_preconnected_frames=*/false, /*path_id=*/0),
                         coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest, ReceivedInitialPacketResetsClientHandshakePeerStateOnSourceConnectionIdChange) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_source_connection_id_ = bytes_from_ints({0x01});
    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .initial_source_connection_id = bytes_from_ints({0xaa}),
    };
    connection.peer_transport_parameters_validated_ = true;
    connection.peer_connection_ids_[7] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 7,
        .connection_id = bytes_from_ints({0x07}),
    };
    connection.active_peer_connection_id_sequence_ = 7;
    connection.deferred_protected_packets_.push_back(
        coquic::quic::DeferredProtectedPacket(bytes_from_ints({0xee})));
    connection.initial_space_.received_packets.record_received(
        4, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    connection.handshake_space_.received_packets.record_received(
        5, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    connection.zero_rtt_space_.received_packets.record_received(
        6, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    const std::vector<std::byte> replacement_source_connection_id = bytes_from_ints({0x02, 0x03});

    expect_codec_true(connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedInitialPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = replacement_source_connection_id,
            .packet_number_length = 1,
            .packet_number = 1,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames = {coquic::quic::PaddingFrame{.length = 1}},
        },
        coquic::quic::test::test_time(1)));

    EXPECT_EQ(optional_value_or_terminate(connection.peer_source_connection_id_),
              replacement_source_connection_id);
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
    EXPECT_FALSE(connection.peer_transport_parameters_.has_value());
    EXPECT_FALSE(connection.peer_transport_parameters_validated_);
    EXPECT_EQ(connection.active_peer_connection_id_sequence_, 0u);
    ASSERT_EQ(connection.peer_connection_ids_.size(), 1u);
    EXPECT_EQ(connection.peer_connection_ids_.at(0).connection_id,
              replacement_source_connection_id);
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.zero_rtt_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, DuplicateReceivedInitialPacketDoesNotResetClientHandshakePeerState) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_source_connection_id_ = bytes_from_ints({0x01});
    connection.peer_connection_ids_[0] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 0,
        .connection_id = bytes_from_ints({0x01}),
    };
    connection.initial_space_.received_packets.record_received(
        4, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);

    expect_codec_success(connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedInitialPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x02}),
            .packet_number_length = 1,
            .packet_number = 4,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1)));

    EXPECT_EQ(optional_value_or_terminate(connection.peer_source_connection_id_),
              bytes_from_ints({0x01}));
    EXPECT_EQ(connection.peer_connection_ids_.at(0).connection_id, bytes_from_ints({0x01}));
    EXPECT_TRUE(connection.initial_space_.received_packets.has_ack_to_send());
}

TEST(
    QuicCoreTest,
    ReceivedHandshakePacketAdoptsVersionAndResetsClientHandshakePeerStateOnSourceConnectionIdChange) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.current_version_ = coquic::quic::kQuicVersion1;
    connection.peer_source_connection_id_ = bytes_from_ints({0x01});
    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .initial_source_connection_id = bytes_from_ints({0xbb}),
    };
    connection.peer_transport_parameters_validated_ = true;
    connection.peer_connection_ids_[9] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 9,
        .connection_id = bytes_from_ints({0x09}),
    };
    connection.active_peer_connection_id_sequence_ = 9;
    connection.deferred_protected_packets_.push_back(
        coquic::quic::DeferredProtectedPacket(bytes_from_ints({0xef})));
    connection.initial_space_.received_packets.record_received(
        7, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    connection.handshake_space_.received_packets.record_received(
        8, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    connection.zero_rtt_space_.received_packets.record_received(
        9, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    const std::vector<std::byte> replacement_source_connection_id = bytes_from_ints({0x04, 0x05});

    expect_codec_true(connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedHandshakePacket{
            .version = coquic::quic::kQuicVersion2,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = replacement_source_connection_id,
            .packet_number_length = 1,
            .packet_number = 2,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames = {coquic::quic::PaddingFrame{.length = 1}},
        },
        coquic::quic::test::test_time(1)));

    EXPECT_EQ(connection.current_version_, coquic::quic::kQuicVersion2);
    EXPECT_EQ(optional_value_or_terminate(connection.peer_source_connection_id_),
              replacement_source_connection_id);
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
    EXPECT_FALSE(connection.peer_transport_parameters_.has_value());
    EXPECT_FALSE(connection.peer_transport_parameters_validated_);
    EXPECT_EQ(connection.active_peer_connection_id_sequence_, 0u);
    ASSERT_EQ(connection.peer_connection_ids_.size(), 1u);
    EXPECT_EQ(connection.peer_connection_ids_.at(0).connection_id,
              replacement_source_connection_id);
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.zero_rtt_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, DuplicateReceivedHandshakePacketDoesNotResetClientHandshakePeerState) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.current_version_ = coquic::quic::kQuicVersion1;
    connection.peer_source_connection_id_ = bytes_from_ints({0x01});
    connection.peer_connection_ids_[0] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 0,
        .connection_id = bytes_from_ints({0x01}),
    };
    connection.handshake_space_.received_packets.record_received(
        5, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);

    expect_codec_success(connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedHandshakePacket{
            .version = coquic::quic::kQuicVersion2,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x02}),
            .packet_number_length = 1,
            .packet_number = 5,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1)));

    EXPECT_EQ(connection.current_version_, coquic::quic::kQuicVersion2);
    EXPECT_EQ(optional_value_or_terminate(connection.peer_source_connection_id_),
              bytes_from_ints({0x01}));
    EXPECT_EQ(connection.peer_connection_ids_.at(0).connection_id, bytes_from_ints({0x01}));
    EXPECT_TRUE(connection.handshake_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ReceivedInitialPacketRejectsInvalidCryptoFrameAndDoesNotRecordPeerActivity) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);

    expect_codec_failure(
        connection.process_inbound_received_packet(
            coquic::quic::ReceivedProtectedInitialPacket{
                .version = coquic::quic::kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_ints({0x01}),
                .packet_number_length = 1,
                .packet_number = 1,
                .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
                .frames =
                    {
                        coquic::quic::MaxDataFrame{.maximum_data = 1},
                    },
            },
            coquic::quic::test::test_time(5)),
        coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
    EXPECT_FALSE(connection.processed_peer_packet_);
    EXPECT_EQ(connection.last_peer_activity_time_, std::optional{coquic::quic::test::test_time(4)});
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest,
     ReceivedInitialAckOnlyPacketDuringClientHandshakeKeepaliveDoesNotRefreshPeerActivity) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.last_client_handshake_keepalive_probe_time_ = coquic::quic::test::test_time(4000);

    expect_codec_success(connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedInitialPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x02}),
            .packet_number_length = 1,
            .packet_number = 1,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames =
                {
                    coquic::quic::ReceivedAckFrame{
                        .largest_acknowledged = 0,
                        .first_ack_range = 0,
                        .additional_ranges_validated = true,
                    },
                },
        },
        coquic::quic::test::test_time(4100)));

    EXPECT_EQ(connection.last_peer_activity_time_, std::optional{coquic::quic::test::test_time(4)});
    EXPECT_FALSE(connection.initial_space_.pending_ack_deadline.has_value());
}

TEST(QuicCoreTest,
     ReceivedHandshakeAckOnlyPacketDuringClientHandshakeKeepaliveDoesNotRefreshPeerActivity) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.last_client_handshake_keepalive_probe_time_ = coquic::quic::test::test_time(4000);

    expect_codec_success(connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedHandshakePacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x03}),
            .packet_number_length = 1,
            .packet_number = 1,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames =
                {
                    coquic::quic::ReceivedAckFrame{
                        .largest_acknowledged = 0,
                        .first_ack_range = 0,
                        .additional_ranges_validated = true,
                    },
                },
        },
        coquic::quic::test::test_time(4100)));

    EXPECT_EQ(connection.last_peer_activity_time_, std::optional{coquic::quic::test::test_time(4)});
    EXPECT_FALSE(connection.handshake_space_.pending_ack_deadline.has_value());
}

TEST(QuicCoreTest, ProcessInboundReceivedCryptoCoversControlAndErrorBranches) {
    const auto make_received_crypto_frame = [](std::initializer_list<std::uint8_t> bytes,
                                               std::uint64_t offset = 0) {
        return coquic::quic::ReceivedCryptoFrame{
            .offset = offset,
            .crypto_data = coquic::quic::SharedBytes(bytes_from_ints(bytes)),
        };
    };

    auto closing = make_connected_client_connection();
    expect_codec_success(
        closing.process_inbound_received_crypto(coquic::quic::EncryptionLevel::application,
                                                std::vector<coquic::quic::ReceivedFrame>{
                                                    coquic::quic::TransportConnectionCloseFrame{
                                                        .error_code = 0,
                                                        .frame_type = 0,
                                                    },
                                                },
                                                coquic::quic::test::test_time(1)));
    EXPECT_TRUE(closing.has_failed());
    EXPECT_TRUE(closing.close_state_active());
    EXPECT_TRUE(closing.next_wakeup().has_value());

    auto server_handshake_done = make_connected_server_connection();
    server_handshake_done.handshake_confirmed_ = false;
    server_handshake_done.handshake_packet_space_discarded_ = false;
    expect_codec_failure(
        server_handshake_done.process_inbound_received_crypto(
            coquic::quic::EncryptionLevel::application,
            std::vector<coquic::quic::ReceivedFrame>{coquic::quic::HandshakeDoneFrame{}},
            coquic::quic::test::test_time(2)),
        coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
    EXPECT_FALSE(server_handshake_done.handshake_confirmed_);
    EXPECT_FALSE(server_handshake_done.handshake_packet_space_discarded_);

    auto invalid_frame = make_connected_client_connection();
    expect_codec_failure(invalid_frame.process_inbound_received_crypto(
                             coquic::quic::EncryptionLevel::initial,
                             std::vector<coquic::quic::ReceivedFrame>{
                                 coquic::quic::MaxDataFrame{.maximum_data = 1},
                             },
                             coquic::quic::test::test_time(3)),
                         coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);

    auto overflow_connection = make_connected_client_connection();
    expect_codec_failure(overflow_connection.process_inbound_received_crypto(
                             coquic::quic::EncryptionLevel::application,
                             std::vector<coquic::quic::ReceivedFrame>{make_received_crypto_frame(
                                 {0x01, 0x02}, (std::uint64_t{1} << 62) - 1)},
                             coquic::quic::test::test_time(4)),
                         coquic::quic::CodecErrorCode::invalid_varint);

    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time(5));
    ASSERT_NE(client.connection_, nullptr);
    auto &post_handshake = *client.connection_;
    ASSERT_TRUE(post_handshake.tls_.has_value());
    post_handshake.application_space_.receive_crypto = coquic::quic::ReliableReceiveBuffer{};
    const coquic::quic::test::ScopedTlsAdapterFaultInjector injector(
        coquic::quic::test::TlsAdapterFaultPoint::provide_post_handshake);
    const auto provide_failure = post_handshake.process_inbound_received_crypto(
        coquic::quic::EncryptionLevel::application,
        std::vector<coquic::quic::ReceivedFrame>{make_received_crypto_frame({0x05})},
        coquic::quic::test::test_time(6));
    ASSERT_FALSE(provide_failure.has_value());
    EXPECT_EQ(provide_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicCoreTest, ServerRejectsNewTokenFrameInApplicationSpace) {
    auto connection = make_connected_server_connection();

    const auto result = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::NewTokenFrame{
                .token = bytes_from_ints({0xaa, 0xbb}),
            },
        },
        coquic::quic::test::test_time(1));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
}

TEST(QuicCoreTest, ProcessInboundAckAcceptsAdditionalRangesAndLeavesMalformedRangesUnacknowledged) {
    const auto seed_declared_lost_packet = [](coquic::quic::PacketSpaceState &packet_space,
                                              std::uint64_t packet_number) {
        packet_space.recovery.on_packet_sent(coquic::quic::SentPacketRecord{
            .packet_number = packet_number,
            .sent_time = coquic::quic::test::test_time(0),
            .ack_eliciting = true,
            .in_flight = false,
            .declared_lost = true,
            .has_ping = true,
            .bytes_in_flight = 0,
        });
        packet_space.recovery.on_packet_declared_lost(packet_number);
    };

    {
        auto connection = make_connected_client_connection();
        seed_declared_lost_packet(connection.application_space_, 2);
        seed_declared_lost_packet(connection.application_space_, 5);
        seed_declared_lost_packet(connection.application_space_, 8);

        const auto result = connection.process_inbound_ack(connection.application_space_,
                                                           coquic::quic::AckFrame{
                                                               .largest_acknowledged = 5,
                                                               .first_ack_range = 0,
                                                               .additional_ranges =
                                                                   {
                                                                       coquic::quic::AckRange{
                                                                           .gap = 1,
                                                                           .range_length = 0,
                                                                       },
                                                                   },
                                                           },
                                                           coquic::quic::test::test_time(1),
                                                           /*ack_delay_exponent=*/0,
                                                           /*max_ack_delay_ms=*/0,
                                                           /*suppress_pto_reset=*/false);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(connection.application_space_.recovery.find_packet(2), nullptr);
        EXPECT_EQ(connection.application_space_.recovery.find_packet(5), nullptr);
        EXPECT_NE(connection.application_space_.recovery.find_packet(8), nullptr);
        EXPECT_EQ(tracked_packet_or_null(connection.application_space_, 2), nullptr);
        EXPECT_EQ(tracked_packet_or_null(connection.application_space_, 5), nullptr);
        const auto *lost_packet = tracked_packet_or_null(connection.application_space_, 8);
        ASSERT_NE(lost_packet, nullptr);
        EXPECT_TRUE(lost_packet->declared_lost);
        EXPECT_FALSE(lost_packet->in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        seed_declared_lost_packet(connection.application_space_, 1);

        const auto result = connection.process_inbound_ack(connection.application_space_,
                                                           coquic::quic::AckFrame{
                                                               .largest_acknowledged = 0,
                                                               .first_ack_range = 1,
                                                           },
                                                           coquic::quic::test::test_time(1),
                                                           /*ack_delay_exponent=*/0,
                                                           /*max_ack_delay_ms=*/0,
                                                           /*suppress_pto_reset=*/false);
        ASSERT_TRUE(result.has_value());
        EXPECT_NE(connection.application_space_.recovery.find_packet(1), nullptr);
        const auto &lost_packet = tracked_packet_or_terminate(connection.application_space_, 1);
        EXPECT_TRUE(lost_packet.declared_lost);
        EXPECT_FALSE(lost_packet.in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        seed_declared_lost_packet(connection.application_space_, 0);

        const auto result = connection.process_inbound_ack(connection.application_space_,
                                                           coquic::quic::AckFrame{
                                                               .largest_acknowledged = 1,
                                                               .first_ack_range = 0,
                                                               .additional_ranges =
                                                                   {
                                                                       coquic::quic::AckRange{
                                                                           .gap = 0,
                                                                           .range_length = 0,
                                                                       },
                                                                   },
                                                           },
                                                           coquic::quic::test::test_time(1),
                                                           /*ack_delay_exponent=*/0,
                                                           /*max_ack_delay_ms=*/0,
                                                           /*suppress_pto_reset=*/false);
        ASSERT_TRUE(result.has_value());
        EXPECT_NE(connection.application_space_.recovery.find_packet(0), nullptr);
        const auto &lost_packet = tracked_packet_or_terminate(connection.application_space_, 0);
        EXPECT_TRUE(lost_packet.declared_lost);
        EXPECT_FALSE(lost_packet.in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        seed_declared_lost_packet(connection.application_space_, 0);

        const auto result = connection.process_inbound_ack(connection.application_space_,
                                                           coquic::quic::AckFrame{
                                                               .largest_acknowledged = 3,
                                                               .first_ack_range = 0,
                                                               .additional_ranges =
                                                                   {
                                                                       coquic::quic::AckRange{
                                                                           .gap = 0,
                                                                           .range_length = 2,
                                                                       },
                                                                   },
                                                           },
                                                           coquic::quic::test::test_time(1),
                                                           /*ack_delay_exponent=*/0,
                                                           /*max_ack_delay_ms=*/0,
                                                           /*suppress_pto_reset=*/false);
        ASSERT_TRUE(result.has_value());
        EXPECT_NE(connection.application_space_.recovery.find_packet(0), nullptr);
        const auto &lost_packet = tracked_packet_or_terminate(connection.application_space_, 0);
        EXPECT_TRUE(lost_packet.declared_lost);
        EXPECT_FALSE(lost_packet.in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        seed_declared_lost_packet(connection.application_space_, 0);

        const auto result = connection.process_inbound_ack(connection.application_space_,
                                                           coquic::quic::AckFrame{
                                                               .largest_acknowledged = 0,
                                                               .first_ack_range = 1,
                                                           },
                                                           coquic::quic::test::test_time(1),
                                                           /*ack_delay_exponent=*/0,
                                                           /*max_ack_delay_ms=*/0,
                                                           /*suppress_pto_reset=*/false);
        ASSERT_TRUE(result.has_value());
        EXPECT_NE(connection.application_space_.recovery.find_packet(0), nullptr);
        const auto &lost_packet = tracked_packet_or_terminate(connection.application_space_, 0);
        EXPECT_TRUE(lost_packet.declared_lost);
        EXPECT_FALSE(lost_packet.in_flight);
    }
}

TEST(QuicCoreTest, ProcessInboundDatagramKeepsDeferredShortHeaderPacketsBufferedUntilConnected) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    const auto deferred_packet = bytes_from_ints({0x40, 0x01, 0x02, 0x03, 0x04});
    connection.deferred_protected_packets_.push_back(deferred_packet);

    connection.process_inbound_datagram(deferred_packet, coquic::quic::test::test_time(1));

    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), deferred_packet);
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ServerDefersAckOnlyOneRttBeforeHandshakeCompletesWhenKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_packet_space_discarded_ = false;

    const auto ack_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 7,
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
    ASSERT_TRUE(ack_packet.has_value());

    connection.process_inbound_datagram(ack_packet.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.handshake_confirmed_);
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), ack_packet.value());
}

TEST(QuicCoreTest, ServerDefersOneRttMaxDataBeforeHandshakeCompletesWhenKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_packet_space_discarded_ = false;
    connection.connection_flow_control_.peer_max_data = 1024;
    connection.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 1024};
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;

    const auto max_data_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 8,
                .frames =
                    {
                        coquic::quic::MaxDataFrame{
                            .maximum_data = 4096,
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
    ASSERT_TRUE(max_data_packet.has_value());

    connection.process_inbound_datagram(max_data_packet.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.handshake_confirmed_);
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), max_data_packet.value());
    EXPECT_EQ(connection.connection_flow_control_.peer_max_data, 1024u);
    EXPECT_TRUE(connection.connection_flow_control_.pending_data_blocked_frame.has_value());
    EXPECT_EQ(connection.connection_flow_control_.data_blocked_state,
              coquic::quic::StreamControlFrameState::pending);
}

TEST(QuicCoreTest, ServerDefersOneRttStreamBeforeHandshakeCompletesWhenKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_packet_space_discarded_ = false;

    const auto stream_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 9,
                .frames =
                    {
                        coquic::quic::test::make_inbound_application_stream_frame(
                            "GET /lost-finished\r\n", 0, 0, true),
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(stream_packet.has_value());

    connection.process_inbound_datagram(stream_packet.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.handshake_confirmed_);
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_TRUE(connection.pending_stream_receive_effects_.empty());
    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), stream_packet.value());
}

TEST(QuicCoreTest, ServerProcessesReceivedOneRttMaxDataBeforeHandshakeCompletesWhenKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.connection_flow_control_.peer_max_data = 1024;

    const auto processed = connection.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::MaxDataFrame{
                .maximum_data = 4096,
            },
        },
        coquic::quic::test::test_time(1), /*allow_preconnected_frames=*/false, /*path_id=*/0);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.connection_flow_control_.peer_max_data, 4096u);
    EXPECT_FALSE(connection.handshake_confirmed_);
}

TEST(QuicCoreTest, ProcessInboundDatagramDeduplicatesAndEvictsDeferredProtectedPackets) {
    const auto make_deferred_packet = [](coquic::quic::QuicConnection &connection,
                                         std::uint64_t packet_number) {
        const auto encoded = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames =
                        {
                            coquic::quic::ResetStreamFrame{
                                .stream_id = 0,
                                .application_protocol_error_code = 1,
                                .final_size = 0,
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
        EXPECT_TRUE(encoded.has_value());
        if (!encoded.has_value()) {
            return std::vector<std::byte>{};
        }
        return encoded.value();
    };

    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.application_space_.read_secret = make_test_traffic_secret(
            coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
        connection.application_space_.write_secret = make_test_traffic_secret(
            coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});

        const auto deferred_packet = make_deferred_packet(connection, 1);
        connection.deferred_protected_packets_.push_back(deferred_packet);

        connection.process_inbound_datagram(deferred_packet, coquic::quic::test::test_time(1));

        ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
        EXPECT_EQ(connection.deferred_protected_packets_.front(), deferred_packet);
    }

    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.application_space_.read_secret = make_test_traffic_secret(
            coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
        connection.application_space_.write_secret = make_test_traffic_secret(
            coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});

        for (std::uint8_t index = 0; index < 32; ++index) {
            connection.deferred_protected_packets_.push_back(
                make_deferred_packet(connection, index));
        }

        const auto evicted_packet = connection.deferred_protected_packets_.front();
        const auto deferred_packet = make_deferred_packet(connection, 40);

        connection.process_inbound_datagram(deferred_packet, coquic::quic::test::test_time(1));

        ASSERT_EQ(connection.deferred_protected_packets_.size(), 32u);
        EXPECT_NE(connection.deferred_protected_packets_.front(), evicted_packet);
        EXPECT_NE(std::find(connection.deferred_protected_packets_.begin(),
                            connection.deferred_protected_packets_.end(), deferred_packet),
                  connection.deferred_protected_packets_.end());
    }
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenDeferredReplayPacketFailsProcessing) {
    auto connection = make_connected_client_connection();
    connection.deferred_protected_packets_.push_back(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x11, 0x01, 0x22, 0x00, 0x00}));

    connection.process_inbound_datagram(bytes_from_ints({0x01}), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
}

TEST(QuicCoreTest, DrainOutboundDatagramReplaysDeferredProtectedPacketsBeforeFlush) {
    auto connection = make_connected_client_connection();
    const auto deferred_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 7,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(deferred_packet.has_value());
    if (!deferred_packet.has_value()) {
        return;
    }
    connection.deferred_protected_packets_.push_back(deferred_packet.value());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 7u);
    if (datagram.empty()) {
        const auto ack_deadline = connection.next_wakeup();
        ASSERT_TRUE(ack_deadline.has_value());
        datagram = connection.drain_outbound_datagram(optional_value_or_terminate(ack_deadline));
    }
    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    for (const auto &frame : application->frames) {
        if (const auto *ack = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_ack = true;
            EXPECT_EQ(ack->largest_acknowledged, 7u);
        }
    }
    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, DrainOutboundDatagramFailsWhenDeferredReplayFails) {
    auto connection = make_connected_client_connection();
    connection.deferred_protected_packets_.push_back(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x11, 0x01, 0x22, 0x00, 0x00}));

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
}

TEST(QuicCoreTest, DrainOutboundDatagramFailsWhenSyncTlsStateFails) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    connection.peer_source_connection_id_ = {std::byte{0x01}};
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(*connection.tls_,
                                                                          {std::byte{0x40}});

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, DrainOutboundDatagramReturnsEmptyWhenNothingIsPending) {
    auto connection = make_connected_client_connection();

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, PacketTargetsDiscardedLongHeaderSpaceCoversEdgeCases) {
    auto connection = make_connected_client_connection();

    EXPECT_FALSE(connection.packet_targets_discarded_long_header_space(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00})));
    EXPECT_FALSE(connection.packet_targets_discarded_long_header_space(bytes_from_ints({0x40})));

    connection.initial_packet_space_discarded_ = true;
    EXPECT_TRUE(connection.packet_targets_discarded_long_header_space(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01})));

    connection.handshake_packet_space_discarded_ = true;
    EXPECT_TRUE(connection.packet_targets_discarded_long_header_space(
        bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01})));

    EXPECT_FALSE(connection.packet_targets_discarded_long_header_space(
        bytes_from_ints({0xd0, 0x00, 0x00, 0x00, 0x01})));
}

TEST(QuicCoreTest, ProcessInboundApplicationRejectsPingBeforeConnectionCompletes) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;

    const auto result = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{coquic::quic::PingFrame{}},
        coquic::quic::test::test_time(1));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest, UnvalidatedMigratedPathIsAntiAmplificationLimited) {
    auto connection = make_connected_server_connection();
    connection.current_send_path_id_ = 9;
    connection.ensure_path_state(9).anti_amplification_received_bytes = 40;
    connection.ensure_path_state(9).anti_amplification_sent_bytes = 120;

    EXPECT_EQ(connection.outbound_datagram_size_limit(), 0u);
}

TEST(QuicCoreTest, PeerPreferredAddressProducesCoreEffectOnceValidated) {
    auto connection = make_connected_client_connection();
    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 8,
        .initial_source_connection_id = bytes_from_ints({0xaa}),
        .preferred_address =
            coquic::quic::PreferredAddress{
                .ipv4_address = {std::byte{127}, std::byte{0}, std::byte{0}, std::byte{2}},
                .ipv4_port = 4444,
                .connection_id = bytes_from_ints({0x41, 0x42, 0x43, 0x44}),
            },
    };
    connection.peer_transport_parameters_validated_ = true;

    connection.sync_tls_state();

    ASSERT_TRUE(connection.pending_preferred_address_effect_.has_value());
    EXPECT_EQ(optional_ref_or_terminate(connection.pending_preferred_address_effect_)
                  .preferred_address.ipv4_port,
              4444);
}

TEST(QuicCoreTest,
     ProcessInboundDatagramDiscardsCorruptedShortHeaderPacketWithoutFailingConnection) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;

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

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::open_set_tag);
    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

} // namespace
