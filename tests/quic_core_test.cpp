#include <gtest/gtest.h>

#include <cstdint>
#include <limits>

#include "src/quic/packet_crypto_test_hooks.h"
#include "src/quic/protected_codec.h"
#include "src/quic/tls_adapter_quictls_test_hooks.h"
#include "tests/quic_test_utils.h"

namespace {

std::vector<std::byte> bytes_from_ints(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

coquic::quic::TrafficSecret make_test_traffic_secret(
    coquic::quic::CipherSuite cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
    std::byte fill = std::byte{0x11}) {
    const std::size_t secret_size =
        cipher_suite == coquic::quic::CipherSuite::tls_aes_256_gcm_sha384 ? 48u : 32u;
    return coquic::quic::TrafficSecret{
        .cipher_suite = cipher_suite,
        .secret = std::vector<std::byte>(secret_size, fill),
    };
}

template <typename Core>
concept has_receive = requires(Core &core) { core.receive(std::vector<std::byte>{}); };

template <typename Core>
concept has_queue_application_data =
    requires(Core &core) { core.queue_application_data(std::vector<std::byte>{}); };

template <typename Core>
concept has_take_received_application_data =
    requires(Core &core) { core.take_received_application_data(); };

static_assert(!has_receive<coquic::quic::QuicCore>);
static_assert(!has_queue_application_data<coquic::quic::QuicCore>);
static_assert(!has_take_received_application_data<coquic::quic::QuicCore>);

TEST(QuicCoreTest, ClientStartProducesSendEffect) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    const auto config = coquic::quic::test::make_client_core_config();

    const auto result =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto datagrams = coquic::quic::test::send_datagrams_from(result);
    ASSERT_EQ(datagrams.size(), 1u);
    ASSERT_GE(datagrams.front().size(), 1200u);
    EXPECT_FALSE(client.is_handshake_complete());
    EXPECT_TRUE(coquic::quic::test::state_changes_from(result).empty());
    EXPECT_EQ(result.next_wakeup, std::nullopt);

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        datagrams.front(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = config.initial_destination_connection_id,
        });
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedInitialPacket>(&decoded.value()[0]), nullptr);
}

TEST(QuicCoreTest, TwoPeersEmitHandshakeReadyExactlyOnce) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    auto client_events = std::vector<coquic::quic::QuicCoreStateChange>{};
    auto server_events = std::vector<coquic::quic::QuicCoreStateChange>{};
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time(),
                                             &client_events, &server_events);

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
    EXPECT_EQ(coquic::quic::test::count_state_change(
                  client_events, coquic::quic::QuicCoreStateChange::handshake_ready),
              1u);
    EXPECT_EQ(coquic::quic::test::count_state_change(
                  server_events, coquic::quic::QuicCoreStateChange::handshake_ready),
              1u);
}

TEST(QuicCoreTest, TwoPeersExchangeApplicationDataThroughEffects) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto send = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("ping"),
        },
        coquic::quic::test::test_time(1));
    const auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(1));

    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(received)),
              "ping");
}

TEST(QuicCoreTest, MoveConstructionPreservesStartBehavior) {
    coquic::quic::QuicCore source(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore moved(std::move(source));

    const auto result =
        moved.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());

    EXPECT_EQ(coquic::quic::test::send_datagrams_from(result).size(), 1u);
}

TEST(QuicCoreTest, MoveAssignmentPreservesStartBehavior) {
    coquic::quic::QuicCore source(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore destination(coquic::quic::test::make_client_core_config());
    destination = std::move(source);

    const auto result =
        destination.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());

    EXPECT_EQ(coquic::quic::test::send_datagrams_from(result).size(), 1u);
}

TEST(QuicCoreTest, FailureEventIsEdgeTriggeredAndLaterCallsAreInert) {
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto failed = server.advance(coquic::quic::QuicCoreInboundDatagram{{std::byte{0x01}}},
                                       coquic::quic::test::test_time());
    const auto after =
        server.advance(coquic::quic::QuicCoreTimerExpired{}, coquic::quic::test::test_time(1));

    EXPECT_EQ(coquic::quic::test::state_changes_from(failed),
              std::vector{coquic::quic::QuicCoreStateChange::failed});
    EXPECT_TRUE(after.effects.empty());
    EXPECT_EQ(after.next_wakeup, std::nullopt);
}

TEST(QuicCoreTest, FailureSuppressesStaleHandshakeReadyInSameResult) {
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    server.connection_->queue_state_change(coquic::quic::QuicCoreStateChange::handshake_ready);

    const auto failed = server.advance(coquic::quic::QuicCoreInboundDatagram{{std::byte{0x01}}},
                                       coquic::quic::test::test_time());
    const auto state_changes = coquic::quic::test::state_changes_from(failed);

    EXPECT_EQ(state_changes, std::vector{coquic::quic::QuicCoreStateChange::failed});
}

TEST(QuicCoreTest, InboundApplicationStreamRequiresOffsetAndLengthFlags) {
    coquic::quic::QuicConnection missing_offset_connection(
        coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        missing_offset_connection, coquic::quic::HandshakeStatus::connected);
    const auto missing_offset_ok =
        coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            missing_offset_connection, {coquic::quic::test::make_inbound_application_stream_frame(
                                           "a", 0, 0, false, false, true)});
    EXPECT_FALSE(missing_offset_ok);
    EXPECT_TRUE(missing_offset_connection.has_failed());

    coquic::quic::QuicConnection missing_length_connection(
        coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        missing_length_connection, coquic::quic::HandshakeStatus::connected);
    const auto missing_length_ok =
        coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            missing_length_connection, {coquic::quic::test::make_inbound_application_stream_frame(
                                           "b", 0, 0, false, true, false)});
    EXPECT_FALSE(missing_length_ok);
    EXPECT_TRUE(missing_length_connection.has_failed());
}

TEST(QuicCoreTest, InboundApplicationStreamFailsBeforeHandshakeConnected) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::in_progress);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("ping")});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.take_received_application_data().empty());
}

TEST(QuicCoreTest, InboundApplicationCryptoFrameIsIgnoredAfterHandshakeConnected) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::CryptoFrame{
                         .offset = 0,
                         .crypto_data = coquic::quic::test::bytes_from_string("ignored"),
                     },
                     coquic::quic::test::make_inbound_application_stream_frame("pong")});

    EXPECT_TRUE(injected);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(coquic::quic::test::string_from_bytes(connection.take_received_application_data()),
              "pong");
}

TEST(QuicCoreTest, InboundApplicationStreamFailsForNonZeroStreamId) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("ping", 0, 1)});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, InboundApplicationStreamFailsWhenFinSet) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::test::make_inbound_application_stream_frame("ping", 0, 0, true)});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ConnectionParserHelpersRejectMalformedClientInitialHeaders) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());

    EXPECT_FALSE(connection.peek_client_initial_destination_connection_id({}).has_value());

    const auto fixed_bit_missing = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0x80, 0x00, 0x00, 0x00, 0x01, 0x00}));
    ASSERT_FALSE(fixed_bit_missing.has_value());
    EXPECT_EQ(fixed_bit_missing.error().code, coquic::quic::CodecErrorCode::invalid_fixed_bit);

    const auto wrong_packet_type = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xf0, 0x00, 0x00, 0x00, 0x01, 0x00}));
    ASSERT_FALSE(wrong_packet_type.has_value());
    EXPECT_EQ(wrong_packet_type.error().code,
              coquic::quic::CodecErrorCode::unsupported_packet_type);

    const auto truncated_version = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00}));
    ASSERT_FALSE(truncated_version.has_value());
    EXPECT_EQ(truncated_version.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto unsupported_version = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x02, 0x00}));
    ASSERT_FALSE(unsupported_version.has_value());
    EXPECT_EQ(unsupported_version.error().code,
              coquic::quic::CodecErrorCode::unsupported_packet_type);

    const auto missing_dcid_length = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01}));
    ASSERT_FALSE(missing_dcid_length.has_value());
    EXPECT_EQ(missing_dcid_length.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto oversized_dcid = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x15}));
    ASSERT_FALSE(oversized_dcid.has_value());
    EXPECT_EQ(oversized_dcid.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto truncated_dcid = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x02}));
    ASSERT_FALSE(truncated_dcid.has_value());
    EXPECT_EQ(truncated_dcid.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicCoreTest, ConnectionParserHelpersRejectMalformedPacketLengths) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());

    EXPECT_FALSE(connection.peek_next_packet_length({}).has_value());

    const auto fixed_bit_missing =
        connection.peek_next_packet_length(bytes_from_ints({0x80, 0x00, 0x00, 0x00, 0x01}));
    ASSERT_FALSE(fixed_bit_missing.has_value());
    EXPECT_EQ(fixed_bit_missing.error().code, coquic::quic::CodecErrorCode::invalid_fixed_bit);

    const auto unsupported_version =
        connection.peek_next_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x02, 0x00}));
    ASSERT_FALSE(unsupported_version.has_value());
    EXPECT_EQ(unsupported_version.error().code,
              coquic::quic::CodecErrorCode::unsupported_packet_type);

    const auto truncated_dcid = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x03, 0x01}));
    ASSERT_FALSE(truncated_dcid.has_value());
    EXPECT_EQ(truncated_dcid.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto oversized_scid = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x15}));
    ASSERT_FALSE(oversized_scid.has_value());
    EXPECT_EQ(oversized_scid.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto unsupported_type = connection.peek_next_packet_length(
        bytes_from_ints({0xd0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x00}));
    ASSERT_FALSE(unsupported_type.has_value());
    EXPECT_EQ(unsupported_type.error().code, coquic::quic::CodecErrorCode::unsupported_packet_type);

    const auto token_too_long = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02}));
    ASSERT_FALSE(token_too_long.has_value());
    EXPECT_EQ(token_too_long.error().code, coquic::quic::CodecErrorCode::packet_length_mismatch);

    const auto payload_too_long = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x02}));
    ASSERT_FALSE(payload_too_long.has_value());
    EXPECT_EQ(payload_too_long.error().code, coquic::quic::CodecErrorCode::packet_length_mismatch);
}

TEST(QuicCoreTest, UnexpectedFirstInboundDatagramsFailAndLaterCallsAreInert) {
    coquic::quic::QuicConnection client(coquic::quic::test::make_client_core_config());
    client.process_inbound_datagram(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00}));
    EXPECT_TRUE(client.has_failed());

    client.start();
    client.queue_application_data(coquic::quic::test::bytes_from_string("ignored"));
    client.status_ = coquic::quic::HandshakeStatus::idle;
    client.queue_application_data({});
    EXPECT_TRUE(client.pending_application_send_.empty());
    client.status_ = coquic::quic::HandshakeStatus::failed;
    client.process_inbound_datagram({});
    EXPECT_TRUE(client.drain_outbound_datagram().empty());
    EXPECT_TRUE(client.take_received_application_data().empty());

    coquic::quic::QuicConnection server(coquic::quic::test::make_server_core_config());
    server.process_inbound_datagram({});
    EXPECT_FALSE(server.has_failed());

    server.process_inbound_datagram(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x04}));
    EXPECT_TRUE(server.has_failed());
}

TEST(QuicCoreTest, ServerStartupFailureReturnsAfterStartingTls) {
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.identity.reset();
    coquic::quic::QuicConnection server(std::move(server_config));

    server.process_inbound_datagram(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x02}));

    EXPECT_TRUE(server.has_failed());
}

TEST(QuicCoreTest, ConnectionProcessInboundCryptoCoversErrorBranches) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    const auto wrong_frame = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial,
        std::array<coquic::quic::Frame, 1>{coquic::quic::PingFrame{}});
    ASSERT_FALSE(wrong_frame.has_value());
    EXPECT_EQ(wrong_frame.error().code,
              coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);

    const auto empty_crypto = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial,
        std::array<coquic::quic::Frame, 1>{coquic::quic::CryptoFrame{}});
    EXPECT_TRUE(empty_crypto.has_value());

    const auto overflow = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial, std::array<coquic::quic::Frame, 1>{
                                                    coquic::quic::CryptoFrame{
                                                        .offset = (std::uint64_t{1} << 62),
                                                        .crypto_data = {std::byte{0x01}},
                                                    },
                                                });
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto missing_tls = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial, std::array<coquic::quic::Frame, 1>{
                                                    coquic::quic::CryptoFrame{
                                                        .offset = 0,
                                                        .crypto_data = {std::byte{0x01}},
                                                    },
                                                });
    ASSERT_FALSE(missing_tls.has_value());
    EXPECT_EQ(missing_tls.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    connection.start_client_if_needed();
    auto &connection_tls = connection.tls_;
    if (!connection_tls.has_value()) {
        ADD_FAILURE() << "expected client startup to initialize TLS state";
        return;
    }
    coquic::quic::test::TlsAdapterTestPeer::set_sticky_error(
        *connection_tls, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
    const auto provided_failure = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial, std::array<coquic::quic::Frame, 1>{
                                                    coquic::quic::CryptoFrame{
                                                        .offset = 1,
                                                        .crypto_data = {std::byte{0x02}},
                                                    },
                                                });
    ASSERT_FALSE(provided_failure.has_value());
    EXPECT_EQ(provided_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicCoreTest, ConnectionProcessInboundApplicationCoversAckAndErrorBranches) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto ack_and_padding =
        connection.process_inbound_application(std::array<coquic::quic::Frame, 3>{
            coquic::quic::AckFrame{},
            coquic::quic::PaddingFrame{.length = 2},
            coquic::quic::test::make_inbound_application_stream_frame("ok"),
        });
    ASSERT_TRUE(ack_and_padding.has_value());
    EXPECT_EQ(coquic::quic::test::string_from_bytes(connection.take_received_application_data()),
              "ok");

    connection.expected_application_stream_offset_ = 4;
    const auto wrong_offset =
        connection.process_inbound_application(std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("x", 1),
        });
    ASSERT_FALSE(wrong_offset.has_value());
    EXPECT_EQ(wrong_offset.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    connection.expected_application_stream_offset_ = std::numeric_limits<std::uint64_t>::max();
    const auto overflow = connection.process_inbound_application(std::array<coquic::quic::Frame, 1>{
        coquic::quic::test::make_inbound_application_stream_frame(
            "x", std::numeric_limits<std::uint64_t>::max()),
    });
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto missing_offset_value =
        connection.process_inbound_application(std::array<coquic::quic::Frame, 1>{
            coquic::quic::StreamFrame{
                .fin = false,
                .has_offset = true,
                .has_length = true,
                .stream_id = 0,
                .offset = std::nullopt,
                .stream_data = {std::byte{'x'}},
            },
        });
    ASSERT_FALSE(missing_offset_value.has_value());
    EXPECT_EQ(missing_offset_value.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest, ConnectionPacketLengthParserRejectsRemainingMalformedInputs) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());

    const auto truncated_version =
        connection.peek_next_packet_length(bytes_from_ints({0xc0, 0x00, 0x00}));
    ASSERT_FALSE(truncated_version.has_value());
    EXPECT_EQ(truncated_version.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto missing_dcid_length =
        connection.peek_next_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01}));
    ASSERT_FALSE(missing_dcid_length.has_value());
    EXPECT_EQ(missing_dcid_length.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto oversized_dcid =
        connection.peek_next_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x15}));
    ASSERT_FALSE(oversized_dcid.has_value());
    EXPECT_EQ(oversized_dcid.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto truncated_scid = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x02, 0x03}));
    ASSERT_FALSE(truncated_scid.has_value());
    EXPECT_EQ(truncated_scid.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto truncated_token_length = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02}));
    ASSERT_FALSE(truncated_token_length.has_value());
    EXPECT_EQ(truncated_token_length.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto truncated_payload_length = connection.peek_next_packet_length(
        bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02}));
    ASSERT_FALSE(truncated_payload_length.has_value());
    EXPECT_EQ(truncated_payload_length.error().code, coquic::quic::CodecErrorCode::truncated_input);
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

TEST(QuicCoreTest, ProcessInboundDatagramFailsForDecodeAndPacketProcessingErrors) {
    coquic::quic::QuicConnection decode_failure(coquic::quic::test::make_client_core_config());
    decode_failure.start_client_if_needed();
    decode_failure.process_inbound_datagram(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x11, 0x01, 0x22, 0x00, 0x00}));
    EXPECT_TRUE(decode_failure.has_failed());

    coquic::quic::QuicConnection packet_failure(coquic::quic::test::make_server_core_config());
    packet_failure.started_ = true;
    packet_failure.status_ = coquic::quic::HandshakeStatus::connected;
    packet_failure.client_initial_destination_connection_id_ =
        packet_failure.config_.initial_destination_connection_id;
    packet_failure.application_space_.read_secret = make_test_traffic_secret();

    const auto invalid_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = packet_failure.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 0,
                .frames =
                    {
                        coquic::quic::test::make_inbound_application_stream_frame("x", 0, 0, false,
                                                                                  true, false),
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
    packet_failure.process_inbound_datagram(invalid_packet.value());
    EXPECT_TRUE(packet_failure.has_failed());
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

    const auto valid_packet = coquic::quic::serialize_protected_datagram(
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
    ASSERT_TRUE(valid_packet.has_value());
    connection.process_inbound_datagram(valid_packet.value());

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ConnectionTlsAndValidationHelpersCoverRemainingBranches) {
    coquic::quic::QuicConnection no_tls_validation(coquic::quic::test::make_client_core_config());
    EXPECT_TRUE(no_tls_validation.validate_peer_transport_parameters_if_ready().has_value());

    coquic::quic::QuicConnection no_tls_connection(coquic::quic::test::make_client_core_config());
    no_tls_connection.install_available_secrets();
    no_tls_connection.collect_pending_tls_bytes();
    EXPECT_TRUE(no_tls_connection.initial_space_.send_crypto.empty());

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
    const auto sync_failure = malformed_params_connection.sync_tls_state();
    ASSERT_FALSE(sync_failure.has_value());
    EXPECT_EQ(sync_failure.error().code, coquic::quic::CodecErrorCode::truncated_input);

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
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        *preloaded_parameters_connection.tls_, coquic::quic::test::sample_transport_parameters());
    EXPECT_TRUE(
        preloaded_parameters_connection.validate_peer_transport_parameters_if_ready().has_value());
    EXPECT_TRUE(preloaded_parameters_connection.peer_transport_parameters_validated_);

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

TEST(QuicCoreTest, ConnectionFailureAndStateChangeGuardsAreEdgeTriggered) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.queue_state_change(coquic::quic::QuicCoreStateChange::handshake_ready);
    connection.queue_state_change(coquic::quic::QuicCoreStateChange::handshake_ready);
    EXPECT_EQ(connection.pending_state_changes_.size(), 1u);

    connection.queue_state_change(coquic::quic::QuicCoreStateChange::failed);
    connection.queue_state_change(coquic::quic::QuicCoreStateChange::failed);
    EXPECT_EQ(connection.pending_state_changes_.size(), 2u);

    connection.mark_failed();
    const auto first_failure_events = connection.pending_state_changes_.size();
    connection.mark_failed();
    EXPECT_EQ(connection.pending_state_changes_.size(), first_failure_events);
}

TEST(QuicCoreTest, PeerTransportParametersValidationContextRequiresPeerConnectionId) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    EXPECT_EQ(connection.peer_transport_parameters_validation_context(), std::nullopt);
}

TEST(QuicCoreTest, FlushOutboundDatagramMarksFailuresForSerializationErrors) {
    coquic::quic::QuicConnection candidate_failure(coquic::quic::test::make_client_core_config());
    candidate_failure.started_ = true;
    candidate_failure.status_ = coquic::quic::HandshakeStatus::connected;
    candidate_failure.application_space_.write_secret = make_test_traffic_secret();
    candidate_failure.pending_application_send_ = coquic::quic::test::bytes_from_string("hello");
    {
        const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
            coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);
        EXPECT_TRUE(candidate_failure.flush_outbound_datagram().empty());
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
        EXPECT_TRUE(final_failure.flush_outbound_datagram().empty());
    }
    EXPECT_TRUE(final_failure.has_failed());

    coquic::quic::QuicConnection missing_handshake_secret(
        coquic::quic::test::make_client_core_config());
    missing_handshake_secret.started_ = true;
    missing_handshake_secret.status_ = coquic::quic::HandshakeStatus::in_progress;
    missing_handshake_secret.handshake_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("hs"));
    EXPECT_TRUE(missing_handshake_secret.flush_outbound_datagram().empty());
    EXPECT_TRUE(missing_handshake_secret.has_failed());

    coquic::quic::QuicConnection missing_application_secret(
        coquic::quic::test::make_client_core_config());
    missing_application_secret.started_ = true;
    missing_application_secret.status_ = coquic::quic::HandshakeStatus::connected;
    missing_application_secret.pending_application_send_ =
        coquic::quic::test::bytes_from_string("hello");
    EXPECT_TRUE(missing_application_secret.flush_outbound_datagram().empty());
    EXPECT_FALSE(missing_application_secret.has_failed());

    coquic::quic::QuicConnection padding_failure(coquic::quic::test::make_client_core_config());
    padding_failure.started_ = true;
    padding_failure.status_ = coquic::quic::HandshakeStatus::in_progress;
    padding_failure.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hi"));
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_length_guard, 2);
    EXPECT_TRUE(padding_failure.flush_outbound_datagram().empty());
    EXPECT_TRUE(padding_failure.has_failed());
}

} // namespace
