#include <cstddef>
#include <cstring>
#include <initializer_list>
#include <type_traits>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "src/coquic.h"
#include "src/quic/packet_crypto_test_hooks.h"
#include "src/quic/protected_codec.h"
#include "src/quic/tls_adapter_quictls_test_hooks.h"
#include "tests/quic_test_utils.h"

namespace {

using coquic::quic::AckFrame;
using coquic::quic::CipherSuite;
using coquic::quic::CodecErrorCode;
using coquic::quic::ConnectionId;
using coquic::quic::CryptoFrame;
using coquic::quic::DeserializeProtectionContext;
using coquic::quic::EndpointRole;
using coquic::quic::Frame;
using coquic::quic::HandshakeStatus;
using coquic::quic::PaddingFrame;
using coquic::quic::ProtectedOneRttPacket;
using coquic::quic::ProtectedPacket;
using coquic::quic::QuicConnection;
using coquic::quic::QuicCore;
using coquic::quic::SerializeProtectionContext;
using coquic::quic::StreamFrame;
using coquic::quic::TlsAdapter;
using coquic::quic::TlsAdapterConfig;
using coquic::quic::TlsIdentity;
using coquic::quic::TrafficSecret;
using coquic::quic::test::ScopedTlsAdapterFaultInjector;
using coquic::quic::test::TlsAdapterFaultPoint;

std::vector<std::byte> byte_vector(std::initializer_list<unsigned int> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }

    return bytes;
}

EndpointRole opposite_role(EndpointRole role) {
    return role == EndpointRole::client ? EndpointRole::server : EndpointRole::client;
}

CipherSuite invalid_cipher_suite() {
    const auto raw = static_cast<std::underlying_type_t<CipherSuite>>(0xff);
    CipherSuite cipher_suite{};
    std::memcpy(&cipher_suite, &raw, sizeof(cipher_suite));
    return cipher_suite;
}

TrafficSecret make_traffic_secret(CipherSuite cipher_suite = CipherSuite::tls_aes_128_gcm_sha256) {
    const std::size_t secret_size = cipher_suite == CipherSuite::tls_aes_256_gcm_sha384 ? 48u : 32u;
    return TrafficSecret{
        .cipher_suite = cipher_suite,
        .secret = std::vector<std::byte>(secret_size, std::byte{0x11}),
    };
}

TlsAdapterConfig make_client_tls_config(std::vector<std::byte> local_transport_parameters =
                                            coquic::quic::test::sample_transport_parameters()) {
    return TlsAdapterConfig{
        .role = EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = std::move(local_transport_parameters),
    };
}

TlsAdapterConfig make_server_tls_config(std::vector<std::byte> local_transport_parameters =
                                            coquic::quic::test::sample_transport_parameters()) {
    return TlsAdapterConfig{
        .role = EndpointRole::server,
        .verify_peer = false,
        .server_name = "localhost",
        .identity =
            TlsIdentity{
                .certificate_pem =
                    coquic::quic::test::read_text_file("tests/fixtures/quic-server-cert.pem"),
                .private_key_pem =
                    coquic::quic::test::read_text_file("tests/fixtures/quic-server-key.pem"),
            },
        .local_transport_parameters = std::move(local_transport_parameters),
    };
}

void drive_tls_handshake(TlsAdapter &client, TlsAdapter &server) {
    ASSERT_TRUE(client.start().has_value());
    auto to_server = client.take_pending(coquic::quic::EncryptionLevel::initial);
    ASSERT_FALSE(to_server.empty());
    ASSERT_TRUE(server.provide(coquic::quic::EncryptionLevel::initial, to_server).has_value());

    for (int i = 0; i < 32 && !(client.handshake_complete() && server.handshake_complete()); ++i) {
        const auto client_initial = client.take_pending(coquic::quic::EncryptionLevel::initial);
        if (!client_initial.empty()) {
            ASSERT_TRUE(
                server.provide(coquic::quic::EncryptionLevel::initial, client_initial).has_value());
        }

        const auto server_initial = server.take_pending(coquic::quic::EncryptionLevel::initial);
        if (!server_initial.empty()) {
            ASSERT_TRUE(
                client.provide(coquic::quic::EncryptionLevel::initial, server_initial).has_value());
        }

        const auto server_handshake = server.take_pending(coquic::quic::EncryptionLevel::handshake);
        if (!server_handshake.empty()) {
            ASSERT_TRUE(server_handshake.size() > 0);
            ASSERT_TRUE(client.provide(coquic::quic::EncryptionLevel::handshake, server_handshake)
                            .has_value());
        }

        const auto client_handshake = client.take_pending(coquic::quic::EncryptionLevel::handshake);
        if (!client_handshake.empty()) {
            ASSERT_TRUE(server.provide(coquic::quic::EncryptionLevel::handshake, client_handshake)
                            .has_value());
        }

        client.poll();
        server.poll();
    }

    ASSERT_TRUE(client.handshake_complete());
    ASSERT_TRUE(server.handshake_complete());
}

std::vector<std::byte> make_one_rtt_datagram(QuicConnection &connection, std::vector<Frame> frames,
                                             const TrafficSecret &secret) {
    const auto serialized = coquic::quic::serialize_protected_datagram(
        std::vector<ProtectedPacket>{ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 0,
            .frames = std::move(frames),
        }},
        SerializeProtectionContext{
            .local_role = opposite_role(connection.config_.role),
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = secret,
        });
    EXPECT_TRUE(serialized.has_value());
    if (!serialized.has_value()) {
        return {};
    }

    return serialized.value();
}

std::vector<std::byte> valid_initial_header_bytes() {
    return byte_vector({
        0xc0,
        0x00,
        0x00,
        0x00,
        0x01,
        0x08,
        0x83,
        0x94,
        0xc8,
        0xf0,
        0x3e,
        0x51,
        0x57,
        0x08,
    });
}

std::vector<std::byte> valid_initial_packet_bytes() {
    return byte_vector({
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0,
        0x3e, 0x51, 0x57, 0x08, 0x01, 0x53, 0x00, 0x01, 0x00,
    });
}

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

TEST(QuicCoreTest, PeekClientInitialDestinationConnectionIdRejectsMalformedHeaders) {
    const QuicConnection connection(coquic::quic::test::make_server_core_config());

    EXPECT_FALSE(connection.peek_client_initial_destination_connection_id({}).has_value());
    EXPECT_FALSE(
        connection.peek_client_initial_destination_connection_id(byte_vector({0x40})).has_value());
    EXPECT_FALSE(
        connection.peek_client_initial_destination_connection_id(byte_vector({0x80})).has_value());
    EXPECT_FALSE(connection
                     .peek_client_initial_destination_connection_id(byte_vector({
                         0xd0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x00,
                     }))
                     .has_value());
}

TEST(QuicCoreTest, PeekClientInitialDestinationConnectionIdRejectsMalformedBodyFields) {
    const QuicConnection connection(coquic::quic::test::make_server_core_config());

    EXPECT_FALSE(connection
                     .peek_client_initial_destination_connection_id(byte_vector({
                         0xc0,
                         0x00,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_client_initial_destination_connection_id(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x02,
                         0x00,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_client_initial_destination_connection_id(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_client_initial_destination_connection_id(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x15,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_client_initial_destination_connection_id(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x02,
                         0xaa,
                     }))
                     .has_value());
}

TEST(QuicCoreTest, PeekNextPacketLengthRejectsMalformedHeaders) {
    const QuicConnection connection(coquic::quic::test::make_server_core_config());

    EXPECT_FALSE(connection.peek_next_packet_length({}).has_value());
    EXPECT_FALSE(connection.peek_next_packet_length(byte_vector({0x80})).has_value());
    EXPECT_FALSE(connection.peek_next_packet_length(byte_vector({0xc0, 0x00})).has_value());
    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x02,
                         0x00,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xd0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x00,
                         0x00,
                     }))
                     .has_value());
}

TEST(QuicCoreTest, PeekNextPacketLengthRejectsMalformedConnectionIdAndLengthFields) {
    const QuicConnection connection(coquic::quic::test::make_server_core_config());

    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x15,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x02,
                         0xaa,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x01,
                         0xaa,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x01,
                         0xaa,
                         0x15,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x01,
                         0xaa,
                         0x02,
                         0xbb,
                     }))
                     .has_value());
}

TEST(QuicCoreTest, PeekNextPacketLengthRejectsMalformedTokenAndPayloadLengths) {
    const QuicConnection connection(coquic::quic::test::make_server_core_config());

    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x01,
                         0xaa,
                         0x01,
                         0xbb,
                         0x40,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xc0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x01,
                         0xaa,
                         0x01,
                         0xbb,
                         0x02,
                         0xcc,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xe0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x01,
                         0xaa,
                         0x01,
                         0xbb,
                         0x40,
                     }))
                     .has_value());
    EXPECT_FALSE(connection
                     .peek_next_packet_length(byte_vector({
                         0xe0,
                         0x00,
                         0x00,
                         0x00,
                         0x01,
                         0x01,
                         0xaa,
                         0x01,
                         0xbb,
                         0x02,
                         0x00,
                     }))
                     .has_value());
}

TEST(QuicCoreTest, ReceiveRejectsUnexpectedClientDatagramBeforeStart) {
    QuicConnection connection(coquic::quic::test::make_client_core_config());

    EXPECT_TRUE(connection.receive(byte_vector({0x01})).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ReceiveReturnsEmptyAfterFailureState) {
    QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(connection,
                                                                     HandshakeStatus::failed);

    EXPECT_TRUE(connection.receive(valid_initial_packet_bytes()).empty());
}

TEST(QuicCoreTest, StartedConnectionRejectsInvalidPacketLength) {
    QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;

    EXPECT_TRUE(connection.receive(byte_vector({0x80})).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, StartedConnectionRejectsUndecodableProtectedDatagram) {
    QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;

    EXPECT_TRUE(connection.receive(byte_vector({0x01})).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, StartedConnectionRejectsInboundApplicationProcessingFailure) {
    QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = HandshakeStatus::connected;
    connection.application_space_.read_secret = make_traffic_secret();

    const auto datagram = make_one_rtt_datagram(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("ping", 1)},
        connection.application_space_.read_secret.value());

    EXPECT_TRUE(connection.receive(datagram).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, StartedConnectionRejectsTlsStateSyncFailureAfterPacketProcessing) {
    QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.application_space_.read_secret = make_traffic_secret();
    connection.peer_source_connection_id_ = ConnectionId{std::byte{0x53}, std::byte{0x01}};

    TlsAdapter client_adapter(make_client_tls_config());
    TlsAdapter server_adapter(make_server_tls_config(byte_vector({0x40})));
    drive_tls_handshake(client_adapter, server_adapter);
    connection.tls_ = std::move(client_adapter);

    const auto datagram = make_one_rtt_datagram(connection,
                                                {AckFrame{
                                                    .largest_acknowledged = 0,
                                                    .ack_delay = 0,
                                                    .first_ack_range = 0,
                                                }},
                                                connection.application_space_.read_secret.value());

    EXPECT_TRUE(connection.receive(datagram).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundCryptoExercisesFailureAndRetryPaths) {
    QuicConnection non_crypto_connection(coquic::quic::test::make_server_core_config());
    EXPECT_FALSE(non_crypto_connection
                     .process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                             std::vector<Frame>{AckFrame{
                                                 .largest_acknowledged = 0,
                                                 .ack_delay = 0,
                                                 .first_ack_range = 0,
                                             }})
                     .has_value());

    QuicConnection overflow_connection(coquic::quic::test::make_server_core_config());
    EXPECT_FALSE(overflow_connection
                     .process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                             std::vector<Frame>{CryptoFrame{
                                                 .offset = (std::uint64_t{1} << 62) - 1,
                                                 .crypto_data = byte_vector({0x01, 0x02}),
                                             }})
                     .has_value());

    QuicConnection out_of_order_connection(coquic::quic::test::make_server_core_config());
    const auto out_of_order = out_of_order_connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial, std::vector<Frame>{CryptoFrame{
                                                    .offset = 2,
                                                    .crypto_data = byte_vector({0x01, 0x02}),
                                                }});
    ASSERT_TRUE(out_of_order.has_value());
    EXPECT_FALSE(out_of_order_connection.has_failed());

    QuicConnection missing_tls_connection(coquic::quic::test::make_server_core_config());
    EXPECT_FALSE(missing_tls_connection
                     .process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                             std::vector<Frame>{CryptoFrame{
                                                 .offset = 0,
                                                 .crypto_data = byte_vector({0x01}),
                                             }})
                     .has_value());

    QuicConnection sticky_tls_connection(coquic::quic::test::make_server_core_config());
    sticky_tls_connection.tls_ = TlsAdapter(TlsAdapterConfig{
        .role = EndpointRole::server,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    EXPECT_FALSE(sticky_tls_connection
                     .process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                             std::vector<Frame>{CryptoFrame{
                                                 .offset = 0,
                                                 .crypto_data = byte_vector({0x01}),
                                             }})
                     .has_value());
}

TEST(QuicCoreTest, ProcessInboundApplicationExercisesRemainingBranches) {
    QuicConnection ignore_connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(ignore_connection,
                                                                     HandshakeStatus::connected);
    const auto ignored = ignore_connection.process_inbound_application(std::vector<Frame>{
        PaddingFrame{.length = 2},
        AckFrame{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
    });
    ASSERT_TRUE(ignored.has_value());
    EXPECT_TRUE(ignore_connection.take_received_application_data().empty());

    QuicConnection offset_connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(offset_connection,
                                                                     HandshakeStatus::connected);
    offset_connection.expected_application_stream_offset_ = 1;
    EXPECT_FALSE(offset_connection
                     .process_inbound_application(std::vector<Frame>{
                         coquic::quic::test::make_inbound_application_stream_frame("a", 0),
                     })
                     .has_value());

    QuicConnection overflow_connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(overflow_connection,
                                                                     HandshakeStatus::connected);
    overflow_connection.expected_application_stream_offset_ =
        std::numeric_limits<std::uint64_t>::max();
    EXPECT_FALSE(overflow_connection
                     .process_inbound_application(std::vector<Frame>{
                         StreamFrame{
                             .fin = false,
                             .has_offset = true,
                             .has_length = true,
                             .stream_id = 0,
                             .offset = std::numeric_limits<std::uint64_t>::max(),
                             .stream_data = byte_vector({0x01}),
                         },
                     })
                     .has_value());
}

TEST(QuicCoreTest, ProcessInboundApplicationRejectsMissingOffsetValueWhenFlagIsSet) {
    QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(connection,
                                                                     HandshakeStatus::connected);

    EXPECT_FALSE(connection
                     .process_inbound_application(std::vector<Frame>{StreamFrame{
                         .fin = false,
                         .has_offset = true,
                         .has_length = true,
                         .stream_id = 0,
                         .offset = std::nullopt,
                         .stream_data = byte_vector({0x01}),
                     }})
                     .has_value());
}

TEST(QuicCoreTest, ConnectionHelpersReturnEarlyWhenStateMakesThemNoOps) {
    QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.queue_application_data({});
    EXPECT_TRUE(connection.pending_application_send_.empty());

    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(connection,
                                                                     HandshakeStatus::failed);
    connection.queue_application_data(byte_vector({0x01}));
    EXPECT_TRUE(connection.pending_application_send_.empty());

    connection.install_available_secrets();
    connection.collect_pending_tls_bytes();
    connection.update_handshake_status();
    EXPECT_FALSE(connection.is_handshake_complete());
    EXPECT_FALSE(connection.peer_transport_parameters_validation_context().has_value());
}

TEST(QuicCoreTest, StartServerReturnsImmediatelyWhenAlreadyStarted) {
    QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = HandshakeStatus::in_progress;

    connection.start_server_if_needed(ConnectionId{std::byte{0xaa}, std::byte{0xbb}});

    EXPECT_TRUE(connection.started_);
    EXPECT_EQ(connection.status_, HandshakeStatus::in_progress);
    EXPECT_FALSE(connection.client_initial_destination_connection_id_.has_value());
}

TEST(QuicCoreTest, StartClientFailsWhenTlsInitializationLeavesAdapterInErrorState) {
    const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::initialize_transport_params);
    QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.start_client_if_needed();

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ValidatePeerTransportParametersIfReadyExercisesDeferredAndFailurePaths) {
    QuicConnection context_missing_connection(coquic::quic::test::make_client_core_config());
    TlsAdapter deferred_client(make_client_tls_config());
    TlsAdapter deferred_server(make_server_tls_config());
    drive_tls_handshake(deferred_client, deferred_server);
    context_missing_connection.tls_ = std::move(deferred_client);
    const auto deferred = context_missing_connection.validate_peer_transport_parameters_if_ready();
    ASSERT_TRUE(deferred.has_value());
    EXPECT_FALSE(context_missing_connection.peer_transport_parameters_validated_);

    QuicConnection malformed_connection(coquic::quic::test::make_client_core_config());
    malformed_connection.peer_source_connection_id_ =
        ConnectionId{std::byte{0x53}, std::byte{0x01}};
    TlsAdapter malformed_client(make_client_tls_config());
    TlsAdapter malformed_server(make_server_tls_config(byte_vector({0x40})));
    drive_tls_handshake(malformed_client, malformed_server);
    malformed_connection.tls_ = std::move(malformed_client);
    EXPECT_FALSE(malformed_connection.validate_peer_transport_parameters_if_ready().has_value());

    QuicConnection mismatch_connection(coquic::quic::test::make_client_core_config());
    mismatch_connection.peer_source_connection_id_ = ConnectionId{std::byte{0x99}, std::byte{0x99}};
    const auto peer_parameters =
        coquic::quic::serialize_transport_parameters(coquic::quic::TransportParameters{
            .original_destination_connection_id =
                mismatch_connection.config_.initial_destination_connection_id,
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
        });
    ASSERT_TRUE(peer_parameters.has_value());
    TlsAdapter mismatch_client(make_client_tls_config());
    TlsAdapter mismatch_server(make_server_tls_config(peer_parameters.value()));
    drive_tls_handshake(mismatch_client, mismatch_server);
    mismatch_connection.tls_ = std::move(mismatch_client);
    EXPECT_FALSE(mismatch_connection.validate_peer_transport_parameters_if_ready().has_value());
}

TEST(QuicCoreTest, ValidatePeerTransportParametersIfReadyShortCircuitsWithoutTlsOrWhenValidated) {
    QuicConnection missing_tls_connection(coquic::quic::test::make_client_core_config());
    const auto missing_tls = missing_tls_connection.validate_peer_transport_parameters_if_ready();
    ASSERT_TRUE(missing_tls.has_value());
    EXPECT_FALSE(missing_tls_connection.peer_transport_parameters_validated_);

    QuicConnection validated_connection(coquic::quic::test::make_client_core_config());
    validated_connection.peer_transport_parameters_validated_ = true;
    validated_connection.tls_ = TlsAdapter(make_client_tls_config());
    const auto validated = validated_connection.validate_peer_transport_parameters_if_ready();
    ASSERT_TRUE(validated.has_value());
    EXPECT_TRUE(validated_connection.peer_transport_parameters_validated_);
}

TEST(QuicCoreTest, ValidatePeerTransportParametersIfReadyReusesCachedParsedParameters) {
    QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.peer_source_connection_id_ = ConnectionId{std::byte{0x53}, std::byte{0x01}};
    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .original_destination_connection_id = connection.config_.initial_destination_connection_id,
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
    };

    const auto peer_parameters =
        coquic::quic::serialize_transport_parameters(connection.peer_transport_parameters_.value());
    ASSERT_TRUE(peer_parameters.has_value());

    TlsAdapter client_adapter(make_client_tls_config());
    TlsAdapter server_adapter(make_server_tls_config(peer_parameters.value()));
    drive_tls_handshake(client_adapter, server_adapter);
    connection.tls_ = std::move(client_adapter);

    const auto validated = connection.validate_peer_transport_parameters_if_ready();
    ASSERT_TRUE(validated.has_value());
    EXPECT_TRUE(connection.peer_transport_parameters_validated_);
}

TEST(QuicCoreTest,
     UpdateHandshakeStatusReturnsWithoutTlsAndRequiresValidatedPeerParametersAndSecrets) {
    QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = HandshakeStatus::in_progress;

    connection.update_handshake_status();
    EXPECT_EQ(connection.status_, HandshakeStatus::in_progress);

    TlsAdapter client_adapter(make_client_tls_config());
    TlsAdapter server_adapter(make_server_tls_config());
    drive_tls_handshake(client_adapter, server_adapter);
    connection.tls_ = std::move(client_adapter);

    connection.update_handshake_status();
    EXPECT_EQ(connection.status_, HandshakeStatus::in_progress);

    connection.peer_transport_parameters_validated_ = true;
    connection.update_handshake_status();
    EXPECT_EQ(connection.status_, HandshakeStatus::in_progress);

    connection.application_space_.read_secret = make_traffic_secret();
    connection.update_handshake_status();
    EXPECT_EQ(connection.status_, HandshakeStatus::in_progress);

    connection.application_space_.write_secret = make_traffic_secret();
    connection.update_handshake_status();
    EXPECT_EQ(connection.status_, HandshakeStatus::connected);
}

TEST(QuicCoreTest, UpdateHandshakeStatusReturnsImmediatelyWhenConnectionWasNeverStarted) {
    QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.status_ = HandshakeStatus::in_progress;

    connection.update_handshake_status();

    EXPECT_EQ(connection.status_, HandshakeStatus::in_progress);
}

TEST(QuicCoreTest, FlushOutboundDatagramExercisesFailureBranches) {
    QuicConnection handshake_secret_connection(coquic::quic::test::make_server_core_config());
    handshake_secret_connection.handshake_space_.send_crypto.append(byte_vector({0x01}));
    EXPECT_TRUE(handshake_secret_connection.flush_outbound_datagram().empty());
    EXPECT_TRUE(handshake_secret_connection.has_failed());

    QuicConnection oversized_connection(coquic::quic::test::make_client_core_config());
    oversized_connection.status_ = HandshakeStatus::connected;
    oversized_connection.application_space_.write_secret = make_traffic_secret();
    oversized_connection.pending_application_send_ = std::vector<std::byte>(2000, std::byte{0x5a});
    const auto oversized_datagram = oversized_connection.flush_outbound_datagram();
    EXPECT_FALSE(oversized_datagram.empty());
    EXPECT_FALSE(oversized_connection.pending_application_send_.empty());

    QuicConnection invalid_secret_connection(coquic::quic::test::make_client_core_config());
    invalid_secret_connection.status_ = HandshakeStatus::connected;
    invalid_secret_connection.application_space_.write_secret =
        make_traffic_secret(invalid_cipher_suite());
    invalid_secret_connection.pending_application_send_ = byte_vector({0x01});
    EXPECT_TRUE(invalid_secret_connection.flush_outbound_datagram().empty());
    EXPECT_TRUE(invalid_secret_connection.has_failed());

    QuicConnection invalid_initial_connection(coquic::quic::test::make_client_core_config());
    invalid_initial_connection.initial_space_.send_crypto.append(byte_vector({0x01}));
    invalid_initial_connection.config_.initial_destination_connection_id =
        ConnectionId(21, std::byte{0xaa});
    EXPECT_TRUE(invalid_initial_connection.flush_outbound_datagram().empty());
    EXPECT_TRUE(invalid_initial_connection.has_failed());

    QuicConnection padded_initial_connection(coquic::quic::test::make_client_core_config());
    padded_initial_connection.initial_space_.send_crypto.append(byte_vector({0x01}));
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new, 2);
    EXPECT_TRUE(padded_initial_connection.flush_outbound_datagram().empty());
    EXPECT_TRUE(padded_initial_connection.has_failed());
}

TEST(QuicCoreTest, FlushOutboundDatagramCanLeaveApplicationBytesQueuedWhenFlightIsFull) {
    bool found_full_flight = false;

    for (std::size_t crypto_bytes = 1000; crypto_bytes < 1200 && !found_full_flight;
         ++crypto_bytes) {
        QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.status_ = HandshakeStatus::connected;
        connection.initial_space_.send_crypto.append(
            std::vector<std::byte>(crypto_bytes, std::byte{0x42}));
        connection.application_space_.write_secret = make_traffic_secret();
        connection.pending_application_send_ = byte_vector({0x99});

        const auto datagram = connection.flush_outbound_datagram();
        if (datagram.empty() || connection.has_failed()) {
            continue;
        }

        if (connection.pending_application_send_ == byte_vector({0x99}) &&
            connection.next_application_stream_offset_ == 0) {
            found_full_flight = true;
        }
    }

    EXPECT_TRUE(found_full_flight);
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

TEST(QuicCoreTest, MoveConstructionPreservesHandshakeStateQueries) {
    coquic::quic::QuicCore original(coquic::quic::test::make_client_core_config());

    const auto initial = original.receive({});
    ASSERT_FALSE(initial.empty());

    coquic::quic::QuicCore moved(std::move(original));

    EXPECT_FALSE(moved.has_failed());
    EXPECT_FALSE(moved.is_handshake_complete());
    EXPECT_TRUE(moved.receive({}).empty());
}

TEST(QuicCoreTest, MoveAssignmentPreservesFailureQueries) {
    coquic::quic::QuicCore source(coquic::quic::test::make_server_core_config());
    EXPECT_TRUE(source.receive({std::byte{0x01}}).empty());
    ASSERT_TRUE(source.has_failed());

    coquic::quic::QuicCore destination(coquic::quic::test::make_client_core_config());
    destination = std::move(source);

    EXPECT_TRUE(destination.has_failed());
    EXPECT_TRUE(destination.receive({}).empty());
}

} // namespace
