#include <array>

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstdint>
#include <limits>

#include "src/quic/packet_crypto_test_hooks.h"
#include "src/quic/protected_codec.h"
#include "src/quic/tls_adapter_quictls_test_hooks.h"
#include "tests/quic_test_utils.h"

namespace coquic::quic {
CodecResult<TrafficSecret> derive_next_traffic_secret(const TrafficSecret &secret);
}

namespace {

std::vector<std::byte> bytes_from_ints(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

std::uint8_t hex_nibble_or_terminate(char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(10 + (value - 'a'));
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<std::uint8_t>(10 + (value - 'A'));
    }

    std::abort();
}

std::vector<std::byte> bytes_from_hex(std::string_view hex) {
    if ((hex.size() % 2u) != 0u) {
        std::abort();
    }

    std::vector<std::byte> bytes;
    bytes.reserve(hex.size() / 2u);
    for (std::size_t index = 0; index < hex.size(); index += 2u) {
        const auto high = hex_nibble_or_terminate(hex[index]);
        const auto low = hex_nibble_or_terminate(hex[index + 1u]);
        bytes.push_back(static_cast<std::byte>((high << 4u) | low));
    }

    return bytes;
}

template <typename T> T optional_value_or_terminate(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return value.value();
}

template <typename T> const T &optional_ref_or_terminate(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return value.value();
}

template <typename T> T &optional_ref_or_terminate(std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return value.value();
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

coquic::quic::QuicConnection make_connected_client_connection() {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::connected;
    connection.handshake_confirmed_ = true;
    connection.peer_source_connection_id_ = {std::byte{0xa1}, std::byte{0xb2}};
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.application_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
    connection.application_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});
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
        .initial_max_stream_data_uni = connection.config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = connection.peer_source_connection_id_,
    };
    connection.peer_transport_parameters_validated_ = true;
    connection.initialize_peer_flow_control_from_transport_parameters();
    return connection;
}

coquic::quic::QuicConnection make_connected_server_connection() {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::connected;
    connection.handshake_confirmed_ = true;
    connection.peer_source_connection_id_ = {std::byte{0xc1}, std::byte{0x01}};
    connection.client_initial_destination_connection_id_ = {
        std::byte{0x83}, std::byte{0x94}, std::byte{0xc8}, std::byte{0xf0},
        std::byte{0x3e}, std::byte{0x51}, std::byte{0x57}, std::byte{0x08},
    };
    connection.local_transport_parameters_ = coquic::quic::TransportParameters{
        .original_destination_connection_id = connection.client_initial_destination_connection_id_,
        .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
        .active_connection_id_limit = 2,
        .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
        .max_ack_delay = connection.config_.transport.max_ack_delay,
        .initial_max_data = connection.config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local =
            connection.config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            connection.config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = connection.config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = connection.config_.source_connection_id,
    };
    connection.initialize_local_flow_control();
    connection.application_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
    connection.application_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});
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
        .initial_max_stream_data_uni = connection.config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = connection.peer_source_connection_id_,
    };
    connection.peer_transport_parameters_validated_ = true;
    connection.initialize_peer_flow_control_from_transport_parameters();
    return connection;
}

std::vector<coquic::quic::ProtectedPacket>
decode_sender_datagram(const coquic::quic::QuicConnection &connection,
                       std::span<const std::byte> datagram) {
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        datagram, coquic::quic::DeserializeProtectionContext{
                      .peer_role = connection.config_.role,
                      .client_initial_destination_connection_id =
                          connection.client_initial_destination_connection_id(),
                      .handshake_secret = connection.handshake_space_.write_secret,
                      .one_rtt_secret = connection.application_space_.write_secret,
                      .one_rtt_key_phase = connection.application_write_key_phase_,
                      .largest_authenticated_initial_packet_number =
                          connection.initial_space_.largest_authenticated_packet_number,
                      .largest_authenticated_handshake_packet_number =
                          connection.handshake_space_.largest_authenticated_packet_number,
                      .largest_authenticated_application_packet_number =
                          connection.application_space_.largest_authenticated_packet_number,
                      .one_rtt_destination_connection_id_length =
                          connection.config_.source_connection_id.size(),
                  });
    EXPECT_TRUE(decoded.has_value());
    if (!decoded.has_value()) {
        return {};
    }

    return decoded.value();
}

std::vector<std::uint64_t>
application_stream_ids_from_datagram(const coquic::quic::QuicConnection &connection,
                                     std::span<const std::byte> datagram) {
    const auto packets = decode_sender_datagram(connection, datagram);
    std::vector<std::uint64_t> stream_ids;
    for (const auto &packet : packets) {
        const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
        if (application == nullptr) {
            continue;
        }

        for (const auto &frame : application->frames) {
            const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            if (std::find(stream_ids.begin(), stream_ids.end(), stream->stream_id) ==
                stream_ids.end()) {
                stream_ids.push_back(stream->stream_id);
            }
        }
    }

    return stream_ids;
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

void expect_local_error(const coquic::quic::QuicCoreResult &result,
                        coquic::quic::QuicCoreLocalErrorCode code, std::uint64_t stream_id) {
    const auto local_error = result.local_error;
    ASSERT_TRUE(local_error.has_value());
    if (!local_error.has_value()) {
        return;
    }

    EXPECT_EQ(local_error->code, code);
    ASSERT_TRUE(local_error->stream_id.has_value());
    if (!local_error->stream_id.has_value()) {
        return;
    }

    EXPECT_EQ(*local_error->stream_id, stream_id);
}

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
    EXPECT_TRUE(result.next_wakeup.has_value());

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

TEST(QuicCoreTest, HandshakeExportsConfiguredTransportParametersToPeer) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.transport.initial_max_data = 7777;
    client_config.transport.initial_max_stream_data_bidi_local = 1234;
    client_config.transport.initial_max_stream_data_bidi_remote = 2345;
    client_config.transport.initial_max_stream_data_uni = 3456;
    client_config.transport.initial_max_streams_bidi = 11;
    client_config.transport.initial_max_streams_uni = 13;

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto &peer_transport_parameters = server.connection_->peer_transport_parameters_;
    ASSERT_TRUE(peer_transport_parameters.has_value());
    if (!peer_transport_parameters.has_value()) {
        return;
    }
    EXPECT_EQ(peer_transport_parameters.value().initial_max_data, 7777u);
    EXPECT_EQ(peer_transport_parameters.value().initial_max_stream_data_bidi_local, 1234u);
    EXPECT_EQ(peer_transport_parameters.value().initial_max_stream_data_bidi_remote, 2345u);
    EXPECT_EQ(peer_transport_parameters.value().initial_max_stream_data_uni, 3456u);
    EXPECT_EQ(peer_transport_parameters.value().initial_max_streams_bidi, 11u);
    EXPECT_EQ(peer_transport_parameters.value().initial_max_streams_uni, 13u);
}

TEST(QuicCoreTest, TwoPeersExchangeStreamZeroDataThroughEffects) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ping"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    const auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(1));

    const auto stream_events = coquic::quic::test::received_stream_data_from(received);
    ASSERT_EQ(stream_events.size(), 1u);
    EXPECT_EQ(stream_events[0].stream_id, 0u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(stream_events[0].bytes), "ping");
    EXPECT_FALSE(stream_events[0].fin);
}

TEST(QuicCoreTest, ClientCanSendOnMultipleBidirectionalStreams) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto first = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("a"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    const auto second = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 4,
            .bytes = coquic::quic::test::bytes_from_string("b"),
            .fin = false,
        },
        coquic::quic::test::test_time(2));

    const auto server_first = coquic::quic::test::relay_send_datagrams_to_peer(
        first, server, coquic::quic::test::test_time(1));
    const auto server_second = coquic::quic::test::relay_send_datagrams_to_peer(
        second, server, coquic::quic::test::test_time(2));

    ASSERT_EQ(coquic::quic::test::stream_payloads_from(server_first).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(server_first)[0],
              (coquic::quic::test::StreamPayload{0, "a", false}));
    ASSERT_EQ(coquic::quic::test::stream_payloads_from(server_second).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(server_second)[0],
              (coquic::quic::test::StreamPayload{4, "b", false}));
}

TEST(QuicCoreTest, BlockedStreamResumesWhenPeerMaxStreamDataArrives) {
    auto client_config = coquic::quic::test::make_client_core_config();
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.transport.initial_max_stream_data_bidi_remote = 4;

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto first = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("abcdef"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    const auto first_received = coquic::quic::test::relay_send_datagrams_to_peer(
        first, server, coquic::quic::test::test_time(2));

    ASSERT_EQ(coquic::quic::test::stream_payloads_from(first_received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(first_received)[0],
              (coquic::quic::test::StreamPayload{0, "abcd", false}));

    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        *client.connection_,
        {coquic::quic::MaxStreamDataFrame{
            .stream_id = 0,
            .maximum_stream_data = 6,
        }},
        /*packet_number=*/1));

    const auto resumed =
        client.advance(coquic::quic::QuicCoreTimerExpired{}, coquic::quic::test::test_time(3));
    const auto resumed_received = coquic::quic::test::relay_send_datagrams_to_peer(
        resumed, server, coquic::quic::test::test_time(4));

    ASSERT_EQ(coquic::quic::test::stream_payloads_from(resumed_received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(resumed_received)[0],
              (coquic::quic::test::StreamPayload{0, "ef", false}));
}

TEST(QuicCoreTest, BlockedConnectionResumesWhenPeerMaxDataArrives) {
    auto client_config = coquic::quic::test::make_client_core_config();
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.transport.initial_max_data = 4;
    server_config.transport.initial_max_stream_data_bidi_remote = 16;

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto first = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("abcdef"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    const auto first_received = coquic::quic::test::relay_send_datagrams_to_peer(
        first, server, coquic::quic::test::test_time(2));

    ASSERT_EQ(coquic::quic::test::stream_payloads_from(first_received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(first_received)[0],
              (coquic::quic::test::StreamPayload{0, "abcd", false}));

    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        *client.connection_,
        {coquic::quic::MaxDataFrame{
            .maximum_data = 6,
        }},
        /*packet_number=*/1));

    const auto resumed =
        client.advance(coquic::quic::QuicCoreTimerExpired{}, coquic::quic::test::test_time(3));
    const auto resumed_received = coquic::quic::test::relay_send_datagrams_to_peer(
        resumed, server, coquic::quic::test::test_time(4));

    ASSERT_EQ(coquic::quic::test::stream_payloads_from(resumed_received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(resumed_received)[0],
              (coquic::quic::test::StreamPayload{0, "ef", false}));
}

TEST(QuicCoreTest, KeyUpdatedMaxDataAndAckUnblockLostApplicationSend) {
    auto connection = make_connected_server_connection();
    connection.connection_flow_control_.peer_max_data = 1173;
    const auto payload = std::vector<std::byte>(4096, std::byte{0x61});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(0));
    ASSERT_FALSE(first_datagram.empty());
    ASSERT_EQ(connection.application_space_.sent_packets.size(), 1u);

    const auto first_packet_number = connection.application_space_.sent_packets.begin()->first;
    const auto first_packet = connection.application_space_.sent_packets.at(first_packet_number);
    ASSERT_FALSE(first_packet.stream_fragments.empty());
    EXPECT_EQ(first_packet.stream_fragments.front().offset, 0u);
    const auto first_fragment_length = first_packet.stream_fragments.front().bytes.size();
    ASSERT_GT(first_fragment_length, 1000u);
    ASSERT_EQ(connection.connection_flow_control_.highest_sent, first_fragment_length);

    connection.mark_lost_packet(connection.application_space_, first_packet);

    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    ASSERT_TRUE(connection.application_space_.write_secret.has_value());
    const auto next_read_secret = coquic::quic::derive_next_traffic_secret(
        optional_ref_or_terminate(connection.application_space_.read_secret));
    const auto next_write_secret = coquic::quic::derive_next_traffic_secret(
        optional_ref_or_terminate(connection.application_space_.write_secret));
    ASSERT_TRUE(next_read_secret.has_value());
    ASSERT_TRUE(next_write_secret.has_value());

    const auto process_client_packet = [&](std::uint64_t packet_number,
                                           std::span<const coquic::quic::Frame> frames,
                                           coquic::quic::QuicCoreTimePoint now) {
        const auto encoded = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .key_phase = true,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames = std::vector<coquic::quic::Frame>(frames.begin(), frames.end()),
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::client,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret = next_read_secret.value(),
                .one_rtt_key_phase = true,
            });
        ASSERT_TRUE(encoded.has_value());
        connection.process_inbound_datagram(encoded.value(), now);
    };

    process_client_packet(/*packet_number=*/1,
                          std::array<coquic::quic::Frame, 1>{
                              coquic::quic::MaxDataFrame{
                                  .maximum_data = first_fragment_length * 2,
                              },
                          },
                          coquic::quic::test::test_time(1));

    ASSERT_FALSE(connection.has_failed());
    ASSERT_EQ(connection.connection_flow_control_.peer_max_data, first_fragment_length * 2);
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    ASSERT_TRUE(connection.application_space_.write_secret.has_value());
    EXPECT_EQ(optional_ref_or_terminate(connection.application_space_.read_secret).secret,
              next_read_secret.value().secret);
    EXPECT_EQ(optional_ref_or_terminate(connection.application_space_.write_secret).secret,
              next_write_secret.value().secret);

    const auto retransmitted = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(retransmitted.empty());
    const auto retransmitted_packets = decode_sender_datagram(connection, retransmitted);
    ASSERT_EQ(retransmitted_packets.size(), 1u);
    const auto *retransmitted_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&retransmitted_packets.front());
    ASSERT_NE(retransmitted_application, nullptr);

    bool saw_retransmitted_prefix = false;
    bool saw_fresh_stream_data = false;
    for (const auto &frame : retransmitted_application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        const auto stream_offset = optional_value_or_terminate(stream->offset);
        if (stream_offset == 0u && stream->stream_data.size() == first_fragment_length) {
            saw_retransmitted_prefix = true;
        } else if (stream_offset >= first_fragment_length) {
            saw_fresh_stream_data = true;
        }
    }
    EXPECT_TRUE(saw_retransmitted_prefix);
    EXPECT_FALSE(saw_fresh_stream_data);

    const auto retransmit_packet_number =
        std::prev(connection.application_space_.sent_packets.end())->first;
    ASSERT_GT(retransmit_packet_number, first_packet_number);

    process_client_packet(/*packet_number=*/2,
                          std::array<coquic::quic::Frame, 1>{
                              coquic::quic::AckFrame{
                                  .largest_acknowledged = retransmit_packet_number,
                                  .first_ack_range = 0,
                              },
                          },
                          coquic::quic::test::test_time(3));

    ASSERT_FALSE(connection.has_failed());
    ASSERT_TRUE(connection.streams_.contains(0));
    const auto &stream = connection.streams_.at(0);
    EXPECT_TRUE(connection.has_pending_application_send())
        << "peer_max_data=" << connection.connection_flow_control_.peer_max_data
        << " highest_sent=" << connection.connection_flow_control_.highest_sent
        << " queued=" << connection.total_queued_stream_bytes()
        << " sendable=" << stream.sendable_bytes()
        << " has_lost=" << stream.send_buffer.has_lost_data() << " outstanding_prefix="
        << stream.send_buffer.has_outstanding_range(0, first_fragment_length)
        << " outstanding_suffix="
        << stream.send_buffer.has_outstanding_range(first_fragment_length,
                                                    payload.size() - first_fragment_length)
        << " sent_packets=" << connection.application_space_.sent_packets.size();

    const auto resumed = connection.drain_outbound_datagram(coquic::quic::test::test_time(4));
    ASSERT_FALSE(resumed.empty())
        << "peer_max_data=" << connection.connection_flow_control_.peer_max_data
        << " highest_sent=" << connection.connection_flow_control_.highest_sent
        << " queued=" << connection.total_queued_stream_bytes()
        << " sendable=" << stream.sendable_bytes()
        << " has_lost=" << stream.send_buffer.has_lost_data() << " outstanding_prefix="
        << stream.send_buffer.has_outstanding_range(0, first_fragment_length)
        << " outstanding_suffix="
        << stream.send_buffer.has_outstanding_range(first_fragment_length,
                                                    payload.size() - first_fragment_length)
        << " sent_packets=" << connection.application_space_.sent_packets.size();
    const auto resumed_packets = decode_sender_datagram(connection, resumed);
    ASSERT_EQ(resumed_packets.size(), 1u);
    const auto *resumed_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&resumed_packets.front());
    ASSERT_NE(resumed_application, nullptr);

    bool saw_remaining_suffix = false;
    for (const auto &frame : resumed_application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        if (optional_value_or_terminate(stream->offset) == first_fragment_length) {
            saw_remaining_suffix = true;
        }
    }
    EXPECT_TRUE(saw_remaining_suffix);
}

TEST(QuicCoreTest, SendStreamLocalErrorsCoverInvalidIdAndClosedSendSide) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    client.connection_->stream_open_limits_.peer_max_bidirectional = 1;

    const auto invalid = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 4,
            .bytes = coquic::quic::test::bytes_from_string("x"),
            .fin = false,
        },
        coquic::quic::test::test_time());
    expect_local_error(invalid, coquic::quic::QuicCoreLocalErrorCode::invalid_stream_id, 4);

    const auto fin = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("x"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    EXPECT_FALSE(fin.local_error.has_value());

    const auto closed = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("y"),
            .fin = false,
        },
        coquic::quic::test::test_time(2));
    expect_local_error(closed, coquic::quic::QuicCoreLocalErrorCode::send_side_closed, 0);
}

TEST(QuicCoreTest, PeerStreamDataBlockedTriggersMaxStreamDataRefresh) {
    auto connection = make_connected_client_connection();
    auto &stream = connection.streams_
                       .emplace(1, coquic::quic::make_implicit_stream_state(
                                       1, coquic::quic::EndpointRole::client))
                       .first->second;
    stream.flow_control.local_receive_window = 8;
    stream.flow_control.advertised_max_stream_data = 8;
    stream.flow_control.delivered_bytes = 4;

    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::StreamDataBlockedFrame{
                        .stream_id = 1,
                        .maximum_stream_data = 8,
                    }}));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_max_stream_data = false;
    for (const auto &frame : application->frames) {
        if (const auto *max_stream_data = std::get_if<coquic::quic::MaxStreamDataFrame>(&frame)) {
            saw_max_stream_data = true;
            EXPECT_EQ(max_stream_data->stream_id, 1u);
            EXPECT_EQ(max_stream_data->maximum_stream_data, 12u);
        }
    }
    EXPECT_TRUE(saw_max_stream_data);
}

TEST(QuicCoreTest, PeerDataBlockedTriggersMaxDataRefresh) {
    auto connection = make_connected_client_connection();
    connection.connection_flow_control_.local_receive_window = 8;
    connection.connection_flow_control_.advertised_max_data = 8;
    connection.connection_flow_control_.delivered_bytes = 4;

    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::DataBlockedFrame{
                        .maximum_data = 8,
                    }}));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_max_data = false;
    for (const auto &frame : application->frames) {
        if (const auto *max_data = std::get_if<coquic::quic::MaxDataFrame>(&frame)) {
            saw_max_data = true;
            EXPECT_EQ(max_data->maximum_data, 12u);
        }
    }
    EXPECT_TRUE(saw_max_data);
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

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
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

    ASSERT_EQ(connection.application_space_.sent_packets.size(), 1u);
    const auto &sent_packet = connection.application_space_.sent_packets.begin()->second;
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

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
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

TEST(QuicCoreTest, StreamReceiveEffectCarriesFin) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto sent = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("hello"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    const auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        sent, server, coquic::quic::test::test_time(2));

    ASSERT_EQ(coquic::quic::test::stream_payloads_from(received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(received)[0],
              (coquic::quic::test::StreamPayload{0, "hello", true}));
}

TEST(QuicCoreTest, StreamReceiveEffectCarriesFinWhenQueuedAfterOutstandingData) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto sent = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("hello"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    const auto first_received = coquic::quic::test::relay_send_datagrams_to_peer(
        sent, server, coquic::quic::test::test_time(2));
    ASSERT_EQ(coquic::quic::test::stream_payloads_from(first_received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(first_received)[0],
              (coquic::quic::test::StreamPayload{0, "hello", false}));

    const auto fin_only = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = {},
            .fin = true,
        },
        coquic::quic::test::test_time(3));
    const auto fin_received = coquic::quic::test::relay_send_datagrams_to_peer(
        fin_only, server, coquic::quic::test::test_time(4));

    ASSERT_EQ(coquic::quic::test::stream_payloads_from(fin_received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(fin_received)[0],
              (coquic::quic::test::StreamPayload{0, "", true}));
}

TEST(QuicCoreTest, ResetStreamLocalCommandEmitsPeerResetEffect) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto reset = client.advance(
        coquic::quic::QuicCoreResetStream{
            .stream_id = 0,
            .application_error_code = 7,
        },
        coquic::quic::test::test_time(1));

    EXPECT_FALSE(reset.local_error.has_value());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(reset).empty());

    const auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        reset, server, coquic::quic::test::test_time(2));

    ASSERT_EQ(coquic::quic::test::peer_resets_from(received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::peer_resets_from(received)[0].stream_id, 0u);
    EXPECT_EQ(coquic::quic::test::peer_resets_from(received)[0].application_error_code, 7u);
    EXPECT_EQ(coquic::quic::test::peer_resets_from(received)[0].final_size, 0u);
    EXPECT_FALSE(server.has_failed());
}

TEST(QuicCoreTest, ResetStreamLocalCommandRejectsReceiveOnlyStreams) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());

    const auto result = client.advance(
        coquic::quic::QuicCoreResetStream{
            .stream_id = 3,
            .application_error_code = 7,
        },
        coquic::quic::test::test_time());

    expect_local_error(result, coquic::quic::QuicCoreLocalErrorCode::invalid_stream_direction, 3);
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(result).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, StopSendingLocalCommandEmitsPeerStopEffect) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto open = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 3,
            .bytes = coquic::quic::test::bytes_from_string("hello"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    const auto opened = coquic::quic::test::relay_send_datagrams_to_peer(
        open, client, coquic::quic::test::test_time(2));
    ASSERT_EQ(coquic::quic::test::stream_payloads_from(opened).size(), 1u);

    const auto stop = client.advance(
        coquic::quic::QuicCoreStopSending{
            .stream_id = 3,
            .application_error_code = 11,
        },
        coquic::quic::test::test_time(3));

    EXPECT_FALSE(stop.local_error.has_value());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(stop).empty());

    const auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        stop, server, coquic::quic::test::test_time(4));

    ASSERT_EQ(coquic::quic::test::peer_stops_from(received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::peer_stops_from(received)[0].stream_id, 3u);
    EXPECT_EQ(coquic::quic::test::peer_stops_from(received)[0].application_error_code, 11u);
    EXPECT_FALSE(server.has_failed());
}

TEST(QuicCoreTest, StopSendingLocalCommandRejectsSendOnlyStreams) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());

    const auto result = client.advance(
        coquic::quic::QuicCoreStopSending{
            .stream_id = 2,
            .application_error_code = 7,
        },
        coquic::quic::test::test_time());

    expect_local_error(result, coquic::quic::QuicCoreLocalErrorCode::invalid_stream_direction, 2);
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(result).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, PeerStopSendingQueuesAutomaticReset) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto sent = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("abc"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    const auto delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        sent, server, coquic::quic::test::test_time(2));
    ASSERT_EQ(coquic::quic::test::stream_payloads_from(delivered).size(), 1u);

    const auto stop = server.advance(
        coquic::quic::QuicCoreStopSending{
            .stream_id = 0,
            .application_error_code = 19,
        },
        coquic::quic::test::test_time(3));
    const auto client_result = coquic::quic::test::relay_send_datagrams_to_peer(
        stop, client, coquic::quic::test::test_time(4));

    ASSERT_EQ(coquic::quic::test::peer_stops_from(client_result).size(), 1u);
    EXPECT_EQ(coquic::quic::test::peer_stops_from(client_result)[0].stream_id, 0u);
    EXPECT_EQ(coquic::quic::test::peer_stops_from(client_result)[0].application_error_code, 19u);
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(client_result).empty());

    const auto server_result = coquic::quic::test::relay_send_datagrams_to_peer(
        client_result, server, coquic::quic::test::test_time(5));
    ASSERT_EQ(coquic::quic::test::peer_resets_from(server_result).size(), 1u);
    EXPECT_EQ(coquic::quic::test::peer_resets_from(server_result)[0].stream_id, 0u);
    EXPECT_EQ(coquic::quic::test::peer_resets_from(server_result)[0].application_error_code, 19u);
    EXPECT_EQ(coquic::quic::test::peer_resets_from(server_result)[0].final_size, 3u);
}

TEST(QuicCoreTest, InboundResetStreamFailsForSendOnlyStream) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::ResetStreamFrame{
                        .stream_id = 2,
                        .application_protocol_error_code = 7,
                        .final_size = 0,
                    }});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, InboundStreamDataIsIgnoredAfterPeerResetStream) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto out_of_order =
        coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            connection,
            {coquic::quic::test::make_inbound_application_stream_frame("lo", 3, 0, false)});
    EXPECT_TRUE(out_of_order);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    const auto reset = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::ResetStreamFrame{
                        .stream_id = 0,
                        .application_protocol_error_code = 7,
                        .final_size = 5,
                    }});
    EXPECT_TRUE(reset);
    EXPECT_FALSE(connection.has_failed());

    const auto peer_reset = connection.take_peer_reset_stream();
    ASSERT_TRUE(peer_reset.has_value());
    if (!peer_reset.has_value()) {
        return;
    }
    EXPECT_EQ(peer_reset.value().stream_id, 0u);
    EXPECT_EQ(peer_reset.value().final_size, 5u);
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    const auto delayed = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::test::make_inbound_application_stream_frame("hel", 0, 0, false)});
    EXPECT_TRUE(delayed);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());
}

TEST(QuicCoreTest, InboundStopSendingFailsForReceiveOnlyStream) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::StopSendingFrame{
                        .stream_id = 3,
                        .application_protocol_error_code = 9,
                    }});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, LostResetStreamIsReEmitted) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection
                    .queue_stream_reset({
                        .stream_id = 0,
                        .application_error_code = 7,
                    })
                    .has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    ASSERT_EQ(connection.application_space_.sent_packets.size(), 1u);
    const auto first_packet = connection.application_space_.sent_packets.begin()->second;
    ASSERT_EQ(first_packet.reset_stream_frames.size(), 1u);

    connection.mark_lost_packet(connection.application_space_, first_packet);

    const auto second_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(second_datagram.empty());
    const auto packets = decode_sender_datagram(connection, second_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_reset = false;
    for (const auto &frame : application->frames) {
        saw_reset = saw_reset || std::holds_alternative<coquic::quic::ResetStreamFrame>(frame);
    }
    EXPECT_TRUE(saw_reset);
}

TEST(QuicCoreTest, LostStopSendingIsReEmitted) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("a", 0, 3)}));
    ASSERT_TRUE(connection
                    .queue_stop_sending({
                        .stream_id = 3,
                        .application_error_code = 11,
                    })
                    .has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    ASSERT_EQ(connection.application_space_.sent_packets.size(), 1u);
    const auto first_packet = connection.application_space_.sent_packets.begin()->second;
    ASSERT_EQ(first_packet.stop_sending_frames.size(), 1u);

    connection.mark_lost_packet(connection.application_space_, first_packet);

    const auto second_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(second_datagram.empty());
    const auto packets = decode_sender_datagram(connection, second_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_stop = false;
    for (const auto &frame : application->frames) {
        saw_stop = saw_stop || std::holds_alternative<coquic::quic::StopSendingFrame>(frame);
    }
    EXPECT_TRUE(saw_stop);
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

TEST(QuicCoreTest, HandshakeRecoversWhenInitialFlightIsDropped) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto dropped =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    EXPECT_TRUE(dropped.next_wakeup.has_value());

    const auto dropped_by_network = coquic::quic::test::relay_send_datagrams_to_peer_except(
        dropped, std::array<std::size_t, 1>{0}, server, coquic::quic::test::test_time(1));
    EXPECT_TRUE(dropped_by_network.effects.empty());

    const auto retry =
        coquic::quic::test::drive_earliest_next_wakeup(client, {dropped.next_wakeup});
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(retry).empty());

    auto to_client = coquic::quic::test::relay_send_datagrams_to_peer(
        retry, server, coquic::quic::test::test_time(2));
    auto to_server = coquic::quic::test::relay_send_datagrams_to_peer(
        to_client, client, coquic::quic::test::test_time(3));

    for (int i = 0; i < 16 && !(client.is_handshake_complete() && server.is_handshake_complete());
         ++i) {
        to_client = coquic::quic::test::relay_send_datagrams_to_peer(
            to_server, server, coquic::quic::test::test_time(4 + i * 2));
        if (client.is_handshake_complete() && server.is_handshake_complete()) {
            break;
        }

        to_server = coquic::quic::test::relay_send_datagrams_to_peer(
            to_client, client, coquic::quic::test::test_time(5 + i * 2));
    }

    EXPECT_FALSE(client.has_failed());
    EXPECT_FALSE(server.has_failed());
    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
}

TEST(QuicCoreTest, ApplicationDataIsRetransmittedAfterLoss) {
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
            .bytes = coquic::quic::test::bytes_from_string("probe"),
        },
        coquic::quic::test::test_time(4));
    EXPECT_TRUE(sent.next_wakeup.has_value());

    const auto dropped = coquic::quic::test::relay_send_datagrams_to_peer_except(
        sent, std::array<std::size_t, 1>{0}, server, coquic::quic::test::test_time(5));
    EXPECT_TRUE(dropped.effects.empty());

    const auto retry = coquic::quic::test::drive_earliest_next_wakeup(client, {sent.next_wakeup});
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(retry).empty());

    const auto delivered = coquic::quic::test::relay_nth_send_datagram_to_peer(
        retry, 0, server, coquic::quic::test::test_time(6));
    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(delivered)),
              "probe");

    const auto acked = coquic::quic::test::relay_send_datagrams_to_peer(
        delivered, client, coquic::quic::test::test_time(7));
    EXPECT_FALSE(client.has_failed());
    EXPECT_FALSE(server.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(acked).empty());
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

    const auto server_after_client_probe = coquic::quic::test::relay_send_datagrams_to_peer(
        client_before_confirmation, server, coquic::quic::test::test_time(3));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(server_after_client_probe).empty());

    const auto client_after_ack = coquic::quic::test::relay_send_datagrams_to_peer(
        server_after_client_probe, client, coquic::quic::test::test_time(4));
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(client_after_ack).empty());

    const auto client_after_confirmation = client.advance(
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
    const auto probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(probe_datagram.empty());

    const auto packets = decode_sender_datagram(connection, probe_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }
    EXPECT_TRUE(saw_stream);
}

TEST(QuicCoreTest, ServerHandshakeCompletionQueuesHandshakeDoneFrame) {
    auto connection = make_connected_server_connection();
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;

    EXPECT_EQ(connection.handshake_done_state_, coquic::quic::StreamControlFrameState::pending);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    bool saw_handshake_done = false;
    for (const auto &packet : decode_sender_datagram(connection, datagram)) {
        const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
        if (one_rtt == nullptr) {
            continue;
        }

        for (const auto &frame : one_rtt->frames) {
            if (std::holds_alternative<coquic::quic::HandshakeDoneFrame>(frame)) {
                saw_handshake_done = true;
            }
        }
    }

    EXPECT_TRUE(saw_handshake_done);
    EXPECT_EQ(connection.handshake_done_state_, coquic::quic::StreamControlFrameState::sent);

    connection.arm_pto_probe(coquic::quic::test::test_time(1000));
    ASSERT_TRUE(connection.application_space_.pending_probe_packet.has_value());
    const auto &pending_probe_packet =
        optional_ref_or_terminate(connection.application_space_.pending_probe_packet);
    EXPECT_TRUE(pending_probe_packet.has_handshake_done);
}

TEST(QuicCoreTest, InboundHandshakeDoneQueuesApplicationAck) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;
    connection.application_space_.pending_ack_deadline = std::nullopt;

    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::HandshakeDoneFrame{}}, /*packet_number=*/1));

    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_TRUE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_TRUE(connection.handshake_confirmed_);
}

TEST(QuicCoreTest, HandshakePacketAcceptsTransportConnectionCloseFrame) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::connected;

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .version = 1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = {std::byte{0x44}},
            .packet_number_length = 2,
            .packet_number = 0,
            .frames =
                {
                    coquic::quic::TransportConnectionCloseFrame{
                        .error_code = 0,
                        .frame_type = 0,
                    },
                },
        },
        coquic::quic::test::test_time());

    EXPECT_TRUE(processed.has_value());
}

TEST(QuicCoreTest, OneRttPacketTerminatesOnConnectionCloseFrames) {
    auto connection = make_connected_client_connection();

    EXPECT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::TransportConnectionCloseFrame{
            .error_code = 0,
            .frame_type = 0,
        }},
        /*packet_number=*/1));
    EXPECT_TRUE(connection.has_failed());
    EXPECT_EQ(connection.next_wakeup(), std::nullopt);

    connection = make_connected_client_connection();
    EXPECT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::ApplicationConnectionCloseFrame{
            .error_code = 0,
        }},
        /*packet_number=*/2));
    EXPECT_TRUE(connection.has_failed());
    EXPECT_EQ(connection.next_wakeup(), std::nullopt);
}

TEST(QuicCoreTest, AckProcessingClearsOutstandingDataAndRemovesWakeup) {
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
    ASSERT_FALSE(client.connection_->application_space_.sent_packets.empty());
    ASSERT_TRUE(client.connection_->streams_.contains(0));
    EXPECT_TRUE(client.connection_->streams_.at(0).has_outstanding_send());

    const auto server_step = coquic::quic::test::relay_send_datagrams_to_peer(
        sent, server, coquic::quic::test::test_time(5));
    const auto client_step = coquic::quic::test::relay_send_datagrams_to_peer(
        server_step, client, coquic::quic::test::test_time(6));

    EXPECT_FALSE(client.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(client_step).empty());
    EXPECT_TRUE(client.connection_->application_space_.sent_packets.empty());
    EXPECT_FALSE(client.connection_->streams_.at(0).has_pending_send());
    EXPECT_FALSE(client.connection_->streams_.at(0).has_outstanding_send());
    EXPECT_EQ(client_step.next_wakeup, std::nullopt);
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

    const auto processed = connection.process_inbound_ack(
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

    const auto processed = connection.process_inbound_ack(
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

    const auto first = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 2,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(20), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().latest_rtt, std::nullopt);

    const auto second = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 2,
            .first_ack_range = 1,
        },
        coquic::quic::test::test_time(70), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
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

TEST(QuicCoreTest, DiscardingInitialPacketSpaceResetsPtoBackoff) {
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

    connection.discard_initial_packet_space();

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

    const auto processed = connection.process_inbound_ack(
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

TEST(QuicCoreTest, DetectLostPacketsMarksCryptoRangesLostAndRebuildsRecoveryState) {
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

    EXPECT_TRUE(connection.initial_space_.sent_packets.empty());
    EXPECT_TRUE(connection.initial_space_.send_crypto.has_pending_data());
    EXPECT_EQ(connection.initial_space_.recovery.largest_acked_packet_number(),
              std::optional<std::uint64_t>{5});
    EXPECT_TRUE(connection.initial_space_.recovery.sent_packets_.empty());
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

    EXPECT_EQ(connection.initial_space_.sent_packets.size(), 3u);
}

TEST(QuicCoreTest, RebuildRecoveryPreservesLargestAckedAndOutstandingPackets) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.recovery.largest_acked_packet_number_ = 9;
    connection.handshake_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(8);
    connection.handshake_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(8);
    connection.handshake_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(8);
    connection.handshake_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(4);

    connection.handshake_space_.sent_packets.emplace(
        4, coquic::quic::SentPacketRecord{
               .packet_number = 4,
               .sent_time = coquic::quic::test::test_time(1),
               .ack_eliciting = true,
               .in_flight = true,
           });
    connection.handshake_space_.sent_packets.emplace(
        7, coquic::quic::SentPacketRecord{
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
    EXPECT_EQ(connection.handshake_space_.recovery.sent_packets_.size(), 2u);
    EXPECT_TRUE(connection.handshake_space_.recovery.sent_packets_.contains(4));
    EXPECT_TRUE(connection.handshake_space_.recovery.sent_packets_.contains(7));
}

TEST(QuicCoreTest, RebuildRecoveryHandlesPacketSpacesWithoutAcknowledgments) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.application_space_.sent_packets.emplace(
        1, coquic::quic::SentPacketRecord{
               .packet_number = 1,
               .sent_time = coquic::quic::test::test_time(0),
               .ack_eliciting = true,
               .in_flight = true,
           });

    connection.rebuild_recovery(connection.application_space_);

    EXPECT_EQ(connection.application_space_.recovery.largest_acked_packet_number(), std::nullopt);
    EXPECT_TRUE(connection.application_space_.recovery.sent_packets_.contains(1));
}

TEST(QuicCoreTest, TimeoutRunsLossDetectionAndArmsPtoProbe) {
    auto connection = make_connected_client_connection();

    connection.initial_space_.recovery.largest_acked_packet_number_ = 5;
    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("lost"));
    const auto initial_ranges = connection.initial_space_.send_crypto.take_ranges(4);
    ASSERT_EQ(initial_ranges.size(), 1u);
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .crypto_ranges = initial_ranges,
                                 });

    connection.track_sent_packet(
        connection.application_space_,
        coquic::quic::SentPacketRecord{
            .packet_number = 3,
            .sent_time = coquic::quic::test::test_time(0),
            .ack_eliciting = true,
            .in_flight = true,
            .stream_fragments =
                {
                    coquic::quic::StreamFrameSendFragment{
                        .stream_id = 0,
                        .offset = 0,
                        .bytes = coquic::quic::test::bytes_from_string("pto"),
                        .fin = false,
                    },
                },
        });

    connection.on_timeout(coquic::quic::test::test_time(999));

    EXPECT_TRUE(connection.initial_space_.send_crypto.has_pending_data());
    if (!connection.application_space_.pending_probe_packet.has_value()) {
        GTEST_FAIL() << "expected pending application probe packet";
        return;
    }
    EXPECT_EQ(connection.application_space_.pending_probe_packet->packet_number, 3u);
}

TEST(QuicCoreTest, TimeoutBeforeLossAndPtoDeadlinesDoesNothing) {
    auto connection = make_connected_client_connection();
    connection.initial_space_.recovery.largest_acked_packet_number_ = 4;
    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });

    connection.on_timeout(coquic::quic::test::test_time(11));

    EXPECT_TRUE(connection.initial_space_.sent_packets.contains(1));
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
    EXPECT_EQ(connection.pto_count_, 0u);
}

TEST(QuicCoreTest, ServerProcessingHandshakePacketDiscardsInitialRecoveryState) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 1,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
            .packet_number = 0,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(connection.initial_space_.sent_packets.empty());
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_EQ(connection.initial_space_.pending_ack_deadline, std::nullopt);
}

TEST(QuicCoreTest, ArmPtoProbeReturnsWhenNoPacketSpaceIsDue) {
    auto connection = make_connected_client_connection();

    connection.arm_pto_probe(coquic::quic::test::test_time(10));

    EXPECT_EQ(connection.pto_count_, 0u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ApplicationPtoBypassesCongestionWindowWhenDataIsPending) {
    auto connection = make_connected_client_connection();
    const auto congestion_window = connection.congestion_controller_.congestion_window();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = congestion_window,
                                 });
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("queued"), false)
            .has_value());

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());
    const auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);
    const auto datagram = connection.drain_outbound_datagram(timeout);

    ASSERT_FALSE(datagram.empty());
    const auto stream_ids = application_stream_ids_from_datagram(connection, datagram);
    EXPECT_EQ(stream_ids, std::vector<std::uint64_t>({0u}));
}

TEST(QuicCoreTest, ApplicationPtoPrefersRetransmittableProbeOverFreshData) {
    auto connection = make_connected_client_connection();
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(32) * 1024u, std::byte{0x50});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::optional<std::uint64_t> first_sent_offset;
    std::uint64_t next_unsent_offset = 0;
    while (true) {
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        const auto packets = decode_sender_datagram(connection, datagram);
        ASSERT_EQ(packets.size(), 1u);
        const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
        ASSERT_NE(application, nullptr);

        for (const auto &frame : application->frames) {
            const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            ASSERT_TRUE(stream->offset.has_value());
            const auto stream_offset = optional_value_or_terminate(stream->offset);
            if (!first_sent_offset.has_value()) {
                first_sent_offset = stream_offset;
            }
            next_unsent_offset =
                stream_offset + static_cast<std::uint64_t>(stream->stream_data.size());
        }
    }

    ASSERT_TRUE(first_sent_offset.has_value());
    ASSERT_TRUE(connection.has_pending_application_send());

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());
    const auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);

    const auto &pending_probe_packet =
        optional_ref_or_terminate(connection.application_space_.pending_probe_packet);
    ASSERT_FALSE(pending_probe_packet.stream_fragments.empty());

    const auto probe_datagram = connection.drain_outbound_datagram(timeout);
    ASSERT_FALSE(probe_datagram.empty());

    const auto probe_packets = decode_sender_datagram(connection, probe_datagram);
    ASSERT_EQ(probe_packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&probe_packets[0]);
    ASSERT_NE(application, nullptr);

    std::vector<std::uint64_t> stream_offsets;
    for (const auto &frame : application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        stream_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    ASSERT_FALSE(stream_offsets.empty());
    EXPECT_EQ(stream_offsets.front(), optional_value_or_terminate(first_sent_offset));
    EXPECT_NE(stream_offsets.front(), next_unsent_offset);
}

TEST(QuicCoreTest, ApplicationPtoSkipsProbePacketsWhoseStreamDataWasAckedByRetransmission) {
    auto connection = make_connected_client_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    const auto payload = coquic::quic::test::bytes_from_string("hello probe");
    stream.send_buffer.append(payload);
    stream.send_buffer.mark_lost(/*offset=*/0, payload.size());

    const auto make_fragment = [&]() {
        return coquic::quic::StreamFrameSendFragment{
            .stream_id = 0,
            .offset = 0,
            .bytes = payload,
            .fin = false,
            .consumes_flow_control = false,
        };
    };

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 72,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = {make_fragment()},
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 73,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = {make_fragment()},
                                 });

    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = 73,
                                             .first_ack_range = 0,
                                         },
                                         coquic::quic::test::test_time(2),
                                         /*ack_delay_exponent=*/0,
                                         /*max_ack_delay_ms=*/0,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    const auto probe = connection.select_pto_probe(connection.application_space_);
    ASSERT_TRUE(probe.has_value());
    const auto &probe_packet = optional_ref_or_terminate(probe);
    EXPECT_TRUE(probe_packet.stream_fragments.empty());
    EXPECT_TRUE(probe_packet.has_ping);
    connection.application_space_.pending_probe_packet = probe;
}

TEST(QuicCoreTest, ApplicationPtoDoesNotResendFullyAckedPrefixOfPartiallyOutstandingFragment) {
    auto connection = make_connected_client_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    stream.flow_control.peer_max_stream_data = 5;
    stream.send_buffer.append(coquic::quic::test::bytes_from_string("hello"));
    stream.send_flow_control_committed = 5;

    const auto initial_fragments = stream.take_send_fragments(/*max_bytes=*/5);
    ASSERT_EQ(initial_fragments.size(), 1u);
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 72,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = initial_fragments,
                                 });
    connection.mark_lost_packet(connection.application_space_,
                                connection.application_space_.sent_packets.at(72));

    const auto retransmitted_prefix = stream.take_send_fragments(coquic::quic::StreamSendBudget{
        .packet_bytes = 2,
        .new_bytes = 0,
    });
    ASSERT_EQ(retransmitted_prefix.size(), 1u);
    EXPECT_EQ(retransmitted_prefix[0].offset, 0u);
    EXPECT_EQ(retransmitted_prefix[0].bytes, coquic::quic::test::bytes_from_string("he"));
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 73,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = retransmitted_prefix,
                                 });

    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = 73,
                                             .first_ack_range = 0,
                                         },
                                         coquic::quic::test::test_time(2),
                                         /*ack_delay_exponent=*/0,
                                         /*max_ack_delay_ms=*/0,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    const auto probe = connection.select_pto_probe(connection.application_space_);
    ASSERT_TRUE(probe.has_value());
    const auto &probe_packet = optional_ref_or_terminate(probe);
    EXPECT_TRUE(probe_packet.stream_fragments.empty());
    EXPECT_TRUE(probe_packet.has_ping);
    connection.application_space_.pending_probe_packet = probe;

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1000));
    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    std::vector<coquic::quic::StreamFrame> stream_frames;
    for (const auto &frame : application->frames) {
        if (const auto *stream_frame = std::get_if<coquic::quic::StreamFrame>(&frame)) {
            stream_frames.push_back(*stream_frame);
        }
    }

    ASSERT_EQ(stream_frames.size(), 1u);
    ASSERT_TRUE(stream_frames[0].offset.has_value());
    EXPECT_EQ(optional_value_or_terminate(stream_frames[0].offset), 2u);
    EXPECT_EQ(stream_frames[0].stream_data, coquic::quic::test::bytes_from_string("llo"));
}

TEST(QuicCoreTest, ArmPtoProbeDefersCryptoProbeWhenCryptoSendDataIsAlreadyPending) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hello"));

    connection.arm_pto_probe(coquic::quic::test::test_time(999));

    EXPECT_EQ(connection.pto_count_, 1u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ArmPtoProbeCoalescesHandshakeProbeWithInitialProbe) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });

    connection.arm_pto_probe(coquic::quic::test::test_time(1000));

    EXPECT_EQ(connection.pto_count_, 1u);
    EXPECT_TRUE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ArmPtoProbeCoalescesHandshakeProbeWhenInitialCryptoIsPending) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hello"));

    connection.arm_pto_probe(coquic::quic::test::test_time(999));

    EXPECT_EQ(connection.pto_count_, 1u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, SelectPtoProbeSkipsPacketsThatCannotBeProbed) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    coquic::quic::PacketSpaceState packet_space;
    packet_space.sent_packets.emplace(0, coquic::quic::SentPacketRecord{
                                             .packet_number = 0,
                                             .sent_time = coquic::quic::test::test_time(0),
                                             .ack_eliciting = false,
                                             .in_flight = false,
                                             .has_ping = true,
                                         });
    packet_space.sent_packets.emplace(1, coquic::quic::SentPacketRecord{
                                             .packet_number = 1,
                                             .sent_time = coquic::quic::test::test_time(0),
                                             .ack_eliciting = true,
                                             .in_flight = false,
                                             .has_ping = true,
                                         });
    packet_space.sent_packets.emplace(2, coquic::quic::SentPacketRecord{
                                             .packet_number = 2,
                                             .sent_time = coquic::quic::test::test_time(0),
                                             .ack_eliciting = true,
                                             .in_flight = true,
                                             .has_ping = true,
                                         });

    const auto probe = connection.select_pto_probe(packet_space);

    if (!probe.has_value()) {
        GTEST_FAIL() << "expected PTO probe";
        return;
    }
    EXPECT_EQ(probe->packet_number, 2u);
    EXPECT_TRUE(probe->has_ping);
}

TEST(QuicCoreTest, AckDeadlinePrefersEarlierLaterPacketSpaceDeadline) {
    auto connection = make_connected_client_connection();
    connection.initial_space_.pending_ack_deadline = coquic::quic::test::test_time(8);
    connection.handshake_space_.pending_ack_deadline = coquic::quic::test::test_time(3);
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(5);

    EXPECT_EQ(connection.ack_deadline(), std::optional{coquic::quic::test::test_time(3)});
}

TEST(QuicCoreTest, LossDeadlineUsesEarliestEligiblePacketWithinPacketSpace) {
    auto connection = make_connected_client_connection();
    connection.initial_space_.recovery.largest_acked_packet_number_ = 10;
    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);

    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(5),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });

    EXPECT_EQ(connection.loss_deadline(), std::optional{coquic::quic::test::test_time(12)});
}

TEST(QuicCoreTest, DeadlineHelpersPreferEarlierCandidatesAndSkipIneligiblePackets) {
    auto connection = make_connected_client_connection();
    connection.initial_space_.recovery.largest_acked_packet_number_ = 6;
    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(5),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(10),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 4,
                                     .sent_time = coquic::quic::test::test_time(2),
                                     .ack_eliciting = true,
                                     .in_flight = false,
                                 });

    const auto loss_deadline = connection.loss_deadline();
    const auto pto_deadline = connection.pto_deadline();

    if (!loss_deadline.has_value() || !pto_deadline.has_value()) {
        GTEST_FAIL() << "expected loss and PTO deadlines";
        return;
    }
    EXPECT_LT(*loss_deadline, *pto_deadline);
}

TEST(QuicCoreTest, HandshakeConfirmationSkipsDiscardedHandshakePacketSpaceWhenProbing) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 10,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 11,
                                     .sent_time = coquic::quic::test::test_time(-1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 20,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });

    connection.confirm_handshake();
    connection.arm_pto_probe(coquic::quic::test::test_time(1000));

    EXPECT_EQ(connection.pto_count_, 1u);
    if (!connection.application_space_.pending_probe_packet.has_value()) {
        GTEST_FAIL() << "expected application PTO probe packet";
        return;
    }
    EXPECT_EQ(connection.application_space_.pending_probe_packet->packet_number, 20u);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ArmPtoProbeSkipsPacketSpacesWhoseDeadlineHasNotArrived) {
    auto connection = make_connected_client_connection();
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(10),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });

    connection.arm_pto_probe(coquic::quic::test::test_time(1000));

    EXPECT_EQ(connection.pto_count_, 0u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ReceivingAckElicitingPacketsSchedulesAckResponse) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ack-me"),
        },
        coquic::quic::test::test_time(1));
    const auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(1));
    const auto response_datagrams = coquic::quic::test::send_datagrams_from(received);

    ASSERT_FALSE(response_datagrams.empty());

    bool saw_ack = false;
    for (const auto &datagram : response_datagrams) {
        const auto decoded = coquic::quic::deserialize_protected_datagram(
            datagram,
            coquic::quic::DeserializeProtectionContext{
                .peer_role = coquic::quic::EndpointRole::server,
                .client_initial_destination_connection_id =
                    client.connection_->client_initial_destination_connection_id(),
                .handshake_secret = client.connection_->handshake_space_.read_secret,
                .one_rtt_secret = client.connection_->application_space_.read_secret,
                .largest_authenticated_initial_packet_number =
                    client.connection_->initial_space_.largest_authenticated_packet_number,
                .largest_authenticated_handshake_packet_number =
                    client.connection_->handshake_space_.largest_authenticated_packet_number,
                .largest_authenticated_application_packet_number =
                    client.connection_->application_space_.largest_authenticated_packet_number,
                .one_rtt_destination_connection_id_length =
                    client.connection_->config_.source_connection_id.size(),
            });
        ASSERT_TRUE(decoded.has_value());

        for (const auto &packet : decoded.value()) {
            const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (one_rtt == nullptr) {
                continue;
            }

            for (const auto &frame : one_rtt->frames) {
                if (std::holds_alternative<coquic::quic::AckFrame>(frame)) {
                    saw_ack = true;
                }
            }
        }
    }

    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, ReorderedApplicationPacketsAreDeliveredOnceContiguous) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto first_send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ping"),
        },
        coquic::quic::test::test_time(1));
    const auto second_send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("pong"),
        },
        coquic::quic::test::test_time(2));

    auto datagrams = coquic::quic::test::send_datagrams_from(first_send);
    const auto second_datagrams = coquic::quic::test::send_datagrams_from(second_send);
    datagrams.insert(datagrams.end(), second_datagrams.begin(), second_datagrams.end());
    ASSERT_EQ(datagrams.size(), 2u);

    const auto reordered = coquic::quic::test::relay_datagrams_to_peer(
        datagrams, std::array<std::size_t, 1>{1}, server, coquic::quic::test::test_time(3));
    EXPECT_FALSE(server.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(reordered).empty());

    const auto contiguous = coquic::quic::test::relay_datagrams_to_peer(
        datagrams, std::array<std::size_t, 1>{0}, server, coquic::quic::test::test_time(4));
    EXPECT_FALSE(server.has_failed());
    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(contiguous)),
              "pingpong");
}

TEST(QuicCoreTest, InboundApplicationAckRetiresOwnedSendRanges) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("retire-me"),
        },
        coquic::quic::test::test_time(1));

    ASSERT_FALSE(client.connection_->application_space_.sent_packets.empty());
    ASSERT_TRUE(client.connection_->streams_.contains(0));
    EXPECT_TRUE(client.connection_->streams_.at(0).has_outstanding_send());

    const auto server_step = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(2));
    const auto client_step = coquic::quic::test::relay_send_datagrams_to_peer(
        server_step, client, coquic::quic::test::test_time(3));

    EXPECT_FALSE(client.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(client_step).empty());
    EXPECT_TRUE(client.connection_->application_space_.sent_packets.empty());
    EXPECT_FALSE(client.connection_->streams_.at(0).has_pending_send());
    EXPECT_FALSE(client.connection_->streams_.at(0).has_outstanding_send());
}

TEST(QuicCoreTest, AckOnlyApplicationResponsesAreNotRetainedAsOutstandingPackets) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto server_send = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ack-me"),
        },
        coquic::quic::test::test_time(1));

    const auto client_step = coquic::quic::test::relay_send_datagrams_to_peer(
        server_send, client, coquic::quic::test::test_time(2));

    EXPECT_FALSE(client.has_failed());
    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(client_step)),
              "ack-me");
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(client_step).empty());
    EXPECT_TRUE(client.connection_->application_space_.sent_packets.empty());
    EXPECT_TRUE(client.connection_->application_space_.recovery.sent_packets_.empty());
}

TEST(QuicCoreTest, LargeAckOnlyHistoryEmitsTrimmedAckDatagram) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    for (std::uint64_t packet_number = 0; packet_number < 4096; ++packet_number) {
        client.connection_->application_space_.received_packets.record_received(
            packet_number * 3, true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
    }

    const auto datagram =
        client.connection_->drain_outbound_datagram(coquic::quic::test::test_time(5000));

    EXPECT_FALSE(client.connection_->has_failed());
    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        datagram,
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                client.connection_->client_initial_destination_connection_id(),
            .handshake_secret = client.connection_->handshake_space_.write_secret,
            .one_rtt_secret = client.connection_->application_space_.write_secret,
            .largest_authenticated_initial_packet_number =
                server.connection_->initial_space_.largest_authenticated_packet_number,
            .largest_authenticated_handshake_packet_number =
                server.connection_->handshake_space_.largest_authenticated_packet_number,
            .largest_authenticated_application_packet_number =
                server.connection_->application_space_.largest_authenticated_packet_number,
            .one_rtt_destination_connection_id_length =
                server.connection_->config_.source_connection_id.size(),
        });
    ASSERT_TRUE(decoded.has_value());

    bool saw_ack = false;
    for (const auto &packet : decoded.value()) {
        const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
        if (one_rtt == nullptr) {
            continue;
        }

        for (const auto &frame : one_rtt->frames) {
            if (std::holds_alternative<coquic::quic::AckFrame>(frame)) {
                saw_ack = true;
            }
        }
    }

    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, InitialProbePacketCanRetransmitCryptoRanges) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 2,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 7,
                    .bytes = coquic::quic::test::bytes_from_string("hi"),
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets[0]);
    ASSERT_NE(initial, nullptr);

    bool saw_crypto = false;
    for (const auto &frame : initial->frames) {
        const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame);
        if (crypto == nullptr) {
            continue;
        }

        saw_crypto = true;
        EXPECT_EQ(crypto->offset, 7u);
        EXPECT_EQ(crypto->crypto_data, coquic::quic::test::bytes_from_string("hi"));
    }

    EXPECT_TRUE(saw_crypto);
    ASSERT_EQ(connection.initial_space_.sent_packets.size(), 1u);
    EXPECT_EQ(connection.initial_space_.sent_packets.begin()->second.crypto_ranges.size(), 1u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, InitialRetransmissionsKeepOriginalDestinationConnectionId) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.peer_source_connection_id_ = {
        std::byte{0xf1},
        std::byte{0xfd},
        std::byte{0x54},
        std::byte{0xd6},
    };
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 4,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = std::vector<std::byte>(64, std::byte{0x61}),
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets[0]);
    ASSERT_NE(initial, nullptr);
    EXPECT_EQ(initial->destination_connection_id,
              connection.client_initial_destination_connection_id());
    EXPECT_EQ(initial->destination_connection_id.size(), 8u);
}

TEST(QuicCoreTest, ServerInitialPacketsUsePeerSourceConnectionIdAsDestination) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.peer_source_connection_id_ = {
        std::byte{0xc1}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x3d},
    };
    connection.client_initial_destination_connection_id_ = {
        std::byte{0x83}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x3c},
    };
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 5,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = std::vector<std::byte>(64, std::byte{0x62}),
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets[0]);
    ASSERT_NE(initial, nullptr);
    EXPECT_EQ(initial->destination_connection_id, connection.peer_source_connection_id_.value());
}

TEST(QuicCoreTest, InitialProbePacketCanFallbackToPing) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 3,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    static_cast<void>(datagram);
    ASSERT_EQ(connection.initial_space_.sent_packets.size(), 1u);
    EXPECT_TRUE(connection.initial_space_.sent_packets.begin()->second.has_ping);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, InitialSendPrefersFreshCryptoRangesOverStoredProbeSnapshot) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("live"));
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 30,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 9,
                    .bytes = coquic::quic::test::bytes_from_string("old"),
                },
            },
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(connection.initial_space_.sent_packets.size(), 1u);
    const auto &sent_packet = connection.initial_space_.sent_packets.begin()->second;
    ASSERT_EQ(sent_packet.crypto_ranges.size(), 1u);
    EXPECT_EQ(sent_packet.crypto_ranges[0].offset, 0u);
    EXPECT_EQ(sent_packet.crypto_ranges[0].bytes, coquic::quic::test::bytes_from_string("live"));
    EXPECT_FALSE(sent_packet.has_ping);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, HandshakeProbePacketCanRetransmitCryptoRanges) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 4,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 11,
                    .bytes = coquic::quic::test::bytes_from_string("hs"),
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets[0]);
    ASSERT_NE(handshake, nullptr);
    ASSERT_EQ(handshake->frames.size(), 1u);
    const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&handshake->frames[0]);
    ASSERT_NE(crypto, nullptr);
    EXPECT_EQ(crypto->offset, 11u);
    ASSERT_EQ(connection.handshake_space_.sent_packets.size(), 1u);
    EXPECT_EQ(connection.handshake_space_.sent_packets.begin()->second.crypto_ranges.size(), 1u);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, HandshakeProbePacketCanFallbackToPing) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 5,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    static_cast<void>(datagram);
    ASSERT_EQ(connection.handshake_space_.sent_packets.size(), 1u);
    EXPECT_TRUE(connection.handshake_space_.sent_packets.begin()->second.has_ping);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, HandshakeSendPrefersFreshCryptoRangesOverStoredProbeSnapshot) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.send_crypto.append(coquic::quic::test::bytes_from_string("live"));
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 31,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 9,
                    .bytes = coquic::quic::test::bytes_from_string("old"),
                },
            },
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(connection.handshake_space_.sent_packets.size(), 1u);
    const auto &sent_packet = connection.handshake_space_.sent_packets.begin()->second;
    ASSERT_EQ(sent_packet.crypto_ranges.size(), 1u);
    EXPECT_EQ(sent_packet.crypto_ranges[0].offset, 0u);
    EXPECT_EQ(sent_packet.crypto_ranges[0].bytes, coquic::quic::test::bytes_from_string("live"));
    EXPECT_FALSE(sent_packet.has_ping);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, HandshakePacketSerializationFailureMarksConnectionFailed) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 6,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationProbePacketCanIncludeAckAndPing) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/12, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 7,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_ping = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_ping);
    EXPECT_EQ(connection.application_space_.pending_ack_deadline, std::nullopt);
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
    ASSERT_EQ(connection.application_space_.sent_packets.size(), 1u);
    EXPECT_TRUE(connection.application_space_.sent_packets.begin()->second.has_ping);
}

TEST(QuicCoreTest, ApplicationProbePathTrimsProbePayloadWhenAckWouldOverflowDatagram) {
    auto connection = make_connected_client_connection();
    for (std::uint64_t packet_number = 0; packet_number < 4096; ++packet_number) {
        connection.application_space_.received_packets.record_received(
            packet_number * 3, true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
    }
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 8,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1200, std::byte{0x41}),
                    .fin = false,
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(5000));

    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    const auto *stream = std::get_if<coquic::quic::StreamFrame>(&application->frames.back());
    ASSERT_NE(stream, nullptr);
    EXPECT_LT(stream->stream_data.size(), 1200u);
}

TEST(QuicCoreTest, ApplicationProbePathTrimsOversizeProbePayloadToFitDatagramBudget) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 9,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1200, std::byte{0x42}),
                    .fin = false,
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        saw_stream = true;
        EXPECT_LT(stream->stream_data.size(), 1200u);
    }
    EXPECT_TRUE(saw_stream);
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenPacketSerializationFails) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 10,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendPathFailsWhenAckCandidateSerializationFails) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/15, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("data"), false)
            .has_value());
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendPathFailsWhenPacketSerializationFails) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("data"), false)
            .has_value());
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendPathFailsWhenFinalPacketSerializationFails) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("data"), false)
            .has_value());
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new, 2);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendPathFailsWhenTrimmedFinOnlyPacketReserializationFails) {
    auto connection = make_connected_client_connection();
    connection.stream_open_limits_.peer_max_bidirectional = 2048;
    for (std::uint64_t stream_index = 0; stream_index < 2048; ++stream_index) {
        ASSERT_TRUE(connection.queue_stream_send(stream_index * 4, {}, true).has_value());
    }
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new, 12);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendClearsPendingProbeAfterSendingStreamData) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 10,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
            .has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
    ASSERT_EQ(connection.application_space_.sent_packets.size(), 1u);
    EXPECT_FALSE(
        connection.application_space_.sent_packets.begin()->second.stream_fragments.empty());
}

TEST(QuicCoreTest, ApplicationSendBudgetsManyFinOnlyStreamsWithinDatagramLimit) {
    auto connection = make_connected_client_connection();
    connection.stream_open_limits_.peer_max_bidirectional = 512;
    for (std::uint64_t stream_index = 0; stream_index < 512; ++stream_index) {
        ASSERT_TRUE(connection.queue_stream_send(stream_index * 4, {}, true).has_value());
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());
}

TEST(QuicCoreTest, ApplicationSendFailsWhenControlFramesAloneExceedDatagramBudget) {
    auto connection = make_connected_client_connection();
    for (std::uint64_t stream_index = 0; stream_index < 256; ++stream_index) {
        const auto stream_id = stream_index * 4;
        auto &stream = connection.streams_
                           .emplace(stream_id, coquic::quic::make_implicit_stream_state(
                                                   stream_id, connection.config_.role))
                           .first->second;
        stream.pending_reset_frame = coquic::quic::ResetStreamFrame{
            .stream_id = stream_id,
            .application_protocol_error_code = 1,
            .final_size = 0,
        };
        stream.reset_state = coquic::quic::StreamControlFrameState::pending;
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendWithLargeAckStateDoesNotFailPacketBudgetSearch) {
    auto connection = make_connected_server_connection();
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(4000), std::byte{0x46});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    for (std::uint64_t packet_number = 0; packet_number < 1200; packet_number += 2) {
        connection.application_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }
    ASSERT_TRUE(connection.application_space_.received_packets.has_ack_to_send());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_stream);
    EXPECT_TRUE(saw_ack || connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ExpiredApplicationAckDeadlineSendsAckBeforeMoreStreamData) {
    auto connection = make_connected_server_connection();
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(8192), std::byte{0x53});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    for (std::uint64_t packet_number = 0; packet_number < 1200; packet_number += 2) {
        connection.application_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

    connection.on_timeout(coquic::quic::test::test_time(1));
    const auto ack_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(ack_datagram.empty());
    const auto ack_packets = decode_sender_datagram(connection, ack_datagram);
    ASSERT_EQ(ack_packets.size(), 1u);
    const auto *ack_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&ack_packets.front());
    ASSERT_NE(ack_application, nullptr);

    bool saw_ack = false;
    bool saw_stream = false;
    for (const auto &frame : ack_application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_FALSE(saw_stream);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_EQ(connection.application_space_.pending_ack_deadline, std::nullopt);
    EXPECT_FALSE(connection.application_space_.force_ack_send);

    const auto data_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(data_datagram.empty());
    EXPECT_FALSE(application_stream_ids_from_datagram(connection, data_datagram).empty());
}

TEST(QuicCoreTest, NewDataSchedulingRoundsRobinAcrossSendableStreams) {
    auto connection = make_connected_client_connection();
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(2000), std::byte{0x61});

    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(4, payload, false).has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto stream_ids = application_stream_ids_from_datagram(connection, datagram);
    EXPECT_NE(std::find(stream_ids.begin(), stream_ids.end(), 0), stream_ids.end());
    EXPECT_NE(std::find(stream_ids.begin(), stream_ids.end(), 4), stream_ids.end());
}

TEST(QuicCoreTest, RetransmissionPreservesStreamIdentityAcrossMultipleStreams) {
    auto connection = make_connected_client_connection();
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(2000), std::byte{0x62});

    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(4, payload, false).has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    ASSERT_EQ(connection.application_space_.sent_packets.size(), 1u);
    const auto first_packet = connection.application_space_.sent_packets.begin()->second;

    connection.mark_lost_packet(connection.application_space_, first_packet);

    const auto repaired_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(repaired_datagram.empty());

    const auto stream_ids = application_stream_ids_from_datagram(connection, repaired_datagram);
    EXPECT_NE(std::find(stream_ids.begin(), stream_ids.end(), 0), stream_ids.end());
    EXPECT_NE(std::find(stream_ids.begin(), stream_ids.end(), 4), stream_ids.end());
}

TEST(QuicCoreTest, ApplicationSendRetransmitsLostDataWithoutConnectionCredit) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
            .has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    ASSERT_EQ(connection.application_space_.sent_packets.size(), 1u);
    const auto first_packet = connection.application_space_.sent_packets.begin()->second;

    connection.mark_lost_packet(connection.application_space_, first_packet);
    connection.connection_flow_control_.peer_max_data =
        connection.connection_flow_control_.highest_sent;

    const auto retransmitted = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(retransmitted.empty());
    const auto packets = decode_sender_datagram(connection, retransmitted);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        saw_stream = true;
        EXPECT_EQ(stream->stream_id, 0u);
        EXPECT_EQ(coquic::quic::test::string_from_bytes(stream->stream_data), "hello");
    }

    EXPECT_TRUE(saw_stream);
}

TEST(QuicCoreTest, AckGapsRetransmitLostOffsetsBeforeFreshData) {
    auto connection = make_connected_server_connection();
    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(128u) * 1024u, std::byte{0x46});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::vector<std::pair<std::uint64_t, std::uint64_t>> packet_offsets;
    std::uint64_t largest_sent_packet = 0;
    std::uint64_t next_unsent_offset = 0;

    while (true) {
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        const auto packets = decode_sender_datagram(connection, datagram);
        ASSERT_EQ(packets.size(), 1u);
        const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
        ASSERT_NE(application, nullptr);

        largest_sent_packet = application->packet_number;
        std::optional<std::uint64_t> first_stream_offset;
        for (const auto &frame : application->frames) {
            const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            ASSERT_TRUE(stream->offset.has_value());
            if (!stream->offset.has_value()) {
                continue;
            }

            const auto stream_offset = optional_value_or_terminate(stream->offset);
            if (!first_stream_offset.has_value()) {
                first_stream_offset = stream_offset;
            }
            next_unsent_offset =
                stream_offset + static_cast<std::uint64_t>(stream->stream_data.size());
        }

        ASSERT_TRUE(first_stream_offset.has_value());
        packet_offsets.emplace_back(application->packet_number,
                                    optional_value_or_terminate(first_stream_offset));
    }

    ASSERT_GE(packet_offsets.size(), 8u);

    const auto lookup_offset = [&](std::uint64_t packet_number) -> std::optional<std::uint64_t> {
        for (const auto &[candidate_packet_number, offset] : packet_offsets) {
            if (candidate_packet_number == packet_number) {
                return offset;
            }
        }
        return std::nullopt;
    };

    const auto first_lost_offset = lookup_offset(/*packet_number=*/2);
    const auto second_lost_offset = lookup_offset(/*packet_number=*/6);
    ASSERT_TRUE(first_lost_offset.has_value());
    ASSERT_TRUE(second_lost_offset.has_value());

    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = largest_sent_packet,
                                             .first_ack_range = largest_sent_packet - 7,
                                             .additional_ranges =
                                                 {
                                                     coquic::quic::AckRange{
                                                         .gap = 0,
                                                         .range_length = 2,
                                                     },
                                                     coquic::quic::AckRange{
                                                         .gap = 0,
                                                         .range_length = 1,
                                                     },
                                                 },
                                         },
                                         coquic::quic::test::test_time(2),
                                         peer_transport_parameters.ack_delay_exponent,
                                         peer_transport_parameters.max_ack_delay,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    ASSERT_TRUE(connection.streams_.contains(0));
    EXPECT_TRUE(connection.streams_.at(0).send_buffer.has_lost_data());

    const auto repaired_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(repaired_datagram.empty());

    const auto repaired_packets = decode_sender_datagram(connection, repaired_datagram);
    ASSERT_EQ(repaired_packets.size(), 1u);
    const auto *application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&repaired_packets[0]);
    ASSERT_NE(application, nullptr);

    std::vector<std::uint64_t> repaired_offsets;
    for (const auto &frame : application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        repaired_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    ASSERT_FALSE(repaired_offsets.empty());
    EXPECT_EQ(repaired_offsets.front(), optional_value_or_terminate(first_lost_offset));
    EXPECT_NE(repaired_offsets.front(), next_unsent_offset);
}

TEST(QuicCoreTest, ApplicationSendRemainsContiguousAfterAcknowledgingInitialFlight) {
    auto connection = make_connected_client_connection();
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(200000), std::byte{0x41});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::uint64_t expected_offset = 0;
    std::size_t emitted_packets = 0;
    for (;;) {
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        const auto packets = decode_sender_datagram(connection, datagram);
        ASSERT_EQ(packets.size(), 1u);
        const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
        ASSERT_NE(application, nullptr);

        for (const auto &frame : application->frames) {
            const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            ASSERT_TRUE(stream->offset.has_value());
            const auto stream_offset = optional_value_or_terminate(stream->offset);
            EXPECT_EQ(stream_offset, expected_offset);
            expected_offset += static_cast<std::uint64_t>(stream->stream_data.size());
        }

        ++emitted_packets;
    }

    ASSERT_GE(emitted_packets, 2u);
    ASSERT_FALSE(connection.application_space_.sent_packets.empty());
    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    const auto largest_sent_packet =
        std::prev(connection.application_space_.sent_packets.end())->first;
    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = largest_sent_packet,
                                             .first_ack_range = largest_sent_packet,
                                         },
                                         coquic::quic::test::test_time(2),
                                         peer_transport_parameters.ack_delay_exponent,
                                         peer_transport_parameters.max_ack_delay,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    const auto resumed_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(resumed_datagram.empty());
    const auto resumed_packets = decode_sender_datagram(connection, resumed_datagram);
    ASSERT_EQ(resumed_packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&resumed_packets[0]);
    ASSERT_NE(application, nullptr);

    const auto *stream = std::get_if<coquic::quic::StreamFrame>(&application->frames.back());
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->offset.has_value());
    EXPECT_EQ(optional_value_or_terminate(stream->offset), expected_offset);
}

TEST(QuicCoreTest, ApplicationSendContinuesAcrossCumulativeAckBursts) {
    auto connection = make_connected_client_connection();
    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(200000), std::byte{0x42});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::uint64_t expected_offset = 0;
    auto verify_sent_datagram = [&](std::span<const std::byte> datagram) -> std::uint64_t {
        const auto packets = decode_sender_datagram(connection, datagram);
        EXPECT_EQ(packets.size(), 1u);
        if (packets.size() != 1u) {
            return 0;
        }

        const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
        EXPECT_NE(application, nullptr);
        if (application == nullptr) {
            return 0;
        }

        for (const auto &frame : application->frames) {
            const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            EXPECT_TRUE(stream->offset.has_value());
            if (!stream->offset.has_value()) {
                return application->packet_number;
            }

            EXPECT_EQ(*stream->offset, expected_offset);
            expected_offset += static_cast<std::uint64_t>(stream->stream_data.size());
        }

        return application->packet_number;
    };

    const auto drain_burst =
        [&](coquic::quic::QuicCoreTimePoint burst_time) -> std::pair<std::size_t, std::uint64_t> {
        std::size_t emitted_packets = 0;
        std::uint64_t largest_sent = 0;
        for (;;) {
            const auto datagram = connection.drain_outbound_datagram(burst_time);
            if (datagram.empty()) {
                break;
            }

            largest_sent = verify_sent_datagram(datagram);
            ++emitted_packets;
        }

        return std::pair{emitted_packets, largest_sent};
    };

    const auto [first_burst_packets, first_largest_sent] =
        drain_burst(coquic::quic::test::test_time(1));
    ASSERT_GE(first_burst_packets, 8u);
    ASSERT_GT(expected_offset, 0u);

    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = first_largest_sent,
                                             .first_ack_range = first_largest_sent,
                                         },
                                         coquic::quic::test::test_time(2),
                                         peer_transport_parameters.ack_delay_exponent,
                                         peer_transport_parameters.max_ack_delay,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    const auto [second_burst_packets, second_largest_sent] =
        drain_burst(coquic::quic::test::test_time(3));
    ASSERT_GT(second_burst_packets, first_burst_packets);

    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = second_largest_sent,
                                             .first_ack_range = second_largest_sent,
                                         },
                                         coquic::quic::test::test_time(4),
                                         peer_transport_parameters.ack_delay_exponent,
                                         peer_transport_parameters.max_ack_delay,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    const auto [third_burst_packets, third_largest_sent] =
        drain_burst(coquic::quic::test::test_time(5));
    ASSERT_GT(third_burst_packets, 0u);
    EXPECT_GT(third_largest_sent, second_largest_sent);
    EXPECT_GT(expected_offset, 60000u);
}

TEST(QuicCoreTest, ApplicationSendDrainsLargePayloadAcrossRepeatedCumulativeAcks) {
    auto connection = make_connected_client_connection();
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(512u) * 1024u, std::byte{0x44});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::uint64_t expected_offset = 0;
    std::size_t total_packets = 0;
    constexpr std::size_t kMaxAckRounds = 2048;

    const auto drain_burst = [&](coquic::quic::QuicCoreTimePoint burst_time) {
        std::size_t emitted_packets = 0;
        std::uint64_t largest_sent = 0;
        for (;;) {
            const auto datagram = connection.drain_outbound_datagram(burst_time);
            if (datagram.empty()) {
                break;
            }

            const auto decoded = coquic::quic::deserialize_protected_datagram(
                datagram, coquic::quic::DeserializeProtectionContext{
                              .peer_role = connection.config_.role,
                              .client_initial_destination_connection_id =
                                  connection.client_initial_destination_connection_id(),
                              .handshake_secret = connection.handshake_space_.write_secret,
                              .one_rtt_secret = connection.application_space_.write_secret,
                              .one_rtt_key_phase = connection.application_write_key_phase_,
                              .largest_authenticated_initial_packet_number =
                                  connection.initial_space_.largest_authenticated_packet_number,
                              .largest_authenticated_handshake_packet_number =
                                  connection.handshake_space_.largest_authenticated_packet_number,
                              .largest_authenticated_application_packet_number =
                                  connection.application_space_.largest_authenticated_packet_number,
                              .one_rtt_destination_connection_id_length =
                                  connection.config_.source_connection_id.size(),
                          });
            EXPECT_TRUE(decoded.has_value());
            if (!decoded.has_value()) {
                continue;
            }

            const auto &packets = decoded.value();
            EXPECT_EQ(packets.size(), 1u);
            if (packets.size() != 1u) {
                continue;
            }

            const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
            EXPECT_NE(application, nullptr);
            if (application == nullptr) {
                continue;
            }

            largest_sent = application->packet_number;
            for (const auto &frame : application->frames) {
                const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
                if (stream == nullptr) {
                    continue;
                }

                EXPECT_TRUE(stream->offset.has_value());
                if (!stream->offset.has_value()) {
                    continue;
                }

                EXPECT_EQ(*stream->offset, expected_offset);
                expected_offset += static_cast<std::uint64_t>(stream->stream_data.size());
            }

            ++emitted_packets;
            ++total_packets;
        }

        return std::pair{emitted_packets, largest_sent};
    };

    for (std::size_t round = 0; round < kMaxAckRounds && expected_offset < payload.size();
         ++round) {
        const auto burst_time =
            coquic::quic::test::test_time(static_cast<std::int64_t>(round * 2 + 1));
        const auto [emitted_packets, largest_sent] = drain_burst(burst_time);
        static_cast<void>(largest_sent);
        const auto largest_outstanding =
            connection.application_space_.sent_packets.empty()
                ? std::optional<std::uint64_t>{}
                : std::optional<std::uint64_t>{
                      connection.application_space_.sent_packets.rbegin()->first,
                  };
        ASSERT_TRUE(emitted_packets > 0u || largest_outstanding.has_value())
            << "round=" << round << " expected_offset=" << expected_offset
            << " total_packets=" << total_packets
            << " bytes_in_flight=" << connection.congestion_controller_.bytes_in_flight()
            << " cwnd=" << connection.congestion_controller_.congestion_window()
            << " sent_packets=" << connection.application_space_.sent_packets.size()
            << " queued_bytes=" << connection.total_queued_stream_bytes()
            << " pending_send=" << connection.has_pending_application_send();
        ASSERT_TRUE(largest_outstanding.has_value());
        const auto largest_acknowledged = optional_value_or_terminate(largest_outstanding);

        ASSERT_TRUE(connection
                        .process_inbound_ack(
                            connection.application_space_,
                            coquic::quic::AckFrame{
                                .largest_acknowledged = largest_acknowledged,
                                .first_ack_range = largest_acknowledged,
                            },
                            coquic::quic::test::test_time(static_cast<std::int64_t>(round * 2 + 2)),
                            peer_transport_parameters.ack_delay_exponent,
                            peer_transport_parameters.max_ack_delay,
                            /*suppress_pto_reset=*/false)
                        .has_value());
    }

    EXPECT_EQ(expected_offset, payload.size())
        << "total_packets=" << total_packets
        << " bytes_in_flight=" << connection.congestion_controller_.bytes_in_flight()
        << " cwnd=" << connection.congestion_controller_.congestion_window()
        << " sent_packets=" << connection.application_space_.sent_packets.size()
        << " queued_bytes=" << connection.total_queued_stream_bytes()
        << " pending_send=" << connection.has_pending_application_send();
}

TEST(QuicCoreTest, ApplicationProbePacketDoesNotLeaveRetransmittedFragmentPending) {
    auto connection = make_connected_server_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;

    const auto payload = coquic::quic::test::bytes_from_string("probe-fragment");
    stream.send_buffer.append(payload);
    const auto initial_fragments = stream.take_send_fragments(payload.size());
    ASSERT_EQ(initial_fragments.size(), 1u);
    EXPECT_EQ(initial_fragments.front().offset, 0u);
    EXPECT_EQ(initial_fragments.front().bytes, payload);

    stream.mark_send_fragment_lost(initial_fragments.front());
    ASSERT_TRUE(stream.send_buffer.has_lost_data());

    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 72,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments = initial_fragments,
    };

    const auto probe_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(probe_datagram.empty());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());

    const auto probe_packets = decode_sender_datagram(connection, probe_datagram);
    ASSERT_EQ(probe_packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&probe_packets[0]);
    ASSERT_NE(application, nullptr);

    std::vector<coquic::quic::StreamFrame> stream_frames;
    for (const auto &frame : application->frames) {
        const auto *stream_frame = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream_frame != nullptr) {
            stream_frames.push_back(*stream_frame);
        }
    }

    ASSERT_EQ(stream_frames.size(), 1u);
    ASSERT_TRUE(stream_frames.front().offset.has_value());
    EXPECT_EQ(optional_value_or_terminate(stream_frames.front().offset), 0u);
    EXPECT_EQ(stream_frames.front().stream_data, payload);

    EXPECT_FALSE(stream.send_buffer.has_lost_data());
    EXPECT_FALSE(connection.has_pending_application_send());
    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(2)).empty());
}

TEST(QuicCoreTest, ApplicationSendDrainsLargePayloadAcrossDroppedCumulativeAckRounds) {
    auto connection = make_connected_server_connection();
    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(128u) * 1024u, std::byte{0x45});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::uint64_t expected_offset = 0;
    std::size_t total_packets = 0;
    std::size_t dropped_ack_rounds = 0;
    constexpr std::size_t kMaxRounds = 1024;

    const auto drain_burst = [&](coquic::quic::QuicCoreTimePoint burst_time) {
        std::size_t emitted_packets = 0;
        std::uint64_t largest_sent = 0;
        for (;;) {
            const auto datagram = connection.drain_outbound_datagram(burst_time);
            if (datagram.empty()) {
                break;
            }

            const auto decoded = coquic::quic::deserialize_protected_datagram(
                datagram, coquic::quic::DeserializeProtectionContext{
                              .peer_role = connection.config_.role,
                              .client_initial_destination_connection_id =
                                  connection.client_initial_destination_connection_id(),
                              .handshake_secret = connection.handshake_space_.write_secret,
                              .one_rtt_secret = connection.application_space_.write_secret,
                              .one_rtt_key_phase = connection.application_write_key_phase_,
                              .largest_authenticated_initial_packet_number =
                                  connection.initial_space_.largest_authenticated_packet_number,
                              .largest_authenticated_handshake_packet_number =
                                  connection.handshake_space_.largest_authenticated_packet_number,
                              .largest_authenticated_application_packet_number =
                                  connection.application_space_.largest_authenticated_packet_number,
                              .one_rtt_destination_connection_id_length =
                                  connection.config_.source_connection_id.size(),
                          });
            EXPECT_TRUE(decoded.has_value());
            if (!decoded.has_value()) {
                continue;
            }

            const auto &packets = decoded.value();
            EXPECT_EQ(packets.size(), 1u);
            if (packets.size() != 1u) {
                continue;
            }

            const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
            EXPECT_NE(application, nullptr);
            if (application == nullptr) {
                continue;
            }

            largest_sent = application->packet_number;
            for (const auto &frame : application->frames) {
                const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
                if (stream == nullptr) {
                    continue;
                }

                EXPECT_TRUE(stream->offset.has_value());
                if (!stream->offset.has_value()) {
                    continue;
                }

                EXPECT_EQ(*stream->offset, expected_offset);
                expected_offset += static_cast<std::uint64_t>(stream->stream_data.size());
            }

            ++emitted_packets;
            ++total_packets;
        }

        return std::pair{emitted_packets, largest_sent};
    };

    for (std::size_t round = 0; round < kMaxRounds && expected_offset < payload.size(); ++round) {
        const auto burst_time =
            coquic::quic::test::test_time(static_cast<std::int64_t>(round * 4 + 1));
        const auto [emitted_packets, largest_sent] = drain_burst(burst_time);
        static_cast<void>(largest_sent);
        const auto largest_outstanding =
            connection.application_space_.sent_packets.empty()
                ? std::optional<std::uint64_t>{}
                : std::optional<std::uint64_t>{
                      connection.application_space_.sent_packets.rbegin()->first,
                  };
        ASSERT_TRUE(emitted_packets > 0u || largest_outstanding.has_value())
            << "round=" << round << " expected_offset=" << expected_offset
            << " total_packets=" << total_packets << " dropped_ack_rounds=" << dropped_ack_rounds
            << " bytes_in_flight=" << connection.congestion_controller_.bytes_in_flight()
            << " cwnd=" << connection.congestion_controller_.congestion_window()
            << " sent_packets=" << connection.application_space_.sent_packets.size()
            << " queued_bytes=" << connection.total_queued_stream_bytes()
            << " pending_send=" << connection.has_pending_application_send();

        if ((round % 5u) == 2u) {
            ++dropped_ack_rounds;
            continue;
        }

        ASSERT_TRUE(largest_outstanding.has_value());
        const auto largest_acknowledged = optional_value_or_terminate(largest_outstanding);

        ASSERT_TRUE(connection
                        .process_inbound_ack(
                            connection.application_space_,
                            coquic::quic::AckFrame{
                                .largest_acknowledged = largest_acknowledged,
                                .first_ack_range = largest_acknowledged,
                            },
                            coquic::quic::test::test_time(static_cast<std::int64_t>(round * 4 + 2)),
                            peer_transport_parameters.ack_delay_exponent,
                            peer_transport_parameters.max_ack_delay,
                            /*suppress_pto_reset=*/false)
                        .has_value());
    }

    EXPECT_EQ(expected_offset, payload.size())
        << "total_packets=" << total_packets << " dropped_ack_rounds=" << dropped_ack_rounds
        << " bytes_in_flight=" << connection.congestion_controller_.bytes_in_flight()
        << " cwnd=" << connection.congestion_controller_.congestion_window()
        << " sent_packets=" << connection.application_space_.sent_packets.size()
        << " queued_bytes=" << connection.total_queued_stream_bytes()
        << " pending_send=" << connection.has_pending_application_send();
}

TEST(QuicCoreTest, ApplicationSendDrainsLargePayloadAcrossDroppedKeyUpdatedAckDatagrams) {
    auto config = coquic::quic::test::make_server_core_config();
    config.source_connection_id = bytes_from_ints({0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
    coquic::quic::QuicConnection connection(std::move(config));
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::connected;
    connection.handshake_confirmed_ = true;
    connection.peer_source_connection_id_ =
        bytes_from_ints({0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
    connection.client_initial_destination_connection_id_ =
        bytes_from_ints({0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    connection.local_transport_parameters_ = coquic::quic::TransportParameters{
        .original_destination_connection_id = connection.client_initial_destination_connection_id_,
        .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
        .active_connection_id_limit = 2,
        .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
        .max_ack_delay = connection.config_.transport.max_ack_delay,
        .initial_max_data = connection.config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local =
            connection.config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            connection.config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = connection.config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = connection.config_.source_connection_id,
    };
    connection.initialize_local_flow_control();
    connection.application_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
    connection.application_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});
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
        .initial_max_stream_data_uni = connection.config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = connection.peer_source_connection_id_,
    };
    connection.peer_transport_parameters_validated_ = true;
    connection.initialize_peer_flow_control_from_transport_parameters();

    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(128u) * 1024u, std::byte{0x47});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    ASSERT_TRUE(connection.application_space_.write_secret.has_value());
    const auto next_read_secret =
        coquic::quic::derive_next_traffic_secret(*connection.application_space_.read_secret);
    const auto next_write_secret =
        coquic::quic::derive_next_traffic_secret(*connection.application_space_.write_secret);
    ASSERT_TRUE(next_read_secret.has_value());
    ASSERT_TRUE(next_write_secret.has_value());

    const auto process_client_packet = [&](std::uint64_t packet_number,
                                           std::span<const coquic::quic::Frame> frames,
                                           coquic::quic::QuicCoreTimePoint now) {
        const auto encoded = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .key_phase = true,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames = std::vector<coquic::quic::Frame>(frames.begin(), frames.end()),
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::client,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret = next_read_secret.value(),
                .one_rtt_key_phase = true,
            });
        ASSERT_TRUE(encoded.has_value());
        connection.process_inbound_datagram(encoded.value(), now);
    };

    process_client_packet(/*packet_number=*/51,
                          std::array<coquic::quic::Frame, 1>{
                              coquic::quic::AckFrame{
                                  .largest_acknowledged = 0,
                                  .first_ack_range = 0,
                              },
                          },
                          coquic::quic::test::test_time(0));
    ASSERT_FALSE(connection.has_failed());
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    ASSERT_EQ(connection.application_space_.read_secret->secret, next_read_secret.value().secret);
    ASSERT_TRUE(connection.application_space_.write_secret.has_value());
    ASSERT_EQ(connection.application_space_.write_secret->secret, next_write_secret.value().secret);

    std::uint64_t expected_offset = 0;
    std::size_t total_packets = 0;
    std::size_t dropped_ack_rounds = 0;
    std::uint64_t next_client_packet_number = 52;
    constexpr std::size_t kMaxRounds = 1024;

    const auto drain_burst = [&](coquic::quic::QuicCoreTimePoint burst_time) {
        std::size_t emitted_packets = 0;
        std::uint64_t largest_sent = 0;
        for (;;) {
            const auto datagram = connection.drain_outbound_datagram(burst_time);
            if (datagram.empty()) {
                break;
            }

            const auto packets = decode_sender_datagram(connection, datagram);
            EXPECT_EQ(packets.size(), 1u);
            if (packets.size() != 1u) {
                continue;
            }

            const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
            EXPECT_NE(application, nullptr);
            if (application == nullptr) {
                continue;
            }

            largest_sent = application->packet_number;
            for (const auto &frame : application->frames) {
                const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
                if (stream == nullptr) {
                    continue;
                }

                EXPECT_TRUE(stream->offset.has_value());
                if (!stream->offset.has_value()) {
                    continue;
                }

                EXPECT_EQ(*stream->offset, expected_offset);
                expected_offset += static_cast<std::uint64_t>(stream->stream_data.size());
            }

            ++emitted_packets;
            ++total_packets;
        }

        return std::pair{emitted_packets, largest_sent};
    };

    for (std::size_t round = 0; round < kMaxRounds && expected_offset < payload.size(); ++round) {
        const auto burst_time =
            coquic::quic::test::test_time(static_cast<std::int64_t>(round * 4 + 1));
        const auto [emitted_packets, largest_sent] = drain_burst(burst_time);
        static_cast<void>(largest_sent);
        const auto largest_outstanding =
            connection.application_space_.sent_packets.empty()
                ? std::optional<std::uint64_t>{}
                : std::optional<std::uint64_t>{
                      connection.application_space_.sent_packets.rbegin()->first,
                  };
        ASSERT_TRUE(emitted_packets > 0u || largest_outstanding.has_value())
            << "round=" << round << " expected_offset=" << expected_offset
            << " total_packets=" << total_packets << " dropped_ack_rounds=" << dropped_ack_rounds
            << " bytes_in_flight=" << connection.congestion_controller_.bytes_in_flight()
            << " cwnd=" << connection.congestion_controller_.congestion_window()
            << " sent_packets=" << connection.application_space_.sent_packets.size()
            << " queued_bytes=" << connection.total_queued_stream_bytes()
            << " pending_send=" << connection.has_pending_application_send();

        if ((round % 5u) == 2u) {
            ++dropped_ack_rounds;
            continue;
        }

        ASSERT_TRUE(largest_outstanding.has_value());
        const auto largest_acknowledged = optional_value_or_terminate(largest_outstanding);

        process_client_packet(
            next_client_packet_number++,
            std::array<coquic::quic::Frame, 1>{
                coquic::quic::AckFrame{
                    .largest_acknowledged = largest_acknowledged,
                    .first_ack_range = largest_acknowledged,
                },
            },
            coquic::quic::test::test_time(static_cast<std::int64_t>(round * 4 + 2)));
        ASSERT_FALSE(connection.has_failed()) << "round=" << round;
    }

    EXPECT_EQ(expected_offset, payload.size())
        << "total_packets=" << total_packets << " dropped_ack_rounds=" << dropped_ack_rounds
        << " bytes_in_flight=" << connection.congestion_controller_.bytes_in_flight()
        << " cwnd=" << connection.congestion_controller_.congestion_window()
        << " sent_packets=" << connection.application_space_.sent_packets.size()
        << " queued_bytes=" << connection.total_queued_stream_bytes()
        << " pending_send=" << connection.has_pending_application_send();
}

TEST(QuicCoreTest, ApplicationSendQueuesBlockedFrameWhenStreamCreditIsZero) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
            .has_value());
    auto &stream = connection.streams_.at(0);
    stream.flow_control.peer_max_stream_data = 0;
    stream.send_flow_control_limit = 0;
    connection.maybe_queue_stream_blocked_frame(stream);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_stream_data_blocked = false;
    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_stream_data_blocked =
            saw_stream_data_blocked ||
            std::holds_alternative<coquic::quic::StreamDataBlockedFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_stream_data_blocked);
    EXPECT_FALSE(saw_stream);
}

TEST(QuicCoreTest, CongestionWindowGatesAckElicitingSendsUntilAckArrives) {
    auto connection = make_connected_client_connection();
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(32) * 1024U, std::byte{0x43});

    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::size_t sent_datagrams = 0;
    while (true) {
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        ++sent_datagrams;
    }

    EXPECT_GT(sent_datagrams, 0u);
    EXPECT_TRUE(connection.has_pending_application_send());
    const auto blocked = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    EXPECT_TRUE(blocked.empty());

    ASSERT_FALSE(connection.application_space_.sent_packets.empty());
    const auto largest_packet_number = connection.application_space_.sent_packets.rbegin()->first;
    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = largest_packet_number,
                                             .first_ack_range = largest_packet_number,
                                         },
                                         coquic::quic::test::test_time(3),
                                         /*ack_delay_exponent=*/3,
                                         /*max_ack_delay_ms=*/25,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    const auto after_ack = connection.drain_outbound_datagram(coquic::quic::test::test_time(4));
    EXPECT_FALSE(after_ack.empty());
}

TEST(QuicCoreTest, ConnectionFlowControlTracksMaxDataAndDataBlockedFrames) {
    coquic::quic::ConnectionFlowControlState state;
    state.peer_max_data = 4;

    EXPECT_EQ(state.sendable_bytes(/*queued_bytes=*/10), 4u);
    EXPECT_TRUE(state.should_send_data_blocked(/*queued_bytes=*/5));

    coquic::quic::ConnectionFlowControlState exhausted_credit;
    exhausted_credit.peer_max_data = 12;
    exhausted_credit.highest_sent = 8;
    EXPECT_EQ(exhausted_credit.sendable_bytes(/*queued_bytes=*/4), 0u);

    state.note_peer_max_data(/*maximum_data=*/4);
    EXPECT_EQ(state.peer_max_data, 4u);
    state.note_peer_max_data(/*maximum_data=*/8);
    EXPECT_EQ(state.peer_max_data, 8u);

    state.advertised_max_data = 10;
    state.queue_max_data(/*maximum_data=*/10);
    EXPECT_FALSE(state.take_max_data_frame().has_value());

    state.queue_max_data(/*maximum_data=*/20);
    const auto max_data = state.take_max_data_frame();
    ASSERT_TRUE(max_data.has_value());
    const auto max_data_frame = max_data.value_or(coquic::quic::MaxDataFrame{});
    state.mark_max_data_frame_lost(max_data_frame);
    const auto resent_max_data = state.take_max_data_frame();
    ASSERT_TRUE(resent_max_data.has_value());
    const auto resent_max_data_frame = resent_max_data.value_or(coquic::quic::MaxDataFrame{});
    state.acknowledge_max_data_frame(resent_max_data_frame);
    EXPECT_EQ(state.max_data_state, coquic::quic::StreamControlFrameState::acknowledged);

    state.pending_max_data_frame = std::nullopt;
    state.max_data_state = coquic::quic::StreamControlFrameState::sent;
    state.acknowledge_max_data_frame(coquic::quic::MaxDataFrame{.maximum_data = 99});
    EXPECT_EQ(state.max_data_state, coquic::quic::StreamControlFrameState::sent);
    state.mark_max_data_frame_lost(coquic::quic::MaxDataFrame{.maximum_data = 99});
    EXPECT_EQ(state.max_data_state, coquic::quic::StreamControlFrameState::sent);

    state.queue_data_blocked(/*maximum_data=*/30);
    state.queue_data_blocked(/*maximum_data=*/30);
    const auto data_blocked = state.take_data_blocked_frame();
    ASSERT_TRUE(data_blocked.has_value());
    const auto data_blocked_frame = data_blocked.value_or(coquic::quic::DataBlockedFrame{});
    state.mark_data_blocked_frame_lost(data_blocked_frame);
    const auto resent_data_blocked = state.take_data_blocked_frame();
    ASSERT_TRUE(resent_data_blocked.has_value());
    const auto resent_data_blocked_frame =
        resent_data_blocked.value_or(coquic::quic::DataBlockedFrame{});
    state.acknowledge_data_blocked_frame(resent_data_blocked_frame);
    EXPECT_EQ(state.data_blocked_state, coquic::quic::StreamControlFrameState::acknowledged);

    state.pending_data_blocked_frame = std::nullopt;
    state.data_blocked_state = coquic::quic::StreamControlFrameState::sent;
    state.acknowledge_data_blocked_frame(coquic::quic::DataBlockedFrame{.maximum_data = 77});
    EXPECT_EQ(state.data_blocked_state, coquic::quic::StreamControlFrameState::sent);
    state.mark_data_blocked_frame_lost(coquic::quic::DataBlockedFrame{.maximum_data = 77});
    EXPECT_EQ(state.data_blocked_state, coquic::quic::StreamControlFrameState::sent);
}

TEST(QuicCoreTest, ConnectionHelperMethodsCoverAdditionalPendingSendAndLimitBranches) {
    auto connection = make_connected_client_connection();
    connection.connection_flow_control_.advertised_max_data = 4;
    connection.connection_flow_control_.delivered_bytes = 5;
    connection.connection_flow_control_.local_receive_window = 2;
    connection.maybe_refresh_connection_receive_credit(/*force=*/false);
    EXPECT_FALSE(connection.connection_flow_control_.pending_max_data_frame.has_value());

    connection.local_transport_parameters_.initial_max_streams_uni = 7;
    EXPECT_EQ(connection.peer_stream_open_limits().unidirectional, 7u);
    connection.local_transport_parameters_.initial_max_streams_uni = 0;
    EXPECT_EQ(connection.peer_stream_open_limits().unidirectional,
              connection.config_.transport.initial_max_streams_uni);

    auto &stream = connection.streams_
                       .emplace(0, coquic::quic::make_implicit_stream_state(
                                       /*stream_id=*/0, connection.config_.role))
                       .first->second;
    stream.flow_control.pending_stream_data_blocked_frame = coquic::quic::StreamDataBlockedFrame{
        .stream_id = 0,
        .maximum_stream_data = 1,
    };
    stream.flow_control.stream_data_blocked_state = coquic::quic::StreamControlFrameState::pending;
    EXPECT_TRUE(connection.has_pending_application_send());

    auto &pending_fin = connection.streams_
                            .emplace(4, coquic::quic::make_implicit_stream_state(
                                            /*stream_id=*/4, connection.config_.role))
                            .first->second;
    pending_fin.send_fin_state = coquic::quic::StreamSendFinState::pending;
    EXPECT_TRUE(connection.has_pending_application_send());
    stream.flow_control.stream_data_blocked_state = coquic::quic::StreamControlFrameState::none;
    stream.flow_control.pending_stream_data_blocked_frame = std::nullopt;
    EXPECT_FALSE(connection.has_pending_application_send());
    pending_fin.send_final_size = 1;
    pending_fin.flow_control.peer_max_stream_data = 0;
    EXPECT_FALSE(connection.has_pending_application_send());

    connection.connection_flow_control_.pending_max_data_frame =
        coquic::quic::MaxDataFrame{.maximum_data = 1};
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::pending;
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    EXPECT_FALSE(datagram.empty());
}

TEST(QuicCoreTest, ConnectionFlowControlTracksMissingPendingFramesAndAcknowledgedLossStates) {
    coquic::quic::ConnectionFlowControlState state;
    state.max_data_state = coquic::quic::StreamControlFrameState::pending;
    EXPECT_FALSE(state.take_max_data_frame().has_value());
    state.pending_max_data_frame = coquic::quic::MaxDataFrame{.maximum_data = 9};
    state.max_data_state = coquic::quic::StreamControlFrameState::acknowledged;
    state.mark_max_data_frame_lost(coquic::quic::MaxDataFrame{.maximum_data = 9});
    EXPECT_EQ(state.max_data_state, coquic::quic::StreamControlFrameState::acknowledged);

    state.pending_data_blocked_frame = coquic::quic::DataBlockedFrame{.maximum_data = 11};
    state.data_blocked_state = coquic::quic::StreamControlFrameState::none;
    state.queue_data_blocked(/*maximum_data=*/11);
    EXPECT_EQ(state.data_blocked_state, coquic::quic::StreamControlFrameState::pending);
    state.pending_data_blocked_frame = coquic::quic::DataBlockedFrame{.maximum_data = 11};
    state.data_blocked_state = coquic::quic::StreamControlFrameState::pending;
    state.queue_data_blocked(/*maximum_data=*/12);
    ASSERT_TRUE(state.pending_data_blocked_frame.has_value());
    EXPECT_EQ(state.pending_data_blocked_frame->maximum_data, 12u);

    state.data_blocked_state = coquic::quic::StreamControlFrameState::pending;
    state.pending_data_blocked_frame = std::nullopt;
    EXPECT_FALSE(state.take_data_blocked_frame().has_value());
    state.pending_data_blocked_frame = coquic::quic::DataBlockedFrame{.maximum_data = 11};
    state.data_blocked_state = coquic::quic::StreamControlFrameState::acknowledged;
    state.mark_data_blocked_frame_lost(coquic::quic::DataBlockedFrame{.maximum_data = 11});
    EXPECT_EQ(state.data_blocked_state, coquic::quic::StreamControlFrameState::acknowledged);
}

TEST(QuicCoreTest, QueueStreamResetRejectsReceiveOnlyStreamAtConnectionLayer) {
    auto connection = make_connected_client_connection();
    connection.stream_open_limits_.peer_max_bidirectional = 1;
    const auto invalid_id =
        connection.queue_stream_reset({.stream_id = 4, .application_error_code = 7});
    ASSERT_FALSE(invalid_id.has_value());
    EXPECT_EQ(invalid_id.error().code, coquic::quic::StreamStateErrorCode::invalid_stream_id);

    const auto result =
        connection.queue_stream_reset({.stream_id = 3, .application_error_code = 7});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::quic::StreamStateErrorCode::invalid_stream_direction);
}

TEST(QuicCoreTest, QueueStreamSendRejectsInvalidIdsAndClosedSendSide) {
    auto connection = make_connected_client_connection();
    const auto payload = bytes_from_ints({0x61});
    connection.stream_open_limits_.peer_max_bidirectional = 1;

    ASSERT_TRUE(connection.queue_stream_send(/*stream_id=*/1, payload, false).has_value());

    const auto invalid_local = connection.queue_stream_send(/*stream_id=*/4, payload, false);
    ASSERT_FALSE(invalid_local.has_value());
    EXPECT_EQ(invalid_local.error().code, coquic::quic::StreamStateErrorCode::invalid_stream_id);

    const auto peer_unidirectional = connection.queue_stream_send(/*stream_id=*/3, payload, false);
    ASSERT_FALSE(peer_unidirectional.has_value());
    EXPECT_EQ(peer_unidirectional.error().code,
              coquic::quic::StreamStateErrorCode::invalid_stream_direction);

    ASSERT_TRUE(connection.queue_stream_send(/*stream_id=*/0, {}, /*fin=*/true).has_value());
    const auto closed = connection.queue_stream_send(/*stream_id=*/0, payload, /*fin=*/false);
    ASSERT_FALSE(closed.has_value());
    EXPECT_EQ(closed.error().code, coquic::quic::StreamStateErrorCode::send_side_closed);
}

TEST(QuicCoreTest, RetireAckedPacketAcknowledgesConnectionAndStreamControlState) {
    auto connection = make_connected_client_connection();
    auto &stream = connection.streams_
                       .emplace(0, coquic::quic::make_implicit_stream_state(
                                       /*stream_id=*/0, connection.config_.role))
                       .first->second;
    auto &fin_stream = connection.streams_
                           .emplace(4, coquic::quic::make_implicit_stream_state(
                                           /*stream_id=*/4, connection.config_.role))
                           .first->second;

    connection.connection_flow_control_.pending_max_data_frame =
        coquic::quic::MaxDataFrame{.maximum_data = 20};
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::sent;
    connection.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 30};
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::sent;

    stream.flow_control.pending_max_stream_data_frame = coquic::quic::MaxStreamDataFrame{
        .stream_id = 0,
        .maximum_stream_data = 40,
    };
    stream.flow_control.max_stream_data_state = coquic::quic::StreamControlFrameState::sent;
    stream.flow_control.pending_stream_data_blocked_frame = coquic::quic::StreamDataBlockedFrame{
        .stream_id = 0,
        .maximum_stream_data = 50,
    };
    stream.flow_control.stream_data_blocked_state = coquic::quic::StreamControlFrameState::sent;
    stream.pending_reset_frame = coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 7,
        .final_size = 5,
    };
    stream.reset_state = coquic::quic::StreamControlFrameState::sent;
    stream.pending_stop_sending_frame = coquic::quic::StopSendingFrame{
        .stream_id = 0,
        .application_protocol_error_code = 9,
    };
    stream.stop_sending_state = coquic::quic::StreamControlFrameState::sent;
    fin_stream.send_fin_state = coquic::quic::StreamSendFinState::sent;

    const auto packet = coquic::quic::SentPacketRecord{
        .packet_number = 7,
        .reset_stream_frames =
            {
                coquic::quic::ResetStreamFrame{
                    .stream_id = 0,
                    .application_protocol_error_code = 7,
                    .final_size = 5,
                },
                coquic::quic::ResetStreamFrame{
                    .stream_id = 99,
                    .application_protocol_error_code = 1,
                    .final_size = 0,
                },
            },
        .stop_sending_frames =
            {
                coquic::quic::StopSendingFrame{
                    .stream_id = 0,
                    .application_protocol_error_code = 9,
                },
                coquic::quic::StopSendingFrame{
                    .stream_id = 99,
                    .application_protocol_error_code = 1,
                },
            },
        .max_data_frame = coquic::quic::MaxDataFrame{.maximum_data = 20},
        .max_stream_data_frames =
            {
                coquic::quic::MaxStreamDataFrame{
                    .stream_id = 0,
                    .maximum_stream_data = 40,
                },
                coquic::quic::MaxStreamDataFrame{
                    .stream_id = 99,
                    .maximum_stream_data = 1,
                },
            },
        .data_blocked_frame = coquic::quic::DataBlockedFrame{.maximum_data = 30},
        .stream_data_blocked_frames =
            {
                coquic::quic::StreamDataBlockedFrame{
                    .stream_id = 0,
                    .maximum_stream_data = 50,
                },
                coquic::quic::StreamDataBlockedFrame{
                    .stream_id = 99,
                    .maximum_stream_data = 2,
                },
            },
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 4,
                    .offset = 5,
                    .bytes = {},
                    .fin = true,
                },
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 99,
                    .offset = 0,
                    .bytes = {},
                    .fin = false,
                },
            },
    };
    connection.application_space_.sent_packets.emplace(packet.packet_number, packet);

    connection.retire_acked_packet(connection.application_space_, packet);

    EXPECT_EQ(connection.connection_flow_control_.max_data_state,
              coquic::quic::StreamControlFrameState::acknowledged);
    EXPECT_EQ(connection.connection_flow_control_.data_blocked_state,
              coquic::quic::StreamControlFrameState::acknowledged);
    EXPECT_EQ(stream.flow_control.max_stream_data_state,
              coquic::quic::StreamControlFrameState::acknowledged);
    EXPECT_EQ(stream.flow_control.stream_data_blocked_state,
              coquic::quic::StreamControlFrameState::acknowledged);
    EXPECT_EQ(stream.reset_state, coquic::quic::StreamControlFrameState::acknowledged);
    EXPECT_EQ(stream.stop_sending_state, coquic::quic::StreamControlFrameState::acknowledged);
    EXPECT_EQ(fin_stream.send_fin_state, coquic::quic::StreamSendFinState::acknowledged);
    EXPECT_FALSE(connection.application_space_.sent_packets.contains(packet.packet_number));
}

TEST(QuicCoreTest, MarkLostPacketRequeuesConnectionAndStreamControlState) {
    auto connection = make_connected_client_connection();
    auto &stream = connection.streams_
                       .emplace(0, coquic::quic::make_implicit_stream_state(
                                       /*stream_id=*/0, connection.config_.role))
                       .first->second;
    auto &fin_stream = connection.streams_
                           .emplace(4, coquic::quic::make_implicit_stream_state(
                                           /*stream_id=*/4, connection.config_.role))
                           .first->second;

    connection.connection_flow_control_.pending_max_data_frame =
        coquic::quic::MaxDataFrame{.maximum_data = 20};
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::sent;
    connection.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 30};
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::sent;

    stream.flow_control.pending_max_stream_data_frame = coquic::quic::MaxStreamDataFrame{
        .stream_id = 0,
        .maximum_stream_data = 40,
    };
    stream.flow_control.max_stream_data_state = coquic::quic::StreamControlFrameState::sent;
    stream.flow_control.pending_stream_data_blocked_frame = coquic::quic::StreamDataBlockedFrame{
        .stream_id = 0,
        .maximum_stream_data = 50,
    };
    stream.flow_control.stream_data_blocked_state = coquic::quic::StreamControlFrameState::sent;
    stream.pending_reset_frame = coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 7,
        .final_size = 5,
    };
    stream.reset_state = coquic::quic::StreamControlFrameState::sent;
    stream.pending_stop_sending_frame = coquic::quic::StopSendingFrame{
        .stream_id = 0,
        .application_protocol_error_code = 9,
    };
    stream.stop_sending_state = coquic::quic::StreamControlFrameState::sent;
    fin_stream.send_fin_state = coquic::quic::StreamSendFinState::sent;

    const auto packet = coquic::quic::SentPacketRecord{
        .packet_number = 9,
        .reset_stream_frames =
            {
                coquic::quic::ResetStreamFrame{
                    .stream_id = 0,
                    .application_protocol_error_code = 7,
                    .final_size = 5,
                },
                coquic::quic::ResetStreamFrame{
                    .stream_id = 99,
                    .application_protocol_error_code = 1,
                    .final_size = 0,
                },
            },
        .stop_sending_frames =
            {
                coquic::quic::StopSendingFrame{
                    .stream_id = 0,
                    .application_protocol_error_code = 9,
                },
                coquic::quic::StopSendingFrame{
                    .stream_id = 99,
                    .application_protocol_error_code = 1,
                },
            },
        .max_data_frame = coquic::quic::MaxDataFrame{.maximum_data = 20},
        .max_stream_data_frames =
            {
                coquic::quic::MaxStreamDataFrame{
                    .stream_id = 0,
                    .maximum_stream_data = 40,
                },
                coquic::quic::MaxStreamDataFrame{
                    .stream_id = 99,
                    .maximum_stream_data = 1,
                },
            },
        .data_blocked_frame = coquic::quic::DataBlockedFrame{.maximum_data = 30},
        .stream_data_blocked_frames =
            {
                coquic::quic::StreamDataBlockedFrame{
                    .stream_id = 0,
                    .maximum_stream_data = 50,
                },
                coquic::quic::StreamDataBlockedFrame{
                    .stream_id = 99,
                    .maximum_stream_data = 2,
                },
            },
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 4,
                    .offset = 5,
                    .bytes = {},
                    .fin = true,
                },
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 99,
                    .offset = 0,
                    .bytes = {},
                    .fin = false,
                },
            },
    };
    connection.application_space_.sent_packets.emplace(packet.packet_number, packet);

    connection.mark_lost_packet(connection.application_space_, packet);

    EXPECT_EQ(connection.connection_flow_control_.max_data_state,
              coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(connection.connection_flow_control_.data_blocked_state,
              coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(stream.flow_control.max_stream_data_state,
              coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(stream.flow_control.stream_data_blocked_state,
              coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(stream.reset_state, coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(stream.stop_sending_state, coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(fin_stream.send_fin_state, coquic::quic::StreamSendFinState::pending);
    EXPECT_FALSE(connection.application_space_.sent_packets.contains(packet.packet_number));
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

TEST(QuicCoreTest, InboundApplicationStreamAllowsOmittedOffsetAndLengthFlags) {
    coquic::quic::QuicConnection missing_offset_connection(
        coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        missing_offset_connection, coquic::quic::HandshakeStatus::connected);
    const auto missing_offset_ok =
        coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            missing_offset_connection, {coquic::quic::test::make_inbound_application_stream_frame(
                                           "a", 0, 0, false, false, true)});
    EXPECT_TRUE(missing_offset_ok);
    EXPECT_FALSE(missing_offset_connection.has_failed());
    const auto missing_offset_data = missing_offset_connection.take_received_stream_data();
    ASSERT_TRUE(missing_offset_data.has_value());
    if (!missing_offset_data.has_value()) {
        return;
    }
    const auto &missing_offset_effect = missing_offset_data.value();
    EXPECT_EQ(coquic::quic::test::string_from_bytes(missing_offset_effect.bytes), "a");

    coquic::quic::QuicConnection missing_length_connection(
        coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        missing_length_connection, coquic::quic::HandshakeStatus::connected);
    const auto missing_length_ok =
        coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            missing_length_connection, {coquic::quic::test::make_inbound_application_stream_frame(
                                           "b", 0, 0, false, true, false)});
    EXPECT_TRUE(missing_length_ok);
    EXPECT_FALSE(missing_length_connection.has_failed());
    const auto missing_length_data = missing_length_connection.take_received_stream_data();
    ASSERT_TRUE(missing_length_data.has_value());
    if (!missing_length_data.has_value()) {
        return;
    }
    const auto &missing_length_effect = missing_length_data.value();
    EXPECT_EQ(coquic::quic::test::string_from_bytes(missing_length_effect.bytes), "b");
}

TEST(QuicCoreTest, InboundApplicationStreamFailsBeforeHandshakeConnected) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::in_progress);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("ping")});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());
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
    const auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    if (!received.has_value()) {
        return;
    }
    EXPECT_EQ(coquic::quic::test::string_from_bytes(received.value().bytes), "pong");
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

TEST(QuicCoreTest,
     InboundApplicationCompatibilityStreamZeroRespectsAdvertisedBidirectionalStreamLimit) {
    auto config = coquic::quic::test::make_server_core_config();
    config.transport.initial_max_streams_bidi = 0;
    coquic::quic::QuicConnection connection(config);
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("ping", 0, 0)});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());
}

TEST(QuicCoreTest, InboundApplicationStreamCarriesFinWhenFinalDataBecomesContiguous) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto out_of_order =
        coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            connection,
            {coquic::quic::test::make_inbound_application_stream_frame("lo", 3, 0, true)});
    EXPECT_TRUE(out_of_order);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::test::make_inbound_application_stream_frame("hel", 0, 0, false)});

    EXPECT_TRUE(injected);
    EXPECT_FALSE(connection.has_failed());
    const auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    if (!received.has_value()) {
        return;
    }
    EXPECT_EQ(received.value().stream_id, 0u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(received.value().bytes), "hello");
    EXPECT_TRUE(received.value().fin);
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
    EXPECT_TRUE(client.drain_outbound_datagram(coquic::quic::test::test_time(2)).empty());
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

    const auto wrong_frame = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial,
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("x")},
        coquic::quic::test::test_time());
    ASSERT_FALSE(wrong_frame.has_value());
    EXPECT_EQ(wrong_frame.error().code,
              coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);

    const auto empty_crypto = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial,
        std::array<coquic::quic::Frame, 1>{coquic::quic::CryptoFrame{}},
        coquic::quic::test::test_time(1));
    EXPECT_TRUE(empty_crypto.has_value());

    const auto overflow =
        connection.process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                          std::array<coquic::quic::Frame, 1>{
                                              coquic::quic::CryptoFrame{
                                                  .offset = (std::uint64_t{1} << 62),
                                                  .crypto_data = {std::byte{0x01}},
                                              },
                                          },
                                          coquic::quic::test::test_time(2));
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto missing_tls =
        connection.process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                          std::array<coquic::quic::Frame, 1>{
                                              coquic::quic::CryptoFrame{
                                                  .offset = 0,
                                                  .crypto_data = {std::byte{0x01}},
                                              },
                                          },
                                          coquic::quic::test::test_time(3));
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
    const auto provided_failure =
        connection.process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                          std::array<coquic::quic::Frame, 1>{
                                              coquic::quic::CryptoFrame{
                                                  .offset = 1,
                                                  .crypto_data = {std::byte{0x02}},
                                              },
                                          },
                                          coquic::quic::test::test_time(4));
    ASSERT_FALSE(provided_failure.has_value());
    EXPECT_EQ(provided_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicCoreTest, ConnectionProcessInboundCryptoAcceptsPingBeforeCryptoFrames) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    const auto initial = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial,
        std::array<coquic::quic::Frame, 2>{coquic::quic::PingFrame{}, coquic::quic::CryptoFrame{}},
        coquic::quic::test::test_time());
    ASSERT_TRUE(initial.has_value());

    const auto handshake = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::handshake,
        std::array<coquic::quic::Frame, 2>{coquic::quic::PingFrame{}, coquic::quic::CryptoFrame{}},
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(handshake.has_value());
}

TEST(QuicCoreTest, ProcessInboundPacketLeavesInitialAndHandshakeStateUntouchedOnFailure) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    const auto initial_failure = connection.process_inbound_packet(
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
    const auto handshake_failure = connection.process_inbound_packet(
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

TEST(QuicCoreTest, ConnectionProcessInboundApplicationCoversAckReorderAndErrorBranches) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto ack_and_padding = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 3>{
            coquic::quic::AckFrame{},
            coquic::quic::PaddingFrame{.length = 2},
            coquic::quic::test::make_inbound_application_stream_frame("ok"),
        },
        coquic::quic::test::test_time());
    ASSERT_TRUE(ack_and_padding.has_value());
    const auto first_received = connection.take_received_stream_data();
    ASSERT_TRUE(first_received.has_value());
    if (!first_received.has_value()) {
        return;
    }
    EXPECT_EQ(coquic::quic::test::string_from_bytes(first_received.value().bytes), "ok");

    const auto reordered = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("x", 4),
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(reordered.has_value());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    const auto gap_filled = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("yz", 2),
        },
        coquic::quic::test::test_time(2));
    ASSERT_TRUE(gap_filled.has_value());
    const auto gap_filled_received = connection.take_received_stream_data();
    ASSERT_TRUE(gap_filled_received.has_value());
    if (!gap_filled_received.has_value()) {
        return;
    }
    EXPECT_EQ(coquic::quic::test::string_from_bytes(gap_filled_received.value().bytes), "yzx");

    const auto overflow = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("x", std::uint64_t{1} << 62),
        },
        coquic::quic::test::test_time(3));
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto missing_offset_value = connection.process_inbound_application(
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

    const auto invalid_packet = coquic::quic::serialize_protected_datagram(
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

    const auto packet = coquic::quic::serialize_protected_datagram(
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

    const auto to_server =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto to_client = coquic::quic::test::relay_send_datagrams_to_peer(
        to_server, server, coquic::quic::test::test_time(1));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(to_client).empty());

    const auto client_handshake = coquic::quic::test::relay_send_datagrams_to_peer(
        to_client, client, coquic::quic::test::test_time(2));
    EXPECT_FALSE(client.has_failed());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(client_handshake).empty());
    ASSERT_NE(client.connection_, nullptr);
    EXPECT_FALSE(client.connection_->initial_space_.read_secret.has_value());
    EXPECT_FALSE(client.connection_->initial_space_.write_secret.has_value());

    const auto replayed = coquic::quic::test::relay_send_datagrams_to_peer(
        to_client, client, coquic::quic::test::test_time(3));

    EXPECT_FALSE(client.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(replayed).empty());
}

TEST(QuicCoreTest, ProcessCapturedQuicGoServerInitialInstallsHandshakeSecrets) {
    auto config = coquic::quic::test::make_client_core_config();
    config.source_connection_id = bytes_from_hex("c100000000000025");
    config.initial_destination_connection_id = bytes_from_hex("8300000000000024");

    coquic::quic::QuicConnection connection(config);
    connection.start_client_if_needed();
    ASSERT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());

    const auto server_first_flight = bytes_from_hex(
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

    const auto initial_packet_bytes = std::span<const std::byte>(server_first_flight).first(482);
    const auto handshake_packet_bytes =
        std::span<const std::byte>(server_first_flight).subspan(482, 747);
    const auto initial_decode = coquic::quic::deserialize_protected_datagram(
        initial_packet_bytes,
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id = config.initial_destination_connection_id,
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

    const auto handshake_with_official_server_secret = coquic::quic::deserialize_protected_datagram(
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
        });
    ASSERT_TRUE(handshake_with_official_server_secret.has_value());
    ASSERT_FALSE(handshake_with_official_server_secret.value().empty());
    ASSERT_TRUE(std::holds_alternative<coquic::quic::ProtectedHandshakePacket>(
        handshake_with_official_server_secret.value().front()));

    // The client handshake secrets are derived from an ephemeral key share, so a captured server
    // flight only stays stable through the Initial packet. Verify those stable Initial-packet
    // properties here, and keep the captured Handshake packet as a fixed codec vector above.
    connection.process_inbound_datagram(initial_packet_bytes, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_hex("c516a356"));
    ASSERT_TRUE(connection.handshake_space_.write_secret.has_value());

    const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(response.empty());

    const auto packets = decode_sender_datagram(connection, response);
    const auto initial_packet =
        std::find_if(packets.begin(), packets.end(), [](const auto &packet) {
            return std::holds_alternative<coquic::quic::ProtectedInitialPacket>(packet);
        });

    EXPECT_NE(initial_packet, packets.end());
    EXPECT_FALSE(connection.initial_packet_space_discarded_);
}

TEST(QuicCoreTest, ProcessInboundDatagramDropsOneRttPacketWithoutReadSecret) {
    coquic::quic::QuicConnection connection(make_connected_client_connection());
    const auto one_rtt_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51});
    connection.application_space_.read_secret.reset();

    const auto packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 0,
                .frames =
                    {
                        coquic::quic::test::make_inbound_application_stream_frame(
                            "missing-read-secret-packet"),
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = std::nullopt,
            .one_rtt_secret = one_rtt_secret,
        });
    ASSERT_TRUE(packet.has_value()) << static_cast<int>(packet.error().code);

    connection.process_inbound_datagram(packet.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::connected);
}

TEST(QuicCoreTest, ServerProcessesBufferedOneRttDataAfterHandshakeKeysArrive) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto to_server =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto to_client = coquic::quic::test::relay_send_datagrams_to_peer(
        to_server, server, coquic::quic::test::test_time(1));
    const auto client_handshake = coquic::quic::test::relay_send_datagrams_to_peer(
        to_client, client, coquic::quic::test::test_time(2));

    const auto request = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("buffer-me"),
            .fin = true,
        },
        coquic::quic::test::test_time(3));

    const auto handshake_datagrams = coquic::quic::test::send_datagrams_from(client_handshake);
    const auto request_datagrams = coquic::quic::test::send_datagrams_from(request);
    ASSERT_FALSE(handshake_datagrams.empty());
    ASSERT_FALSE(request_datagrams.empty());

    const auto find_packet_datagram_index = [&](std::span<const std::vector<std::byte>> datagrams,
                                                auto matches_packet) -> std::optional<std::size_t> {
        for (std::size_t index = 0; index < datagrams.size(); ++index) {
            const auto packets = decode_sender_datagram(*client.connection_, datagrams[index]);
            for (const auto &packet : packets) {
                if (matches_packet(packet)) {
                    return index;
                }
            }
        }

        return std::nullopt;
    };

    const auto handshake_datagram_index =
        find_packet_datagram_index(handshake_datagrams, [](const auto &packet) {
            return std::holds_alternative<coquic::quic::ProtectedHandshakePacket>(packet);
        });
    const auto one_rtt_datagram_index =
        find_packet_datagram_index(request_datagrams, [](const auto &packet) {
            return std::holds_alternative<coquic::quic::ProtectedOneRttPacket>(packet);
        });
    ASSERT_TRUE(handshake_datagram_index.has_value());
    ASSERT_TRUE(one_rtt_datagram_index.has_value());
    const auto handshake_index = optional_value_or_terminate(handshake_datagram_index);
    const auto one_rtt_index = optional_value_or_terminate(one_rtt_datagram_index);

    const auto server_before_keys = coquic::quic::test::relay_nth_send_datagram_to_peer(
        request, one_rtt_index, server, coquic::quic::test::test_time(4));
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(server_before_keys).empty());
    EXPECT_FALSE(server.has_failed());

    const auto server_after_keys = coquic::quic::test::relay_nth_send_datagram_to_peer(
        client_handshake, handshake_index, server, coquic::quic::test::test_time(5));
    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(server_after_keys)),
              "buffer-me");
    EXPECT_FALSE(server.has_failed());
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
    connection.process_inbound_datagram(valid_packet.value(), coquic::quic::test::test_time());

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramResyncsHandshakeStateBeforeOneRttControls) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    auto &connection = *client.connection_;
    ASSERT_TRUE(connection.tls_.has_value());
    if (!connection.tls_.has_value()) {
        return;
    }
    auto &tls = connection.tls_.value();
    ASSERT_TRUE(tls.handshake_complete());
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    ASSERT_TRUE(connection.peer_transport_parameters_validated_);

    connection.status_ = coquic::quic::HandshakeStatus::in_progress;

    const auto
        control_packet =
            coquic::quic::serialize_protected_datagram(
                std::array<coquic::quic::ProtectedPacket, 1>{
                    coquic::quic::ProtectedOneRttPacket{
                        .destination_connection_id = connection.config_.source_connection_id,
                        .packet_number_length = 2,
                        .packet_number = 0,
                        .frames =
                            {
                                coquic::quic::NewConnectionIdFrame{
                                    .sequence_number = 1,
                                    .retire_prior_to = 0,
                                    .connection_id = bytes_from_ints({0x12, 0x34, 0x56, 0x78}),
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
                            },
                    },
                },
                coquic::quic::SerializeProtectionContext{
                    .local_role = coquic::quic::EndpointRole::server,
                    .client_initial_destination_connection_id =
                        connection.client_initial_destination_connection_id(),
                    .handshake_secret = connection.handshake_space_.read_secret,
                    .one_rtt_secret = connection.application_space_.read_secret,
                });
    ASSERT_TRUE(control_packet.has_value());

    connection.process_inbound_datagram(control_packet.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::connected);
}

TEST(QuicCoreTest, ProcessInboundDatagramPromotesApplicationKeysOnPeerKeyUpdate) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    if (!connection.application_space_.read_secret.has_value()) {
        return;
    }
    const auto &current_read_secret = connection.application_space_.read_secret.value();

    const auto next_read_secret = coquic::quic::derive_next_traffic_secret(current_read_secret);
    ASSERT_TRUE(next_read_secret.has_value());
    const auto &next_read_secret_value = next_read_secret.value();

    const auto updated_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = true,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 100,
                .frames =
                    {
                        coquic::quic::StreamFrame{
                            .fin = false,
                            .has_offset = false,
                            .has_length = true,
                            .stream_id = 0,
                            .offset = std::nullopt,
                            .stream_data = bytes_from_ints({0x61}),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = std::nullopt,
            .one_rtt_secret = next_read_secret_value,
            .one_rtt_key_phase = true,
        });
    ASSERT_TRUE(updated_packet.has_value());

    connection.process_inbound_datagram(updated_packet.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    if (!connection.application_space_.read_secret.has_value()) {
        return;
    }
    const auto &promoted_read_secret = connection.application_space_.read_secret.value();
    EXPECT_EQ(promoted_read_secret.secret, next_read_secret_value.secret);

    const auto outbound = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(outbound.empty());
    const auto write_secret = connection.application_space_.write_secret;
    ASSERT_TRUE(write_secret.has_value());
    const auto decoded = coquic::quic::deserialize_protected_datagram(
        outbound, coquic::quic::DeserializeProtectionContext{
                      .peer_role = connection.config_.role,
                      .client_initial_destination_connection_id =
                          connection.client_initial_destination_connection_id(),
                      .one_rtt_secret = write_secret,
                      .one_rtt_key_phase = true,
                      .largest_authenticated_application_packet_number =
                          connection.application_space_.largest_authenticated_packet_number,
                      .one_rtt_destination_connection_id_length =
                          connection.outbound_destination_connection_id().size(),
                  });
    ASSERT_TRUE(decoded.has_value());
    ASSERT_FALSE(decoded.value().empty());
    const auto *one_rtt =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded.value().front());
    ASSERT_NE(one_rtt, nullptr);
    EXPECT_TRUE(one_rtt->key_phase);
}

TEST(QuicCoreTest, KeyUpdatedAckOnlyPacketRetiresAckedApplicationFragment) {
    auto connection = make_connected_server_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;

    std::vector<std::byte> payload(150000, std::byte{0x61});
    stream.send_buffer.append(payload);
    static_cast<void>(stream.send_buffer.take_ranges(payload.size()));

    constexpr std::uint64_t fragment_offset = 140720;
    constexpr std::size_t fragment_length = 1173;
    const auto fragment_begin = payload.begin() + static_cast<std::ptrdiff_t>(fragment_offset);
    const auto fragment_end = fragment_begin + static_cast<std::ptrdiff_t>(fragment_length);
    const auto fragment_bytes = std::vector<std::byte>(fragment_begin, fragment_end);

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 124,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments =
                                         {
                                             coquic::quic::StreamFrameSendFragment{
                                                 .stream_id = 0,
                                                 .offset = fragment_offset,
                                                 .bytes = fragment_bytes,
                                                 .fin = false,
                                                 .consumes_flow_control = false,
                                             },
                                         },
                                 });

    connection.application_space_.largest_authenticated_packet_number = 59;

    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    const auto next_read_secret = coquic::quic::derive_next_traffic_secret(
        optional_ref_or_terminate(connection.application_space_.read_secret));
    ASSERT_TRUE(next_read_secret.has_value());

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = true,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 60,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 125,
                            .first_ack_range = 4,
                            .additional_ranges =
                                {
                                    coquic::quic::AckRange{
                                        .gap = 1,
                                        .range_length = 5,
                                    },
                                },
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = next_read_secret.value(),
            .one_rtt_key_phase = true,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.application_space_.sent_packets.contains(124));
    EXPECT_FALSE(stream.send_buffer.has_outstanding_range(fragment_offset, fragment_length));
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

TEST(QuicCoreTest, ServerHandshakeStatusUpdateDoesNotConfirmHandshakeEarly) {
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
    connection.handshake_space_.sent_packets.emplace(
        9, coquic::quic::SentPacketRecord{
               .packet_number = 9,
               .sent_time = coquic::quic::test::test_time(1),
               .ack_eliciting = true,
               .in_flight = true,
               .has_ping = true,
           });

    connection.update_handshake_status();

    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::connected);
    EXPECT_EQ(connection.handshake_done_state_, coquic::quic::StreamControlFrameState::pending);
    EXPECT_FALSE(connection.handshake_confirmed_);
    EXPECT_TRUE(connection.handshake_space_.read_secret.has_value());
    EXPECT_TRUE(connection.handshake_space_.write_secret.has_value());
    EXPECT_EQ(connection.handshake_space_.sent_packets.size(), 1u);
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

TEST(QuicCoreTest, ConnectionHelperMethodsCoverRemainingStreamOpenAndFlowControlBranches) {
    coquic::quic::QuicConnection receive_window(coquic::quic::test::make_client_core_config());
    receive_window.connection_flow_control_.advertised_max_data = 5;
    receive_window.connection_flow_control_.delivered_bytes = 5;
    receive_window.connection_flow_control_.local_receive_window = 0;
    receive_window.maybe_refresh_connection_receive_credit(/*force=*/false);
    EXPECT_FALSE(receive_window.connection_flow_control_.pending_max_data_frame.has_value());

    receive_window.connection_flow_control_.local_receive_window = 1;
    receive_window.maybe_refresh_connection_receive_credit(/*force=*/false);
    ASSERT_TRUE(receive_window.connection_flow_control_.pending_max_data_frame.has_value());
    if (receive_window.connection_flow_control_.pending_max_data_frame.has_value()) {
        EXPECT_EQ(receive_window.connection_flow_control_.pending_max_data_frame->maximum_data, 6u);
    }

    auto &stream = receive_window.streams_
                       .emplace(0, coquic::quic::make_implicit_stream_state(
                                       /*stream_id=*/0, receive_window.config_.role))
                       .first->second;
    receive_window.initialize_stream_flow_control(stream);
    stream.flow_control.advertised_max_stream_data = 4;
    stream.flow_control.delivered_bytes = 4;
    stream.flow_control.local_receive_window = 1;
    receive_window.maybe_refresh_stream_receive_credit(stream, /*force=*/false);
    ASSERT_TRUE(stream.flow_control.pending_max_stream_data_frame.has_value());
    if (stream.flow_control.pending_max_stream_data_frame.has_value()) {
        EXPECT_EQ(stream.flow_control.pending_max_stream_data_frame->maximum_stream_data, 5u);
    }

    coquic::quic::QuicConnection no_peer_params(coquic::quic::test::make_client_core_config());
    no_peer_params.initialize_peer_flow_control_from_transport_parameters();
    EXPECT_EQ(no_peer_params.connection_flow_control_.peer_max_data, 0u);

    coquic::quic::QuicConnection peer_flow(coquic::quic::test::make_client_core_config());
    auto &existing = peer_flow.streams_
                         .emplace(0, coquic::quic::make_implicit_stream_state(
                                         /*stream_id=*/0, peer_flow.config_.role))
                         .first->second;
    peer_flow.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_max_data = 99,
        .initial_max_stream_data_bidi_local = 7,
        .initial_max_stream_data_bidi_remote = 8,
        .initial_max_stream_data_uni = 9,
        .initial_max_streams_bidi = 1,
        .initial_max_streams_uni = 2,
        .initial_source_connection_id = coquic::quic::ConnectionId{std::byte{0x01}},
    };
    peer_flow.initialize_peer_flow_control_from_transport_parameters();
    EXPECT_EQ(peer_flow.connection_flow_control_.peer_max_data, 99u);
    EXPECT_EQ(existing.send_flow_control_limit, 8u);
    EXPECT_EQ(existing.receive_flow_control_limit, peer_flow.initial_stream_receive_window(0));

    const auto existing_local = peer_flow.get_or_open_local_stream(/*stream_id=*/0);
    ASSERT_TRUE(existing_local.has_value());
    EXPECT_EQ(existing_local.value(), &existing);

    const auto invalid_peer_bidi = peer_flow.get_or_open_local_stream(/*stream_id=*/1);
    ASSERT_FALSE(invalid_peer_bidi.has_value());
    EXPECT_EQ(invalid_peer_bidi.error().code,
              coquic::quic::StreamStateErrorCode::invalid_stream_id);

    const auto invalid_peer_uni = peer_flow.get_or_open_local_stream(/*stream_id=*/3);
    ASSERT_FALSE(invalid_peer_uni.has_value());
    EXPECT_EQ(invalid_peer_uni.error().code,
              coquic::quic::StreamStateErrorCode::invalid_stream_direction);

    coquic::quic::QuicConnection stream_open(coquic::quic::test::make_client_core_config());
    const auto missing_receive = stream_open.get_existing_receive_stream(/*stream_id=*/0);
    ASSERT_FALSE(missing_receive.has_value());
    EXPECT_EQ(missing_receive.error().code, coquic::quic::StreamStateErrorCode::invalid_stream_id);

    const auto send_only_receive = stream_open.get_or_open_receive_stream(/*stream_id=*/2);
    ASSERT_FALSE(send_only_receive.has_value());
    EXPECT_EQ(send_only_receive.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    stream_open.local_transport_parameters_.initial_max_streams_bidi = 1;
    const auto over_limit_receive = stream_open.get_or_open_receive_stream(/*stream_id=*/9);
    ASSERT_FALSE(over_limit_receive.has_value());
    EXPECT_EQ(over_limit_receive.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto over_limit_send = stream_open.get_or_open_send_stream(/*stream_id=*/9);
    ASSERT_FALSE(over_limit_send.has_value());
    EXPECT_EQ(over_limit_send.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    coquic::quic::QuicConnection blocked(coquic::quic::test::make_client_core_config());
    auto &blocked_stream = blocked.streams_
                               .emplace(0, coquic::quic::make_implicit_stream_state(
                                               /*stream_id=*/0, blocked.config_.role))
                               .first->second;
    blocked_stream.send_flow_control_committed = 6;
    blocked.connection_flow_control_.peer_max_data = 5;
    blocked.connection_flow_control_.highest_sent = 5;
    blocked.maybe_queue_connection_blocked_frame();
    ASSERT_TRUE(blocked.connection_flow_control_.pending_data_blocked_frame.has_value());
    if (blocked.connection_flow_control_.pending_data_blocked_frame.has_value()) {
        EXPECT_EQ(blocked.connection_flow_control_.pending_data_blocked_frame->maximum_data, 5u);
    }

    coquic::quic::QuicConnection failed_commands(coquic::quic::test::make_client_core_config());
    failed_commands.status_ = coquic::quic::HandshakeStatus::failed;
    EXPECT_TRUE(failed_commands.queue_stream_reset({.stream_id = 0, .application_error_code = 1})
                    .has_value());
    EXPECT_TRUE(failed_commands.queue_stop_sending({.stream_id = 0, .application_error_code = 1})
                    .has_value());

    coquic::quic::QuicConnection validation_commands(coquic::quic::test::make_client_core_config());
    validation_commands.status_ = coquic::quic::HandshakeStatus::connected;
    auto &reset_stream = validation_commands.streams_
                             .emplace(0, coquic::quic::make_implicit_stream_state(
                                             /*stream_id=*/0, validation_commands.config_.role))
                             .first->second;
    reset_stream.send_fin_state = coquic::quic::StreamSendFinState::acknowledged;
    const auto reset_result =
        validation_commands.queue_stream_reset({.stream_id = 0, .application_error_code = 7});
    ASSERT_FALSE(reset_result.has_value());
    EXPECT_EQ(reset_result.error().code, coquic::quic::StreamStateErrorCode::send_side_closed);

    validation_commands.streams_.emplace(2, coquic::quic::make_implicit_stream_state(
                                                /*stream_id=*/2, validation_commands.config_.role));
    const auto stop_result =
        validation_commands.queue_stop_sending({.stream_id = 2, .application_error_code = 9});
    ASSERT_FALSE(stop_result.has_value());
    EXPECT_EQ(stop_result.error().code,
              coquic::quic::StreamStateErrorCode::invalid_stream_direction);
}

TEST(QuicCoreTest, ConnectionProcessInboundApplicationCoversRemainingValidationBranches) {
    auto flow_overflow = make_connected_client_connection();
    flow_overflow.connection_flow_control_.advertised_max_data = 0;
    const auto overflow = flow_overflow.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("x"),
        },
        coquic::quic::test::test_time());
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

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
    const auto contiguous_failure = buffer_failure.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("xy",
                                                                      (std::uint64_t{1} << 62) - 1),
        },
        coquic::quic::test::test_time(1));
    ASSERT_FALSE(contiguous_failure.has_value());
    EXPECT_EQ(contiguous_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    coquic::quic::QuicConnection gating(coquic::quic::test::make_client_core_config());
    gating.status_ = coquic::quic::HandshakeStatus::in_progress;
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
        const auto gated = gating.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{frame}, coquic::quic::test::test_time(2));
        ASSERT_FALSE(gated.has_value());
        EXPECT_EQ(gated.error().code, coquic::quic::CodecErrorCode::invalid_varint);
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
        const auto accepted = preconnected_controls.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{frame}, coquic::quic::test::test_time(2));
        ASSERT_TRUE(accepted.has_value());
    }

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
    const auto connected_controls = connected.process_inbound_application(
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
        coquic::quic::test::test_time(3));
    ASSERT_TRUE(connected_controls.has_value());
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
    const auto max_stream_data_failure = invalid_max_stream_data.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::MaxStreamDataFrame{
                .stream_id = 3,
                .maximum_stream_data = 1,
            },
        },
        coquic::quic::test::test_time(4));
    ASSERT_FALSE(max_stream_data_failure.has_value());
    EXPECT_EQ(max_stream_data_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto invalid_stream_data_blocked = make_connected_client_connection();
    const auto stream_data_blocked_failure =
        invalid_stream_data_blocked.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{
                coquic::quic::StreamDataBlockedFrame{
                    .stream_id = 2,
                    .maximum_stream_data = 1,
                },
            },
            coquic::quic::test::test_time(5));
    ASSERT_FALSE(stream_data_blocked_failure.has_value());
    EXPECT_EQ(stream_data_blocked_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_varint);

    auto reset_conflict = make_connected_client_connection();
    auto &conflict_stream = reset_conflict.streams_
                                .emplace(0, coquic::quic::make_implicit_stream_state(
                                                /*stream_id=*/0, reset_conflict.config_.role))
                                .first->second;
    reset_conflict.initialize_stream_flow_control(conflict_stream);
    conflict_stream.highest_received_offset = 6;
    const auto reset_failure = reset_conflict.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::ResetStreamFrame{
                .stream_id = 0,
                .application_protocol_error_code = 1,
                .final_size = 5,
            },
        },
        coquic::quic::test::test_time(6));
    ASSERT_FALSE(reset_failure.has_value());
    EXPECT_EQ(reset_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);
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

TEST(QuicCoreTest, InboundFlowControlFramesDoNotRefreshOrClearWhenLimitsStillDoNotAllowProgress) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("abcdefghij"), false)
            .has_value());
    connection.connection_flow_control_.peer_max_data = 4;
    connection.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 4};
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::sent;

    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::MaxDataFrame{
            .maximum_data = 6,
        }},
        /*packet_number=*/1));
    ASSERT_TRUE(connection.connection_flow_control_.pending_data_blocked_frame.has_value());
    EXPECT_EQ(connection.connection_flow_control_.data_blocked_state,
              coquic::quic::StreamControlFrameState::sent);

    connection.connection_flow_control_.advertised_max_data = 10;
    connection.connection_flow_control_.delivered_bytes = 8;
    connection.connection_flow_control_.local_receive_window = 4;
    connection.connection_flow_control_.pending_max_data_frame = std::nullopt;

    const auto receive_stream = connection.get_or_open_receive_stream(/*stream_id=*/1);
    ASSERT_TRUE(receive_stream.has_value());
    auto *stream = receive_stream.value();
    stream->flow_control.advertised_max_stream_data = 9;
    stream->flow_control.delivered_bytes = 8;
    stream->flow_control.local_receive_window = 4;
    stream->flow_control.pending_max_stream_data_frame = std::nullopt;

    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {
            coquic::quic::DataBlockedFrame{.maximum_data = 9},
            coquic::quic::StreamDataBlockedFrame{
                .stream_id = 1,
                .maximum_stream_data = 8,
            },
        },
        /*packet_number=*/2));
    EXPECT_FALSE(connection.connection_flow_control_.pending_max_data_frame.has_value());
    EXPECT_FALSE(stream->flow_control.pending_max_stream_data_frame.has_value());
}

TEST(QuicCoreTest, ConnectionPersistentCongestionPathsAreExercised) {
    auto detect_connection = make_connected_client_connection();
    detect_connection.application_space_.recovery.largest_acked_packet_number_ = 5;
    auto &detect_rtt = detect_connection.application_space_.recovery.rtt_state();
    detect_rtt.latest_rtt = std::chrono::milliseconds(10);
    detect_rtt.min_rtt = std::chrono::milliseconds(10);
    detect_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    detect_rtt.rttvar = std::chrono::milliseconds(1);
    const auto initial_window = detect_connection.congestion_controller_.congestion_window();
    detect_connection.track_sent_packet(detect_connection.application_space_,
                                        coquic::quic::SentPacketRecord{
                                            .packet_number = 1,
                                            .sent_time = coquic::quic::test::test_time(0),
                                            .ack_eliciting = true,
                                            .in_flight = true,
                                            .bytes_in_flight = 1200,
                                        });
    detect_connection.track_sent_packet(detect_connection.application_space_,
                                        coquic::quic::SentPacketRecord{
                                            .packet_number = 2,
                                            .sent_time = coquic::quic::test::test_time(200),
                                            .ack_eliciting = true,
                                            .in_flight = true,
                                            .bytes_in_flight = 1200,
                                        });

    detect_connection.detect_lost_packets(detect_connection.application_space_,
                                          coquic::quic::test::test_time(250));

    EXPECT_LT(detect_connection.congestion_controller_.congestion_window(), initial_window);
    EXPECT_EQ(detect_connection.congestion_controller_.congestion_window(),
              detect_connection.congestion_controller_.minimum_window());

    coquic::quic::QuicConnection ack_connection(coquic::quic::test::make_client_core_config());
    ack_connection.status_ = coquic::quic::HandshakeStatus::connected;
    auto &ack_rtt = ack_connection.application_space_.recovery.rtt_state();
    ack_rtt.latest_rtt = std::chrono::milliseconds(10);
    ack_rtt.min_rtt = std::chrono::milliseconds(10);
    ack_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    ack_rtt.rttvar = std::chrono::milliseconds(1);
    const auto ack_initial_window = ack_connection.congestion_controller_.congestion_window();
    ack_connection.track_sent_packet(ack_connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 1,
                                         .sent_time = coquic::quic::test::test_time(0),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
    ack_connection.track_sent_packet(ack_connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 2,
                                         .sent_time = coquic::quic::test::test_time(200),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
    ack_connection.track_sent_packet(ack_connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 3,
                                         .sent_time = coquic::quic::test::test_time(350),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
    ack_connection.track_sent_packet(ack_connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 5,
                                         .sent_time = coquic::quic::test::test_time(400),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });

    const auto processed = ack_connection.process_inbound_ack(
        ack_connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 5,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(400), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_LT(ack_connection.congestion_controller_.congestion_window(), ack_initial_window / 2);
    EXPECT_GE(ack_connection.congestion_controller_.congestion_window(),
              ack_connection.congestion_controller_.minimum_window());
}

TEST(QuicCoreTest, LossDetectionSkipsCongestionResponseForNonAckElicitingLoss) {
    auto connection = make_connected_client_connection();
    connection.application_space_.recovery.largest_acked_packet_number_ = 5;
    auto &rtt = connection.application_space_.recovery.rtt_state();
    rtt.latest_rtt = std::chrono::milliseconds(10);
    rtt.min_rtt = std::chrono::milliseconds(10);
    rtt.smoothed_rtt = std::chrono::milliseconds(10);
    rtt.rttvar = std::chrono::milliseconds(1);
    const auto initial_window = connection.congestion_controller_.congestion_window();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = false,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });

    connection.detect_lost_packets(connection.application_space_,
                                   coquic::quic::test::test_time(800));

    EXPECT_EQ(connection.congestion_controller_.congestion_window(), initial_window);
}

TEST(QuicCoreTest, LossDetectionUsesDefaultAckDelayButRequiresRttSampleForPersistentCongestion) {
    auto connection = make_connected_client_connection();
    connection.peer_transport_parameters_ = std::nullopt;
    connection.application_space_.recovery.largest_acked_packet_number_ = 5;
    auto &rtt = connection.application_space_.recovery.rtt_state();
    rtt.min_rtt = std::chrono::milliseconds(10);
    rtt.smoothed_rtt = std::chrono::milliseconds(10);
    rtt.rttvar = std::chrono::milliseconds(1);
    const auto initial_window = connection.congestion_controller_.congestion_window();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(700),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });

    connection.detect_lost_packets(connection.application_space_,
                                   coquic::quic::test::test_time(1200));

    EXPECT_LT(connection.congestion_controller_.congestion_window(), initial_window);
    EXPECT_GT(connection.congestion_controller_.congestion_window(),
              connection.congestion_controller_.minimum_window());
}

TEST(QuicCoreTest, LossDetectionSkipsNonAckElicitingPacketsForPersistentCongestionWindow) {
    auto connection = make_connected_client_connection();
    connection.application_space_.recovery.largest_acked_packet_number_ = 5;
    auto &rtt = connection.application_space_.recovery.rtt_state();
    rtt.latest_rtt = std::chrono::milliseconds(10);
    rtt.min_rtt = std::chrono::milliseconds(10);
    rtt.smoothed_rtt = std::chrono::milliseconds(10);
    rtt.rttvar = std::chrono::milliseconds(1);
    const auto initial_window = connection.congestion_controller_.congestion_window();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = false,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(200),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });

    connection.detect_lost_packets(connection.application_space_,
                                   coquic::quic::test::test_time(250));

    EXPECT_LT(connection.congestion_controller_.congestion_window(), initial_window);
    EXPECT_GT(connection.congestion_controller_.congestion_window(),
              connection.congestion_controller_.minimum_window());
}

TEST(QuicCoreTest, LateAckOfDeclaredLostRetransmissionRetiresApplicationFragment) {
    auto connection = make_connected_client_connection();
    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);

    const auto payload = std::vector<std::byte>(4096, std::byte{0x5a});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(0));
    ASSERT_FALSE(first_datagram.empty());

    const auto first_packet_number = connection.application_space_.sent_packets.begin()->first;
    const auto first_packet = connection.application_space_.sent_packets.at(first_packet_number);
    ASSERT_FALSE(first_packet.stream_fragments.empty());
    const auto &tracked_fragment = first_packet.stream_fragments.front();
    const auto tracked_offset = tracked_fragment.offset;
    const auto tracked_length = tracked_fragment.bytes.size();

    auto &rtt = connection.application_space_.recovery.rtt_state();
    rtt.latest_rtt = std::chrono::milliseconds(10);
    rtt.min_rtt = std::chrono::milliseconds(10);
    rtt.smoothed_rtt = std::chrono::milliseconds(10);
    rtt.rttvar = std::chrono::milliseconds(1);

    connection.application_space_.recovery.largest_acked_packet_number_ = first_packet_number + 5;
    connection.detect_lost_packets(connection.application_space_,
                                   coquic::quic::test::test_time(20));
    ASSERT_TRUE(connection.streams_.at(0).send_buffer.has_lost_data());

    const auto retransmit_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(21));
    ASSERT_FALSE(retransmit_datagram.empty());

    const auto retransmit_packet_number =
        std::prev(connection.application_space_.sent_packets.end())->first;
    ASSERT_GT(retransmit_packet_number, first_packet_number);
    const auto retransmit_packet =
        connection.application_space_.sent_packets.at(retransmit_packet_number);
    ASSERT_FALSE(retransmit_packet.stream_fragments.empty());
    EXPECT_EQ(retransmit_packet.stream_fragments.front().offset, tracked_offset);
    EXPECT_EQ(retransmit_packet.stream_fragments.front().bytes.size(), tracked_length);

    connection.application_space_.recovery.largest_acked_packet_number_ =
        retransmit_packet_number + 5;
    connection.detect_lost_packets(connection.application_space_,
                                   coquic::quic::test::test_time(41));

    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = retransmit_packet_number,
                                             .first_ack_range = 0,
                                         },
                                         coquic::quic::test::test_time(42),
                                         peer_transport_parameters.ack_delay_exponent,
                                         peer_transport_parameters.max_ack_delay,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    EXPECT_FALSE(connection.streams_.at(0).send_buffer.has_outstanding_range(tracked_offset,
                                                                             tracked_length));

    const auto next_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(43));
    ASSERT_FALSE(next_datagram.empty());
    const auto next_packets = decode_sender_datagram(connection, next_datagram);
    ASSERT_EQ(next_packets.size(), 1u);
    const auto *next_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&next_packets.front());
    ASSERT_NE(next_application, nullptr);

    for (const auto &frame : next_application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        EXPECT_NE(optional_value_or_terminate(stream->offset), tracked_offset);
    }
}

} // namespace
