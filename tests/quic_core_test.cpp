#include <array>

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

TEST(QuicCoreTest, ArmPtoProbeReturnsWhenNoPacketSpaceIsDue) {
    auto connection = make_connected_client_connection();

    connection.arm_pto_probe(coquic::quic::test::test_time(10));

    EXPECT_EQ(connection.pto_count_, 0u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ArmPtoProbeDefersApplicationProbeWhenSendDataIsAlreadyPending) {
    auto connection = make_connected_client_connection();
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
                        .bytes = coquic::quic::test::bytes_from_string("probe-me"),
                        .fin = false,
                    },
                },
        });
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("queued"), false)
            .has_value());

    connection.arm_pto_probe(coquic::quic::test::test_time(999));

    EXPECT_EQ(connection.pto_count_, 1u);
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
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

TEST(QuicCoreTest, ArmPtoProbeComparesCandidatesWithinAndAcrossPacketSpaces) {
    auto connection = make_connected_client_connection();

    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(2),
                                     .ack_eliciting = true,
                                     .in_flight = false,
                                     .has_ping = true,
                                 });
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

    connection.arm_pto_probe(coquic::quic::test::test_time(1000));

    EXPECT_EQ(connection.pto_count_, 1u);
    if (!connection.handshake_space_.pending_probe_packet.has_value()) {
        GTEST_FAIL() << "expected handshake PTO probe packet";
        return;
    }
    EXPECT_EQ(connection.handshake_space_.pending_probe_packet->packet_number, 10u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
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

TEST(QuicCoreTest, ApplicationProbePathFailsWhenAckTrimCannotFitDatagram) {
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

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenProbePayloadExceedsDatagramBudget) {
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

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
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
    coquic::quic::QuicConnection connection(std::move(config));
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
        std::array<coquic::quic::Frame, 1>{coquic::quic::PingFrame{}},
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

TEST(QuicCoreTest, ProcessInboundPacketLeavesInitialAndHandshakeStateUntouchedOnFailure) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    const auto initial_failure = connection.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .version = 1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = {std::byte{0xaa}},
            .packet_number_length = 2,
            .packet_number = 0,
            .frames = {coquic::quic::PingFrame{}},
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
            .frames = {coquic::quic::PingFrame{}},
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
    packet_failure.process_inbound_datagram(invalid_packet.value(),
                                            coquic::quic::test::test_time(1));
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
    connection.process_inbound_datagram(valid_packet.value(), coquic::quic::test::test_time());

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

} // namespace
