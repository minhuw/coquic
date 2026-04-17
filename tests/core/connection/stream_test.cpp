#include <array>

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <type_traits>

#include "src/quic/connection_test_hooks.h"
#include "src/quic/packet_crypto_test_hooks.h"
#include "src/quic/protected_codec.h"
#include "src/quic/protected_codec_test_hooks.h"
#include "src/quic/tls_adapter_quictls_test_hooks.h"
#include "src/quic/varint.h"
#include "src/quic/qlog/types.h"
#include "tests/support/core/connection_test_fixtures.h"
#include "tests/support/quic_test_utils.h"
#include "src/http3/http3.h"
#include "src/quic/qlog/session.h"

namespace coquic::quic {
CodecResult<TrafficSecret> derive_next_traffic_secret(const TrafficSecret &secret);
}

namespace {
using coquic::quic::test_support::ack_frame_acks_packet_number_for_tests;
using coquic::quic::test_support::application_stream_ids_from_datagram;
using coquic::quic::test_support::bytes_from_hex;
using coquic::quic::test_support::bytes_from_ints;
using coquic::quic::test_support::datagram_has_application_ack;
using coquic::quic::test_support::datagram_has_application_stream;
using coquic::quic::test_support::decode_sender_datagram;
using coquic::quic::test_support::expect_local_error;
using coquic::quic::test_support::find_application_probe_payload_size_that_drops_ack;
using coquic::quic::test_support::find_application_send_payload_size_that_drops_ack;
using coquic::quic::test_support::first_tracked_packet;
using coquic::quic::test_support::invalid_cipher_suite;
using coquic::quic::test_support::last_tracked_packet;
using coquic::quic::test_support::make_connected_client_connection;
using coquic::quic::test_support::make_connected_server_connection;
using coquic::quic::test_support::make_connected_server_connection_with_preferred_address;
using coquic::quic::test_support::make_test_preferred_address;
using coquic::quic::test_support::make_test_traffic_secret;
using coquic::quic::test_support::optional_ref_or_terminate;
using coquic::quic::test_support::optional_value_or_terminate;
using coquic::quic::test_support::protected_datagram_destination_connection_ids;
using coquic::quic::test_support::protected_datagram_packet_kinds;
using coquic::quic::test_support::protected_next_packet_length;
using coquic::quic::test_support::ProtectedPacketKind;
using coquic::quic::test_support::read_u32_be_at;
using coquic::quic::test_support::ScopedEnvVar;
using coquic::quic::test_support::tracked_packet_count;
using coquic::quic::test_support::tracked_packet_or_null;
using coquic::quic::test_support::tracked_packet_or_terminate;
using coquic::quic::test_support::tracked_packet_snapshot;

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

TEST(QuicCoreTest, ServerProcessesOneRttStreamBeforeHandshakeCompletesWhenApplicationKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .key_phase = false,
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 1,
            .packet_number = 7,
            .frames =
                {
                    coquic::quic::StreamFrame{
                        .fin = true,
                        .has_offset = true,
                        .has_length = true,
                        .stream_id = 0,
                        .offset = 0,
                        .stream_data = coquic::quic::test::bytes_from_string("late-handshake"),
                    },
                },
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(processed.has_value());

    const auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    if (!received.has_value()) {
        return;
    }
    const auto &received_stream = *received;
    EXPECT_EQ(received_stream.stream_id, 0u);
    EXPECT_EQ(received_stream.bytes, coquic::quic::test::bytes_from_string("late-handshake"));
    EXPECT_TRUE(received_stream.fin);
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest,
     ProcessInboundDatagramProcessesOneRttStreamBeforeHandshakeCompletesWhenApplicationKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = false,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = 7,
                .frames =
                    {
                        coquic::quic::StreamFrame{
                            .fin = true,
                            .has_offset = true,
                            .has_length = true,
                            .stream_id = 0,
                            .offset = 0,
                            .stream_data = coquic::quic::test::bytes_from_string("late-handshake"),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = optional_ref_or_terminate(connection.application_space_.read_secret),
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    const auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    if (!received.has_value()) {
        return;
    }
    const auto &received_stream = *received;
    EXPECT_EQ(received_stream.stream_id, 0u);
    EXPECT_EQ(received_stream.bytes, coquic::quic::test::bytes_from_string("late-handshake"));
    EXPECT_TRUE(received_stream.fin);
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
}

TEST(QuicCoreTest, ProcessInboundDatagramBuffersOutOfOrderOneRttStreamDataUntilGapCloses) {
    auto connection = make_connected_server_connection();

    const auto make_datagram = [&](std::uint64_t packet_number,
                                   const coquic::quic::StreamFrame &frame) {
        return coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 1,
                    .packet_number = packet_number,
                    .frames = {frame},
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::client,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret =
                    optional_ref_or_terminate(connection.application_space_.read_secret),
            });
    };

    const auto late = make_datagram(
        7, coquic::quic::test::make_inbound_application_stream_frame("lo", 3, 0, true));
    ASSERT_TRUE(late.has_value());
    connection.process_inbound_datagram(late.value(), coquic::quic::test::test_time(1));

    ASSERT_EQ(connection.streams_.at(0).receive_buffer.buffered_bytes_.size(), 1u);
    const auto &buffered = connection.streams_.at(0).receive_buffer.buffered_bytes_.begin()->second;
    EXPECT_EQ(connection.streams_.at(0).receive_buffer.buffered_bytes_.begin()->first, 3u);
    EXPECT_GT(buffered.storage()->size(), buffered.size());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    const auto early = make_datagram(
        8, coquic::quic::test::make_inbound_application_stream_frame("hel", 0, 0, false));
    ASSERT_TRUE(early.has_value());
    connection.process_inbound_datagram(early.value(), coquic::quic::test::test_time(2));

    const auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    EXPECT_EQ(coquic::quic::test::string_from_bytes(received->bytes), "hello");
    EXPECT_TRUE(received->fin);
    EXPECT_TRUE(connection.streams_.at(0).receive_buffer.buffered_bytes_.empty());
}

TEST(
    QuicCoreTest,
    ProcessInboundDatagramProcessesOneRttAckAndStreamBeforeHandshakeCompletesWhenApplicationKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = false,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = 8,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 0,
                            .first_ack_range = 0,
                        },
                        coquic::quic::StreamFrame{
                            .fin = true,
                            .has_offset = true,
                            .has_length = true,
                            .stream_id = 0,
                            .offset = 0,
                            .stream_data = coquic::quic::test::bytes_from_string("late-handshake"),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = optional_ref_or_terminate(connection.application_space_.read_secret),
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    const auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    if (!received.has_value()) {
        return;
    }
    const auto &received_stream = *received;
    EXPECT_EQ(received_stream.stream_id, 0u);
    EXPECT_EQ(received_stream.bytes, coquic::quic::test::bytes_from_string("late-handshake"));
    EXPECT_TRUE(received_stream.fin);
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
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

TEST(QuicCoreTest, ClosedPeerInitiatedBidirectionalStreamRefreshesMaxStreams) {
    auto connection = make_connected_server_connection();
    connection.config_.transport.initial_max_streams_bidi = 1;
    connection.local_transport_parameters_.initial_max_streams_bidi = 1;
    connection.local_stream_limit_state_.initialize(coquic::quic::PeerStreamOpenLimits{
        .bidirectional = 1,
        .unidirectional = connection.local_stream_limit_state_.advertised_max_streams_uni,
    });

    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("GET /one\r\n",
                                                                               /*offset=*/0,
                                                                               /*stream_id=*/0,
                                                                               /*fin=*/true)}));

    auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    const auto received_data = received.value_or(coquic::quic::QuicCoreReceiveStreamData{});
    EXPECT_EQ(received_data.stream_id, 0u);
    EXPECT_TRUE(received_data.fin);

    ASSERT_TRUE(connection.queue_stream_send(0, bytes_from_ints({0x6f, 0x6b}), true).has_value());

    const auto response_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(response_datagram.empty());
    ASSERT_NE(tracked_packet_count(connection.application_space_), 0u);

    const auto response_packet_number =
        first_tracked_packet(connection.application_space_).packet_number;
    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = response_packet_number,
                                             .first_ack_range = 0,
                                         },
                                         coquic::quic::test::test_time(2),
                                         /*ack_delay_exponent=*/3,
                                         /*max_ack_delay_ms=*/25,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    const auto refresh_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(refresh_datagram.empty());

    const auto packets = decode_sender_datagram(connection, refresh_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_max_streams = false;
    for (const auto &frame : application->frames) {
        if (const auto *max_streams = std::get_if<coquic::quic::MaxStreamsFrame>(&frame)) {
            saw_max_streams = true;
            EXPECT_EQ(max_streams->stream_type, coquic::quic::StreamLimitType::bidirectional);
            EXPECT_EQ(max_streams->maximum_streams, 2u);
        }
    }

    EXPECT_TRUE(saw_max_streams);
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

TEST(QuicCoreTest, LocalApplicationCloseQueuesApplicationConnectionCloseFrame) {
    static_assert(std::is_same_v<
                  decltype(std::declval<coquic::quic::QuicConnection &>().queue_application_close(
                      coquic::quic::LocalApplicationCloseCommand{})),
                  coquic::quic::StreamStateResult<bool>>);

    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto closed = client.advance(
        coquic::quic::QuicCoreCloseConnection{
            .application_error_code =
                static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::missing_settings),
            .reason_phrase = "http3 missing settings",
        },
        coquic::quic::test::test_time(1));
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(closed).empty());
    EXPECT_EQ(coquic::quic::test::count_state_change(coquic::quic::test::state_changes_from(closed),
                                                     coquic::quic::QuicCoreStateChange::failed),
              1u);

    bool saw_application_close = false;
    for (const auto &datagram : coquic::quic::test::send_datagrams_from(closed)) {
        for (const auto &packet : decode_sender_datagram(*client.connection_, datagram)) {
            const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (one_rtt == nullptr) {
                continue;
            }

            for (const auto &frame : one_rtt->frames) {
                const auto *close_frame =
                    std::get_if<coquic::quic::ApplicationConnectionCloseFrame>(&frame);
                if (close_frame == nullptr) {
                    continue;
                }

                saw_application_close = true;
                EXPECT_EQ(
                    close_frame->error_code,
                    static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::missing_settings));
                EXPECT_EQ(coquic::quic::test::string_from_bytes(close_frame->reason.bytes),
                          "http3 missing settings");
            }
        }
    }
    EXPECT_TRUE(saw_application_close);
    EXPECT_TRUE(client.has_failed());

    const auto delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        closed, server, coquic::quic::test::test_time(2));
    const auto changes = coquic::quic::test::state_changes_from(delivered);
    EXPECT_EQ(
        coquic::quic::test::count_state_change(changes, coquic::quic::QuicCoreStateChange::failed),
        1u);
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

TEST(QuicCoreTest, TakePeerEffectsReturnNulloptWhenEmptyOrFailed) {
    auto connection = make_connected_client_connection();

    EXPECT_FALSE(connection.take_peer_reset_stream().has_value());
    EXPECT_FALSE(connection.take_peer_stop_sending().has_value());

    connection.pending_peer_stop_effects_.push_back(coquic::quic::QuicCorePeerStopSending{
        .stream_id = 4,
        .application_error_code = 9,
    });
    const auto stop_sending = connection.take_peer_stop_sending();
    ASSERT_TRUE(stop_sending.has_value());
    EXPECT_EQ(optional_ref_or_terminate(stop_sending).stream_id, 4u);

    connection.pending_peer_reset_effects_.push_back(coquic::quic::QuicCorePeerResetStream{
        .stream_id = 8,
        .application_error_code = 3,
        .final_size = 21,
    });
    connection.status_ = coquic::quic::HandshakeStatus::failed;
    EXPECT_FALSE(connection.take_peer_reset_stream().has_value());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresEmptyAndFailedInputs) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.last_inbound_path_id_ = 5;

    connection.process_inbound_datagram({}, coquic::quic::test::test_time(1), /*path_id=*/7);
    EXPECT_EQ(connection.last_inbound_path_id_, 5u);
    EXPECT_FALSE(connection.current_send_path_id_.has_value());

    connection.status_ = coquic::quic::HandshakeStatus::failed;
    connection.process_inbound_datagram(coquic::quic::test::bytes_from_string("x"),
                                        coquic::quic::test::test_time(2), /*path_id=*/9);
    EXPECT_EQ(connection.last_inbound_path_id_, 5u);
    EXPECT_FALSE(connection.current_send_path_id_.has_value());
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
    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);
    const auto first_packet = first_tracked_packet(connection.application_space_);
    ASSERT_EQ(first_packet.reset_stream_frames.size(), 1u);

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            first_packet.packet_number)));

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
    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);
    const auto first_packet = first_tracked_packet(connection.application_space_);
    ASSERT_EQ(first_packet.stop_sending_frames.size(), 1u);

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            first_packet.packet_number)));

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

TEST(QuicCoreTest, ApplicationPtoBurstUsesFreshStreamDataAfterFirstProbe) {
    auto connection = make_connected_client_connection();
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(32) * 1024u, std::byte{0x51});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::optional<std::uint64_t> first_sent_offset;
    std::optional<std::uint64_t> last_sent_offset;
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
            last_sent_offset = stream_offset;
            next_unsent_offset =
                stream_offset + static_cast<std::uint64_t>(stream->stream_data.size());
        }
    }

    ASSERT_TRUE(first_sent_offset.has_value());
    ASSERT_TRUE(last_sent_offset.has_value());
    ASSERT_TRUE(connection.has_pending_application_send());

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());
    const auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);

    const auto first_probe_datagram = connection.drain_outbound_datagram(timeout);
    ASSERT_FALSE(first_probe_datagram.empty());

    const auto first_probe_packets = decode_sender_datagram(connection, first_probe_datagram);
    ASSERT_EQ(first_probe_packets.size(), 1u);
    const auto *first_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&first_probe_packets[0]);
    ASSERT_NE(first_application, nullptr);

    std::vector<std::uint64_t> first_probe_offsets;
    for (const auto &frame : first_application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        first_probe_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    ASSERT_FALSE(first_probe_offsets.empty());
    EXPECT_EQ(first_probe_offsets.front(), optional_value_or_terminate(last_sent_offset));

    const auto second_probe_datagram = connection.drain_outbound_datagram(timeout);
    ASSERT_FALSE(second_probe_datagram.empty());

    const auto second_probe_packets = decode_sender_datagram(connection, second_probe_datagram);
    ASSERT_EQ(second_probe_packets.size(), 1u);
    const auto *second_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&second_probe_packets[0]);
    ASSERT_NE(second_application, nullptr);

    std::vector<std::uint64_t> second_probe_offsets;
    for (const auto &frame : second_application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        second_probe_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    ASSERT_FALSE(second_probe_offsets.empty());
    EXPECT_EQ(second_probe_offsets.front(), next_unsent_offset);
    EXPECT_NE(second_probe_offsets.front(), optional_value_or_terminate(last_sent_offset));
}

TEST(QuicCoreTest,
     ApplicationPtoBurstPrefersFreshStreamDataOverOlderLostRangesOnLastProbeDatagram) {
    auto connection = make_connected_client_connection();
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(64) * 1024u, std::byte{0x52});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    struct SentStreamPacket {
        std::uint64_t packet_number;
        std::uint64_t first_stream_offset;
    };
    std::vector<SentStreamPacket> sent_stream_packets;
    std::uint64_t next_unsent_offset = 0;
    while (true) {
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        const auto packet_number = last_tracked_packet(connection.application_space_).packet_number;
        const auto &sent_packet =
            tracked_packet_or_terminate(connection.application_space_, packet_number);
        ASSERT_FALSE(sent_packet.stream_fragments.empty());
        sent_stream_packets.push_back(SentStreamPacket{
            .packet_number = packet_number,
            .first_stream_offset = sent_packet.stream_fragments.front().offset,
        });
        for (const auto &fragment : sent_packet.stream_fragments) {
            next_unsent_offset =
                std::max(next_unsent_offset,
                         fragment.offset + static_cast<std::uint64_t>(fragment.bytes.size()));
        }
    }

    ASSERT_GE(sent_stream_packets.size(), 2u);
    const auto lost_packet = tracked_packet_or_terminate(connection.application_space_,
                                                         sent_stream_packets.front().packet_number);
    const auto lost_offset = sent_stream_packets.front().first_stream_offset;
    const auto probe_packet_number = sent_stream_packets.back().packet_number;
    const auto probe_offset = sent_stream_packets.back().first_stream_offset;

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            lost_packet.packet_number)));

    ASSERT_TRUE(connection.streams_.contains(0));
    ASSERT_TRUE(connection.streams_.at(0).send_buffer.has_lost_data());
    ASSERT_NE(tracked_packet_or_null(connection.application_space_, probe_packet_number), nullptr);
    ASSERT_TRUE(connection.has_pending_application_send());

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());
    const auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);

    const auto &pending_probe_packet =
        optional_ref_or_terminate(connection.application_space_.pending_probe_packet);
    ASSERT_FALSE(pending_probe_packet.stream_fragments.empty());
    EXPECT_EQ(pending_probe_packet.packet_number, probe_packet_number);
    EXPECT_EQ(pending_probe_packet.stream_fragments.front().offset, probe_offset);

    const auto first_probe_datagram = connection.drain_outbound_datagram(timeout);
    ASSERT_FALSE(first_probe_datagram.empty());

    const auto first_probe_packets = decode_sender_datagram(connection, first_probe_datagram);
    ASSERT_EQ(first_probe_packets.size(), 1u);
    const auto *first_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&first_probe_packets[0]);
    ASSERT_NE(first_application, nullptr);

    std::vector<std::uint64_t> first_probe_offsets;
    for (const auto &frame : first_application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        first_probe_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    ASSERT_FALSE(first_probe_offsets.empty());
    EXPECT_EQ(first_probe_offsets.front(), probe_offset);

    const auto second_probe_datagram = connection.drain_outbound_datagram(timeout);
    ASSERT_FALSE(second_probe_datagram.empty());

    const auto second_probe_packets = decode_sender_datagram(connection, second_probe_datagram);
    ASSERT_EQ(second_probe_packets.size(), 1u);
    const auto *second_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&second_probe_packets[0]);
    ASSERT_NE(second_application, nullptr);

    std::vector<std::uint64_t> second_probe_offsets;
    for (const auto &frame : second_application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        second_probe_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    ASSERT_FALSE(second_probe_offsets.empty());
    EXPECT_EQ(second_probe_offsets.front(), next_unsent_offset);
    EXPECT_NE(second_probe_offsets.front(), lost_offset);
    EXPECT_NE(second_probe_offsets.front(), probe_offset);
}

TEST(QuicCoreTest, ApplicationPtoPrefersPendingStreamDataOverControlOnlyProbe) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));
    const auto crypto_ranges = connection.application_space_.send_crypto.take_ranges(
        std::numeric_limits<std::size_t>::max());
    ASSERT_FALSE(crypto_ranges.empty());

    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(1024), std::byte{0x53});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, true).has_value());
    ASSERT_TRUE(connection.has_pending_application_send());

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 10,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_handshake_done = true,
                                     .crypto_ranges = crypto_ranges,
                                     .bytes_in_flight = 300,
                                 });

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());
    const auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);

    const auto datagram = connection.drain_outbound_datagram(timeout);
    ASSERT_FALSE(datagram.empty());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_stream = false;
    bool saw_crypto = false;
    bool saw_handshake_done = false;
    for (const auto &frame : application->frames) {
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
        saw_crypto = saw_crypto || std::holds_alternative<coquic::quic::CryptoFrame>(frame);
        saw_handshake_done =
            saw_handshake_done || std::holds_alternative<coquic::quic::HandshakeDoneFrame>(frame);
    }

    EXPECT_TRUE(saw_stream);
    EXPECT_TRUE(saw_crypto || saw_handshake_done);
}

TEST(QuicCoreTest, SelectPtoProbePrefersOutstandingStreamDataOverNewerControlOnlyPacket) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;

    const auto payload = coquic::quic::test::bytes_from_string("server-response");
    ASSERT_TRUE(connection.queue_stream_send(0, payload, true).has_value());
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    auto stream_fragments = stream.take_send_fragments(coquic::quic::StreamSendBudget{
        .packet_bytes = payload.size(),
        .new_bytes = payload.size(),
    });
    ASSERT_EQ(stream_fragments.size(), 1u);

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 10,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = stream_fragments,
                                     .bytes_in_flight = 200,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 11,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_handshake_done = true,
                                     .bytes_in_flight = 60,
                                 });

    const auto probe = connection.select_pto_probe(connection.application_space_);

    ASSERT_TRUE(probe.has_value());
    const auto &probe_value = optional_ref_or_terminate(probe);
    EXPECT_EQ(probe_value.packet_number, 10u);
    ASSERT_EQ(probe_value.stream_fragments.size(), 1u);
    EXPECT_EQ(probe_value.stream_fragments.front().stream_id, 0u);
    EXPECT_EQ(probe_value.stream_fragments.front().bytes, payload);
    EXPECT_TRUE(probe_value.stream_fragments.front().fin);
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
    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);
    EXPECT_FALSE(first_tracked_packet(connection.application_space_).stream_fragments.empty());
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

TEST(QuicCoreTest, NewDataSchedulingResumesRoundRobinAfterLastSentStream) {
    auto connection = make_connected_client_connection();
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(2000), std::byte{0x61});

    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(4, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(8, payload, false).has_value());
    connection.last_application_send_stream_id_ = 4;

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(application_stream_ids_from_datagram(connection, datagram),
              (std::vector<std::uint64_t>{8, 0, 4}));
}

TEST(QuicCoreTest, RetransmissionPreservesStreamIdentityAcrossMultipleStreams) {
    auto connection = make_connected_client_connection();
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(2000), std::byte{0x62});

    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(4, payload, false).has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);
    const auto first_packet = first_tracked_packet(connection.application_space_);

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            first_packet.packet_number)));

    const auto repaired_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(repaired_datagram.empty());

    const auto stream_ids = application_stream_ids_from_datagram(connection, repaired_datagram);
    EXPECT_NE(std::find(stream_ids.begin(), stream_ids.end(), 0), stream_ids.end());
    EXPECT_NE(std::find(stream_ids.begin(), stream_ids.end(), 4), stream_ids.end());
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

TEST(QuicCoreTest, CongestionBlockedSendRestoresPendingMaxStreamsFrame) {
    auto connection = make_connected_client_connection();
    const auto maximum_streams =
        connection.local_stream_limit_state_.advertised_max_streams_bidi + 1;
    connection.local_stream_limit_state_.queue_max_streams(
        coquic::quic::StreamLimitType::bidirectional, maximum_streams);
    connection.congestion_controller_.bytes_in_flight_ =
        connection.congestion_controller_.congestion_window_;

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_EQ(connection.local_stream_limit_state_.max_streams_bidi_state,
              coquic::quic::StreamControlFrameState::pending);
    ASSERT_TRUE(connection.local_stream_limit_state_.pending_max_streams_bidi_frame.has_value());
    EXPECT_EQ(optional_ref_or_terminate(
                  connection.local_stream_limit_state_.pending_max_streams_bidi_frame)
                  .maximum_streams,
              maximum_streams);
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
    connection.track_sent_packet(connection.application_space_, packet);

    connection.retire_acked_packet(
        connection.application_space_,
        optional_value_or_terminate(
            connection.application_space_.recovery.handle_for_packet_number(packet.packet_number)));

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
    EXPECT_EQ(tracked_packet_or_null(connection.application_space_, packet.packet_number), nullptr);
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
    connection.track_sent_packet(connection.application_space_, packet);

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(
            connection.application_space_.recovery.handle_for_packet_number(packet.packet_number)));

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
    const auto &lost_packet =
        tracked_packet_or_terminate(connection.application_space_, packet.packet_number);
    EXPECT_TRUE(lost_packet.declared_lost);
    EXPECT_FALSE(lost_packet.in_flight);
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
    const auto &received_stream = *received;
    EXPECT_EQ(received_stream.stream_id, 0u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(received_stream.bytes), "hello");
    EXPECT_TRUE(received_stream.fin);
}

TEST(QuicCoreTest, SelectPtoProbeDropsAcknowledgedAndMismatchedMaxStreamsFrames) {
    auto connection = make_connected_client_connection();
    connection.local_stream_limit_state_.pending_max_streams_bidi_frame =
        coquic::quic::MaxStreamsFrame{
            .stream_type = coquic::quic::StreamLimitType::bidirectional,
            .maximum_streams = 3,
        };
    connection.local_stream_limit_state_.max_streams_bidi_state =
        coquic::quic::StreamControlFrameState::sent;
    connection.local_stream_limit_state_.pending_max_streams_uni_frame =
        coquic::quic::MaxStreamsFrame{
            .stream_type = coquic::quic::StreamLimitType::unidirectional,
            .maximum_streams = 4,
        };
    connection.local_stream_limit_state_.max_streams_uni_state =
        coquic::quic::StreamControlFrameState::acknowledged;

    coquic::quic::PacketSpaceState packet_space;
    connection.track_sent_packet(
        packet_space, coquic::quic::SentPacketRecord{
                          .packet_number = 7,
                          .ack_eliciting = true,
                          .in_flight = true,
                          .max_streams_frames =
                              {
                                  coquic::quic::MaxStreamsFrame{
                                      .stream_type = coquic::quic::StreamLimitType::bidirectional,
                                      .maximum_streams = 9,
                                  },
                                  coquic::quic::MaxStreamsFrame{
                                      .stream_type = coquic::quic::StreamLimitType::unidirectional,
                                      .maximum_streams = 4,
                                  },
                              },
                      });

    const auto probe = connection.select_pto_probe(packet_space);

    ASSERT_TRUE(probe.has_value());
    const auto &probe_packet = optional_ref_or_terminate(probe);
    EXPECT_TRUE(probe_packet.max_streams_frames.empty());
    EXPECT_TRUE(probe_packet.has_ping);
}

TEST(QuicCoreTest, AckGapOnLaterMigratedPathRetransmitsLostStreamData) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 9;
    connection.current_send_path_id_ = 9;
    connection.ensure_path_state(9).validated = true;
    connection.ensure_path_state(9).is_current_send_path = true;

    ASSERT_TRUE(
        connection
            .queue_stream_send(
                0, coquic::quic::test::bytes_from_string(std::string(std::size_t{48} * 1024u, 'm')),
                false)
            .has_value());

    constexpr std::size_t kDeliveredPackets = 4;
    constexpr std::size_t kGapPackets = 6;
    std::vector<std::uint64_t> delivered_packet_numbers;
    std::vector<std::uint64_t> gap_packet_numbers;

    for (std::size_t i = 0; i < kDeliveredPackets; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(i) + 1));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
        delivered_packet_numbers.push_back(
            last_tracked_packet(connection.application_space_).packet_number);
    }
    for (std::size_t i = 0; i < kGapPackets; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(kDeliveredPackets + i + 1u)));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
        gap_packet_numbers.push_back(
            last_tracked_packet(connection.application_space_).packet_number);
    }

    ASSERT_FALSE(delivered_packet_numbers.empty());
    ASSERT_FALSE(gap_packet_numbers.empty());
    const auto first_gap_packet_number = gap_packet_numbers.front();
    const auto first_gap_packet =
        tracked_packet_or_terminate(connection.application_space_, first_gap_packet_number);
    ASSERT_FALSE(first_gap_packet.stream_fragments.empty());
    const auto tracked_gap_offset = first_gap_packet.stream_fragments.front().offset;

    ASSERT_TRUE(connection
                    .process_inbound_application(
                        std::vector<coquic::quic::Frame>{
                            coquic::quic::AckFrame{
                                .largest_acknowledged = delivered_packet_numbers.back(),
                                .first_ack_range = delivered_packet_numbers.back() -
                                                   delivered_packet_numbers.front(),
                            },
                        },
                        coquic::quic::test::test_time(99), /*allow_preconnected_frames=*/false,
                        /*path_id=*/11)
                    .has_value());
    connection.ensure_path_state(11).anti_amplification_received_bytes = 4000;

    const auto migration_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(100));
    ASSERT_FALSE(migration_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 11u);
    ASSERT_TRUE(connection.paths_.contains(11));
    ASSERT_TRUE(connection.paths_.at(11).outstanding_challenge.has_value());
    const auto challenge =
        optional_ref_or_terminate(connection.paths_.at(11).outstanding_challenge);
    const auto migration_packet_number =
        last_tracked_packet(connection.application_space_).packet_number;

    const auto first_delivered_packet_number = delivered_packet_numbers.front();
    const auto last_delivered_packet_number = delivered_packet_numbers.back();
    ASSERT_GT(migration_packet_number, last_delivered_packet_number + 1);

    const auto ack_gap = migration_packet_number - last_delivered_packet_number - 2;
    ASSERT_TRUE(connection
                    .process_inbound_application(
                        std::vector<coquic::quic::Frame>{
                            coquic::quic::PathResponseFrame{.data = challenge},
                            coquic::quic::AckFrame{
                                .largest_acknowledged = migration_packet_number,
                                .first_ack_range = 0,
                                .additional_ranges =
                                    {
                                        coquic::quic::AckRange{
                                            .gap = ack_gap,
                                            .range_length = last_delivered_packet_number -
                                                            first_delivered_packet_number,
                                        },
                                    },
                            },
                        },
                        coquic::quic::test::test_time(101), /*allow_preconnected_frames=*/false,
                        /*path_id=*/11)
                    .has_value());

    ASSERT_TRUE(connection.streams_.contains(0));
    EXPECT_TRUE(connection.streams_.at(0).send_buffer.has_lost_data());

    const auto retransmit_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(102));
    ASSERT_FALSE(retransmit_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 11u);

    const auto retransmit_packet_number =
        last_tracked_packet(connection.application_space_).packet_number;
    const auto retransmit_packet =
        tracked_packet_or_terminate(connection.application_space_, retransmit_packet_number);
    ASSERT_FALSE(retransmit_packet.stream_fragments.empty());
    EXPECT_EQ(retransmit_packet.stream_fragments.front().offset, tracked_gap_offset);
}

TEST(QuicCoreTest, InboundMigratedAckGapDatagramRetransmitsLostStreamData) {
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    server.connection_ =
        std::make_unique<coquic::quic::QuicConnection>(make_connected_server_connection());
    auto &connection = *server.connection_;
    connection.last_validated_path_id_ = 9;
    connection.current_send_path_id_ = 9;
    connection.ensure_path_state(9).validated = true;
    connection.ensure_path_state(9).is_current_send_path = true;

    ASSERT_TRUE(
        connection
            .queue_stream_send(
                0, coquic::quic::test::bytes_from_string(std::string(std::size_t{48} * 1024u, 'm')),
                false)
            .has_value());

    constexpr std::size_t kDeliveredPackets = 4;
    constexpr std::size_t kGapPackets = 6;
    std::vector<std::uint64_t> delivered_packet_numbers;
    std::vector<std::uint64_t> gap_packet_numbers;

    for (std::size_t i = 0; i < kDeliveredPackets; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(i) + 1));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
        delivered_packet_numbers.push_back(
            last_tracked_packet(connection.application_space_).packet_number);
    }
    for (std::size_t i = 0; i < kGapPackets; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(kDeliveredPackets + i + 1u)));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
        gap_packet_numbers.push_back(
            last_tracked_packet(connection.application_space_).packet_number);
    }

    ASSERT_FALSE(delivered_packet_numbers.empty());
    ASSERT_FALSE(gap_packet_numbers.empty());
    const auto first_gap_packet_number = gap_packet_numbers.front();
    const auto first_gap_packet =
        tracked_packet_or_terminate(connection.application_space_, first_gap_packet_number);
    ASSERT_FALSE(first_gap_packet.stream_fragments.empty());
    const auto tracked_gap_offset = first_gap_packet.stream_fragments.front().offset;

    ASSERT_TRUE(connection
                    .process_inbound_application(
                        std::vector<coquic::quic::Frame>{
                            coquic::quic::AckFrame{
                                .largest_acknowledged = delivered_packet_numbers.back(),
                                .first_ack_range = delivered_packet_numbers.back() -
                                                   delivered_packet_numbers.front(),
                            },
                        },
                        coquic::quic::test::test_time(99), /*allow_preconnected_frames=*/false,
                        /*path_id=*/11)
                    .has_value());
    connection.ensure_path_state(11).anti_amplification_received_bytes = 4000;

    const auto migration_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(100));
    ASSERT_FALSE(migration_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 11u);
    ASSERT_TRUE(connection.paths_.contains(11));
    ASSERT_TRUE(connection.paths_.at(11).outstanding_challenge.has_value());
    const auto challenge =
        optional_ref_or_terminate(connection.paths_.at(11).outstanding_challenge);
    const auto migration_packet_number =
        last_tracked_packet(connection.application_space_).packet_number;

    const auto first_delivered_packet_number = delivered_packet_numbers.front();
    const auto last_delivered_packet_number = delivered_packet_numbers.back();
    ASSERT_GT(migration_packet_number, last_delivered_packet_number + 1);

    const auto ack_gap = migration_packet_number - last_delivered_packet_number - 2;
    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = connection.application_read_key_phase_,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 1759,
                .frames =
                    {
                        coquic::quic::PathResponseFrame{.data = challenge},
                        coquic::quic::AckFrame{
                            .largest_acknowledged = migration_packet_number,
                            .first_ack_range = 0,
                            .additional_ranges =
                                {
                                    coquic::quic::AckRange{
                                        .gap = ack_gap,
                                        .range_length = last_delivered_packet_number -
                                                        first_delivered_packet_number,
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
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(encoded.has_value());

    const auto result = server.advance(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = encoded.value(),
            .route_handle = 11,
        },
        coquic::quic::test::test_time(101));

    ASSERT_FALSE(result.local_error.has_value());
    ASSERT_TRUE(connection.streams_.contains(0));

    bool saw_send_on_migrated_path = false;
    bool saw_retransmit_for_gap_offset = false;
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }

        ASSERT_TRUE(send->route_handle.has_value());
        EXPECT_EQ(optional_value_or_terminate(send->route_handle), 11u);
        saw_send_on_migrated_path = true;

        for (const auto &packet : decode_sender_datagram(connection, send->bytes)) {
            const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (one_rtt == nullptr) {
                continue;
            }
            for (const auto &frame : one_rtt->frames) {
                const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
                if (stream == nullptr || !stream->offset.has_value()) {
                    continue;
                }
                if (optional_value_or_terminate(stream->offset) == tracked_gap_offset) {
                    saw_retransmit_for_gap_offset = true;
                }
            }
        }
    }

    EXPECT_TRUE(saw_send_on_migrated_path);
    EXPECT_TRUE(saw_retransmit_for_gap_offset);
}

TEST(QuicCoreTest, LiveLikeMigratedAckGapDatagramRetransmitsLostStreamData) {
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    server.connection_ =
        std::make_unique<coquic::quic::QuicConnection>(make_connected_server_connection());
    auto &connection = *server.connection_;
    connection.application_space_.next_send_packet_number = 8241;
    connection.last_validated_path_id_ = 9;
    connection.current_send_path_id_ = 9;
    connection.ensure_path_state(9).validated = true;
    connection.ensure_path_state(9).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = std::size_t{1024} * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(0,
                                       coquic::quic::test::bytes_from_string(
                                           std::string(std::size_t{512} * 1024u, 'm')),
                                       false)
                    .has_value());

    constexpr std::size_t kDeliveredPackets = 131;
    constexpr std::size_t kGapPackets = 22;
    std::vector<std::uint64_t> delivered_packet_numbers;
    std::vector<std::uint64_t> gap_packet_numbers;

    for (std::size_t i = 0; i < kDeliveredPackets; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(i) + 1));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
        delivered_packet_numbers.push_back(
            last_tracked_packet(connection.application_space_).packet_number);
    }
    for (std::size_t i = 0; i < kGapPackets; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(kDeliveredPackets + i + 1u)));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
        gap_packet_numbers.push_back(
            last_tracked_packet(connection.application_space_).packet_number);
    }

    ASSERT_EQ(delivered_packet_numbers.front(), 8241u);
    ASSERT_EQ(delivered_packet_numbers.back(), 8371u);
    ASSERT_EQ(gap_packet_numbers.front(), 8372u);
    ASSERT_EQ(gap_packet_numbers.back(), 8393u);

    const auto first_gap_packet = tracked_packet_or_terminate(connection.application_space_, 8372);
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
                        /*path_id=*/11)
                    .has_value());
    connection.ensure_path_state(11).anti_amplification_received_bytes = 4000;

    const auto migration_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(100));
    ASSERT_FALSE(migration_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 11u);
    ASSERT_TRUE(connection.paths_.contains(11));
    ASSERT_TRUE(connection.paths_.at(11).outstanding_challenge.has_value());
    const auto challenge =
        optional_ref_or_terminate(connection.paths_.at(11).outstanding_challenge);
    const auto migration_packet_number =
        last_tracked_packet(connection.application_space_).packet_number;
    ASSERT_EQ(migration_packet_number, 8394u);

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = connection.application_read_key_phase_,
                .destination_connection_id = connection.config_.source_connection_id,
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
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(encoded.has_value());

    const auto result = server.advance(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = encoded.value(),
            .route_handle = 11,
        },
        coquic::quic::test::test_time(101));

    ASSERT_FALSE(result.local_error.has_value());

    bool saw_retransmit_for_gap_offset = false;
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }

        ASSERT_TRUE(send->route_handle.has_value());
        EXPECT_EQ(optional_value_or_terminate(send->route_handle), 11u);

        for (const auto &packet : decode_sender_datagram(connection, send->bytes)) {
            const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (one_rtt == nullptr) {
                continue;
            }
            for (const auto &frame : one_rtt->frames) {
                const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
                if (stream == nullptr || !stream->offset.has_value()) {
                    continue;
                }
                if (optional_value_or_terminate(stream->offset) == tracked_gap_offset) {
                    saw_retransmit_for_gap_offset = true;
                }
            }
        }
    }

    EXPECT_TRUE(saw_retransmit_for_gap_offset);
}

TEST(QuicCoreTest, SelectPtoProbeDropsFramesWhoseStreamsNoLongerExist) {
    auto connection = make_connected_client_connection();

    coquic::quic::PacketSpaceState packet_space;
    connection.track_sent_packet(packet_space, coquic::quic::SentPacketRecord{
                                                   .packet_number = 3,
                                                   .ack_eliciting = true,
                                                   .in_flight = true,
                                                   .reset_stream_frames =
                                                       {
                                                           coquic::quic::ResetStreamFrame{
                                                               .stream_id = 11,
                                                               .application_protocol_error_code = 1,
                                                               .final_size = 0,
                                                           },
                                                       },
                                                   .stop_sending_frames =
                                                       {
                                                           coquic::quic::StopSendingFrame{
                                                               .stream_id = 11,
                                                               .application_protocol_error_code = 2,
                                                           },
                                                       },
                                                   .max_stream_data_frames =
                                                       {
                                                           coquic::quic::MaxStreamDataFrame{
                                                               .stream_id = 11,
                                                               .maximum_stream_data = 3,
                                                           },
                                                       },
                                                   .stream_data_blocked_frames =
                                                       {
                                                           coquic::quic::StreamDataBlockedFrame{
                                                               .stream_id = 11,
                                                               .maximum_stream_data = 4,
                                                           },
                                                       },
                                                   .has_ping = true,
                                               });

    const auto probe = connection.select_pto_probe(packet_space);

    ASSERT_TRUE(probe.has_value());
    const auto &probe_packet = optional_ref_or_terminate(probe);
    EXPECT_TRUE(probe_packet.reset_stream_frames.empty());
    EXPECT_TRUE(probe_packet.stop_sending_frames.empty());
    EXPECT_TRUE(probe_packet.max_stream_data_frames.empty());
    EXPECT_TRUE(probe_packet.stream_data_blocked_frames.empty());
    EXPECT_TRUE(probe_packet.has_ping);
}

TEST(QuicCoreTest,
     ProcessInboundDatagramSkipsMalformedLongHeaderPacketAndProcessesLaterOneRttStream) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto first_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 40,
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
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(first_packet.has_value());

    const auto second_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 41,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 1,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(second_packet.has_value());

    auto malformed_second_packet = second_packet.value();
    malformed_second_packet.front() = std::byte{static_cast<std::uint8_t>(
        std::to_integer<std::uint8_t>(malformed_second_packet.front()) & 0xbfu)};

    const auto third_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 42,
                .frames =
                    {
                        coquic::quic::StreamFrame{
                            .fin = true,
                            .has_offset = true,
                            .has_length = true,
                            .stream_id = 0,
                            .offset = 0,
                            .stream_data = coquic::quic::test::bytes_from_string("late-handshake"),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = optional_ref_or_terminate(connection.application_space_.read_secret),
        });
    ASSERT_TRUE(third_packet.has_value());

    auto datagram = first_packet.value();
    datagram.insert(datagram.end(), malformed_second_packet.begin(), malformed_second_packet.end());
    datagram.insert(datagram.end(), third_packet.value().begin(), third_packet.value().end());

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    const auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    EXPECT_EQ(optional_value_or_terminate(received).stream_id, 0u);
    EXPECT_EQ(optional_value_or_terminate(received).bytes,
              coquic::quic::test::bytes_from_string("late-handshake"));
    EXPECT_TRUE(optional_value_or_terminate(received).fin);
}

TEST(QuicCoreTest, LocalStreamLimitStateTracksUnidirectionalFramesAcrossQueueLossAndAck) {
    coquic::quic::LocalStreamLimitState limits;
    limits.initialize(coquic::quic::PeerStreamOpenLimits{
        .bidirectional = 1,
        .unidirectional = 2,
    });

    limits.queue_max_streams(coquic::quic::StreamLimitType::unidirectional, 3);
    ASSERT_TRUE(limits.pending_max_streams_uni_frame.has_value());
    EXPECT_EQ(limits.advertised_max_streams_uni, 3u);
    EXPECT_EQ(limits.max_streams_uni_state, coquic::quic::StreamControlFrameState::pending);

    const auto first_frames = limits.take_max_streams_frames();
    ASSERT_EQ(first_frames.size(), 1u);
    EXPECT_EQ(first_frames.front().stream_type, coquic::quic::StreamLimitType::unidirectional);
    EXPECT_EQ(first_frames.front().maximum_streams, 3u);
    EXPECT_EQ(limits.max_streams_uni_state, coquic::quic::StreamControlFrameState::sent);

    limits.mark_max_streams_frame_lost(first_frames.front());
    EXPECT_EQ(limits.max_streams_uni_state, coquic::quic::StreamControlFrameState::pending);

    const auto retry_frames = limits.take_max_streams_frames();
    ASSERT_EQ(retry_frames.size(), 1u);
    limits.acknowledge_max_streams_frame(retry_frames.front());
    EXPECT_EQ(limits.max_streams_uni_state, coquic::quic::StreamControlFrameState::acknowledged);

    limits.queue_max_streams(coquic::quic::StreamLimitType::unidirectional, 3);
    EXPECT_EQ(limits.max_streams_uni_state, coquic::quic::StreamControlFrameState::acknowledged);
}

TEST(QuicCoreTest, LocalStreamLimitStateTracksBidirectionalFramesAcrossQueueLossAndAck) {
    coquic::quic::LocalStreamLimitState limits;
    limits.initialize(coquic::quic::PeerStreamOpenLimits{
        .bidirectional = 1,
        .unidirectional = 2,
    });

    limits.queue_max_streams(coquic::quic::StreamLimitType::bidirectional, 3);
    ASSERT_TRUE(limits.pending_max_streams_bidi_frame.has_value());
    EXPECT_EQ(limits.advertised_max_streams_bidi, 3u);
    EXPECT_EQ(limits.max_streams_bidi_state, coquic::quic::StreamControlFrameState::pending);

    const auto first_frames = limits.take_max_streams_frames();
    ASSERT_EQ(first_frames.size(), 1u);
    EXPECT_EQ(first_frames.front().stream_type, coquic::quic::StreamLimitType::bidirectional);
    EXPECT_EQ(first_frames.front().maximum_streams, 3u);
    EXPECT_EQ(limits.max_streams_bidi_state, coquic::quic::StreamControlFrameState::sent);

    limits.mark_max_streams_frame_lost(first_frames.front());
    EXPECT_EQ(limits.max_streams_bidi_state, coquic::quic::StreamControlFrameState::pending);

    const auto retry_frames = limits.take_max_streams_frames();
    ASSERT_EQ(retry_frames.size(), 1u);
    limits.acknowledge_max_streams_frame(retry_frames.front());
    EXPECT_EQ(limits.max_streams_bidi_state, coquic::quic::StreamControlFrameState::acknowledged);
}

TEST(QuicCoreTest, AcknowledgeMaxStreamsFrameWithoutPendingStateIsIgnored) {
    coquic::quic::LocalStreamLimitState limits;

    limits.acknowledge_max_streams_frame(coquic::quic::MaxStreamsFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 1,
    });

    EXPECT_EQ(limits.max_streams_bidi_state, coquic::quic::StreamControlFrameState::none);
}

TEST(QuicCoreTest, AcknowledgeMaxStreamsFrameWithoutPendingFrameIsIgnored) {
    coquic::quic::LocalStreamLimitState limits;
    limits.max_streams_bidi_state = coquic::quic::StreamControlFrameState::sent;

    limits.acknowledge_max_streams_frame(coquic::quic::MaxStreamsFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 1,
    });

    EXPECT_EQ(limits.max_streams_bidi_state, coquic::quic::StreamControlFrameState::sent);
}

TEST(QuicCoreTest, AcknowledgeMismatchedUnidirectionalMaxStreamsFrameIsIgnored) {
    coquic::quic::LocalStreamLimitState limits;
    limits.initialize(coquic::quic::PeerStreamOpenLimits{
        .bidirectional = 1,
        .unidirectional = 2,
    });

    limits.queue_max_streams(coquic::quic::StreamLimitType::unidirectional, 3);
    const auto frames = limits.take_max_streams_frames();
    ASSERT_EQ(frames.size(), 1u);

    limits.acknowledge_max_streams_frame(coquic::quic::MaxStreamsFrame{
        .stream_type = coquic::quic::StreamLimitType::unidirectional,
        .maximum_streams = 4,
    });

    EXPECT_EQ(limits.max_streams_uni_state, coquic::quic::StreamControlFrameState::sent);
}

TEST(QuicCoreTest, MarkLostAcknowledgedBidirectionalMaxStreamsFrameIsIgnored) {
    coquic::quic::LocalStreamLimitState limits;
    limits.initialize(coquic::quic::PeerStreamOpenLimits{
        .bidirectional = 1,
        .unidirectional = 2,
    });

    limits.queue_max_streams(coquic::quic::StreamLimitType::bidirectional, 3);
    const auto frames = limits.take_max_streams_frames();
    ASSERT_EQ(frames.size(), 1u);
    limits.acknowledge_max_streams_frame(frames.front());

    limits.mark_max_streams_frame_lost(frames.front());

    EXPECT_EQ(limits.max_streams_bidi_state, coquic::quic::StreamControlFrameState::acknowledged);
}

TEST(QuicCoreTest, MarkLostMaxStreamsFrameWithoutPendingStateIsIgnored) {
    coquic::quic::LocalStreamLimitState limits;

    limits.mark_max_streams_frame_lost(coquic::quic::MaxStreamsFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 1,
    });

    EXPECT_EQ(limits.max_streams_bidi_state, coquic::quic::StreamControlFrameState::none);
}

TEST(QuicCoreTest, MarkLostMaxStreamsFrameWithoutPendingFrameIsIgnored) {
    coquic::quic::LocalStreamLimitState limits;
    limits.max_streams_bidi_state = coquic::quic::StreamControlFrameState::sent;

    limits.mark_max_streams_frame_lost(coquic::quic::MaxStreamsFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 1,
    });

    EXPECT_EQ(limits.max_streams_bidi_state, coquic::quic::StreamControlFrameState::sent);
}

TEST(QuicCoreTest, MarkLostMismatchedUnidirectionalMaxStreamsFrameIsIgnored) {
    coquic::quic::LocalStreamLimitState limits;
    limits.initialize(coquic::quic::PeerStreamOpenLimits{
        .bidirectional = 1,
        .unidirectional = 2,
    });

    limits.queue_max_streams(coquic::quic::StreamLimitType::unidirectional, 3);
    const auto frames = limits.take_max_streams_frames();
    ASSERT_EQ(frames.size(), 1u);

    limits.mark_max_streams_frame_lost(coquic::quic::MaxStreamsFrame{
        .stream_type = coquic::quic::StreamLimitType::unidirectional,
        .maximum_streams = 4,
    });

    EXPECT_EQ(limits.max_streams_uni_state, coquic::quic::StreamControlFrameState::sent);
}

TEST(QuicCoreTest, PeerStreamOpenLimitsUseBidirectionalTransportDefaultsWhenUnset) {
    auto connection = make_connected_server_connection();

    connection.local_stream_limit_state_.advertised_max_streams_bidi = 0;
    connection.local_transport_parameters_.initial_max_streams_bidi = 5;
    EXPECT_EQ(connection.peer_stream_open_limits().bidirectional, 5u);

    connection.local_transport_parameters_.initial_max_streams_bidi = 0;
    EXPECT_EQ(connection.peer_stream_open_limits().bidirectional,
              connection.config_.transport.initial_max_streams_bidi);
}

TEST(QuicCoreTest, PendingUnidirectionalMaxStreamsFrameCountsAsPendingApplicationSend) {
    auto connection = make_connected_client_connection();

    connection.local_stream_limit_state_.max_streams_uni_state =
        coquic::quic::StreamControlFrameState::pending;
    EXPECT_TRUE(connection.has_pending_application_send());

    connection.local_stream_limit_state_.max_streams_uni_state =
        coquic::quic::StreamControlFrameState::none;
    EXPECT_FALSE(connection.has_pending_application_send());
}

TEST(QuicCoreTest, ClosingPeerInitiatedUnidirectionalStreamRefreshesStreamLimit) {
    auto connection = make_connected_server_connection();
    auto &stream =
        connection.streams_
            .emplace(2, coquic::quic::make_implicit_stream_state(2, connection.config_.role))
            .first->second;

    stream.peer_fin_delivered = true;

    connection.maybe_refresh_peer_stream_limit(stream);

    EXPECT_TRUE(stream.peer_stream_limit_released);
    EXPECT_EQ(connection.local_stream_limit_state_.max_streams_uni_state,
              coquic::quic::StreamControlFrameState::pending);
    ASSERT_TRUE(connection.local_stream_limit_state_.pending_max_streams_uni_frame.has_value());
    EXPECT_EQ(optional_ref_or_terminate(
                  connection.local_stream_limit_state_.pending_max_streams_uni_frame)
                  .stream_type,
              coquic::quic::StreamLimitType::unidirectional);
}

TEST(QuicCoreTest, NonTerminalPeerStreamDoesNotRefreshStreamLimit) {
    auto connection = make_connected_server_connection();
    auto &stream =
        connection.streams_
            .emplace(2, coquic::quic::make_implicit_stream_state(2, connection.config_.role))
            .first->second;

    connection.maybe_refresh_peer_stream_limit(stream);

    EXPECT_FALSE(stream.peer_stream_limit_released);
    EXPECT_EQ(connection.local_stream_limit_state_.max_streams_uni_state,
              coquic::quic::StreamControlFrameState::none);
}

TEST(QuicCoreTest, ReleasedPeerStreamDoesNotRefreshStreamLimitAgain) {
    auto connection = make_connected_server_connection();
    auto &stream =
        connection.streams_
            .emplace(2, coquic::quic::make_implicit_stream_state(2, connection.config_.role))
            .first->second;
    stream.peer_stream_limit_released = true;
    stream.peer_fin_delivered = true;

    connection.maybe_refresh_peer_stream_limit(stream);

    EXPECT_TRUE(stream.peer_stream_limit_released);
    EXPECT_EQ(connection.local_stream_limit_state_.max_streams_uni_state,
              coquic::quic::StreamControlFrameState::none);
}

TEST(QuicCoreTest, MarkLostPacketRequeuesUnidirectionalMaxStreamsFrame) {
    auto connection = make_connected_server_connection();
    const auto maximum_streams =
        connection.local_stream_limit_state_.advertised_max_streams_uni + 1;
    connection.local_stream_limit_state_.queue_max_streams(
        coquic::quic::StreamLimitType::unidirectional, maximum_streams);
    const auto frames = connection.local_stream_limit_state_.take_max_streams_frames();
    ASSERT_EQ(frames.size(), 1u);

    connection.track_sent_packet(connection.application_space_, coquic::quic::SentPacketRecord{
                                                                    .packet_number = 7,
                                                                    .max_streams_frames = frames,
                                                                });
    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(
            connection.application_space_.recovery.handle_for_packet_number(7)));

    EXPECT_EQ(connection.local_stream_limit_state_.max_streams_uni_state,
              coquic::quic::StreamControlFrameState::pending);
}

TEST(QuicCoreTest, ApplicationProbePacketCanSendMaxStreamsFrames) {
    auto connection = make_connected_server_connection();
    const auto maximum_streams =
        connection.local_stream_limit_state_.advertised_max_streams_uni + 1;
    connection.local_stream_limit_state_.queue_max_streams(
        coquic::quic::StreamLimitType::unidirectional, maximum_streams);
    const auto frames = connection.local_stream_limit_state_.take_max_streams_frames();
    ASSERT_EQ(frames.size(), 1u);

    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 89,
        .ack_eliciting = true,
        .in_flight = true,
        .max_streams_frames = frames,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_max_streams = false;
    for (const auto &frame : application->frames) {
        if (const auto *max_streams = std::get_if<coquic::quic::MaxStreamsFrame>(&frame)) {
            saw_max_streams = true;
            EXPECT_EQ(max_streams->stream_type, coquic::quic::StreamLimitType::unidirectional);
            EXPECT_EQ(max_streams->maximum_streams, maximum_streams);
        }
    }

    EXPECT_TRUE(saw_max_streams);
}

TEST(QuicCoreTest, ApplicationProbePacketCanSendBidirectionalMaxStreamsFrames) {
    auto connection = make_connected_server_connection();
    const auto maximum_streams =
        connection.local_stream_limit_state_.advertised_max_streams_bidi + 1;
    connection.local_stream_limit_state_.queue_max_streams(
        coquic::quic::StreamLimitType::bidirectional, maximum_streams);
    const auto frames = connection.local_stream_limit_state_.take_max_streams_frames();
    ASSERT_EQ(frames.size(), 1u);

    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 90,
        .ack_eliciting = true,
        .in_flight = true,
        .max_streams_frames = frames,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_max_streams = false;
    for (const auto &frame : application->frames) {
        if (const auto *max_streams = std::get_if<coquic::quic::MaxStreamsFrame>(&frame)) {
            saw_max_streams = true;
            EXPECT_EQ(max_streams->stream_type, coquic::quic::StreamLimitType::bidirectional);
            EXPECT_EQ(max_streams->maximum_streams, maximum_streams);
        }
    }

    EXPECT_TRUE(saw_max_streams);
}

TEST(QuicCoreTest, ApplicationProbeIgnoresQueuedStreamDataOnResettingStream) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("ignored"), false)
            .has_value());
    auto &stream = connection.streams_.at(0);
    stream.pending_reset_frame = coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 1,
        .final_size = 0,
    };
    stream.reset_state = coquic::quic::StreamControlFrameState::pending;
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 91,
        .ack_eliciting = true,
        .in_flight = true,
        .has_handshake_done = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_handshake_done = false;
    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_handshake_done =
            saw_handshake_done || std::holds_alternative<coquic::quic::HandshakeDoneFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_handshake_done);
    EXPECT_FALSE(saw_stream);
}

} // namespace
