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

TEST(QuicCoreTest, ApplicationProbeForceAckDoesNotDuplicateMatchingMaxStreamDataFrame) {
    auto connection = make_connected_client_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    connection.initialize_stream_flow_control(stream);
    stream.flow_control.pending_max_stream_data_frame = coquic::quic::MaxStreamDataFrame{
        .stream_id = 0,
        .maximum_stream_data = 17,
    };
    stream.flow_control.max_stream_data_state = coquic::quic::StreamControlFrameState::pending;
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/41, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 25,
        .ack_eliciting = true,
        .in_flight = true,
        .max_stream_data_frames =
            {
                *stream.flow_control.pending_max_stream_data_frame,
            },
        .force_ack = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    std::size_t max_stream_data_frames = 0;
    for (const auto &frame : application->frames) {
        if (std::holds_alternative<coquic::quic::MaxStreamDataFrame>(frame)) {
            ++max_stream_data_frames;
        }
    }

    EXPECT_EQ(max_stream_data_frames, 1u);
}

TEST(QuicCoreTest, ApplicationProbeForceAckDropsFreshReceiveCreditWhenProbeWouldOverflow) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 26,
        .ack_eliciting = true,
        .in_flight = true,
        .force_ack = true,
    };

    for (std::uint64_t index = 0; index < 200; ++index) {
        const auto stream_id = 1u + (index * 4u);
        auto &stream = connection.streams_
                           .emplace(stream_id, coquic::quic::make_implicit_stream_state(
                                                   stream_id, coquic::quic::EndpointRole::client))
                           .first->second;
        connection.initialize_stream_flow_control(stream);
        stream.flow_control.local_receive_window = 0x4000;
        stream.flow_control.advertised_max_stream_data = 1;
        stream.flow_control.delivered_bytes = 1;
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ping = false;
    bool saw_max_data = false;
    bool saw_max_stream_data = false;
    for (const auto &frame : application->frames) {
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
        saw_max_data = saw_max_data || std::holds_alternative<coquic::quic::MaxDataFrame>(frame);
        saw_max_stream_data =
            saw_max_stream_data || std::holds_alternative<coquic::quic::MaxStreamDataFrame>(frame);
    }

    EXPECT_TRUE(saw_ping);
    EXPECT_FALSE(saw_max_data);
    EXPECT_FALSE(saw_max_stream_data);
    EXPECT_EQ(connection.streams_.at(1).flow_control.max_stream_data_state,
              coquic::quic::StreamControlFrameState::pending);
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ApplicationSendDropsFreshReceiveCreditWhenPayloadWouldOverflow) {
    auto connection = make_connected_client_connection();
    connection.connection_flow_control_.advertised_max_data = 1;
    connection.connection_flow_control_.queue_max_data(0x4001);
    ASSERT_TRUE(
        connection
            .queue_stream_send(0, coquic::quic::test::bytes_from_string("request-bytes"), false)
            .has_value());

    for (std::uint64_t index = 0; index < 200; ++index) {
        const auto stream_id = 1u + (index * 4u);
        auto &stream = connection.streams_
                           .emplace(stream_id, coquic::quic::make_implicit_stream_state(
                                                   stream_id, coquic::quic::EndpointRole::client))
                           .first->second;
        connection.initialize_stream_flow_control(stream);
        stream.flow_control.advertised_max_stream_data = 1;
        stream.queue_max_stream_data(0x4001);
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_stream = false;
    bool saw_max_data = false;
    bool saw_max_stream_data = false;
    for (const auto &frame : application->frames) {
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
        saw_max_data = saw_max_data || std::holds_alternative<coquic::quic::MaxDataFrame>(frame);
        saw_max_stream_data =
            saw_max_stream_data || std::holds_alternative<coquic::quic::MaxStreamDataFrame>(frame);
    }

    EXPECT_TRUE(saw_stream);
    EXPECT_FALSE(saw_max_data);
    EXPECT_FALSE(saw_max_stream_data);
    EXPECT_EQ(connection.connection_flow_control_.max_data_state,
              coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(connection.streams_.at(1).flow_control.max_stream_data_state,
              coquic::quic::StreamControlFrameState::pending);
}

TEST(QuicCoreTest, ApplicationSendQueuesConnectionDataBlockedFrameWhenCreditIsExhausted) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("blocked"), false)
            .has_value());
    connection.connection_flow_control_.peer_max_data = 4;
    connection.connection_flow_control_.highest_sent = 4;
    connection.application_space_.received_packets.record_received(
        91, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_data_blocked = false;
    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_data_blocked =
            saw_data_blocked || std::holds_alternative<coquic::quic::DataBlockedFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_data_blocked);
    EXPECT_FALSE(saw_stream);
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
    EXPECT_EQ(optional_ref_or_terminate(state.pending_data_blocked_frame).maximum_data, 12u);

    state.data_blocked_state = coquic::quic::StreamControlFrameState::pending;
    state.pending_data_blocked_frame = std::nullopt;
    EXPECT_FALSE(state.take_data_blocked_frame().has_value());
    state.pending_data_blocked_frame = coquic::quic::DataBlockedFrame{.maximum_data = 11};
    state.data_blocked_state = coquic::quic::StreamControlFrameState::acknowledged;
    state.mark_data_blocked_frame_lost(coquic::quic::DataBlockedFrame{.maximum_data = 11});
    EXPECT_EQ(state.data_blocked_state, coquic::quic::StreamControlFrameState::acknowledged);
}

TEST(QuicCoreTest, InitializePeerFlowControlAssignsReceiveWindowToPreexistingStreams) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.peer_source_connection_id_ = {std::byte{0x77}};

    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    stream.receive_flow_control_limit = 0;
    stream.flow_control.local_receive_window = 0;
    stream.flow_control.advertised_max_stream_data = std::numeric_limits<std::uint64_t>::max();

    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 1024,
        .initial_max_stream_data_bidi_remote = 2048,
        .initial_max_stream_data_uni = 512,
        .initial_max_streams_bidi = 4,
        .initial_max_streams_uni = 4,
        .initial_source_connection_id = connection.peer_source_connection_id_,
    };

    connection.initialize_peer_flow_control_from_transport_parameters();

    EXPECT_NE(stream.receive_flow_control_limit, 0u);
    EXPECT_EQ(stream.receive_flow_control_limit, stream.flow_control.local_receive_window);
    EXPECT_EQ(stream.receive_flow_control_limit, stream.flow_control.advertised_max_stream_data);
}

TEST(QuicCoreTest, ClientLargePartialResponseFlowKeepsReceiveCreditStateConsistent) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto request = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /\r\n"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    const auto request_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        request, server, coquic::quic::test::test_time(2));
    EXPECT_FALSE(coquic::quic::test::received_application_data_from(request_delivered).empty());

    const auto response_payload = coquic::quic::test::bytes_from_string(
        std::string(static_cast<std::size_t>(256) * 1024u, 'r'));
    const auto response = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = response_payload,
            .fin = false,
        },
        coquic::quic::test::test_time(3));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(response).empty());

    auto response_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        response, client, coquic::quic::test::test_time(4));
    EXPECT_FALSE(coquic::quic::test::received_application_data_from(response_delivered).empty());
    if (coquic::quic::test::send_datagrams_from(response_delivered).empty()) {
        const auto ack_deadline = client.connection_->next_wakeup();
        ASSERT_TRUE(ack_deadline.has_value());
        response_delivered = client.advance(coquic::quic::QuicCoreTimerExpired{},
                                            optional_value_or_terminate(ack_deadline));
    }
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(response_delivered).empty());

    bool saw_max_data = false;
    bool saw_max_stream_data = false;
    const auto note_receive_credit_frames = [&](const auto &result) {
        for (const auto &datagram : coquic::quic::test::send_datagrams_from(result)) {
            for (const auto &packet : decode_sender_datagram(*client.connection_, datagram)) {
                const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
                if (application == nullptr) {
                    continue;
                }
                for (const auto &frame : application->frames) {
                    saw_max_data =
                        saw_max_data || std::holds_alternative<coquic::quic::MaxDataFrame>(frame);
                    saw_max_stream_data =
                        saw_max_stream_data ||
                        std::holds_alternative<coquic::quic::MaxStreamDataFrame>(frame);
                }
            }
        }
    };
    note_receive_credit_frames(response_delivered);

    ASSERT_TRUE(client.connection_->handshake_confirmed_);
    auto to_server = response_delivered;
    auto to_client = coquic::quic::QuicCoreResult{};
    auto step_now = coquic::quic::test::test_time(5);
    for (int i = 0; i < 64; ++i) {
        if (!coquic::quic::test::send_datagrams_from(to_server).empty()) {
            to_client =
                coquic::quic::test::relay_send_datagrams_to_peer(to_server, server, step_now);
            to_server.effects.clear();
            step_now += std::chrono::milliseconds(1);
            continue;
        }

        if (!coquic::quic::test::send_datagrams_from(to_client).empty()) {
            to_server =
                coquic::quic::test::relay_send_datagrams_to_peer(to_client, client, step_now);
            note_receive_credit_frames(to_server);
            to_client.effects.clear();
            step_now += std::chrono::milliseconds(1);
            continue;
        }

        if (client.connection_->application_space_.pending_ack_deadline.has_value()) {
            const auto ack_deadline = optional_value_or_terminate(
                client.connection_->application_space_.pending_ack_deadline);
            to_server = client.advance(coquic::quic::QuicCoreTimerExpired{}, ack_deadline);
            note_receive_credit_frames(to_server);
            step_now = ack_deadline + std::chrono::milliseconds(1);
            continue;
        }

        break;
    }

    const auto sent_packets = tracked_packet_snapshot(client.connection_->application_space_);
    const auto in_flight_application_packets =
        std::count_if(sent_packets.begin(), sent_packets.end(),
                      [](const auto &packet) { return packet.ack_eliciting && packet.in_flight; });
    ASSERT_LE(in_flight_application_packets, 1);

    const auto deadline = client.connection_->next_wakeup();
    ASSERT_TRUE(deadline.has_value());

    const auto timeout_result =
        client.advance(coquic::quic::QuicCoreTimerExpired{}, optional_value_or_terminate(deadline));
    const auto timeout_datagrams = coquic::quic::test::send_datagrams_from(timeout_result);
    ASSERT_FALSE(timeout_datagrams.empty());

    note_receive_credit_frames(timeout_result);

    const auto &connection_flow_control = client.connection_->connection_flow_control_;
    if (!saw_max_data && !connection_flow_control.pending_max_data_frame.has_value()) {
        ASSERT_GE(connection_flow_control.advertised_max_data,
                  connection_flow_control.delivered_bytes);
        const auto remaining_connection_credit =
            connection_flow_control.advertised_max_data - connection_flow_control.delivered_bytes;
        if (connection_flow_control.local_receive_window <= 1) {
            EXPECT_GT(remaining_connection_credit, 0u);
        } else {
            EXPECT_GE(remaining_connection_credit,
                      connection_flow_control.local_receive_window / 2);
        }
    }

    const bool has_pending_max_stream_data =
        std::ranges::any_of(client.connection_->streams_, [](const auto &entry) {
            return entry.second.flow_control.pending_max_stream_data_frame.has_value();
        });
    EXPECT_TRUE(saw_max_stream_data || has_pending_max_stream_data);
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

    stream_open.local_stream_limit_state_.initialize(coquic::quic::PeerStreamOpenLimits{
        .bidirectional = 1,
        .unidirectional = stream_open.local_stream_limit_state_.advertised_max_streams_uni,
    });
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

} // namespace
