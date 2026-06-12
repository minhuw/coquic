#include <array>

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string_view>
#include <type_traits>

#include "src/quic/codec/protected_codec.h"
#include "src/quic/codec/varint.h"
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
using coquic::quic::test_support::application_datagram_payloads_from_datagram;
using coquic::quic::test_support::application_stream_ids_from_datagram;
using coquic::quic::test_support::bytes_from_hex;
using coquic::quic::test_support::bytes_from_ints;
using coquic::quic::test_support::datagram_has_application_ack;
using coquic::quic::test_support::datagram_has_application_datagram_frame;
using coquic::quic::test_support::datagram_has_application_stream;
using coquic::quic::test_support::decode_sender_datagram;
using coquic::quic::test_support::expect_local_error;
using coquic::quic::test_support::find_application_probe_payload_size_that_drops_ack;
using coquic::quic::test_support::find_application_send_payload_size_that_drops_ack;
using coquic::quic::test_support::first_stream_frame_length_for_tests;
using coquic::quic::test_support::first_stream_frame_offset_for_tests;
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
using coquic::quic::test_support::sent_packet_has_stream_frames_for_tests;
using coquic::quic::test_support::tracked_packet_count;
using coquic::quic::test_support::tracked_packet_or_null;
using coquic::quic::test_support::tracked_packet_or_terminate;
using coquic::quic::test_support::tracked_packet_snapshot;

template <typename T> T codec_value_or_terminate(coquic::quic::CodecResult<T> result) {
    if (!result.has_value()) {
        std::abort();
    }
    return std::move(result).value();
}

TEST(QuicCoreTest, TwoPeersExchangeStreamZeroDataThroughEffects) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    auto send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ping"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(1));

    auto stream_events = coquic::quic::test::received_stream_data_from(received);
    ASSERT_EQ(stream_events.size(), 1u);
    EXPECT_EQ(stream_events[0].stream_id, 0u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(stream_events[0].bytes), "ping");
    EXPECT_FALSE(stream_events[0].fin);
}

TEST(QuicCoreTest, TwoPeersExchangeDatagramFramesThroughEffects) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    auto send = client.advance(
        coquic::quic::QuicCoreSendDatagramData{
            .bytes = coquic::quic::test::bytes_from_string("ping"),
        },
        coquic::quic::test::test_time(1));
    auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(2));

    auto datagram_events = coquic::quic::test::received_datagram_data_from(received);
    ASSERT_EQ(datagram_events.size(), 1u);
    //= https://www.rfc-editor.org/rfc/rfc9221#section-5
    // # This frame SHOULD be sent as soon as possible (as determined
    // # by factors like congestion control, described below) and MAY be
    // # coalesced with other frames.
    EXPECT_EQ(datagram_events[0].connection, 1u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(datagram_events[0].payload()), "ping");
    EXPECT_EQ(datagram_events[0].byte_count(), 4u);
}

TEST(QuicCoreTest, DatagramSendPriorityChoosesHigherPriorityThenFifo) {
    auto connection = make_connected_client_connection();

    ASSERT_TRUE(connection.queue_datagram_send(bytes_from_ints({0x01}), 0).has_value());
    ASSERT_TRUE(connection.queue_datagram_send(bytes_from_ints({0x02}), 7).has_value());
    ASSERT_TRUE(connection.queue_datagram_send(bytes_from_ints({0x03}), 7).has_value());

    auto first = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first.empty());
    //= https://www.rfc-editor.org/rfc/rfc9221#section-5.1
    // # QUIC implementations SHOULD present an API to applications to assign
    // # relative priorities to DATAGRAM frames with respect to each other and
    // # to QUIC streams.
    EXPECT_EQ(application_datagram_payloads_from_datagram(connection, first),
              std::vector<std::vector<std::byte>>({bytes_from_ints({0x02})}));

    auto second = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(second.empty());
    EXPECT_EQ(application_datagram_payloads_from_datagram(connection, second),
              std::vector<std::vector<std::byte>>({bytes_from_ints({0x03})}));
}

TEST(QuicCoreTest, DatagramSendPriorityIsRelativeToPendingStreamWork) {
    auto connection = make_connected_client_connection();

    //= https://www.rfc-editor.org/rfc/rfc9000#section-2.3
    // # A QUIC implementation SHOULD provide ways in which an application can
    // # indicate the relative priority of streams.
    ASSERT_TRUE(connection
                    .queue_stream_send(0, bytes_from_ints({0x73}), false,
                                       /*priority=*/5)
                    .has_value());
    ASSERT_TRUE(
        connection.queue_datagram_send(bytes_from_ints({0x64}), /*priority=*/1).has_value());

    auto stream_first = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(stream_first.empty());
    EXPECT_TRUE(datagram_has_application_stream(connection, stream_first));
    EXPECT_FALSE(datagram_has_application_datagram_frame(connection, stream_first));

    ASSERT_TRUE(
        connection.queue_datagram_send(bytes_from_ints({0x68}), /*priority=*/9).has_value());
    auto high_priority_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(high_priority_datagram.empty());
    EXPECT_EQ(application_datagram_payloads_from_datagram(connection, high_priority_datagram),
              std::vector<std::vector<std::byte>>({bytes_from_ints({0x68})}));
}

TEST(QuicCoreTest, TwoPeersExchangeSharedDatagramFramesThroughEffects) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    auto send = client.advance(
        coquic::quic::QuicCoreSendSharedDatagramData{
            .bytes = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string("pong")),
        },
        coquic::quic::test::test_time(1));
    auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(2));

    auto datagram_events = coquic::quic::test::received_datagram_data_from(received);
    ASSERT_EQ(datagram_events.size(), 1u);
    EXPECT_EQ(datagram_events[0].connection, 1u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(datagram_events[0].payload()), "pong");
    EXPECT_EQ(datagram_events[0].byte_count(), 4u);
}

TEST(QuicCoreTest, TwoPeersExchangeEmptyDatagramFrame) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    auto send =
        client.advance(coquic::quic::QuicCoreSendDatagramData{}, coquic::quic::test::test_time(1));
    auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(2));

    auto datagram_events = coquic::quic::test::received_datagram_data_from(received);
    ASSERT_EQ(datagram_events.size(), 1u);
    EXPECT_TRUE(datagram_events[0].payload().empty());
    EXPECT_EQ(datagram_events[0].byte_count(), 0u);
}

TEST(QuicCoreTest, ClientCanSendOnMultipleBidirectionalStreams) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    auto first = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("a"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    auto second = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 4,
            .bytes = coquic::quic::test::bytes_from_string("b"),
            .fin = false,
        },
        coquic::quic::test::test_time(2));

    auto server_first = coquic::quic::test::relay_send_datagrams_to_peer(
        first, server, coquic::quic::test::test_time(1));
    auto server_second = coquic::quic::test::relay_send_datagrams_to_peer(
        second, server, coquic::quic::test::test_time(2));

    ASSERT_EQ(coquic::quic::test::stream_payloads_from(server_first).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(server_first)[0],
              (coquic::quic::test::StreamPayload{0, "a", false}));
    ASSERT_EQ(coquic::quic::test::stream_payloads_from(server_second).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(server_second)[0],
              (coquic::quic::test::StreamPayload{4, "b", false}));
}

TEST(QuicCoreTest, BatchedStreamSendsPackIntoSharedDatagrams) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    auto *client_connection = client.connection_.get();
    ASSERT_NE(client_connection, nullptr);
    client_connection->config_.transport.pmtud_enabled = false;
    client_connection->config_.max_outbound_datagram_size = 1472;
    auto &peer_transport = optional_ref_or_terminate(client_connection->peer_transport_parameters_);
    peer_transport.max_udp_payload_size = 1472;
    peer_transport.initial_max_streams_bidi = 64;
    client_connection->initialize_peer_flow_control_from_transport_parameters();

    std::vector<coquic::quic::QuicCoreInput> inputs;
    inputs.reserve(20);
    for (std::uint64_t index = 0; index < 20; ++index) {
        inputs.emplace_back(coquic::quic::QuicCoreSendStreamData{
            .stream_id = index * 4,
            .bytes = coquic::quic::test::bytes_from_string("GET /zero-rtt.txt\r\n"),
            .fin = true,
        });
    }

    auto result = client.advance(inputs, coquic::quic::test::test_time(1));
    ASSERT_FALSE(result.local_error.has_value());

    auto datagrams = coquic::quic::test::send_datagrams_from(result);
    ASSERT_FALSE(datagrams.empty());
    EXPECT_LT(datagrams.size(), inputs.size());

    bool saw_packed_datagram = false;
    std::vector<std::uint64_t> delivered_streams;
    for (auto &datagram : datagrams) {
        auto stream_ids = application_stream_ids_from_datagram(*client_connection, datagram);
        if (stream_ids.size() > 1) {
            saw_packed_datagram = true;
        }
        delivered_streams.insert(delivered_streams.end(), stream_ids.begin(), stream_ids.end());
    }

    EXPECT_TRUE(saw_packed_datagram);
    EXPECT_EQ(delivered_streams.size(), inputs.size());

    for (auto &effect : result.effects) {
        if (auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect)) {
            EXPECT_EQ(send->connection, 1u);
        }
    }
}

TEST(QuicCoreTest, ServerProcessesOneRttStreamBeforeHandshakeCompletesWhenApplicationKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;

    auto processed = connection.process_inbound_packet(
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

    auto received_stream = optional_value_or_terminate(connection.take_received_stream_data());
    if (received_stream.stream_id != 0u) {
        ADD_FAILURE() << "unexpected stream id";
    }
    if (received_stream.bytes != coquic::quic::test::bytes_from_string("late-handshake")) {
        ADD_FAILURE() << "unexpected stream bytes";
    }
    if (!received_stream.fin) {
        ADD_FAILURE() << "stream fin was not set";
    }
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest,
     ProcessInboundDatagramDefersOneRttStreamBeforeHandshakeCompletesWhenApplicationKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;

    auto encoded = coquic::quic::serialize_protected_datagram(
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

    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), encoded.value());
}

TEST(QuicCoreTest, ProcessInboundDatagramBuffersOutOfOrderOneRttStreamDataUntilGapCloses) {
    auto connection = make_connected_server_connection();

    auto make_datagram = [&](std::uint64_t packet_number, const coquic::quic::StreamFrame &frame) {
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

    connection.process_inbound_datagram(
        codec_value_or_terminate(make_datagram(
            7, coquic::quic::test::make_inbound_application_stream_frame("lo", 3, 0, true))),
        coquic::quic::test::test_time(1));

    ASSERT_EQ(connection.streams_.at(0).receive_buffer.buffered_bytes_.size(), 1u);
    auto &buffered = connection.streams_.at(0).receive_buffer.buffered_bytes_.begin()->second;
    EXPECT_EQ(connection.streams_.at(0).receive_buffer.buffered_bytes_.begin()->first, 3u);
    EXPECT_GT(buffered.storage()->size(), buffered.size());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    connection.process_inbound_datagram(
        codec_value_or_terminate(make_datagram(
            8, coquic::quic::test::make_inbound_application_stream_frame("hel", 0, 0, false))),
        coquic::quic::test::test_time(2));

    auto received_stream = optional_value_or_terminate(connection.take_received_stream_data());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
    // # Endpoints MUST be able to deliver stream data to an application as an
    // # ordered byte stream.
    EXPECT_EQ(received_stream.offset, 0u);
    if (coquic::quic::test::string_from_bytes(received_stream.bytes) != "hello") {
        ADD_FAILURE() << "unexpected coalesced stream bytes";
    }
    if (!received_stream.fin) {
        ADD_FAILURE() << "coalesced stream fin was not set";
    }
    ASSERT_TRUE(received_stream.final_size.has_value());
    EXPECT_EQ(*received_stream.final_size, 5u);
    EXPECT_TRUE(connection.streams_.at(0).receive_buffer.buffered_bytes_.empty());
}

TEST(QuicCoreTest, OutOfOrderReceiveModeEmitsSparseStreamRangesBeforeGapCloses) {
    auto connection = make_connected_server_connection();
    connection.config_.enable_out_of_order_receive = true;

    std::array late_frames = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = false,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 3,
            .stream_data = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string("lo")),
        }},
    };
    ASSERT_TRUE(
        connection
            .process_inbound_received_application(late_frames, coquic::quic::test::test_time(1))
            .has_value());

    auto late = optional_value_or_terminate(connection.take_received_stream_data());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
    // # implementations MAY choose to offer the ability to deliver data out
    // # of order to a receiving application.
    EXPECT_EQ(late.stream_id, 0u);
    EXPECT_EQ(late.offset, 3u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(late.payload()), "lo");
    EXPECT_FALSE(late.fin);
    EXPECT_FALSE(late.final_size.has_value());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    std::array early_frames = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = false,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 0,
            .stream_data = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string("hel")),
        }},
    };
    ASSERT_TRUE(
        connection
            .process_inbound_received_application(early_frames, coquic::quic::test::test_time(2))
            .has_value());

    auto early = optional_value_or_terminate(connection.take_received_stream_data());
    EXPECT_EQ(early.offset, 0u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(early.payload()), "hel");
    EXPECT_FALSE(early.fin);
    EXPECT_TRUE(connection.streams_.at(0).receive_buffer.buffered_bytes_.empty());
    EXPECT_EQ(connection.streams_.at(0).receive_flow_control_consumed, 5u);
    EXPECT_EQ(connection.streams_.at(0).flow_control.delivered_bytes, 5u);
    EXPECT_EQ(connection.connection_flow_control_.delivered_bytes, 5u);
}

TEST(QuicCoreTest, OutOfOrderReceiveModeSuppressesDuplicateAndOverlappingRanges) {
    auto connection = make_connected_server_connection();
    connection.config_.enable_out_of_order_receive = true;

    auto inject = [&](std::uint64_t offset, std::string_view text) {
        std::array frames = {
            coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
                .fin = false,
                .has_offset = true,
                .has_length = true,
                .stream_id = 0,
                .offset = offset,
                .stream_data =
                    coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string(text)),
            }},
        };
        return connection.process_inbound_received_application(
            frames, coquic::quic::test::test_time(static_cast<std::int64_t>(offset + text.size())));
    };

    ASSERT_TRUE(inject(4, "efgh").has_value());
    auto first = optional_value_or_terminate(connection.take_received_stream_data());
    EXPECT_EQ(first.offset, 4u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(first.payload()), "efgh");

    ASSERT_TRUE(inject(4, "efgh").has_value());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    ASSERT_TRUE(inject(2, "cdefghij").has_value());
    auto prefix = optional_value_or_terminate(connection.take_received_stream_data());
    auto suffix = optional_value_or_terminate(connection.take_received_stream_data());
    EXPECT_EQ(prefix.offset, 2u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(prefix.payload()), "cd");
    EXPECT_EQ(suffix.offset, 8u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(suffix.payload()), "ij");
    EXPECT_FALSE(connection.take_received_stream_data().has_value());
    EXPECT_EQ(connection.streams_.at(0).receive_flow_control_consumed, 8u);
    EXPECT_EQ(connection.connection_flow_control_.delivered_bytes, 8u);
}

TEST(QuicCoreTest, OutOfOrderReceiveModeReportsFinAndFinalSizeOnce) {
    auto connection = make_connected_server_connection();
    connection.config_.enable_out_of_order_receive = true;

    std::array fin_frames = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = true,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 3,
            .stream_data = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string("lo")),
        }},
    };
    ASSERT_TRUE(
        connection
            .process_inbound_received_application(fin_frames, coquic::quic::test::test_time(1))
            .has_value());

    auto late = optional_value_or_terminate(connection.take_received_stream_data());
    EXPECT_EQ(late.offset, 3u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(late.payload()), "lo");
    EXPECT_TRUE(late.fin);
    ASSERT_TRUE(late.final_size.has_value());
    EXPECT_EQ(*late.final_size, 5u);
    EXPECT_EQ(connection.streams_.at(0).receive_flow_control_consumed, 2u);
    EXPECT_FALSE(connection.streams_.at(0).peer_fin_delivered);

    ASSERT_TRUE(
        connection
            .process_inbound_received_application(fin_frames, coquic::quic::test::test_time(2))
            .has_value());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    std::array early_frames = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = false,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 0,
            .stream_data = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string("hel")),
        }},
    };
    ASSERT_TRUE(
        connection
            .process_inbound_received_application(early_frames, coquic::quic::test::test_time(3))
            .has_value());

    auto early = optional_value_or_terminate(connection.take_received_stream_data());
    EXPECT_EQ(early.offset, 0u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(early.payload()), "hel");
    EXPECT_FALSE(early.fin);
    EXPECT_EQ(connection.streams_.at(0).receive_flow_control_consumed, 5u);
    EXPECT_TRUE(connection.streams_.at(0).peer_fin_delivered);
}

TEST(QuicCoreTest, OutOfOrderReceiveModeReportsEmptyFinFinalSize) {
    auto connection = make_connected_server_connection();
    connection.config_.enable_out_of_order_receive = true;

    std::array data_frames = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = false,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 0,
            .stream_data = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string("done")),
        }},
    };
    ASSERT_TRUE(
        connection
            .process_inbound_received_application(data_frames, coquic::quic::test::test_time(1))
            .has_value());
    ASSERT_TRUE(connection.take_received_stream_data().has_value());

    std::array fin_frames = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = true,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 4,
            .stream_data = coquic::quic::SharedBytes{},
        }},
    };
    ASSERT_TRUE(
        connection
            .process_inbound_received_application(fin_frames, coquic::quic::test::test_time(2))
            .has_value());

    auto fin = optional_value_or_terminate(connection.take_received_stream_data());
    EXPECT_EQ(fin.offset, 4u);
    EXPECT_TRUE(fin.payload().empty());
    EXPECT_TRUE(fin.fin);
    ASSERT_TRUE(fin.final_size.has_value());
    EXPECT_EQ(*fin.final_size, 4u);
    EXPECT_TRUE(connection.streams_.at(0).peer_fin_delivered);
}

TEST(QuicCoreTest, OutOfOrderReceiveModeRejectsFinalSizeConflicts) {
    auto connection = make_connected_server_connection();
    connection.config_.enable_out_of_order_receive = true;

    std::array first_fin = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = true,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 2,
            .stream_data = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string("x")),
        }},
    };
    ASSERT_TRUE(
        connection.process_inbound_received_application(first_fin, coquic::quic::test::test_time(1))
            .has_value());
    ASSERT_TRUE(connection.take_received_stream_data().has_value());

    std::array conflicting_fin = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = true,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 4,
            .stream_data = coquic::quic::SharedBytes{},
        }},
    };
    auto conflict = connection.process_inbound_received_application(
        conflicting_fin, coquic::quic::test::test_time(2));

    EXPECT_FALSE(conflict.has_value());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());
}

TEST(QuicCoreTest, OutOfOrderReceiveModeReportsResetAndClearsBufferedReceiveState) {
    auto connection = make_connected_server_connection();
    connection.config_.enable_out_of_order_receive = true;

    std::array frames = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = false,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 4,
            .stream_data = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string("data")),
        }},
        coquic::quic::ReceivedFrame{coquic::quic::ResetStreamFrame{
            .stream_id = 0,
            .application_protocol_error_code = 77,
            .final_size = 8,
        }},
    };

    ASSERT_TRUE(
        connection.process_inbound_received_application(frames, coquic::quic::test::test_time(1))
            .has_value());

    auto received = optional_value_or_terminate(connection.take_received_stream_data());
    EXPECT_EQ(received.offset, 4u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(received.payload()), "data");
    auto reset = optional_value_or_terminate(connection.take_peer_reset_stream());
    EXPECT_EQ(reset.stream_id, 0u);
    EXPECT_EQ(reset.application_error_code, 77u);
    EXPECT_EQ(reset.final_size, 8u);
    ASSERT_TRUE(connection.streams_.contains(0));
    EXPECT_TRUE(connection.streams_.at(0).peer_reset_received);
    EXPECT_TRUE(connection.streams_.at(0).receive_buffer.buffered_bytes_.empty());
}

TEST(QuicCoreTest, ProcessInboundDatagramFastReceivesInOrderSharedOneRttStreamData) {
    auto connection = make_connected_server_connection();
    connection.config_.emit_shared_receive_stream_data = true;

    auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
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
                            .stream_data = coquic::quic::test::bytes_from_string("fast"),
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

    auto received_stream = optional_value_or_terminate(connection.take_received_stream_data());
    EXPECT_EQ(coquic::quic::test::string_from_bytes(received_stream.payload()), "fast");
    EXPECT_TRUE(received_stream.bytes.empty());
    EXPECT_FALSE(received_stream.shared_bytes.empty());
    EXPECT_TRUE(received_stream.fin);
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    ASSERT_TRUE(connection.streams_.contains(0));
    EXPECT_TRUE(connection.streams_.at(0).receive_buffer.buffered_bytes_.empty());
    EXPECT_EQ(connection.streams_.at(0).receive_flow_control_consumed, 4u);
    EXPECT_TRUE(connection.streams_.at(0).peer_fin_delivered);
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresAckRangeTrimmedOneRttReplay) {
    auto connection = make_connected_server_connection();
    connection.config_.emit_shared_receive_stream_data = false;

    auto make_stream_datagram = [&](std::uint64_t packet_number, std::uint64_t stream_id,
                                    std::string_view text) {
        return coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames =
                        {
                            coquic::quic::StreamFrame{
                                .fin = false,
                                .has_offset = true,
                                .has_length = true,
                                .stream_id = stream_id,
                                .offset = 0,
                                .stream_data = coquic::quic::test::bytes_from_string(text),
                            },
                        },
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
    auto make_ping_datagram = [&](std::uint64_t packet_number) {
        return coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames = {coquic::quic::PingFrame{}},
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

    connection.process_inbound_datagram(
        codec_value_or_terminate(make_stream_datagram(0, 0, "replay")),
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(connection.take_received_stream_data().has_value());

    for (std::uint64_t packet_number = 2; packet_number <= coquic::quic::kMaxTrackedAckRanges * 2;
         packet_number += 2) {
        auto datagram = make_ping_datagram(packet_number);
        ASSERT_TRUE(datagram.has_value());
        connection.process_inbound_datagram(
            datagram.value(),
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number + 1)));
        ASSERT_FALSE(connection.take_received_stream_data().has_value());
    }
    ASSERT_TRUE(connection.application_space_.received_packets.should_ignore(0));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
    // # Receivers can discard all ACK Ranges, but they MUST retain the
    // # largest packet number that has been successfully processed, as that
    // # is used to recover packet numbers from subsequent packets; see
    // # Section 17.1.
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number,
              coquic::quic::kMaxTrackedAckRanges * 2);

    connection.process_inbound_datagram(
        codec_value_or_terminate(make_stream_datagram(0, 0, "replay")),
        coquic::quic::test::test_time(200));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.3
    // # A receiver MUST discard a newly unprotected packet unless it is
    // # certain that it has not processed another packet with the same packet
    // # number from the same packet number space.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.3
    // # Duplicate suppression MUST
    // # happen after removing packet protection for the reasons described in
    // # Section 9.5 of [QUIC-TLS].
    EXPECT_FALSE(connection.take_received_stream_data().has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
    // # Receivers can discard all ACK Ranges, but they MUST retain the
    // # largest packet number that has been successfully processed, as that
    // # is used to recover packet numbers from subsequent packets; see
    // # Section 17.1.
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number,
              coquic::quic::kMaxTrackedAckRanges * 2);
    EXPECT_FALSE(connection.has_failed());
}

TEST(
    QuicCoreTest,
    ProcessInboundDatagramDefersOneRttAckAndStreamBeforeHandshakeCompletesWhenApplicationKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;

    auto encoded = coquic::quic::serialize_protected_datagram(
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

    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), encoded.value());
}

TEST(QuicCoreTest, ReceivedApplicationStreamDataCanBeEmittedAsSharedBytes) {
    auto connection = make_connected_server_connection();
    connection.config_.emit_shared_receive_stream_data = true;

    auto storage =
        std::make_shared<std::vector<std::byte>>(coquic::quic::test::bytes_from_string("xxshared"));
    std::array frames = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = true,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 0,
            .stream_data = coquic::quic::SharedBytes(storage, 2, storage->size()),
        }},
    };

    auto processed = connection.process_inbound_received_application(
        frames, coquic::quic::test::test_time(1), /*allow_preconnected_frames=*/false,
        /*path_id=*/0);
    ASSERT_TRUE(processed.has_value());

    auto received_stream = optional_value_or_terminate(connection.take_received_stream_data());
    if (!received_stream.bytes.empty()) {
        ADD_FAILURE() << "shared receive unexpectedly copied bytes";
    }
    if (received_stream.shared_bytes.storage() != storage) {
        ADD_FAILURE() << "shared receive did not preserve storage";
    }
    if (coquic::quic::test::string_from_bytes(received_stream.payload()) != "shared") {
        ADD_FAILURE() << "unexpected shared stream payload";
    }
    if (received_stream.byte_count() != 6u) {
        ADD_FAILURE() << "unexpected shared stream byte count";
    }
    if (!received_stream.fin) {
        ADD_FAILURE() << "shared stream fin was not set";
    }
}

TEST(QuicCoreTest, SharedReceiveModeFallsBackToOwnedBytesForCoalescedSegments) {
    auto connection = make_connected_server_connection();
    connection.config_.emit_shared_receive_stream_data = true;

    auto late_storage =
        std::make_shared<std::vector<std::byte>>(coquic::quic::test::bytes_from_string("two"));
    std::array late_frames = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = true,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 3,
            .stream_data = coquic::quic::SharedBytes(late_storage, 0, late_storage->size()),
        }},
    };
    ASSERT_TRUE(connection
                    .process_inbound_received_application(late_frames,
                                                          coquic::quic::test::test_time(1),
                                                          /*allow_preconnected_frames=*/false,
                                                          /*path_id=*/0)
                    .has_value());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    auto first_segment_storage =
        std::make_shared<std::vector<std::byte>>(coquic::quic::test::bytes_from_string("one"));
    std::array first_segment_frames = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
            .fin = false,
            .has_offset = true,
            .has_length = true,
            .stream_id = 0,
            .offset = 0,
            .stream_data =
                coquic::quic::SharedBytes(first_segment_storage, 0, first_segment_storage->size()),
        }},
    };
    ASSERT_TRUE(connection
                    .process_inbound_received_application(first_segment_frames,
                                                          coquic::quic::test::test_time(2),
                                                          /*allow_preconnected_frames=*/false,
                                                          /*path_id=*/0)
                    .has_value());

    auto received_stream = optional_value_or_terminate(connection.take_received_stream_data());
    if (!received_stream.shared_bytes.empty()) {
        ADD_FAILURE() << "coalesced receive unexpectedly preserved shared bytes";
    }
    if (coquic::quic::test::string_from_bytes(received_stream.bytes) != "onetwo") {
        ADD_FAILURE() << "unexpected coalesced receive bytes";
    }
    if (received_stream.byte_count() != 6u) {
        ADD_FAILURE() << "unexpected coalesced receive byte count";
    }
    if (!received_stream.fin) {
        ADD_FAILURE() << "coalesced receive fin was not set";
    }
}

TEST(QuicCoreTest, InboundSharedDatagramPreservesSharedPayload) {
    auto connection = make_connected_server_connection();
    auto storage =
        std::make_shared<std::vector<std::byte>>(coquic::quic::test::bytes_from_string("xxshared"));
    std::array frames = {
        coquic::quic::ReceivedFrame{coquic::quic::ReceivedDatagramFrame{
            .has_length = true,
            .data = coquic::quic::SharedBytes(storage, 2, storage->size()),
        }},
    };

    auto processed = connection.process_inbound_received_application(
        frames, coquic::quic::test::test_time(1), /*allow_preconnected_frames=*/false,
        /*path_id=*/0);
    ASSERT_TRUE(processed.has_value());

    auto received_datagram = optional_value_or_terminate(connection.take_received_datagram_data());
    if (!received_datagram.bytes.empty()) {
        ADD_FAILURE() << "shared datagram unexpectedly copied bytes";
    }
    if (received_datagram.shared_bytes.storage() != storage) {
        ADD_FAILURE() << "shared datagram did not preserve storage";
    }
    if (coquic::quic::test::string_from_bytes(received_datagram.payload()) != "shared") {
        ADD_FAILURE() << "unexpected shared datagram payload";
    }
    if (received_datagram.byte_count() != 6u) {
        ADD_FAILURE() << "unexpected shared datagram byte count";
    }
}

TEST(QuicCoreTest, SendStreamLocalErrorsCoverInvalidIdAndClosedSendSide) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    client.connection_->stream_open_limits_.peer_max_bidirectional = 1;

    auto invalid = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 4,
            .bytes = coquic::quic::test::bytes_from_string("x"),
            .fin = false,
        },
        coquic::quic::test::test_time());
    expect_local_error(invalid, coquic::quic::QuicCoreLocalErrorCode::invalid_stream_id, 4);

    auto fin = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("x"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    EXPECT_FALSE(fin.local_error.has_value());

    auto closed = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("y"),
            .fin = false,
        },
        coquic::quic::test::test_time(2));
    expect_local_error(closed, coquic::quic::QuicCoreLocalErrorCode::send_side_closed, 0);
}

TEST(QuicCoreTest, DatagramSendReportsPeerSupportAndSizeLocalErrors) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    client.connection_ =
        std::make_unique<coquic::quic::QuicConnection>(make_connected_client_connection());

    auto &peer_transport =
        optional_ref_or_terminate(client.connection_->peer_transport_parameters_);
    peer_transport.max_datagram_frame_size = 0;

    auto unsupported = client.advance(
        coquic::quic::QuicCoreSendDatagramData{
            .bytes = bytes_from_ints({0x01}),
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(unsupported.local_error.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.21
    // # An extension to QUIC that wishes to use a new type of frame MUST first
    // # ensure that a peer is able to understand the frame.
    //= https://www.rfc-editor.org/rfc/rfc9221#section-3
    // # Application protocols that use DATAGRAM frames MAY choose to only
    // # negotiate and use them in a single direction.
    EXPECT_EQ(optional_ref_or_terminate(unsupported.local_error).code,
              coquic::quic::QuicCoreLocalErrorCode::datagram_not_supported);
    EXPECT_FALSE(optional_ref_or_terminate(unsupported.local_error).stream_id.has_value());
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(unsupported).empty());

    auto shared_unsupported = client.advance(
        coquic::quic::QuicCoreSendSharedDatagramData{
            .bytes = coquic::quic::SharedBytes(bytes_from_ints({0x02})),
        },
        coquic::quic::test::test_time(2));
    ASSERT_TRUE(shared_unsupported.local_error.has_value());
    EXPECT_EQ(optional_ref_or_terminate(shared_unsupported.local_error).code,
              coquic::quic::QuicCoreLocalErrorCode::datagram_not_supported);
    EXPECT_FALSE(optional_ref_or_terminate(shared_unsupported.local_error).stream_id.has_value());
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(shared_unsupported).empty());

    peer_transport.max_datagram_frame_size = 2;
    auto oversized_send = client.advance(
        coquic::quic::QuicCoreSendDatagramData{
            .bytes = bytes_from_ints({0x01}),
        },
        coquic::quic::test::test_time(3));
    ASSERT_TRUE(oversized_send.local_error.has_value());
    EXPECT_EQ(optional_ref_or_terminate(oversized_send.local_error).code,
              coquic::quic::QuicCoreLocalErrorCode::datagram_too_large);
    EXPECT_FALSE(optional_ref_or_terminate(oversized_send.local_error).stream_id.has_value());
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(oversized_send).empty());
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

    auto received_data = optional_value_or_terminate(connection.take_received_stream_data());
    if (received_data.stream_id != 0u) {
        ADD_FAILURE() << "unexpected stream id";
    }
    if (!received_data.fin) {
        ADD_FAILURE() << "stream fin was not set";
    }

    ASSERT_TRUE(connection.queue_stream_send(0, bytes_from_ints({0x6f, 0x6b}), true).has_value());

    auto response_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (response_datagram.empty()) {
        ADD_FAILURE() << "missing response datagram";
        return;
    }
    if (tracked_packet_count(connection.application_space_) == 0u) {
        ADD_FAILURE() << "response datagram was not tracked";
        return;
    }

    auto response_packet_number = first_tracked_packet(connection.application_space_).packet_number;
    auto acked_response =
        connection.process_inbound_ack(connection.application_space_,
                                       coquic::quic::AckFrame{
                                           .largest_acknowledged = response_packet_number,
                                           .first_ack_range = 0,
                                       },
                                       coquic::quic::test::test_time(2),
                                       /*ack_delay_exponent=*/3,
                                       /*max_ack_delay_ms=*/25,
                                       /*suppress_pto_reset=*/false);
    if (!acked_response.has_value()) {
        ADD_FAILURE() << "response ack was rejected";
        return;
    }

    auto refresh_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    if (refresh_datagram.empty()) {
        ADD_FAILURE() << "missing stream limit refresh datagram";
        return;
    }

    auto packets = decode_sender_datagram(connection, refresh_datagram);
    if (packets.size() != 1u) {
        ADD_FAILURE() << "unexpected stream limit refresh packet count";
        return;
    }
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    if (application == nullptr) {
        ADD_FAILURE() << "stream limit refresh was not a 1-RTT packet";
        return;
    }

    bool saw_max_streams = false;
    for (auto &frame : application->frames) {
        if (auto *max_streams = std::get_if<coquic::quic::MaxStreamsFrame>(&frame)) {
            saw_max_streams = true;
            EXPECT_EQ(max_streams->stream_type, coquic::quic::StreamLimitType::bidirectional);
            EXPECT_EQ(max_streams->maximum_streams, 2u);
        }
    }

    if (!saw_max_streams) {
        ADD_FAILURE() << "missing MAX_STREAMS refresh";
    }
}

TEST(QuicCoreTest, StreamReceiveEffectCarriesFin) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    auto sent = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("hello"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        sent, server, coquic::quic::test::test_time(2));

    ASSERT_EQ(coquic::quic::test::stream_payloads_from(received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(received)[0],
              (coquic::quic::test::StreamPayload{0, "hello", true}));
}

TEST(QuicCoreTest, SmallStreamSendKeepsFinWithData) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), true)
            .has_value());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    auto stream_it =
        std::find_if(application->frames.begin(), application->frames.end(), [](auto &frame) {
            return std::holds_alternative<coquic::quic::StreamFrame>(frame);
        });
    ASSERT_NE(stream_it, application->frames.end());

    const auto &stream = std::get<coquic::quic::StreamFrame>(*stream_it);
    EXPECT_EQ(stream.stream_id, 0u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(stream.stream_data), "hello");
    EXPECT_TRUE(stream.fin);
}

TEST(QuicCoreTest, LargeStreamSendSplitsSmallTerminalDataFin) {
    auto connection = make_connected_client_connection();
    constexpr std::size_t kMinimumInitialDatagramSizeForTest = 1200;
    connection.config_.transport.pmtud_enabled = false;
    connection.config_.max_outbound_datagram_size = kMinimumInitialDatagramSizeForTest;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.max_udp_payload_size = kMinimumInitialDatagramSizeForTest;
    connection.congestion_controller_.congestion_window_ = std::uint64_t{64} * 1024u;

    constexpr std::size_t kPayloadSize = 1300;
    ASSERT_TRUE(
        connection.queue_stream_send(0, std::vector<std::byte>(kPayloadSize, std::byte{0x61}), true)
            .has_value());

    auto first = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first.empty());
    auto first_packets = decode_sender_datagram(connection, first);
    ASSERT_EQ(first_packets.size(), 1u);
    auto *first_application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&first_packets[0]);
    ASSERT_NE(first_application, nullptr);
    auto first_stream_it = std::find_if(
        first_application->frames.begin(), first_application->frames.end(),
        [](auto &frame) { return std::holds_alternative<coquic::quic::StreamFrame>(frame); });
    ASSERT_NE(first_stream_it, first_application->frames.end());
    const auto &first_stream = std::get<coquic::quic::StreamFrame>(*first_stream_it);
    EXPECT_FALSE(first_stream.fin);
    ASSERT_FALSE(first_stream.stream_data.empty());

    auto terminal_data = connection.drain_outbound_datagram(coquic::quic::test::test_time(1),
                                                            /*continue_paced_burst=*/true);
    ASSERT_FALSE(terminal_data.empty());
    EXPECT_LT(terminal_data.size(), kMinimumInitialDatagramSizeForTest);
    auto terminal_packets = decode_sender_datagram(connection, terminal_data);
    ASSERT_EQ(terminal_packets.size(), 1u);
    auto *terminal_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&terminal_packets[0]);
    ASSERT_NE(terminal_application, nullptr);
    auto terminal_stream_it = std::find_if(
        terminal_application->frames.begin(), terminal_application->frames.end(),
        [](auto &frame) { return std::holds_alternative<coquic::quic::StreamFrame>(frame); });
    ASSERT_NE(terminal_stream_it, terminal_application->frames.end());
    const auto &terminal_stream = std::get<coquic::quic::StreamFrame>(*terminal_stream_it);
    ASSERT_TRUE(terminal_stream.offset.has_value());
    EXPECT_EQ(optional_ref_or_terminate(terminal_stream.offset) +
                  terminal_stream.stream_data.size(),
              kPayloadSize);
    EXPECT_FALSE(terminal_stream.fin);
    ASSERT_FALSE(terminal_stream.stream_data.empty());

    auto fin_only = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(fin_only.empty());
    auto fin_packets = decode_sender_datagram(connection, fin_only);
    ASSERT_EQ(fin_packets.size(), 1u);
    auto *fin_application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&fin_packets[0]);
    ASSERT_NE(fin_application, nullptr);
    auto fin_stream_it = std::find_if(
        fin_application->frames.begin(), fin_application->frames.end(),
        [](auto &frame) { return std::holds_alternative<coquic::quic::StreamFrame>(frame); });
    ASSERT_NE(fin_stream_it, fin_application->frames.end());
    const auto &fin_stream = std::get<coquic::quic::StreamFrame>(*fin_stream_it);
    EXPECT_EQ(fin_stream.stream_id, 0u);
    ASSERT_TRUE(fin_stream.offset.has_value());
    EXPECT_EQ(optional_ref_or_terminate(fin_stream.offset), kPayloadSize);
    EXPECT_TRUE(fin_stream.fin);
    EXPECT_TRUE(fin_stream.stream_data.empty());
}

TEST(QuicCoreTest, StreamReceiveEffectCarriesFinWhenQueuedAfterOutstandingData) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    auto sent = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("hello"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    auto first_received = coquic::quic::test::relay_send_datagrams_to_peer(
        sent, server, coquic::quic::test::test_time(2));
    ASSERT_EQ(coquic::quic::test::stream_payloads_from(first_received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(first_received)[0],
              (coquic::quic::test::StreamPayload{0, "hello", false}));

    auto fin_only = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = {},
            .fin = true,
        },
        coquic::quic::test::test_time(3));
    auto fin_received = coquic::quic::test::relay_send_datagrams_to_peer(
        fin_only, server, coquic::quic::test::test_time(4));

    ASSERT_EQ(coquic::quic::test::stream_payloads_from(fin_received).size(), 1u);
    EXPECT_EQ(coquic::quic::test::stream_payloads_from(fin_received)[0],
              (coquic::quic::test::StreamPayload{0, "", true}));
}

TEST(QuicCoreTest, ResetStreamLocalCommandEmitsPeerResetEffect) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    auto reset = client.advance(
        coquic::quic::QuicCoreResetStream{
            .stream_id = 0,
            .application_error_code = 7,
        },
        coquic::quic::test::test_time(1));

    EXPECT_FALSE(reset.local_error.has_value());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(reset).empty());

    auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        reset, server, coquic::quic::test::test_time(2));

    ASSERT_EQ(coquic::quic::test::peer_resets_from(received).size(), 1u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11.2
    // # RESET_STREAM MUST only be instigated by the application protocol that
    // # uses QUIC.
    EXPECT_EQ(coquic::quic::test::peer_resets_from(received)[0].stream_id, 0u);
    EXPECT_EQ(coquic::quic::test::peer_resets_from(received)[0].application_error_code, 7u);
    EXPECT_EQ(coquic::quic::test::peer_resets_from(received)[0].final_size, 0u);
    EXPECT_FALSE(server.has_failed());
}

TEST(QuicCoreTest, ResetStreamLocalCommandRejectsReceiveOnlyStreams) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());

    auto result = client.advance(
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

    auto open = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 3,
            .bytes = coquic::quic::test::bytes_from_string("hello"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    auto opened = coquic::quic::test::relay_send_datagrams_to_peer(
        open, client, coquic::quic::test::test_time(2));
    ASSERT_EQ(coquic::quic::test::stream_payloads_from(opened).size(), 1u);

    auto stop = client.advance(
        coquic::quic::QuicCoreStopSending{
            .stream_id = 3,
            .application_error_code = 11,
        },
        coquic::quic::test::test_time(3));

    EXPECT_FALSE(stop.local_error.has_value());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(stop).empty());

    auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        stop, server, coquic::quic::test::test_time(4));

    ASSERT_EQ(coquic::quic::test::peer_stops_from(received).size(), 1u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
    // # If the stream is in the "Recv" or "Size Known" state, the transport
    // # SHOULD signal this by sending a STOP_SENDING frame to prompt closure
    // # of the stream in the opposite direction.
    EXPECT_EQ(coquic::quic::test::peer_stops_from(received)[0].stream_id, 3u);
    EXPECT_EQ(coquic::quic::test::peer_stops_from(received)[0].application_error_code, 11u);
    EXPECT_FALSE(server.has_failed());
}

TEST(QuicCoreTest, StopSendingLocalCommandRejectsSendOnlyStreams) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());

    auto result = client.advance(
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

    auto closed = client.advance(
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
    for (auto &datagram : coquic::quic::test::send_datagrams_from(closed)) {
        for (auto &packet : decode_sender_datagram(*client.connection_, datagram)) {
            auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (one_rtt == nullptr) {
                continue;
            }

            for (auto &frame : one_rtt->frames) {
                auto *close_frame =
                    std::get_if<coquic::quic::ApplicationConnectionCloseFrame>(&frame);
                if (close_frame == nullptr) {
                    continue;
                }

                saw_application_close = true;
                //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
                // # After the handshake is confirmed (see Section 4.1.2 of
                // # [QUIC-TLS]), an endpoint MUST send any CONNECTION_CLOSE
                // # frames in a 1-RTT packet.
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

    auto delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        closed, server, coquic::quic::test::test_time(2));
    auto changes = coquic::quic::test::state_changes_from(delivered);
    EXPECT_EQ(
        coquic::quic::test::count_state_change(changes, coquic::quic::QuicCoreStateChange::failed),
        1u);
}

TEST(QuicCoreTest, LocalApplicationCloseDropsInvalidUtf8ReasonPhrase) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    std::string invalid_reason;
    invalid_reason.push_back(static_cast<char>(0xc0));
    invalid_reason.push_back(static_cast<char>(0xaf));
    auto closed = client.advance(
        coquic::quic::QuicCoreCloseConnection{
            .application_error_code = 7,
            .reason_phrase = invalid_reason,
        },
        coquic::quic::test::test_time(1));

    bool saw_application_close = false;
    for (auto &datagram : coquic::quic::test::send_datagrams_from(closed)) {
        for (auto &packet : decode_sender_datagram(*client.connection_, datagram)) {
            auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (one_rtt == nullptr) {
                continue;
            }
            for (auto &frame : one_rtt->frames) {
                auto *close_frame =
                    std::get_if<coquic::quic::ApplicationConnectionCloseFrame>(&frame);
                if (close_frame == nullptr) {
                    continue;
                }
                saw_application_close = true;
                //= https://www.rfc-editor.org/rfc/rfc9000#section-19.19
                // # This SHOULD be a UTF-8 encoded string [RFC3629], though the
                // # frame does not carry information, such as language tags, that
                // # would aid comprehension by any entity other than the one that
                // # created the text.
                EXPECT_TRUE(close_frame->reason.bytes.empty());
            }
        }
    }
    EXPECT_TRUE(saw_application_close);
}

TEST(QuicCoreTest, PeerStopSendingQueuesAutomaticReset) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    auto sent = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("abc"),
            .fin = false,
        },
        coquic::quic::test::test_time(1));
    auto delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        sent, server, coquic::quic::test::test_time(2));
    ASSERT_EQ(coquic::quic::test::stream_payloads_from(delivered).size(), 1u);

    auto stop = server.advance(
        coquic::quic::QuicCoreStopSending{
            .stream_id = 0,
            .application_error_code = 19,
        },
        coquic::quic::test::test_time(3));
    auto client_result = coquic::quic::test::relay_send_datagrams_to_peer(
        stop, client, coquic::quic::test::test_time(4));

    ASSERT_EQ(coquic::quic::test::peer_stops_from(client_result).size(), 1u);
    EXPECT_EQ(coquic::quic::test::peer_stops_from(client_result)[0].stream_id, 0u);
    EXPECT_EQ(coquic::quic::test::peer_stops_from(client_result)[0].application_error_code, 19u);
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(client_result).empty());

    auto server_result = coquic::quic::test::relay_send_datagrams_to_peer(
        client_result, server, coquic::quic::test::test_time(5));
    ASSERT_EQ(coquic::quic::test::peer_resets_from(server_result).size(), 1u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11.2
    // # RESET_STREAM MUST only be instigated by the application protocol that
    // # uses QUIC.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
    // # An endpoint that receives a STOP_SENDING frame
    // # MUST send a RESET_STREAM frame if the stream is in the "Ready" or
    // # "Send" state.
    EXPECT_EQ(coquic::quic::test::peer_resets_from(server_result)[0].stream_id, 0u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
    // # An endpoint SHOULD copy the error code from the STOP_SENDING frame to
    // # the RESET_STREAM frame it sends, but it can use any application error
    // # code.
    EXPECT_EQ(coquic::quic::test::peer_resets_from(server_result)[0].application_error_code, 19u);
    EXPECT_EQ(coquic::quic::test::peer_resets_from(server_result)[0].final_size, 3u);
}

TEST(QuicCoreTest, InboundResetStreamFailsForSendOnlyStream) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::ResetStreamFrame{
                        .stream_id = 2,
                        .application_protocol_error_code = 7,
                        .final_size = 0,
                    }});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, PeerControlFrameCreatesLowerSameTypeStreams) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::StopSendingFrame{
                        .stream_id = 8,
                        .application_protocol_error_code = 7,
                    }});

    EXPECT_TRUE(injected);
    EXPECT_FALSE(connection.has_failed());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.2
    // # Before a stream is created, all streams of the same type with lower-
    // # numbered stream IDs MUST be created.
    EXPECT_TRUE(connection.streams_.contains(0));
    EXPECT_TRUE(connection.streams_.contains(4));
    EXPECT_TRUE(connection.streams_.contains(8));
}

TEST(QuicCoreTest, InboundStreamDataIsIgnoredAfterPeerResetStream) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    auto out_of_order = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("lo", 3, 0, false)});
    EXPECT_TRUE(out_of_order);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    auto reset = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::ResetStreamFrame{
                        .stream_id = 0,
                        .application_protocol_error_code = 7,
                        .final_size = 5,
                    }});
    EXPECT_TRUE(reset);
    EXPECT_FALSE(connection.has_failed());

    auto peer_reset = connection.take_peer_reset_stream();
    ASSERT_TRUE(peer_reset.has_value());
    if (!peer_reset.has_value()) {
        return;
    }
    EXPECT_EQ(peer_reset.value().stream_id, 0u);
    EXPECT_EQ(peer_reset.value().final_size, 5u);
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    if (!coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            connection,
            {coquic::quic::test::make_inbound_application_stream_frame("hel", 0, 0, false)})) {
        ADD_FAILURE() << "delayed stream data injection failed";
    }
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
    auto stop_sending = connection.take_peer_stop_sending();
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

TEST(QuicCoreTest, InboundDatagramWithoutLocalSupportFailsWithProtocolViolation) {
    auto connection = make_connected_server_connection();
    connection.local_transport_parameters_.max_datagram_frame_size = 0;

    auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 1,
            .packet_number = 7,
            .frames =
                {
                    coquic::quic::DatagramFrame{
                        .has_length = true,
                        .data = bytes_from_ints({0x01}),
                    },
                },
        },
        coquic::quic::test::test_time(1));

    ASSERT_FALSE(processed.has_value());
    EXPECT_TRUE(processed.error().has_transport_error_code);
    EXPECT_EQ(processed.error().transport_error_code,
              static_cast<std::uint64_t>(coquic::quic::QuicTransportErrorCode::protocol_violation));
}

TEST(QuicCoreTest, InboundDatagramLargerThanLocalLimitFailsWithProtocolViolation) {
    auto connection = make_connected_server_connection();
    connection.local_transport_parameters_.max_datagram_frame_size = 2;

    auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 1,
            .packet_number = 7,
            .frames =
                {
                    coquic::quic::DatagramFrame{
                        .has_length = true,
                        .data = bytes_from_ints({0x01}),
                    },
                },
        },
        coquic::quic::test::test_time(1));

    ASSERT_FALSE(processed.has_value());
    EXPECT_TRUE(processed.error().has_transport_error_code);
    EXPECT_EQ(processed.error().transport_error_code,
              static_cast<std::uint64_t>(coquic::quic::QuicTransportErrorCode::protocol_violation));
}

TEST(QuicCoreTest, InboundStopSendingFailsForReceiveOnlyStream) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
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

    auto first_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (first_datagram.empty()) {
        ADD_FAILURE() << "missing initial RESET_STREAM datagram";
        return;
    }
    if (tracked_packet_count(connection.application_space_) != 1u) {
        ADD_FAILURE() << "unexpected initial RESET_STREAM tracked packet count";
        return;
    }
    auto first_packet = first_tracked_packet(connection.application_space_);
    if (first_packet.reset_stream_frames.size() != 1u) {
        ADD_FAILURE() << "unexpected initial RESET_STREAM frame count";
        return;
    }

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            first_packet.packet_number)));

    auto second_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    if (second_datagram.empty()) {
        ADD_FAILURE() << "missing retransmitted RESET_STREAM datagram";
        return;
    }
    auto packets = decode_sender_datagram(connection, second_datagram);
    if (packets.size() != 1u) {
        ADD_FAILURE() << "unexpected retransmitted RESET_STREAM packet count";
        return;
    }
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    if (application == nullptr) {
        ADD_FAILURE() << "retransmitted RESET_STREAM was not a 1-RTT packet";
        return;
    }

    bool saw_reset = false;
    for (auto &frame : application->frames) {
        saw_reset = saw_reset || std::holds_alternative<coquic::quic::ResetStreamFrame>(frame);
    }
    if (!saw_reset) {
        ADD_FAILURE() << "missing retransmitted RESET_STREAM frame";
    }
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

    auto first_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (first_datagram.empty()) {
        ADD_FAILURE() << "missing initial STOP_SENDING datagram";
        return;
    }
    if (tracked_packet_count(connection.application_space_) != 1u) {
        ADD_FAILURE() << "unexpected initial STOP_SENDING tracked packet count";
        return;
    }
    auto first_packet = first_tracked_packet(connection.application_space_);
    if (first_packet.stop_sending_frames.size() != 1u) {
        ADD_FAILURE() << "unexpected initial STOP_SENDING frame count";
        return;
    }

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            first_packet.packet_number)));

    auto second_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    if (second_datagram.empty()) {
        ADD_FAILURE() << "missing retransmitted STOP_SENDING datagram";
        return;
    }
    auto packets = decode_sender_datagram(connection, second_datagram);
    if (packets.size() != 1u) {
        ADD_FAILURE() << "unexpected retransmitted STOP_SENDING packet count";
        return;
    }
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    if (application == nullptr) {
        ADD_FAILURE() << "retransmitted STOP_SENDING was not a 1-RTT packet";
        return;
    }

    bool saw_stop = false;
    for (auto &frame : application->frames) {
        saw_stop = saw_stop || std::holds_alternative<coquic::quic::StopSendingFrame>(frame);
    }
    if (!saw_stop) {
        ADD_FAILURE() << "missing retransmitted STOP_SENDING frame";
    }
}

TEST(QuicCoreTest, LostDatagramFrameIsNotRetransmitted) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection.queue_datagram_send(bytes_from_ints({0x64, 0x67})).has_value());

    auto first_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (first_datagram.empty()) {
        ADD_FAILURE() << "missing DATAGRAM frame";
        return;
    }
    auto datagram_payloads =
        application_datagram_payloads_from_datagram(connection, first_datagram);
    if (datagram_payloads != std::vector<std::vector<std::byte>>({bytes_from_ints({0x64, 0x67})})) {
        ADD_FAILURE() << "unexpected DATAGRAM frame payload";
    }
    if (!connection.pending_datagram_send_queue_.empty()) {
        ADD_FAILURE() << "DATAGRAM send queue was not drained";
    }

    if (tracked_packet_count(connection.application_space_) != 1u) {
        ADD_FAILURE() << "unexpected DATAGRAM tracked packet count";
        return;
    }
    auto sent_packet = first_tracked_packet(connection.application_space_);
    if (!sent_packet.ack_eliciting) {
        ADD_FAILURE() << "DATAGRAM packet was not ack eliciting";
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.21
    // # Extension frames MUST be congestion controlled and MUST cause an ACK
    // # frame to be sent.
    if (!sent_packet.in_flight) {
        ADD_FAILURE() << "DATAGRAM packet was not congestion controlled";
    }
    if (sent_packet.bytes_in_flight == 0) {
        ADD_FAILURE() << "DATAGRAM packet did not contribute bytes in flight";
    }
    if (sent_packet_has_stream_frames_for_tests(sent_packet)) {
        ADD_FAILURE() << "DATAGRAM packet unexpectedly carried stream frames";
    }

    auto handle = optional_value_or_terminate(
        connection.application_space_.recovery.handle_for_packet_number(sent_packet.packet_number));
    auto lost = connection.mark_lost_packet(connection.application_space_, handle);
    if (!lost.has_value()) {
        ADD_FAILURE() << "DATAGRAM packet loss did not return tracked metadata";
        return;
    }
    if (sent_packet_has_stream_frames_for_tests(optional_ref_or_terminate(lost))) {
        ADD_FAILURE() << "lost DATAGRAM packet unexpectedly carried stream frames";
    }
    if (!connection.pending_datagram_send_queue_.empty()) {
        ADD_FAILURE() << "DATAGRAM loss requeued the send queue";
    }

    auto &tracked =
        tracked_packet_or_terminate(connection.application_space_, sent_packet.packet_number);
    if (!tracked.declared_lost) {
        ADD_FAILURE() << "DATAGRAM packet was not declared lost";
    }
    if (tracked.in_flight) {
        ADD_FAILURE() << "lost DATAGRAM packet remained in flight";
    }
}

TEST(QuicCoreTest, ApplicationPtoBurstUsesFreshStreamDataAfterFirstProbe) {
    auto connection = make_connected_client_connection();
    auto payload = std::vector<std::byte>(static_cast<std::size_t>(32) * 1024u, std::byte{0x51});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::optional<std::uint64_t> first_sent_offset;
    std::optional<std::uint64_t> last_sent_offset;
    std::uint64_t next_unsent_offset = 0;
    while (true) {
        auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        auto packets = decode_sender_datagram(connection, datagram);
        if (packets.size() != 1u) {
            ADD_FAILURE() << "unexpected sent stream packet count";
            return;
        }
        auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
        if (application == nullptr) {
            ADD_FAILURE() << "sent stream datagram was not a 1-RTT packet";
            return;
        }

        for (auto &frame : application->frames) {
            auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            if (!stream->offset.has_value()) {
                ADD_FAILURE() << "stream frame did not carry an offset";
                return;
            }
            auto stream_offset = optional_value_or_terminate(stream->offset);
            if (!first_sent_offset.has_value()) {
                first_sent_offset = stream_offset;
            }
            last_sent_offset = stream_offset;
            next_unsent_offset =
                stream_offset + static_cast<std::uint64_t>(stream->stream_data.size());
        }
    }

    if (!first_sent_offset.has_value()) {
        ADD_FAILURE() << "no initial stream offset was sent";
        return;
    }
    if (!last_sent_offset.has_value()) {
        ADD_FAILURE() << "no last stream offset was sent";
        return;
    }
    if (!connection.has_pending_application_send()) {
        ADD_FAILURE() << "connection did not retain pending stream data";
        return;
    }

    auto deadline = connection.pto_deadline();
    if (!deadline.has_value()) {
        ADD_FAILURE() << "missing PTO deadline";
        return;
    }
    auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);

    auto first_probe_datagram = connection.drain_outbound_datagram(timeout);
    if (first_probe_datagram.empty()) {
        ADD_FAILURE() << "missing first PTO probe datagram";
        return;
    }

    auto first_probe_packets = decode_sender_datagram(connection, first_probe_datagram);
    if (first_probe_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected first PTO probe packet count";
        return;
    }
    auto *first_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&first_probe_packets[0]);
    if (first_application == nullptr) {
        ADD_FAILURE() << "first PTO probe was not a 1-RTT packet";
        return;
    }

    std::vector<std::uint64_t> first_probe_offsets;
    for (auto &frame : first_application->frames) {
        auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        if (!stream->offset.has_value()) {
            ADD_FAILURE() << "first PTO stream frame did not carry an offset";
            return;
        }
        first_probe_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    if (first_probe_offsets.empty()) {
        ADD_FAILURE() << "first PTO probe did not carry stream data";
        return;
    }
    if (first_probe_offsets.front() != optional_value_or_terminate(last_sent_offset)) {
        ADD_FAILURE() << "first PTO probe did not reuse the last sent offset";
    }

    auto second_probe_datagram = connection.drain_outbound_datagram(timeout);
    if (second_probe_datagram.empty()) {
        ADD_FAILURE() << "missing second PTO probe datagram";
        return;
    }

    auto second_probe_packets = decode_sender_datagram(connection, second_probe_datagram);
    if (second_probe_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected second PTO probe packet count";
        return;
    }
    auto *second_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&second_probe_packets[0]);
    if (second_application == nullptr) {
        ADD_FAILURE() << "second PTO probe was not a 1-RTT packet";
        return;
    }

    std::vector<std::uint64_t> second_probe_offsets;
    for (auto &frame : second_application->frames) {
        auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        if (!stream->offset.has_value()) {
            ADD_FAILURE() << "second PTO stream frame did not carry an offset";
            return;
        }
        second_probe_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    if (second_probe_offsets.empty()) {
        ADD_FAILURE() << "second PTO probe did not carry stream data";
        return;
    }
    if (second_probe_offsets.front() != next_unsent_offset) {
        ADD_FAILURE() << "second PTO probe did not use fresh stream data";
    }
    if (second_probe_offsets.front() == optional_value_or_terminate(last_sent_offset)) {
        ADD_FAILURE() << "second PTO probe reused the first probe offset";
    }
}

TEST(QuicCoreTest,
     ApplicationPtoBurstPrefersFreshStreamDataOverOlderLostRangesOnLastProbeDatagram) {
    auto connection = make_connected_client_connection();
    auto payload = std::vector<std::byte>(static_cast<std::size_t>(64) * 1024u, std::byte{0x52});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    struct SentStreamPacket {
        std::uint64_t packet_number;
        std::uint64_t first_stream_offset;
    };
    std::vector<SentStreamPacket> sent_stream_packets;
    std::uint64_t next_unsent_offset = 0;
    while (true) {
        auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        auto packet_number = last_tracked_packet(connection.application_space_).packet_number;
        auto &sent_packet =
            tracked_packet_or_terminate(connection.application_space_, packet_number);
        if (!sent_packet_has_stream_frames_for_tests(sent_packet)) {
            ADD_FAILURE() << "sent packet did not carry stream frames";
            return;
        }
        sent_stream_packets.push_back(SentStreamPacket{
            .packet_number = packet_number,
            .first_stream_offset = first_stream_frame_offset_for_tests(sent_packet),
        });
        next_unsent_offset = std::max(
            next_unsent_offset,
            first_stream_frame_offset_for_tests(sent_packet) +
                static_cast<std::uint64_t>(first_stream_frame_length_for_tests(sent_packet)));
    }

    if (sent_stream_packets.size() < 2u) {
        ADD_FAILURE() << "not enough stream packets were sent";
        return;
    }
    auto lost_packet = tracked_packet_or_terminate(connection.application_space_,
                                                   sent_stream_packets.front().packet_number);
    auto lost_offset = sent_stream_packets.front().first_stream_offset;
    auto probe_packet_number = sent_stream_packets.back().packet_number;
    auto probe_offset = sent_stream_packets.back().first_stream_offset;

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            lost_packet.packet_number)));

    if (!connection.streams_.contains(0)) {
        ADD_FAILURE() << "stream state was missing";
        return;
    }
    if (!connection.streams_.at(0).send_buffer.has_lost_data()) {
        ADD_FAILURE() << "lost stream data was not retained";
        return;
    }
    if (tracked_packet_or_null(connection.application_space_, probe_packet_number) == nullptr) {
        ADD_FAILURE() << "probe packet was not tracked";
        return;
    }
    if (!connection.has_pending_application_send()) {
        ADD_FAILURE() << "connection did not retain fresh pending stream data";
        return;
    }

    auto deadline = connection.pto_deadline();
    if (!deadline.has_value()) {
        ADD_FAILURE() << "missing PTO deadline";
        return;
    }
    auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);

    auto &pending_probe_packet =
        optional_ref_or_terminate(connection.application_space_.pending_probe_packet);
    if (!sent_packet_has_stream_frames_for_tests(pending_probe_packet)) {
        ADD_FAILURE() << "pending PTO probe did not carry stream frames";
        return;
    }
    if (pending_probe_packet.packet_number != probe_packet_number) {
        ADD_FAILURE() << "pending PTO probe used the wrong packet number";
    }
    if (first_stream_frame_offset_for_tests(pending_probe_packet) != probe_offset) {
        ADD_FAILURE() << "pending PTO probe used the wrong stream offset";
    }

    auto first_probe_datagram = connection.drain_outbound_datagram(timeout);
    if (first_probe_datagram.empty()) {
        ADD_FAILURE() << "missing first PTO probe datagram";
        return;
    }

    auto first_probe_packets = decode_sender_datagram(connection, first_probe_datagram);
    if (first_probe_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected first PTO probe packet count";
        return;
    }
    auto *first_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&first_probe_packets[0]);
    if (first_application == nullptr) {
        ADD_FAILURE() << "first PTO probe was not a 1-RTT packet";
        return;
    }

    std::vector<std::uint64_t> first_probe_offsets;
    for (auto &frame : first_application->frames) {
        auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        if (!stream->offset.has_value()) {
            ADD_FAILURE() << "first PTO stream frame did not carry an offset";
            return;
        }
        first_probe_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    if (first_probe_offsets.empty()) {
        ADD_FAILURE() << "first PTO probe did not carry stream data";
        return;
    }
    if (first_probe_offsets.front() != probe_offset) {
        ADD_FAILURE() << "first PTO probe did not use the pending probe offset";
    }

    auto second_probe_datagram = connection.drain_outbound_datagram(timeout);
    if (second_probe_datagram.empty()) {
        ADD_FAILURE() << "missing second PTO probe datagram";
        return;
    }

    auto second_probe_packets = decode_sender_datagram(connection, second_probe_datagram);
    if (second_probe_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected second PTO probe packet count";
        return;
    }
    auto *second_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&second_probe_packets[0]);
    if (second_application == nullptr) {
        ADD_FAILURE() << "second PTO probe was not a 1-RTT packet";
        return;
    }

    std::vector<std::uint64_t> second_probe_offsets;
    for (auto &frame : second_application->frames) {
        auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        if (!stream->offset.has_value()) {
            ADD_FAILURE() << "second PTO stream frame did not carry an offset";
            return;
        }
        second_probe_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    if (second_probe_offsets.empty()) {
        ADD_FAILURE() << "second PTO probe did not carry stream data";
        return;
    }
    if (second_probe_offsets.front() != next_unsent_offset) {
        ADD_FAILURE() << "second PTO probe did not use fresh stream data";
    }
    if (second_probe_offsets.front() == lost_offset) {
        ADD_FAILURE() << "second PTO probe used the older lost offset";
    }
    if (second_probe_offsets.front() == probe_offset) {
        ADD_FAILURE() << "second PTO probe reused the pending probe offset";
    }
}

TEST(QuicCoreTest, ApplicationPtoPrefersPendingStreamDataOverControlOnlyProbe) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));
    auto crypto_ranges = connection.application_space_.send_crypto.take_ranges(
        std::numeric_limits<std::size_t>::max());
    ASSERT_FALSE(crypto_ranges.empty());

    auto payload = std::vector<std::byte>(static_cast<std::size_t>(1024), std::byte{0x53});
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

    auto deadline = connection.pto_deadline();
    if (!deadline.has_value()) {
        ADD_FAILURE() << "missing PTO deadline";
        return;
    }
    auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);

    auto datagram = connection.drain_outbound_datagram(timeout);
    if (datagram.empty()) {
        ADD_FAILURE() << "missing PTO datagram";
        return;
    }

    auto packets = decode_sender_datagram(connection, datagram);
    if (packets.size() != 1u) {
        ADD_FAILURE() << "unexpected PTO packet count";
        return;
    }
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    if (application == nullptr) {
        ADD_FAILURE() << "PTO datagram was not a 1-RTT packet";
        return;
    }

    bool saw_stream = false;
    bool saw_crypto = false;
    bool saw_handshake_done = false;
    for (auto &frame : application->frames) {
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
        saw_crypto = saw_crypto || std::holds_alternative<coquic::quic::CryptoFrame>(frame);
        saw_handshake_done =
            saw_handshake_done || std::holds_alternative<coquic::quic::HandshakeDoneFrame>(frame);
    }

    if (!saw_stream) {
        ADD_FAILURE() << "PTO datagram did not carry stream data";
    }
    if (!saw_crypto && !saw_handshake_done) {
        ADD_FAILURE() << "PTO datagram did not carry control data";
    }
}

TEST(QuicCoreTest, SelectPtoProbePrefersOutstandingStreamDataOverNewerControlOnlyPacket) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;

    auto payload = coquic::quic::test::bytes_from_string("server-response");
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

    auto stream_probe = connection.select_pto_probe(connection.application_space_);

    if (stream_probe.packet_number != 10u) {
        ADD_FAILURE() << "PTO probe selected the wrong packet number";
    }
    if (stream_probe.stream_fragments.size() != 1u) {
        ADD_FAILURE() << "PTO probe did not carry exactly one stream fragment";
        return;
    }
    if (stream_probe.stream_fragments.front().stream_id != 0u) {
        ADD_FAILURE() << "PTO probe selected the wrong stream";
    }
    if (stream_probe.stream_fragments.front().bytes != payload) {
        ADD_FAILURE() << "PTO probe selected the wrong payload";
    }
    if (!stream_probe.stream_fragments.front().fin) {
        ADD_FAILURE() << "PTO probe did not preserve FIN";
    }
}

TEST(QuicCoreTest, ApplicationPtoSkipsProbePacketsWhoseStreamDataWasAckedByRetransmission) {
    auto connection = make_connected_client_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    auto payload = coquic::quic::test::bytes_from_string("hello probe");
    stream.send_buffer.append(payload);
    stream.send_buffer.mark_lost(/*offset=*/0, payload.size());

    auto make_fragment = [&]() {
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

    auto pto_probe = connection.select_pto_probe(connection.application_space_);
    if (!pto_probe.stream_fragments.empty()) {
        ADD_FAILURE() << "PTO probe kept acked stream fragments";
    }
    if (!pto_probe.has_ping) {
        ADD_FAILURE() << "PTO probe did not fall back to PING";
    }
    connection.application_space_.pending_probe_packet = pto_probe;
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    if (datagram.empty()) {
        ADD_FAILURE() << "missing application send datagram";
        return;
    }
    if (connection.application_space_.pending_probe_packet.has_value()) {
        ADD_FAILURE() << "pending PTO probe was not cleared";
    }
    if (tracked_packet_count(connection.application_space_) != 1u) {
        ADD_FAILURE() << "unexpected tracked packet count";
        return;
    }
    if (!sent_packet_has_stream_frames_for_tests(
            first_tracked_packet(connection.application_space_))) {
        ADD_FAILURE() << "application send datagram did not carry stream frames";
    }
}

TEST(QuicCoreTest, ApplicationSendBudgetsManyFinOnlyStreamsWithinDatagramLimit) {
    auto connection = make_connected_client_connection();
    connection.stream_open_limits_.peer_max_bidirectional = 512;
    for (std::uint64_t stream_index = 0; stream_index < 512; ++stream_index) {
        ASSERT_TRUE(connection.queue_stream_send(stream_index * 4, {}, true).has_value());
    }

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());
}

TEST(QuicCoreTest, ExpiredApplicationAckDeadlineSendsAckBeforeMoreStreamData) {
    auto connection = make_connected_server_connection();
    auto payload = std::vector<std::byte>(static_cast<std::size_t>(8192), std::byte{0x53});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    for (std::uint64_t packet_number = 0; packet_number < 1200; packet_number += 2) {
        connection.application_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

    connection.on_timeout(coquic::quic::test::test_time(1));
    auto ack_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    if (ack_datagram.empty()) {
        ADD_FAILURE() << "missing ACK datagram";
        return;
    }
    auto ack_packets = decode_sender_datagram(connection, ack_datagram);
    if (ack_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected ACK datagram packet count";
        return;
    }
    auto *ack_application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&ack_packets.front());
    if (ack_application == nullptr) {
        ADD_FAILURE() << "ACK datagram was not a 1-RTT packet";
        return;
    }

    bool saw_ack = false;
    bool saw_stream = false;
    for (auto &frame : ack_application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    if (!saw_ack) {
        ADD_FAILURE() << "ACK datagram did not carry an ACK frame";
    }
    if (saw_stream) {
        ADD_FAILURE() << "ACK datagram unexpectedly carried stream data";
    }
    if (connection.application_space_.received_packets.has_ack_to_send()) {
        ADD_FAILURE() << "ACK state was not drained";
    }
    if (connection.application_space_.pending_ack_deadline != std::nullopt) {
        ADD_FAILURE() << "ACK deadline was not cleared";
    }
    if (connection.application_space_.force_ack_send) {
        ADD_FAILURE() << "force ACK flag was not cleared";
    }

    auto data_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    if (data_datagram.empty()) {
        ADD_FAILURE() << "missing deferred data datagram";
        return;
    }
    if (application_stream_ids_from_datagram(connection, data_datagram).empty()) {
        ADD_FAILURE() << "deferred data datagram did not carry stream data";
    }
}

TEST(QuicCoreTest, NewDataSchedulingRoundsRobinAcrossSendableStreams) {
    auto connection = make_connected_client_connection();
    auto payload = std::vector<std::byte>(static_cast<std::size_t>(2000), std::byte{0x61});

    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(4, payload, false).has_value());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto stream_ids = application_stream_ids_from_datagram(connection, datagram);
    EXPECT_EQ(stream_ids, std::vector<std::uint64_t>{0});

    auto next_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(next_datagram.empty());
    EXPECT_EQ(application_stream_ids_from_datagram(connection, next_datagram),
              std::vector<std::uint64_t>{4});
}

TEST(QuicCoreTest, NewDataSchedulingResumesRoundRobinAfterLastSentStream) {
    auto connection = make_connected_client_connection();
    auto payload = std::vector<std::byte>(static_cast<std::size_t>(2000), std::byte{0x61});

    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(4, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(8, payload, false).has_value());
    connection.last_application_send_stream_id_ = 4;

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(application_stream_ids_from_datagram(connection, datagram),
              std::vector<std::uint64_t>{8});

    auto next_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(next_datagram.empty());
    EXPECT_EQ(application_stream_ids_from_datagram(connection, next_datagram),
              std::vector<std::uint64_t>{0});
}

TEST(QuicCoreTest, LargeDatagramSchedulingLimitsFreshDataToLeadingBulkStreamsPerPacket) {
    auto connection = make_connected_client_connection();
    constexpr std::size_t kLargeDatagramSize = std::size_t{16} * 1024u;
    constexpr std::uint64_t kLargeFlowCredit = std::uint64_t{128} * 1024u;
    connection.config_.transport.pmtud_enabled = true;
    connection.paths_.at(0).mtu.validated_datagram_size = kLargeDatagramSize;
    connection.paths_.at(0).mtu.probe_ceiling = kLargeDatagramSize;
    connection.config_.transport.pmtud_max_datagram_size = kLargeDatagramSize;
    connection.config_.max_outbound_datagram_size = kLargeDatagramSize;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.max_udp_payload_size = static_cast<std::uint64_t>(kLargeDatagramSize);
    peer_transport_parameters.initial_max_data = kLargeFlowCredit;
    peer_transport_parameters.initial_max_stream_data_bidi_remote = kLargeFlowCredit;
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = kLargeFlowCredit;
    auto payload = std::vector<std::byte>(static_cast<std::size_t>(12000), std::byte{0x61});

    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(4, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(8, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(12, payload, false).has_value());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(application_stream_ids_from_datagram(connection, datagram),
              (std::vector<std::uint64_t>{0, 4}));
}

TEST(QuicCoreTest, BulkStreamDatagramsFillValidatedMtuExactly) {
    constexpr std::array kPathUdpPayloadSizes = {std::size_t{1452}, std::size_t{1472}};
    for (auto path_udp_payload_size : kPathUdpPayloadSizes) {
        auto connection = make_connected_client_connection();
        connection.config_.transport.pmtud_enabled = true;
        connection.paths_.at(0).mtu.validated_datagram_size = path_udp_payload_size;
        connection.paths_.at(0).mtu.probe_ceiling = path_udp_payload_size;
        connection.config_.transport.pmtud_max_datagram_size = path_udp_payload_size;
        connection.config_.max_outbound_datagram_size = path_udp_payload_size;
        auto &peer_transport_parameters =
            optional_ref_or_terminate(connection.peer_transport_parameters_);
        peer_transport_parameters.max_udp_payload_size =
            static_cast<std::uint64_t>(path_udp_payload_size);
        connection.congestion_controller_.congestion_window_ = std::uint64_t{64} * 1024u;

        auto payload =
            std::vector<std::byte>(static_cast<std::size_t>(32) * 1024u, std::byte{0x61});
        ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

        auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

        ASSERT_FALSE(datagram.empty());
        //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
        // # All QUIC packets that are not sent in a PMTU probe SHOULD be
        // # sized to fit within the maximum datagram size to avoid the
        // # datagram being fragmented or dropped [RFC8085].
        EXPECT_EQ(datagram.size(), path_udp_payload_size);
    }
}

TEST(QuicCoreTest, DisabledPmtudCapsApplicationDatagramsAtMinimumSize) {
    auto connection = make_connected_client_connection();
    connection.config_.transport.pmtud_enabled = false;
    connection.config_.max_outbound_datagram_size = 4096;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.max_udp_payload_size = 4096;
    peer_transport_parameters.initial_max_data = std::uint64_t{64} * 1024u;
    peer_transport_parameters.initial_max_stream_data_bidi_remote = std::uint64_t{64} * 1024u;
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = std::size_t{64} * 1024u;

    const auto payload = std::vector<std::byte>(std::size_t{32} * 1024u, std::byte{0x42});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
    // # In the absence of these mechanisms, QUIC endpoints SHOULD NOT send
    // # datagrams larger than the smallest allowed maximum datagram size.
    EXPECT_LE(datagram.size(), 1200u);
}

TEST(QuicCoreTest, LastPtoProbeFreshSchedulingTreatsSingleFinOnlyStreamAsActive) {
    auto connection = make_connected_client_connection();
    constexpr std::size_t kLargeDatagramSize = std::size_t{16} * 1024u;
    connection.config_.max_outbound_datagram_size = kLargeDatagramSize;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.max_udp_payload_size = static_cast<std::uint64_t>(kLargeDatagramSize);
    connection.congestion_controller_.congestion_window_ = kLargeDatagramSize;

    ASSERT_TRUE(connection.queue_stream_send(/*stream_id=*/0, {}, /*fin=*/true).has_value());
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 17,
        .ack_eliciting = true,
        .in_flight = true,
    };
    connection.remaining_pto_probe_datagrams_ = 1;
    ASSERT_TRUE(connection.has_pending_fresh_application_stream_send());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    if (datagram.empty()) {
        ADD_FAILURE() << "missing PTO FIN-only datagram";
        return;
    }
    auto packets = decode_sender_datagram(connection, datagram);
    if (packets.size() != 1u) {
        ADD_FAILURE() << "unexpected PTO FIN-only packet count";
        return;
    }
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    if (application == nullptr) {
        ADD_FAILURE() << "PTO FIN-only datagram was not a 1-RTT packet";
        return;
    }

    auto stream_it =
        std::find_if(application->frames.begin(), application->frames.end(), [](auto &frame) {
            return std::holds_alternative<coquic::quic::StreamFrame>(frame);
        });
    if (stream_it == application->frames.end()) {
        ADD_FAILURE() << "PTO FIN-only datagram did not carry a stream frame";
        return;
    }
    auto &stream = std::get<coquic::quic::StreamFrame>(*stream_it);
    if (stream.stream_id != 0u) {
        ADD_FAILURE() << "PTO FIN-only datagram used the wrong stream";
    }
    if (!stream.fin) {
        ADD_FAILURE() << "PTO FIN-only stream frame did not preserve FIN";
    }
    if (!stream.stream_data.empty()) {
        ADD_FAILURE() << "PTO FIN-only stream frame carried data";
    }
}

TEST(QuicCoreTest, RetransmissionPreservesStreamIdentityAcrossMultipleStreams) {
    auto connection = make_connected_client_connection();
    auto payload = std::vector<std::byte>(static_cast<std::size_t>(2000), std::byte{0x62});

    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    ASSERT_TRUE(connection.queue_stream_send(4, payload, false).has_value());

    auto first_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (first_datagram.empty()) {
        ADD_FAILURE() << "missing first stream datagram";
        return;
    }
    if (tracked_packet_count(connection.application_space_) != 1u) {
        ADD_FAILURE() << "unexpected first datagram tracked packet count";
        return;
    }
    auto first_packet = first_tracked_packet(connection.application_space_);

    auto second_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    if (second_datagram.empty()) {
        ADD_FAILURE() << "missing second stream datagram";
        return;
    }
    if (tracked_packet_count(connection.application_space_) != 2u) {
        ADD_FAILURE() << "unexpected second datagram tracked packet count";
        return;
    }
    auto second_packet = tracked_packet_or_terminate(connection.application_space_, 1);

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            first_packet.packet_number)));
    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            second_packet.packet_number)));

    auto repaired_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    if (repaired_datagram.empty()) {
        ADD_FAILURE() << "missing repaired stream datagram";
        return;
    }

    auto stream_ids = application_stream_ids_from_datagram(connection, repaired_datagram);
    if (std::find(stream_ids.begin(), stream_ids.end(), 0) == stream_ids.end()) {
        ADD_FAILURE() << "repaired datagram did not preserve stream 0";
    }
    if (std::find(stream_ids.begin(), stream_ids.end(), 4) == stream_ids.end()) {
        ADD_FAILURE() << "repaired datagram did not preserve stream 4";
    }
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_stream_data_blocked = false;
    bool saw_stream = false;
    for (auto &frame : application->frames) {
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
    auto maximum_streams = connection.local_stream_limit_state_.advertised_max_streams_bidi + 1;
    connection.local_stream_limit_state_.queue_max_streams(
        coquic::quic::StreamLimitType::bidirectional, maximum_streams);
    connection.congestion_controller_.bytes_in_flight_ =
        connection.congestion_controller_.congestion_window_;

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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
    auto invalid_id = connection.queue_stream_reset({.stream_id = 4, .application_error_code = 7});
    ASSERT_FALSE(invalid_id.has_value());
    EXPECT_EQ(invalid_id.error().code, coquic::quic::StreamStateErrorCode::invalid_stream_id);

    auto result = connection.queue_stream_reset({.stream_id = 3, .application_error_code = 7});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::quic::StreamStateErrorCode::invalid_stream_direction);
}

TEST(QuicCoreTest, QueueStreamSendRejectsInvalidIdsAndClosedSendSide) {
    auto connection = make_connected_client_connection();
    auto payload = bytes_from_ints({0x61});
    connection.stream_open_limits_.peer_max_bidirectional = 1;

    ASSERT_TRUE(connection.queue_stream_send(/*stream_id=*/1, payload, false).has_value());

    auto invalid_local = connection.queue_stream_send(/*stream_id=*/4, payload, false);
    ASSERT_FALSE(invalid_local.has_value());
    EXPECT_EQ(invalid_local.error().code, coquic::quic::StreamStateErrorCode::invalid_stream_id);

    auto peer_unidirectional = connection.queue_stream_send(/*stream_id=*/3, payload, false);
    ASSERT_FALSE(peer_unidirectional.has_value());
    EXPECT_EQ(peer_unidirectional.error().code,
              coquic::quic::StreamStateErrorCode::invalid_stream_direction);

    ASSERT_TRUE(connection.queue_stream_send(/*stream_id=*/0, {}, /*fin=*/true).has_value());
    auto closed = connection.queue_stream_send(/*stream_id=*/0, payload, /*fin=*/false);
    ASSERT_FALSE(closed.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
    // # An endpoint MUST NOT send data on a stream at or beyond the final size.
    EXPECT_EQ(closed.error().code, coquic::quic::StreamStateErrorCode::send_side_closed);
}

TEST(QuicCoreTest, PeerStreamOpenLimitsTrackStreamsBlockedAcrossQueueLossAndAck) {
    coquic::quic::StreamOpenLimits limits;
    limits.peer_max_bidirectional = 2;
    limits.peer_max_unidirectional = 3;

    limits.queue_streams_blocked(coquic::quic::StreamLimitType::bidirectional);
    ASSERT_TRUE(limits.pending_streams_blocked_bidi_frame.has_value());
    EXPECT_EQ(limits.streams_blocked_bidi_state, coquic::quic::StreamControlFrameState::pending);

    auto first_frames = limits.take_streams_blocked_frames();
    ASSERT_EQ(first_frames.size(), 1u);
    EXPECT_EQ(first_frames.front().stream_type, coquic::quic::StreamLimitType::bidirectional);
    EXPECT_EQ(first_frames.front().maximum_streams, 2u);
    EXPECT_EQ(limits.streams_blocked_bidi_state, coquic::quic::StreamControlFrameState::sent);

    limits.mark_streams_blocked_frame_lost(first_frames.front());
    EXPECT_EQ(limits.streams_blocked_bidi_state, coquic::quic::StreamControlFrameState::pending);

    auto retry_frames = limits.take_streams_blocked_frames();
    ASSERT_EQ(retry_frames.size(), 1u);
    limits.acknowledge_streams_blocked_frame(retry_frames.front());
    EXPECT_EQ(limits.streams_blocked_bidi_state,
              coquic::quic::StreamControlFrameState::acknowledged);

    limits.queue_streams_blocked(coquic::quic::StreamLimitType::bidirectional);
    ASSERT_TRUE(limits.pending_streams_blocked_bidi_frame.has_value());
    limits.note_peer_max_streams(coquic::quic::StreamLimitType::bidirectional, 4);
    EXPECT_EQ(limits.streams_blocked_bidi_state, coquic::quic::StreamControlFrameState::none);
    EXPECT_FALSE(limits.pending_streams_blocked_bidi_frame.has_value());

    limits.queue_streams_blocked(coquic::quic::StreamLimitType::unidirectional);
    auto uni_frames = limits.take_streams_blocked_frames();
    ASSERT_EQ(uni_frames.size(), 1u);
    EXPECT_EQ(uni_frames.front().stream_type, coquic::quic::StreamLimitType::unidirectional);
    EXPECT_EQ(uni_frames.front().maximum_streams, 3u);
}

TEST(QuicCoreTest, LocalOpenBlockedByPeerLimitSendsStreamsBlockedFrame) {
    auto connection = make_connected_client_connection();
    auto payload = bytes_from_ints({0x61});
    connection.stream_open_limits_.peer_max_bidirectional = 1;

    auto blocked = connection.queue_stream_send(/*stream_id=*/4, payload, false);

    ASSERT_FALSE(blocked.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
    // # An endpoint that is unable to open a new stream due to the peer's
    // # limits SHOULD send a STREAMS_BLOCKED frame (Section 19.14).
    EXPECT_EQ(blocked.error().code, coquic::quic::StreamStateErrorCode::invalid_stream_id);

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    const coquic::quic::StreamsBlockedFrame *blocked_frame = nullptr;
    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        if (const auto *candidate = std::get_if<coquic::quic::StreamsBlockedFrame>(&frame)) {
            blocked_frame = candidate;
        }
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    ASSERT_NE(blocked_frame, nullptr);
    EXPECT_EQ(blocked_frame->stream_type, coquic::quic::StreamLimitType::bidirectional);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.14
    // # A sender SHOULD send a STREAMS_BLOCKED frame (type=0x16 or 0x17) when
    // # it wishes to open a stream but is unable to do so due to the maximum
    // # stream limit set by its peer; see Section 19.11.
    EXPECT_EQ(blocked_frame->maximum_streams, 1u);
    EXPECT_FALSE(saw_stream);

    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);
    const auto sent = first_tracked_packet(connection.application_space_);
    ASSERT_EQ(sent.streams_blocked_frames.size(), 1u);
    EXPECT_EQ(connection.stream_open_limits_.streams_blocked_bidi_state,
              coquic::quic::StreamControlFrameState::sent);

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(
            connection.application_space_.recovery.handle_for_packet_number(sent.packet_number)));
    EXPECT_EQ(connection.stream_open_limits_.streams_blocked_bidi_state,
              coquic::quic::StreamControlFrameState::pending);
}

TEST(QuicCoreTest, LocalOpenBlockedByPeerUnidirectionalLimitSendsStreamsBlockedFrame) {
    auto connection = make_connected_client_connection();
    connection.stream_open_limits_.peer_max_unidirectional = 0;
    auto blocked = connection.queue_stream_send(/*stream_id=*/2, bytes_from_ints({0x61}), false);

    ASSERT_FALSE(blocked.has_value());
    ASSERT_EQ(blocked.error().code, coquic::quic::StreamStateErrorCode::invalid_stream_id);
    ASSERT_EQ(connection.stream_open_limits_.streams_blocked_uni_state,
              coquic::quic::StreamControlFrameState::pending);

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    const coquic::quic::StreamsBlockedFrame *blocked_frame = nullptr;
    for (const auto &frame : application->frames) {
        if (const auto *candidate = std::get_if<coquic::quic::StreamsBlockedFrame>(&frame)) {
            blocked_frame = candidate;
        }
    }

    ASSERT_NE(blocked_frame, nullptr);
    EXPECT_EQ(blocked_frame->stream_type, coquic::quic::StreamLimitType::unidirectional);
    EXPECT_EQ(blocked_frame->maximum_streams, 0u);
}

TEST(QuicCoreTest, QueueStreamSendReturnsSuccessWithoutOpeningStreamWhenConnectionAlreadyFailed) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::failed;

    auto queued = connection.queue_stream_send(/*stream_id=*/0, bytes_from_ints({0x61}),
                                               /*fin=*/false);

    ASSERT_TRUE(queued.has_value());
    EXPECT_TRUE(queued.value());
    EXPECT_FALSE(connection.streams_.contains(0));
}

TEST(QuicCoreTest, QueueStreamSendSharedBuffersPayloadAndTracksCommittedFlowControl) {
    auto connection = make_connected_client_connection();
    auto payload =
        coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string("shared-payload"));

    auto queued = connection.queue_stream_send_shared(/*stream_id=*/0, payload, /*fin=*/false);

    ASSERT_TRUE(queued.has_value());
    EXPECT_TRUE(queued.value());
    ASSERT_TRUE(connection.streams_.contains(0));
    auto &stream = connection.streams_.at(0);
    EXPECT_TRUE(stream.send_buffer.has_pending_data());
    EXPECT_EQ(stream.send_flow_control_committed, static_cast<std::uint64_t>(payload.size()));
}

TEST(QuicCoreTest, QueueStreamSendSharedReturnsSuccessWithoutOpeningStreamForEmptySharedPayload) {
    auto connection = make_connected_client_connection();

    auto queued = connection.queue_stream_send_shared(/*stream_id=*/0, coquic::quic::SharedBytes{},
                                                      /*fin=*/false);

    ASSERT_TRUE(queued.has_value());
    EXPECT_TRUE(queued.value());
    EXPECT_FALSE(connection.streams_.contains(0));
}

TEST(QuicCoreTest, QueueStreamSendSharedAllowsFinOnlySendWithEmptySharedPayload) {
    auto connection = make_connected_client_connection();

    auto queued = connection.queue_stream_send_shared(/*stream_id=*/0, coquic::quic::SharedBytes{},
                                                      /*fin=*/true);

    ASSERT_TRUE(queued.has_value());
    EXPECT_TRUE(queued.value());
    ASSERT_TRUE(connection.streams_.contains(0));
    auto &stream = connection.streams_.at(0);
    EXPECT_FALSE(stream.send_buffer.has_pending_data());
    EXPECT_EQ(stream.send_fin_state, coquic::quic::StreamSendFinState::pending);
    ASSERT_TRUE(stream.send_final_size.has_value());
    EXPECT_EQ(optional_value_or_terminate(stream.send_final_size), 0u);
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

    auto packet = coquic::quic::SentPacketRecord{
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

    auto packet = coquic::quic::SentPacketRecord{
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
    auto &lost_packet =
        tracked_packet_or_terminate(connection.application_space_, packet.packet_number);
    if (!lost_packet.declared_lost) {
        ADD_FAILURE() << "packet was not marked lost";
    }
    if (lost_packet.in_flight) {
        ADD_FAILURE() << "lost packet remained in flight";
    }
}

TEST(QuicCoreTest, InboundApplicationStreamAllowsOmittedOffsetAndLengthFlags) {
    coquic::quic::QuicConnection missing_offset_connection(
        coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        missing_offset_connection, coquic::quic::HandshakeStatus::connected);
    auto missing_offset_ok =
        coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            missing_offset_connection, {coquic::quic::test::make_inbound_application_stream_frame(
                                           "a", 0, 0, false, false, true)});
    EXPECT_TRUE(missing_offset_ok);
    EXPECT_FALSE(missing_offset_connection.has_failed());
    auto missing_offset_data = missing_offset_connection.take_received_stream_data();
    ASSERT_TRUE(missing_offset_data.has_value());
    if (!missing_offset_data.has_value()) {
        return;
    }
    auto &missing_offset_effect = missing_offset_data.value();
    EXPECT_EQ(coquic::quic::test::string_from_bytes(missing_offset_effect.bytes), "a");

    coquic::quic::QuicConnection missing_length_connection(
        coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        missing_length_connection, coquic::quic::HandshakeStatus::connected);
    if (!coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            missing_length_connection, {coquic::quic::test::make_inbound_application_stream_frame(
                                           "b", 0, 0, false, true, false)})) {
        ADD_FAILURE() << "missing-length stream data injection failed";
        return;
    }
    EXPECT_FALSE(missing_length_connection.has_failed());
    auto missing_length_effect =
        optional_value_or_terminate(missing_length_connection.take_received_stream_data());
    if (coquic::quic::test::string_from_bytes(missing_length_effect.bytes) != "b") {
        ADD_FAILURE() << "unexpected missing-length stream bytes";
    }
}

TEST(QuicCoreTest, InboundApplicationStreamFailsBeforeHandshakeConnected) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::in_progress);

    auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("ping")});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());
}

TEST(QuicCoreTest, InboundApplicationStreamFailsForNonZeroStreamId) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("ping", 0, 1)});

    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.8
    // # An endpoint MUST terminate the connection with error STREAM_STATE_ERROR
    // # if it receives a STREAM frame for a locally initiated stream that has
    // # not yet been created, or for a send-only stream.
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

    auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("ping", 0, 0)});

    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
    // # An endpoint that receives a frame with a stream ID exceeding the
    // # limit it has sent MUST treat this as a connection error of type
    // # STREAM_LIMIT_ERROR; see Section 11 for details on error handling.
    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());
}

TEST(QuicCoreTest, PeerStreamFrameCreatesLowerSameTypeStreams) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::test::make_inbound_application_stream_frame("ping", 0, 8, false)});

    EXPECT_TRUE(injected);
    EXPECT_FALSE(connection.has_failed());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.2
    // # Before a stream is created, all streams of the same type with lower-
    // # numbered stream IDs MUST be created.
    EXPECT_TRUE(connection.streams_.contains(0));
    EXPECT_TRUE(connection.streams_.contains(4));
    EXPECT_TRUE(connection.streams_.contains(8));
}

TEST(QuicCoreTest, InboundApplicationStreamCarriesFinWhenFinalDataBecomesContiguous) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    auto out_of_order = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("lo", 3, 0, true)});
    EXPECT_TRUE(out_of_order);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::test::make_inbound_application_stream_frame("hel", 0, 0, false)});

    EXPECT_TRUE(injected);
    EXPECT_FALSE(connection.has_failed());
    auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    if (!received.has_value()) {
        return;
    }
    auto &received_stream = *received;
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

    auto pto_probe = connection.select_pto_probe(packet_space);
    if (!pto_probe.max_streams_frames.empty()) {
        ADD_FAILURE() << "PTO probe retained acked MAX_STREAMS frames";
    }
    if (!pto_probe.has_ping) {
        ADD_FAILURE() << "PTO probe did not fall back to PING";
    }
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
        connection.reset_unpaced_ack_eliciting_burst();
        auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(i) + 1));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
        delivered_packet_numbers.push_back(
            last_tracked_packet(connection.application_space_).packet_number);
    }
    for (std::size_t i = 0; i < kGapPackets; ++i) {
        connection.reset_unpaced_ack_eliciting_burst();
        auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(kDeliveredPackets + i + 1u)));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
        gap_packet_numbers.push_back(
            last_tracked_packet(connection.application_space_).packet_number);
    }

    ASSERT_FALSE(delivered_packet_numbers.empty());
    ASSERT_FALSE(gap_packet_numbers.empty());
    auto first_gap_packet_number = gap_packet_numbers.front();
    auto first_gap_packet =
        tracked_packet_or_terminate(connection.application_space_, first_gap_packet_number);
    ASSERT_TRUE(sent_packet_has_stream_frames_for_tests(first_gap_packet));
    auto tracked_gap_offset = first_stream_frame_offset_for_tests(first_gap_packet);

    ASSERT_TRUE(connection
                    .process_inbound_application(
                        std::vector<coquic::quic::Frame>{
                            coquic::quic::PingFrame{},
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

    auto migration_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(100));
    ASSERT_FALSE(migration_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 11u);
    ASSERT_TRUE(connection.paths_.contains(11));
    ASSERT_TRUE(connection.paths_.at(11).outstanding_challenge.has_value());
    auto challenge = optional_ref_or_terminate(connection.paths_.at(11).outstanding_challenge);
    auto migration_packet_number = last_tracked_packet(connection.application_space_).packet_number;

    auto first_delivered_packet_number = delivered_packet_numbers.front();
    auto last_delivered_packet_number = delivered_packet_numbers.back();
    ASSERT_GT(migration_packet_number, last_delivered_packet_number + 1);

    auto ack_gap = migration_packet_number - last_delivered_packet_number - 2;
    ASSERT_TRUE(connection
                    .process_inbound_application(
                        std::vector<coquic::quic::Frame>{
                            coquic::quic::PingFrame{},
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

    auto retransmit_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(102));
    ASSERT_FALSE(retransmit_datagram.empty());
    EXPECT_TRUE(connection.last_drained_path_id().has_value());

    auto retransmit_packet_number =
        last_tracked_packet(connection.application_space_).packet_number;
    auto retransmit_packet =
        tracked_packet_or_terminate(connection.application_space_, retransmit_packet_number);
    ASSERT_TRUE(sent_packet_has_stream_frames_for_tests(retransmit_packet));
    EXPECT_EQ(first_stream_frame_offset_for_tests(retransmit_packet), tracked_gap_offset);
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
        connection.reset_unpaced_ack_eliciting_burst();
        auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(i) + 1));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
        delivered_packet_numbers.push_back(
            last_tracked_packet(connection.application_space_).packet_number);
    }
    for (std::size_t i = 0; i < kGapPackets; ++i) {
        connection.reset_unpaced_ack_eliciting_burst();
        auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(kDeliveredPackets + i + 1u)));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
        gap_packet_numbers.push_back(
            last_tracked_packet(connection.application_space_).packet_number);
    }

    ASSERT_FALSE(delivered_packet_numbers.empty());
    ASSERT_FALSE(gap_packet_numbers.empty());
    auto first_gap_packet_number = gap_packet_numbers.front();
    auto first_gap_packet =
        tracked_packet_or_terminate(connection.application_space_, first_gap_packet_number);
    ASSERT_TRUE(sent_packet_has_stream_frames_for_tests(first_gap_packet));
    auto tracked_gap_offset = first_stream_frame_offset_for_tests(first_gap_packet);

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

    auto migration_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(100));
    ASSERT_FALSE(migration_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 11u);
    ASSERT_TRUE(connection.paths_.contains(11));
    ASSERT_TRUE(connection.paths_.at(11).outstanding_challenge.has_value());
    auto challenge = optional_ref_or_terminate(connection.paths_.at(11).outstanding_challenge);
    auto migration_packet_number = last_tracked_packet(connection.application_space_).packet_number;

    auto first_delivered_packet_number = delivered_packet_numbers.front();
    auto last_delivered_packet_number = delivered_packet_numbers.back();
    ASSERT_GT(migration_packet_number, last_delivered_packet_number + 1);

    auto ack_gap = migration_packet_number - last_delivered_packet_number - 2;
    auto encoded = coquic::quic::serialize_protected_datagram(
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

    auto result = server.advance(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = encoded.value(),
            .route_handle = 11,
        },
        coquic::quic::test::test_time(101));

    ASSERT_FALSE(result.local_error.has_value());
    ASSERT_TRUE(connection.streams_.contains(0));

    bool saw_send_on_migrated_path = false;
    bool saw_retransmit_for_gap_offset = false;
    for (auto &effect : result.effects) {
        auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }

        ASSERT_TRUE(send->route_handle.has_value());
        EXPECT_EQ(optional_value_or_terminate(send->route_handle), 11u);
        saw_send_on_migrated_path = true;

        for (auto &packet : decode_sender_datagram(connection, send->bytes)) {
            auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (one_rtt == nullptr) {
                continue;
            }
            for (auto &frame : one_rtt->frames) {
                auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
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
        connection.reset_unpaced_ack_eliciting_burst();
        auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(i) + 1));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
        delivered_packet_numbers.push_back(
            last_tracked_packet(connection.application_space_).packet_number);
    }
    for (std::size_t i = 0; i < kGapPackets; ++i) {
        connection.reset_unpaced_ack_eliciting_burst();
        auto datagram = connection.drain_outbound_datagram(
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

    auto first_gap_packet = tracked_packet_or_terminate(connection.application_space_, 8372);
    ASSERT_TRUE(sent_packet_has_stream_frames_for_tests(first_gap_packet));
    auto tracked_gap_offset = first_stream_frame_offset_for_tests(first_gap_packet);

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

    auto migration_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(100));
    ASSERT_FALSE(migration_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 11u);
    ASSERT_TRUE(connection.paths_.contains(11));
    ASSERT_TRUE(connection.paths_.at(11).outstanding_challenge.has_value());
    auto challenge = optional_ref_or_terminate(connection.paths_.at(11).outstanding_challenge);
    auto migration_packet_number = last_tracked_packet(connection.application_space_).packet_number;
    ASSERT_EQ(migration_packet_number, 8394u);

    auto encoded = coquic::quic::serialize_protected_datagram(
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

    auto result = server.advance(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = encoded.value(),
            .route_handle = 11,
        },
        coquic::quic::test::test_time(101));

    ASSERT_FALSE(result.local_error.has_value());

    bool saw_retransmit_for_gap_offset = false;
    for (auto &effect : result.effects) {
        auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }

        ASSERT_TRUE(send->route_handle.has_value());
        EXPECT_EQ(optional_value_or_terminate(send->route_handle), 11u);

        for (auto &packet : decode_sender_datagram(connection, send->bytes)) {
            auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (one_rtt == nullptr) {
                continue;
            }
            for (auto &frame : one_rtt->frames) {
                auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
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

    auto control_frame_probe = connection.select_pto_probe(packet_space);

    auto &probe_packet = control_frame_probe;
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

    auto first_packet = coquic::quic::serialize_protected_datagram(
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

    auto second_packet = coquic::quic::serialize_protected_datagram(
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

    auto third_packet = coquic::quic::serialize_protected_datagram(
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

    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
    // # For example, if decryption fails (because the keys are not available
    // # or for any other reason), the receiver MAY either discard or buffer
    // # the packet for later processing and MUST attempt to process the
    // # remaining packets.
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), third_packet.value());

    auto received = connection.take_received_stream_data();
    EXPECT_FALSE(received.has_value());
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

    auto first_frames = limits.take_max_streams_frames();
    ASSERT_EQ(first_frames.size(), 1u);
    EXPECT_EQ(first_frames.front().stream_type, coquic::quic::StreamLimitType::unidirectional);
    EXPECT_EQ(first_frames.front().maximum_streams, 3u);
    EXPECT_EQ(limits.max_streams_uni_state, coquic::quic::StreamControlFrameState::sent);

    limits.mark_max_streams_frame_lost(first_frames.front());
    EXPECT_EQ(limits.max_streams_uni_state, coquic::quic::StreamControlFrameState::pending);

    auto retry_frames = limits.take_max_streams_frames();
    ASSERT_EQ(retry_frames.size(), 1u);
    limits.acknowledge_max_streams_frame(retry_frames.front());
    EXPECT_EQ(limits.max_streams_uni_state, coquic::quic::StreamControlFrameState::acknowledged);

    limits.queue_max_streams(coquic::quic::StreamLimitType::unidirectional, 3);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
    // # MAX_STREAMS frames that do not increase the stream limit MUST be
    // # ignored.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.11
    // # MAX_STREAMS frames that do not increase the stream limit MUST be
    // # ignored.
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

    auto first_frames = limits.take_max_streams_frames();
    ASSERT_EQ(first_frames.size(), 1u);
    EXPECT_EQ(first_frames.front().stream_type, coquic::quic::StreamLimitType::bidirectional);
    EXPECT_EQ(first_frames.front().maximum_streams, 3u);
    EXPECT_EQ(limits.max_streams_bidi_state, coquic::quic::StreamControlFrameState::sent);

    limits.mark_max_streams_frame_lost(first_frames.front());
    EXPECT_EQ(limits.max_streams_bidi_state, coquic::quic::StreamControlFrameState::pending);

    auto retry_frames = limits.take_max_streams_frames();
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
    auto frames = limits.take_max_streams_frames();
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
    auto frames = limits.take_max_streams_frames();
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
    auto frames = limits.take_max_streams_frames();
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

TEST(QuicCoreTest, FinOnlyStreamBlockedByPeerCreditIsNotPendingApplicationSend) {
    auto connection = make_connected_client_connection();
    auto &stream = connection.streams_
                       .emplace(0, coquic::quic::make_implicit_stream_state(
                                       /*stream_id=*/0, connection.config_.role))
                       .first->second;
    stream.send_fin_state = coquic::quic::StreamSendFinState::pending;
    stream.send_final_size = 1;
    stream.flow_control.peer_max_stream_data = 0;

    //= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
    // # An endpoint MUST NOT send data on any stream without ensuring that it
    // # is within the flow control limits set by its peer.
    EXPECT_FALSE(connection.has_pending_fresh_application_stream_send());
    EXPECT_FALSE(connection.has_pending_application_send());
}

TEST(QuicCoreTest,
     PendingUnidirectionalMaxStreamsFrameCountsAsPendingApplicationSendOnBareConnection) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::none;
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::none;
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::none;
    connection.local_stream_limit_state_.max_streams_bidi_state =
        coquic::quic::StreamControlFrameState::none;
    connection.local_stream_limit_state_.max_streams_uni_state =
        coquic::quic::StreamControlFrameState::pending;
    EXPECT_TRUE(connection.has_pending_application_send());

    connection.local_stream_limit_state_.max_streams_uni_state =
        coquic::quic::StreamControlFrameState::none;
    EXPECT_FALSE(connection.has_pending_application_send());
}

TEST(QuicCoreTest, FinOnlyStreamWithoutCreditIsNotPendingApplicationSend) {
    auto connection = make_connected_client_connection();
    auto &stream = connection.streams_
                       .emplace(0, coquic::quic::make_implicit_stream_state(
                                       /*stream_id=*/0, connection.config_.role))
                       .first->second;

    stream.send_fin_state = coquic::quic::StreamSendFinState::pending;
    stream.send_final_size = 1;
    stream.flow_control.peer_max_stream_data = 0;

    EXPECT_FALSE(connection.has_pending_fresh_application_stream_send());
    EXPECT_FALSE(connection.has_pending_application_send());
}

TEST(QuicCoreTest, FinBlockedByStreamCreditDoesNotCountAsPendingSend) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;

    stream.send_fin_state = coquic::quic::StreamSendFinState::pending;
    stream.send_final_size = 1;
    stream.flow_control.peer_max_stream_data = 0;

    EXPECT_FALSE(connection.has_pending_fresh_application_stream_send());
    EXPECT_FALSE(connection.has_pending_application_send());
}

TEST(QuicCoreTest, BlockedFinByStreamCreditIsNotPendingApplicationSend) {
    auto connection = make_connected_client_connection();
    auto &stream = connection.streams_
                       .emplace(0, coquic::quic::make_implicit_stream_state(
                                       /*stream_id=*/0, connection.config_.role))
                       .first->second;
    stream.send_fin_state = coquic::quic::StreamSendFinState::pending;
    stream.send_final_size = 2;
    stream.flow_control.peer_max_stream_data = 1;

    EXPECT_FALSE(connection.has_pending_application_send());
    EXPECT_FALSE(connection.has_pending_fresh_application_stream_send());
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
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
    // # An endpoint MUST NOT wait to receive this signal before advertising
    // # additional credit, since doing so will mean that the peer will be
    // # blocked for at least an entire round trip, and potentially indefinitely
    // # if the peer chooses not to send STREAMS_BLOCKED frames.
    ASSERT_TRUE(connection.local_stream_limit_state_.pending_max_streams_uni_frame.has_value());
    EXPECT_EQ(optional_ref_or_terminate(
                  connection.local_stream_limit_state_.pending_max_streams_uni_frame)
                  .stream_type,
              coquic::quic::StreamLimitType::unidirectional);
}

TEST(QuicCoreTest, ClosingPeerInitiatedBidirectionalStreamRefreshesStreamLimit) {
    auto connection = make_connected_server_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;

    stream.peer_fin_delivered = true;
    stream.send_fin_state = coquic::quic::StreamSendFinState::acknowledged;

    connection.maybe_refresh_peer_stream_limit(stream);

    EXPECT_TRUE(stream.peer_stream_limit_released);
    EXPECT_EQ(connection.local_stream_limit_state_.max_streams_bidi_state,
              coquic::quic::StreamControlFrameState::pending);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
    // # An endpoint MUST NOT wait to receive this signal before advertising
    // # additional credit, since doing so will mean that the peer will be
    // # blocked for at least an entire round trip, and potentially indefinitely
    // # if the peer chooses not to send STREAMS_BLOCKED frames.
    ASSERT_TRUE(connection.local_stream_limit_state_.pending_max_streams_bidi_frame.has_value());
    EXPECT_EQ(optional_ref_or_terminate(
                  connection.local_stream_limit_state_.pending_max_streams_bidi_frame)
                  .stream_type,
              coquic::quic::StreamLimitType::bidirectional);
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

TEST(QuicCoreTest, TerminalPeerStreamWithPendingOrOutstandingSendIsNotRetired) {
    auto connection = make_connected_server_connection();
    auto &stream =
        connection.streams_
            .emplace(2, coquic::quic::make_implicit_stream_state(2, connection.config_.role))
            .first->second;
    stream.peer_fin_delivered = true;

    stream.stop_sending_state = coquic::quic::StreamControlFrameState::pending;
    connection.maybe_retire_stream(2);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.4
    // # Both endpoints MUST maintain flow control state for the stream in the
    // # unterminated direction until that direction enters a terminal state.
    EXPECT_TRUE(connection.streams_.contains(2));

    stream.stop_sending_state = coquic::quic::StreamControlFrameState::sent;
    connection.maybe_retire_stream(2);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.4
    // # Both endpoints MUST maintain flow control state for the stream in the
    // # unterminated direction until that direction enters a terminal state.
    EXPECT_TRUE(connection.streams_.contains(2));
}

TEST(QuicCoreTest, RetiredPeerStreamRangeRejectsIneligibleTerminalStates) {
    auto connection = make_connected_server_connection();
    const auto make_candidate = [&](std::uint64_t stream_id = 0) {
        auto stream = coquic::quic::make_implicit_stream_state(stream_id, connection.config_.role);
        connection.initialize_stream_flow_control(stream);
        stream.peer_final_size = 32;
        stream.peer_send_closed = true;
        stream.peer_fin_delivered = true;
        stream.receive_flow_control_consumed = 32;
        stream.highest_received_offset = 32;
        stream.flow_control.delivered_bytes = 32;
        stream.send_final_size = 32;
        stream.send_flow_control_committed = 32;
        stream.flow_control.highest_sent = 32;
        stream.send_fin_state = coquic::quic::StreamSendFinState::acknowledged;
        stream.peer_stream_limit_released = true;
        return stream;
    };

    auto local_initiated = make_candidate(1);
    EXPECT_FALSE(connection.try_retire_stream_to_peer_range(local_initiated));

    auto missing_peer_fin = make_candidate();
    missing_peer_fin.peer_fin_delivered = false;
    EXPECT_FALSE(connection.try_retire_stream_to_peer_range(missing_peer_fin));

    auto peer_reset = make_candidate();
    peer_reset.peer_reset_received = true;
    EXPECT_FALSE(connection.try_retire_stream_to_peer_range(peer_reset));

    auto missing_peer_final_size = make_candidate();
    missing_peer_final_size.peer_final_size.reset();
    EXPECT_FALSE(connection.try_retire_stream_to_peer_range(missing_peer_final_size));

    auto missing_send_final_size = make_candidate();
    missing_send_final_size.send_final_size.reset();
    EXPECT_FALSE(connection.try_retire_stream_to_peer_range(missing_send_final_size));

    auto pending_reset = make_candidate();
    pending_reset.reset_state = coquic::quic::StreamControlFrameState::pending;
    EXPECT_FALSE(connection.try_retire_stream_to_peer_range(pending_reset));

    auto pending_stop_sending = make_candidate();
    pending_stop_sending.stop_sending_state = coquic::quic::StreamControlFrameState::pending;
    EXPECT_FALSE(connection.try_retire_stream_to_peer_range(pending_stop_sending));

    auto pending_max_stream_data = make_candidate();
    pending_max_stream_data.flow_control.max_stream_data_state =
        coquic::quic::StreamControlFrameState::pending;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.4
    // # Both endpoints MUST maintain flow control state for the stream in the
    // # unterminated direction until that direction enters a terminal state.
    EXPECT_FALSE(connection.try_retire_stream_to_peer_range(pending_max_stream_data));

    auto pending_stream_data_blocked = make_candidate();
    pending_stream_data_blocked.flow_control.stream_data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.4
    // # Both endpoints MUST maintain flow control state for the stream in the
    // # unterminated direction until that direction enters a terminal state.
    EXPECT_FALSE(connection.try_retire_stream_to_peer_range(pending_stream_data_blocked));

    EXPECT_EQ(connection.retired_peer_stream_count(), 0u);
}

TEST(QuicCoreTest, TerminalPeerBidirectionalStreamsRetireIntoCompactRanges) {
    auto connection = make_connected_server_connection();
    const auto retire_terminal_peer_bidi_stream = [](coquic::quic::QuicConnection &connection,
                                                     std::uint64_t stream_id) {
        auto &stream = connection.streams_
                           .emplace(stream_id, coquic::quic::make_implicit_stream_state(
                                                   stream_id, connection.config_.role))
                           .first->second;
        connection.initialize_stream_flow_control(stream);
        stream.peer_final_size = 32;
        stream.peer_send_closed = true;
        stream.peer_fin_delivered = true;
        stream.receive_flow_control_consumed = 32;
        stream.highest_received_offset = 32;
        stream.flow_control.delivered_bytes = 32;
        stream.send_final_size = 32;
        stream.send_flow_control_committed = 32;
        stream.flow_control.highest_sent = 32;
        stream.send_fin_state = coquic::quic::StreamSendFinState::acknowledged;
        stream.peer_stream_limit_released = true;

        connection.maybe_retire_stream(stream_id);
        EXPECT_FALSE(connection.streams_.contains(stream_id));
    };
    for (std::uint64_t stream_id : {0u, 4u}) {
        retire_terminal_peer_bidi_stream(connection, stream_id);
    }

    EXPECT_TRUE(connection.retired_streams_.empty());
    ASSERT_EQ(connection.retired_peer_bidi_stream_ranges_.size(), 1u);
    EXPECT_EQ(connection.retired_peer_stream_count(), 2u);

    const auto duplicate =
        connection.validate_retired_peer_stream_frame(/*stream_id=*/0, /*offset=*/0,
                                                      /*length=*/32, /*fin=*/true, 0x08);
    ASSERT_TRUE(duplicate.has_value());
    EXPECT_TRUE(duplicate.value());

    const auto final_size_conflict =
        connection.validate_retired_peer_stream_frame(/*stream_id=*/0, /*offset=*/0,
                                                      /*length=*/33, /*fin=*/true, 0x08);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
    // # Once a final size for a stream is known, it cannot change.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
    // # If a RESET_STREAM or STREAM frame is received indicating a change
    // # in the final size for the stream, an endpoint SHOULD respond with
    // # an error of type FINAL_SIZE_ERROR; see Section 11 for details on
    // # error handling.
    EXPECT_FALSE(final_size_conflict.has_value());

    const auto non_fin_size_conflict =
        connection.validate_retired_peer_stream_frame(/*stream_id=*/0, /*offset=*/33,
                                                      /*length=*/1, /*fin=*/false, 0x08);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
    // # A receiver SHOULD treat receipt of data at or beyond the final
    // # size as an error of type FINAL_SIZE_ERROR, even after a stream
    // # is closed.
    EXPECT_FALSE(non_fin_size_conflict.has_value());

    const auto short_fin_size_conflict =
        connection.validate_retired_peer_stream_frame(/*stream_id=*/0, /*offset=*/0,
                                                      /*length=*/31, /*fin=*/true, 0x08);
    EXPECT_FALSE(short_fin_size_conflict.has_value());

    const auto overflow_size_conflict = connection.validate_retired_peer_stream_frame(
        /*stream_id=*/0, std::numeric_limits<std::uint64_t>::max(), /*length=*/1,
        /*fin=*/false, 0x08);
    EXPECT_FALSE(overflow_size_conflict.has_value());

    const auto reset_final_size_match =
        connection.validate_retired_peer_reset_stream_frame(/*stream_id=*/0,
                                                            /*final_size=*/32, 0x04);
    ASSERT_TRUE(reset_final_size_match.has_value());
    EXPECT_TRUE(reset_final_size_match.value());

    const auto reset_final_size_conflict =
        connection.validate_retired_peer_reset_stream_frame(/*stream_id=*/0,
                                                            /*final_size=*/31, 0x04);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
    // # Once a final size for a stream is known, it cannot change.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
    // # If a RESET_STREAM or STREAM frame is received indicating a change
    // # in the final size for the stream, an endpoint SHOULD respond with
    // # an error of type FINAL_SIZE_ERROR; see Section 11 for details on
    // # error handling.
    EXPECT_FALSE(reset_final_size_conflict.has_value());

    const auto unretired_stream =
        connection.validate_retired_peer_stream_frame(/*stream_id=*/8, /*offset=*/0,
                                                      /*length=*/0, /*fin=*/false, 0x08);
    ASSERT_TRUE(unretired_stream.has_value());
    EXPECT_FALSE(unretired_stream.value());

    const auto unretired_reset =
        connection.validate_retired_peer_reset_stream_frame(/*stream_id=*/8,
                                                            /*final_size=*/0, 0x04);
    ASSERT_TRUE(unretired_reset.has_value());
    EXPECT_FALSE(unretired_reset.value());

    auto reverse_merge_connection = make_connected_server_connection();
    retire_terminal_peer_bidi_stream(reverse_merge_connection, 4u);
    retire_terminal_peer_bidi_stream(reverse_merge_connection, 0u);

    EXPECT_TRUE(reverse_merge_connection.retired_streams_.empty());
    ASSERT_EQ(reverse_merge_connection.retired_peer_bidi_stream_ranges_.size(), 1u);
    const auto &reverse_range =
        reverse_merge_connection.retired_peer_bidi_stream_ranges_.begin()->second;
    EXPECT_EQ(reverse_range.first_index, 0u);
    EXPECT_EQ(reverse_range.last_index, 1u);

    auto *retired_scratch = reverse_merge_connection.find_stream_state(0);
    ASSERT_NE(retired_scratch, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-2.1
    // # A QUIC endpoint MUST NOT reuse a stream ID within a connection.
    EXPECT_TRUE(retired_scratch->send_closed);
    EXPECT_TRUE(retired_scratch->receive_closed);
    EXPECT_EQ(retired_scratch->flow_control.peer_max_stream_data,
              reverse_range.peer_max_stream_data);

    const auto &const_reverse_merge_connection = reverse_merge_connection;
    const auto *const_retired_scratch = const_reverse_merge_connection.find_stream_state(4);
    ASSERT_NE(const_retired_scratch, nullptr);
    EXPECT_TRUE(const_retired_scratch->send_closed);
    EXPECT_TRUE(const_retired_scratch->receive_closed);
}

TEST(QuicCoreTest, TerminalLocalBidirectionalStreamsRetireIntoCompactRanges) {
    auto connection = make_connected_client_connection();
    const auto retire_terminal_local_bidi_stream = [](coquic::quic::QuicConnection &connection,
                                                      std::uint64_t stream_id) {
        auto &stream = connection.streams_
                           .emplace(stream_id, coquic::quic::make_implicit_stream_state(
                                                   stream_id, connection.config_.role))
                           .first->second;
        connection.initialize_stream_flow_control(stream);
        stream.peer_final_size = 32;
        stream.peer_send_closed = true;
        stream.peer_fin_delivered = true;
        stream.receive_flow_control_consumed = 32;
        stream.highest_received_offset = 32;
        stream.flow_control.delivered_bytes = 32;
        stream.send_final_size = 32;
        stream.send_flow_control_committed = 32;
        stream.flow_control.highest_sent = 32;
        stream.send_fin_state = coquic::quic::StreamSendFinState::acknowledged;

        connection.maybe_retire_stream(stream_id);
        EXPECT_FALSE(connection.streams_.contains(stream_id));
    };

    for (std::uint64_t stream_id : {0u, 4u}) {
        retire_terminal_local_bidi_stream(connection, stream_id);
    }

    EXPECT_TRUE(connection.retired_streams_.empty());
    ASSERT_EQ(connection.retired_local_bidi_stream_ranges_.size(), 1u);
    EXPECT_EQ(connection.retired_local_stream_count(), 2u);

    const auto duplicate =
        connection.validate_retired_peer_stream_frame(/*stream_id=*/0, /*offset=*/0,
                                                      /*length=*/32, /*fin=*/true, 0x08);
    ASSERT_TRUE(duplicate.has_value());
    EXPECT_TRUE(duplicate.value());

    const auto final_size_conflict =
        connection.validate_retired_peer_stream_frame(/*stream_id=*/0, /*offset=*/0,
                                                      /*length=*/33, /*fin=*/true, 0x08);
    EXPECT_FALSE(final_size_conflict.has_value());

    const auto reset_final_size_match =
        connection.validate_retired_peer_reset_stream_frame(/*stream_id=*/0,
                                                            /*final_size=*/32, 0x04);
    ASSERT_TRUE(reset_final_size_match.has_value());
    EXPECT_TRUE(reset_final_size_match.value());

    auto *retired_scratch = connection.find_stream_state(0);
    ASSERT_NE(retired_scratch, nullptr);
    EXPECT_TRUE(retired_scratch->send_closed);
    EXPECT_TRUE(retired_scratch->receive_closed);
    EXPECT_EQ(retired_scratch->send_final_size, std::optional<std::uint64_t>{32});
    EXPECT_EQ(retired_scratch->peer_final_size, std::optional<std::uint64_t>{32});
}

TEST(QuicCoreTest, MarkLostPacketRequeuesUnidirectionalMaxStreamsFrame) {
    auto connection = make_connected_server_connection();
    auto maximum_streams = connection.local_stream_limit_state_.advertised_max_streams_uni + 1;
    connection.local_stream_limit_state_.queue_max_streams(
        coquic::quic::StreamLimitType::unidirectional, maximum_streams);
    auto frames = connection.local_stream_limit_state_.take_max_streams_frames();
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
    auto maximum_streams = connection.local_stream_limit_state_.advertised_max_streams_uni + 1;
    connection.local_stream_limit_state_.queue_max_streams(
        coquic::quic::StreamLimitType::unidirectional, maximum_streams);
    auto frames = connection.local_stream_limit_state_.take_max_streams_frames();
    ASSERT_EQ(frames.size(), 1u);

    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 89,
        .ack_eliciting = true,
        .in_flight = true,
        .max_streams_frames = frames,
    };

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_max_streams = false;
    for (auto &frame : application->frames) {
        if (auto *max_streams = std::get_if<coquic::quic::MaxStreamsFrame>(&frame)) {
            saw_max_streams = true;
            EXPECT_EQ(max_streams->stream_type, coquic::quic::StreamLimitType::unidirectional);
            EXPECT_EQ(max_streams->maximum_streams, maximum_streams);
        }
    }

    EXPECT_TRUE(saw_max_streams);
}

TEST(QuicCoreTest, ApplicationProbePacketCanSendBidirectionalMaxStreamsFrames) {
    auto connection = make_connected_server_connection();
    auto maximum_streams = connection.local_stream_limit_state_.advertised_max_streams_bidi + 1;
    connection.local_stream_limit_state_.queue_max_streams(
        coquic::quic::StreamLimitType::bidirectional, maximum_streams);
    auto frames = connection.local_stream_limit_state_.take_max_streams_frames();
    ASSERT_EQ(frames.size(), 1u);

    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 90,
        .ack_eliciting = true,
        .in_flight = true,
        .max_streams_frames = frames,
    };

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_max_streams = false;
    for (auto &frame : application->frames) {
        if (auto *max_streams = std::get_if<coquic::quic::MaxStreamsFrame>(&frame)) {
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_handshake_done = false;
    bool saw_stream = false;
    for (auto &frame : application->frames) {
        saw_handshake_done =
            saw_handshake_done || std::holds_alternative<coquic::quic::HandshakeDoneFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_handshake_done);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
    // # A sender MUST NOT send any of these frames from a terminal state
    // # ("Data Recvd" or "Reset Recvd").
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
    // # A sender MUST NOT send a STREAM or STREAM_DATA_BLOCKED frame for
    // # a stream in the "Reset Sent" state or any terminal state -- that
    // # is, after sending a RESET_STREAM frame.
    EXPECT_FALSE(saw_stream);
}

} // namespace
