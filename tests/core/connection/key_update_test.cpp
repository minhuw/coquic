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
using coquic::quic::test_support::invalid_cipher_suite;
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

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            first_packet.packet_number)));

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
    const auto retransmit_packet_number =
        std::prev(connection.application_space_.sent_packets.end())->first;
    const auto retransmit_packet =
        connection.application_space_.sent_packets.at(retransmit_packet_number);
    ASSERT_FALSE(retransmit_packet.stream_fragments.empty());
    const auto retransmitted_packets = decode_sender_datagram(connection, retransmitted);
    ASSERT_EQ(retransmitted_packets.size(), 1u);
    const auto *retransmitted_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&retransmitted_packets.front());
    ASSERT_NE(retransmitted_application, nullptr);

    bool saw_ack = false;
    bool saw_retransmitted_prefix = false;
    bool saw_fresh_stream_data = false;
    for (const auto &frame : retransmitted_application->frames) {
        if (std::holds_alternative<coquic::quic::AckFrame>(frame)) {
            saw_ack = true;
        }

        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        const auto stream_offset = optional_value_or_terminate(stream->offset);
        if (stream_offset == 0u && !stream->stream_data.empty() &&
            stream->stream_data.size() <= first_fragment_length) {
            saw_retransmitted_prefix = true;
        } else if (stream_offset >= first_fragment_length) {
            saw_fresh_stream_data = true;
        }
    }
    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_retransmitted_prefix);
    for (const auto &fragment : retransmit_packet.stream_fragments) {
        EXPECT_FALSE(fragment.consumes_flow_control);
    }
    EXPECT_FALSE(saw_fresh_stream_data);
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
    connection.peer_address_validated_ = true;
    connection.last_validated_path_id_ = 0;
    connection.current_send_path_id_ = 0;
    auto &path = connection.ensure_path_state(0);
    path.validated = true;
    path.is_current_send_path = true;

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

    auto outbound = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (outbound.empty()) {
        const auto ack_deadline = connection.next_wakeup();
        ASSERT_TRUE(ack_deadline.has_value());
        outbound = connection.drain_outbound_datagram(optional_value_or_terminate(ack_deadline));
    }
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

TEST(QuicCoreTest, LocalKeyUpdateWaitsForHandshakeConfirmationAndAckedCurrentPhasePacket) {
    auto connection = make_connected_client_connection();
    const auto original_write_key_phase = connection.application_write_key_phase_;
    connection.handshake_confirmed_ = false;
    connection.request_key_update();

    EXPECT_TRUE(connection.local_key_update_requested_);
    EXPECT_FALSE(connection.local_key_update_initiated_);
    EXPECT_EQ(connection.application_write_key_phase_, original_write_key_phase);

    ASSERT_TRUE(connection.queue_stream_send(0, bytes_from_ints({0x61}), false).has_value());
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    EXPECT_TRUE(connection.local_key_update_requested_);
    EXPECT_FALSE(connection.local_key_update_initiated_);
    EXPECT_EQ(connection.application_write_key_phase_, original_write_key_phase);

    const auto decoded = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(decoded.size(), 1u);
    const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded.front());
    ASSERT_NE(one_rtt, nullptr);
    EXPECT_EQ(one_rtt->key_phase, original_write_key_phase);
}

TEST(QuicCoreTest, LocalKeyUpdateUsesNewKeyPhaseAfterCurrentPhasePacketIsAcknowledged) {
    auto connection = make_connected_client_connection();
    const auto original_write_key_phase = connection.application_write_key_phase_;
    connection.request_key_update();

    EXPECT_TRUE(connection.local_key_update_requested_);
    EXPECT_FALSE(connection.local_key_update_initiated_);
    EXPECT_EQ(connection.application_write_key_phase_, original_write_key_phase);

    ASSERT_TRUE(connection.queue_stream_send(0, bytes_from_ints({0x61}), false).has_value());
    const auto current_phase_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(current_phase_datagram.empty());

    EXPECT_TRUE(connection.local_key_update_requested_);
    EXPECT_FALSE(connection.local_key_update_initiated_);
    EXPECT_EQ(connection.application_write_key_phase_, original_write_key_phase);

    const auto decoded_current = decode_sender_datagram(connection, current_phase_datagram);
    ASSERT_EQ(decoded_current.size(), 1u);
    const auto *current_one_rtt =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded_current.front());
    ASSERT_NE(current_one_rtt, nullptr);
    EXPECT_EQ(current_one_rtt->key_phase, original_write_key_phase);

    const auto ack_result = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(2), connection.config_.transport.ack_delay_exponent,
        connection.config_.transport.max_ack_delay, false);
    ASSERT_TRUE(ack_result.has_value());

    ASSERT_TRUE(connection.queue_stream_send(4, bytes_from_ints({0x62}), false).has_value());
    const auto updated_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(updated_datagram.empty());

    EXPECT_TRUE(connection.local_key_update_initiated_);
    EXPECT_EQ(connection.application_write_key_phase_, !original_write_key_phase);

    const auto decoded_updated = decode_sender_datagram(connection, updated_datagram);
    ASSERT_EQ(decoded_updated.size(), 1u);
    const auto *updated_one_rtt =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded_updated.front());
    ASSERT_NE(updated_one_rtt, nullptr);
    EXPECT_EQ(updated_one_rtt->key_phase, !original_write_key_phase);
}

TEST(QuicCoreTest, LocalKeyUpdateWaitsForApplicationReadSecretAvailability) {
    auto connection = make_connected_client_connection();
    const auto original_write_key_phase = connection.application_write_key_phase_;
    connection.application_space_.read_secret = std::nullopt;
    connection.request_key_update();

    ASSERT_TRUE(connection.queue_stream_send(0, bytes_from_ints({0x61}), false).has_value());
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    EXPECT_TRUE(connection.local_key_update_requested_);
    EXPECT_FALSE(connection.local_key_update_initiated_);
    EXPECT_EQ(connection.application_write_key_phase_, original_write_key_phase);

    const auto decoded = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(decoded.size(), 1u);
    const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded.front());
    ASSERT_NE(one_rtt, nullptr);
    EXPECT_EQ(one_rtt->key_phase, original_write_key_phase);
}

TEST(QuicCoreTest, LocalKeyUpdateDoesNotReinitiateWhenAlreadyMarkedInProgress) {
    auto connection = make_connected_client_connection();
    const auto original_write_key_phase = connection.application_write_key_phase_;
    connection.local_key_update_requested_ = true;
    connection.local_key_update_initiated_ = true;
    connection.current_write_phase_first_packet_number_ = 0;
    connection.application_space_.recovery.largest_acked_packet_number_ = 0;

    ASSERT_TRUE(connection.queue_stream_send(0, bytes_from_ints({0x61}), false).has_value());
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    EXPECT_TRUE(connection.local_key_update_requested_);
    EXPECT_TRUE(connection.local_key_update_initiated_);
    EXPECT_EQ(connection.application_write_key_phase_, original_write_key_phase);

    const auto decoded = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(decoded.size(), 1u);
    const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded.front());
    ASSERT_NE(one_rtt, nullptr);
    EXPECT_EQ(one_rtt->key_phase, original_write_key_phase);
}

TEST(QuicCoreTest, RequestKeyUpdatePreservesRecordedPhaseStartWhenAlreadyInitiated) {
    auto connection = make_connected_client_connection();
    connection.local_key_update_initiated_ = true;
    connection.current_write_phase_first_packet_number_ = 17;
    connection.application_space_.next_send_packet_number = 23;

    connection.request_key_update();

    EXPECT_TRUE(connection.local_key_update_requested_);
    ASSERT_TRUE(connection.current_write_phase_first_packet_number_.has_value());
    EXPECT_EQ(optional_value_or_terminate(connection.current_write_phase_first_packet_number_),
              17u);
}

TEST(QuicCoreTest, LocalKeyUpdateWaitsUntilLargestAckCoversCurrentWritePhasePacket) {
    auto connection = make_connected_client_connection();
    const auto original_write_key_phase = connection.application_write_key_phase_;
    connection.request_key_update();
    connection.current_write_phase_first_packet_number_ = 5;
    connection.application_space_.recovery.largest_acked_packet_number_ = 4;

    ASSERT_TRUE(connection.queue_stream_send(0, bytes_from_ints({0x61}), false).has_value());
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    EXPECT_TRUE(connection.local_key_update_requested_);
    EXPECT_FALSE(connection.local_key_update_initiated_);
    EXPECT_EQ(connection.application_write_key_phase_, original_write_key_phase);

    const auto decoded = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(decoded.size(), 1u);
    const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded.front());
    ASSERT_NE(one_rtt, nullptr);
    EXPECT_EQ(one_rtt->key_phase, original_write_key_phase);
}

TEST(QuicCoreTest, LocalKeyUpdateRetainsPreviousReadKeysUntilPeerRespondsInNewPhase) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    if (!connection.application_space_.read_secret.has_value()) {
        return;
    }

    const auto pre_update_read_secret = connection.application_space_.read_secret.value();
    const auto pre_update_read_key_phase = connection.application_read_key_phase_;
    const auto post_update_read_secret =
        coquic::quic::derive_next_traffic_secret(pre_update_read_secret);
    ASSERT_TRUE(post_update_read_secret.has_value());

    connection.request_key_update();
    ASSERT_TRUE(connection.queue_stream_send(0, bytes_from_ints({0x61}), false).has_value());
    const auto current_phase_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(current_phase_datagram.empty());

    connection.process_inbound_ack(connection.application_space_,
                                   coquic::quic::AckFrame{
                                       .largest_acknowledged = 0,
                                       .first_ack_range = 0,
                                   },
                                   coquic::quic::test::test_time(2),
                                   connection.config_.transport.ack_delay_exponent,
                                   connection.config_.transport.max_ack_delay, false);

    ASSERT_TRUE(connection.queue_stream_send(4, bytes_from_ints({0x62}), false).has_value());
    const auto updated_phase_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(updated_phase_datagram.empty());
    ASSERT_TRUE(connection.previous_application_read_secret_.has_value());

    const auto reordered_old_phase_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = pre_update_read_key_phase,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 1000,
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
            .one_rtt_secret = pre_update_read_secret,
            .one_rtt_key_phase = pre_update_read_key_phase,
        });
    ASSERT_TRUE(reordered_old_phase_packet.has_value());

    connection.process_inbound_datagram(reordered_old_phase_packet.value(),
                                        coquic::quic::test::test_time(4));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 1000u);

    const auto current_read_key_phase = connection.application_read_key_phase_;
    const auto new_phase_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = current_read_key_phase,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 1001,
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
            .one_rtt_secret = post_update_read_secret.value(),
            .one_rtt_key_phase = current_read_key_phase,
        });
    ASSERT_TRUE(new_phase_packet.has_value());

    connection.process_inbound_datagram(new_phase_packet.value(), coquic::quic::test::test_time(5));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 1001u);
    EXPECT_FALSE(connection.previous_application_read_secret_.has_value());
}

TEST(QuicCoreTest, CoreRequestKeyUpdateWaitsForAckThenFlipsOutboundPhase) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    ASSERT_NE(client.connection_, nullptr);
    const auto original_write_key_phase = client.connection_->application_write_key_phase_;

    const auto key_update_request =
        client.advance(coquic::quic::QuicCoreRequestKeyUpdate{}, coquic::quic::test::test_time(1));
    EXPECT_FALSE(key_update_request.local_error.has_value());
    EXPECT_TRUE(client.connection_->local_key_update_requested_);
    EXPECT_FALSE(client.connection_->local_key_update_initiated_);
    EXPECT_EQ(client.connection_->application_write_key_phase_, original_write_key_phase);

    const auto current_phase_send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = bytes_from_ints({0x61}),
            .fin = false,
        },
        coquic::quic::test::test_time(2));
    const auto current_phase_datagrams =
        coquic::quic::test::send_datagrams_from(current_phase_send);
    ASSERT_FALSE(current_phase_datagrams.empty());
    const auto decoded_current =
        decode_sender_datagram(*client.connection_, current_phase_datagrams.front());
    ASSERT_FALSE(decoded_current.empty());
    const auto *current_one_rtt =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded_current.front());
    ASSERT_NE(current_one_rtt, nullptr);
    EXPECT_EQ(current_one_rtt->key_phase, original_write_key_phase);
    EXPECT_FALSE(client.connection_->local_key_update_initiated_);
    EXPECT_EQ(client.connection_->application_write_key_phase_, original_write_key_phase);

    auto server_ack = coquic::quic::test::relay_send_datagrams_to_peer(
        current_phase_send, server, coquic::quic::test::test_time(3));
    if (coquic::quic::test::send_datagrams_from(server_ack).empty()) {
        const auto ack_deadline = server.connection_->next_wakeup();
        ASSERT_TRUE(ack_deadline.has_value());
        server_ack = server.advance(coquic::quic::QuicCoreTimerExpired{},
                                    optional_value_or_terminate(ack_deadline));
    }
    const auto client_after_ack = coquic::quic::test::relay_send_datagrams_to_peer(
        server_ack, client, coquic::quic::test::test_time(5));
    EXPECT_FALSE(client.has_failed());
    EXPECT_FALSE(server.has_failed());
    static_cast<void>(client_after_ack);
    const auto largest_acked =
        client.connection_->application_space_.recovery.largest_acked_packet_number();
    const auto largest_acked_packet_number = optional_value_or_terminate(largest_acked);
    const auto current_phase_first_packet_number =
        optional_value_or_terminate(client.connection_->current_write_phase_first_packet_number_);
    EXPECT_GE(largest_acked_packet_number, current_phase_first_packet_number);

    const auto updated_phase_send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 4,
            .bytes = bytes_from_ints({0x62}),
            .fin = false,
        },
        coquic::quic::test::test_time(6));
    const auto updated_phase_datagrams =
        coquic::quic::test::send_datagrams_from(updated_phase_send);
    ASSERT_FALSE(updated_phase_datagrams.empty());
    const auto decoded_updated =
        decode_sender_datagram(*client.connection_, updated_phase_datagrams.front());
    ASSERT_FALSE(decoded_updated.empty());
    const auto *updated_one_rtt =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded_updated.front());
    ASSERT_NE(updated_one_rtt, nullptr);
    EXPECT_EQ(updated_one_rtt->key_phase, !original_write_key_phase);
    EXPECT_TRUE(client.connection_->local_key_update_initiated_);
    EXPECT_EQ(client.connection_->application_write_key_phase_, !original_write_key_phase);
}

TEST(QuicCoreTest, PendingLocalKeyUpdateClearsWhenPeerUpdatesFirst) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    if (!connection.application_space_.read_secret.has_value()) {
        return;
    }

    const auto pre_update_read_secret = connection.application_space_.read_secret.value();
    const auto peer_updated_read_secret =
        coquic::quic::derive_next_traffic_secret(pre_update_read_secret);
    ASSERT_TRUE(peer_updated_read_secret.has_value());

    connection.request_key_update();
    EXPECT_TRUE(connection.local_key_update_requested_);

    const auto peer_updated_key_phase = !connection.application_read_key_phase_;
    const auto peer_updated_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = peer_updated_key_phase,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 1002,
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
            .one_rtt_secret = peer_updated_read_secret.value(),
            .one_rtt_key_phase = peer_updated_key_phase,
        });
    ASSERT_TRUE(peer_updated_packet.has_value());

    connection.process_inbound_datagram(peer_updated_packet.value(),
                                        coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.local_key_update_requested_);
    EXPECT_FALSE(connection.local_key_update_initiated_);
    EXPECT_EQ(connection.application_read_key_phase_, peer_updated_key_phase);

    const auto promoted_write_key_phase = connection.application_write_key_phase_;
    ASSERT_TRUE(connection.queue_stream_send(0, bytes_from_ints({0x61}), false).has_value());
    const auto followup_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(followup_datagram.empty());
    const auto followup_packets = decode_sender_datagram(connection, followup_datagram);
    ASSERT_FALSE(followup_packets.empty());
    const auto *followup_one_rtt =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&followup_packets.front());
    ASSERT_NE(followup_one_rtt, nullptr);
    EXPECT_EQ(followup_one_rtt->key_phase, promoted_write_key_phase);
    EXPECT_FALSE(connection.local_key_update_initiated_);
    EXPECT_EQ(connection.application_write_key_phase_, promoted_write_key_phase);
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenKeyUpdateCannotDeriveNextWriteSecret) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    connection.application_space_.write_secret = coquic::quic::TrafficSecret{
        .cipher_suite = invalid_cipher_suite(),
        .secret = {std::byte{0x01}},
    };

    const auto next_read_secret = coquic::quic::derive_next_traffic_secret(
        optional_ref_or_terminate(connection.application_space_.read_secret));
    ASSERT_TRUE(next_read_secret.has_value());

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = true,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 77,
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
            .one_rtt_secret = next_read_secret.value(),
            .one_rtt_key_phase = true,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest,
     ProcessInboundDatagramRetainsLocalKeyUpdateRequestWhenPeerUpdateArrivesAfterLocalInitiation) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    connection.local_key_update_requested_ = true;
    connection.local_key_update_initiated_ = true;
    const auto peer_updated_key_phase = !connection.application_read_key_phase_;
    const auto next_read_secret = coquic::quic::derive_next_traffic_secret(
        optional_ref_or_terminate(connection.application_space_.read_secret));
    ASSERT_TRUE(next_read_secret.has_value());

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = peer_updated_key_phase,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 80,
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
            .one_rtt_secret = next_read_secret.value(),
            .one_rtt_key_phase = peer_updated_key_phase,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.local_key_update_requested_);
    EXPECT_TRUE(connection.local_key_update_initiated_);
    EXPECT_EQ(connection.application_read_key_phase_, peer_updated_key_phase);
}

TEST(QuicCoreTest, ApplicationProbeFailsWhenLocalKeyUpdateCannotDeriveNextReadSecret) {
    auto connection = make_connected_server_connection();
    connection.local_key_update_requested_ = true;
    connection.current_write_phase_first_packet_number_ = 0;
    connection.application_space_.recovery.largest_acked_packet_number_ = 0;
    connection.application_space_.read_secret = coquic::quic::TrafficSecret{
        .cipher_suite = invalid_cipher_suite(),
        .secret = {std::byte{0x01}},
    };
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 88,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendFailsWhenAckOnlyFallbackKeyUpdateCannotDeriveNextWriteSecret) {
    const auto configure_ack_only_key_update_fallback =
        [](coquic::quic::QuicConnection &connection) {
            ASSERT_TRUE(connection.application_space_.read_secret.has_value());
            ASSERT_TRUE(connection.application_space_.write_secret.has_value());
            optional_ref_or_terminate(connection.application_space_.read_secret)
                .header_protection_key = std::vector<std::byte>(16, std::byte{0x81});
            optional_ref_or_terminate(connection.application_space_.write_secret)
                .header_protection_key = std::vector<std::byte>(16, std::byte{0x82});

            const auto payload =
                std::vector<std::byte>(static_cast<std::size_t>(2048), std::byte{0x52});
            ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

            connection.application_space_.received_packets.record_received(
                77, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
            ASSERT_TRUE(connection.application_space_.received_packets.has_ack_to_send());

            connection.congestion_controller_.on_packet_sent(
                connection.congestion_controller_.congestion_window(), /*ack_eliciting=*/true);
            ASSERT_EQ(connection.congestion_controller_.bytes_in_flight(),
                      connection.congestion_controller_.congestion_window());

            connection.local_key_update_requested_ = true;
            connection.current_write_phase_first_packet_number_ = 0;
            connection.application_space_.recovery.largest_acked_packet_number_ = 0;
        };

    auto control = make_connected_server_connection();
    configure_ack_only_key_update_fallback(control);
    const auto original_write_key_phase = control.application_write_key_phase_;

    const auto control_datagram = control.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(control_datagram.empty());
    EXPECT_FALSE(control.has_failed());
    EXPECT_TRUE(datagram_has_application_ack(control, control_datagram));
    EXPECT_FALSE(datagram_has_application_stream(control, control_datagram));
    EXPECT_TRUE(control.has_pending_application_send());
    EXPECT_FALSE(control.local_key_update_requested_);
    EXPECT_TRUE(control.local_key_update_initiated_);
    EXPECT_EQ(control.application_write_key_phase_, !original_write_key_phase);

    bool saw_faulted_failure = false;
    for (std::size_t occurrence = 1; occurrence <= 24; ++occurrence) {
        auto failure = make_connected_server_connection();
        configure_ack_only_key_update_fallback(failure);
        {
            const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
                coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup, occurrence);
            const auto faulted_datagram =
                failure.drain_outbound_datagram(coquic::quic::test::test_time(1));
            if (!failure.has_failed()) {
                continue;
            }

            saw_faulted_failure = true;
            EXPECT_TRUE(faulted_datagram.empty()) << "occurrence=" << occurrence;
        }
    }

    EXPECT_TRUE(saw_faulted_failure);
}

TEST(QuicCoreTest,
     ApplicationSendAckOnlyFallbackRestoresCurrentPathValidationFramesOnKeyUpdateFailure) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 7;
    connection.current_send_path_id_ = 7;
    auto &current_path = connection.ensure_path_state(7);
    current_path.validated = true;
    current_path.is_current_send_path = true;
    current_path.pending_response =
        std::array{std::byte{0x71}, std::byte{0x72}, std::byte{0x73}, std::byte{0x74},
                   std::byte{0x75}, std::byte{0x76}, std::byte{0x77}, std::byte{0x78}};
    current_path.challenge_pending = true;
    current_path.outstanding_challenge =
        std::array{std::byte{0x81}, std::byte{0x82}, std::byte{0x83}, std::byte{0x84},
                   std::byte{0x85}, std::byte{0x86}, std::byte{0x87}, std::byte{0x88}};

    ASSERT_TRUE(
        connection.queue_stream_send(0, std::vector<std::byte>(2048, std::byte{0x52}), false)
            .has_value());
    connection.application_space_.received_packets.record_received(
        77, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.application_space_.received_packets.has_ack_to_send());

    connection.congestion_controller_.on_packet_sent(
        connection.congestion_controller_.congestion_window(), /*ack_eliciting=*/true);
    ASSERT_EQ(connection.congestion_controller_.bytes_in_flight(),
              connection.congestion_controller_.congestion_window());

    connection.local_key_update_requested_ = true;
    connection.current_write_phase_first_packet_number_ = 0;
    connection.application_space_.recovery.largest_acked_packet_number_ = 0;
    connection.application_space_.read_secret = coquic::quic::TrafficSecret{
        .cipher_suite = invalid_cipher_suite(),
        .secret = {std::byte{0x01}},
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
    ASSERT_TRUE(connection.paths_.contains(7));
    ASSERT_TRUE(connection.paths_.at(7).pending_response.has_value());
    EXPECT_EQ(optional_ref_or_terminate(connection.paths_.at(7).pending_response),
              (std::array{std::byte{0x71}, std::byte{0x72}, std::byte{0x73}, std::byte{0x74},
                          std::byte{0x75}, std::byte{0x76}, std::byte{0x77}, std::byte{0x78}}));
    EXPECT_TRUE(connection.paths_.at(7).challenge_pending);
}

TEST(QuicCoreTest, ApplicationSendFailsWhenKeyUpdateCannotReserveNormalPacketNumber) {
    auto connection = make_connected_server_connection();
    connection.local_key_update_requested_ = true;
    connection.current_write_phase_first_packet_number_ = 0;
    connection.application_space_.recovery.largest_acked_packet_number_ = 0;
    connection.application_space_.read_secret = coquic::quic::TrafficSecret{
        .cipher_suite = invalid_cipher_suite(),
        .secret = {std::byte{0x01}},
    };

    ASSERT_TRUE(connection.queue_stream_send(0, bytes_from_ints({0x61}), false).has_value());

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramDiscardsWhenKeyUpdateRetryCannotDecryptPacket) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = true,
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
            .one_rtt_secret = optional_ref_or_terminate(connection.application_space_.read_secret),
            .one_rtt_key_phase = true,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenDeferredReplayKeyUpdateFailsAfterReconnect) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    ASSERT_NE(client.connection_, nullptr);
    auto &connection = *client.connection_;
    ASSERT_TRUE(connection.tls_.has_value());
    auto &tls = optional_ref_or_terminate(connection.tls_);
    ASSERT_TRUE(tls.handshake_complete());
    ASSERT_TRUE(connection.peer_source_connection_id_.has_value());
    ASSERT_TRUE(connection.peer_transport_parameters_.has_value());
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());

    const auto peer_source_connection_id =
        optional_value_or_terminate(connection.peer_source_connection_id_);
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.peer_transport_parameters_validated_ = false;
    connection.peer_source_connection_id_.reset();
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto next_read_secret = coquic::quic::derive_next_traffic_secret(
        optional_ref_or_terminate(connection.application_space_.read_secret));
    ASSERT_TRUE(next_read_secret.has_value());

    const auto deferred_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = true,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 120,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = next_read_secret.value(),
            .one_rtt_key_phase = true,
        });
    ASSERT_TRUE(deferred_packet.has_value());
    connection.deferred_protected_packets_.push_back(deferred_packet.value());

    connection.application_space_.write_secret = coquic::quic::TrafficSecret{
        .cipher_suite = invalid_cipher_suite(),
        .secret = {std::byte{0x01}},
    };

    const auto reconnect_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = peer_source_connection_id,
                .packet_number_length = 2,
                .packet_number = 90,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(reconnect_packet.has_value());

    connection.process_inbound_datagram(reconnect_packet.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

} // namespace
