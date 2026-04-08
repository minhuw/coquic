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
#include "src/quic/http3.h"
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

TEST(QuicCoreTest, ApplicationAckFramesIncludeEcnCountsWhenReceiveMetadataIsAvailable) {
    auto connection = make_connected_server_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/7, /*ack_eliciting=*/true, coquic::quic::test::test_time(1),
        coquic::quic::QuicEcnCodepoint::ce);
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(1);

    const auto ack_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(ack_datagram.empty());
    const auto packets = decode_sender_datagram(connection, ack_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    const auto ack_it =
        std::find_if(application->frames.begin(), application->frames.end(), [](const auto &frame) {
            return std::holds_alternative<coquic::quic::AckFrame>(frame);
        });
    ASSERT_NE(ack_it, application->frames.end());
    const auto &ack = std::get<coquic::quic::AckFrame>(*ack_it);
    ASSERT_TRUE(ack.ecn_counts.has_value());
    const auto &ecn_counts = optional_ref_or_terminate(ack.ecn_counts);
    EXPECT_EQ(ecn_counts.ect0, 0u);
    EXPECT_EQ(ecn_counts.ect1, 0u);
    EXPECT_EQ(ecn_counts.ecn_ce, 1u);
}

TEST(QuicCoreTest, ServerProcessesOneRttPingBeforeHandshakeCompletesWhenApplicationKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());

    const auto processed = connection.process_inbound_packet(
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
    std::size_t gap = 4u;
    std::size_t tail_offset = 1230u;
    if (client_hello.size() <= tail_offset) {
        prefix = std::min<std::size_t>(63u, client_hello.size() / 4u);
        gap = 1u;
        tail_offset = prefix + gap + ((client_hello.size() - (prefix + gap)) / 2u);
    }
    ASSERT_LT(prefix + gap, tail_offset);
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
                    .crypto_data = slice_bytes(prefix, prefix + gap),
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
                    .offset = static_cast<std::uint64_t>(prefix + gap),
                    .crypto_data = slice_bytes(prefix + gap, tail_offset),
                },
                coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = slice_bytes(0u, prefix),
                },
            },
    };

    const auto pad_initial = [&](coquic::quic::ProtectedInitialPacket packet) {
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
    const auto server_after_first = server.advance(
        coquic::quic::QuicCoreInboundDatagram{first_datagram}, coquic::quic::test::test_time(1));
    EXPECT_FALSE(server.has_failed());

    const auto first_response_datagrams =
        coquic::quic::test::send_datagrams_from(server_after_first);
    ASSERT_FALSE(first_response_datagrams.empty());
    for (const auto &datagram : first_response_datagrams) {
        const auto packets = decode_sender_datagram(*server.connection_, datagram);
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
    const auto server_after_second = server.advance(
        coquic::quic::QuicCoreInboundDatagram{second_datagram}, coquic::quic::test::test_time(2));
    EXPECT_FALSE(server.has_failed());

    const auto response_datagrams = coquic::quic::test::send_datagrams_from(server_after_second);
    ASSERT_FALSE(response_datagrams.empty());

    bool saw_initial_crypto = false;
    bool saw_handshake_crypto = false;
    for (const auto &datagram : response_datagrams) {
        const auto packets = decode_sender_datagram(*server.connection_, datagram);
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
    EXPECT_EQ(client_step.next_wakeup, client.connection_->next_wakeup());
    EXPECT_TRUE(client_step.next_wakeup.has_value());
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

    const auto processed = connection.process_inbound_ack(
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

    const auto first = connection.process_inbound_ack(
        connection.application_space_,
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
        coquic::quic::test::test_time(10), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);
    ASSERT_TRUE(first.has_value());
    const auto first_reduction = connection.congestion_controller_.congestion_window();

    const auto second = connection.process_inbound_ack(
        connection.application_space_,
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
        coquic::quic::test::test_time(12), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
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

    const auto processed = connection.process_inbound_ack(
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

    EXPECT_TRUE(connection.application_space_.sent_packets.empty());
    EXPECT_TRUE(connection.application_space_.send_crypto.has_pending_data());
    EXPECT_EQ(connection.application_space_.recovery.largest_acked_packet_number(),
              std::optional<std::uint64_t>{5});
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
    EXPECT_EQ(stream_offsets.front(), optional_value_or_terminate(last_sent_offset));
    EXPECT_NE(stream_offsets.front(), optional_value_or_terminate(first_sent_offset));
    EXPECT_NE(stream_offsets.front(), next_unsent_offset);
}

TEST(QuicCoreTest, ApplicationPtoPrefersNewestRetransmittablePacketOverOlderCryptoOnlyPacket) {
    auto connection = make_connected_server_connection();
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));
    const auto crypto_ranges = connection.application_space_.send_crypto.take_ranges(
        std::numeric_limits<std::size_t>::max());
    ASSERT_FALSE(crypto_ranges.empty());

    const auto payload = coquic::quic::test::bytes_from_string("server-response");
    ASSERT_TRUE(connection.queue_stream_send(0, payload, true).has_value());
    auto &stream = connection.streams_.at(0);
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
                                     .crypto_ranges = crypto_ranges,
                                     .bytes_in_flight = 300,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 11,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = stream_fragments,
                                     .bytes_in_flight = 200,
                                 });

    const auto probe = connection.select_pto_probe(connection.application_space_);

    ASSERT_TRUE(probe.has_value());
    const auto &probe_value = optional_ref_or_terminate(probe);
    EXPECT_EQ(probe_value.packet_number, 11u);
    ASSERT_EQ(probe_value.stream_fragments.size(), 1u);
    EXPECT_EQ(probe_value.stream_fragments.front().stream_id, 0u);
    EXPECT_EQ(probe_value.stream_fragments.front().bytes, payload);
    EXPECT_TRUE(probe_value.stream_fragments.front().fin);
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

TEST(QuicCoreTest, ServerPtoProbeEmitsTwoDatagramsWhenInitialAndHandshakeAreInFlight) {
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
    std::size_t gap = 4u;
    std::size_t tail_offset = 1230u;
    if (client_hello.size() <= tail_offset) {
        prefix = std::min<std::size_t>(63u, client_hello.size() / 4u);
        gap = 1u;
        tail_offset = prefix + gap + ((client_hello.size() - (prefix + gap)) / 2u);
    }
    ASSERT_LT(prefix + gap, tail_offset);
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
                    .crypto_data = slice_bytes(prefix, prefix + gap),
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
                    .offset = static_cast<std::uint64_t>(prefix + gap),
                    .crypto_data = slice_bytes(prefix + gap, tail_offset),
                },
                coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = slice_bytes(0u, prefix),
                },
            },
    };

    const auto pad_initial = [&](coquic::quic::ProtectedInitialPacket packet) {
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
    const auto server_after_first = server.advance(
        coquic::quic::QuicCoreInboundDatagram{first_datagram}, coquic::quic::test::test_time(1));
    EXPECT_FALSE(server.has_failed());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(server_after_first).empty());

    const auto second_datagram = pad_initial(delivered_packet_two);
    const auto server_after_second = server.advance(
        coquic::quic::QuicCoreInboundDatagram{second_datagram}, coquic::quic::test::test_time(2));
    EXPECT_FALSE(server.has_failed());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(server_after_second).empty());

    const auto next_wakeup = server_after_second.next_wakeup;
    ASSERT_TRUE(next_wakeup.has_value());
    if (!next_wakeup.has_value()) {
        return;
    }
    const auto probe = server.advance(coquic::quic::QuicCoreTimerExpired{}, next_wakeup.value());
    const auto probe_datagrams = coquic::quic::test::send_datagrams_from(probe);
    EXPECT_EQ(probe_datagrams.size(), 2u);
}

TEST(QuicCoreTest, ServerPtoProbeWithHandshakeAndApplicationInFlightBeforeConfirmationDoesNotFail) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::sent;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.next_send_packet_number = 1;

    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = 60,
                                 });
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

    const auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(first_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto second_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(second_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ServerPtoProbeWithOnlyApplicationCryptoInFlightDoesNotFailAcrossBurst) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto next_wakeup = connection.next_wakeup();
    ASSERT_TRUE(next_wakeup.has_value());
    if (!next_wakeup.has_value()) {
        return;
    }

    connection.on_timeout(*next_wakeup);

    const auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(first_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto second_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(second_probe_datagram.empty() || !second_probe_datagram.empty());
}

TEST(QuicCoreTest, ServerPtoProbeWithHandshakeAndOnlyApplicationCryptoInFlightEmitsSecondDatagram) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.next_send_packet_number = 1;
    connection.handshake_space_.sent_packets.emplace(
        0, coquic::quic::SentPacketRecord{
               .packet_number = 0,
               .sent_time = coquic::quic::test::test_time(0),
               .ack_eliciting = true,
               .in_flight = true,
               .has_ping = true,
               .bytes_in_flight = 60,
           });
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto next_wakeup = connection.next_wakeup();
    ASSERT_TRUE(next_wakeup.has_value());
    if (!next_wakeup.has_value()) {
        return;
    }

    connection.on_timeout(*next_wakeup);

    const auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(first_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto second_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(second_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest,
     ServerPtoProbeWithHandshakeCryptoAndOnlyApplicationCryptoInFlightEmitsSecondDatagram) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(36), std::byte{0x31}));
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto next_wakeup = connection.next_wakeup();
    ASSERT_TRUE(next_wakeup.has_value());
    if (!next_wakeup.has_value()) {
        return;
    }

    connection.on_timeout(*next_wakeup);

    const auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(first_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto second_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(second_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest,
     LargeHandshakeProbeLeavesRoomForApplicationProbeInSecondPtoDatagramInsteadOfFailing) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::sent;
    connection.remaining_pto_probe_datagrams_ = 2;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    connection.handshake_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(1170), std::byte{0x31}));
    const auto handshake_crypto = connection.handshake_space_.send_crypto.take_ranges(
        std::numeric_limits<std::size_t>::max());
    ASSERT_FALSE(handshake_crypto.empty());
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 4,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges = handshake_crypto,
        .bytes_in_flight = 1200,
    };
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 7,
        .ack_eliciting = true,
        .in_flight = true,
        .has_handshake_done = true,
        .bytes_in_flight = 21,
    };

    const auto first_probe_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto second_probe_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(second_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, HandshakeOversizeFinalizesInitialPacketAtAmplificationBudget) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 400;
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 3,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x44});
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.handshake_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_EQ(connection.handshake_space_.next_send_packet_number, 0u);

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedInitialPacket>(&packets.front()), nullptr);
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

TEST(QuicCoreTest,
     ServerHandshakeConfirmationFromApplicationAckKeepsPtoForMissingApplicationTailPacket) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::sent;
    connection.handshake_space_.sent_packets.emplace(
        7, coquic::quic::SentPacketRecord{
               .packet_number = 7,
               .sent_time = coquic::quic::test::test_time(0),
               .ack_eliciting = true,
               .in_flight = true,
               .has_ping = true,
               .bytes_in_flight = 60,
           });

    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(1024), std::byte{0x53});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, true).has_value());
    ASSERT_TRUE(connection.streams_.contains(0));
    auto &stream = connection.streams_.at(0);

    auto first_fragment = stream.take_send_fragments(coquic::quic::StreamSendBudget{
        .packet_bytes = 384,
        .new_bytes = 384,
    });
    auto second_fragment = stream.take_send_fragments(coquic::quic::StreamSendBudget{
        .packet_bytes = 383,
        .new_bytes = 383,
    });
    auto tail_fragment = stream.take_send_fragments(coquic::quic::StreamSendBudget{
        .packet_bytes = 512,
        .new_bytes = 512,
    });

    ASSERT_EQ(first_fragment.size(), 1u);
    ASSERT_EQ(second_fragment.size(), 1u);
    ASSERT_EQ(tail_fragment.size(), 1u);
    EXPECT_EQ(first_fragment.front().offset, 0u);
    EXPECT_EQ(second_fragment.front().offset, 384u);
    EXPECT_EQ(tail_fragment.front().offset, 767u);
    EXPECT_TRUE(tail_fragment.front().fin);

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = tail_fragment,
                                     .bytes_in_flight = 320,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = first_fragment,
                                     .bytes_in_flight = 448,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = second_fragment,
                                     .bytes_in_flight = 447,
                                 });

    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = 3,
                                             .first_ack_range = 1,
                                         },
                                         coquic::quic::test::test_time(2),
                                         peer_transport_parameters.ack_delay_exponent,
                                         peer_transport_parameters.max_ack_delay,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    EXPECT_TRUE(connection.handshake_confirmed_);
    ASSERT_TRUE(connection.next_wakeup().has_value());
    const auto deadline = optional_value_or_terminate(connection.next_wakeup());

    connection.on_timeout(deadline);
    const auto probe_datagram = connection.drain_outbound_datagram(deadline);
    ASSERT_FALSE(probe_datagram.empty());

    const auto probe_packets = decode_sender_datagram(connection, probe_datagram);
    ASSERT_EQ(probe_packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&probe_packets[0]);
    ASSERT_NE(application, nullptr);

    std::vector<coquic::quic::StreamFrame> stream_frames;
    for (const auto &frame : application->frames) {
        if (const auto *stream_frame = std::get_if<coquic::quic::StreamFrame>(&frame)) {
            stream_frames.push_back(*stream_frame);
        }
    }

    ASSERT_EQ(stream_frames.size(), 1u);
    ASSERT_TRUE(stream_frames.front().offset.has_value());
    EXPECT_EQ(optional_value_or_terminate(stream_frames.front().offset), 767u);
    EXPECT_EQ(stream_frames.front().stream_data.size(), static_cast<std::size_t>(257));
    EXPECT_TRUE(stream_frames.front().fin);
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

TEST(QuicCoreTest, ClientHandshakePtoBackoffCapsBeforeHandshakeConfirmation) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.pto_count_ = 4;

    connection.arm_pto_probe(coquic::quic::test::test_time(4000));

    EXPECT_EQ(connection.pto_count_, 5u);
    ASSERT_TRUE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ClientHandshakeKeepalivePtoUsesPeerActivityBeforeHandshakeKeysAreReady) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;

    EXPECT_EQ(connection.pto_deadline(), std::optional{coquic::quic::test::test_time(4000)});
    EXPECT_EQ(connection.next_wakeup(), std::optional{coquic::quic::test::test_time(4000)});

    connection.on_timeout(coquic::quic::test::test_time(4000));

    EXPECT_EQ(connection.pto_count_, 5u);
    EXPECT_TRUE(connection.initial_space_.pending_probe_packet.has_value() &&
                connection.initial_space_.pending_probe_packet->has_ping);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveAckDoesNotResetPtoBackoff) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;

    ASSERT_EQ(connection.pto_deadline(), std::optional{coquic::quic::test::test_time(4000)});

    connection.on_timeout(coquic::quic::test::test_time(4000));

    ASSERT_EQ(connection.pto_count_, 5u);
    EXPECT_TRUE(connection.initial_space_.pending_probe_packet.has_value() &&
                connection.initial_space_.pending_probe_packet->has_ping);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(4000));
    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(connection.initial_space_.sent_packets.size(), 1u);

    const auto processed = connection.process_inbound_ack(
        connection.initial_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(4100), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 5u);
    const auto next_deadline = connection.pto_deadline();
    EXPECT_TRUE(next_deadline.has_value() &&
                next_deadline.value() > coquic::quic::test::test_time(5000));
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveAckOnlyPacketDoesNotRefreshPeerActivity) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;

    connection.on_timeout(coquic::quic::test::test_time(4000));

    ASSERT_EQ(connection.pto_count_, 5u);
    ASSERT_TRUE(connection.initial_space_.pending_probe_packet.has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(4000));
    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(connection.initial_space_.sent_packets.size(), 1u);
    ASSERT_EQ(connection.last_client_handshake_keepalive_probe_time_,
              std::optional{coquic::quic::test::test_time(4000)});
    ASSERT_EQ(connection.pto_count_, 5u);

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .destination_connection_id = {},
            .source_connection_id = {std::byte{0x01}},
            .token = {},
            .packet_number = 1,
            .frames =
                {
                    coquic::quic::AckFrame{
                        .largest_acknowledged = 0,
                        .first_ack_range = 0,
                    },
                },
        },
        coquic::quic::test::test_time(4100));

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 5u);
    EXPECT_EQ(connection.last_peer_activity_time_, std::optional{coquic::quic::test::test_time(4)});
    const auto next_deadline = connection.pto_deadline();
    EXPECT_TRUE(next_deadline.has_value() &&
                next_deadline.value() > coquic::quic::test::test_time(5000));
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveUsesMostRecentProbeTimeAsReference) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.last_client_handshake_keepalive_probe_time_ = coquic::quic::test::test_time(10);
    connection.pto_count_ = 4;

    const auto expected = coquic::quic::compute_pto_deadline(connection.shared_recovery_rtt_state(),
                                                             std::chrono::milliseconds(0),
                                                             coquic::quic::test::test_time(10), 2);

    EXPECT_EQ(connection.pto_deadline(), std::optional{expected});
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveProbeArmsFromMostRecentProbeTimeReference) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.last_client_handshake_keepalive_probe_time_ = coquic::quic::test::test_time(10);
    connection.pto_count_ = 4;

    const auto deadline = coquic::quic::compute_pto_deadline(connection.shared_recovery_rtt_state(),
                                                             std::chrono::milliseconds(0),
                                                             coquic::quic::test::test_time(10), 2);

    connection.arm_pto_probe(deadline);

    EXPECT_EQ(connection.pto_count_, 5u);
    ASSERT_TRUE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(optional_ref_or_terminate(connection.initial_space_.pending_probe_packet).has_ping);
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveProbeDoesNotArmBeforeDeadline) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;

    connection.arm_pto_probe(coquic::quic::test::test_time(3999));

    EXPECT_EQ(connection.pto_count_, 4u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveProbeDoesNotArmAfterInitialSpaceDiscarded) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.initial_packet_space_discarded_ = true;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;

    EXPECT_FALSE(connection.pto_deadline().has_value());

    connection.arm_pto_probe(coquic::quic::test::test_time(4000));

    EXPECT_EQ(connection.pto_count_, 4u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveProbeDoesNotArmWhileAckElicitingPacketIsInFlight) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;
    connection.handshake_space_.sent_packets.emplace(
        1, coquic::quic::SentPacketRecord{
               .packet_number = 1,
               .sent_time = coquic::quic::test::test_time(1),
               .ack_eliciting = true,
               .in_flight = true,
           });

    connection.arm_pto_probe(coquic::quic::test::test_time(2));

    EXPECT_EQ(connection.pto_count_, 4u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveTracksHandshakeProbePacketSend) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 9,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto now = coquic::quic::test::test_time(5);
    const auto datagram = connection.drain_outbound_datagram(now);

    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_client_handshake_keepalive_probe_time_, now);
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveTrackingIgnoresRetransmittableProbePackets) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 1,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = {std::byte{0x01}},
                },
            },
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.last_client_handshake_keepalive_probe_time_.has_value());
}

TEST(QuicCoreTest, ClientHandshakeAckOnlyHandshakePacketDoesNotRefreshPeerActivity) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.last_client_handshake_keepalive_probe_time_ = coquic::quic::test::test_time(4000);
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x42});

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .destination_connection_id = {},
            .source_connection_id = {std::byte{0x02}},
            .packet_number = 1,
            .frames =
                {
                    coquic::quic::AckFrame{
                        .largest_acknowledged = 0,
                        .first_ack_range = 0,
                    },
                },
        },
        coquic::quic::test::test_time(4100));

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.last_peer_activity_time_, std::optional{coquic::quic::test::test_time(4)});
    EXPECT_FALSE(connection.handshake_space_.pending_ack_deadline.has_value());
}

TEST(QuicCoreTest, ApplicationSpaceAckOfPingOnlyPacketResetsHandshakePtoBackoff) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.pto_count_ = 5;
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 7,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = 1,
                                 });

    const auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 7,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(2), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 0u);
}

TEST(QuicCoreTest, ClientHandshakeAckOfRetransmittableProbeResetsPtoBackoff) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.pto_count_ = 5;
    connection.track_sent_packet(
        connection.initial_space_,
        coquic::quic::SentPacketRecord{
            .packet_number = 0,
            .sent_time = coquic::quic::test::test_time(1),
            .ack_eliciting = true,
            .in_flight = true,
            .max_streams_frames =
                {
                    coquic::quic::MaxStreamsFrame{
                        .stream_type = coquic::quic::StreamLimitType::bidirectional,
                        .maximum_streams = 1,
                    },
                },
            .has_ping = true,
            .bytes_in_flight = 1,
        });

    const auto processed = connection.process_inbound_ack(
        connection.initial_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(2), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 0u);
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

TEST(QuicCoreTest, InitialProbePacketCanFallbackToPing) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 3,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
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

    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(connection.handshake_space_.sent_packets.size(), 1u);
    EXPECT_TRUE(connection.handshake_space_.sent_packets.begin()->second.has_ping);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, HandshakeProbeTrimLoopCanDropFullyTrimmedProbeRange) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 32,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1300, std::byte{0x51}),
                },
                coquic::quic::ByteRange{
                    .offset = 1300,
                    .bytes = std::vector<std::byte>(1, std::byte{0x52}),
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets[0]);
    ASSERT_NE(handshake, nullptr);

    std::vector<const coquic::quic::CryptoFrame *> crypto_frames;
    for (const auto &frame : handshake->frames) {
        if (const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame)) {
            crypto_frames.push_back(crypto);
        }
    }

    ASSERT_EQ(crypto_frames.size(), 1u);
    EXPECT_EQ(crypto_frames.front()->offset, 0u);
    EXPECT_LT(crypto_frames.front()->crypto_data.size(), 1300u);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest,
     HandshakeProbeTrimReserializationFailureMarksConnectionFailedAfterDroppingRange) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 33,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1300, std::byte{0x53}),
                },
                coquic::quic::ByteRange{
                    .offset = 1300,
                    .bytes = std::vector<std::byte>(1, std::byte{0x54}),
                },
            },
    };
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new, 2);

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.handshake_space_.sent_packets.empty());
}

TEST(QuicCoreTest, HandshakeProbeTrimLoopStopsWhenAckStillOverflowsAfterAllProbeCryptoIsRemoved) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 34,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = coquic::quic::test::bytes_from_string("hs"),
                },
            },
    };
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.handshake_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_TRUE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(connection.handshake_space_.sent_packets.empty());
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

TEST(QuicCoreTest, ApplicationProbePacketCanIncludePendingApplicationCryptoAndPing) {
    auto connection = make_connected_server_connection();
    connection.application_space_.send_crypto.append(coquic::quic::test::bytes_from_string("app"));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 78,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_crypto = false;
    bool saw_ping = false;
    for (const auto &frame : application->frames) {
        if (const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame)) {
            saw_crypto = true;
            EXPECT_EQ(crypto->offset, 0u);
            EXPECT_EQ(crypto->crypto_data, coquic::quic::test::bytes_from_string("app"));
        }
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_crypto);
    EXPECT_TRUE(saw_ping);
    ASSERT_EQ(connection.application_space_.sent_packets.size(), 1u);
    const auto &sent_packet = connection.application_space_.sent_packets.begin()->second;
    ASSERT_EQ(sent_packet.crypto_ranges.size(), 1u);
    EXPECT_EQ(sent_packet.crypto_ranges[0].bytes, coquic::quic::test::bytes_from_string("app"));
    EXPECT_TRUE(sent_packet.has_ping);
}

TEST(QuicCoreTest, ApplicationCryptoOnlyProbeBurstDoesNotFailWhenLostCryptoIsPending) {
    auto connection = make_connected_server_connection();
    connection.application_space_.send_crypto.append(coquic::quic::test::bytes_from_string("app"));
    auto lost_crypto = connection.application_space_.send_crypto.take_ranges(
        std::numeric_limits<std::size_t>::max());
    ASSERT_EQ(lost_crypto.size(), 1u);
    const auto &range = lost_crypto.front();
    connection.application_space_.send_crypto.mark_lost(range.offset, range.bytes.size());
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 79,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges = lost_crypto,
    };
    connection.remaining_pto_probe_datagrams_ = 2;

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    static_cast<void>(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)));
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ConnectedConnectionWithoutApplicationWriteSecretSkipsApplicationSend) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/12, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.write_secret = std::nullopt;

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
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

TEST(QuicCoreTest, ApplicationProbePathFailsWhenAckCandidateSerializationFails) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/16, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 17,
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

TEST(QuicCoreTest, ApplicationProbePathDropsBaseAckWhenNoAckFallbackFits) {
    const auto payload_size = find_application_probe_payload_size_that_drops_ack();
    ASSERT_TRUE(payload_size.has_value());
    const auto payload_size_value = optional_value_or_terminate(payload_size);

    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/18, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 19,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(payload_size_value, std::byte{0x54}),
                    .fin = false,
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(datagram_has_application_ack(connection, datagram));
    EXPECT_TRUE(datagram_has_application_stream(connection, datagram));
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenNoAckFallbackSerializationFails) {
    const auto payload_size = find_application_probe_payload_size_that_drops_ack();
    ASSERT_TRUE(payload_size.has_value());
    const auto payload_size_value = optional_value_or_terminate(payload_size);

    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/20, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 21,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(payload_size_value, std::byte{0x55}),
                    .fin = false,
                },
            },
    };
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new, 3);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenTrimLoopReserializationFails) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 22,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1200, std::byte{0x56}),
                    .fin = false,
                },
            },
    };
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new, 2);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationProbePathRestoresEmptyAndFullyTrimmedFragments) {
    auto connection = make_connected_client_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    stream.send_buffer.append(std::vector<std::byte>(1201, std::byte{0x57}));

    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 23,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1200, std::byte{0x57}),
                    .fin = false,
                },
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 1200,
                    .bytes = std::vector<std::byte>(1, std::byte{0x58}),
                    .fin = false,
                },
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 1201,
                    .bytes = {},
                    .fin = true,
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(datagram_has_application_stream(connection, datagram));
    EXPECT_EQ(stream.send_fin_state, coquic::quic::StreamSendFinState::pending);
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenAcklessControlFramesStillExceedDatagramBudget) {
    auto connection = make_connected_client_connection();
    for (std::uint64_t stream_index = 0; stream_index < 256; ++stream_index) {
        connection.application_space_.pending_probe_packet =
            connection.application_space_.pending_probe_packet.value_or(
                coquic::quic::SentPacketRecord{
                    .packet_number = 24,
                    .ack_eliciting = true,
                    .in_flight = true,
                });
        connection.application_space_.pending_probe_packet->reset_stream_frames.push_back(
            coquic::quic::ResetStreamFrame{
                .stream_id = stream_index * 4,
                .application_protocol_error_code = 1,
                .final_size = 0,
            });
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationProbeRestoresCryptoWhenAmplificationBudgetIsTooSmall) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 10;
    connection.application_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("probe-crypto"));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 27,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.application_space_.send_crypto.has_pending_data());
    EXPECT_TRUE(connection.application_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ApplicationProbeRestoresLostProbeFragmentsWhenAmplificationBudgetIsTooSmall) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 10;
    connection.application_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("probe-crypto"));
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    const auto payload = coquic::quic::test::bytes_from_string("probe-fragment");
    stream.send_buffer.append(payload);
    const auto initial_fragments = stream.take_send_fragments(payload.size());
    ASSERT_EQ(initial_fragments.size(), 1u);
    stream.mark_send_fragment_lost(initial_fragments.front());
    ASSERT_TRUE(stream.send_buffer.has_lost_data());
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 28,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments = initial_fragments,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.application_space_.send_crypto.has_pending_data());
    EXPECT_TRUE(connection.application_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(stream.send_buffer.has_lost_data());
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenAckAndControlFramesStillExceedDatagramBudget) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/25, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 26,
        .ack_eliciting = true,
        .in_flight = true,
    };
    for (std::uint64_t stream_index = 0; stream_index < 256; ++stream_index) {
        connection.application_space_.pending_probe_packet->reset_stream_frames.push_back(
            coquic::quic::ResetStreamFrame{
                .stream_id = stream_index * 4,
                .application_protocol_error_code = 1,
                .final_size = 0,
            });
    }

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

TEST(QuicCoreTest, ApplicationSendRestoresUnsentCandidateWhenCongestionBlocked) {
    auto connection = make_connected_client_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    connection.connection_flow_control_.pending_max_data_frame =
        coquic::quic::MaxDataFrame{.maximum_data = 20};
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::pending;
    connection.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 21};
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;
    stream.flow_control.pending_max_stream_data_frame = coquic::quic::MaxStreamDataFrame{
        .stream_id = 0,
        .maximum_stream_data = 22,
    };
    stream.flow_control.max_stream_data_state = coquic::quic::StreamControlFrameState::pending;
    stream.flow_control.pending_stream_data_blocked_frame = coquic::quic::StreamDataBlockedFrame{
        .stream_id = 0,
        .maximum_stream_data = 23,
    };
    stream.flow_control.stream_data_blocked_state = coquic::quic::StreamControlFrameState::pending;
    stream.pending_reset_frame = coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 1,
        .final_size = 0,
    };
    stream.reset_state = coquic::quic::StreamControlFrameState::pending;
    stream.pending_stop_sending_frame = coquic::quic::StopSendingFrame{
        .stream_id = 0,
        .application_protocol_error_code = 2,
    };
    stream.stop_sending_state = coquic::quic::StreamControlFrameState::pending;
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("blocked"), false)
            .has_value());

    connection.congestion_controller_.bytes_in_flight_ =
        connection.congestion_controller_.congestion_window();

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());
    EXPECT_EQ(connection.connection_flow_control_.highest_sent, 0u);
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
}

TEST(QuicCoreTest,
     ApplicationSendRestoresPendingCryptoWhenCongestionBlockedAndAckOnlySerializationFails) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/32, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("blocked-crypto"));
    connection.congestion_controller_.bytes_in_flight_ =
        connection.congestion_controller_.congestion_window();
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new, 3);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.application_space_.send_crypto.has_pending_data());
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ApplicationSendPathFailsWhenNoAckFallbackSerializationFails) {
    const auto payload_size = find_application_send_payload_size_that_drops_ack();
    ASSERT_TRUE(payload_size.has_value());
    const auto payload_size_value = optional_value_or_terminate(payload_size);

    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/27, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, std::vector<std::byte>(payload_size_value, std::byte{0x59}), false)
                    .has_value());
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new, 3);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendFallsBackToAckOnlyWhenAmplificationBudgetShrinks) {
    bool saw_ack_only_fallback = false;

    for (std::uint64_t received_bytes = 10; received_bytes <= 80; ++received_bytes) {
        auto connection = make_connected_server_connection();
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = received_bytes;
        connection.application_space_.received_packets.record_received(
            /*packet_number=*/33, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
        ASSERT_TRUE(
            connection.queue_stream_send(0, std::vector<std::byte>(256, std::byte{0x60}), false)
                .has_value());

        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (connection.has_failed() || datagram.empty()) {
            continue;
        }

        if (!datagram_has_application_stream(connection, datagram) &&
            datagram_has_application_ack(connection, datagram) &&
            connection.has_pending_application_send()) {
            saw_ack_only_fallback = true;
            break;
        }
    }

    EXPECT_TRUE(saw_ack_only_fallback);
}

TEST(QuicCoreTest, ApplicationSendFailsWhenAckedControlFramesAndDataStillExceedDatagramBudget) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/30, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("x"), false)
                    .has_value());
    for (std::uint64_t stream_index = 1; stream_index <= 256; ++stream_index) {
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
    EXPECT_TRUE(connection.application_space_.sent_packets.empty());
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

TEST(QuicCoreTest, ApplicationSendOversizeFinalizesHandshakePacketAtAmplificationBudget) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 400;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x62});
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 9,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
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

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front()), nullptr);
}

TEST(QuicCoreTest, HandshakeOversizeWithoutInitialPacketReturnsEmptyAtAmplificationBudget) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 10;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x63});
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.handshake_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_TRUE(connection.initial_space_.sent_packets.empty());
    EXPECT_TRUE(connection.handshake_space_.sent_packets.empty());
}

TEST(QuicCoreTest, RetransmittedServerResponseStillCarriesAckForRepeatedRequestPacket) {
    auto connection = make_connected_server_connection();

    const auto process_request = [&](std::uint64_t packet_number,
                                     coquic::quic::QuicCoreTimePoint now) {
        const auto processed = connection.process_inbound_packet(
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = false,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = packet_number,
                .frames =
                    {
                        coquic::quic::StreamFrame{
                            .fin = true,
                            .has_offset = true,
                            .has_length = true,
                            .stream_id = 0,
                            .offset = 0,
                            .stream_data =
                                coquic::quic::test::bytes_from_string("GET /repeat-me\r\n"),
                        },
                    },
            },
            now);
        ASSERT_TRUE(processed.has_value());
    };

    process_request(/*packet_number=*/7, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.take_received_stream_data().has_value());
    ASSERT_TRUE(
        connection
            .queue_stream_send(
                0, std::vector<std::byte>(static_cast<std::size_t>(1024), std::byte{0x52}), true)
            .has_value());

    const auto first_response =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_response.empty());
    ASSERT_FALSE(connection.application_space_.sent_packets.empty());

    const auto first_packet_number =
        std::prev(connection.application_space_.sent_packets.end())->first;
    const auto first_packet = connection.application_space_.sent_packets.at(first_packet_number);
    ASSERT_FALSE(first_packet.stream_fragments.empty());

    connection.mark_lost_packet(connection.application_space_, first_packet);
    ASSERT_TRUE(connection.has_pending_application_send());

    process_request(/*packet_number=*/8, coquic::quic::test::test_time(2));
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    const auto retransmitted = connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(retransmitted.empty());

    const auto packets = decode_sender_datagram(connection, retransmitted);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_stream);
    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, CongestionBlockedApplicationSendStillEmitsAckOnlyDatagram) {
    auto connection = make_connected_server_connection();
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(2048), std::byte{0x52});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    connection.application_space_.received_packets.record_received(
        77, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.application_space_.received_packets.has_ack_to_send());

    connection.congestion_controller_.on_packet_sent(
        connection.congestion_controller_.congestion_window(), /*ack_eliciting=*/true);
    ASSERT_EQ(connection.congestion_controller_.bytes_in_flight(),
              connection.congestion_controller_.congestion_window());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_FALSE(saw_stream);
    EXPECT_TRUE(connection.has_pending_application_send());
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, LostPostHandshakeCryptoDoesNotStarveRetransmittedServerResponse) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;

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
                        .stream_data = coquic::quic::test::bytes_from_string("GET /\r\n"),
                    },
                },
        },
        coquic::quic::test::test_time(0));
    ASSERT_TRUE(processed.has_value());
    ASSERT_TRUE(connection.take_received_stream_data().has_value());

    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(1024), std::byte{0x53});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, true).has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    ASSERT_EQ(connection.application_space_.sent_packets.size(), 1u);

    const auto first_packet_number =
        std::prev(connection.application_space_.sent_packets.end())->first;
    const auto first_packet = connection.application_space_.sent_packets.at(first_packet_number);
    EXPECT_FALSE(first_packet.crypto_ranges.empty());

    connection.mark_lost_packet(connection.application_space_, first_packet);
    EXPECT_TRUE(connection.has_pending_application_send());

    const auto second_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(second_datagram.empty());

    const auto packets = decode_sender_datagram(connection, second_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_stream);
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, CorruptedOneRttRequestWithPendingPostHandshakeDataDoesNotBreakRetransmit) {
    auto connection = make_connected_server_connection();
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));

    const auto request = coquic::quic::serialize_protected_datagram(
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
                            .stream_data = coquic::quic::test::bytes_from_string(
                                "GET /toasty-vibrant-mesprit\r\n"),
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
    ASSERT_TRUE(request.has_value());
    if (!request.has_value()) {
        return;
    }

    const auto request_datagram = request.has_value() ? request.value() : std::vector<std::byte>{};
    auto corrupted = request_datagram;
    ASSERT_GT(corrupted.size(), 43u);
    corrupted[43] = std::byte{0xae};

    connection.process_inbound_datagram(corrupted, coquic::quic::test::test_time(1));
    EXPECT_FALSE(connection.has_failed());

    connection.process_inbound_datagram(request_datagram, coquic::quic::test::test_time(2));
    EXPECT_FALSE(connection.has_failed());

    const auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    const auto &received_value = optional_ref_or_terminate(received);
    EXPECT_EQ(received_value.stream_id, 0u);
    EXPECT_EQ(received_value.bytes,
              coquic::quic::test::bytes_from_string("GET /toasty-vibrant-mesprit\r\n"));
    EXPECT_TRUE(received_value.fin);
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

TEST(QuicCoreTest, ConnectionNamespaceHelpersCoverEdgeCases) {
    EXPECT_TRUE(coquic::quic::test::connection_helper_edge_cases_for_tests());
}

TEST(QuicCoreTest, AckProcessingAccountsForLateAckedEcnPackets) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::probing;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(3),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::ect0,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 5,
                                     .sent_time = coquic::quic::test::test_time(5),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::ect0,
                                 });
    auto late_packet = connection.application_space_.sent_packets.at(3);
    late_packet.in_flight = false;
    late_packet.declared_lost = true;
    late_packet.bytes_in_flight = 0;
    connection.application_space_.declared_lost_packets.emplace(3, late_packet);
    connection.application_space_.sent_packets.erase(3);

    const auto processed =
        connection.process_inbound_ack(connection.application_space_,
                                       coquic::quic::AckFrame{
                                           .largest_acknowledged = 5,
                                           .first_ack_range = 0,
                                           .additional_ranges =
                                               {
                                                   coquic::quic::AckRange{
                                                       .gap = 0,
                                                       .range_length = 0,
                                                   },
                                               },
                                           .ecn_counts =
                                               coquic::quic::AckEcnCounts{
                                                   .ect0 = 2,
                                                   .ect1 = 0,
                                                   .ecn_ce = 0,
                                               },
                                       },
                                       coquic::quic::test::test_time(10), /*ack_delay_exponent=*/0,
                                       /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_FALSE(connection.application_space_.declared_lost_packets.contains(3));
    EXPECT_FALSE(connection.application_space_.sent_packets.contains(5));
}

TEST(QuicCoreTest, AckProcessingDisablesEcnWhenPeerDecreasesEct1OrCeCounts) {
    struct CountCase {
        coquic::quic::AckEcnCounts previous_counts;
        coquic::quic::AckEcnCounts current_counts;
    };

    for (const auto &test_case : std::array{
             CountCase{
                 .previous_counts =
                     {
                         .ect0 = 1,
                         .ect1 = 2,
                         .ecn_ce = 3,
                     },
                 .current_counts =
                     {
                         .ect0 = 1,
                         .ect1 = 1,
                         .ecn_ce = 3,
                     },
             },
             CountCase{
                 .previous_counts =
                     {
                         .ect0 = 1,
                         .ect1 = 1,
                         .ecn_ce = 2,
                     },
                 .current_counts =
                     {
                         .ect0 = 1,
                         .ect1 = 1,
                         .ecn_ce = 1,
                     },
             },
         }) {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.ecn.state = coquic::quic::QuicPathEcnState::capable;
        path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;
        path.ecn.has_last_peer_counts[2] = true;
        path.ecn.last_peer_counts[2] = test_case.previous_counts;

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

        const auto processed = connection.process_inbound_ack(
            connection.application_space_,
            coquic::quic::AckFrame{
                .largest_acknowledged = 1,
                .first_ack_range = 0,
                .ecn_counts = test_case.current_counts,
            },
            coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
            /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

        ASSERT_TRUE(processed.has_value());
        EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::failed);
    }
}

TEST(QuicCoreTest, AckProcessingDisablesEcnWhenPeerCountsDecrease) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::capable;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;
    path.ecn.has_last_peer_counts[2] = true;
    path.ecn.last_peer_counts[2] = coquic::quic::AckEcnCounts{
        .ect0 = 2,
        .ect1 = 0,
        .ecn_ce = 0,
    };

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

    const auto processed =
        connection.process_inbound_ack(connection.application_space_,
                                       coquic::quic::AckFrame{
                                           .largest_acknowledged = 1,
                                           .first_ack_range = 0,
                                           .ecn_counts =
                                               coquic::quic::AckEcnCounts{
                                                   .ect0 = 1,
                                                   .ect1 = 0,
                                                   .ecn_ce = 0,
                                               },
                                       },
                                       coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
                                       /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::failed);
    EXPECT_FALSE(path.ecn.has_last_peer_counts[2]);
    EXPECT_EQ(connection.outbound_ecn_codepoint_for_path(0),
              coquic::quic::QuicEcnCodepoint::not_ect);
}

TEST(QuicCoreTest, AckProcessingDisablesEcnWhenEct1FeedbackIsMissingOrImpossible) {
    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.ecn.state = coquic::quic::QuicPathEcnState::capable;
        path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect1;

        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 1,
                                         .sent_time = coquic::quic::test::test_time(1),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                         .path_id = 0,
                                         .ecn = coquic::quic::QuicEcnCodepoint::ect1,
                                     });

        const auto missing_feedback = connection.process_inbound_ack(
            connection.application_space_,
            coquic::quic::AckFrame{
                .largest_acknowledged = 1,
                .first_ack_range = 0,
                .ecn_counts =
                    coquic::quic::AckEcnCounts{
                        .ect0 = 0,
                        .ect1 = 0,
                        .ecn_ce = 0,
                    },
            },
            coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
            /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

        ASSERT_TRUE(missing_feedback.has_value());
        EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::failed);
    }

    {
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

        const auto impossible_feedback = connection.process_inbound_ack(
            connection.application_space_,
            coquic::quic::AckFrame{
                .largest_acknowledged = 1,
                .first_ack_range = 0,
                .ecn_counts =
                    coquic::quic::AckEcnCounts{
                        .ect0 = 1,
                        .ect1 = 1,
                        .ecn_ce = 0,
                    },
            },
            coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
            /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

        ASSERT_TRUE(impossible_feedback.has_value());
        EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::failed);
    }
}

TEST(QuicCoreTest, AckProcessingKeepsProbingWhenAckedPacketsWereNotEctMarked) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::probing;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::not_ect,
                                 });

    const auto processed =
        connection.process_inbound_ack(connection.application_space_,
                                       coquic::quic::AckFrame{
                                           .largest_acknowledged = 1,
                                           .first_ack_range = 0,
                                           .ecn_counts =
                                               coquic::quic::AckEcnCounts{
                                                   .ect0 = 0,
                                                   .ect1 = 0,
                                                   .ecn_ce = 0,
                                               },
                                       },
                                       coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
                                       /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::probing);
    EXPECT_EQ(path.ecn.probing_packets_acked, 0u);
}

TEST(QuicCoreTest, AckProcessingPromotesProbingPathWhenAckedProbeCountsOnlyCeMarks) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::probing;
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

    const auto processed =
        connection.process_inbound_ack(connection.application_space_,
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
                                       coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
                                       /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::capable);
    EXPECT_EQ(path.ecn.probing_packets_acked, 1u);
}

TEST(QuicCoreTest, MarkLostPacketKeepsEcnProbingWhenProbeLossIsNotConclusive) {
    struct LossCase {
        std::uint64_t probing_packets_sent;
        std::uint64_t probing_packets_acked;
    };

    for (const auto &test_case : std::array{
             LossCase{
                 .probing_packets_sent = 0,
                 .probing_packets_acked = 0,
             },
             LossCase{
                 .probing_packets_sent = 1,
                 .probing_packets_acked = 1,
             },
             LossCase{
                 .probing_packets_sent = 2,
                 .probing_packets_acked = 0,
             },
         }) {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.ecn.state = coquic::quic::QuicPathEcnState::probing;
        path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;
        path.ecn.probing_packets_sent = test_case.probing_packets_sent;
        path.ecn.probing_packets_acked = test_case.probing_packets_acked;

        const auto packet = coquic::quic::SentPacketRecord{
            .packet_number = 9,
            .sent_time = coquic::quic::test::test_time(1),
            .ack_eliciting = true,
            .in_flight = true,
            .bytes_in_flight = 1200,
            .path_id = 0,
            .ecn = coquic::quic::QuicEcnCodepoint::ect0,
        };
        connection.application_space_.sent_packets.emplace(packet.packet_number, packet);

        connection.mark_lost_packet(connection.application_space_, packet);

        EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::probing);
    }
}

TEST(QuicCoreTest, OutboundEcnCodepointReturnsNotEctWhenPathTransmitMarkIsUnmarked) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::capable;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::not_ect;

    EXPECT_EQ(connection.outbound_ecn_codepoint_for_path(0),
              coquic::quic::QuicEcnCodepoint::not_ect);
}

TEST(QuicCoreTest, ApplicationCloseDrainReturnsEmptyWithoutOneRttKeys) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection
                    .queue_application_close({
                        .application_error_code = 9,
                        .reason_phrase = "closing",
                    })
                    .has_value());
    connection.application_space_.write_secret.reset();

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    EXPECT_TRUE(datagram.empty());
}

TEST(QuicCoreTest, TinyDatagramBudgetFailsApplicationCloseSerialization) {
    auto connection = make_connected_client_connection();
    connection.config_.transport.max_udp_payload_size = 48;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.max_udp_payload_size = 48;

    ASSERT_TRUE(connection
                    .queue_application_close({
                        .application_error_code = 11,
                        .reason_phrase = std::string(256, 'x'),
                    })
                    .has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    EXPECT_FALSE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, AntiAmplificationAccountingSaturatesBudgetAndCounters) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.peer_address_validated_ = false;

    connection.anti_amplification_received_bytes_ =
        (std::numeric_limits<std::uint64_t>::max() / 3u) + 1u;
    EXPECT_EQ(connection.anti_amplification_send_budget(),
              std::numeric_limits<std::uint64_t>::max());

    connection.anti_amplification_received_bytes_ = std::numeric_limits<std::uint64_t>::max() - 4u;
    connection.note_inbound_datagram_bytes(8);
    EXPECT_EQ(connection.anti_amplification_received_bytes_,
              std::numeric_limits<std::uint64_t>::max());

    connection.anti_amplification_sent_bytes_ = std::numeric_limits<std::uint64_t>::max() - 4u;
    connection.note_outbound_datagram_bytes(8);
    EXPECT_EQ(connection.anti_amplification_sent_bytes_, std::numeric_limits<std::uint64_t>::max());
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

TEST(QuicCoreTest, ServerProcessesOneRttDataBeforeHandshakeCompletionWhenKeysAlreadyExist) {
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

    ASSERT_TRUE(server.connection_->application_space_.read_secret.has_value());

    const auto server_before_completion = coquic::quic::test::relay_nth_send_datagram_to_peer(
        request, one_rtt_index, server, coquic::quic::test::test_time(4));
    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(server_before_completion)),
              "buffer-me");
    EXPECT_FALSE(server.has_failed());
    EXPECT_TRUE(server.connection_->deferred_protected_packets_.empty());

    const auto server_after_completion = coquic::quic::test::relay_nth_send_datagram_to_peer(
        client_handshake, handshake_index, server, coquic::quic::test::test_time(5));
    EXPECT_TRUE(
        coquic::quic::test::received_application_data_from(server_after_completion).empty());
    EXPECT_FALSE(server.has_failed());
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
                                    .sequence_number = 2,
                                    .retire_prior_to = 1,
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

TEST(QuicCoreTest, DuplicateAckElicitingInitialQueuesServerHandshakeRecoveryProbe) {
    coquic::quic::QuicConnection server(coquic::quic::test::make_server_core_config());
    server.started_ = true;
    server.status_ = coquic::quic::HandshakeStatus::in_progress;
    server.initial_space_.received_packets.record_received(7, /*ack_eliciting=*/true,
                                                           coquic::quic::test::test_time(0));
    server.handshake_space_.sent_packets.emplace(3,
                                                 coquic::quic::SentPacketRecord{
                                                     .packet_number = 3,
                                                     .sent_time = coquic::quic::test::test_time(0),
                                                     .ack_eliciting = true,
                                                     .in_flight = true,
                                                 });

    const auto processed = server.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = server.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x44, 0x55}),
            .packet_number_length = 2,
            .packet_number = 7,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(processed.has_value());
    ASSERT_TRUE(server.handshake_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(optional_value_or_terminate(server.handshake_space_.pending_probe_packet).has_ping);
}

TEST(QuicCoreTest, ClientHandshakeKeepalivePtoDeadlineArmsProbeWithoutInflightPackets) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(0);

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());

    connection.arm_pto_probe(coquic::quic::test::test_time(1000));

    ASSERT_TRUE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(
        optional_value_or_terminate(connection.initial_space_.pending_probe_packet).has_ping);
    EXPECT_EQ(connection.remaining_pto_probe_datagrams_, 2);
}

TEST(QuicCoreTest, ClientReceiveKeepalivePtoDeadlineArmsProbeWithoutInflightPackets) {
    auto connection = make_connected_client_connection();
    connection.current_send_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(1).is_current_send_path = true;
    connection.last_validated_path_id_ = 1;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;
    connection.streams_.emplace(
        0, coquic::quic::make_implicit_stream_state(0, connection.config_.role));

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());
    EXPECT_EQ(connection.next_wakeup(), deadline);

    const auto deadline_value = optional_value_or_terminate(deadline);
    connection.arm_pto_probe(deadline_value);

    ASSERT_TRUE(connection.application_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(
        optional_value_or_terminate(connection.application_space_.pending_probe_packet).has_ping);
    EXPECT_EQ(connection.remaining_pto_probe_datagrams_, 2);

    const auto datagram = connection.drain_outbound_datagram(deadline_value);
    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), std::optional<coquic::quic::QuicPathId>{1});
}

TEST(QuicCoreTest, ClientReceiveKeepalivePtoDeadlineStaysArmedAfterPartialResponseFlow) {
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

    const auto response_payload =
        coquic::quic::test::bytes_from_string(std::string(static_cast<std::size_t>(2048), 'r'));
    const auto response = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = response_payload,
            .fin = false,
        },
        coquic::quic::test::test_time(3));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(response).empty());

    const auto response_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        response, client, coquic::quic::test::test_time(4));
    EXPECT_EQ(coquic::quic::test::received_application_data_from(response_delivered),
              response_payload);

    ASSERT_TRUE(client.connection_->handshake_confirmed_);
    ASSERT_TRUE(client.connection_->streams_.contains(0));
    EXPECT_FALSE(client.connection_->streams_.at(0).peer_fin_delivered);

    const auto deadline = client.connection_->next_wakeup();
    ASSERT_TRUE(deadline.has_value());

    const auto timeout_result =
        client.advance(coquic::quic::QuicCoreTimerExpired{}, optional_value_or_terminate(deadline));
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(timeout_result).empty());
}

TEST(QuicCoreTest, ClientTimerAfterLargePartialResponseFlowStillSendsProbe) {
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

    const auto response_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        response, client, coquic::quic::test::test_time(4));
    EXPECT_FALSE(coquic::quic::test::received_application_data_from(response_delivered).empty());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(response_delivered).empty());

    ASSERT_TRUE(client.connection_->handshake_confirmed_);
    ASSERT_FALSE(client.connection_->application_space_.sent_packets.empty());

    const auto deadline = client.connection_->next_wakeup();
    ASSERT_TRUE(deadline.has_value());

    const auto timeout_result =
        client.advance(coquic::quic::QuicCoreTimerExpired{}, optional_value_or_terminate(deadline));
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(timeout_result).empty());
}

TEST(QuicCoreTest, ClientTimerAfterLargePartialResponseFlowRetainsAckOnProbe) {
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

    const auto response_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        response, client, coquic::quic::test::test_time(4));
    EXPECT_FALSE(coquic::quic::test::received_application_data_from(response_delivered).empty());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(response_delivered).empty());

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
            to_client.effects.clear();
            step_now += std::chrono::milliseconds(1);
            continue;
        }

        break;
    }

    const auto in_flight_application_packets = std::count_if(
        client.connection_->application_space_.sent_packets.begin(),
        client.connection_->application_space_.sent_packets.end(),
        [](const auto &entry) { return entry.second.ack_eliciting && entry.second.in_flight; });
    ASSERT_EQ(in_flight_application_packets, 0);

    const auto deadline = client.connection_->next_wakeup();
    ASSERT_TRUE(deadline.has_value());

    const auto timeout_result =
        client.advance(coquic::quic::QuicCoreTimerExpired{}, optional_value_or_terminate(deadline));
    const auto timeout_datagrams = coquic::quic::test::send_datagrams_from(timeout_result);
    ASSERT_FALSE(timeout_datagrams.empty());

    bool saw_ack = false;
    for (const auto &datagram : timeout_datagrams) {
        for (const auto &packet : decode_sender_datagram(*client.connection_, datagram)) {
            const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (application == nullptr) {
                continue;
            }
            for (const auto &frame : application->frames) {
                saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
            }
        }
    }

    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, SelectPtoProbePrefersRetransmittableCryptoOverPingFallback) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.send_crypto.append(bytes_from_ints({0xaa}));
    const auto crypto_ranges = connection.handshake_space_.send_crypto.take_ranges(1);
    ASSERT_EQ(crypto_ranges.size(), 1u);

    connection.handshake_space_.sent_packets.emplace(
        1, coquic::quic::SentPacketRecord{
               .packet_number = 1,
               .sent_time = coquic::quic::test::test_time(0),
               .ack_eliciting = true,
               .in_flight = true,
               .has_ping = true,
           });
    connection.handshake_space_.sent_packets.emplace(
        2, coquic::quic::SentPacketRecord{
               .packet_number = 2,
               .sent_time = coquic::quic::test::test_time(1),
               .ack_eliciting = true,
               .in_flight = true,
               .crypto_ranges = crypto_ranges,
           });

    const auto probe = connection.select_pto_probe(connection.handshake_space_);

    ASSERT_TRUE(probe.has_value());
    EXPECT_EQ(optional_value_or_terminate(probe).packet_number, 2u);
    EXPECT_EQ(optional_value_or_terminate(probe).crypto_ranges.size(), 1u);
}

TEST(QuicCoreTest, AckOnlyOneRttPacketDoesNotScheduleApplicationAckDeadline) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_ack_deadline = std::nullopt;

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 4,
            .frames =
                {
                    coquic::quic::AckFrame{
                        .largest_acknowledged = 0,
                        .first_ack_range = 0,
                    },
                },
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_FALSE(connection.application_space_.pending_ack_deadline.has_value());
}

TEST(QuicCoreTest, ApplicationSendOversizeWithoutExistingPacketsReturnsEmptyAtAmplificationBudget) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 10;
    for (std::uint64_t stream_index = 0; stream_index < 64; ++stream_index) {
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
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());
    EXPECT_TRUE(connection.handshake_space_.sent_packets.empty());
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

TEST(QuicCoreTest, AckTriggeredLossUsesLostPacketSentTimeForRecoveryBoundary) {
    auto connection = make_connected_client_connection();
    auto &rtt = connection.application_space_.recovery.rtt_state();
    rtt.latest_rtt = std::chrono::milliseconds(10);
    rtt.min_rtt = std::chrono::milliseconds(10);
    rtt.smoothed_rtt = std::chrono::milliseconds(10);
    rtt.rttvar = std::chrono::milliseconds(1);
    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(8192, 'r')), false)
                    .has_value());

    for (std::uint64_t packet_number = 1; packet_number <= 8; ++packet_number) {
        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = packet_number,
                                         .sent_time = coquic::quic::test::test_time(
                                             static_cast<std::int64_t>(100u + packet_number)),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
    }

    const auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 8,
            .first_ack_range = 4,
        },
        coquic::quic::test::test_time(120), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);
    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.congestion_controller_.congestion_window(), 7200u);
    EXPECT_EQ(connection.congestion_controller_.bytes_in_flight(), 0u);
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

TEST(QuicCoreTest, SelectPtoProbeFiltersControlFramesAgainstCurrentPendingState) {
    auto connection = make_connected_client_connection();

    auto &matching_stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    matching_stream.pending_reset_frame = coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 7,
        .final_size = 11,
    };
    matching_stream.reset_state = coquic::quic::StreamControlFrameState::pending;
    matching_stream.pending_stop_sending_frame = coquic::quic::StopSendingFrame{
        .stream_id = 0,
        .application_protocol_error_code = 9,
    };
    matching_stream.stop_sending_state = coquic::quic::StreamControlFrameState::pending;
    matching_stream.flow_control.pending_max_stream_data_frame = coquic::quic::MaxStreamDataFrame{
        .stream_id = 0,
        .maximum_stream_data = 13,
    };
    matching_stream.flow_control.max_stream_data_state =
        coquic::quic::StreamControlFrameState::pending;
    matching_stream.flow_control.pending_stream_data_blocked_frame =
        coquic::quic::StreamDataBlockedFrame{
            .stream_id = 0,
            .maximum_stream_data = 15,
        };
    matching_stream.flow_control.stream_data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;

    auto &missing_pending_stream =
        connection.streams_
            .emplace(4, coquic::quic::make_implicit_stream_state(4, connection.config_.role))
            .first->second;
    missing_pending_stream.reset_state = coquic::quic::StreamControlFrameState::pending;
    missing_pending_stream.stop_sending_state = coquic::quic::StreamControlFrameState::pending;
    missing_pending_stream.flow_control.max_stream_data_state =
        coquic::quic::StreamControlFrameState::pending;
    missing_pending_stream.flow_control.stream_data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;

    connection.connection_flow_control_.pending_max_data_frame =
        coquic::quic::MaxDataFrame{.maximum_data = 99};
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::pending;
    connection.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 77};
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::acknowledged;

    coquic::quic::PacketSpaceState packet_space;
    packet_space.sent_packets.emplace(
        7, coquic::quic::SentPacketRecord{
               .packet_number = 7,
               .ack_eliciting = true,
               .in_flight = true,
               .has_handshake_done = true,
               .reset_stream_frames =
                   {
                       matching_stream.pending_reset_frame.value(),
                       coquic::quic::ResetStreamFrame{
                           .stream_id = 4,
                           .application_protocol_error_code = 1,
                           .final_size = 0,
                       },
                   },
               .stop_sending_frames =
                   {
                       matching_stream.pending_stop_sending_frame.value(),
                       coquic::quic::StopSendingFrame{
                           .stream_id = 4,
                           .application_protocol_error_code = 2,
                       },
                   },
               .max_data_frame = coquic::quic::MaxDataFrame{.maximum_data = 100},
               .max_stream_data_frames =
                   {
                       matching_stream.flow_control.pending_max_stream_data_frame.value(),
                       coquic::quic::MaxStreamDataFrame{
                           .stream_id = 4,
                           .maximum_stream_data = 12,
                       },
                   },
               .data_blocked_frame =
                   coquic::quic::DataBlockedFrame{
                       .maximum_data = 88,
                   },
               .stream_data_blocked_frames =
                   {
                       matching_stream.flow_control.pending_stream_data_blocked_frame.value(),
                       coquic::quic::StreamDataBlockedFrame{
                           .stream_id = 4,
                           .maximum_stream_data = 14,
                       },
                   },
           });

    const auto probe = connection.select_pto_probe(packet_space);

    ASSERT_TRUE(probe.has_value());
    const auto &probe_packet = optional_ref_or_terminate(probe);
    ASSERT_EQ(probe_packet.reset_stream_frames.size(), 1u);
    EXPECT_EQ(probe_packet.reset_stream_frames.front().stream_id, 0u);
    ASSERT_EQ(probe_packet.stop_sending_frames.size(), 1u);
    EXPECT_EQ(probe_packet.stop_sending_frames.front().stream_id, 0u);
    ASSERT_EQ(probe_packet.max_stream_data_frames.size(), 1u);
    EXPECT_EQ(probe_packet.max_stream_data_frames.front().stream_id, 0u);
    ASSERT_EQ(probe_packet.stream_data_blocked_frames.size(), 1u);
    EXPECT_EQ(probe_packet.stream_data_blocked_frames.front().stream_id, 0u);
    EXPECT_FALSE(probe_packet.max_data_frame.has_value());
    EXPECT_FALSE(probe_packet.data_blocked_frame.has_value());
    EXPECT_FALSE(probe_packet.has_handshake_done);
}

TEST(QuicCoreTest, SelectPtoProbeKeepsMatchingConnectionBlockedFrames) {
    auto connection = make_connected_client_connection();
    connection.connection_flow_control_.pending_max_data_frame =
        coquic::quic::MaxDataFrame{.maximum_data = 99};
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::pending;
    connection.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 77};
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;

    coquic::quic::PacketSpaceState packet_space;
    packet_space.sent_packets.emplace(
        7, coquic::quic::SentPacketRecord{
               .packet_number = 7,
               .ack_eliciting = true,
               .in_flight = true,
               .max_data_frame = connection.connection_flow_control_.pending_max_data_frame,
               .data_blocked_frame = connection.connection_flow_control_.pending_data_blocked_frame,
           });

    const auto probe = connection.select_pto_probe(packet_space);

    ASSERT_TRUE(probe.has_value());
    const auto &probe_packet = optional_ref_or_terminate(probe);
    ASSERT_TRUE(probe_packet.max_data_frame.has_value());
    const auto &max_data_frame = optional_ref_or_terminate(probe_packet.max_data_frame);
    EXPECT_EQ(max_data_frame.maximum_data, 99u);
    ASSERT_TRUE(probe_packet.data_blocked_frame.has_value());
    const auto &data_blocked_frame = optional_ref_or_terminate(probe_packet.data_blocked_frame);
    EXPECT_EQ(data_blocked_frame.maximum_data, 77u);
}

TEST(QuicCoreTest, SelectPtoProbeKeepsFinOnlyFragmentThatMatchesFinalSize) {
    auto connection = make_connected_client_connection();

    auto &reset_stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    reset_stream.reset_state = coquic::quic::StreamControlFrameState::pending;

    auto &fin_stream =
        connection.streams_
            .emplace(4, coquic::quic::make_implicit_stream_state(4, connection.config_.role))
            .first->second;
    fin_stream.send_fin_state = coquic::quic::StreamSendFinState::pending;
    fin_stream.send_final_size = 5;

    coquic::quic::PacketSpaceState packet_space;
    packet_space.sent_packets.emplace(
        1, coquic::quic::SentPacketRecord{
               .packet_number = 1,
               .ack_eliciting = true,
               .in_flight = true,
               .stream_fragments =
                   {
                       coquic::quic::StreamFrameSendFragment{
                           .stream_id = 0,
                           .offset = 0,
                           .bytes = coquic::quic::test::bytes_from_string("drop"),
                           .fin = false,
                           .consumes_flow_control = false,
                       },
                       coquic::quic::StreamFrameSendFragment{
                           .stream_id = 4,
                           .offset = 0,
                           .bytes = coquic::quic::test::bytes_from_string("hello"),
                           .fin = true,
                           .consumes_flow_control = false,
                       },
                   },
           });

    const auto probe = connection.select_pto_probe(packet_space);

    ASSERT_TRUE(probe.has_value());
    const auto &probe_packet = optional_ref_or_terminate(probe);
    ASSERT_EQ(probe_packet.stream_fragments.size(), 1u);
    EXPECT_EQ(probe_packet.stream_fragments.front().stream_id, 4u);
    EXPECT_EQ(probe_packet.stream_fragments.front().bytes,
              coquic::quic::test::bytes_from_string("hello"));
    EXPECT_TRUE(probe_packet.stream_fragments.front().fin);
}

TEST(QuicCoreTest, OnTimeoutForcesInitialAndHandshakeAckWhenDeadlinesExpire) {
    auto connection = make_connected_client_connection();
    connection.initial_space_.pending_ack_deadline = coquic::quic::test::test_time(0);
    connection.handshake_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

    connection.on_timeout(coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.initial_space_.force_ack_send);
    EXPECT_TRUE(connection.handshake_space_.force_ack_send);
}

TEST(QuicCoreTest, SharedRecoveryRttStateFallsBackAcrossPacketSpacesAndSynchronizes) {
    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(5);

        const auto &shared = connection.shared_recovery_rtt_state();

        EXPECT_EQ(&shared, &connection.initial_space_.recovery.rtt_state());
        connection.synchronize_recovery_rtt_state();
        EXPECT_EQ(connection.recovery_rtt_state_.latest_rtt, std::chrono::milliseconds(5));
    }

    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.handshake_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(7);

        const auto &shared = connection.shared_recovery_rtt_state();

        EXPECT_EQ(&shared, &connection.handshake_space_.recovery.rtt_state());
        connection.synchronize_recovery_rtt_state();
        EXPECT_EQ(connection.recovery_rtt_state_.latest_rtt, std::chrono::milliseconds(7));
    }

    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.application_space_.recovery.rtt_state().latest_rtt =
            std::chrono::milliseconds(9);

        connection.synchronize_recovery_rtt_state();

        EXPECT_EQ(connection.recovery_rtt_state_.latest_rtt, std::chrono::milliseconds(9));
        EXPECT_EQ(connection.initial_space_.recovery.rtt_state().latest_rtt,
                  std::chrono::milliseconds(9));
        EXPECT_EQ(connection.handshake_space_.recovery.rtt_state().latest_rtt,
                  std::chrono::milliseconds(9));
    }
}

TEST(QuicCoreTest, MarkLostPacketRequeuesHandshakeDoneWhenItWasNotYetAcknowledged) {
    auto connection = make_connected_server_connection();
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::sent;

    const auto packet = coquic::quic::SentPacketRecord{
        .packet_number = 3,
        .has_handshake_done = true,
    };
    connection.application_space_.sent_packets.emplace(packet.packet_number, packet);

    connection.mark_lost_packet(connection.application_space_, packet);

    EXPECT_EQ(connection.handshake_done_state_, coquic::quic::StreamControlFrameState::pending);
}

TEST(QuicCoreTest, ApplicationProbeWithoutCurrentSendPathStillSendsProbePayload) {
    auto connection = make_connected_client_connection();
    connection.current_send_path_id_.reset();
    connection.last_validated_path_id_.reset();
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 18,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_path_challenge = false;
    bool saw_path_response = false;
    for (const auto &frame : application->frames) {
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
        saw_path_response =
            saw_path_response || std::holds_alternative<coquic::quic::PathResponseFrame>(frame);
    }

    EXPECT_FALSE(saw_path_challenge);
    EXPECT_FALSE(saw_path_response);
}

TEST(QuicCoreTest, ApplicationProbePacketCanSendHandshakeDoneAndAdvanceState) {
    auto connection = make_connected_server_connection();
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 88,
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
    for (const auto &frame : application->frames) {
        saw_handshake_done =
            saw_handshake_done || std::holds_alternative<coquic::quic::HandshakeDoneFrame>(frame);
    }

    EXPECT_TRUE(saw_handshake_done);
    EXPECT_EQ(connection.handshake_done_state_, coquic::quic::StreamControlFrameState::sent);
}

} // namespace
