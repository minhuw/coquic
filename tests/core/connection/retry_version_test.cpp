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

TEST(QuicCoreTest, ApplicationProbePathFailsWhenRetryWithoutAckCannotSerialize) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/28, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 29,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1, std::byte{0x5a}),
                    .fin = false,
                },
            },
    };
    for (std::uint64_t stream_index = 1; stream_index <= 256; ++stream_index) {
        connection.application_space_.pending_probe_packet->reset_stream_frames.push_back(
            coquic::quic::ResetStreamFrame{
                .stream_id = stream_index * 4,
                .application_protocol_error_code = 1,
                .final_size = 0,
            });
    }
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 5);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.application_space_.sent_packets.empty());
}

TEST(QuicCoreTest, ApplicationSendFailsWhenRetryWithoutAckCannotSerialize) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/31, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
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
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 5);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.application_space_.sent_packets.empty());
}

TEST(QuicCoreTest, ApplicationSendReturnsEmptyWhenRetryWithoutAckTrimsAwayAllStreamData) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 6;
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/31, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.queue_stream_send(0, std::vector<std::byte>(128, std::byte{0x54}), false)
                    .has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ClientRestartsHandshakeAfterValidVersionNegotiation) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = 0x00000001u;
    client_config.initial_version = 0x00000001u;
    client_config.supported_versions = {0x6b3343cfu, 0x00000001u};
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(start).empty());

    const auto version_negotiation =
        coquic::quic::serialize_packet(coquic::quic::VersionNegotiationPacket{
            .destination_connection_id = {std::byte{0xc1}, std::byte{0x01}},
            .source_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                     std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                     std::byte{0x57}, std::byte{0x08}},
            .supported_versions = {0x6b3343cfu},
        });
    ASSERT_TRUE(version_negotiation.has_value());

    const auto after_version_negotiation =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = version_negotiation.value()},
                       coquic::quic::test::test_time(1));
    const auto restart_datagrams =
        coquic::quic::test::send_datagrams_from(after_version_negotiation);
    ASSERT_FALSE(restart_datagrams.empty());
    EXPECT_EQ(read_u32_be_at(restart_datagrams.front(), 1), 0x6b3343cfu);
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresVersionNegotiationThatEchoesOriginalVersion) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = 0x00000001u;
    client_config.initial_version = 0x00000001u;
    client_config.supported_versions = {0x6b3343cfu, 0x00000001u};
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(start).empty());

    const auto version_negotiation =
        coquic::quic::serialize_packet(coquic::quic::VersionNegotiationPacket{
            .destination_connection_id = {std::byte{0xc1}, std::byte{0x01}},
            .source_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                     std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                     std::byte{0x57}, std::byte{0x08}},
            .supported_versions = {0x00000001u, 0x6b3343cfu},
        });
    ASSERT_TRUE(version_negotiation.has_value());

    const auto after_version_negotiation =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = version_negotiation.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_version_negotiation).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresMalformedVersionNegotiationDatagram) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = 0x00000001u;
    client_config.initial_version = 0x00000001u;
    client_config.supported_versions = {0x6b3343cfu, 0x00000001u};
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(start).empty());

    const auto malformed_version_negotiation =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x00, 0x01});
    const auto after_malformed = client.advance(
        coquic::quic::QuicCoreInboundDatagram{.bytes = malformed_version_negotiation},
        coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_malformed).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresVersionNegotiationWithUnexpectedDestinationConnectionId) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = 0x00000001u;
    client_config.initial_version = 0x00000001u;
    client_config.supported_versions = {0x6b3343cfu, 0x00000001u};
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(start).empty());

    const auto version_negotiation =
        coquic::quic::serialize_packet(coquic::quic::VersionNegotiationPacket{
            .destination_connection_id = {std::byte{0x99}, std::byte{0x98}},
            .source_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                     std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                     std::byte{0x57}, std::byte{0x08}},
            .supported_versions = {0x6b3343cfu},
        });
    ASSERT_TRUE(version_negotiation.has_value());

    const auto after_version_negotiation =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = version_negotiation.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_version_negotiation).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresVersionNegotiationWithUnexpectedSourceConnectionId) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = 0x00000001u;
    client_config.initial_version = 0x00000001u;
    client_config.supported_versions = {0x6b3343cfu, 0x00000001u};
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(start).empty());

    const auto version_negotiation =
        coquic::quic::serialize_packet(coquic::quic::VersionNegotiationPacket{
            .destination_connection_id = {std::byte{0xc1}, std::byte{0x01}},
            .source_connection_id = {std::byte{0x91}, std::byte{0x92}, std::byte{0x93},
                                     std::byte{0x94}},
            .supported_versions = {0x6b3343cfu},
        });
    ASSERT_TRUE(version_negotiation.has_value());

    const auto after_version_negotiation =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = version_negotiation.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_version_negotiation).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientRestartsHandshakeAfterVersionNegotiationSkipsUnsupportedVersion) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = 0x00000001u;
    client_config.initial_version = 0x00000001u;
    client_config.supported_versions = {0xa1b2c3d4u, 0x6b3343cfu, 0x00000001u};
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(start).empty());

    const auto version_negotiation =
        coquic::quic::serialize_packet(coquic::quic::VersionNegotiationPacket{
            .destination_connection_id = {std::byte{0xc1}, std::byte{0x01}},
            .source_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                     std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                     std::byte{0x57}, std::byte{0x08}},
            .supported_versions = {0x6b3343cfu},
        });
    ASSERT_TRUE(version_negotiation.has_value());

    const auto after_version_negotiation =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = version_negotiation.value()},
                       coquic::quic::test::test_time(1));
    const auto restart_datagrams =
        coquic::quic::test::send_datagrams_from(after_version_negotiation);
    ASSERT_FALSE(restart_datagrams.empty());
    EXPECT_EQ(read_u32_be_at(restart_datagrams.front(), 1), 0x6b3343cfu);
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresVersionNegotiationWithoutVersionOverlap) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = 0x00000001u;
    client_config.initial_version = 0x00000001u;
    client_config.supported_versions = {0xa1b2c3d4u, 0x00000001u};
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(start).empty());

    const auto version_negotiation =
        coquic::quic::serialize_packet(coquic::quic::VersionNegotiationPacket{
            .destination_connection_id = {std::byte{0xc1}, std::byte{0x01}},
            .source_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                     std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                     std::byte{0x57}, std::byte{0x08}},
            .supported_versions = {0x6b3343cfu},
        });
    ASSERT_TRUE(version_negotiation.has_value());

    const auto after_version_negotiation =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = version_negotiation.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_version_negotiation).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientRestartsHandshakeAfterValidRetry) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});
    const auto next_initial_send_packet_number =
        client.connection_->initial_space_.next_send_packet_number;
    ASSERT_GT(next_initial_send_packet_number, 0u);

    const auto retry_source_connection_id = bytes_from_ints({0x55, 0x66, 0x77, 0x88});
    const auto retry_token = bytes_from_ints({0xaa, 0xbb, 0xcc});
    const auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, retry_source_connection_id, retry_token,
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    const auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    const auto restarted_datagrams = coquic::quic::test::send_datagrams_from(after_retry);
    ASSERT_FALSE(restarted_datagrams.empty());

    const auto restarted_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(restarted_datagrams.front());
    ASSERT_TRUE(restarted_destination_connection_id.has_value());
    const auto restarted_destination_connection_id_value =
        restarted_destination_connection_id.value_or(coquic::quic::ConnectionId{});
    EXPECT_EQ(restarted_destination_connection_id_value, retry_source_connection_id);
    const auto restarted_initial_token =
        coquic::quic::test::client_initial_datagram_token(restarted_datagrams.front());
    ASSERT_TRUE(restarted_initial_token.has_value());
    const auto restarted_initial_token_value =
        restarted_initial_token.value_or(std::vector<std::byte>{});
    EXPECT_EQ(restarted_initial_token_value, retry_token);
    EXPECT_TRUE(
        client.connection_->initial_space_.sent_packets.contains(next_initial_send_packet_number));
    EXPECT_EQ(client.connection_->initial_space_.next_send_packet_number,
              next_initial_send_packet_number + 1);
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryWithInvalidIntegrityTag) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    const auto retry_source_connection_id = bytes_from_ints({0x44, 0x33, 0x22, 0x11});
    const auto retry_token = bytes_from_ints({0xda, 0x7a});
    const auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, retry_source_connection_id, retry_token,
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    auto retry_with_invalid_tag = retry_datagram.value();
    ASSERT_FALSE(retry_with_invalid_tag.empty());
    retry_with_invalid_tag.back() = retry_with_invalid_tag.back() ^ std::byte{0x01};

    const auto after_invalid_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_with_invalid_tag},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_invalid_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryWithEmptyToken) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    const auto retry_source_connection_id = bytes_from_ints({0x41, 0x42, 0x43, 0x44});
    const auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, retry_source_connection_id, {},
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    const auto after_empty_token_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_empty_token_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresSecondRetry) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    const auto first_retry_source_connection_id = bytes_from_ints({0x51, 0x52, 0x53, 0x54});
    const auto first_retry_token = bytes_from_ints({0xa1, 0xa2, 0xa3});
    const auto first_retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, first_retry_source_connection_id, first_retry_token,
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(first_retry_datagram.has_value());

    const auto after_first_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = first_retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(after_first_retry).empty());

    const auto second_retry_source_connection_id = bytes_from_ints({0x61, 0x62, 0x63, 0x64});
    const auto second_retry_token = bytes_from_ints({0xb1, 0xb2, 0xb3});
    const auto second_retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, second_retry_source_connection_id, second_retry_token,
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(second_retry_datagram.has_value());

    const auto after_second_retry = client.advance(
        coquic::quic::QuicCoreInboundDatagram{.bytes = second_retry_datagram.value()},
        coquic::quic::test::test_time(2));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_second_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryAfterProcessingServerInitial) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    auto server_config = coquic::quic::test::make_server_core_config();
    coquic::quic::QuicCore server(std::move(server_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    const auto server_first_flight = coquic::quic::test::relay_send_datagrams_to_peer(
        start, server, coquic::quic::test::test_time(1));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(server_first_flight).empty());

    const auto client_after_server_initial = coquic::quic::test::relay_send_datagrams_to_peer(
        server_first_flight, client, coquic::quic::test::test_time(2));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(client_after_server_initial).empty());

    const auto retry_source_connection_id = bytes_from_ints({0x71, 0x72, 0x73, 0x74});
    const auto retry_token = bytes_from_ints({0xc1, 0xc2, 0xc3});
    const auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, retry_source_connection_id, retry_token,
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    const auto after_late_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(3));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_late_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryAfterProcessingPeerPacketBeforeHandshakeCompletion) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    const auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, bytes_from_ints({0x55, 0x66, 0x77, 0x88}),
        bytes_from_ints({0xaa, 0xbb}), original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    ASSERT_NE(client.connection_, nullptr);
    client.connection_->processed_peer_packet_ = true;
    ASSERT_FALSE(client.is_handshake_complete());

    const auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryWithUnexpectedDestinationConnectionId) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    const auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        bytes_from_ints({0x31, 0x32, 0x33, 0x34}), bytes_from_ints({0x55, 0x66, 0x77, 0x88}),
        bytes_from_ints({0xaa, 0xbb}), original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    const auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryOnDifferentVersion) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    const auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, bytes_from_ints({0x55, 0x66, 0x77, 0x88}),
        bytes_from_ints({0xaa, 0xbb}), original_destination_connection_id_value,
        coquic::quic::kQuicVersion2);
    ASSERT_TRUE(retry_datagram.has_value());

    const auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryWhenIntegrityValidationCannotRun) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());

    const auto retry_datagram = coquic::quic::serialize_packet(coquic::quic::RetryPacket{
        .version = 0xf1f2f3f4u,
        .retry_unused_bits = 0,
        .destination_connection_id = client_source_connection_id,
        .source_connection_id = bytes_from_ints({0x55, 0x66, 0x77, 0x88}),
        .retry_token = bytes_from_ints({0xaa, 0xbb}),
        .retry_integrity_tag = {},
    });
    ASSERT_TRUE(retry_datagram.has_value());

    const auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryDatagramWithTrailingBytes) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, bytes_from_ints({0x55, 0x66, 0x77, 0x88}),
        bytes_from_ints({0xaa, 0xbb}), original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());
    retry_datagram.value().push_back(std::byte{0x00});

    const auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientFailsOnNonRetryLongHeaderDatagramAfterRetryParserRejectsIt) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto server_source_connection_id = client_config.initial_destination_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(start).empty());

    const auto initial_datagram = coquic::quic::serialize_packet(coquic::quic::InitialPacket{
        .version = original_version,
        .destination_connection_id = client_source_connection_id,
        .source_connection_id = server_source_connection_id,
        .token = {},
        .packet_number_length = 1,
        .truncated_packet_number = 0,
        .frames = {coquic::quic::PingFrame{}},
    });
    ASSERT_TRUE(initial_datagram.has_value());

    const auto after_initial =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = initial_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_initial).empty());
    EXPECT_TRUE(client.has_failed());
}

TEST(QuicCoreTest, ClientFailsOnNonRetryLongHeaderDatagramWithTrailingBytes) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto server_source_connection_id = client_config.initial_destination_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(start).empty());

    auto initial_datagram = coquic::quic::serialize_packet(coquic::quic::InitialPacket{
        .version = original_version,
        .destination_connection_id = client_source_connection_id,
        .source_connection_id = server_source_connection_id,
        .token = {},
        .packet_number_length = 1,
        .truncated_packet_number = 0,
        .frames = {coquic::quic::PingFrame{}},
    });
    ASSERT_TRUE(initial_datagram.has_value());
    initial_datagram.value().push_back(std::byte{0x00});

    const auto after_initial =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = initial_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_initial).empty());
    EXPECT_TRUE(client.has_failed());
}

TEST(QuicCoreTest,
     CompatibleNegotiationServerDefersNegotiatedVersionCryptoUntilPeerTransportParametersValidate) {
    auto config = coquic::quic::test::make_server_core_config();
    config.original_version = coquic::quic::kQuicVersion1;
    config.initial_version = coquic::quic::kQuicVersion1;
    config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};

    coquic::quic::QuicConnection connection(std::move(config));
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.original_version_ = coquic::quic::kQuicVersion1;
    connection.current_version_ = coquic::quic::kQuicVersion2;
    connection.client_initial_destination_connection_id_ = bytes_from_hex("8394c8f03e515708");
    connection.peer_source_connection_id_ = bytes_from_hex("c101");
    connection.initial_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("serverhello"));
    connection.handshake_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("encryptedextensions"));
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x61});
    connection.initial_space_.received_packets.record_received(
        /*packet_number=*/0, /*ack_eliciting=*/true, coquic::quic::test::test_time(1));
    connection.anti_amplification_received_bytes_ = 1200;

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets.front());
    ASSERT_NE(initial, nullptr);
    EXPECT_EQ(initial->version, coquic::quic::kQuicVersion1);
    EXPECT_TRUE(std::ranges::none_of(initial->frames, [](const auto &frame) {
        return std::holds_alternative<coquic::quic::CryptoFrame>(frame);
    }));

    EXPECT_TRUE(connection.initial_space_.send_crypto.has_pending_data());
    EXPECT_TRUE(connection.handshake_space_.send_crypto.has_pending_data());
}

TEST(QuicCoreTest,
     CompatibleNegotiationServerCanSendHandshakeAckWhileDeferringNegotiatedVersionCrypto) {
    auto config = coquic::quic::test::make_server_core_config();
    config.original_version = coquic::quic::kQuicVersion1;
    config.initial_version = coquic::quic::kQuicVersion1;
    config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};

    coquic::quic::QuicConnection connection(std::move(config));
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.original_version_ = coquic::quic::kQuicVersion1;
    connection.current_version_ = coquic::quic::kQuicVersion2;
    connection.client_initial_destination_connection_id_ = bytes_from_hex("8394c8f03e515708");
    connection.peer_source_connection_id_ = bytes_from_hex("c101");
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x61});
    connection.handshake_space_.received_packets.record_received(
        /*packet_number=*/0, /*ack_eliciting=*/true, coquic::quic::test::test_time(1));
    connection.anti_amplification_received_bytes_ = 1200;

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front());
    ASSERT_NE(handshake, nullptr);
    EXPECT_TRUE(std::ranges::any_of(handshake->frames, [](const auto &frame) {
        return std::holds_alternative<coquic::quic::AckFrame>(frame);
    }));
    EXPECT_TRUE(std::ranges::none_of(handshake->frames, [](const auto &frame) {
        return std::holds_alternative<coquic::quic::CryptoFrame>(frame);
    }));
    EXPECT_FALSE(connection.handshake_space_.send_crypto.has_pending_data());
    EXPECT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, CompatibleNegotiationUpgradesV1HandshakeToV2) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.source_connection_id = bytes_from_hex("c100000000000001");
    client_config.initial_destination_connection_id = bytes_from_hex("8300000000000000");
    client_config.original_version = coquic::quic::kQuicVersion1;
    client_config.initial_version = coquic::quic::kQuicVersion1;
    client_config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};
    coquic::quic::QuicCore client(std::move(client_config));

    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.source_connection_id = bytes_from_hex("5300000000000001");
    server_config.original_version = coquic::quic::kQuicVersion1;
    server_config.initial_version = coquic::quic::kQuicVersion1;
    server_config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};
    coquic::quic::QuicCore server(std::move(server_config));

    const auto assert_long_header_version = [](const coquic::quic::QuicConnection &connection,
                                               std::span<const std::vector<std::byte>> datagrams,
                                               std::uint32_t expected_version) {
        bool saw_long_header = false;
        for (const auto &datagram : datagrams) {
            for (const auto &packet : decode_sender_datagram(connection, datagram)) {
                if (const auto *initial =
                        std::get_if<coquic::quic::ProtectedInitialPacket>(&packet)) {
                    saw_long_header = true;
                    EXPECT_EQ(initial->version, expected_version);
                    continue;
                }
                if (const auto *handshake =
                        std::get_if<coquic::quic::ProtectedHandshakePacket>(&packet)) {
                    saw_long_header = true;
                    EXPECT_EQ(handshake->version, expected_version);
                }
            }
        }
        EXPECT_TRUE(saw_long_header);
    };

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto client_start_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(client_start_datagrams.empty());
    EXPECT_EQ(read_u32_be_at(client_start_datagrams.front(), 1), coquic::quic::kQuicVersion1);

    const auto server_first_flight = coquic::quic::test::relay_send_datagrams_to_peer(
        start, server, coquic::quic::test::test_time(1));
    const auto server_first_flight_datagrams =
        coquic::quic::test::send_datagrams_from(server_first_flight);
    ASSERT_FALSE(server_first_flight_datagrams.empty());
    ASSERT_NE(server.connection_, nullptr);
    EXPECT_EQ(server.connection_->original_version_, coquic::quic::kQuicVersion1);
    EXPECT_EQ(server.connection_->current_version_, coquic::quic::kQuicVersion2);
    assert_long_header_version(*server.connection_, server_first_flight_datagrams,
                               coquic::quic::kQuicVersion2);

    const auto client_handshake = coquic::quic::test::relay_send_datagrams_to_peer(
        server_first_flight, client, coquic::quic::test::test_time(2));
    ASSERT_NE(client.connection_, nullptr);
    EXPECT_EQ(client.connection_->current_version_, coquic::quic::kQuicVersion2);
    const auto client_handshake_datagrams =
        coquic::quic::test::send_datagrams_from(client_handshake);
    ASSERT_FALSE(client_handshake_datagrams.empty());
    assert_long_header_version(*client.connection_, client_handshake_datagrams,
                               coquic::quic::kQuicVersion2);

    coquic::quic::test::drive_quic_handshake_from_results(client, server, client_handshake, {},
                                                          coquic::quic::test::test_time(2));

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
    EXPECT_FALSE(client.has_failed());
    EXPECT_FALSE(server.has_failed());
}

TEST(QuicCoreTest,
     ClientStartupPreservesPreseededAntiAmplificationBudgetWithoutRetrySourceConnectionId) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.anti_amplification_received_bytes_ = 77;

    connection.start_client_if_needed();

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.anti_amplification_received_bytes_, 77u);
}

TEST(QuicCoreTest, ConnectionConstructorSeedsSupportedVersionsWhenUnset) {
    auto config = coquic::quic::test::make_client_core_config();
    const auto initial_version = config.initial_version;
    config.supported_versions.clear();

    coquic::quic::QuicConnection connection(std::move(config));

    EXPECT_EQ(connection.config_.supported_versions, std::vector<std::uint32_t>{initial_version});
}

TEST(QuicCoreTest, ServerCreatedFromRetriedInitialExportsRetryTransportParameters) {
    auto server_config = coquic::quic::test::make_server_core_config();
    const auto retry_source_connection_id = bytes_from_hex("5300000000000001");
    const auto original_destination_connection_id = bytes_from_hex("8394c8f03e515708");
    server_config.initial_destination_connection_id = retry_source_connection_id;
    server_config.original_destination_connection_id = original_destination_connection_id;
    server_config.retry_source_connection_id = retry_source_connection_id;

    coquic::quic::QuicConnection server(std::move(server_config));
    server.start_server_if_needed(retry_source_connection_id, coquic::quic::kQuicVersion1);

    EXPECT_FALSE(server.has_failed());
    ASSERT_TRUE(server.local_transport_parameters_.original_destination_connection_id.has_value());
    ASSERT_TRUE(server.local_transport_parameters_.retry_source_connection_id.has_value());
    const auto exported_original_destination_connection_id =
        server.local_transport_parameters_.original_destination_connection_id.value_or(
            coquic::quic::ConnectionId{});
    const auto exported_retry_source_connection_id =
        server.local_transport_parameters_.retry_source_connection_id.value_or(
            coquic::quic::ConnectionId{});
    EXPECT_EQ(exported_original_destination_connection_id, original_destination_connection_id);
    EXPECT_EQ(exported_retry_source_connection_id, retry_source_connection_id);
}

TEST(QuicCoreTest, CompatibleNegotiationServerFirstFlightEmitsV2InitialCrypto) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = coquic::quic::kQuicVersion1;
    client_config.initial_version = coquic::quic::kQuicVersion1;
    client_config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};
    coquic::quic::QuicCore client(std::move(client_config));

    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.original_version = coquic::quic::kQuicVersion1;
    server_config.initial_version = coquic::quic::kQuicVersion1;
    server_config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};
    coquic::quic::QuicCore server(std::move(server_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto server_first_flight = coquic::quic::test::relay_send_datagrams_to_peer(
        start, server, coquic::quic::test::test_time(1));
    const auto server_first_flight_datagrams =
        coquic::quic::test::send_datagrams_from(server_first_flight);
    ASSERT_NE(server.connection_, nullptr);
    ASSERT_FALSE(server_first_flight_datagrams.empty());

    const auto packets =
        decode_sender_datagram(*server.connection_, server_first_flight_datagrams.front());
    const auto initial_packet =
        std::find_if(packets.begin(), packets.end(), [](const auto &packet) {
            return std::holds_alternative<coquic::quic::ProtectedInitialPacket>(packet);
        });
    ASSERT_NE(initial_packet, packets.end());

    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&*initial_packet);
    ASSERT_NE(initial, nullptr);
    EXPECT_EQ(initial->version, coquic::quic::kQuicVersion2);
    EXPECT_TRUE(std::ranges::any_of(initial->frames, [](const auto &frame) {
        return std::holds_alternative<coquic::quic::CryptoFrame>(frame);
    }));
    ASSERT_FALSE(initial->frames.empty());
    EXPECT_TRUE(std::holds_alternative<coquic::quic::CryptoFrame>(initial->frames.front()));
    EXPECT_FALSE(std::ranges::any_of(initial->frames, [](const auto &frame) {
        return std::holds_alternative<coquic::quic::AckFrame>(frame);
    }));
}

TEST(QuicCoreTest, CompatibleNegotiationServerFirstFlightDuplicatesV2InitialCrypto) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = coquic::quic::kQuicVersion1;
    client_config.initial_version = coquic::quic::kQuicVersion1;
    client_config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};
    coquic::quic::QuicCore client(std::move(client_config));

    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.original_version = coquic::quic::kQuicVersion1;
    server_config.initial_version = coquic::quic::kQuicVersion1;
    server_config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};
    coquic::quic::QuicCore server(std::move(server_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto server_first_flight = coquic::quic::test::relay_send_datagrams_to_peer(
        start, server, coquic::quic::test::test_time(1));
    const auto server_first_flight_datagrams =
        coquic::quic::test::send_datagrams_from(server_first_flight);
    ASSERT_NE(server.connection_, nullptr);
    ASSERT_FALSE(server_first_flight_datagrams.empty());

    const auto packets =
        decode_sender_datagram(*server.connection_, server_first_flight_datagrams.front());
    std::vector<const coquic::quic::ProtectedInitialPacket *> initial_packets;
    for (const auto &packet : packets) {
        if (const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packet)) {
            initial_packets.push_back(initial);
        }
    }

    ASSERT_GE(initial_packets.size(), 2u);

    const auto first_crypto =
        std::get_if<coquic::quic::CryptoFrame>(&initial_packets[0]->frames.front());
    const auto second_crypto =
        std::get_if<coquic::quic::CryptoFrame>(&initial_packets[1]->frames.front());
    ASSERT_NE(first_crypto, nullptr);
    ASSERT_NE(second_crypto, nullptr);

    EXPECT_EQ(initial_packets[0]->version, coquic::quic::kQuicVersion2);
    EXPECT_EQ(initial_packets[1]->version, coquic::quic::kQuicVersion2);
    EXPECT_EQ(first_crypto->offset, second_crypto->offset);
    EXPECT_EQ(first_crypto->crypto_data, second_crypto->crypto_data);
}

TEST(QuicCoreTest, CompatibleNegotiationDuplicateInitialSerializationFailureMarksConnectionFailed) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.original_version_ = coquic::quic::kQuicVersion1;
    connection.current_version_ = coquic::quic::kQuicVersion2;
    connection.client_initial_destination_connection_id_ = bytes_from_hex("8394c8f03e515708");
    connection.peer_source_connection_id_ = bytes_from_hex("c101");
    connection.peer_transport_parameters_validated_ = true;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 1200;
    connection.initial_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("serverhello"));
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(
    QuicCoreTest,
    CompatibleNegotiationDuplicateInitialSerializationFailureAfterPrimarySendMarksConnectionFailed) {
    bool found_duplicate_serialization_failure = false;

    for (std::size_t occurrence = 1; occurrence <= 64 && !found_duplicate_serialization_failure;
         ++occurrence) {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.original_version_ = coquic::quic::kQuicVersion1;
        connection.current_version_ = coquic::quic::kQuicVersion2;
        connection.client_initial_destination_connection_id_ = bytes_from_hex("8394c8f03e515708");
        connection.peer_source_connection_id_ = bytes_from_hex("c101");
        connection.peer_transport_parameters_validated_ = true;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 1200;
        connection.initial_space_.send_crypto.append(
            coquic::quic::test::bytes_from_string("serverhello"));

        const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
            coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, occurrence);

        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

        if (!connection.has_failed() || connection.initial_space_.sent_packets.size() != 1u) {
            continue;
        }

        found_duplicate_serialization_failure = true;
        EXPECT_TRUE(datagram.empty());
        EXPECT_EQ(connection.initial_space_.next_send_packet_number, 1u);
        EXPECT_EQ(connection.initial_space_.sent_packets.begin()->second.packet_number, 0u);
    }

    EXPECT_TRUE(found_duplicate_serialization_failure);
}

TEST(QuicCoreTest,
     CompatibleNegotiationSkipsDuplicateInitialWhenCombinedDatagramWouldExceedBudget) {
    bool skipped_duplicate_initial = false;

    for (std::size_t crypto_size = 256; crypto_size <= 1400 && !skipped_duplicate_initial;
         crypto_size += 16) {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.original_version_ = coquic::quic::kQuicVersion1;
        connection.current_version_ = coquic::quic::kQuicVersion2;
        connection.client_initial_destination_connection_id_ = bytes_from_hex("8394c8f03e515708");
        connection.peer_source_connection_id_ = bytes_from_hex("c101");
        connection.peer_transport_parameters_validated_ = true;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 1200;
        connection.initial_space_.send_crypto.append(
            std::vector<std::byte>(crypto_size, std::byte{0x6a}));

        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty() || connection.has_failed()) {
            continue;
        }

        const auto packets = decode_sender_datagram(connection, datagram);
        const auto initial_count =
            std::count_if(packets.begin(), packets.end(), [](const auto &packet) {
                return std::holds_alternative<coquic::quic::ProtectedInitialPacket>(packet);
            });
        if (initial_count != 1u || connection.initial_space_.sent_packets.size() != 1u) {
            continue;
        }

        skipped_duplicate_initial = true;
        EXPECT_EQ(connection.initial_space_.next_send_packet_number, 1u);
    }

    EXPECT_TRUE(skipped_duplicate_initial);
}

TEST(QuicCoreTest, ClientProcessInboundPacketAdoptsSupportedVersionFromInitialAndHandshake) {
    coquic::quic::QuicConnection client(coquic::quic::test::make_client_core_config());
    client.started_ = true;
    client.status_ = coquic::quic::HandshakeStatus::in_progress;

    const auto initial_result = client.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .version = coquic::quic::kQuicVersion2,
            .destination_connection_id = client.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x01, 0x02}),
            .packet_number_length = 2,
            .packet_number = 1,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(initial_result.has_value());
    EXPECT_EQ(client.current_version_, coquic::quic::kQuicVersion2);

    client.current_version_ = coquic::quic::kQuicVersion1;
    const auto handshake_result = client.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .version = coquic::quic::kQuicVersion2,
            .destination_connection_id = client.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x01, 0x02}),
            .packet_number_length = 2,
            .packet_number = 2,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(2));
    ASSERT_TRUE(handshake_result.has_value());
    EXPECT_EQ(client.current_version_, coquic::quic::kQuicVersion2);
}

TEST(QuicCoreTest, ClientRequiresRetrySourceConnectionIdAfterRetry) {
    coquic::quic::QuicConnection client(coquic::quic::test::make_client_core_config());
    const auto original_destination_connection_id = bytes_from_hex("8394c8f03e515708");
    const auto retry_source_connection_id = bytes_from_hex("5300000000000001");
    client.config_.original_destination_connection_id = original_destination_connection_id;
    client.config_.retry_source_connection_id = retry_source_connection_id;
    client.peer_source_connection_id_ = retry_source_connection_id;
    client.current_version_ = coquic::quic::kQuicVersion1;

    const auto context = client.peer_transport_parameters_validation_context();
    ASSERT_TRUE(context.has_value());
    const auto context_value = context.value_or(coquic::quic::TransportParametersValidationContext{
        .expected_initial_source_connection_id = {},
    });
    EXPECT_EQ(context_value.expected_original_destination_connection_id,
              original_destination_connection_id);
    EXPECT_EQ(context_value.expected_retry_source_connection_id, retry_source_connection_id);
}

TEST(QuicCoreTest, ClientRetryOnOriginalVersionDoesNotRequireVersionInformation) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};
    coquic::quic::QuicConnection client(std::move(client_config));
    const auto original_destination_connection_id = bytes_from_hex("8394c8f03e515708");
    const auto retry_source_connection_id = bytes_from_hex("5300000000000001");
    client.config_.original_destination_connection_id = original_destination_connection_id;
    client.config_.retry_source_connection_id = retry_source_connection_id;
    client.peer_source_connection_id_ = retry_source_connection_id;
    client.original_version_ = coquic::quic::kQuicVersion1;
    client.current_version_ = coquic::quic::kQuicVersion1;

    const auto context = client.peer_transport_parameters_validation_context();
    ASSERT_TRUE(context.has_value());
    const auto &context_value = optional_ref_or_terminate(context);
    EXPECT_FALSE(context_value.expected_version_information.has_value());

    const auto validation = coquic::quic::validate_peer_transport_parameters(
        coquic::quic::EndpointRole::server,
        coquic::quic::TransportParameters{
            .original_destination_connection_id = original_destination_connection_id,
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = retry_source_connection_id,
            .retry_source_connection_id = retry_source_connection_id,
        },
        context_value);
    EXPECT_TRUE(validation.has_value());
}

TEST(QuicCoreTest, ProcessInboundDatagramDiscardsPacketWhenPreviousReadSecretRetryStillFails) {
    auto connection = make_connected_client_connection();
    connection.previous_application_read_secret_ = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.previous_application_read_key_phase_ = connection.application_read_key_phase_;
    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x61});

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = connection.application_read_key_phase_,
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
            .one_rtt_secret = unrelated_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

} // namespace
