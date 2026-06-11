#include <array>

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <type_traits>

#include "src/quic/crypto/packet_crypto_test_hooks.h"
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

struct CryptoFrameSnapshot {
    std::uint64_t offset = 0;
    std::vector<std::byte> crypto_data;
};

struct ZeroRttStreamSnapshot {
    std::uint64_t packet_number = 0;
    std::uint64_t stream_id = 0;
    std::uint64_t offset = 0;
    std::vector<std::byte> stream_data;
    bool fin = false;
};

std::vector<CryptoFrameSnapshot>
initial_crypto_frame_snapshots(const coquic::quic::QuicConnection &connection,
                               std::span<const std::byte> datagram) {
    std::vector<CryptoFrameSnapshot> snapshots;
    for (const auto &packet : decode_sender_datagram(connection, datagram)) {
        const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packet);
        if (initial == nullptr) {
            continue;
        }
        for (const auto &frame : initial->frames) {
            const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame);
            if (crypto == nullptr) {
                continue;
            }
            snapshots.push_back(CryptoFrameSnapshot{
                .offset = crypto->offset,
                .crypto_data = crypto->crypto_data,
            });
        }
    }
    return snapshots;
}

std::vector<ZeroRttStreamSnapshot>
zero_rtt_stream_snapshots(const coquic::quic::QuicConnection &connection,
                          std::span<const std::byte> datagram) {
    std::vector<ZeroRttStreamSnapshot> snapshots;
    for (const auto &packet : decode_sender_datagram(connection, datagram)) {
        const auto *zero_rtt = std::get_if<coquic::quic::ProtectedZeroRttPacket>(&packet);
        if (zero_rtt == nullptr) {
            continue;
        }
        for (const auto &frame : zero_rtt->frames) {
            const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }
            snapshots.push_back(ZeroRttStreamSnapshot{
                .packet_number = zero_rtt->packet_number,
                .stream_id = stream->stream_id,
                .offset = stream->offset.value_or(0),
                .stream_data =
                    std::vector<std::byte>(stream->stream_data.begin(), stream->stream_data.end()),
                .fin = stream->fin,
            });
        }
    }
    return snapshots;
}

std::vector<ZeroRttStreamSnapshot>
zero_rtt_stream_snapshots(const coquic::quic::QuicConnection &connection,
                          std::span<const std::vector<std::byte>> datagrams) {
    std::vector<ZeroRttStreamSnapshot> snapshots;
    for (const auto &datagram : datagrams) {
        auto datagram_snapshots = zero_rtt_stream_snapshots(connection, datagram);
        snapshots.insert(snapshots.end(), datagram_snapshots.begin(), datagram_snapshots.end());
    }
    return snapshots;
}

bool has_matching_zero_rtt_stream_snapshot(std::span<const ZeroRttStreamSnapshot> snapshots,
                                           const ZeroRttStreamSnapshot &target,
                                           std::uint64_t minimum_packet_number) {
    for (const auto &snapshot : snapshots) {
        if (snapshot.packet_number > minimum_packet_number &&
            snapshot.stream_id == target.stream_id && snapshot.offset == target.offset &&
            snapshot.stream_data == target.stream_data && snapshot.fin == target.fin) {
            return true;
        }
    }
    return false;
}

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
    EXPECT_EQ(tracked_packet_count(connection.application_space_), 0u);
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
    EXPECT_EQ(tracked_packet_count(connection.application_space_), 0u);
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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
    //= https://www.rfc-editor.org/rfc/rfc9000#section-6.2
    // # A client that supports only this version of QUIC MUST abandon the
    // # current connection attempt if it receives a Version Negotiation
    // # packet, with the following two exceptions.
    EXPECT_EQ(read_u32_be_at(restart_datagrams.front(), 1), 0x6b3343cfu);
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresVersionNegotiationThatEchoesOriginalVersion) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = 0x00000001u;
    client_config.initial_version = 0x00000001u;
    client_config.supported_versions = {0x6b3343cfu, 0x00000001u};
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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
    //= https://www.rfc-editor.org/rfc/rfc9000#section-6.2
    // # A client MUST discard a Version Negotiation packet that
    // # lists the QUIC version selected by the client.
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_version_negotiation).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresVersionNegotiationAfterProcessingPeerPacket) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = 0x00000001u;
    client_config.initial_version = 0x00000001u;
    client_config.supported_versions = {0x6b3343cfu, 0x00000001u};
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(start).empty());
    ASSERT_NE(client.connection_, nullptr);
    client.connection_->processed_peer_packet_ = true;
    ASSERT_FALSE(client.is_handshake_complete());

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

    //= https://www.rfc-editor.org/rfc/rfc9000#section-6.2
    // # A client MUST discard any Version Negotiation packet if it has
    // # received and successfully processed any other packet, including an
    // # earlier Version Negotiation packet.
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_version_negotiation).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresMalformedVersionNegotiationDatagram) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = 0x00000001u;
    client_config.initial_version = 0x00000001u;
    client_config.supported_versions = {0x6b3343cfu, 0x00000001u};
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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
    //= https://www.rfc-editor.org/rfc/rfc9000#section-6.2
    // # A client that supports only this version of QUIC MUST abandon the
    // # current connection attempt if it receives a Version Negotiation
    // # packet, with the following two exceptions.
    EXPECT_EQ(read_u32_be_at(restart_datagrams.front(), 1), 0x6b3343cfu);
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresVersionNegotiationWithoutVersionOverlap) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = 0x00000001u;
    client_config.initial_version = 0x00000001u;
    client_config.supported_versions = {0xa1b2c3d4u, 0x00000001u};
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());
    ASSERT_NE(client.connection_, nullptr);
    const auto first_initial_crypto =
        initial_crypto_frame_snapshots(*client.connection_, initial_datagrams.front());
    ASSERT_FALSE(first_initial_crypto.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});
    const auto next_initial_send_packet_number =
        client.connection_->initial_space_.next_send_packet_number;
    ASSERT_GT(next_initial_send_packet_number, 0u);

    auto retry_source_connection_id = bytes_from_ints({0x55, 0x66, 0x77, 0x88});
    auto retry_token = bytes_from_ints({0xaa, 0xbb, 0xcc});
    auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, retry_source_connection_id, retry_token,
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    const auto restarted_datagrams = coquic::quic::test::send_datagrams_from(after_retry);
    ASSERT_FALSE(restarted_datagrams.empty());

    auto restarted_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(restarted_datagrams.front());
    ASSERT_TRUE(restarted_destination_connection_id.has_value());
    auto restarted_destination_connection_id_value =
        restarted_destination_connection_id.value_or(coquic::quic::ConnectionId{});
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
    // # The client MUST use the value from the Source
    // # Connection ID field of the Retry packet in the Destination Connection
    // # ID field of subsequent packets that it sends.
    EXPECT_EQ(restarted_destination_connection_id_value, retry_source_connection_id);
    auto restarted_source_connection_id =
        coquic::quic::test::long_header_source_connection_id(restarted_datagrams.front());
    ASSERT_TRUE(restarted_source_connection_id.has_value());
    auto restarted_source_connection_id_value =
        restarted_source_connection_id.value_or(coquic::quic::ConnectionId{});
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
    // # The client MUST NOT change the Source Connection ID because the server
    // # could include the connection ID as part of its token validation logic;
    // # see Section 8.1.4.
    EXPECT_EQ(restarted_source_connection_id_value, client_source_connection_id);
    auto restarted_initial_token =
        coquic::quic::test::client_initial_datagram_token(restarted_datagrams.front());
    ASSERT_TRUE(restarted_initial_token.has_value());
    auto restarted_initial_token_value = restarted_initial_token.value_or(std::vector<std::byte>{});
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.2
    // # This token MUST be repeated by the client in all
    // # Initial packets it sends for that connection after it receives the
    // # Retry packet.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # The client MUST include the token in all Initial packets it sends,
    // # unless a Retry replaces the token with a newer one.
    EXPECT_EQ(restarted_initial_token_value, retry_token);
    const auto restarted_initial_crypto =
        initial_crypto_frame_snapshots(*client.connection_, restarted_datagrams.front());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.3
    // # A client MUST use the same cryptographic handshake message it included
    // # in this packet.
    ASSERT_EQ(restarted_initial_crypto.size(), first_initial_crypto.size());
    for (std::size_t index = 0; index < first_initial_crypto.size(); ++index) {
        EXPECT_EQ(restarted_initial_crypto[index].offset, first_initial_crypto[index].offset);
        EXPECT_EQ(restarted_initial_crypto[index].crypto_data,
                  first_initial_crypto[index].crypto_data);
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.3
    // # A client MUST NOT reset the packet number for any packet number space
    // # after processing a Retry packet.
    EXPECT_NE(
        tracked_packet_or_null(client.connection_->initial_space_, next_initial_send_packet_number),
        nullptr);
    EXPECT_EQ(client.connection_->initial_space_.next_send_packet_number,
              next_initial_send_packet_number + 1);
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientResendsZeroRttStreamDataAfterRetry) {
    auto warmup_client_config = coquic::quic::test::make_client_core_config();
    auto warmup_server_config = coquic::quic::test::make_server_core_config();
    warmup_client_config.zero_rtt.application_context = {std::byte{0x10}};
    warmup_server_config.zero_rtt.allow = true;
    warmup_server_config.zero_rtt.application_context = {std::byte{0x10}};

    coquic::quic::QuicCore warmup_client(std::move(warmup_client_config));
    coquic::quic::QuicCore warmup_server(std::move(warmup_server_config));
    const auto warmup_transcript = coquic::quic::test::drive_quic_handshake_with_results(
        warmup_client, warmup_server, coquic::quic::test::test_time());
    const auto state =
        coquic::quic::test::last_resumption_state_from(warmup_transcript.client_results);
    ASSERT_TRUE(state.has_value());
    if (!state.has_value()) {
        return;
    }

    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    client_config.resumption_state = *state;
    client_config.zero_rtt = coquic::quic::QuicZeroRttConfig{
        .attempt = true,
        .allow = false,
        .application_context = {std::byte{0x10}},
    };
    coquic::quic::QuicCore client(std::move(client_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time(100));
    auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());
    ASSERT_NE(client.connection_, nullptr);

    const auto early_data = coquic::quic::test::bytes_from_string("GET /retry\r\n");
    const auto send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = early_data,
            .fin = true,
        },
        coquic::quic::test::test_time(101));
    const auto zero_rtt_datagrams = coquic::quic::test::send_datagrams_from(send);
    auto original_zero_rtt = zero_rtt_stream_snapshots(*client.connection_, zero_rtt_datagrams);
    ASSERT_EQ(coquic::quic::test::zero_rtt_statuses_from(send),
              std::vector{coquic::quic::QuicZeroRttStatus::attempted});
    ASSERT_FALSE(original_zero_rtt.empty());
    const auto &original_zero_rtt_stream = original_zero_rtt.front();
    ASSERT_EQ(original_zero_rtt_stream.stream_id, 0u);
    ASSERT_EQ(original_zero_rtt_stream.offset, 0u);
    ASSERT_EQ(original_zero_rtt_stream.stream_data, early_data);
    ASSERT_TRUE(original_zero_rtt_stream.fin);

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});
    auto retry_source_connection_id = bytes_from_ints({0x55, 0x66, 0x77, 0x88});
    auto retry_token = bytes_from_ints({0xaa, 0xbb, 0xcc});
    auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, retry_source_connection_id, retry_token,
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(102));
    const auto restarted_datagrams = coquic::quic::test::send_datagrams_from(after_retry);
    ASSERT_FALSE(restarted_datagrams.empty());
    auto packet_kinds =
        coquic::quic::test_support::protected_datagram_packet_kinds(restarted_datagrams.front());
    ASSERT_TRUE(packet_kinds.has_value());
    const auto &packet_kind_values = optional_ref_or_terminate(packet_kinds);
    ASSERT_FALSE(packet_kind_values.empty());
    EXPECT_EQ(packet_kind_values.front(), coquic::quic::test_support::ProtectedPacketKind::initial);

    const auto stream = client.connection_->streams_.find(original_zero_rtt_stream.stream_id);
    ASSERT_NE(stream, client.connection_->streams_.end());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.3
    // # A client SHOULD attempt to resend data in 0-RTT packets after it
    // # sends a new Initial packet.
    EXPECT_EQ(stream->second.send_buffer.first_unsent_offset(), original_zero_rtt_stream.offset);
    EXPECT_EQ(stream->second.sendable_bytes(), original_zero_rtt_stream.stream_data.size());
    EXPECT_EQ(stream->second.send_fin_state, coquic::quic::StreamSendFinState::pending);
    EXPECT_EQ(client.connection_->connection_flow_control_.highest_sent, 0u);
    EXPECT_TRUE(client.connection_->has_pending_application_send());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.3
    // # New packet numbers MUST be used for any new packets that are sent;
    // # as described in Section 17.2.5.3, reusing packet numbers could
    // # compromise packet protection.
    EXPECT_EQ(client.connection_->application_space_.next_send_packet_number,
              original_zero_rtt_stream.packet_number + 1u);
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryWithInvalidIntegrityTag) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    auto retry_source_connection_id = bytes_from_ints({0x44, 0x33, 0x22, 0x11});
    auto retry_token = bytes_from_ints({0xda, 0x7a});
    auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, retry_source_connection_id, retry_token,
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    auto retry_with_invalid_tag = retry_datagram.value();
    ASSERT_FALSE(retry_with_invalid_tag.empty());
    retry_with_invalid_tag.back() = retry_with_invalid_tag.back() ^ std::byte{0x01};

    auto after_invalid_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_with_invalid_tag},
                       coquic::quic::test::test_time(1));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
    // # Clients MUST discard Retry packets that have a Retry Integrity Tag
    // # that cannot be validated; see Section 5.8 of [QUIC-TLS].
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_invalid_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryWithEmptyToken) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    auto retry_source_connection_id = bytes_from_ints({0x41, 0x42, 0x43, 0x44});
    auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, retry_source_connection_id, {},
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    auto after_empty_token_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
    // # A client
    // # MUST discard a Retry packet with a zero-length Retry Token field.
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_empty_token_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresSecondRetry) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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

    auto after_first_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = first_retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(after_first_retry).empty());

    auto second_retry_source_connection_id = bytes_from_ints({0x61, 0x62, 0x63, 0x64});
    auto second_retry_token = bytes_from_ints({0xb1, 0xb2, 0xb3});
    auto second_retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, second_retry_source_connection_id, second_retry_token,
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(second_retry_datagram.has_value());

    auto after_second_retry = client.advance(
        coquic::quic::QuicCoreInboundDatagram{.bytes = second_retry_datagram.value()},
        coquic::quic::test::test_time(2));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
    // # A client MUST accept and process at most one Retry packet for each
    // # connection attempt.
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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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

    auto retry_source_connection_id = bytes_from_ints({0x71, 0x72, 0x73, 0x74});
    auto retry_token = bytes_from_ints({0xc1, 0xc2, 0xc3});
    auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, retry_source_connection_id, retry_token,
        original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    auto after_late_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(3));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
    // # After the client has received and processed an
    // # Initial or Retry packet from the server, it MUST discard any
    // # subsequent Retry packets that it receives.
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_late_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryAfterProcessingPeerPacketBeforeHandshakeCompletion) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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

    ASSERT_NE(client.connection_, nullptr);
    client.connection_->processed_peer_packet_ = true;
    ASSERT_FALSE(client.is_handshake_complete());

    auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
    // # After the client has received and processed an
    // # Initial or Retry packet from the server, it MUST discard any
    // # subsequent Retry packets that it receives.
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryWithUnexpectedDestinationConnectionId) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        bytes_from_ints({0x31, 0x32, 0x33, 0x34}), bytes_from_ints({0x55, 0x66, 0x77, 0x88}),
        bytes_from_ints({0xaa, 0xbb}), original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryWhoseSourceConnectionIdEqualsOriginalDestination) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, original_destination_connection_id_value,
        bytes_from_ints({0xaa, 0xbb}), original_destination_connection_id_value, original_version);
    ASSERT_TRUE(retry_datagram.has_value());

    auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
    // # A client MUST discard a Retry packet that contains a Source
    // # Connection ID field that is identical to the Destination
    // # Connection ID field of its Initial packet.
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryOnDifferentVersion) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());
    const auto original_destination_connection_id_value =
        original_destination_connection_id.value_or(coquic::quic::ConnectionId{});

    auto retry_datagram = coquic::quic::test::make_valid_retry_datagram(
        client_source_connection_id, bytes_from_ints({0x55, 0x66, 0x77, 0x88}),
        bytes_from_ints({0xaa, 0xbb}), original_destination_connection_id_value,
        coquic::quic::kQuicVersion2);
    ASSERT_TRUE(retry_datagram.has_value());

    auto after_retry =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = retry_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(after_retry).empty());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicCoreTest, ClientIgnoresRetryWhenIntegrityValidationCannotRun) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto initial_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(initial_datagrams.empty());

    const auto original_destination_connection_id =
        coquic::quic::test::long_header_destination_connection_id(initial_datagrams.front());
    ASSERT_TRUE(original_destination_connection_id.has_value());

    auto retry_datagram = coquic::quic::serialize_packet(coquic::quic::RetryPacket{
        .version = 0xf1f2f3f4u,
        .retry_unused_bits = 0,
        .destination_connection_id = client_source_connection_id,
        .source_connection_id = bytes_from_ints({0x55, 0x66, 0x77, 0x88}),
        .retry_token = bytes_from_ints({0xaa, 0xbb}),
        .retry_integrity_tag = {},
    });
    ASSERT_TRUE(retry_datagram.has_value());

    auto after_retry =
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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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

    auto after_retry =
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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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

    auto after_initial =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = initial_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_EQ(coquic::quic::test::send_datagrams_from(after_initial).size(), 1u);
    auto later =
        client.advance(coquic::quic::QuicCoreTimerExpired{}, coquic::quic::test::test_time(2));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(later).empty());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2
    // # An endpoint MUST generate a connection error if processing the contents
    // # of these packets prior to discovering an error, or fully revert any
    // # changes made during that processing.
    EXPECT_TRUE(client.has_failed());
}

TEST(QuicCoreTest, ClientFailsOnNonRetryLongHeaderDatagramWithTrailingBytes) {
    auto client_config = coquic::quic::test::make_client_core_config();
    const auto client_source_connection_id = client_config.source_connection_id;
    const auto server_source_connection_id = client_config.initial_destination_connection_id;
    const auto original_version = client_config.original_version;
    coquic::quic::QuicCore client(std::move(client_config));

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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

    auto after_initial =
        client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = initial_datagram.value()},
                       coquic::quic::test::test_time(1));
    EXPECT_EQ(coquic::quic::test::send_datagrams_from(after_initial).size(), 1u);
    auto later =
        client.advance(coquic::quic::QuicCoreTimerExpired{}, coquic::quic::test::test_time(2));
    EXPECT_TRUE(coquic::quic::test::send_datagrams_from(later).empty());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2
    // # An endpoint MUST generate a connection error if processing the contents
    // # of these packets prior to discovering an error, or fully revert any
    // # changes made during that processing.
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    auto packets = decode_sender_datagram(connection, datagram);
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    auto packets = decode_sender_datagram(connection, datagram);
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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
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
    auto retry_source_connection_id = bytes_from_hex("5300000000000001");
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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto server_first_flight = coquic::quic::test::relay_send_datagrams_to_peer(
        start, server, coquic::quic::test::test_time(1));
    const auto server_first_flight_datagrams =
        coquic::quic::test::send_datagrams_from(server_first_flight);
    ASSERT_NE(server.connection_, nullptr);
    ASSERT_FALSE(server_first_flight_datagrams.empty());

    auto packets =
        decode_sender_datagram(*server.connection_, server_first_flight_datagrams.front());
    auto initial_packet_it = std::find_if(packets.begin(), packets.end(), [](const auto &packet) {
        return std::holds_alternative<coquic::quic::ProtectedInitialPacket>(packet);
    });
    if (initial_packet_it == packets.end()) {
        FAIL() << "server first flight did not include an Initial packet";
    }

    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&*initial_packet_it);
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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto server_first_flight = coquic::quic::test::relay_send_datagrams_to_peer(
        start, server, coquic::quic::test::test_time(1));
    const auto server_first_flight_datagrams =
        coquic::quic::test::send_datagrams_from(server_first_flight);
    ASSERT_NE(server.connection_, nullptr);
    ASSERT_FALSE(server_first_flight_datagrams.empty());

    auto packets =
        decode_sender_datagram(*server.connection_, server_first_flight_datagrams.front());
    std::vector<const coquic::quic::ProtectedInitialPacket *> initial_packets;
    for (const auto &packet : packets) {
        if (const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packet)) {
            initial_packets.push_back(initial);
        }
    }

    ASSERT_GE(initial_packets.size(), 2u);

    auto first_crypto = std::get_if<coquic::quic::CryptoFrame>(&initial_packets[0]->frames.front());
    auto second_crypto =
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

        auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

        if (!connection.has_failed() || tracked_packet_count(connection.initial_space_) != 1u) {
            continue;
        }

        found_duplicate_serialization_failure = true;
        EXPECT_TRUE(datagram.empty());
        EXPECT_EQ(connection.initial_space_.next_send_packet_number, 1u);
        EXPECT_EQ(first_tracked_packet(connection.initial_space_).packet_number, 0u);
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

        auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty() || connection.has_failed()) {
            continue;
        }

        auto packets = decode_sender_datagram(connection, datagram);
        auto initial_count = std::count_if(packets.begin(), packets.end(), [](const auto &packet) {
            return std::holds_alternative<coquic::quic::ProtectedInitialPacket>(packet);
        });
        if (initial_count != 1u || tracked_packet_count(connection.initial_space_) != 1u) {
            continue;
        }

        skipped_duplicate_initial = true;
        EXPECT_EQ(connection.initial_space_.next_send_packet_number, 1u);
    }

    EXPECT_TRUE(skipped_duplicate_initial);
}

TEST(QuicCoreTest,
     CompatibleNegotiationFinalizesInitialWhenDuplicateInitialWouldExceedCongestionWindow) {
    bool finalized_single_initial = false;

    for (std::size_t crypto_size = 64; crypto_size <= 2048 && !finalized_single_initial;
         crypto_size += 64) {
        auto config = coquic::quic::test::make_server_core_config();
        config.max_outbound_datagram_size = 4096;
        coquic::quic::QuicConnection connection(std::move(config));
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.original_version_ = coquic::quic::kQuicVersion1;
        connection.current_version_ = coquic::quic::kQuicVersion2;
        connection.client_initial_destination_connection_id_ = bytes_from_hex("8394c8f03e515708");
        connection.peer_source_connection_id_ = bytes_from_hex("c101");
        connection.peer_transport_parameters_validated_ = true;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 4096;
        connection.initial_space_.send_crypto.append(
            std::vector<std::byte>(crypto_size, std::byte{0x6a}));
        connection.congestion_controller_.congestion_window_ = 1200;

        auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty() || connection.has_failed()) {
            continue;
        }

        auto packets = decode_sender_datagram(connection, datagram);
        if (packets.size() != 1u) {
            continue;
        }
        if (!std::holds_alternative<coquic::quic::ProtectedInitialPacket>(packets.front())) {
            continue;
        }
        if (connection.initial_space_.next_send_packet_number != 1u ||
            tracked_packet_count(connection.initial_space_) != 1u) {
            continue;
        }

        finalized_single_initial = true;
    }

    EXPECT_TRUE(finalized_single_initial);
}

TEST(QuicCoreTest, ClientProcessInboundPacketAdoptsSupportedVersionFromInitialAndHandshake) {
    auto config = coquic::quic::test::make_client_core_config();
    config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};
    coquic::quic::QuicConnection client(std::move(config));
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

TEST(QuicCoreTest, ClientDiscardsLongHeaderPacketWithVersionItDidNotSelect) {
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
    EXPECT_EQ(client.current_version_, coquic::quic::kQuicVersion1);
    EXPECT_FALSE(client.initial_space_.received_packets.has_ack_to_send());

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
    EXPECT_EQ(client.current_version_, coquic::quic::kQuicVersion1);
    EXPECT_FALSE(client.handshake_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ClientRequiresRetrySourceConnectionIdAfterRetry) {
    coquic::quic::QuicConnection client(coquic::quic::test::make_client_core_config());
    const auto original_destination_connection_id = bytes_from_hex("8394c8f03e515708");
    auto retry_source_connection_id = bytes_from_hex("5300000000000001");
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
    auto retry_source_connection_id = bytes_from_hex("5300000000000001");
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
