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

TEST(QuicCoreTest, ClientUsesResumptionStateToEmitZeroRttDatagramBeforeHandshakeReady) {
    auto first_client_config = coquic::quic::test::make_client_core_config();
    auto first_server_config = coquic::quic::test::make_server_core_config();
    first_client_config.zero_rtt.application_context = {std::byte{0x10}};
    first_server_config.zero_rtt.allow = true;
    first_server_config.zero_rtt.application_context = {std::byte{0x10}};

    coquic::quic::QuicCore first_client(std::move(first_client_config));
    coquic::quic::QuicCore first_server(std::move(first_server_config));
    const auto first_transcript = coquic::quic::test::drive_quic_handshake_with_results(
        first_client, first_server, coquic::quic::test::test_time());
    const auto state =
        coquic::quic::test::last_resumption_state_from(first_transcript.client_results);
    ASSERT_TRUE(state.has_value());
    if (!state.has_value()) {
        return;
    }
    const auto &resumption_state = *state;

    auto resumed_client_config = coquic::quic::test::make_client_core_config();
    resumed_client_config.resumption_state = resumption_state;
    resumed_client_config.zero_rtt = coquic::quic::QuicZeroRttConfig{
        .attempt = true,
        .allow = false,
        .application_context = {std::byte{0x10}},
    };

    coquic::quic::QuicCore resumed_client(std::move(resumed_client_config));
    static_cast<void>(
        resumed_client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time(100)));
    const auto send = resumed_client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /index.html\r\n"),
            .fin = true,
        },
        coquic::quic::test::test_time(101));

    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(send).empty());
    EXPECT_EQ(coquic::quic::test::zero_rtt_statuses_from(send),
              std::vector{coquic::quic::QuicZeroRttStatus::attempted});
}

TEST(QuicCoreTest, EmptySourceCidClientCompletesResumedZeroRttHandshake) {
    auto warmup_client_config = coquic::quic::test::make_client_core_config();
    auto warmup_server_config = coquic::quic::test::make_server_core_config();
    warmup_client_config.source_connection_id = {};
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
    const auto &resumption_state = *state;

    auto client_config = coquic::quic::test::make_client_core_config();
    auto server_config = coquic::quic::test::make_server_core_config();
    client_config.source_connection_id = {};
    client_config.resumption_state = resumption_state;
    client_config.zero_rtt = coquic::quic::QuicZeroRttConfig{
        .attempt = true,
        .allow = false,
        .application_context = {std::byte{0x10}},
    };
    server_config.zero_rtt.allow = true;
    server_config.zero_rtt.application_context = {std::byte{0x10}};

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));

    auto to_server =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time(100));
    const auto early_send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /index.html\r\n"),
            .fin = true,
        },
        coquic::quic::test::test_time(101));
    to_server.effects.insert(to_server.effects.end(), early_send.effects.begin(),
                             early_send.effects.end());
    to_server.next_wakeup =
        coquic::quic::test::earliest_next_wakeup({to_server.next_wakeup, early_send.next_wakeup});

    coquic::quic::test::drive_quic_handshake_from_results(client, server, std::move(to_server), {},
                                                          coquic::quic::test::test_time(102));

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
}

TEST(QuicCoreTest, EmptySourceCidClientCompletesResumedZeroRttHandshakeWithManyStreams) {
    auto warmup_client_config = coquic::quic::test::make_client_core_config();
    auto warmup_server_config = coquic::quic::test::make_server_core_config();
    warmup_client_config.source_connection_id = {};
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
    const auto &resumption_state = *state;

    auto client_config = coquic::quic::test::make_client_core_config();
    auto server_config = coquic::quic::test::make_server_core_config();
    client_config.source_connection_id = {};
    client_config.resumption_state = resumption_state;
    client_config.zero_rtt = coquic::quic::QuicZeroRttConfig{
        .attempt = true,
        .allow = false,
        .application_context = {std::byte{0x10}},
    };
    server_config.zero_rtt.allow = true;
    server_config.zero_rtt.application_context = {std::byte{0x10}};

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));

    auto to_server =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time(100));
    for (std::uint64_t stream_id = 0; stream_id < 64; stream_id += 4) {
        const auto send = client.advance(
            coquic::quic::QuicCoreSendStreamData{
                .stream_id = stream_id,
                .bytes = coquic::quic::test::bytes_from_string("GET /index.html\r\n"),
                .fin = true,
            },
            coquic::quic::test::test_time(101));
        to_server.effects.insert(to_server.effects.end(), send.effects.begin(), send.effects.end());
        to_server.next_wakeup =
            coquic::quic::test::earliest_next_wakeup({to_server.next_wakeup, send.next_wakeup});
    }

    coquic::quic::test::drive_quic_handshake_from_results(client, server, std::move(to_server), {},
                                                          coquic::quic::test::test_time(102));

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
}

TEST(QuicCoreTest, ResumedClientDoesNotCoalescePacketsWithDifferentDestinationConnectionIds) {
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
    const auto &resumption_state = *state;

    auto client_config = coquic::quic::test::make_client_core_config();
    auto server_config = coquic::quic::test::make_server_core_config();
    client_config.resumption_state = resumption_state;
    client_config.zero_rtt = coquic::quic::QuicZeroRttConfig{
        .attempt = true,
        .allow = false,
        .application_context = {std::byte{0x10}},
    };
    server_config.zero_rtt.allow = true;
    server_config.zero_rtt.application_context = {std::byte{0x10}};

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));

    auto to_server =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time(100));
    for (std::uint64_t stream_id : {0ull, 4ull}) {
        const auto send = client.advance(
            coquic::quic::QuicCoreSendStreamData{
                .stream_id = stream_id,
                .bytes = coquic::quic::test::bytes_from_string("GET /index.html\r\n"),
                .fin = true,
            },
            coquic::quic::test::test_time(101));
        to_server.effects.insert(to_server.effects.end(), send.effects.begin(), send.effects.end());
        to_server.next_wakeup =
            coquic::quic::test::earliest_next_wakeup({to_server.next_wakeup, send.next_wakeup});
    }

    const auto to_client = coquic::quic::test::relay_send_datagrams_to_peer(
        to_server, server, coquic::quic::test::test_time(102));
    ASSERT_NE(client.connection_, nullptr);
    const auto client_reply = coquic::quic::test::relay_send_datagrams_to_peer(
        to_client, client, coquic::quic::test::test_time(103));

    bool saw_mixed_destination_connection_ids = false;
    for (const auto &datagram : coquic::quic::test::send_datagrams_from(client_reply)) {
        const auto destination_connection_ids = protected_datagram_destination_connection_ids(
            datagram, client.connection_->outbound_destination_connection_id().size());
        ASSERT_TRUE(destination_connection_ids.has_value());
        if (!destination_connection_ids.has_value()) {
            return;
        }
        if (destination_connection_ids->size() < 2) {
            continue;
        }

        std::optional<coquic::quic::ConnectionId> destination_connection_id;
        for (const auto &packet_destination_connection_id : *destination_connection_ids) {
            if (!destination_connection_id.has_value()) {
                destination_connection_id = packet_destination_connection_id;
                continue;
            }
            if (destination_connection_id.value() != packet_destination_connection_id) {
                saw_mixed_destination_connection_ids = true;
                break;
            }
        }
        if (saw_mixed_destination_connection_ids) {
            break;
        }
    }

    EXPECT_FALSE(saw_mixed_destination_connection_ids);
}

TEST(QuicCoreTest, ResumedClientStillEmitsHandshakePacketWhenAppSendIsCwndBlocked) {
    auto warmup_client_config = coquic::quic::test::make_client_core_config();
    auto warmup_server_config = coquic::quic::test::make_server_core_config();
    warmup_client_config.zero_rtt.application_context = {std::byte{0x10}};
    warmup_client_config.transport.initial_max_streams_bidi = 64;
    warmup_server_config.zero_rtt.allow = true;
    warmup_server_config.zero_rtt.application_context = {std::byte{0x10}};
    warmup_server_config.transport.initial_max_streams_bidi = 64;

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
    const auto &resumption_state = *state;

    auto client_config = coquic::quic::test::make_client_core_config();
    auto server_config = coquic::quic::test::make_server_core_config();
    client_config.resumption_state = resumption_state;
    client_config.zero_rtt = coquic::quic::QuicZeroRttConfig{
        .attempt = true,
        .allow = false,
        .application_context = {std::byte{0x10}},
    };
    client_config.transport.initial_max_streams_bidi = 64;
    server_config.zero_rtt.allow = true;
    server_config.zero_rtt.application_context = {std::byte{0x10}};
    server_config.transport.initial_max_streams_bidi = 64;

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));

    auto to_server =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time(100));
    const auto request_bytes = std::vector<std::byte>(512, std::byte{0x61});
    for (std::uint64_t stream_id = 0; stream_id < 64; stream_id += 4) {
        const auto send = client.advance(
            coquic::quic::QuicCoreSendStreamData{
                .stream_id = stream_id,
                .bytes = request_bytes,
                .fin = stream_id != 0,
            },
            coquic::quic::test::test_time(101));
        to_server.effects.insert(to_server.effects.end(), send.effects.begin(), send.effects.end());
        to_server.next_wakeup =
            coquic::quic::test::earliest_next_wakeup({to_server.next_wakeup, send.next_wakeup});
    }

    const auto to_client = coquic::quic::test::relay_send_datagrams_to_peer(
        to_server, server, coquic::quic::test::test_time(102));
    ASSERT_NE(client.connection_, nullptr);
    const auto server_datagrams = coquic::quic::test::send_datagrams_from(to_client);
    ASSERT_FALSE(server_datagrams.empty());
    client.connection_->process_inbound_datagram(server_datagrams.front(),
                                                 coquic::quic::test::test_time(103));

    ASSERT_TRUE(client.connection_->application_space_.write_secret.has_value());
    ASSERT_TRUE(client.connection_->handshake_space_.write_secret.has_value());
    ASSERT_TRUE(client.connection_->handshake_space_.received_packets.has_ack_to_send());

    const auto queued = client.connection_->queue_stream_send(
        0, std::vector<std::byte>(512, std::byte{0x62}), /*fin=*/true);
    ASSERT_TRUE(queued.has_value());

    const auto first_reply =
        client.connection_->drain_outbound_datagram(coquic::quic::test::test_time(103));
    const auto first_packet_kinds = protected_datagram_packet_kinds(first_reply);
    ASSERT_TRUE(first_packet_kinds.has_value());
    if (!first_packet_kinds.has_value()) {
        return;
    }
    const auto &first_kinds = *first_packet_kinds;
    ASSERT_EQ(first_kinds.size(), 1u);
    EXPECT_EQ(first_kinds[0], ProtectedPacketKind::initial);

    client.connection_->congestion_controller_.bytes_in_flight_ =
        client.connection_->congestion_controller_.congestion_window();

    const auto second_reply =
        client.connection_->drain_outbound_datagram(coquic::quic::test::test_time(103));
    const auto second_packet_kinds = protected_datagram_packet_kinds(second_reply);
    ASSERT_TRUE(second_packet_kinds.has_value());
    if (!second_packet_kinds.has_value()) {
        return;
    }
    const auto &second_kinds = *second_packet_kinds;
    ASSERT_FALSE(second_kinds.empty());
    EXPECT_EQ(second_kinds[0], ProtectedPacketKind::handshake);
}

TEST(QuicCoreTest, ResumedServerFirstApplicationAckCoversOriginalZeroRttPacketRange) {
    auto warmup_client_config = coquic::quic::test::make_client_core_config();
    auto warmup_server_config = coquic::quic::test::make_server_core_config();
    warmup_client_config.source_connection_id = {};
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
    const auto &resumption_state = *state;

    auto client_config = coquic::quic::test::make_client_core_config();
    auto server_config = coquic::quic::test::make_server_core_config();
    client_config.source_connection_id = {};
    client_config.resumption_state = resumption_state;
    client_config.zero_rtt = coquic::quic::QuicZeroRttConfig{
        .attempt = true,
        .allow = false,
        .application_context = {std::byte{0x10}},
    };
    server_config.zero_rtt.allow = true;
    server_config.zero_rtt.application_context = {std::byte{0x10}};

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));

    auto to_server =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time(100));
    std::vector<std::uint64_t> zero_rtt_packet_numbers;
    const auto collect_zero_rtt_packets = [&](const coquic::quic::QuicCoreResult &result) {
        for (const auto &datagram : coquic::quic::test::send_datagrams_from(result)) {
            for (const auto &packet : decode_sender_datagram(*client.connection_, datagram)) {
                const auto *zero_rtt = std::get_if<coquic::quic::ProtectedZeroRttPacket>(&packet);
                if (zero_rtt == nullptr) {
                    continue;
                }

                zero_rtt_packet_numbers.push_back(zero_rtt->packet_number);
            }
        }
    };
    collect_zero_rtt_packets(to_server);
    for (std::uint64_t stream_id = 0; stream_id < 64; stream_id += 4) {
        const auto send = client.advance(
            coquic::quic::QuicCoreSendStreamData{
                .stream_id = stream_id,
                .bytes = coquic::quic::test::bytes_from_string("GET /index.html\r\n"),
                .fin = true,
            },
            coquic::quic::test::test_time(101));
        collect_zero_rtt_packets(send);
        to_server.effects.insert(to_server.effects.end(), send.effects.begin(), send.effects.end());
        to_server.next_wakeup =
            coquic::quic::test::earliest_next_wakeup({to_server.next_wakeup, send.next_wakeup});
    }

    ASSERT_FALSE(zero_rtt_packet_numbers.empty());
    const auto min_zero_rtt =
        *std::min_element(zero_rtt_packet_numbers.begin(), zero_rtt_packet_numbers.end());
    const auto max_zero_rtt =
        *std::max_element(zero_rtt_packet_numbers.begin(), zero_rtt_packet_numbers.end());

    const auto to_client = coquic::quic::test::relay_send_datagrams_to_peer(
        to_server, server, coquic::quic::test::test_time(102));
    const auto response_datagrams = coquic::quic::test::send_datagrams_from(to_client);
    ASSERT_FALSE(response_datagrams.empty());
    EXPECT_TRUE(server.connection_->zero_rtt_space_.read_secret.has_value());
    EXPECT_TRUE(server.connection_->application_space_.read_secret.has_value());
    EXPECT_TRUE(server.connection_->application_space_.write_secret.has_value());
    EXPECT_FALSE(coquic::quic::test::received_stream_data_from(to_client).empty());
    EXPECT_FALSE(server.connection_->application_space_.received_packets.has_ack_to_send());
    EXPECT_TRUE(server.connection_->deferred_protected_packets_.empty());

    const auto decode_server_response_datagram = [&](std::span<const std::byte> datagram) {
        const auto decoded = coquic::quic::deserialize_protected_datagram(
            datagram,
            coquic::quic::DeserializeProtectionContext{
                .peer_role = coquic::quic::EndpointRole::server,
                .client_initial_destination_connection_id =
                    server.connection_->client_initial_destination_connection_id(),
                .handshake_secret = server.connection_->handshake_space_.write_secret,
                .one_rtt_secret = server.connection_->application_space_.write_secret,
                .largest_authenticated_initial_packet_number =
                    server.connection_->initial_space_.largest_authenticated_packet_number,
                .largest_authenticated_handshake_packet_number =
                    server.connection_->handshake_space_.largest_authenticated_packet_number,
                .largest_authenticated_application_packet_number =
                    server.connection_->application_space_.largest_authenticated_packet_number,
                .one_rtt_destination_connection_id_length =
                    client.connection_->config_.source_connection_id.size(),
            });
        EXPECT_TRUE(decoded.has_value());
        if (!decoded.has_value()) {
            return std::vector<coquic::quic::ProtectedPacket>{};
        }

        return decoded.value();
    };

    bool saw_ack_frame = false;
    bool saw_ack_covering_zero_rtt_range = false;
    for (const auto &datagram : response_datagrams) {
        for (const auto &packet : decode_server_response_datagram(datagram)) {
            const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (one_rtt == nullptr) {
                continue;
            }

            for (const auto &frame : one_rtt->frames) {
                const auto *ack = std::get_if<coquic::quic::AckFrame>(&frame);
                if (ack == nullptr) {
                    continue;
                }

                saw_ack_frame = true;
                if (ack_frame_acks_packet_number_for_tests(*ack, min_zero_rtt) &&
                    ack_frame_acks_packet_number_for_tests(*ack, max_zero_rtt)) {
                    saw_ack_covering_zero_rtt_range = true;
                }
            }
        }
    }

    EXPECT_TRUE(saw_ack_frame);
    EXPECT_TRUE(saw_ack_covering_zero_rtt_range);
}

TEST(QuicCoreTest, EmptySourceCidClientCompletesHandshakeAndEmitsResumptionState) {
    auto client_config = coquic::quic::test::make_client_core_config();
    auto server_config = coquic::quic::test::make_server_core_config();
    client_config.source_connection_id = {};
    client_config.zero_rtt.application_context = {std::byte{0x10}};
    server_config.zero_rtt.allow = true;
    server_config.zero_rtt.application_context = {std::byte{0x10}};

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));
    const auto transcript = coquic::quic::test::drive_quic_handshake_with_results(
        client, server, coquic::quic::test::test_time());
    const auto state = coquic::quic::test::last_resumption_state_from(transcript.client_results);

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
    ASSERT_TRUE(state.has_value());
    if (!state.has_value()) {
        return;
    }
    const auto &resumption_state = *state;
    EXPECT_FALSE(resumption_state.serialized.empty());
}

TEST(QuicCoreTest, ClientUsesProtectedZeroRttPacketForEarlyApplicationSend) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.application_space_.read_secret.reset();
    connection.application_space_.write_secret.reset();
    connection.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("early-data"), false)
            .has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(0));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *zero_rtt = std::get_if<coquic::quic::ProtectedZeroRttPacket>(&packets.front());
    ASSERT_NE(zero_rtt, nullptr);

    bool saw_stream = false;
    for (const auto &frame : zero_rtt->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        saw_stream = true;
        EXPECT_EQ(stream->stream_id, 0u);
        EXPECT_EQ(stream->stream_data, coquic::quic::test::bytes_from_string("early-data"));
    }

    EXPECT_TRUE(saw_stream);
}

TEST(QuicCoreTest, ClientEarlyApplicationSendFailsWhenZeroRttPacketSerializationFails) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.application_space_.read_secret.reset();
    connection.application_space_.write_secret.reset();
    connection.zero_rtt_space_.write_secret =
        make_test_traffic_secret(invalid_cipher_suite(), std::byte{0x44});

    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("early-data"), false)
            .has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(0));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, QlogCapturesZeroRttPacketTypeForOutboundEarlyData) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.config_.initial_destination_connection_id, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.qlog_session_ != nullptr);

    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.application_space_.read_secret.reset();
    connection.application_space_.write_secret.reset();
    connection.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("early-data"), false)
            .has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:packet_sent"), 1u);
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(records, "\"packet_type\":\"0RTT\""));
}

TEST(QuicCoreTest, ZeroRttApplicationCloseWithoutOneRttKeysReturnsEmpty) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.application_space_.read_secret.reset();
    connection.application_space_.write_secret.reset();
    connection.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51});

    ASSERT_TRUE(connection
                    .queue_application_close({
                        .application_error_code = 13,
                        .reason_phrase = "zero-rtt-close",
                    })
                    .has_value());

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(0)).empty());
}

TEST(QuicCoreTest, ApplicationCloseUsesOneRttProtectionWhenZeroRttIsAlsoAvailable) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x52});

    ASSERT_TRUE(connection
                    .queue_application_close({
                        .application_error_code = 14,
                        .reason_phrase = "zero-rtt-upgrade",
                    })
                    .has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(0));
    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front()), nullptr);
    EXPECT_EQ(std::get_if<coquic::quic::ProtectedZeroRttPacket>(&packets.front()), nullptr);
}

TEST(QuicCoreTest, ApplicationCloseDropsAckToFitDatagramWhenZeroRttIsAlsoAvailable) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x53});
    connection.config_.transport.max_udp_payload_size = 72;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.max_udp_payload_size = 72;
    connection.application_space_.received_packets.record_received(
        77, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));

    ASSERT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    ASSERT_TRUE(connection
                    .queue_application_close({
                        .application_error_code = 15,
                        .reason_phrase = std::string(24, 'z'),
                    })
                    .has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(packet, nullptr);

    bool saw_ack = false;
    bool saw_application_close = false;
    for (const auto &frame : packet->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_application_close =
            saw_application_close ||
            std::holds_alternative<coquic::quic::ApplicationConnectionCloseFrame>(frame);
    }

    EXPECT_FALSE(saw_ack);
    EXPECT_TRUE(saw_application_close);
}

TEST(QuicCoreTest, AcceptedZeroRttPacketsScheduleApplicationAck) {
    auto connection = make_connected_server_connection();
    connection.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedZeroRttPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id =
                optional_value_or_terminate(connection.peer_source_connection_id_),
            .packet_number_length = 1,
            .packet_number = 7,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(processed.has_value());

    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 7u);
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    ASSERT_TRUE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_EQ(optional_value_or_terminate(connection.application_space_.pending_ack_deadline),
              coquic::quic::test::test_time(1));

    const auto ack_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(ack_datagram.empty());
    const auto packets = decode_sender_datagram(connection, ack_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    for (const auto &frame : application->frames) {
        const auto *ack = std::get_if<coquic::quic::AckFrame>(&frame);
        if (ack == nullptr) {
            continue;
        }

        saw_ack = true;
        EXPECT_EQ(ack->largest_acknowledged, 7u);
    }

    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, AckOnlyZeroRttPacketDoesNotScheduleApplicationAckDeadline) {
    auto connection = make_connected_server_connection();
    connection.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.application_space_.pending_ack_deadline = std::nullopt;

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedZeroRttPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id =
                optional_value_or_terminate(connection.peer_source_connection_id_),
            .packet_number_length = 1,
            .packet_number = 8,
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
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 8u);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_EQ(connection.last_peer_activity_time_, coquic::quic::test::test_time(1));
}

TEST(QuicCoreTest, ServerProcessesZeroRttStreamBeforeHandshakeCompletes) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedZeroRttPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id =
                optional_value_or_terminate(connection.peer_source_connection_id_),
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
                        .stream_data = coquic::quic::test::bytes_from_string("early-data"),
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
    EXPECT_EQ(received_stream.bytes, coquic::quic::test::bytes_from_string("early-data"));
    EXPECT_TRUE(received_stream.fin);
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramProcessesZeroRttStreamBeforeHandshakeCompletes) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedZeroRttPacket{
                .version = coquic::quic::kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id =
                    optional_value_or_terminate(connection.peer_source_connection_id_),
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
                            .stream_data = coquic::quic::test::bytes_from_string("early-data"),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .zero_rtt_secret = optional_ref_or_terminate(connection.zero_rtt_space_.read_secret),
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
    EXPECT_EQ(received_stream.bytes, coquic::quic::test::bytes_from_string("early-data"));
    EXPECT_TRUE(received_stream.fin);
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
}

TEST(QuicCoreTest, ClientStopsUsingZeroRttWhenApplicationWriteKeysExist) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    ASSERT_TRUE(connection.application_space_.write_secret.has_value());
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("late-early"), false)
            .has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(0));

    EXPECT_FALSE(connection.zero_rtt_space_.write_secret.has_value());
    if (!datagram.empty()) {
        const auto packets = decode_sender_datagram(connection, datagram);
        ASSERT_EQ(packets.size(), 1u);
        EXPECT_EQ(std::get_if<coquic::quic::ProtectedZeroRttPacket>(&packets.front()), nullptr);
    }
}

TEST(QuicCoreTest, ServerRetainsZeroRttReadSecretLongEnoughForReorderedZeroRttPackets) {
    auto connection = make_connected_server_connection();
    connection.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto early_zero_rtt = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedZeroRttPacket{
                .version = coquic::quic::kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id =
                    optional_value_or_terminate(connection.peer_source_connection_id_),
                .packet_number_length = 1,
                .packet_number = 0,
                .frames =
                    {
                        coquic::quic::StreamFrame{
                            .fin = true,
                            .has_offset = true,
                            .has_length = true,
                            .stream_id = 0,
                            .offset = 0,
                            .stream_data = coquic::quic::test::bytes_from_string("early"),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .zero_rtt_secret = connection.zero_rtt_space_.read_secret,
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(early_zero_rtt.has_value());

    const auto first_one_rtt = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = 9,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .zero_rtt_secret = connection.zero_rtt_space_.read_secret,
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(first_one_rtt.has_value());

    const auto late_zero_rtt = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedZeroRttPacket{
                .version = coquic::quic::kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id =
                    optional_value_or_terminate(connection.peer_source_connection_id_),
                .packet_number_length = 1,
                .packet_number = 2,
                .frames =
                    {
                        coquic::quic::StreamFrame{
                            .fin = true,
                            .has_offset = true,
                            .has_length = true,
                            .stream_id = 4,
                            .offset = 0,
                            .stream_data = coquic::quic::test::bytes_from_string("late"),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .zero_rtt_secret = connection.zero_rtt_space_.read_secret,
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(late_zero_rtt.has_value());

    connection.process_inbound_datagram(early_zero_rtt.value(), coquic::quic::test::test_time(1));
    connection.process_inbound_datagram(first_one_rtt.value(), coquic::quic::test::test_time(2));

    ASSERT_TRUE(connection.zero_rtt_space_.read_secret.has_value());

    connection.process_inbound_datagram(late_zero_rtt.value(), coquic::quic::test::test_time(3));

    const auto first_received = connection.take_received_stream_data();
    ASSERT_TRUE(first_received.has_value());
    if (!first_received.has_value()) {
        return;
    }
    const auto &first_stream = *first_received;
    EXPECT_EQ(first_stream.stream_id, 0u);
    EXPECT_EQ(first_stream.bytes, coquic::quic::test::bytes_from_string("early"));

    const auto second_received = connection.take_received_stream_data();
    ASSERT_TRUE(second_received.has_value());
    if (!second_received.has_value()) {
        return;
    }
    const auto &second_stream = *second_received;
    EXPECT_EQ(second_stream.stream_id, 4u);
    EXPECT_EQ(second_stream.bytes, coquic::quic::test::bytes_from_string("late"));
}

TEST(QuicCoreTest, ServerDiscardsZeroRttReadSecretAfterShortRetentionWindowFollowingOneRtt) {
    auto connection = make_connected_server_connection();
    connection.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 1,
            .packet_number = 3,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(processed.has_value());

    ASSERT_TRUE(connection.zero_rtt_space_.read_secret.has_value());

    connection.on_timeout(coquic::quic::test::test_time(2999));
    EXPECT_FALSE(connection.zero_rtt_space_.read_secret.has_value());
}

TEST(QuicCoreTest, InboundOneRttPacketDiscardsClientZeroRttWriteKeys) {
    auto connection = make_connected_client_connection();
    connection.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 1,
            .packet_number = 3,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_FALSE(connection.zero_rtt_space_.write_secret.has_value());
}

TEST(QuicCoreTest, ClientStartupReportsUnavailableZeroRttForMalformedResumptionState) {
    auto config = coquic::quic::test::make_client_core_config();
    config.resumption_state = coquic::quic::QuicResumptionState{
        .serialized = {std::byte{0x00}},
    };
    config.zero_rtt = coquic::quic::QuicZeroRttConfig{
        .attempt = true,
        .allow = false,
        .application_context = {},
    };

    coquic::quic::QuicConnection connection(std::move(config));
    connection.start_client_if_needed();

    EXPECT_TRUE(connection.started_);
    EXPECT_FALSE(connection.has_failed());
    ASSERT_FALSE(connection.decoded_resumption_state_.has_value());
    const auto event = connection.take_zero_rtt_status_event();
    ASSERT_TRUE(event.has_value());
    if (!event.has_value()) {
        return;
    }
    EXPECT_EQ(event->status, coquic::quic::QuicZeroRttStatus::unavailable);
}

TEST(QuicCoreTest, ClientStartupReportsUnavailableZeroRttForApplicationContextMismatch) {
    coquic::quic::QuicCore warmup_client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore warmup_server(coquic::quic::test::make_server_core_config());
    const auto transcript = coquic::quic::test::drive_quic_handshake_with_results(
        warmup_client, warmup_server, coquic::quic::test::test_time());
    const auto state = coquic::quic::test::last_resumption_state_from(transcript.client_results);
    ASSERT_TRUE(state.has_value());
    if (!state.has_value()) {
        return;
    }

    auto resumed_config = coquic::quic::test::make_client_core_config();
    resumed_config.resumption_state = *state;
    resumed_config.zero_rtt = coquic::quic::QuicZeroRttConfig{
        .attempt = true,
        .allow = false,
        .application_context = {std::byte{0x7a}},
    };

    coquic::quic::QuicConnection resumed(std::move(resumed_config));
    resumed.start_client_if_needed();

    EXPECT_TRUE(resumed.started_);
    EXPECT_FALSE(resumed.has_failed());
    ASSERT_TRUE(resumed.decoded_resumption_state_.has_value());
    EXPECT_FALSE(resumed.peer_transport_parameters_.has_value());
    const auto event = resumed.take_zero_rtt_status_event();
    ASSERT_TRUE(event.has_value());
    if (!event.has_value()) {
        return;
    }
    EXPECT_EQ(event->status, coquic::quic::QuicZeroRttStatus::unavailable);
}

TEST(QuicCoreTest, ClientStartupReportsUnavailableZeroRttForMalformedResumptionFields) {
    const auto append_u32_be = [](std::vector<std::byte> &output, std::uint32_t value) {
        output.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
        output.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
        output.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
        output.push_back(static_cast<std::byte>(value & 0xffu));
    };
    const auto append_length_prefixed_bytes = [&](std::vector<std::byte> &output,
                                                  std::span<const std::byte> bytes) {
        append_u32_be(output, static_cast<std::uint32_t>(bytes.size()));
        output.insert(output.end(), bytes.begin(), bytes.end());
    };
    const auto append_length_prefixed_text = [&](std::vector<std::byte> &output,
                                                 std::string_view text) {
        append_u32_be(output, static_cast<std::uint32_t>(text.size()));
        output.insert(output.end(), reinterpret_cast<const std::byte *>(text.data()),
                      reinterpret_cast<const std::byte *>(text.data() + text.size()));
    };
    const auto run_unavailable_case = [&](std::vector<std::byte> serialized) {
        auto config = coquic::quic::test::make_client_core_config();
        config.resumption_state = coquic::quic::QuicResumptionState{
            .serialized = std::move(serialized),
        };
        config.zero_rtt = coquic::quic::QuicZeroRttConfig{
            .attempt = true,
            .allow = false,
            .application_context = {},
        };

        coquic::quic::QuicConnection connection(std::move(config));
        connection.start_client_if_needed();

        EXPECT_FALSE(connection.has_failed());
        const auto event = connection.take_zero_rtt_status_event();
        ASSERT_TRUE(event.has_value());
        if (!event.has_value()) {
            return;
        }
        EXPECT_EQ(event->status, coquic::quic::QuicZeroRttStatus::unavailable);
    };

    std::vector<std::byte> truncated_length_prefix = {
        std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    };
    run_unavailable_case(std::move(truncated_length_prefix));

    std::vector<std::byte> truncated_field_payload = {
        std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02}, std::byte{0xaa},
    };
    run_unavailable_case(std::move(truncated_field_payload));

    std::vector<std::byte> invalid_transport_parameters = {std::byte{0x01}};
    append_u32_be(invalid_transport_parameters, coquic::quic::kQuicVersion1);
    append_length_prefixed_bytes(invalid_transport_parameters, {});
    append_length_prefixed_text(invalid_transport_parameters, "h3");
    const auto malformed_transport_parameters = bytes_from_ints({0x40});
    append_length_prefixed_bytes(invalid_transport_parameters, malformed_transport_parameters);
    append_length_prefixed_bytes(invalid_transport_parameters, {});
    run_unavailable_case(std::move(invalid_transport_parameters));

    std::vector<std::byte> trailing_bytes_after_context = {std::byte{0x01}};
    append_u32_be(trailing_bytes_after_context, coquic::quic::kQuicVersion1);
    append_length_prefixed_bytes(trailing_bytes_after_context, {});
    append_length_prefixed_text(trailing_bytes_after_context, "h3");
    const auto transport_parameters =
        coquic::quic::serialize_transport_parameters(coquic::quic::TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 8,
            .initial_source_connection_id = bytes_from_ints({0x01}),
        });
    ASSERT_TRUE(transport_parameters.has_value());
    if (!transport_parameters.has_value()) {
        return;
    }
    append_length_prefixed_bytes(trailing_bytes_after_context, transport_parameters.value());
    append_length_prefixed_bytes(trailing_bytes_after_context, {});
    trailing_bytes_after_context.push_back(std::byte{0xff});
    run_unavailable_case(std::move(trailing_bytes_after_context));
}

TEST(QuicCoreTest, ServerApplicationPacketArmsZeroRttDiscardDeadline) {
    auto server = make_connected_server_connection();
    server.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto processed = server.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = server.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 9,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(server.server_zero_rtt_discard_deadline_.has_value());
}

TEST(QuicCoreTest, ServerRejectsInvalidZeroRttApplicationFrame) {
    auto server = make_connected_server_connection();

    const auto processed = server.process_inbound_packet(
        coquic::quic::ProtectedZeroRttPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = server.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x10, 0x20}),
            .packet_number_length = 2,
            .packet_number = 3,
            .frames = {coquic::quic::NewTokenFrame{.token = bytes_from_ints({0xaa})}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_FALSE(processed.has_value());
    EXPECT_EQ(processed.error().code,
              coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
}

TEST(QuicCoreTest, SyncTlsStateSkipsResumptionEmissionWithoutPeerTransportParameters) {
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

    connection.pending_resumption_state_effect_.reset();
    connection.resumption_state_emitted_ = false;
    connection.peer_transport_parameters_.reset();
    coquic::quic::test::TlsAdapterTestPeer::clear_peer_transport_parameters(tls);

    const auto synced = connection.sync_tls_state();

    ASSERT_TRUE(synced.has_value());
    EXPECT_FALSE(connection.pending_resumption_state_effect_.has_value());
    EXPECT_FALSE(connection.resumption_state_emitted_);
}

TEST(QuicCoreTest, QueueStreamSendEmitsZeroRttAttemptEventForResumedClient) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.config_.zero_rtt.attempt = true;
    connection.streams_.emplace(
        0, coquic::quic::make_implicit_stream_state(0, connection.config_.role));
    connection.decoded_resumption_state_ = coquic::quic::StoredClientResumptionState{
        .tls_state = {},
        .quic_version = coquic::quic::kQuicVersion1,
        .application_protocol = connection.config_.application_protocol,
        .peer_transport_parameters =
            {
                .max_udp_payload_size = 1200,
                .active_connection_id_limit = 2,
                .initial_source_connection_id = coquic::quic::ConnectionId{std::byte{0x01}},
            },
        .application_context = connection.config_.zero_rtt.application_context,
    };
    connection.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x55});

    const auto queued = connection.queue_stream_send(0, bytes_from_ints({0x61}), false);

    ASSERT_TRUE(queued.has_value());
    ASSERT_TRUE(connection.pending_zero_rtt_status_event_.has_value());
    EXPECT_EQ(optional_value_or_terminate(connection.pending_zero_rtt_status_event_).status,
              coquic::quic::QuicZeroRttStatus::attempted);
    EXPECT_TRUE(connection.zero_rtt_attempted_event_emitted_);
}

TEST(QuicCoreTest, ServerOneRttPacketDiscardsWriteOnlyZeroRttState) {
    auto server = make_connected_server_connection();
    server.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x66});
    server.zero_rtt_space_.read_secret.reset();
    server.server_zero_rtt_discard_deadline_.reset();

    const auto processed = server.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = server.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 10,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_FALSE(server.zero_rtt_space_.write_secret.has_value());
    EXPECT_FALSE(server.zero_rtt_space_.read_secret.has_value());
    EXPECT_FALSE(server.server_zero_rtt_discard_deadline_.has_value());
}

TEST(QuicCoreTest, ReceivedZeroRttPacketSchedulesApplicationAck) {
    auto connection = make_connected_server_connection();
    connection.application_space_.pending_ack_deadline = std::nullopt;
    connection.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto processed = connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedZeroRttPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id =
                optional_value_or_terminate(connection.peer_source_connection_id_),
            .packet_number_length = 1,
            .packet_number = 11,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 11u);
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    ASSERT_TRUE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_EQ(optional_value_or_terminate(connection.application_space_.pending_ack_deadline),
              coquic::quic::test::test_time(1));
}

TEST(QuicCoreTest, ReceivedZeroRttAckOnlyPacketDoesNotScheduleApplicationAck) {
    auto connection = make_connected_server_connection();
    connection.application_space_.pending_ack_deadline = std::nullopt;
    connection.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto processed = connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedZeroRttPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id =
                optional_value_or_terminate(connection.peer_source_connection_id_),
            .packet_number_length = 1,
            .packet_number = 12,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames =
                {
                    coquic::quic::ReceivedAckFrame{
                        .largest_acknowledged = 0,
                        .first_ack_range = 0,
                        .additional_ranges_validated = true,
                    },
                },
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 12u);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_EQ(connection.last_peer_activity_time_, std::optional{coquic::quic::test::test_time(1)});
}

TEST(QuicCoreTest, ReceivedZeroRttPacketRejectsInvalidApplicationFrame) {
    auto server = make_connected_server_connection();

    const auto processed = server.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedZeroRttPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = server.config_.source_connection_id,
            .source_connection_id = optional_value_or_terminate(server.peer_source_connection_id_),
            .packet_number_length = 2,
            .packet_number = 3,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames =
                {
                    coquic::quic::NewTokenFrame{.token = bytes_from_ints({0xaa})},
                },
        },
        coquic::quic::test::test_time(1));

    ASSERT_FALSE(processed.has_value());
    EXPECT_EQ(processed.error().code,
              coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
    EXPECT_FALSE(server.processed_peer_packet_);
    EXPECT_FALSE(server.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ClientReceivedOneRttPacketDiscardsWriteOnlyZeroRttState) {
    auto client = make_connected_client_connection();
    client.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x66});
    client.zero_rtt_space_.read_secret.reset();

    const auto processed = client.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedOneRttPacket{
            .destination_connection_id = client.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 12,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_FALSE(client.zero_rtt_space_.write_secret.has_value());
    EXPECT_FALSE(client.zero_rtt_space_.read_secret.has_value());
}

TEST(QuicCoreTest, ServerReceivedOneRttPacketDiscardsWriteOnlyZeroRttState) {
    auto server = make_connected_server_connection();
    server.zero_rtt_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x66});
    server.zero_rtt_space_.read_secret.reset();
    server.server_zero_rtt_discard_deadline_.reset();

    const auto processed = server.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedOneRttPacket{
            .destination_connection_id = server.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 13,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_FALSE(server.zero_rtt_space_.write_secret.has_value());
    EXPECT_FALSE(server.zero_rtt_space_.read_secret.has_value());
    EXPECT_FALSE(server.server_zero_rtt_discard_deadline_.has_value());
}

TEST(QuicCoreTest, StartClientWithMalformedResumptionStateMarksZeroRttUnavailable) {
    auto config = coquic::quic::test::make_client_core_config();
    config.zero_rtt.attempt = true;
    config.resumption_state = coquic::quic::QuicResumptionState{
        .serialized = {std::byte{0x01}, std::byte{0x02}},
    };

    coquic::quic::QuicConnection connection(std::move(config));
    connection.start_client_if_needed();

    ASSERT_TRUE(connection.pending_zero_rtt_status_event_.has_value());
    EXPECT_EQ(optional_value_or_terminate(connection.pending_zero_rtt_status_event_).status,
              coquic::quic::QuicZeroRttStatus::unavailable);
}

TEST(QuicCoreTest, StartClientWithVersionMismatchedResumptionStateMarksZeroRttUnavailable) {
    auto warmup_client = coquic::quic::QuicCore(coquic::quic::test::make_client_core_config());
    auto warmup_server = coquic::quic::QuicCore(coquic::quic::test::make_server_core_config());
    const auto transcript = coquic::quic::test::drive_quic_handshake_with_results(
        warmup_client, warmup_server, coquic::quic::test::test_time());
    const auto state = coquic::quic::test::last_resumption_state_from(transcript.client_results);
    ASSERT_TRUE(state.has_value());

    auto resumed_config = coquic::quic::test::make_client_core_config();
    resumed_config.initial_version = coquic::quic::kQuicVersion2;
    resumed_config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};
    resumed_config.resumption_state = optional_value_or_terminate(state);
    resumed_config.zero_rtt.attempt = true;

    coquic::quic::QuicConnection resumed(std::move(resumed_config));
    resumed.start_client_if_needed();

    ASSERT_TRUE(resumed.pending_zero_rtt_status_event_.has_value());
    EXPECT_EQ(optional_value_or_terminate(resumed.pending_zero_rtt_status_event_).status,
              coquic::quic::QuicZeroRttStatus::unavailable);
}

TEST(QuicCoreTest,
     StartClientWithApplicationProtocolMismatchedResumptionStateMarksZeroRttUnavailable) {
    auto warmup_client = coquic::quic::QuicCore(coquic::quic::test::make_client_core_config());
    auto warmup_server = coquic::quic::QuicCore(coquic::quic::test::make_server_core_config());
    const auto transcript = coquic::quic::test::drive_quic_handshake_with_results(
        warmup_client, warmup_server, coquic::quic::test::test_time());
    const auto state = coquic::quic::test::last_resumption_state_from(transcript.client_results);
    ASSERT_TRUE(state.has_value());

    auto resumed_config = coquic::quic::test::make_client_core_config();
    resumed_config.application_protocol = "mismatch";
    resumed_config.resumption_state = optional_value_or_terminate(state);
    resumed_config.zero_rtt.attempt = true;

    coquic::quic::QuicConnection resumed(std::move(resumed_config));
    resumed.start_client_if_needed();

    ASSERT_TRUE(resumed.pending_zero_rtt_status_event_.has_value());
    EXPECT_EQ(optional_value_or_terminate(resumed.pending_zero_rtt_status_event_).status,
              coquic::quic::QuicZeroRttStatus::unavailable);
}

TEST(QuicCoreTest, ServerHandshakeRecoveryAndZeroRttDeadlineHelpersCoverEarlyReturns) {
    auto client = make_connected_client_connection();
    client.status_ = coquic::quic::HandshakeStatus::in_progress;
    client.handshake_confirmed_ = false;
    client.queue_server_handshake_recovery_probes();
    EXPECT_FALSE(client.handshake_space_.pending_probe_packet.has_value());
    client.arm_server_zero_rtt_discard_deadline(coquic::quic::test::test_time(1));
    EXPECT_FALSE(client.server_zero_rtt_discard_deadline_.has_value());

    auto server_with_probe = make_connected_server_connection();
    server_with_probe.status_ = coquic::quic::HandshakeStatus::in_progress;
    server_with_probe.handshake_confirmed_ = false;
    server_with_probe.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 3,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    server_with_probe.queue_server_handshake_recovery_probes();
    ASSERT_TRUE(server_with_probe.handshake_space_.pending_probe_packet.has_value());
    EXPECT_EQ(server_with_probe.handshake_space_.pending_probe_packet->packet_number, 3u);

    auto server_with_crypto = make_connected_server_connection();
    server_with_crypto.status_ = coquic::quic::HandshakeStatus::in_progress;
    server_with_crypto.handshake_confirmed_ = false;
    server_with_crypto.handshake_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("hs"));
    server_with_crypto.queue_server_handshake_recovery_probes();
    EXPECT_FALSE(server_with_crypto.handshake_space_.pending_probe_packet.has_value());

    auto probing_server = make_connected_server_connection();
    probing_server.status_ = coquic::quic::HandshakeStatus::in_progress;
    probing_server.handshake_confirmed_ = false;
    probing_server.track_sent_packet(probing_server.handshake_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 9,
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .has_ping = true,
                                     });
    probing_server.queue_server_handshake_recovery_probes();
    ASSERT_TRUE(probing_server.handshake_space_.pending_probe_packet.has_value());
    EXPECT_EQ(optional_value_or_terminate(probing_server.handshake_space_.pending_probe_packet)
                  .packet_number,
              9u);

    auto server_without_secret = make_connected_server_connection();
    server_without_secret.zero_rtt_space_.read_secret.reset();
    server_without_secret.server_zero_rtt_discard_deadline_.reset();
    server_without_secret.arm_server_zero_rtt_discard_deadline(coquic::quic::test::test_time(2));
    EXPECT_FALSE(server_without_secret.server_zero_rtt_discard_deadline_.has_value());

    auto already_armed = make_connected_server_connection();
    already_armed.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    already_armed.server_zero_rtt_discard_deadline_ = coquic::quic::test::test_time(5);
    already_armed.arm_server_zero_rtt_discard_deadline(coquic::quic::test::test_time(3));
    EXPECT_EQ(already_armed.server_zero_rtt_discard_deadline_, coquic::quic::test::test_time(5));
}

} // namespace
