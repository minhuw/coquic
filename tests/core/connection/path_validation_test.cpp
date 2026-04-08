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

TEST(QuicCoreTest,
     ServerProcessesOneRttPathChallengeBeforeHandshakeCompletesWhenApplicationKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;

    constexpr std::array<std::byte, 8> challenge = {
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};
    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .key_phase = false,
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 1,
            .packet_number = 7,
            .frames =
                {
                    coquic::quic::AckFrame{},
                    coquic::quic::PathChallengeFrame{
                        .data = challenge,
                    },
                    coquic::quic::PingFrame{},
                },
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(processed.value());
    EXPECT_FALSE(connection.has_failed());
    ASSERT_TRUE(connection.paths_.contains(0));
    ASSERT_TRUE(connection.paths_.at(0).pending_response.has_value());
    EXPECT_EQ(optional_ref_or_terminate(connection.paths_.at(0).pending_response), challenge);
}

TEST(QuicCoreTest, PreconnectedPathResponseWithoutApplicationKeysIsRejectedWhilePaddingIsIgnored) {
    {
        auto connection = make_connected_client_connection();
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.application_space_.read_secret.reset();

        const auto processed = connection.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{
                coquic::quic::PathResponseFrame{
                    .data =
                        {
                            std::byte{0x01},
                            std::byte{0x02},
                            std::byte{0x03},
                            std::byte{0x04},
                            std::byte{0x05},
                            std::byte{0x06},
                            std::byte{0x07},
                            std::byte{0x08},
                        },
                },
            },
            coquic::quic::test::test_time(1));

        ASSERT_FALSE(processed.has_value());
        EXPECT_EQ(processed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
    }

    {
        auto connection = make_connected_client_connection();
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.application_space_.read_secret.reset();

        const auto processed = connection.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{
                coquic::quic::PaddingFrame{},
            },
            coquic::quic::test::test_time(1));

        ASSERT_TRUE(processed.has_value());
        EXPECT_TRUE(processed.value());
    }
}

TEST(QuicCoreTest, PreconnectedPathResponseIsAcceptedWhenApplicationKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;

    constexpr std::array<std::byte, 8> challenge = {
        std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34},
        std::byte{0x35}, std::byte{0x36}, std::byte{0x37}, std::byte{0x38}};
    auto &candidate_path = connection.ensure_path_state(9);
    candidate_path.validated = false;
    candidate_path.challenge_pending = false;
    candidate_path.validation_initiated_locally = false;
    candidate_path.outstanding_challenge = challenge;

    const auto processed = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::PathResponseFrame{
                .data = challenge,
            },
        },
        coquic::quic::test::test_time(1), /*allow_preconnected_frames=*/false, /*path_id=*/9);
    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(processed.value());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.paths_.at(9).validated);
    EXPECT_EQ(connection.last_validated_path_id_, 9u);
    EXPECT_EQ(connection.current_send_path_id_, 9u);
}

TEST(QuicCoreTest, ApplicationSendAckOnlyFallbackCarriesPathValidationFrames) {
    bool saw_ack_only_path_validation_fallback = false;

    for (std::uint64_t received_bytes = 10; received_bytes <= 80; ++received_bytes) {
        auto connection = make_connected_server_connection();
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = false;
        connection.last_validated_path_id_ = 3;
        connection.current_send_path_id_ = 3;
        connection.ensure_path_state(3).validated = true;
        connection.ensure_path_state(3).is_current_send_path = true;
        auto &response_path = connection.ensure_path_state(7);
        response_path.validated = false;
        response_path.is_current_send_path = false;
        response_path.validation_initiated_locally = false;
        response_path.anti_amplification_received_bytes = received_bytes;
        response_path.pending_response =
            std::array{std::byte{0x51}, std::byte{0x52}, std::byte{0x53}, std::byte{0x54},
                       std::byte{0x55}, std::byte{0x56}, std::byte{0x57}, std::byte{0x58}};
        response_path.challenge_pending = true;
        response_path.outstanding_challenge =
            std::array{std::byte{0x61}, std::byte{0x62}, std::byte{0x63}, std::byte{0x64},
                       std::byte{0x65}, std::byte{0x66}, std::byte{0x67}, std::byte{0x68}};
        connection.application_space_.received_packets.record_received(
            /*packet_number=*/43, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
        ASSERT_TRUE(
            connection.queue_stream_send(0, std::vector<std::byte>(256, std::byte{0x60}), false)
                .has_value());

        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (connection.has_failed() || datagram.empty()) {
            continue;
        }

        const auto packets = decode_sender_datagram(connection, datagram);
        ASSERT_EQ(packets.size(), 1u);
        const auto *application =
            std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
        ASSERT_NE(application, nullptr);

        bool saw_ack = false;
        bool saw_stream = false;
        bool saw_path_response = false;
        bool saw_path_challenge = false;
        for (const auto &frame : application->frames) {
            saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
            saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
            saw_path_response =
                saw_path_response || std::holds_alternative<coquic::quic::PathResponseFrame>(frame);
            saw_path_challenge = saw_path_challenge ||
                                 std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
        }

        if (saw_ack && !saw_stream && saw_path_response && saw_path_challenge &&
            connection.has_pending_application_send()) {
            saw_ack_only_path_validation_fallback = true;
            break;
        }
    }

    EXPECT_TRUE(saw_ack_only_path_validation_fallback);
}

TEST(QuicCoreTest, ApplicationSendAckOnlyFallbackCarriesCurrentPathValidationFrames) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 7;
    connection.current_send_path_id_ = 7;
    auto &current_path = connection.ensure_path_state(7);
    current_path.validated = true;
    current_path.is_current_send_path = true;
    current_path.pending_response =
        std::array{std::byte{0x51}, std::byte{0x52}, std::byte{0x53}, std::byte{0x54},
                   std::byte{0x55}, std::byte{0x56}, std::byte{0x57}, std::byte{0x58}};
    current_path.challenge_pending = true;
    current_path.outstanding_challenge =
        std::array{std::byte{0x61}, std::byte{0x62}, std::byte{0x63}, std::byte{0x64},
                   std::byte{0x65}, std::byte{0x66}, std::byte{0x67}, std::byte{0x68}};

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

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());
    ASSERT_TRUE(connection.paths_.contains(7));
    EXPECT_FALSE(connection.paths_.at(7).pending_response.has_value());
    EXPECT_FALSE(connection.paths_.at(7).challenge_pending);

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_stream = false;
    bool saw_path_response = false;
    bool saw_path_challenge = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
        saw_path_response =
            saw_path_response || std::holds_alternative<coquic::quic::PathResponseFrame>(frame);
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_FALSE(saw_stream);
    EXPECT_TRUE(saw_path_response);
    EXPECT_TRUE(saw_path_challenge);
}

TEST(QuicCoreTest, PathChallengeRequiresConnectedStateWithoutApplicationKeys) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    constexpr std::array<std::byte, 8> challenge = {
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    const auto processed = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::PathChallengeFrame{
                .data = challenge,
            },
        },
        coquic::quic::test::test_time(0));

    ASSERT_FALSE(processed.has_value());
    EXPECT_EQ(processed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest, PathValidationFramesAreAllowedDuringHandshakeWhenApplicationKeysExist) {
    constexpr std::array<std::byte, 8> challenge = {
        std::byte{0x11}, std::byte{0x12}, std::byte{0x13}, std::byte{0x14},
        std::byte{0x15}, std::byte{0x16}, std::byte{0x17}, std::byte{0x18}};

    auto challenge_connection = make_connected_client_connection();
    challenge_connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    challenge_connection.handshake_confirmed_ = false;

    const auto challenge_processed = challenge_connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::PathChallengeFrame{
                .data = challenge,
            },
        },
        coquic::quic::test::test_time(0));
    ASSERT_TRUE(challenge_processed.has_value());

    auto response_connection = make_connected_client_connection();
    response_connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    response_connection.handshake_confirmed_ = false;
    response_connection.start_path_validation(7, /*initiated_locally=*/true);
    const auto outstanding_challenge =
        optional_ref_or_terminate(response_connection.paths_.at(7).outstanding_challenge);

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        response_connection, 7,
        {coquic::quic::PathResponseFrame{
            .data = outstanding_challenge,
        }}));
    EXPECT_TRUE(response_connection.paths_.at(7).validated);
}

TEST(QuicCoreTest, ClientTimerAfterLargePartialResponseFlowAddsPathChallengeOnProbe) {
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

    bool saw_path_challenge = false;
    for (const auto &datagram : timeout_datagrams) {
        for (const auto &packet : decode_sender_datagram(*client.connection_, datagram)) {
            const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (application == nullptr) {
                continue;
            }
            for (const auto &frame : application->frames) {
                saw_path_challenge =
                    saw_path_challenge ||
                    std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
            }
        }
    }

    EXPECT_TRUE(saw_path_challenge);
}

TEST(QuicCoreTest, ClientTimerAfterLargePartialResponseFlowRetainsPathChallengeAcrossPtoBurst) {
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

    const auto deadline_value = optional_value_or_terminate(deadline);
    client.connection_->on_timeout(deadline_value);

    const auto first_probe_datagram = client.connection_->drain_outbound_datagram(deadline_value);
    ASSERT_FALSE(first_probe_datagram.empty());
    const auto second_probe_datagram = client.connection_->drain_outbound_datagram(deadline_value);
    ASSERT_FALSE(second_probe_datagram.empty());

    bool first_has_ack = false;
    bool first_has_path_challenge = false;
    for (const auto &packet : decode_sender_datagram(*client.connection_, first_probe_datagram)) {
        const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
        if (application == nullptr) {
            continue;
        }

        for (const auto &frame : application->frames) {
            first_has_ack = first_has_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
            first_has_path_challenge =
                first_has_path_challenge ||
                std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
        }
    }

    bool second_has_ack = false;
    bool second_has_path_challenge = false;
    for (const auto &packet : decode_sender_datagram(*client.connection_, second_probe_datagram)) {
        const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
        if (application == nullptr) {
            continue;
        }

        for (const auto &frame : application->frames) {
            second_has_ack =
                second_has_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
            second_has_path_challenge =
                second_has_path_challenge ||
                std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
        }
    }

    EXPECT_TRUE(first_has_ack);
    EXPECT_TRUE(first_has_path_challenge);
    EXPECT_TRUE(second_has_ack);
    EXPECT_TRUE(second_has_path_challenge);
}

TEST(QuicCoreTest, PathChallengeQueuesMatchingPathResponseOnSamePath) {
    auto connection = make_connected_server_connection();
    constexpr std::array<std::byte, 8> challenge = {
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9, {coquic::quic::PathChallengeFrame{.data = challenge}}));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);
}

TEST(QuicCoreTest, FirstServerResponseToProbingPacketOnNewPathAlsoIncludesPathChallenge) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    constexpr std::array<std::byte, 8> challenge = {
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};
    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9, {coquic::quic::PathChallengeFrame{.data = challenge}}));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *first_packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(first_packet, nullptr);

    bool saw_path_response = false;
    bool saw_path_challenge = false;
    for (const auto &frame : first_packet->frames) {
        saw_path_response =
            saw_path_response || std::holds_alternative<coquic::quic::PathResponseFrame>(frame);
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_path_response);
    EXPECT_TRUE(saw_path_challenge);
}

TEST(QuicCoreTest, ApplicationProbeOnNewPathIncludesPathChallenge) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 7,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = coquic::quic::SharedBytes(
                        coquic::quic::test::bytes_from_string("probe-data")),
                    .fin = false,
                    .consumes_flow_control = false,
                },
            },
    };

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9, {coquic::quic::PingFrame{}}));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *first_packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(first_packet, nullptr);

    bool saw_path_challenge = false;
    for (const auto &frame : first_packet->frames) {
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_path_challenge);
}

TEST(QuicCoreTest, ApplicationProbeRetainsPendingPathValidationFramesAcrossPtoBurst) {
    auto connection = make_connected_client_connection();
    connection.last_validated_path_id_ = 9;
    connection.current_send_path_id_ = 9;
    connection.ensure_path_state(9).validated = true;
    connection.ensure_path_state(9).is_current_send_path = true;
    connection.ensure_path_state(9).pending_response =
        std::array{std::byte{0x21}, std::byte{0x22}, std::byte{0x23}, std::byte{0x24},
                   std::byte{0x25}, std::byte{0x26}, std::byte{0x27}, std::byte{0x28}};
    connection.ensure_path_state(9).challenge_pending = true;
    connection.ensure_path_state(9).outstanding_challenge =
        std::array{std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34},
                   std::byte{0x35}, std::byte{0x36}, std::byte{0x37}, std::byte{0x38}};
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 12,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    connection.remaining_pto_probe_datagrams_ = 2;

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *first_packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(first_packet, nullptr);

    bool saw_path_response = false;
    bool saw_path_challenge = false;
    for (const auto &frame : first_packet->frames) {
        saw_path_response =
            saw_path_response || std::holds_alternative<coquic::quic::PathResponseFrame>(frame);
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_path_response);
    EXPECT_TRUE(saw_path_challenge);
    ASSERT_TRUE(connection.paths_.at(9).pending_response.has_value());
    EXPECT_TRUE(connection.paths_.at(9).challenge_pending);
}

TEST(QuicCoreTest, ApplicationProbeIgnoresMissingCurrentSendPathValidationState) {
    auto connection = make_connected_client_connection();
    connection.current_send_path_id_ = 77;
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 19,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.paths_.contains(77));

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

TEST(QuicCoreTest, AckOnlyResponseOnNewPathStillIncludesPathChallenge) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    const auto datagram = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 17,
                .frames =
                    {
                        coquic::quic::PingFrame{},
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(datagram.has_value());

    connection.process_inbound_datagram(datagram.value(), coquic::quic::test::test_time(1),
                                        /*path_id=*/9);

    connection.on_timeout(coquic::quic::test::test_time(2));

    const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(response.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);

    const auto packets = decode_sender_datagram(connection, response);
    ASSERT_EQ(packets.size(), 1u);
    const auto *first_packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(first_packet, nullptr);

    bool saw_ack = false;
    bool saw_path_challenge = false;
    for (const auto &frame : first_packet->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_path_challenge);
}

TEST(QuicCoreTest, AckOnlyResponseOnNewPathAlsoIncludesPathResponse) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/17, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));

    constexpr std::array<std::byte, 8> challenge = {
        std::byte{0x41}, std::byte{0x42}, std::byte{0x43}, std::byte{0x44},
        std::byte{0x45}, std::byte{0x46}, std::byte{0x47}, std::byte{0x48}};
    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9,
        {
            coquic::quic::PingFrame{},
            coquic::quic::PathChallengeFrame{.data = challenge},
        }));

    const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(response.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);

    const auto packets = decode_sender_datagram(connection, response);
    ASSERT_EQ(packets.size(), 1u);
    const auto *first_packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(first_packet, nullptr);

    bool saw_ack = false;
    bool saw_path_response = false;
    bool saw_path_challenge = false;
    for (const auto &frame : first_packet->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_path_response =
            saw_path_response || std::holds_alternative<coquic::quic::PathResponseFrame>(frame);
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_path_response);
    EXPECT_TRUE(saw_path_challenge);
}

TEST(QuicCoreTest, ServerOneRttPacketOnNewPathStillRequiresPathValidation) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    const auto datagram = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 17,
                .frames =
                    {
                        coquic::quic::PingFrame{},
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(datagram.has_value());

    connection.process_inbound_datagram(datagram.value(), coquic::quic::test::test_time(1),
                                        /*path_id=*/9);

    ASSERT_TRUE(connection.paths_.contains(9));
    EXPECT_FALSE(connection.paths_.at(9).validated);
    EXPECT_TRUE(connection.paths_.at(9).outstanding_challenge.has_value());

    const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(response.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);

    const auto packets = decode_sender_datagram(connection, response);
    ASSERT_EQ(packets.size(), 1u);
    const auto *first_packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(first_packet, nullptr);

    bool saw_path_challenge = false;
    for (const auto &frame : first_packet->frames) {
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_path_challenge);
}

TEST(QuicCoreTest, FirstServerResponseOnMigratedPathIncludesPathChallengeAlongsidePathResponse) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;
    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string("migration-response"), false)
                    .has_value());

    constexpr std::array<std::byte, 8> challenge = {
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};
    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9,
        {
            coquic::quic::PingFrame{},
            coquic::quic::PathChallengeFrame{.data = challenge},
        }));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *first_packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(first_packet, nullptr);

    bool saw_path_response = false;
    bool saw_path_challenge = false;
    for (const auto &frame : first_packet->frames) {
        saw_path_response =
            saw_path_response || std::holds_alternative<coquic::quic::PathResponseFrame>(frame);
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_path_response);
    EXPECT_TRUE(saw_path_challenge);
}

TEST(QuicCoreTest, MatchingPathResponseValidatesCandidatePath) {
    auto connection = make_connected_client_connection();
    connection.start_path_validation(7, /*initiated_locally=*/true);
    const auto challenge = optional_ref_or_terminate(connection.paths_.at(7).outstanding_challenge);

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 7, {coquic::quic::PathResponseFrame{.data = challenge}}));

    ASSERT_TRUE(connection.paths_.contains(7));
    EXPECT_TRUE(connection.paths_.at(7).validated);
    EXPECT_EQ(connection.last_validated_path_id_, 7u);
}

TEST(QuicCoreTest, MatchingPathResponseSwitchesCurrentSendPathToValidatedPath) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    constexpr std::array<std::byte, 8> outstanding_challenge = {
        std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34},
        std::byte{0x35}, std::byte{0x36}, std::byte{0x37}, std::byte{0x38}};
    auto &candidate_path = connection.ensure_path_state(9);
    candidate_path.validated = false;
    candidate_path.challenge_pending = false;
    candidate_path.validation_initiated_locally = false;
    candidate_path.outstanding_challenge = outstanding_challenge;

    const auto processed = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::PathResponseFrame{
                .data = outstanding_challenge,
            },
        },
        coquic::quic::test::test_time(1), /*allow_preconnected_frames=*/false, /*path_id=*/9);
    ASSERT_TRUE(processed.has_value());

    EXPECT_TRUE(connection.paths_.at(9).validated);
    EXPECT_EQ(connection.last_validated_path_id_, 9u);
    EXPECT_EQ(connection.current_send_path_id_, 9u);
    EXPECT_FALSE(connection.paths_.at(3).is_current_send_path);
    EXPECT_TRUE(connection.paths_.at(9).is_current_send_path);
}

TEST(QuicCoreTest, RepeatedPathValidationUsesFreshChallengeData) {
    auto connection = make_connected_client_connection();

    connection.start_path_validation(7, /*initiated_locally=*/true);
    ASSERT_TRUE(connection.paths_.contains(7));
    ASSERT_TRUE(connection.paths_.at(7).outstanding_challenge.has_value());
    const auto first_challenge =
        optional_ref_or_terminate(connection.paths_.at(7).outstanding_challenge);

    connection.paths_.at(7).challenge_pending = false;
    connection.paths_.at(7).outstanding_challenge.reset();

    connection.start_path_validation(7, /*initiated_locally=*/true);
    ASSERT_TRUE(connection.paths_.at(7).outstanding_challenge.has_value());
    const auto second_challenge =
        optional_ref_or_terminate(connection.paths_.at(7).outstanding_challenge);

    EXPECT_NE(first_challenge, second_challenge);
}

TEST(QuicCoreTest, MatchingPathResponseValidatesChallengedPathAcrossInboundPathIds) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9, {coquic::quic::PingFrame{}}));

    const auto validation_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(validation_datagram.empty());
    ASSERT_TRUE(connection.paths_.contains(9));
    ASSERT_TRUE(connection.paths_.at(9).outstanding_challenge.has_value());
    const auto outstanding_challenge =
        optional_ref_or_terminate(connection.paths_.at(9).outstanding_challenge);

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 11, {coquic::quic::PathResponseFrame{.data = outstanding_challenge}}));

    ASSERT_TRUE(connection.paths_.contains(9));
    EXPECT_TRUE(connection.paths_.at(9).validated);
    EXPECT_EQ(connection.last_validated_path_id_, 9u);
    EXPECT_EQ(connection.current_send_path_id_, 9u);
}

TEST(QuicCoreTest, DuplicateSerializedPathResponseOnlyPacketsDoNotFailMigratedServerPath) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9, {coquic::quic::PingFrame{}}));
    const auto validation_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(validation_datagram.empty());
    ASSERT_TRUE(connection.paths_.contains(9));
    ASSERT_TRUE(connection.paths_.at(9).outstanding_challenge.has_value());
    const auto outstanding_challenge =
        optional_ref_or_terminate(connection.paths_.at(9).outstanding_challenge);

    const auto make_path_response = [&](std::uint64_t packet_number) {
        return coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames =
                        {
                            coquic::quic::PathResponseFrame{
                                .data = outstanding_challenge,
                            },
                        },
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::client,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret = connection.application_space_.read_secret,
            });
    };

    const auto first_response = make_path_response(90);
    ASSERT_TRUE(first_response.has_value());
    connection.process_inbound_datagram(first_response.value(), coquic::quic::test::test_time(2),
                                        /*path_id=*/9);

    ASSERT_FALSE(connection.has_failed());
    ASSERT_TRUE(connection.paths_.at(9).validated);
    EXPECT_EQ(connection.last_validated_path_id_, 9u);
    EXPECT_EQ(connection.current_send_path_id_, 9u);

    const auto duplicate_response = make_path_response(91);
    ASSERT_TRUE(duplicate_response.has_value());
    connection.process_inbound_datagram(duplicate_response.value(),
                                        coquic::quic::test::test_time(3), /*path_id=*/9);

    EXPECT_FALSE(connection.has_failed());
    ASSERT_TRUE(connection.paths_.contains(9));
    EXPECT_TRUE(connection.paths_.at(9).validated);
    EXPECT_EQ(connection.last_validated_path_id_, 9u);
    EXPECT_EQ(connection.current_send_path_id_, 9u);
}

TEST(QuicCoreTest, LiveLikePathResponseBurstKeepsMigratedServerSending) {
    auto connection = make_connected_server_connection();
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

    const auto serialize_client_packet = [&](std::uint64_t packet_number,
                                             std::vector<coquic::quic::Frame> frames) {
        return coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .key_phase = connection.application_read_key_phase_,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames = std::move(frames),
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::client,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret = connection.application_space_.read_secret,
                .one_rtt_key_phase = connection.application_read_key_phase_,
            });
    };
    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 11, {coquic::quic::PingFrame{}}));
    ASSERT_TRUE(connection.paths_.contains(11));
    ASSERT_TRUE(connection.paths_.at(11).outstanding_challenge.has_value());

    const auto first_migrated_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(100));
    ASSERT_FALSE(first_migrated_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 11u);

    const auto first_packets = decode_sender_datagram(connection, first_migrated_datagram);
    ASSERT_EQ(first_packets.size(), 1u);
    const auto *first_packet =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&first_packets.front());
    ASSERT_NE(first_packet, nullptr);

    std::optional<std::array<std::byte, 8>> challenge;
    for (const auto &frame : first_packet->frames) {
        if (const auto *path_challenge = std::get_if<coquic::quic::PathChallengeFrame>(&frame)) {
            challenge = path_challenge->data;
        }
    }
    ASSERT_TRUE(challenge.has_value());

    const auto process_client_packet = [&](std::uint64_t packet_number,
                                           std::vector<coquic::quic::Frame> frames,
                                           coquic::quic::QuicCoreTimePoint at) {
        const auto encoded = serialize_client_packet(packet_number, std::move(frames));
        ASSERT_TRUE(encoded.has_value());
        connection.process_inbound_datagram(encoded.value(), at, /*path_id=*/11);
    };

    const auto challenge_value = optional_value_or_terminate(challenge);
    process_client_packet(4295,
                          {
                              coquic::quic::PathResponseFrame{.data = challenge_value},
                          },
                          coquic::quic::test::test_time(300));
    process_client_packet(4296, {coquic::quic::PathResponseFrame{.data = challenge_value}},
                          coquic::quic::test::test_time(301));
    process_client_packet(4297, {coquic::quic::PathResponseFrame{.data = challenge_value}},
                          coquic::quic::test::test_time(302));
    process_client_packet(4298, {coquic::quic::PathResponseFrame{.data = challenge_value}},
                          coquic::quic::test::test_time(303));

    ASSERT_FALSE(connection.has_failed());
    ASSERT_TRUE(connection.paths_.contains(11));
    EXPECT_TRUE(connection.paths_.at(11).validated);
    EXPECT_EQ(connection.last_validated_path_id_, 11u);
    EXPECT_EQ(connection.current_send_path_id_, 11u);

    const auto resumed_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(304));
    ASSERT_FALSE(resumed_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 11u);

    bool saw_stream_frame = false;
    for (const auto &packet : decode_sender_datagram(connection, resumed_datagram)) {
        const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
        if (one_rtt == nullptr) {
            continue;
        }
        for (const auto &frame : one_rtt->frames) {
            saw_stream_frame =
                saw_stream_frame || std::holds_alternative<coquic::quic::StreamFrame>(frame);
        }
    }

    EXPECT_TRUE(saw_stream_frame);
}

TEST(QuicCoreTest, MismatchedPathResponseDoesNotValidatePath) {
    auto connection = make_connected_client_connection();
    connection.start_path_validation(7, /*initiated_locally=*/true);

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 7,
        {coquic::quic::PathResponseFrame{
            .data = {std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}, std::byte{0xdd},
                     std::byte{0xee}, std::byte{0xff}, std::byte{0x11}, std::byte{0x22}},
        }}));

    ASSERT_TRUE(connection.paths_.contains(7));
    EXPECT_FALSE(connection.paths_.at(7).validated);
}

TEST(QuicCoreTest, NewPathNonProbingPacketStartsValidationAndSwitchesSendPath) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9,
        {coquic::quic::PingFrame{}, coquic::quic::MaxDataFrame{.maximum_data = 1024}}));

    EXPECT_EQ(connection.current_send_path_id_, 9u);
    ASSERT_TRUE(connection.paths_.contains(9));
    EXPECT_TRUE(connection.paths_.at(9).outstanding_challenge.has_value());
}

TEST(QuicCoreTest, ProbingOnlyPacketOnNewPathDoesNotSwitchSendPath) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9, {coquic::quic::PathChallengeFrame{}}));

    EXPECT_EQ(connection.current_send_path_id_, 3u);
}

TEST(QuicCoreTest, SendingPathValidationResponseAdoptsNewSendPath) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    const auto inbound_challenge = std::array{
        std::byte{0x20}, std::byte{0x21}, std::byte{0x22}, std::byte{0x23},
        std::byte{0x24}, std::byte{0x25}, std::byte{0x26}, std::byte{0x27},
    };
    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9, {coquic::quic::PathChallengeFrame{.data = inbound_challenge}}));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);
    EXPECT_EQ(connection.current_send_path_id_, 9u);
    ASSERT_TRUE(connection.paths_.contains(9));
    EXPECT_FALSE(connection.paths_.at(9).validated);
}

TEST(QuicCoreTest, PtoOnUnvalidatedMigratedPathRearmsPathChallenge) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(3000, 'm')), false)
                    .has_value());
    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9, {coquic::quic::PingFrame{}}));
    connection.ensure_path_state(9).anti_amplification_received_bytes = 4000;

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);

    const auto first_packets = decode_sender_datagram(connection, first_datagram);
    ASSERT_EQ(first_packets.size(), 1u);
    const auto *first_packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&first_packets[0]);
    ASSERT_NE(first_packet, nullptr);

    bool first_has_path_challenge = false;
    for (const auto &frame : first_packet->frames) {
        first_has_path_challenge = first_has_path_challenge ||
                                   std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }
    EXPECT_TRUE(first_has_path_challenge);

    connection.on_timeout(coquic::quic::test::test_time(1000));
    ASSERT_TRUE(connection.paths_.contains(9));
    EXPECT_TRUE(connection.paths_.at(9).challenge_pending);

    const auto second_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1000));
    ASSERT_FALSE(second_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);

    const auto second_packets = decode_sender_datagram(connection, second_datagram);
    ASSERT_EQ(second_packets.size(), 1u);
    const auto *second_packet =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&second_packets[0]);
    ASSERT_NE(second_packet, nullptr);

    bool second_has_path_challenge = false;
    for (const auto &frame : second_packet->frames) {
        second_has_path_challenge = second_has_path_challenge ||
                                    std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }
    EXPECT_TRUE(second_has_path_challenge);
}

TEST(QuicCoreTest, UnvalidatedMigratedPathDoesNotRepeatPathChallengeBeforePto) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(4096, 'm')), false)
                    .has_value());
    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9, {coquic::quic::PingFrame{}}));
    connection.ensure_path_state(9).anti_amplification_received_bytes = 4000;

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);

    const auto first_packets = decode_sender_datagram(connection, first_datagram);
    ASSERT_EQ(first_packets.size(), 1u);
    const auto *first_packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&first_packets[0]);
    ASSERT_NE(first_packet, nullptr);

    std::optional<std::array<std::byte, 8>> first_challenge;
    for (const auto &frame : first_packet->frames) {
        if (const auto *path_challenge = std::get_if<coquic::quic::PathChallengeFrame>(&frame)) {
            first_challenge = path_challenge->data;
        }
    }
    ASSERT_TRUE(first_challenge.has_value());
    EXPECT_FALSE(connection.paths_.at(9).challenge_pending);

    const auto second_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    EXPECT_TRUE(second_datagram.empty());
    EXPECT_FALSE(connection.paths_.at(9).challenge_pending);
}

TEST(QuicCoreTest, FailedPathValidationRevertsToLastValidatedPath) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 9;
    connection.previous_path_id_ = 3;
    connection.ensure_path_state(9).validation_deadline = coquic::quic::test::test_time(1);

    connection.on_timeout(coquic::quic::test::test_time(2));

    EXPECT_EQ(connection.current_send_path_id_, 3u);
}

} // namespace
