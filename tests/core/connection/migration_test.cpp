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

bool connection_additional_internal_coverage_for_tests() {
    bool ok = true;

    {
        auto connection = make_connected_client_connection();
        connection.streams_.emplace(
            0, coquic::quic::make_implicit_stream_state(0, connection.config_.role));
        connection.current_send_path_id_ = 7;
        auto &current_path = connection.ensure_path_state(7);
        current_path.validated = true;
        current_path.is_current_send_path = true;
        current_path.outstanding_challenge.reset();
        connection.last_peer_activity_time_ = coquic::quic::test::test_time(0);

        connection.arm_pto_probe(coquic::quic::test::test_time(0));
        ok &= !connection.application_space_.pending_probe_packet.has_value();

        connection.arm_pto_probe(coquic::quic::test::test_time(10'000));
        const bool has_probe_packet =
            connection.application_space_.pending_probe_packet.has_value();
        ok &= has_probe_packet;
        ok &= has_probe_packet ? connection.application_space_.pending_probe_packet->force_ack
                               : false;
        ok &= connection.paths_.at(7).challenge_pending;
        ok &= connection.paths_.at(7).outstanding_challenge.has_value();
    }

    {
        auto connection = make_connected_client_connection();
        connection.streams_.emplace(
            0, coquic::quic::make_implicit_stream_state(0, connection.config_.role));
        connection.current_send_path_id_.reset();
        connection.last_peer_activity_time_ = coquic::quic::test::test_time(0);

        connection.arm_pto_probe(coquic::quic::test::test_time(10'000));
        const bool has_probe_packet =
            connection.application_space_.pending_probe_packet.has_value();
        ok &= has_probe_packet;
        ok &= has_probe_packet ? connection.application_space_.pending_probe_packet->force_ack
                               : false;
    }

    {
        auto connection = make_connected_client_connection();
        connection.streams_.emplace(
            0, coquic::quic::make_implicit_stream_state(0, connection.config_.role));
        connection.current_send_path_id_ = 7;
        auto &current_path = connection.ensure_path_state(7);
        current_path.validated = false;
        current_path.is_current_send_path = true;
        current_path.outstanding_challenge.reset();
        connection.last_peer_activity_time_ = coquic::quic::test::test_time(0);

        connection.arm_pto_probe(coquic::quic::test::test_time(10'000));
        const bool has_probe_packet =
            connection.application_space_.pending_probe_packet.has_value();
        ok &= has_probe_packet;
        ok &= has_probe_packet ? connection.application_space_.pending_probe_packet->force_ack
                               : false;
        ok &= !connection.paths_.at(7).challenge_pending;
        ok &= !connection.paths_.at(7).outstanding_challenge.has_value();
    }

    {
        auto connection = make_connected_client_connection();
        connection.streams_.emplace(
            0, coquic::quic::make_implicit_stream_state(0, connection.config_.role));
        connection.current_send_path_id_ = 7;
        auto &current_path = connection.ensure_path_state(7);
        current_path.validated = true;
        current_path.is_current_send_path = true;
        const auto existing_challenge = connection.next_path_challenge_data(7);
        current_path.outstanding_challenge = existing_challenge;
        connection.last_peer_activity_time_ = coquic::quic::test::test_time(0);

        connection.arm_pto_probe(coquic::quic::test::test_time(10'000));
        const bool has_probe_packet =
            connection.application_space_.pending_probe_packet.has_value();
        ok &= has_probe_packet;
        ok &= has_probe_packet ? connection.application_space_.pending_probe_packet->force_ack
                               : false;
        ok &= connection.paths_.at(7).challenge_pending;
        ok &= connection.paths_.at(7).outstanding_challenge.has_value();
        ok &= optional_ref_or_terminate(connection.paths_.at(7).outstanding_challenge) ==
              existing_challenge;
    }

    {
        auto connection = make_connected_client_connection();
        const std::array frames = {
            coquic::quic::Frame{coquic::quic::AckFrame{
                .largest_acknowledged = 0,
                .first_ack_range = 0,
            }},
        };
        const auto result = connection.process_inbound_application(
            frames, coquic::quic::test::test_time(0), /*allow_preconnected_frames=*/false,
            /*path_id=*/9);
        const bool processed = result.has_value() && result.value();
        ok &= processed;
        ok &= connection.paths_.contains(9);
    }

    {
        auto connection = make_connected_client_connection();
        connection.paths_.clear();
        connection.current_send_path_id_.reset();
        const std::array frames = {
            coquic::quic::Frame{coquic::quic::AckFrame{
                .largest_acknowledged = 0,
                .first_ack_range = 0,
            }},
        };
        const auto result = connection.process_inbound_application(
            frames, coquic::quic::test::test_time(0), /*allow_preconnected_frames=*/false,
            /*path_id=*/9);
        ok &= result.has_value() && result.value();
        ok &= connection.paths_.contains(9);
    }

    {
        auto connection = make_connected_client_connection();
        connection.local_key_update_requested_ = true;
        connection.local_key_update_initiated_ = false;
        connection.current_write_phase_first_packet_number_.reset();
        const std::array payload = {std::byte{0x01}};
        const auto queued = connection.queue_stream_send(0, payload, /*fin=*/false);
        ok &= queued.has_value();
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        ok &= !datagram.empty();
        ok &= connection.current_write_phase_first_packet_number_.has_value();
    }

    {
        auto connection = make_connected_client_connection();
        connection.current_send_path_id_.reset();
        connection.start_path_validation(/*path_id=*/9, /*initiated_locally=*/false);
        ok &= connection.current_send_path_id_ == std::optional<coquic::quic::QuicPathId>{9};
        ok &= connection.paths_.contains(9);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(9);
        path.validated = true;
        connection.current_send_path_id_.reset();
        connection.maybe_switch_to_path(/*path_id=*/9, /*initiated_locally=*/false);
        ok &= connection.current_send_path_id_ == std::optional<coquic::quic::QuicPathId>{9};
        ok &= connection.paths_.at(9).is_current_send_path;
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(9);
        path.validated = true;
        connection.current_send_path_id_ = 11;
        connection.paths_.erase(11);
        connection.maybe_switch_to_path(/*path_id=*/9, /*initiated_locally=*/false);
        ok &= connection.previous_path_id_ == std::optional<coquic::quic::QuicPathId>{11};
        ok &= connection.current_send_path_id_ == std::optional<coquic::quic::QuicPathId>{9};
        ok &= connection.paths_.at(9).is_current_send_path;
    }

    {
        auto connection = make_connected_client_connection();
        connection.current_send_path_id_.reset();
        auto &response_path = connection.ensure_path_state(9);
        response_path.validated = false;
        response_path.pending_response = connection.next_path_challenge_data(9);
        const std::array payload = {std::byte{0x02}};
        ok &= connection.queue_stream_send(0, payload, /*fin=*/false).has_value();
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        ok &= !datagram.empty();
        ok &= connection.current_send_path_id_ == std::optional<coquic::quic::QuicPathId>{9};
        ok &= connection.paths_.at(9).is_current_send_path;
    }

    {
        auto connection = make_connected_client_connection();
        connection.current_send_path_id_ = 11;
        connection.paths_.erase(11);
        auto &response_path = connection.ensure_path_state(9);
        response_path.validated = false;
        response_path.pending_response = connection.next_path_challenge_data(9);
        const std::array payload = {std::byte{0x03}};
        ok &= connection.queue_stream_send(0, payload, /*fin=*/false).has_value();
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        ok &= !datagram.empty();
        ok &= connection.previous_path_id_ == std::optional<coquic::quic::QuicPathId>{11};
        ok &= connection.current_send_path_id_ == std::optional<coquic::quic::QuicPathId>{9};
        ok &= connection.paths_.at(9).is_current_send_path;
    }

    {
        auto connection = make_connected_client_connection();
        connection.streams_.emplace(
            1, coquic::quic::make_implicit_stream_state(1, connection.config_.role));
        connection.retired_streams_.emplace(
            3, coquic::quic::make_implicit_stream_state(3, connection.config_.role));
        const auto *active = connection.find_stream_state(1);
        const auto *retired = connection.find_stream_state(3);
        const auto *missing = connection.find_stream_state(5);
        const auto &const_connection = connection;
        ok &= active == &connection.streams_.at(1);
        ok &= retired == &connection.retired_streams_.at(3);
        ok &= missing == nullptr;
        ok &= const_connection.find_stream_state(1) == &connection.streams_.at(1);
        ok &= const_connection.find_stream_state(3) == &connection.retired_streams_.at(3);
        ok &= const_connection.find_stream_state(5) == nullptr;
        connection.maybe_retire_stream(5);
        ok &= !connection.retired_streams_.contains(5);
    }

    {
        auto connection = make_connected_client_connection();
        auto &stream =
            connection.streams_
                .emplace(3, coquic::quic::make_implicit_stream_state(3, connection.config_.role))
                .first->second;
        stream.peer_fin_delivered = true;

        connection.maybe_refresh_peer_stream_limit(stream);

        ok &= stream.peer_stream_limit_released;
        ok &= connection.local_stream_limit_state_.max_streams_uni_state ==
              coquic::quic::StreamControlFrameState::pending;
        ok &= connection.local_stream_limit_state_.pending_max_streams_uni_frame.has_value();
        ok &=
            connection.local_stream_limit_state_.pending_max_streams_uni_frame.has_value()
                ? connection.local_stream_limit_state_.pending_max_streams_uni_frame->stream_type ==
                      coquic::quic::StreamLimitType::unidirectional
                : false;
    }

    {
        auto connection = make_connected_client_connection();
        constexpr auto missing_handle = coquic::quic::RecoveryPacketHandle{
            .packet_number = 999,
            .slot_index = 999,
        };
        ok &= !connection.retire_acked_packet(connection.application_space_, missing_handle)
                   .has_value();
        ok &=
            !connection.mark_lost_packet(connection.application_space_, missing_handle).has_value();
    }

    {
        auto connection = make_connected_client_connection();
        connection.peer_transport_parameters_.reset();
        connection.current_send_path_id_ = 7;
        auto &current_path = connection.ensure_path_state(7);
        current_path.validated = false;
        current_path.is_current_send_path = true;
        auto &inbound_path = connection.ensure_path_state(9);
        inbound_path.validated = true;
        const std::array frames = {
            coquic::quic::ReceivedFrame{coquic::quic::ReceivedAckFrame{
                .largest_acknowledged = 0,
                .first_ack_range = 0,
                .additional_ranges_validated = true,
            }},
        };
        const auto result = connection.process_inbound_received_application(
            frames, coquic::quic::test::test_time(0), /*allow_preconnected_frames=*/false,
            /*path_id=*/9);
        ok &= result.has_value() && result.value();
        ok &= connection.current_send_path_id_ == std::optional<coquic::quic::QuicPathId>{7};
    }

    {
        auto connection = make_connected_client_connection();
        const auto crypto_bytes = coquic::quic::SharedBytes(bytes_from_ints({0x01, 0x02}));
        static_cast<void>(
            connection.application_space_.receive_crypto.push_shared(0, crypto_bytes));
        const std::array frames = {
            coquic::quic::ReceivedFrame{coquic::quic::ReceivedCryptoFrame{
                .offset = 0,
                .crypto_data = crypto_bytes,
            }},
        };
        const auto result = connection.process_inbound_received_application(
            frames, coquic::quic::test::test_time(0));
        ok &= result.has_value() && result.value();
    }

    {
        auto connection = make_connected_client_connection();
        const std::array frames = {
            coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
                .has_offset = true,
                .stream_id = 1,
                .offset = std::nullopt,
                .stream_data = coquic::quic::SharedBytes(bytes_from_ints({0x0a})),
            }},
        };
        const auto result = connection.process_inbound_received_application(
            frames, coquic::quic::test::test_time(0));
        ok &= !result.has_value();
        ok &= !result.has_value()
                  ? result.error().code == coquic::quic::CodecErrorCode::invalid_varint
                  : false;
    }

    {
        auto connection = make_connected_client_connection();
        connection.streams_.emplace(
            1, coquic::quic::make_implicit_stream_state(1, connection.config_.role));
        connection.streams_.at(1).peer_reset_received = true;
        const std::array frames = {
            coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
                .stream_id = 1,
                .offset = 0,
                .stream_data = coquic::quic::SharedBytes(bytes_from_ints({0x0b})),
            }},
        };
        const auto result = connection.process_inbound_received_application(
            frames, coquic::quic::test::test_time(0));
        ok &= result.has_value() && result.value();
    }

    {
        auto connection = make_connected_client_connection();
        auto stream = coquic::quic::make_implicit_stream_state(1, connection.config_.role);
        stream.peer_final_size = 1;
        connection.streams_.insert_or_assign(1, stream);
        const std::array frames = {
            coquic::quic::ReceivedFrame{coquic::quic::ReceivedStreamFrame{
                .stream_id = 1,
                .offset = 0,
                .stream_data = coquic::quic::SharedBytes(bytes_from_ints({0x0c, 0x0d})),
            }},
        };
        const auto result = connection.process_inbound_received_application(
            frames, coquic::quic::test::test_time(0));
        ok &= !result.has_value();
        ok &= !result.has_value()
                  ? result.error().code == coquic::quic::CodecErrorCode::invalid_varint
                  : false;
    }

    {
        auto connection = make_connected_client_connection();
        const std::array frames = {
            coquic::quic::ReceivedFrame{coquic::quic::NewTokenFrame{
                .token = bytes_from_ints({0x72, 0x74}),
            }},
        };
        const auto result = connection.process_inbound_received_application(
            frames, coquic::quic::test::test_time(0));
        ok &= result.has_value() && result.value();
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_space_.write_secret = make_test_traffic_secret();
        const std::array payload = {std::byte{0x05}};
        ok &= connection.queue_stream_send(0, payload, /*fin=*/false).has_value();
        const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
            coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_context_new);
        static_cast<void>(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)));
        ok &= connection.has_failed();
    }

    {
        auto connection = make_connected_server_connection();
        connection.zero_rtt_space_.write_secret =
            make_test_traffic_secret(invalid_cipher_suite(), std::byte{0x06});
        const std::array payload = {std::byte{0x06}};
        ok &= connection.queue_stream_send(0, payload, /*fin=*/false).has_value();
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        ok &= datagram.empty();
        ok &= connection.has_failed();
    }

    {
        auto connection = make_connected_server_connection();
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 400;
        connection.handshake_space_.write_secret = make_test_traffic_secret(
            coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x67});
        connection.zero_rtt_space_.write_secret =
            make_test_traffic_secret(invalid_cipher_suite(), std::byte{0x68});
        connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
            .packet_number = 11,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };
        const std::array payload = {std::byte{0x07}};
        ok &= connection.queue_stream_send(0, payload, /*fin=*/false).has_value();
        connection.congestion_controller_.on_packet_sent(
            connection.congestion_controller_.congestion_window(), /*ack_eliciting=*/true);
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        ok &= datagram.empty();
        ok &= connection.has_failed();
    }

    return ok;
}

TEST(QuicCoreTest, ConnectedServerQueuesSpareConnectionIdsForMigration) {
    auto connection = make_connected_server_connection();
    connection.issue_spare_connection_ids();

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    EXPECT_TRUE(
        std::any_of(application->frames.begin(), application->frames.end(), [](const auto &frame) {
            return std::holds_alternative<coquic::quic::NewConnectionIdFrame>(frame);
        }));
}

TEST(QuicCoreTest, ClientHandshakeConfirmationQueuesSpareConnectionIdsForMigration) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;
    connection.pending_new_connection_id_frames_.clear();
    optional_ref_or_terminate(connection.peer_transport_parameters_).active_connection_id_limit = 8;

    connection.confirm_handshake();

    EXPECT_EQ(connection.pending_new_connection_id_frames_.size(), 7u);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    EXPECT_TRUE(
        std::any_of(application->frames.begin(), application->frames.end(), [](const auto &frame) {
            return std::holds_alternative<coquic::quic::NewConnectionIdFrame>(frame);
        }));
}

TEST(QuicCoreTest, ConnectionInternalCoverageHooksExerciseRemainingMigrationBranches) {
    EXPECT_TRUE(connection_additional_internal_coverage_for_tests());
}

TEST(QuicCoreTest, CoreMigrationRequestReportsUnsupportedOperationWhenPeerDisablesActiveMigration) {
    coquic::quic::QuicCore core(coquic::quic::test::make_client_core_config());
    core.connection_->peer_transport_parameters_ = coquic::quic::TransportParameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 8,
        .disable_active_migration = true,
        .initial_source_connection_id = bytes_from_ints({0xaa}),
    };

    const auto result = core.advance(
        coquic::quic::QuicCoreRequestConnectionMigration{
            .route_handle = 7,
            .reason = coquic::quic::QuicMigrationRequestReason::active,
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(result.local_error.has_value());
    const auto &local_error = optional_ref_or_terminate(result.local_error);
    EXPECT_EQ(local_error.code, coquic::quic::QuicCoreLocalErrorCode::unsupported_operation);
    EXPECT_EQ(local_error.stream_id, std::nullopt);
}

TEST(QuicCoreTest, PeerMigrationDefersApplicationProbePayloadUntilPathValidated) {
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
    connection.ensure_path_state(9).anti_amplification_received_bytes = 4000;

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 9u);

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *first_packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(first_packet, nullptr);

    bool saw_path_challenge = false;
    bool saw_stream_frame = false;
    for (const auto &frame : first_packet->frames) {
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
        saw_stream_frame =
            saw_stream_frame || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_path_challenge);
    EXPECT_FALSE(saw_stream_frame);
    EXPECT_TRUE(connection.application_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, MatchingPathResponsePromotesValidatedPeerMigrationPath) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    const auto inbound_challenge = std::array{
        std::byte{0x10}, std::byte{0x11}, std::byte{0x12}, std::byte{0x13},
        std::byte{0x14}, std::byte{0x15}, std::byte{0x16}, std::byte{0x17},
    };
    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9, {coquic::quic::PathChallengeFrame{.data = inbound_challenge}}));

    const auto validation_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(validation_datagram.empty());
    ASSERT_TRUE(connection.paths_.contains(9));
    ASSERT_TRUE(connection.paths_.at(9).outstanding_challenge.has_value());
    const auto outstanding_challenge =
        optional_ref_or_terminate(connection.paths_.at(9).outstanding_challenge);

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 9, {coquic::quic::PathResponseFrame{.data = outstanding_challenge}}));

    ASSERT_TRUE(connection.paths_.at(9).validated);
    EXPECT_EQ(connection.last_validated_path_id_, 9u);
    EXPECT_EQ(connection.current_send_path_id_, 9u);
}

TEST(QuicCoreTest, AckOnlyRebindResponseIncludesPathChallengeOnFirstNewPathPacket) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = std::size_t{1024} * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(4096, 'm')), false)
                    .has_value());

    const auto path3_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(path3_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 3u);
    ASSERT_NE(tracked_packet_count(connection.application_space_), 0u);
    const auto largest_sent_packet =
        last_tracked_packet(connection.application_space_).packet_number;

    ASSERT_TRUE(connection
                    .process_inbound_application(
                        std::vector<coquic::quic::Frame>{
                            coquic::quic::AckFrame{
                                .largest_acknowledged = largest_sent_packet,
                                .first_ack_range = 0,
                            },
                        },
                        coquic::quic::test::test_time(2), /*allow_preconnected_frames=*/false,
                        /*path_id=*/7)
                    .has_value());
    connection.ensure_path_state(7).anti_amplification_received_bytes = 4000;

    const auto migrated_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(migrated_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 7u);

    const auto packets = decode_sender_datagram(connection, migrated_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(packet, nullptr);

    bool saw_path_challenge = false;
    for (const auto &frame : packet->frames) {
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_path_challenge);
}

TEST(QuicCoreTest, AckOnlyRebindDefersQueuedStreamDataUntilPathValidated) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = std::size_t{1024} * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(4096, 'm')), false)
                    .has_value());

    const auto path3_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(path3_datagram.empty());
    ASSERT_NE(tracked_packet_count(connection.application_space_), 0u);
    const auto largest_sent_packet =
        last_tracked_packet(connection.application_space_).packet_number;

    ASSERT_TRUE(connection
                    .process_inbound_application(
                        std::vector<coquic::quic::Frame>{
                            coquic::quic::AckFrame{
                                .largest_acknowledged = largest_sent_packet,
                                .first_ack_range = 0,
                            },
                        },
                        coquic::quic::test::test_time(2), /*allow_preconnected_frames=*/false,
                        /*path_id=*/7)
                    .has_value());
    connection.ensure_path_state(7).anti_amplification_received_bytes = 4000;

    const auto migrated_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(migrated_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 7u);

    const auto packets = decode_sender_datagram(connection, migrated_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(packet, nullptr);

    bool saw_path_challenge = false;
    bool saw_stream_frame = false;
    for (const auto &frame : packet->frames) {
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
        saw_stream_frame =
            saw_stream_frame || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_path_challenge);
    EXPECT_FALSE(saw_stream_frame);
}

TEST(QuicCoreTest, AckOnlyRebindDefersApplicationProbePayloadUntilPathValidated) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = std::size_t{1024} * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(1200, 'p')), false)
                    .has_value());

    const auto path3_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(path3_datagram.empty());
    ASSERT_NE(tracked_packet_count(connection.application_space_), 0u);
    const auto largest_sent_packet =
        last_tracked_packet(connection.application_space_).packet_number;
    connection.application_space_.pending_probe_packet =
        tracked_packet_or_terminate(connection.application_space_, largest_sent_packet);
    ASSERT_TRUE(connection.application_space_.pending_probe_packet.has_value());
    ASSERT_FALSE(connection.application_space_.pending_probe_packet->stream_fragments.empty());

    ASSERT_TRUE(connection
                    .process_inbound_application(
                        std::vector<coquic::quic::Frame>{
                            coquic::quic::AckFrame{
                                .largest_acknowledged = largest_sent_packet,
                                .first_ack_range = 0,
                            },
                        },
                        coquic::quic::test::test_time(2), /*allow_preconnected_frames=*/false,
                        /*path_id=*/7)
                    .has_value());
    connection.ensure_path_state(7).anti_amplification_received_bytes = 4000;

    const auto migrated_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(migrated_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 7u);

    const auto packets = decode_sender_datagram(connection, migrated_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(packet, nullptr);

    bool saw_path_challenge = false;
    bool saw_stream_frame = false;
    for (const auto &frame : packet->frames) {
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
        saw_stream_frame =
            saw_stream_frame || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_path_challenge);
    EXPECT_FALSE(saw_stream_frame);
    EXPECT_TRUE(connection.application_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, AckOnlyRebindPathValidationBypassesCongestionWindow) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(4096, 'm')), false)
                    .has_value());

    const auto path3_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(path3_datagram.empty());
    ASSERT_NE(tracked_packet_count(connection.application_space_), 0u);
    const auto largest_sent_packet =
        last_tracked_packet(connection.application_space_).packet_number;

    ASSERT_TRUE(connection
                    .process_inbound_application(
                        std::vector<coquic::quic::Frame>{
                            coquic::quic::AckFrame{
                                .largest_acknowledged = largest_sent_packet,
                                .first_ack_range = 0,
                            },
                        },
                        coquic::quic::test::test_time(2), /*allow_preconnected_frames=*/false,
                        /*path_id=*/7)
                    .has_value());
    connection.ensure_path_state(7).anti_amplification_received_bytes = 4000;
    connection.congestion_controller_.bytes_in_flight_ =
        connection.congestion_controller_.congestion_window();

    const auto migrated_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(migrated_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 7u);

    const auto packets = decode_sender_datagram(connection, migrated_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(packet, nullptr);

    bool saw_path_challenge = false;
    bool saw_stream_frame = false;
    for (const auto &frame : packet->frames) {
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
        saw_stream_frame =
            saw_stream_frame || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_path_challenge);
    EXPECT_FALSE(saw_stream_frame);
}

TEST(QuicCoreTest, AckOnlyRebindWithLargeAckRangesDoesNotFailOnSecondDrain) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 1;
    connection.current_send_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(1).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = std::size_t{1024} * 1024u;
    connection.application_space_.next_send_packet_number = 92;

    ASSERT_TRUE(connection
                    .queue_stream_send(0,
                                       coquic::quic::test::bytes_from_string(
                                           std::string(std::size_t{512} * 1024u, 'm')),
                                       false)
                    .has_value());

    while (connection.application_space_.next_send_packet_number <= 253) {
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(
            static_cast<std::int64_t>(connection.application_space_.next_send_packet_number)));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 1u);
    }

    const auto make_ack_frame_from_ranges =
        [](std::initializer_list<std::pair<std::uint64_t, std::uint64_t>> ranges) {
            auto it = ranges.begin();
            EXPECT_NE(it, ranges.end());
            coquic::quic::AckFrame ack{
                .largest_acknowledged = it->first,
                .first_ack_range = it->first - it->second,
            };
            auto previous_smallest = it->second;
            ++it;
            for (; it != ranges.end(); ++it) {
                ack.additional_ranges.push_back(coquic::quic::AckRange{
                    .gap = previous_smallest - it->first - 2,
                    .range_length = it->first - it->second,
                });
                previous_smallest = it->second;
            }
            return ack;
        };

    const auto rebind_ack = make_ack_frame_from_ranges({
        {253, 253}, {250, 249}, {246, 245}, {242, 241}, {239, 239}, {237, 235}, {232, 232},
        {229, 228}, {225, 223}, {221, 220}, {217, 216}, {213, 212}, {209, 208}, {206, 204},
        {201, 200}, {198, 196}, {193, 192}, {190, 188}, {185, 183}, {181, 180}, {177, 176},
        {174, 172}, {169, 168}, {166, 164}, {161, 160}, {158, 156}, {153, 152}, {150, 148},
        {145, 144}, {142, 140}, {137, 136}, {134, 132}, {129, 128}, {126, 124}, {122, 114},
    });

    ASSERT_TRUE(connection
                    .process_inbound_application(std::vector<coquic::quic::Frame>{rebind_ack},
                                                 coquic::quic::test::test_time(1000),
                                                 /*allow_preconnected_frames=*/false, /*path_id=*/2)
                    .has_value());
    connection.ensure_path_state(2).anti_amplification_received_bytes = 4000;
    connection.congestion_controller_.congestion_window_ = 3600;
    connection.congestion_controller_.bytes_in_flight_ = 44400;

    const auto validation_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1001));
    ASSERT_FALSE(validation_datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 2u);
    EXPECT_FALSE(connection.has_failed());

    const auto followup_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1002));
    static_cast<void>(followup_datagram);
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, LiveLikeAckOnlyRebindFirstResponseIncludesPathChallenge) {
    auto connection = make_connected_server_connection();
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
    for (std::size_t i = 0; i < kDeliveredPackets; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(i) + 1));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
    }
    for (std::size_t i = 0; i < kGapPackets; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(kDeliveredPackets + i + 1u)));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 9u);
    }

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

    const auto packets = decode_sender_datagram(connection, migration_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(packet, nullptr);

    bool saw_path_challenge = false;
    for (const auto &frame : packet->frames) {
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_path_challenge);
}

TEST(QuicCoreTest, LocalMigrationRequestSendsPathChallengeWithoutOtherPayload) {
    auto connection = make_connected_client_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    const auto requested = connection.request_connection_migration(
        7, coquic::quic::QuicMigrationRequestReason::active);

    ASSERT_TRUE(requested.has_value());
    ASSERT_TRUE(connection.paths_.contains(7));
    EXPECT_TRUE(connection.paths_.at(7).challenge_pending);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 7u);

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_path_challenge = false;
    for (const auto &frame : application->frames) {
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_path_challenge);
}

TEST(QuicCoreTest, LocalMigrationRequestUsesSparePeerConnectionIdOnNewPath) {
    auto connection = make_connected_client_connection();
    connection.paths_.clear();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;
    connection.ensure_path_state(3).peer_connection_id_sequence = 0;

    connection.peer_connection_ids_[0] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 0,
        .connection_id = bytes_from_ints({0xaa, 0xab}),
    };
    connection.peer_connection_ids_[2] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 2,
        .connection_id = bytes_from_ints({0x10, 0x11}),
    };
    connection.active_peer_connection_id_sequence_ = 0;

    const auto requested = connection.request_connection_migration(
        7, coquic::quic::QuicMigrationRequestReason::active);

    ASSERT_TRUE(requested.has_value());
    ASSERT_TRUE(connection.paths_.contains(7));
    EXPECT_EQ(connection.paths_.at(7).peer_connection_id_sequence, 2u);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 7u);

    const auto destination_connection_ids = protected_datagram_destination_connection_ids(
        datagram, connection.config_.source_connection_id.size());
    ASSERT_TRUE(destination_connection_ids.has_value());
    const auto &destination_connection_ids_value =
        optional_ref_or_terminate(destination_connection_ids);
    ASSERT_EQ(destination_connection_ids_value.size(), 1u);
    EXPECT_EQ(destination_connection_ids_value.front(), bytes_from_ints({0x10, 0x11}));
}

TEST(QuicCoreTest, PeerMigrationKeepsCurrentPeerConnectionIdOnNewPath) {
    auto connection = make_connected_server_connection();
    connection.paths_.clear();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;
    connection.ensure_path_state(3).peer_connection_id_sequence = 0;

    connection.peer_connection_ids_[0] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 0,
        .connection_id = bytes_from_ints({0xaa, 0xab}),
    };
    connection.peer_connection_ids_[2] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 2,
        .connection_id = bytes_from_ints({0x10, 0x11}),
    };
    connection.active_peer_connection_id_sequence_ = 0;

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 7, {coquic::quic::PingFrame{}}));

    ASSERT_TRUE(connection.paths_.contains(7));
    EXPECT_EQ(connection.paths_.at(7).peer_connection_id_sequence, 0u);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 7u);

    const auto destination_connection_ids = protected_datagram_destination_connection_ids(
        datagram, connection.config_.source_connection_id.size());
    ASSERT_TRUE(destination_connection_ids.has_value());
    const auto &destination_connection_ids_value =
        optional_ref_or_terminate(destination_connection_ids);
    ASSERT_EQ(destination_connection_ids_value.size(), 1u);
    EXPECT_EQ(destination_connection_ids_value.front(), bytes_from_ints({0xaa, 0xab}));
}

TEST(QuicCoreTest, LocalMigrationRequestKeepsPendingSendPathDespiteOldPathTraffic) {
    auto connection = make_connected_client_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    const auto requested = connection.request_connection_migration(
        7, coquic::quic::QuicMigrationRequestReason::active);

    ASSERT_TRUE(requested.has_value());
    ASSERT_TRUE(connection.paths_.contains(7));
    EXPECT_EQ(connection.current_send_path_id_, 7u);
    ASSERT_TRUE(connection.paths_.at(7).outstanding_challenge.has_value());

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 3,
        {coquic::quic::PingFrame{}, coquic::quic::MaxDataFrame{.maximum_data = 1024}}));

    EXPECT_EQ(connection.current_send_path_id_, 7u);
    EXPECT_EQ(connection.previous_path_id_, 3u);
    EXPECT_FALSE(connection.paths_.at(7).validated);
    EXPECT_TRUE(connection.paths_.at(7).outstanding_challenge.has_value());
}

TEST(QuicCoreTest, PeerMigrationKeepsPendingSendPathDespiteOldPathTraffic) {
    auto connection = make_connected_server_connection();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;

    ASSERT_TRUE(coquic::quic::test::inject_inbound_application_frames_on_path(
        connection, 7,
        {coquic::quic::PingFrame{}, coquic::quic::MaxDataFrame{.maximum_data = 1024}}));

    EXPECT_EQ(connection.current_send_path_id_, 7u);
    EXPECT_EQ(connection.previous_path_id_, 3u);
    ASSERT_TRUE(connection.paths_.contains(7));
    EXPECT_FALSE(connection.paths_.at(7).validated);
    EXPECT_TRUE(connection.paths_.at(7).outstanding_challenge.has_value());

    ASSERT_TRUE(
        coquic::quic::test::inject_inbound_application_frames_on_path(connection, 3,
                                                                      {coquic::quic::AckFrame{
                                                                          .largest_acknowledged = 0,
                                                                          .first_ack_range = 0,
                                                                      }}));

    EXPECT_EQ(connection.current_send_path_id_, 7u);
    EXPECT_EQ(connection.previous_path_id_, 3u);
    EXPECT_FALSE(connection.paths_.at(7).validated);
    EXPECT_TRUE(connection.paths_.at(7).outstanding_challenge.has_value());
}

TEST(QuicCoreTest, PreferredAddressMigrationUsesPreferredAddressConnectionId) {
    auto connection = make_connected_client_connection();
    connection.paths_.clear();
    connection.last_validated_path_id_ = 3;
    connection.current_send_path_id_ = 3;
    connection.ensure_path_state(3).validated = true;
    connection.ensure_path_state(3).is_current_send_path = true;
    connection.ensure_path_state(3).peer_connection_id_sequence = 0;

    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 8,
        .initial_source_connection_id = bytes_from_ints({0xaa}),
        .preferred_address =
            coquic::quic::PreferredAddress{
                .ipv4_address = {std::byte{127}, std::byte{0}, std::byte{0}, std::byte{2}},
                .ipv4_port = 4444,
                .connection_id = bytes_from_ints({0x41, 0x42, 0x43, 0x44}),
            },
    };
    connection.peer_connection_ids_[0] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 0,
        .connection_id = bytes_from_ints({0xaa, 0xab}),
    };
    connection.peer_connection_ids_[2] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 2,
        .connection_id = bytes_from_ints({0x10, 0x11}),
    };
    connection.active_peer_connection_id_sequence_ = 0;

    const auto requested = connection.request_connection_migration(
        7, coquic::quic::QuicMigrationRequestReason::preferred_address);

    ASSERT_TRUE(requested.has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());

    ASSERT_GE(datagram.size(), 5u);
    EXPECT_EQ(std::vector<std::byte>(datagram.begin() + 1, datagram.begin() + 5),
              bytes_from_ints({0x41, 0x42, 0x43, 0x44}));
}

TEST(QuicCoreTest, DisableActiveMigrationRejectsGenericMigrationRequest) {
    auto connection = make_connected_client_connection();
    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 8,
        .disable_active_migration = true,
        .initial_source_connection_id = bytes_from_ints({0xaa}),
    };

    const auto requested = connection.request_connection_migration(
        7, coquic::quic::QuicMigrationRequestReason::active);

    ASSERT_FALSE(requested.has_value());
}

TEST(QuicCoreTest, PreferredAddressMigrationBypassesDisableActiveMigration) {
    auto connection = make_connected_client_connection();
    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 8,
        .disable_active_migration = true,
        .initial_source_connection_id = bytes_from_ints({0xaa}),
    };

    const auto requested = connection.request_connection_migration(
        7, coquic::quic::QuicMigrationRequestReason::preferred_address);

    ASSERT_TRUE(requested.has_value());
}

TEST(QuicCoreTest, MigrationHelpersCoverExistingPathSelectionAndAmplificationBranches) {
    {
        auto connection = make_connected_client_connection();
        connection.current_send_path_id_ = 3;
        connection.previous_path_id_ = 1;
        connection.ensure_path_state(3).validated = true;
        connection.ensure_path_state(3).is_current_send_path = true;

        connection.maybe_switch_to_path(3, /*initiated_locally=*/false);

        EXPECT_EQ(connection.current_send_path_id_, 3u);
        EXPECT_EQ(connection.previous_path_id_, 1u);
    }

    {
        auto connection = make_connected_client_connection();
        connection.current_send_path_id_ = 3;
        connection.ensure_path_state(3).validated = true;
        connection.ensure_path_state(3).is_current_send_path = true;
        connection.ensure_path_state(9).validated = true;

        connection.maybe_switch_to_path(9, /*initiated_locally=*/false);

        EXPECT_EQ(connection.previous_path_id_, 3u);
        EXPECT_EQ(connection.current_send_path_id_, 9u);
        EXPECT_FALSE(connection.paths_.at(3).is_current_send_path);
        EXPECT_TRUE(connection.paths_.at(9).is_current_send_path);
    }

    {
        auto connection = make_connected_server_connection();
        connection.peer_connection_ids_[2] = coquic::quic::PeerConnectionIdRecord{
            .sequence_number = 2,
            .connection_id = bytes_from_ints({0x42}),
        };
        connection.ensure_path_state(7).peer_connection_id_sequence = 2;

        EXPECT_EQ(connection.select_peer_connection_id_sequence_for_path(7), 2u);

        connection.start_path_validation(7, /*initiated_locally=*/false);

        EXPECT_EQ(connection.paths_.at(7).peer_connection_id_sequence, 2u);
        EXPECT_FALSE(connection.path_validation_timed_out(99, coquic::quic::test::test_time(1)));
    }

    {
        auto connection = make_connected_server_connection();
        connection.current_send_path_id_ = 9;
        connection.ensure_path_state(9).validated = false;
        connection.ensure_path_state(9).anti_amplification_received_bytes = 4;

        EXPECT_TRUE(connection.anti_amplification_applies());
        EXPECT_EQ(connection.anti_amplification_send_budget(), 12u);

        connection.ensure_path_state(7).pending_response =
            std::array{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                       std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};
        connection.ensure_path_state(7).anti_amplification_received_bytes = 5;
        EXPECT_EQ(connection.anti_amplification_send_budget(), 15u);

        connection.paths_.at(7).pending_response.reset();
        connection.ensure_path_state(11).anti_amplification_received_bytes =
            std::numeric_limits<std::uint64_t>::max() / 3u + 1u;
        EXPECT_EQ(connection.anti_amplification_send_budget(11),
                  std::numeric_limits<std::uint64_t>::max());
    }
}

TEST(QuicCoreTest, MigrationHelpersCoverAdditionalPrivateBranches) {
    {
        auto connection = make_connected_client_connection();
        connection.current_send_path_id_ = 11;
        connection.last_validated_path_id_.reset();
        connection.ensure_path_state(11).validation_deadline = coquic::quic::test::test_time(9);

        connection.on_timeout(coquic::quic::test::test_time(10));

        EXPECT_EQ(connection.current_send_path_id_, 11u);
        EXPECT_FALSE(connection.previous_path_id_.has_value());
    }

    {
        auto connection = make_connected_server_connection();
        connection.active_peer_connection_id_sequence_ = 1;
        connection.peer_connection_ids_[1] = coquic::quic::PeerConnectionIdRecord{
            .sequence_number = 1,
            .connection_id = bytes_from_ints({0x40}),
        };
        connection.peer_connection_ids_[2] = coquic::quic::PeerConnectionIdRecord{
            .sequence_number = 2,
            .connection_id = bytes_from_ints({0x41}),
        };
        connection.ensure_path_state(9).peer_connection_id_sequence = 99;

        EXPECT_EQ(connection.select_peer_connection_id_sequence_for_path(9), 2u);

        connection.paths_.clear();
        connection.start_path_validation(9, /*initiated_locally=*/false);
        ASSERT_TRUE(connection.paths_.contains(9));
        EXPECT_EQ(connection.paths_.at(9).peer_connection_id_sequence, 1u);
        connection.paths_.at(9).validation_deadline = coquic::quic::test::test_time(20);
        EXPECT_FALSE(connection.path_validation_timed_out(9, coquic::quic::test::test_time(19)));
    }

    {
        auto connection = make_connected_client_connection();
        EXPECT_FALSE(connection.is_probing_only(std::array<coquic::quic::Frame, 1>{
            coquic::quic::PingFrame{},
        }));
    }

    {
        auto connection = make_connected_server_connection();
        auto &path = connection.ensure_path_state(17);
        path.validated = false;

        EXPECT_FALSE(connection.anti_amplification_applies(17));

        connection.status_ = coquic::quic::HandshakeStatus::connected;
        connection.last_inbound_path_id_ = 17;
        path.anti_amplification_received_bytes = std::numeric_limits<std::uint64_t>::max() - 4;
        connection.note_inbound_datagram_bytes(10);
        EXPECT_EQ(path.anti_amplification_received_bytes,
                  std::numeric_limits<std::uint64_t>::max());
    }

    {
        auto connection = make_connected_server_connection();
        auto &path = connection.ensure_path_state(19);
        path.validated = false;
        path.anti_amplification_received_bytes = 1;
        path.anti_amplification_sent_bytes = std::numeric_limits<std::uint64_t>::max() - 3;

        connection.note_outbound_datagram_bytes(10, 19);

        EXPECT_EQ(path.anti_amplification_sent_bytes, std::numeric_limits<std::uint64_t>::max());
    }
}

TEST(QuicCoreTest, PacketTraceLogsAckTimeoutMigrationAndBlockedSendPaths) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");

    testing::internal::CaptureStderr();

    {
        auto connection = make_connected_client_connection();
        connection.last_validated_path_id_ = 3;
        connection.current_send_path_id_ = 3;
        connection.ensure_path_state(3).validated = true;
        connection.ensure_path_state(3).is_current_send_path = true;

        ASSERT_TRUE(
            connection
                .queue_stream_send(0, coquic::quic::test::bytes_from_string("trace-ack"), false)
                .has_value());
        const auto outbound = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        ASSERT_FALSE(outbound.empty());
        ASSERT_NE(tracked_packet_count(connection.application_space_), 0u);
        const auto largest_sent_packet =
            last_tracked_packet(connection.application_space_).packet_number;

        connection.start_path_validation(9, /*initiated_locally=*/true);
        ASSERT_TRUE(connection.paths_.at(9).outstanding_challenge.has_value());
        const auto outstanding_challenge =
            optional_ref_or_terminate(connection.paths_.at(9).outstanding_challenge);
        connection.current_send_path_id_ = 3;
        connection.paths_.at(3).is_current_send_path = true;
        connection.paths_.at(9).is_current_send_path = false;
        connection.last_inbound_path_id_ = 9;

        ASSERT_TRUE(connection
                        .process_inbound_application(
                            std::vector<coquic::quic::Frame>{
                                coquic::quic::AckFrame{
                                    .largest_acknowledged = largest_sent_packet,
                                    .first_ack_range = 0,
                                },
                                coquic::quic::PathChallengeFrame{
                                    .data =
                                        {
                                            std::byte{0x10},
                                            std::byte{0x11},
                                            std::byte{0x12},
                                            std::byte{0x13},
                                            std::byte{0x14},
                                            std::byte{0x15},
                                            std::byte{0x16},
                                            std::byte{0x17},
                                        },
                                },
                                coquic::quic::PathResponseFrame{
                                    .data = outstanding_challenge,
                                },
                            },
                            coquic::quic::test::test_time(2), /*allow_preconnected_frames=*/false,
                            /*path_id=*/9)
                        .has_value());
    }

    {
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
        connection.arm_pto_probe(coquic::quic::test::test_time(1000));
    }

    {
        auto connection = make_connected_client_connection();
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.handshake_space_.write_secret = make_test_traffic_secret();
        connection.track_sent_packet(connection.handshake_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 1,
                                         .sent_time = coquic::quic::test::test_time(0),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .has_ping = true,
                                     });

        connection.arm_pto_probe(coquic::quic::test::test_time(1000));
    }

    {
        auto connection = make_connected_client_connection();
        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 1,
                                         .sent_time = coquic::quic::test::test_time(0),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .has_ping = true,
                                     });

        connection.on_timeout(coquic::quic::test::test_time(1000));
    }

    {
        auto connection = make_connected_server_connection();
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 0;

        ASSERT_TRUE(
            connection
                .queue_stream_send(0, coquic::quic::test::bytes_from_string("trace-amp"), false)
                .has_value());
        EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.congestion_controller_.bytes_in_flight_ =
            connection.congestion_controller_.congestion_window();

        ASSERT_TRUE(connection
                        .queue_stream_send(
                            0, coquic::quic::test::bytes_from_string("trace-congestion"), false)
                        .has_value());
        EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.write_secret.reset();
        connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
            .packet_number = 99,
            .ack_eliciting = true,
            .in_flight = true,
        };
        EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    }

    const auto stderr_output = testing::internal::GetCapturedStderr();
    EXPECT_NE(stderr_output.find("quic-packet-trace ack scid=c101"), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace recv-app scid=c101"), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace path-response scid=c101"), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace arm-pto scid=c101"), std::string::npos);
    EXPECT_NE(stderr_output.find("selected=initial"), std::string::npos);
    EXPECT_NE(stderr_output.find("selected=handshake"), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace timeout scid=c101"), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace send-empty scid=c101"), std::string::npos);
    EXPECT_NE(stderr_output.find("reason=amp-budget-zero"), std::string::npos);
    EXPECT_NE(stderr_output.find("reason=congestion"), std::string::npos);
}

} // namespace
