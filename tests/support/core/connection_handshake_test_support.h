#ifndef COQUIC_TESTS_SUPPORT_CORE_CONNECTION_HANDSHAKE_TEST_SUPPORT_H
#define COQUIC_TESTS_SUPPORT_CORE_CONNECTION_HANDSHAKE_TEST_SUPPORT_H

#include <array>

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>

#include "src/quic/connection/connection_test_hooks.h"
#include "src/quic/crypto/packet_crypto.h"
#include "src/quic/crypto/packet_crypto_test_hooks.h"
#include "src/quic/codec/protected_codec.h"
#include "src/quic/codec/protected_codec_test_hooks.h"
#include "src/quic/crypto/tls_adapter_quictls_test_hooks.h"
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

template <typename Core>
concept has_receive = requires(Core &core) { core.receive(std::vector<std::byte>{}); };

template <typename Core>
concept has_queue_application_data =
    requires(Core &core) { core.queue_application_data(std::vector<std::byte>{}); };

template <typename Core>
concept has_take_received_application_data =
    requires(Core &core) { core.take_received_application_data(); };

static_assert(!has_receive<coquic::quic::QuicCore>);
static_assert(!has_queue_application_data<coquic::quic::QuicCore>);
static_assert(!has_take_received_application_data<coquic::quic::QuicCore>);

template <typename T> void expect_codec_success(const coquic::quic::CodecResult<T> &result) {
    ASSERT_TRUE(result.has_value());
}

inline void expect_codec_true(const coquic::quic::CodecResult<bool> &result) {
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
}

template <typename T>
const T &codec_value_or_terminate(const coquic::quic::CodecResult<T> &result) {
    if (!result.has_value()) {
        std::abort();
    }
    return result.value();
}

template <typename T>
void expect_codec_failure(const coquic::quic::CodecResult<T> &result,
                          coquic::quic::CodecErrorCode expected_code) {
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, expected_code);
}

inline void expect_protected_datagram_starts_with_handshake(
    coquic::quic::CodecResult<std::vector<coquic::quic::ProtectedPacket>> result) {
    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(result.value().empty());
    ASSERT_TRUE(
        std::holds_alternative<coquic::quic::ProtectedHandshakePacket>(result.value().front()));
}

inline void expect_single_packet_kind(const coquic::quic::DatagramBuffer &datagram,
                                      ProtectedPacketKind expected_kind) {
    const auto packet_kinds = protected_datagram_packet_kinds(datagram);
    ASSERT_TRUE(packet_kinds.has_value());
    const auto &packet_kind_values = optional_ref_or_terminate(packet_kinds);
    ASSERT_EQ(packet_kind_values.size(), 1u);
    EXPECT_EQ(packet_kind_values.front(), expected_kind);
}

inline void expect_blocked_drain_trace_contains(coquic::quic::QuicConnection &connection,
                                                coquic::quic::QuicCoreTimePoint send_time,
                                                std::string_view required_text) {
    testing::internal::CaptureStderr();
    const coquic::quic::DatagramBuffer drained_datagram =
        connection.drain_outbound_datagram(send_time);
    const std::string captured_stderr = testing::internal::GetCapturedStderr();

    EXPECT_TRUE(drained_datagram.empty());
    EXPECT_NE(captured_stderr.find(required_text), std::string::npos);
}

inline void expect_blocked_drain_trace_contains(coquic::quic::QuicConnection &connection,
                                                coquic::quic::QuicCoreTimePoint send_time,
                                                std::string_view first_required_text,
                                                std::string_view second_required_text) {
    testing::internal::CaptureStderr();
    const coquic::quic::DatagramBuffer drained_datagram =
        connection.drain_outbound_datagram(send_time);
    const std::string captured_stderr = testing::internal::GetCapturedStderr();

    EXPECT_TRUE(drained_datagram.empty());
    EXPECT_NE(captured_stderr.find(first_required_text), std::string::npos);
    EXPECT_NE(captured_stderr.find(second_required_text), std::string::npos);
}

std::vector<std::byte>
serialize_one_rtt_ack_datagram_for_test(const coquic::quic::QuicConnection &connection,
                                        const coquic::quic::TrafficSecret &secret,
                                        std::uint64_t packet_number, bool key_phase = false) {
    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = key_phase,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = packet_number,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = secret,
            .one_rtt_key_phase = key_phase,
        });
    EXPECT_TRUE(encoded.has_value());
    if (!encoded.has_value()) {
        return {};
    }
    return encoded.value();
}

void enable_qlog_session_for_test(
    coquic::quic::QuicConnection &connection, const std::filesystem::path &directory,
    coquic::quic::QuicCoreTimePoint start_time = coquic::quic::test::test_time()) {
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = directory};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(), start_time);
    ASSERT_NE(connection.qlog_session_, nullptr);
}

struct ScopedConnectionDrainTestHookReset {
    ~ScopedConnectionDrainTestHookReset() {
        coquic::quic::test::connection_set_force_missing_packet_metadata_for_tests(false);
        coquic::quic::test::connection_set_force_missing_fallback_packet_length_for_tests(false);
        coquic::quic::test::connection_set_force_aead_confidentiality_limit_for_tests(false);
        coquic::quic::test::connection_set_force_aead_integrity_limit_for_tests(false);
    }
};

} // namespace

#endif // COQUIC_TESTS_SUPPORT_CORE_CONNECTION_HANDSHAKE_TEST_SUPPORT_H
