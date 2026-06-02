#ifndef COQUIC_TESTS_SUPPORT_CORE_CONNECTION_ACK_TEST_SUPPORT_H
#define COQUIC_TESTS_SUPPORT_CORE_CONNECTION_ACK_TEST_SUPPORT_H

#include <algorithm>
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

namespace coquic::quic::test {

struct PacketSpaceRecoveryTestPeer {
    static void install_stale_live_slot(PacketSpaceRecovery &recovery,
                                        std::uint64_t packet_number) {
        recovery.slots_.assign(1, PacketSpaceRecovery::SentPacketLedgerSlot{});
        recovery.live_links_.assign(1, PacketSpaceRecovery::LiveSlotLink{});
        auto &slot = recovery.slots_.front();
        slot.state = PacketSpaceRecovery::LedgerSlotState::retired;
        slot.packet.packet_number = packet_number;
        recovery.first_live_slot_ = 0;
        recovery.last_live_slot_ = 0;
    }
};

struct ScopedConnectionDrainTestHookReset {
    ~ScopedConnectionDrainTestHookReset() {
        coquic::quic::test::connection_set_force_quic_core_secret_rand_failure_for_tests(false);
        coquic::quic::test::connection_set_force_prf_failure_for_tests(false);
        coquic::quic::test::connection_set_force_issued_connection_id_rand_failure_for_tests(false);
        coquic::quic::test::connection_set_force_stateless_reset_token_rand_failure_for_tests(
            false);
        coquic::quic::test::connection_set_force_path_challenge_rand_failure_for_tests(false);
        coquic::quic::test::connection_set_force_random_one_in_sixteen_rand_failure_for_tests(
            false);
        coquic::quic::test::connection_set_force_missing_packet_metadata_for_tests(false);
        coquic::quic::test::connection_set_force_missing_fallback_packet_length_for_tests(false);
        coquic::quic::test::connection_set_force_appended_fragment_base_datagram_failure_for_tests(
            false);
        coquic::quic::test::connection_set_force_aead_confidentiality_limit_for_tests(false);
        coquic::quic::test::connection_set_force_aead_integrity_limit_for_tests(false);
        coquic::quic::test::
            connection_set_force_application_candidate_estimate_failure_countdown_for_tests(-1);
        coquic::quic::test::
            connection_set_force_candidate_datagram_serialization_failure_countdown_for_tests(-1);
        const coquic::quic::test::ApplicationCandidateDatagramExtraBytesTestHook extra_bytes_hook{
            .countdown = -1,
            .bytes = 0,
        };
        coquic::quic::test::
            connection_set_force_application_candidate_datagram_extra_bytes_for_tests(
                extra_bytes_hook);
        coquic::quic::test::
            connection_set_force_packet_inspection_missing_plaintext_storage_for_tests(false);
    }
};

} // namespace coquic::quic::test

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

} // namespace

#endif // COQUIC_TESTS_SUPPORT_CORE_CONNECTION_ACK_TEST_SUPPORT_H
