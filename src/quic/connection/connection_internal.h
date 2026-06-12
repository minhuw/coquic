#pragma once

#include "src/quic/connection/connection.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#if !defined(COQUIC_WASM_NO_FILESYSTEM)
#include <filesystem>
#include <fstream>
#endif
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <ranges>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "src/quic/codec/buffer.h"
#include "src/quic/connection/connection_test_hooks.h"
#include "src/quic/codec/frame.h"
#include "src/quic/codec/packet_number.h"
#include "src/quic/crypto/packet_crypto.h"
#include "src/quic/crypto/packet_crypto_test_hooks.h"
#include "src/quic/codec/protected_codec.h"
#include "src/quic/qlog/json.h"
#include "src/quic/qlog/session.h"
#include "src/quic/crypto/tls_adapter_quictls_test_hooks.h"

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#define COQUIC_NOINLINE __attribute__((noinline))
#else
#define COQUIC_NO_PROFILE
#define COQUIC_NOINLINE
#endif

#ifndef COQUIC_PROFILE_HOOKS
#define COQUIC_PROFILE_HOOKS 1
#endif

namespace coquic::quic {

constexpr std::size_t kMinimumInitialDatagramSize = 1200;
constexpr std::size_t kMaximumDatagramSize = 1200;
constexpr std::size_t kMaximumDeferredProtectedPackets = 32;
constexpr std::uint8_t kDefaultInitialPacketNumberLength = 2;
constexpr std::uint8_t kFullPacketNumberLength = 4;
constexpr std::size_t kOneRttPacketProtectionTagLength = 16;
constexpr std::size_t kShortHeaderProtectionSampleOffset = 4;
constexpr std::uint64_t kMaxQuicVarInt = 4611686018427387903ull;
constexpr std::uint64_t kCompatibilityStreamId = 0;
//= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.1
// # The RECOMMENDED value for kPersistentCongestionThreshold is 3, which
// # results in behavior that is approximately equivalent to a TCP sender
// # declaring an RTO after two TLPs.
constexpr std::uint32_t kPersistentCongestionThreshold = 3;
constexpr std::size_t kPmtudMinimumProbeGrowth = 16;
constexpr std::size_t kMaximumRememberedPmtudFailedProbeSizes = 16;
constexpr std::size_t kPmtudIPv6EthernetUdpPayloadSize = 1452;
constexpr std::size_t kPmtudIPv4EthernetUdpPayloadSize = 1472;
constexpr std::size_t kQuicCoreSecretLength = 32;
constexpr std::size_t kMaxConsecutiveNonproductivePackets = 128;
constexpr std::uint64_t kFrameTypePadding = 0x00;
constexpr std::uint64_t kFrameTypePing = 0x01;
constexpr std::uint64_t kFrameTypeAck = 0x02;
constexpr std::uint64_t kFrameTypeResetStream = 0x04;
constexpr std::uint64_t kFrameTypeStopSending = 0x05;
constexpr std::uint64_t kFrameTypeCrypto = 0x06;
constexpr std::uint64_t kFrameTypeNewToken = 0x07;
constexpr std::uint64_t kFrameTypeStreamBase = 0x08;
constexpr std::uint64_t kFrameTypeMaxData = 0x10;
constexpr std::uint64_t kFrameTypeMaxStreamData = 0x11;
constexpr std::uint64_t kFrameTypeMaxStreamsBidi = 0x12;
constexpr std::uint64_t kFrameTypeMaxStreamsUni = 0x13;
constexpr std::uint64_t kFrameTypeDataBlocked = 0x14;
constexpr std::uint64_t kFrameTypeStreamDataBlocked = 0x15;
constexpr std::uint64_t kFrameTypeStreamsBlockedBidi = 0x16;
constexpr std::uint64_t kFrameTypeStreamsBlockedUni = 0x17;
constexpr std::uint64_t kFrameTypeNewConnectionId = 0x18;
constexpr std::uint64_t kFrameTypeRetireConnectionId = 0x19;
constexpr std::uint64_t kFrameTypePathChallenge = 0x1a;
constexpr std::uint64_t kFrameTypePathResponse = 0x1b;
constexpr std::uint64_t kFrameTypeConnectionClose = 0x1c;
constexpr std::uint64_t kFrameTypeApplicationClose = 0x1d;
constexpr std::uint64_t kFrameTypeHandshakeDone = 0x1e;
constexpr std::uint64_t kFrameTypeDatagram = 0x30;
constexpr std::uint64_t kPreferredAddressConnectionIdSequence = 1;
constexpr std::uint64_t kAesGcmConfidentialityLimit = std::uint64_t{1} << 23u;
constexpr std::uint64_t kProactiveKeyUpdatePacketLimitDivisor = 2;
constexpr std::uint64_t kAesGcmIntegrityLimit = std::uint64_t{1} << 52u;
constexpr std::uint64_t kChaCha20Poly1305IntegrityLimit = std::uint64_t{1} << 36u;
constexpr std::size_t kMaxUnpacedBurstPackets = 10;

struct ConnectionDrainTestHooks {
    bool force_missing_packet_metadata = false;
    bool force_missing_fallback_packet_length = false;
    bool force_aead_confidentiality_limit = false;
    bool force_aead_integrity_limit = false;
    bool force_appended_fragment_base_datagram_failure = false;
    int force_application_candidate_estimate_failure_countdown = -1;
    int force_candidate_datagram_serialization_failure_countdown = -1;
};

struct SendProfileCounters {
    std::uint64_t drain_calls = 0;
    std::uint64_t datagrams = 0;
    std::uint64_t empty_drains = 0;
    std::uint64_t pmtu_probe_datagrams = 0;
    std::uint64_t congestion_blocks = 0;
    std::uint64_t pacing_blocks = 0;
    std::uint64_t has_sendable_checks = 0;
    std::uint64_t has_sendable_false = 0;
    std::uint64_t has_sendable_no_application_packets = 0;
    std::uint64_t has_sendable_no_application_data = 0;
    std::uint64_t has_sendable_control = 0;
    std::uint64_t has_sendable_no_stream_minimum = 0;
    std::uint64_t has_sendable_congestion = 0;
    std::uint64_t has_sendable_pacing = 0;
    std::uint64_t application_select_pacing_blocked = 0;
    std::uint64_t application_select_stream_attempts = 0;
    std::uint64_t application_select_stream_empty = 0;
    std::uint64_t application_select_stream_bytes = 0;
    std::uint64_t continuation_allowed = 0;
    std::uint64_t continuation_denied_no_stream = 0;
    std::uint64_t continuation_denied_bypass = 0;
    std::uint64_t continuation_denied_not_ack_eliciting = 0;
    std::uint64_t serialize_calls = 0;
    std::uint64_t estimate_calls = 0;
    std::uint64_t trim_ack_calls = 0;
    std::uint64_t application_preflight_attempts = 0;
    std::uint64_t application_preflight_available = 0;
    std::uint64_t application_preflight_admitted = 0;
    std::uint64_t application_candidate_serializations = 0;
    std::uint64_t application_no_ack_candidate_attempts = 0;
    std::uint64_t application_no_ack_candidate_used = 0;
    std::uint64_t application_trim_candidate_calls = 0;
    std::uint64_t application_trim_candidate_iterations = 0;
    std::uint64_t application_no_ack_retry_attempts = 0;
    std::uint64_t application_receive_credit_retry_attempts = 0;
    std::uint64_t application_close_reason_retry_attempts = 0;
    std::uint64_t application_write_key_phase_reserializes = 0;
    std::uint64_t application_fast_serialized_commits = 0;
    std::uint64_t application_slow_commits = 0;
    std::uint64_t inbound_calls = 0;
    std::uint64_t inbound_packets = 0;
    std::uint64_t bytes = 0;
    std::uint64_t stream_bytes = 0;
    std::uint64_t inbound_bytes = 0;
    std::uint64_t datagrams_le_1200 = 0;
    std::uint64_t datagrams_le_1434 = 0;
    std::uint64_t datagrams_le_1472 = 0;
    std::uint64_t datagrams_gt_1472 = 0;
    std::uint64_t max_datagram = 0;
    std::uint64_t serialize_ns = 0;
    std::uint64_t estimate_ns = 0;
    std::uint64_t trim_ack_ns = 0;
    std::uint64_t stream_select_ns = 0;
    std::uint64_t commit_ns = 0;
    std::uint64_t commit_pmtu_probe_scan_ns = 0;
    std::uint64_t commit_packet_count_ns = 0;
    std::uint64_t commit_key_limit_ns = 0;
    std::uint64_t commit_track_pending_ns = 0;
    std::uint64_t commit_burst_note_ns = 0;
    std::uint64_t commit_pto_probe_ns = 0;
    std::uint64_t commit_handshake_discard_ns = 0;
    std::uint64_t commit_qlog_ns = 0;
    std::uint64_t commit_datagram_bookkeeping_ns = 0;
    std::uint64_t commit_continuation_ns = 0;
    std::uint64_t commit_inspection_ns = 0;
    std::uint64_t commit_profile_accounting_ns = 0;
    std::uint64_t track_sent_congestion_ns = 0;
    std::uint64_t track_sent_ecn_ns = 0;
    std::uint64_t track_sent_recovery_ns = 0;
    std::uint64_t track_sent_profile_ns = 0;
    std::uint64_t track_sent_qlog_ns = 0;
    std::uint64_t inbound_ns = 0;
    std::uint64_t deserialize_ns = 0;
    std::uint64_t process_packet_ns = 0;
    std::uint64_t outbound_sync_tls_ns = 0;
    std::uint64_t inbound_setup_ns = 0;
    std::uint64_t inbound_initial_sync_tls_ns = 0;
    std::uint64_t inbound_post_process_sync_tls_ns = 0;
    std::uint64_t inbound_replay_deferred_ns = 0;
    std::uint64_t packet_loop_ns = 0;
    std::uint64_t packet_length_peek_ns = 0;
    std::uint64_t packet_bytes_ns = 0;
    std::uint64_t make_deserialize_context_ns = 0;
    std::uint64_t deserialize_attempts = 0;
    std::uint64_t packet_storage_range_ns = 0;
    std::uint64_t process_decoded_packet_ns = 0;
    std::uint64_t defer_decision_ns = 0;
    std::uint64_t qlog_emit_ns = 0;
    std::uint64_t inbound_initial_sync_tls_calls = 0;
    std::uint64_t inbound_initial_sync_tls_skipped = 0;
    std::uint64_t inbound_post_process_sync_tls_calls = 0;
    std::uint64_t inbound_post_process_sync_tls_skipped = 0;
    std::uint64_t outbound_sync_tls_calls = 0;
    std::uint64_t outbound_sync_tls_skipped = 0;
    std::uint64_t inbound_replay_deferred_calls = 0;
    std::uint64_t packet_length_peeks = 0;
    std::uint64_t packet_bytes_calls = 0;
    std::uint64_t make_deserialize_context_calls = 0;
    std::uint64_t packet_storage_range_checks = 0;
    std::uint64_t process_decoded_packet_calls = 0;
    std::uint64_t defer_decision_calls = 0;
    std::uint64_t qlog_emit_calls = 0;
    std::uint64_t congestion_block_cwnd_sum = 0;
    std::uint64_t congestion_block_bif_sum = 0;
    std::uint64_t congestion_block_max_cwnd = 0;
    std::uint64_t congestion_block_min_cwnd = 0;
    std::uint64_t congestion_cwnd_last = 0;
    std::uint64_t congestion_cwnd_max = 0;
    std::uint64_t congestion_bif_last = 0;
    std::uint64_t congestion_bif_max = 0;
    std::uint64_t ack_frames = 0;
    std::uint64_t acked_packets = 0;
    std::uint64_t late_acked_packets = 0;
    std::uint64_t ack_lost_packets = 0;
    std::uint64_t timer_lost_packets = 0;
    std::uint64_t acked_bytes = 0;
    std::uint64_t late_acked_bytes = 0;
    std::uint64_t ack_lost_bytes = 0;
    std::uint64_t timer_lost_bytes = 0;
    std::uint64_t loss_events = 0;
    std::uint64_t persistent_congestion_events = 0;
    std::uint64_t ecn_loss_events = 0;
    std::uint64_t packet_threshold_losses = 0;
    std::uint64_t time_threshold_losses = 0;
    std::uint64_t rtt_samples = 0;
    std::uint64_t latest_rtt_us_sum = 0;
    std::uint64_t latest_rtt_us_max = 0;
    std::uint64_t smoothed_rtt_us_last = 0;
    std::uint64_t rttvar_us_last = 0;
    std::uint64_t cc_debug_samples = 0;
    std::uint64_t cc_mode_last = 0;
    std::uint64_t cc_bandwidth_bps_last = 0;
    std::uint64_t cc_bandwidth_bps_max = 0;
    std::uint64_t cc_max_bandwidth_bps_last = 0;
    std::uint64_t cc_max_bandwidth_bps_max = 0;
    std::uint64_t cc_pacing_rate_bps_last = 0;
    std::uint64_t cc_pacing_rate_bps_max = 0;
    std::uint64_t cc_bdp_bytes_last = 0;
    std::uint64_t cc_bdp_bytes_max = 0;
    std::uint64_t cc_max_inflight_last = 0;
    std::uint64_t cc_max_inflight_max = 0;
    std::uint64_t cc_send_quantum_last = 0;
    std::uint64_t cc_send_quantum_max = 0;
    std::uint64_t cc_pacing_budget_last = 0;
    std::uint64_t cc_pacing_budget_max = 0;
    std::uint64_t cc_inflight_longterm_last = 0;
    std::uint64_t cc_inflight_longterm_max = 0;
    std::uint64_t cc_inflight_longterm_finite_samples = 0;
    std::uint64_t cc_inflight_shortterm_last = 0;
    std::uint64_t cc_inflight_shortterm_max = 0;
    std::uint64_t cc_inflight_shortterm_finite_samples = 0;
    std::uint64_t cc_extra_acked_last = 0;
    std::uint64_t cc_extra_acked_max = 0;
    std::uint64_t cc_total_delivered_last = 0;
    std::uint64_t cc_total_lost_last = 0;
    std::uint64_t cc_latest_rtt_us_last = 0;
    std::uint64_t cc_min_rtt_us_last = 0;
    std::uint64_t cc_unjittered_rtt_us_last = 0;
    std::uint64_t cc_target_window_last = 0;
    std::uint64_t cc_target_window_max = 0;
    std::uint64_t cc_target_window_finite_samples = 0;
    std::uint64_t cc_app_limited_samples = 0;
    std::uint64_t cc_full_bw_samples = 0;
    std::uint64_t cc_slow_start_samples = 0;
    std::uint64_t cc_startup_probe_complete_samples = 0;
};

template <typename T>
inline COQUIC_NO_PROFILE const T &optional_ref_or_abort(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return value.value();
}

inline ConnectionDrainTestHooks &connection_drain_test_hooks() {
    static ConnectionDrainTestHooks hooks;
    return hooks;
}

inline bool consume_connection_drain_countdown(int ConnectionDrainTestHooks::*field) {
    auto &value = connection_drain_test_hooks().*field;
    if (value < 0) {
        return false;
    }
    if (value == 0) {
        value = -1;
        return true;
    }
    --value;
    return false;
}

template <typename SerializePadded>
inline COQUIC_NO_PROFILE bool retry_padded_pmtu_probe_serialization(
    CodecResult<SerializedProtectedDatagram> &candidate, std::vector<Frame> &frames_with_padding,
    std::size_t target_pmtu_probe_size, std::size_t &probe_padding_length,
    SerializePadded serialize_padded) {
    CodecResult<SerializedProtectedDatagram> padded;
    for (std::size_t attempt = 0; attempt < 2; ++attempt) {
        padded = serialize_padded();
        if (!padded.has_value()) {
            return false;
        }
        if (padded.value().bytes.size() >= target_pmtu_probe_size) {
            break;
        }
        const auto additional_padding = target_pmtu_probe_size - padded.value().bytes.size();
        probe_padding_length += additional_padding;
        frames_with_padding.back() = PaddingFrame{.length = probe_padding_length};
    }
    candidate = std::move(padded);
    return candidate.value().bytes.size() <= target_pmtu_probe_size;
}

constexpr bool kCoquicProfileHooksEnabled = COQUIC_PROFILE_HOOKS != 0;

inline COQUIC_NO_PROFILE bool send_profile_enabled() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return false;
    }

    static const bool enabled = [] {
        const char *value = std::getenv("COQUIC_SEND_PROFILE");
        return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
    }();
    return enabled;
}

inline SendProfileCounters &send_profile_counters() {
    static SendProfileCounters counters;
    return counters;
}

inline void print_send_profile() {
    if (!send_profile_enabled()) {
        return;
    }

    const auto &c = send_profile_counters();
    std::cerr
        // Overall send-loop counters stay first so log parsers can locate profile records.
        << "coquic-send-profile" << " drains=" << c.drain_calls << " datagrams=" << c.datagrams
        << " empty=" << c.empty_drains << " pmtu_probe=" << c.pmtu_probe_datagrams
        << " congestion_blocks=" << c.congestion_blocks << " pacing_blocks="
        << c.pacing_blocks
        // Sendability and application-selection counters explain why packets were not emitted.
        << " has_sendable_checks=" << c.has_sendable_checks
        << " has_sendable_false=" << c.has_sendable_false
        << " has_sendable_no_application_packets=" << c.has_sendable_no_application_packets
        << " has_sendable_no_application_data=" << c.has_sendable_no_application_data
        << " has_sendable_control=" << c.has_sendable_control
        << " has_sendable_no_stream_minimum=" << c.has_sendable_no_stream_minimum
        << " has_sendable_congestion=" << c.has_sendable_congestion
        << " has_sendable_pacing=" << c.has_sendable_pacing
        << " application_select_pacing_blocked=" << c.application_select_pacing_blocked
        << " application_select_stream_attempts=" << c.application_select_stream_attempts
        << " application_select_stream_empty=" << c.application_select_stream_empty
        << " application_select_stream_bytes=" << c.application_select_stream_bytes
        << " continuation_allowed=" << c.continuation_allowed
        << " continuation_denied_no_stream=" << c.continuation_denied_no_stream
        << " continuation_denied_bypass=" << c.continuation_denied_bypass
        << " continuation_denied_not_ack_eliciting="
        << c.continuation_denied_not_ack_eliciting
        // Byte and datagram-size counters summarize outbound and inbound traffic volume.
        << " bytes=" << c.bytes << " stream_bytes=" << c.stream_bytes
        << " inbound_calls=" << c.inbound_calls << " inbound_packets=" << c.inbound_packets
        << " inbound_bytes=" << c.inbound_bytes << " le1200=" << c.datagrams_le_1200
        << " le1434=" << c.datagrams_le_1434 << " le1472=" << c.datagrams_le_1472
        << " gt1472=" << c.datagrams_gt_1472 << " max="
        << c.max_datagram
        // Timing counters expose hot serialize, trim, select, and inbound-processing paths.
        << " serialize_calls=" << c.serialize_calls << " serialize_ns=" << c.serialize_ns
        << " estimate_calls=" << c.estimate_calls << " estimate_ns=" << c.estimate_ns
        << " trim_ack_calls=" << c.trim_ack_calls << " trim_ack_ns=" << c.trim_ack_ns
        << " application_preflight_attempts=" << c.application_preflight_attempts
        << " application_preflight_available=" << c.application_preflight_available
        << " application_preflight_admitted=" << c.application_preflight_admitted
        << " application_candidate_serializations=" << c.application_candidate_serializations
        << " application_no_ack_candidate_attempts=" << c.application_no_ack_candidate_attempts
        << " application_no_ack_candidate_used=" << c.application_no_ack_candidate_used
        << " application_trim_candidate_calls=" << c.application_trim_candidate_calls
        << " application_trim_candidate_iterations=" << c.application_trim_candidate_iterations
        << " application_no_ack_retry_attempts=" << c.application_no_ack_retry_attempts
        << " application_receive_credit_retry_attempts="
        << c.application_receive_credit_retry_attempts
        << " application_close_reason_retry_attempts=" << c.application_close_reason_retry_attempts
        << " application_write_key_phase_reserializes="
        << c.application_write_key_phase_reserializes
        << " application_fast_serialized_commits=" << c.application_fast_serialized_commits
        << " application_slow_commits=" << c.application_slow_commits
        << " stream_select_ns=" << c.stream_select_ns << " commit_ns=" << c.commit_ns
        << " commit_pmtu_probe_scan_ns=" << c.commit_pmtu_probe_scan_ns
        << " commit_packet_count_ns=" << c.commit_packet_count_ns
        << " commit_key_limit_ns=" << c.commit_key_limit_ns
        << " commit_track_pending_ns=" << c.commit_track_pending_ns
        << " commit_burst_note_ns=" << c.commit_burst_note_ns
        << " commit_pto_probe_ns=" << c.commit_pto_probe_ns
        << " commit_handshake_discard_ns=" << c.commit_handshake_discard_ns
        << " commit_qlog_ns=" << c.commit_qlog_ns
        << " commit_datagram_bookkeeping_ns=" << c.commit_datagram_bookkeeping_ns
        << " commit_continuation_ns=" << c.commit_continuation_ns
        << " commit_inspection_ns=" << c.commit_inspection_ns
        << " commit_profile_accounting_ns=" << c.commit_profile_accounting_ns
        << " track_sent_congestion_ns=" << c.track_sent_congestion_ns
        << " track_sent_ecn_ns=" << c.track_sent_ecn_ns
        << " track_sent_recovery_ns=" << c.track_sent_recovery_ns
        << " track_sent_profile_ns=" << c.track_sent_profile_ns
        << " track_sent_qlog_ns=" << c.track_sent_qlog_ns << " inbound_ns=" << c.inbound_ns
        << " deserialize_ns=" << c.deserialize_ns << " process_packet_ns=" << c.process_packet_ns
        << " outbound_sync_tls_calls=" << c.outbound_sync_tls_calls
        << " outbound_sync_tls_skipped=" << c.outbound_sync_tls_skipped
        << " outbound_sync_tls_ns=" << c.outbound_sync_tls_ns
        << " inbound_setup_ns=" << c.inbound_setup_ns
        << " inbound_initial_sync_tls_calls=" << c.inbound_initial_sync_tls_calls
        << " inbound_initial_sync_tls_skipped=" << c.inbound_initial_sync_tls_skipped
        << " inbound_initial_sync_tls_ns=" << c.inbound_initial_sync_tls_ns
        << " inbound_post_process_sync_tls_calls=" << c.inbound_post_process_sync_tls_calls
        << " inbound_post_process_sync_tls_skipped=" << c.inbound_post_process_sync_tls_skipped
        << " inbound_post_process_sync_tls_ns=" << c.inbound_post_process_sync_tls_ns
        << " inbound_replay_deferred_calls=" << c.inbound_replay_deferred_calls
        << " inbound_replay_deferred_ns=" << c.inbound_replay_deferred_ns
        << " packet_loop_ns=" << c.packet_loop_ns
        << " packet_length_peeks=" << c.packet_length_peeks
        << " packet_length_peek_ns=" << c.packet_length_peek_ns
        << " packet_bytes_calls=" << c.packet_bytes_calls
        << " packet_bytes_ns=" << c.packet_bytes_ns
        << " make_deserialize_context_calls=" << c.make_deserialize_context_calls
        << " make_deserialize_context_ns=" << c.make_deserialize_context_ns
        << " deserialize_attempts=" << c.deserialize_attempts
        << " packet_storage_range_checks=" << c.packet_storage_range_checks
        << " packet_storage_range_ns=" << c.packet_storage_range_ns
        << " process_decoded_packet_calls=" << c.process_decoded_packet_calls
        << " process_decoded_packet_ns="
        << c.process_decoded_packet_ns
        // Congestion and loss counters are grouped before RTT and congestion-controller samples.
        << " defer_decision_calls=" << c.defer_decision_calls
        << " defer_decision_ns=" << c.defer_decision_ns << " qlog_emit_calls=" << c.qlog_emit_calls
        << " qlog_emit_ns=" << c.qlog_emit_ns
        << " congestion_block_cwnd_sum=" << c.congestion_block_cwnd_sum
        << " congestion_block_bif_sum=" << c.congestion_block_bif_sum
        << " congestion_block_max_cwnd=" << c.congestion_block_max_cwnd
        << " congestion_block_min_cwnd=" << c.congestion_block_min_cwnd
        << " congestion_cwnd_last=" << c.congestion_cwnd_last
        << " congestion_cwnd_max=" << c.congestion_cwnd_max
        << " congestion_bif_last=" << c.congestion_bif_last
        << " congestion_bif_max=" << c.congestion_bif_max << " ack_frames=" << c.ack_frames
        << " acked_packets=" << c.acked_packets << " late_acked_packets=" << c.late_acked_packets
        << " ack_lost_packets=" << c.ack_lost_packets
        << " timer_lost_packets=" << c.timer_lost_packets << " acked_bytes=" << c.acked_bytes
        << " late_acked_bytes=" << c.late_acked_bytes << " ack_lost_bytes=" << c.ack_lost_bytes
        << " timer_lost_bytes=" << c.timer_lost_bytes << " loss_events=" << c.loss_events
        << " persistent_congestion_events=" << c.persistent_congestion_events
        << " ecn_loss_events=" << c.ecn_loss_events
        << " packet_threshold_losses=" << c.packet_threshold_losses
        << " time_threshold_losses=" << c.time_threshold_losses << " rtt_samples=" << c.rtt_samples
        << " latest_rtt_us_sum=" << c.latest_rtt_us_sum
        << " latest_rtt_us_max=" << c.latest_rtt_us_max
        << " smoothed_rtt_us_last=" << c.smoothed_rtt_us_last
        << " rttvar_us_last=" << c.rttvar_us_last << " cc_debug_samples=" << c.cc_debug_samples
        << " cc_mode_last=" << c.cc_mode_last
        << " cc_bandwidth_bps_last=" << c.cc_bandwidth_bps_last
        << " cc_bandwidth_bps_max=" << c.cc_bandwidth_bps_max
        << " cc_max_bandwidth_bps_last=" << c.cc_max_bandwidth_bps_last
        << " cc_max_bandwidth_bps_max=" << c.cc_max_bandwidth_bps_max
        << " cc_pacing_rate_bps_last=" << c.cc_pacing_rate_bps_last
        << " cc_pacing_rate_bps_max=" << c.cc_pacing_rate_bps_max
        << " cc_bdp_bytes_last=" << c.cc_bdp_bytes_last
        << " cc_bdp_bytes_max=" << c.cc_bdp_bytes_max
        << " cc_max_inflight_last=" << c.cc_max_inflight_last
        << " cc_max_inflight_max=" << c.cc_max_inflight_max
        << " cc_send_quantum_last=" << c.cc_send_quantum_last
        << " cc_send_quantum_max=" << c.cc_send_quantum_max
        << " cc_pacing_budget_last=" << c.cc_pacing_budget_last
        << " cc_pacing_budget_max=" << c.cc_pacing_budget_max
        << " cc_inflight_longterm_last=" << c.cc_inflight_longterm_last
        << " cc_inflight_longterm_max=" << c.cc_inflight_longterm_max
        << " cc_inflight_longterm_finite_samples=" << c.cc_inflight_longterm_finite_samples
        << " cc_inflight_shortterm_last=" << c.cc_inflight_shortterm_last
        << " cc_inflight_shortterm_max=" << c.cc_inflight_shortterm_max
        << " cc_inflight_shortterm_finite_samples=" << c.cc_inflight_shortterm_finite_samples
        << " cc_extra_acked_last=" << c.cc_extra_acked_last
        << " cc_extra_acked_max=" << c.cc_extra_acked_max
        << " cc_total_delivered_last=" << c.cc_total_delivered_last
        << " cc_total_lost_last=" << c.cc_total_lost_last
        << " cc_latest_rtt_us_last=" << c.cc_latest_rtt_us_last
        << " cc_min_rtt_us_last=" << c.cc_min_rtt_us_last
        << " cc_unjittered_rtt_us_last=" << c.cc_unjittered_rtt_us_last
        << " cc_target_window_last=" << c.cc_target_window_last
        << " cc_target_window_max=" << c.cc_target_window_max
        << " cc_target_window_finite_samples=" << c.cc_target_window_finite_samples
        << " cc_app_limited_samples=" << c.cc_app_limited_samples
        << " cc_full_bw_samples=" << c.cc_full_bw_samples
        << " cc_slow_start_samples=" << c.cc_slow_start_samples
        << " cc_startup_probe_complete_samples=" << c.cc_startup_probe_complete_samples << '\n';
}

inline COQUIC_NO_PROFILE void register_send_profile_printer_once() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return;
    }

    static const bool registered = [] {
        std::atexit(print_send_profile);
        return true;
    }();
    static_cast<void>(registered);
}

struct SendProfileTimer {
    std::uint64_t *target = nullptr;
    QuicCoreTimePoint start{};

    COQUIC_NO_PROFILE explicit SendProfileTimer(std::uint64_t &counter)
        : target(kCoquicProfileHooksEnabled && send_profile_enabled() ? &counter : nullptr) {
        if (target != nullptr) {
            start = QuicCoreClock::now();
        }
    }

    COQUIC_NO_PROFILE void stop() {
        if (target == nullptr) {
            return;
        }
        *target += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(QuicCoreClock::now() - start)
                .count());
        target = nullptr;
    }

    COQUIC_NO_PROFILE ~SendProfileTimer() {
        stop();
    }
};

#if COQUIC_PROFILE_HOOKS
#define COQUIC_SEND_PROFILE_TIMER(name, counter)                                                   \
    SendProfileTimer name(send_profile_counters().counter)
#else
struct NoopSendProfileTimer {
    void stop() {
    }
};
#define COQUIC_SEND_PROFILE_TIMER(name, counter) NoopSendProfileTimer name
#endif

inline bool is_ect_codepoint(QuicEcnCodepoint ecn) {
    return ecn == QuicEcnCodepoint::ect0 || ecn == QuicEcnCodepoint::ect1;
}

inline std::size_t
ecn_packet_space_index(const PacketSpaceState &packet_space,
                       std::span<const PacketSpaceState *const, 3> packet_spaces) {
    if (packet_spaces[0] == &packet_space) {
        return 0;
    }
    if (packet_spaces[1] == &packet_space) {
        return 1;
    }

    return 2;
}

inline bool packet_trace_enabled() {
#ifdef NDEBUG
    static const bool enabled = [] {
        const char *value = std::getenv("COQUIC_PACKET_TRACE");
        return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
    }();
    return enabled;
#else
    const char *value = std::getenv("COQUIC_PACKET_TRACE");
    return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
#endif
}

inline std::string format_connection_id_hex(std::span<const std::byte> connection_id) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (const auto byte : connection_id) {
        hex << std::setw(2) << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
    }
    return hex.str();
}

inline std::uint64_t mix_connection_id_word(std::uint64_t value) {
    value ^= value >> 30u;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27u;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31u;
    return value;
}

inline void absorb_connection_id_seed_byte(std::uint64_t &state, std::uint8_t byte) {
    state ^= byte;
    state *= 0x100000001b3ULL;
}

inline COQUIC_NO_PROFILE bool rand_bytes_for_connection(std::span<std::byte> bytes) {
    return RAND_bytes(reinterpret_cast<unsigned char *>(bytes.data()),
                      static_cast<int>(bytes.size())) == 1;
}

inline std::array<std::byte, kQuicCoreSecretLength> make_quic_core_secret() {
    std::array<std::byte, kQuicCoreSecretLength> secret{};
    if (rand_bytes_for_connection(secret)) {
        return secret;
    }

    std::random_device random_device;
    for (auto &byte : secret) {
        byte = static_cast<std::byte>(random_device());
    }
    return secret;
}

inline std::span<const std::byte, kQuicCoreSecretLength> quic_connection_id_secret() {
    static const auto secret = make_quic_core_secret();
    return std::span<const std::byte, kQuicCoreSecretLength>(secret);
}

inline std::span<const std::byte, kQuicCoreSecretLength> quic_reset_token_secret() {
    static const auto secret = make_quic_core_secret();
    return std::span<const std::byte, kQuicCoreSecretLength>(secret);
}

inline std::span<const std::byte, kQuicCoreSecretLength> quic_path_challenge_secret() {
    static const auto secret = make_quic_core_secret();
    return std::span<const std::byte, kQuicCoreSecretLength>(secret);
}

inline COQUIC_NO_PROFILE std::optional<std::array<unsigned char, EVP_MAX_MD_SIZE>>
compute_hmac_sha256_for_connection(std::span<const std::byte> secret,
                                   std::span<const unsigned char> input, unsigned int &produced) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    if (HMAC(EVP_sha256(), reinterpret_cast<const unsigned char *>(secret.data()),
             static_cast<int>(secret.size()), input.data(), input.size(), digest.data(),
             &produced) == nullptr) {
        return std::nullopt;
    }
    return digest;
}

template <std::size_t Size>
inline COQUIC_NO_PROFILE std::optional<std::array<std::byte, Size>>
prf_bytes(std::span<const std::byte> secret, // NOLINT(bugprone-easily-swappable-parameters)
          std::span<const std::byte> label, std::span<const std::byte> context) {
    std::array<std::byte, Size> output{};
    std::vector<unsigned char> input;
    input.reserve(label.size() + context.size());
    for (const auto byte : label) {
        input.push_back(std::to_integer<unsigned char>(byte));
    }
    for (const auto byte : context) {
        input.push_back(std::to_integer<unsigned char>(byte));
    }

    unsigned int produced = 0;
    const auto digest = compute_hmac_sha256_for_connection(secret, input, produced);
    if (!digest.has_value()) {
        return std::nullopt;
    }
    static_assert(Size <= SHA256_DIGEST_LENGTH);
    static_cast<void>(produced);
    std::copy_n(reinterpret_cast<const std::byte *>(digest->data()), output.size(), output.begin());
    return output;
}

inline COQUIC_NO_PROFILE bool random_one_in_sixteen_fallback() {
    static thread_local std::mt19937 fallback_random{std::random_device{}()};
    return (fallback_random() & 0x0fu) == 0;
}

inline COQUIC_NO_PROFILE bool random_bool_for_disabled_spin_bit() {
    std::uint8_t value = 0;
    if (RAND_bytes(&value, 1) == 1) {
        return (value & 0x01u) != 0;
    }

    static thread_local std::mt19937 fallback_random{std::random_device{}()};
    return (fallback_random() & 0x01u) != 0;
}

inline std::uint64_t read_u64_be(std::span<const std::byte, sizeof(std::uint64_t)> bytes) {
    std::uint64_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8u) | std::to_integer<std::uint8_t>(byte);
    }
    return value;
}

inline std::uint64_t make_grease_quic_bit_seed() {
    std::array<std::byte, sizeof(std::uint64_t)> seed_bytes{};
    if (!rand_bytes_for_connection(seed_bytes)) {
        std::random_device random_device;
        for (auto &byte : seed_bytes) {
            byte = static_cast<std::byte>(random_device());
        }
    }
    return read_u64_be(std::span<const std::byte, sizeof(std::uint64_t)>(seed_bytes));
}

inline void append_u64_be(std::vector<std::byte> &bytes, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes.push_back(static_cast<std::byte>((value >> static_cast<unsigned>(shift)) & 0xffu));
    }
}

inline std::vector<std::byte>
make_secret_derivation_context(std::span<const std::byte> connection_id,
                               std::uint64_t sequence_number, std::uint64_t discriminator = 0) {
    std::vector<std::byte> context;
    context.reserve(connection_id.size() + sizeof(sequence_number) + sizeof(discriminator));
    context.insert(context.end(), connection_id.begin(), connection_id.end());
    append_u64_be(context, sequence_number);
    append_u64_be(context, discriminator);
    return context;
}

inline ConnectionId make_issued_connection_id(std::span<const std::byte> base_connection_id,
                                              std::uint64_t sequence_number) {
    ConnectionId connection_id(base_connection_id.begin(), base_connection_id.end());
    if (connection_id.empty()) {
        return connection_id;
    }

    const auto context = make_secret_derivation_context(base_connection_id, sequence_number);
    constexpr std::array label{
        std::byte{'c'}, std::byte{'o'}, std::byte{'q'}, std::byte{'u'}, std::byte{'i'},
        std::byte{'c'}, std::byte{' '}, std::byte{'c'}, std::byte{'i'}, std::byte{'d'},
    };
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1
    // # Connection IDs MUST NOT contain any information that can be used by an
    // # external observer (that is, one that does not cooperate with the issuer)
    // # to correlate them with other connection IDs for the same connection.
    const auto derived = prf_bytes<32>(quic_connection_id_secret(), label, context);
    if (derived.has_value()) {
        std::copy_n(derived->begin(), connection_id.size(), connection_id.begin());
        return connection_id;
    }

    if (rand_bytes_for_connection(connection_id)) {
        return connection_id;
    }

    std::uint64_t state = 0xcbf29ce484222325ULL;
    for (const auto byte : base_connection_id) {
        absorb_connection_id_seed_byte(state, std::to_integer<std::uint8_t>(byte));
    }
    absorb_connection_id_seed_byte(state, 0xffu);
    absorb_connection_id_seed_byte(state, static_cast<std::uint8_t>(sequence_number & 0xffu));
    for (std::size_t i = 0; i < connection_id.size(); ++i) {
        connection_id[i] =
            static_cast<std::byte>((mix_connection_id_word(state + sequence_number) >>
                                    static_cast<unsigned>((i % sizeof(std::uint64_t)) * 8u)) &
                                   0xffu);
    }
    return connection_id;
}

inline std::array<std::byte, 16> make_stateless_reset_token(
    std::span<const std::byte> connection_id, std::uint64_t sequence_number,
    const std::optional<QuicStatelessResetSecret> &configured_secret = std::nullopt) {
    std::array<std::byte, 16> token{};
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
    // # The same stateless reset token MUST NOT be used for multiple
    // # connection IDs.
    const auto context = make_secret_derivation_context(
        connection_id, configured_secret.has_value() ? 0 : sequence_number);
    constexpr std::array label{
        std::byte{'c'}, std::byte{'o'}, std::byte{'q'}, std::byte{'u'}, std::byte{'i'},
        std::byte{'c'}, std::byte{' '}, std::byte{'s'}, std::byte{'r'}, std::byte{'t'},
    };
    const auto secret = configured_secret.has_value()
                            ? std::span<const std::byte>(*configured_secret)
                            : std::span<const std::byte>(quic_reset_token_secret());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
    // # The stateless reset token MUST be difficult to guess.
    if (const auto derived = prf_bytes<16>(secret, label, context)) {
        return *derived;
    }

    if (rand_bytes_for_connection(token)) {
        return token;
    }

    for (std::size_t i = 0; i < token.size(); ++i) {
        const auto sequence_shift = static_cast<unsigned>((i % sizeof(sequence_number)) * 8u);
        auto mixed_byte = static_cast<std::uint8_t>((sequence_number >> sequence_shift) & 0xffu);
        mixed_byte ^= static_cast<std::uint8_t>(0xa5u + static_cast<unsigned>(i * 13u));
        if (!connection_id.empty()) {
            mixed_byte ^= std::to_integer<std::uint8_t>(connection_id[i % connection_id.size()]);
        }
        token[i] = std::byte{mixed_byte};
    }

    return token;
}

inline std::array<std::byte, 8>
make_path_challenge_data(std::span<const std::byte> local_connection_id, QuicPathId path_id,
                         std::uint64_t sequence_number) {
    std::array<std::byte, 8> challenge{};
    const auto context =
        make_secret_derivation_context(local_connection_id, sequence_number, path_id);
    constexpr std::array label{
        std::byte{'c'}, std::byte{'o'}, std::byte{'q'}, std::byte{'u'},
        std::byte{'i'}, std::byte{'c'}, std::byte{' '}, std::byte{'p'},
        std::byte{'a'}, std::byte{'t'}, std::byte{'h'},
    };
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.1
    // # The endpoint MUST use unpredictable data in every PATH_CHALLENGE
    // # frame so that it can associate the peer's response with the
    // # corresponding PATH_CHALLENGE.
    if (const auto derived = prf_bytes<8>(quic_path_challenge_secret(), label, context)) {
        return *derived;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.2.1
    // # The endpoint MUST use unpredictable data in every PATH_CHALLENGE
    // # frame so that it can associate the peer's response with the
    // # corresponding PATH_CHALLENGE.
    if (rand_bytes_for_connection(challenge)) {
        return challenge;
    }

    for (std::size_t index = 0; index < challenge.size(); ++index) {
        const auto path_shift = static_cast<unsigned>((index % sizeof(path_id)) * 8u);
        const auto sequence_shift = static_cast<unsigned>(index * 8u);
        auto mixed = static_cast<std::uint8_t>(((path_id >> path_shift) & 0xffu) ^
                                               ((sequence_number >> sequence_shift) & 0xffu) ^
                                               static_cast<std::uint64_t>(0x31u + index));
        if (!local_connection_id.empty()) {
            mixed ^= std::to_integer<std::uint8_t>(
                local_connection_id[(local_connection_id.size() - 1u - index) %
                                    local_connection_id.size()]);
        }
        challenge[index] = std::byte{mixed};
    }
    return challenge;
}

inline COQUIC_NO_PROFILE bool random_one_in_sixteen_from_openssl(std::uint8_t value) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.4
    // # Even when the spin bit is not disabled by the administrator,
    // # endpoints MUST disable their use of the spin bit for a random
    // # selection of at least one in every 16 network paths, or for one in
    // # every 16 connection IDs, in order to ensure that QUIC connections that
    // # disable the spin bit are commonly observed on the network.
    return (value & 0x0fu) == 0;
}

inline COQUIC_NO_PROFILE bool random_one_in_sixteen() {
    std::uint8_t value = 0;
    if (RAND_bytes(&value, 1) == 1) {
        return random_one_in_sixteen_from_openssl(value);
    }

    return random_one_in_sixteen_fallback();
}

inline COQUIC_NO_PROFILE bool closing_close_packet_can_send(bool pending, bool has_close_frame) {
    return pending & has_close_frame;
}

inline std::size_t count_active_connection_ids(
    const std::map<std::uint64_t, LocalConnectionIdRecord> &connection_ids) {
    return static_cast<std::size_t>(
        std::count_if(connection_ids.begin(), connection_ids.end(),
                      [](const auto &entry) { return !entry.second.retired; }));
}

inline std::size_t count_unretired_connection_ids_without_pending_retirement(
    const std::map<std::uint64_t, LocalConnectionIdRecord> &connection_ids) {
    return static_cast<std::size_t>(
        std::count_if(connection_ids.begin(), connection_ids.end(), [](const auto &entry) {
            return !entry.second.retired && !entry.second.retirement_requested;
        }));
}

inline bool packet_trace_matches_connection(std::span<const std::byte> local_connection_id) {
    if (!packet_trace_enabled()) {
        return false;
    }

#ifdef NDEBUG
    static const auto filter = [] {
        const char *value = std::getenv("COQUIC_PACKET_TRACE_SCID");
        return value != nullptr ? std::optional<std::string>{value} : std::nullopt;
    }();
    if (!filter.has_value() || filter->empty()) {
        return true;
    }

    const auto formatted_connection_id = format_connection_id_hex(local_connection_id);
    return std::string_view(*filter) == formatted_connection_id;
#else
    const char *filter = std::getenv("COQUIC_PACKET_TRACE_SCID");
    if (filter == nullptr || filter[0] == '\0') {
        return true;
    }

    const auto formatted_connection_id = format_connection_id_hex(local_connection_id);
    return std::string_view(filter) == formatted_connection_id;
#endif
}

inline std::string format_optional_path_id(std::optional<QuicPathId> path_id) {
    if (!path_id.has_value()) {
        return "-";
    }
    return std::to_string(*path_id);
}

inline const PathState *find_path_state(const std::map<QuicPathId, PathState> &paths,
                                        std::optional<QuicPathId> path_id) {
    if (!path_id.has_value()) {
        return nullptr;
    }
    const auto it = paths.find(*path_id);
    return it == paths.end() ? nullptr : &it->second;
}

inline COQUIC_NO_PROFILE bool path_state_is_validating(const PathState *path) {
    return path != nullptr && !path->validated;
}

inline COQUIC_NO_PROFILE bool path_state_is_validated(const PathState *path) {
    return path != nullptr && path->validated;
}

inline std::string format_path_state_summary(const PathState *path) {
    if (path == nullptr) {
        return "-";
    }

    std::ostringstream summary;
    summary << "id=" << path->id << " val=" << static_cast<int>(path->validated)
            << " cur=" << static_cast<int>(path->is_current_send_path)
            << " chal=" << static_cast<int>(path->challenge_pending)
            << " out=" << static_cast<int>(path->outstanding_challenge.has_value())
            << " resp=" << static_cast<int>(path->pending_response.has_value())
            << " recv=" << path->anti_amplification_received_bytes
            << " sent=" << path->anti_amplification_sent_bytes;
    return summary.str();
}

inline std::string format_ack_ranges(const AckFrame &ack) {
    std::ostringstream ranges;
    ranges << '[';
    if (ack.largest_acknowledged < ack.first_ack_range) {
        ranges << "invalid";
    } else {
        auto range_smallest = ack.largest_acknowledged - ack.first_ack_range;
        ranges << range_smallest << '-' << ack.largest_acknowledged;
        auto previous_smallest = range_smallest;
        for (const auto &range : ack.additional_ranges) {
            if (previous_smallest < range.gap + 2) {
                ranges << ",invalid";
                break;
            }

            const auto range_largest = previous_smallest - range.gap - 2;
            if (range_largest < range.range_length) {
                ranges << ",invalid";
                break;
            }

            range_smallest = range_largest - range.range_length;
            ranges << ',' << range_smallest << '-' << range_largest;
            previous_smallest = range_smallest;
        }
    }
    ranges << ']';
    return ranges.str();
}

inline std::string format_ack_ranges(const ReceivedAckFrame &ack) {
    auto cursor = make_ack_range_cursor(ack);
    if (!cursor.has_value()) {
        return "[invalid]";
    }

    std::ostringstream ranges;
    ranges << '[';
    bool first = true;
    while (const auto range = next_ack_range(cursor.value())) {
        if (!first) {
            ranges << ',';
        }
        ranges << range->smallest << '-' << range->largest;
        first = false;
    }
    ranges << ']';
    return ranges.str();
}

inline COQUIC_NO_PROFILE std::optional<std::uint64_t>
largest_acknowledged_by_ack_frame(std::span<const Frame> frames) {
    for (const auto &frame : frames) {
        if (const auto *ack = std::get_if<AckFrame>(&frame); ack != nullptr) {
            return ack->largest_acknowledged;
        }
        if (const auto *ack = std::get_if<OutboundAckFrame>(&frame); ack != nullptr) {
            return ack->header.largest_acknowledged;
        }
    }
    return std::nullopt;
}

inline COQUIC_NO_PROFILE std::optional<std::uint64_t>
largest_acknowledged_for_ack_eliciting_sent_record(bool ack_eliciting,
                                                   std::span<const Frame> frames) {
    if (!ack_eliciting) {
        return std::nullopt;
    }
    return largest_acknowledged_by_ack_frame(frames);
}

inline COQUIC_NO_PROFILE bool send_continuation_allowed(bool continuation_has_pending_work,
                                                        bool bypass_burst_limit,
                                                        std::size_t unpaced_ack_eliciting_packets) {
    return continuation_has_pending_work && !bypass_burst_limit &&
           unpaced_ack_eliciting_packets != 0;
}

inline std::size_t packet_stream_frame_count(const SentPacketRecord &packet);
std::optional<std::uint64_t> packet_first_stream_frame_offset(const SentPacketRecord &packet);

inline std::string summarize_packets(std::span<const SentPacketRecord> packets) {
    if (packets.empty()) {
        return "count=0";
    }

    auto [first_packet, last_packet] =
        std::minmax_element(packets.begin(), packets.end(),
                            [](const SentPacketRecord &lhs, const SentPacketRecord &rhs) {
                                return lhs.packet_number < rhs.packet_number;
                            });

    std::size_t stream_fragment_count = 0;
    std::optional<std::uint64_t> first_stream_offset;
    for (const auto &packet : packets) {
        stream_fragment_count += packet_stream_frame_count(packet);
        if (!first_stream_offset.has_value()) {
            first_stream_offset = packet_first_stream_frame_offset(packet);
        }
    }

    std::ostringstream summary;
    summary << "count=" << packets.size() << " pn=" << first_packet->packet_number << '-'
            << last_packet->packet_number << " stream_fragments=" << stream_fragment_count;
    if (first_stream_offset.has_value()) {
        summary << " first_stream_offset=" << *first_stream_offset;
    }
    return summary.str();
}

inline bool supports_version(std::span<const std::uint32_t> supported_versions,
                             std::uint32_t version) {
    return std::find(supported_versions.begin(), supported_versions.end(), version) !=
           supported_versions.end();
}

inline bool supports_quic_v2(std::span<const std::uint32_t> supported_versions) {
    return supports_version(supported_versions, kQuicVersion2);
}

inline CodecResult<bool> prime_traffic_secret_cache(const std::optional<TrafficSecret> &secret) {
    if (!secret.has_value()) {
        return CodecResult<bool>::success(true);
    }

    const auto expanded = expand_traffic_secret_cached(secret.value());
    if (!expanded.has_value()) {
        return CodecResult<bool>::failure(expanded.error().code, expanded.error().offset);
    }

    return CodecResult<bool>::success(true);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
inline bool is_initial_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    if (version == kQuicVersion2) {
        return packet_type == 0x01u;
    }
    return packet_type == 0x00u;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
inline bool is_handshake_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    if (version == kQuicVersion2) {
        return packet_type == 0x03u;
    }
    return packet_type == 0x02u;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
inline bool is_zero_rtt_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    if (version == kQuicVersion2) {
        return packet_type == 0x02u;
    }
    return packet_type == 0x01u;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
inline bool is_bufferable_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    return is_initial_long_header_type(version, packet_type) |
           is_zero_rtt_long_header_type(version, packet_type) |
           is_handshake_long_header_type(version, packet_type);
}

inline std::uint32_t read_u32_be(std::span<const std::byte> bytes);

inline bool packet_is_bufferable(std::span<const std::byte> packet_bytes) {
    const auto first_byte = std::to_integer<std::uint8_t>(packet_bytes.front());
    if ((first_byte & 0x80u) == 0) {
        return true;
    }

    if (packet_bytes.size() < 5) {
        return false;
    }

    const auto version = read_u32_be(packet_bytes.subspan(1, 4));
    return is_bufferable_long_header_type(version,
                                          static_cast<std::uint8_t>((first_byte >> 4) & 0x03u));
}

inline bool datagram_starts_with_initial_packet(std::span<const std::byte> bytes) {
    if (bytes.size() < 5) {
        return false;
    }

    const auto first_byte = std::to_integer<std::uint8_t>(bytes.front());
    if ((first_byte & 0x80u) == 0 || (first_byte & 0x40u) == 0) {
        return false;
    }

    const auto version = read_u32_be(bytes.subspan(1, 4));
    if (!is_supported_quic_version(version)) {
        return false;
    }

    return is_initial_long_header_type(version,
                                       static_cast<std::uint8_t>((first_byte >> 4) & 0x03u));
}

inline bool datagram_starts_with_initial_packet(std::span<const std::byte> bytes,
                                                bool accept_greased_quic_bit) {
    if (!accept_greased_quic_bit) {
        return datagram_starts_with_initial_packet(bytes);
    }
    if (bytes.size() < 5) {
        return false;
    }

    const auto first_byte = std::to_integer<std::uint8_t>(bytes.front());
    if ((first_byte & 0x80u) == 0) {
        return false;
    }

    const auto version = read_u32_be(bytes.subspan(1, 4));
    if (!is_supported_quic_version(version)) {
        return false;
    }

    return is_initial_long_header_type(version,
                                       static_cast<std::uint8_t>((first_byte >> 4) & 0x03u));
}

inline std::optional<VersionInformation>
make_local_version_information(std::span<const std::uint32_t> supported_versions,
                               std::uint32_t chosen_version) {
    if (!supports_quic_v2(supported_versions)) {
        return std::nullopt;
    }

    //= https://www.rfc-editor.org/rfc/rfc9368#section-3
    // # Any version of QUIC that supports this mechanism MUST provide a
    // # mechanism to exchange Version Information in both directions during
    // # the handshake, such that this data is authenticated.
    //= https://www.rfc-editor.org/rfc/rfc9369#section-4
    // # Any QUIC endpoint that supports QUIC version 2 MUST send, process,
    // # and validate the version_information transport parameter specified in
    // # [QUIC-VN] to prevent version downgrade attacks.
    return VersionInformation{
        .chosen_version = chosen_version,
        //= https://www.rfc-editor.org/rfc/rfc9368#section-3
        // # Note that the
        // # version in the Chosen Version field MUST be included in this list
        // # to allow the client to communicate the Chosen Version's
        // # preference.
        .available_versions =
            std::vector<std::uint32_t>(supported_versions.begin(), supported_versions.end()),
    };
}

inline std::optional<VersionInformation>
version_information_for_handshake(std::span<const std::uint32_t> supported_versions,
                                  std::uint32_t chosen_version,
                                  const std::optional<ConnectionId> &retry_source_connection_id,
                                  std::uint32_t original_version, std::uint32_t current_version) {
    if (retry_source_connection_id.has_value() && current_version == original_version) {
        return std::nullopt;
    }

    return make_local_version_information(supported_versions, chosen_version);
}

inline std::uint32_t select_server_version(std::span<const std::uint32_t> supported_versions,
                                           std::uint32_t client_initial_version) {
    if (supports_version(supported_versions, client_initial_version)) {
        return client_initial_version;
    }

    //= https://www.rfc-editor.org/rfc/rfc9368#section-2.2
    // # Implementations MUST NOT assume compatibility
    // # between versions unless explicitly specified.
    return client_initial_version;
}

inline EndpointRole opposite_role(EndpointRole role) {
    return role == EndpointRole::client ? EndpointRole::server : EndpointRole::client;
}

inline std::vector<std::byte> application_protocol_bytes(std::string_view protocol) {
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte *>(protocol.data()),
        reinterpret_cast<const std::byte *>(protocol.data() + protocol.size()));
}

inline void log_codec_failure(std::string_view where, const CodecError &error) {
    static_cast<void>(where);
    static_cast<void>(error);
}

inline std::size_t datagram_size_or_zero(const CodecResult<std::vector<std::byte>> &datagram) {
    const auto *value = std::get_if<std::vector<std::byte>>(&datagram.storage);
    return value == nullptr ? 0 : value->size();
}

inline std::size_t datagram_size_or_zero(const CodecResult<SerializedProtectedDatagram> &datagram) {
    const auto *value = std::get_if<SerializedProtectedDatagram>(&datagram.storage);
    return value == nullptr ? 0 : value->bytes.size();
}

inline COQUIC_NO_PROFILE bool
is_empty_packet_payload_error(const CodecResult<std::vector<std::byte>> &datagram) {
    const auto *error = std::get_if<CodecError>(&datagram.storage);
    return error != nullptr && error->code == CodecErrorCode::empty_packet_payload;
}

inline COQUIC_NO_PROFILE bool
is_empty_packet_payload_error(const CodecResult<SerializedProtectedDatagram> &datagram) {
    const auto *error = std::get_if<CodecError>(&datagram.storage);
    return error != nullptr && error->code == CodecErrorCode::empty_packet_payload;
}

inline std::uint32_t read_u32_be(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | std::to_integer<std::uint8_t>(byte);
    }

    return value;
}

inline void append_u32_be(std::vector<std::byte> &output, std::uint32_t value) {
    output.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
    output.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    output.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    output.push_back(static_cast<std::byte>(value & 0xffu));
}

inline void append_length_prefixed_bytes(std::vector<std::byte> &output,
                                         std::span<const std::byte> bytes) {
    append_u32_be(output, static_cast<std::uint32_t>(bytes.size()));
    output.insert(output.end(), bytes.begin(), bytes.end());
}

inline void append_length_prefixed_text(std::vector<std::byte> &output, std::string_view text) {
    append_u32_be(output, static_cast<std::uint32_t>(text.size()));
    output.insert(output.end(), reinterpret_cast<const std::byte *>(text.data()),
                  reinterpret_cast<const std::byte *>(text.data() + text.size()));
}

inline std::optional<std::span<const std::byte>>
read_length_prefixed_bytes(std::span<const std::byte> bytes, std::size_t &offset) {
    if (offset + 4 > bytes.size()) {
        return std::nullopt;
    }

    const auto length = read_u32_be(bytes.subspan(offset, 4));
    offset += 4;
    if (offset + length > bytes.size()) {
        return std::nullopt;
    }

    const auto value = bytes.subspan(offset, length);
    offset += length;
    return value;
}

inline std::vector<std::byte>
encode_resumption_state(std::span<const std::byte> tls_state, std::uint32_t quic_version,
                        std::string_view application_protocol,
                        const TransportParameters &peer_transport_parameters,
                        std::span<const std::byte> application_context) {
    std::vector<std::byte> encoded;
    const auto serialized_transport_parameters =
        serialize_transport_parameters(peer_transport_parameters);
    if (!serialized_transport_parameters.has_value()) {
        return encoded;
    }

    encoded.push_back(std::byte{0x01});
    append_u32_be(encoded, quic_version);
    append_length_prefixed_bytes(encoded, tls_state);
    append_length_prefixed_text(encoded, application_protocol);
    append_length_prefixed_bytes(encoded, serialized_transport_parameters.value());
    append_length_prefixed_bytes(encoded, application_context);
    return encoded;
}

inline std::optional<StoredClientResumptionState>
decode_resumption_state(std::span<const std::byte> bytes) {
    if (bytes.size() < 5 || bytes.front() != std::byte{0x01}) {
        return std::nullopt;
    }

    std::size_t offset = 1;
    const auto quic_version = read_u32_be(bytes.subspan(offset, 4));
    offset += 4;

    const auto tls_state_bytes = read_length_prefixed_bytes(bytes, offset);
    const auto application_protocol_bytes = read_length_prefixed_bytes(bytes, offset);
    const auto transport_parameters_bytes = read_length_prefixed_bytes(bytes, offset);
    const auto application_context_bytes = read_length_prefixed_bytes(bytes, offset);
    if (!tls_state_bytes.has_value() || !application_protocol_bytes.has_value() ||
        !transport_parameters_bytes.has_value() || !application_context_bytes.has_value() ||
        offset != bytes.size()) {
        return std::nullopt;
    }

    const auto peer_transport_parameters =
        deserialize_transport_parameters(*transport_parameters_bytes);
    if (!peer_transport_parameters.has_value()) {
        return std::nullopt;
    }

    StoredClientResumptionState state{
        .tls_state = std::vector<std::byte>(tls_state_bytes->begin(), tls_state_bytes->end()),
        .quic_version = quic_version,
        .application_protocol =
            std::string(reinterpret_cast<const char *>(application_protocol_bytes->data()),
                        application_protocol_bytes->size()),
        .peer_transport_parameters = peer_transport_parameters.value(),
        .application_context = std::vector<std::byte>(application_context_bytes->begin(),
                                                      application_context_bytes->end()),
    };
    return state;
}

inline bool zero_rtt_transport_limits_not_reduced(const TransportParameters &remembered,
                                                  const TransportParameters &current) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4.1
    // # A server MAY store and recover the previously sent values of the
    // # max_idle_timeout, max_udp_payload_size, and disable_active_migration
    // # parameters and reject 0-RTT if it selects smaller values.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4.1
    // # If 0-RTT data is accepted by the server, the server MUST NOT reduce
    // # any limits or alter any values that might be violated by the client
    // # with its 0-RTT data.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4.1
    // # In particular, a server that accepts 0-RTT data MUST NOT set values
    // # for the following parameters (Section 18.2) that are smaller than the
    // # remembered values of the parameters.
    return current.active_connection_id_limit >= remembered.active_connection_id_limit &&
           current.initial_max_data >= remembered.initial_max_data &&
           current.initial_max_stream_data_bidi_local >=
               remembered.initial_max_stream_data_bidi_local &&
           current.initial_max_stream_data_bidi_remote >=
               remembered.initial_max_stream_data_bidi_remote &&
           current.initial_max_stream_data_uni >= remembered.initial_max_stream_data_uni &&
           current.initial_max_streams_bidi >= remembered.initial_max_streams_bidi &&
           current.initial_max_streams_uni >= remembered.initial_max_streams_uni &&
           current.max_datagram_frame_size >= remembered.max_datagram_frame_size;
}

inline std::uint64_t transport_error_code_value(QuicTransportErrorCode code) {
    return static_cast<std::uint64_t>(code);
}

inline CodecError transport_codec_error(CodecErrorCode codec_error,
                                        QuicTransportErrorCode transport_error,
                                        std::uint64_t frame_type, std::size_t offset = 0) {
    return CodecError{
        .code = codec_error,
        .offset = offset,
        .transport_error_code = transport_error_code_value(transport_error),
        .has_transport_error_code = true,
        .frame_type = frame_type,
        .has_frame_type = true,
    };
}

template <typename T>
inline CodecResult<T> transport_failure(CodecErrorCode codec_error,
                                        QuicTransportErrorCode transport_error,
                                        std::uint64_t frame_type, std::size_t offset = 0) {
    return CodecResult<T>::failure(
        transport_codec_error(codec_error, transport_error, frame_type, offset));
}

inline COQUIC_NO_PROFILE QuicTransportErrorCode
stream_transport_error_for_state_error(StreamStateErrorCode code) {
    switch (code) {
    case StreamStateErrorCode::invalid_stream_id:
        return QuicTransportErrorCode::stream_limit_error;
    case StreamStateErrorCode::invalid_stream_direction:
    case StreamStateErrorCode::send_side_closed:
    case StreamStateErrorCode::receive_side_closed:
        return QuicTransportErrorCode::stream_state_error;
    case StreamStateErrorCode::flow_control_violation:
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
        // # A receiver MUST close the connection with an error of type
        // # FLOW_CONTROL_ERROR if the sender violates the advertised connection
        // # or stream data limits; see Section 11 for details on error handling.
        return QuicTransportErrorCode::flow_control_error;
    case StreamStateErrorCode::final_size_conflict:
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
        // # If a RESET_STREAM or STREAM frame is received indicating a change
        // # in the final size for the stream, an endpoint SHOULD respond with
        // # an error of type FINAL_SIZE_ERROR; see Section 11 for details on
        // # error handling.
        return QuicTransportErrorCode::final_size_error;
    }
    return QuicTransportErrorCode::protocol_violation;
}

inline CodecError stream_state_codec_error(StreamStateErrorCode code, std::uint64_t frame_type) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 stream_transport_error_for_state_error(code), frame_type);
}

inline CodecError stream_state_codec_error(const StreamStateError &error,
                                           std::uint64_t frame_type) {
    return stream_state_codec_error(error.code, frame_type);
}

inline CodecError stream_state_codec_error(const CodecError &error, std::uint64_t frame_type) {
    auto out = error;
    out.frame_type = frame_type;
    out.has_frame_type = true;
    if (!out.has_transport_error_code) {
        out.transport_error_code =
            transport_error_code_value(QuicTransportErrorCode::stream_state_error);
        out.has_transport_error_code = true;
    }
    return out;
}

inline std::uint64_t stream_frame_type_for(bool has_offset, bool has_length, bool fin) {
    return kFrameTypeStreamBase | (fin ? 0x01u : 0u) | (has_length ? 0x02u : 0u) |
           (has_offset ? 0x04u : 0u);
}

inline std::uint64_t stream_frame_type_for(const StreamFrame &frame) {
    return stream_frame_type_for(frame.has_offset, frame.has_length, frame.fin);
}

inline std::uint64_t stream_frame_type_for(const ReceivedStreamFrame &frame) {
    return stream_frame_type_for(frame.has_offset, frame.has_length, frame.fin);
}

inline std::uint64_t datagram_frame_type_for(bool has_length) {
    return kFrameTypeDatagram | (has_length ? 0x01u : 0u);
}

inline std::uint64_t datagram_frame_type_for(const DatagramFrame &frame) {
    return datagram_frame_type_for(frame.has_length);
}

inline std::uint64_t datagram_frame_type_for(const ReceivedDatagramFrame &frame) {
    return datagram_frame_type_for(frame.has_length);
}

inline std::size_t datagram_frame_wire_size(std::size_t payload_size, bool has_length) {
    return std::size_t{1} + (has_length ? encoded_varint_size(payload_size) : std::size_t{0}) +
           payload_size;
}

inline std::uint64_t frame_type_for_max_streams(StreamLimitType type) {
    return type == StreamLimitType::bidirectional ? kFrameTypeMaxStreamsBidi
                                                  : kFrameTypeMaxStreamsUni;
}

inline std::uint64_t frame_type_for_streams_blocked(StreamLimitType type) {
    return type == StreamLimitType::bidirectional ? kFrameTypeStreamsBlockedBidi
                                                  : kFrameTypeStreamsBlockedUni;
}

inline CodecError frame_encoding_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::frame_encoding_error, frame_type, offset);
}

inline CodecError protocol_violation_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::protocol_violation, frame_type, offset);
}

inline CodecError optimistic_ack_protocol_violation_error(std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::protocol_violation, /*frame_type=*/0,
                                 offset);
}

inline CodecError key_update_error() {
    //= https://www.rfc-editor.org/rfc/rfc9001#section-6.2
    // # An endpoint MAY treat such consecutive key updates as a connection
    // # error of type KEY_UPDATE_ERROR.
    //= https://www.rfc-editor.org/rfc/rfc9001#section-6.2
    // # An endpoint that receives an acknowledgment that is carried in a packet
    // # protected with old keys where any acknowledged packet was protected
    // # with newer keys MAY treat that as a connection error of type
    // # KEY_UPDATE_ERROR.
    return transport_codec_error(CodecErrorCode::invalid_packet_protection_state,
                                 QuicTransportErrorCode::key_update_error, /*frame_type=*/0);
}

inline CodecError frame_not_allowed_protocol_violation_error(std::uint64_t frame_type,
                                                             std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::frame_not_allowed_in_packet_type,
                                 QuicTransportErrorCode::protocol_violation, frame_type, offset);
}

inline CodecError flow_control_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::flow_control_error, frame_type, offset);
}

inline CodecError stream_limit_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::stream_limit_error, frame_type, offset);
}

inline CodecError stream_state_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::stream_state_error, frame_type, offset);
}

inline CodecError connection_id_limit_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::connection_id_limit_error, frame_type,
                                 offset);
}

inline CodecError aead_limit_reached_error() {
    //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
    // # If a key update is not possible or integrity limits are reached, the
    // # endpoint MUST stop using the connection and only send stateless resets
    // # in response to receiving packets.
    //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
    // # It is RECOMMENDED that endpoints immediately close the connection with
    // # a connection error of type AEAD_LIMIT_REACHED before reaching a state
    // # where key updates are not possible.
    return CodecError{
        .code = CodecErrorCode::invalid_packet_protection_state,
        .offset = 0,
        .transport_error_code =
            transport_error_code_value(QuicTransportErrorCode::aead_limit_reached),
        .has_transport_error_code = true,
    };
}

inline CodecError transport_parameter_error(CodecErrorCode code, std::size_t offset = 0) {
    return CodecError{
        .code = code,
        .offset = offset,
        .transport_error_code =
            transport_error_code_value(QuicTransportErrorCode::transport_parameter_error),
        .has_transport_error_code = true,
    };
}

inline CodecError version_negotiation_error(std::size_t offset = 0) {
    return CodecError{
        .code = CodecErrorCode::invalid_packet_protection_state,
        .offset = offset,
        .transport_error_code =
            transport_error_code_value(QuicTransportErrorCode::version_negotiation_error),
        .has_transport_error_code = true,
    };
}

inline COQUIC_NO_PROFILE QuicTransportErrorCode
transport_error_for_codec_error(CodecErrorCode code) {
    switch (code) {
    case CodecErrorCode::truncated_input:
    case CodecErrorCode::invalid_varint:
    case CodecErrorCode::unknown_frame_type:
    case CodecErrorCode::non_shortest_frame_type_encoding:
    case CodecErrorCode::empty_packet_payload:
    case CodecErrorCode::packet_length_mismatch:
    case CodecErrorCode::frame_not_allowed_in_packet_type:
        return QuicTransportErrorCode::frame_encoding_error;
    case CodecErrorCode::unsupported_cipher_suite:
    case CodecErrorCode::invalid_packet_protection_state:
        return QuicTransportErrorCode::transport_parameter_error;
    case CodecErrorCode::crypto_buffer_exceeded:
        //= https://www.rfc-editor.org/rfc/rfc9000#section-7.5
        // # If an endpoint does not expand its buffer, it MUST close the
        // # connection with a CRYPTO_BUFFER_EXCEEDED error code.
        return QuicTransportErrorCode::crypto_buffer_exceeded;
    case CodecErrorCode::invalid_reserved_bits:
    case CodecErrorCode::unsupported_packet_type:
    case CodecErrorCode::malformed_short_header_context:
    case CodecErrorCode::packet_number_recovery_failed:
        return QuicTransportErrorCode::protocol_violation;
    case CodecErrorCode::invalid_fixed_bit:
    case CodecErrorCode::missing_crypto_context:
    case CodecErrorCode::header_protection_sample_too_short:
    case CodecErrorCode::header_protection_failed:
    case CodecErrorCode::packet_decryption_failed:
        return QuicTransportErrorCode::internal_error;
    case CodecErrorCode::http09_parse_error:
    case CodecErrorCode::http3_parse_error:
        return QuicTransportErrorCode::application_error;
    }
    return QuicTransportErrorCode::protocol_violation;
}

inline QuicCoreDuration transport_parameter_milliseconds(std::uint64_t milliseconds) {
    using Rep = QuicCoreDuration::rep;
    constexpr auto max_milliseconds =
        static_cast<std::uint64_t>(std::numeric_limits<Rep>::max() / 1000);
    const auto clamped_milliseconds = std::min(milliseconds, max_milliseconds);
    return QuicCoreDuration{static_cast<Rep>(clamped_milliseconds) * Rep{1000}};
}

inline QuicCoreDuration three_pto_period(const RecoveryRttState &rtt) {
    const auto pto_reference =
        std::max(compute_pto_deadline(rtt, QuicCoreDuration{0}, QuicCoreTimePoint{},
                                      /*pto_count=*/0) -
                     QuicCoreTimePoint{},
                 QuicCoreClock::duration::zero());
    return std::chrono::duration_cast<QuicCoreDuration>(pto_reference *
                                                        kPersistentCongestionThreshold);
}

inline PacketSpaceState &packet_space_for_level(EncryptionLevel level,
                                                PacketSpaceState &initial_space,
                                                PacketSpaceState &handshake_space,
                                                PacketSpaceState &zero_rtt_space,
                                                PacketSpaceState &application_space) {
    if (level == EncryptionLevel::initial) {
        return initial_space;
    }
    if (level == EncryptionLevel::handshake) {
        return handshake_space;
    }
    if (level == EncryptionLevel::zero_rtt) {
        return zero_rtt_space;
    }

    return application_space;
}

template <typename FrameType> bool is_padding_frame(const FrameType &frame) {
    return std::holds_alternative<PaddingFrame>(frame);
}

template <typename FrameType> bool is_ack_eliciting_frame(const FrameType &frame) {
    constexpr auto kAckElicitingByFrameIndex = std::to_array<bool>({
        false, // PaddingFrame
        true,  // PingFrame
        false, // AckFrame
        true,  // ResetStreamFrame
        true,  // StopSendingFrame
        true,  // CryptoFrame
        true,  // NewTokenFrame
        true,  // StreamFrame
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.21
        // # Extension frames MUST be congestion controlled and MUST cause an ACK
        // # frame to be sent.
        true,  // DatagramFrame
        true,  // MaxDataFrame
        true,  // MaxStreamDataFrame
        true,  // MaxStreamsFrame
        true,  // DataBlockedFrame
        true,  // StreamDataBlockedFrame
        true,  // StreamsBlockedFrame
        true,  // NewConnectionIdFrame
        true,  // RetireConnectionIdFrame
        true,  // PathChallengeFrame
        true,  // PathResponseFrame
        false, // TransportConnectionCloseFrame
        false, // ApplicationConnectionCloseFrame
        true,  // HandshakeDoneFrame
        false, // OutboundAckFrame
    });

    return kAckElicitingByFrameIndex[frame.index()];
}

template <typename FrameRange> bool has_ack_eliciting_frame(const FrameRange &frames) {
    for (const auto &frame : frames) {
        if (is_ack_eliciting_frame(frame)) {
            return true;
        }
    }

    return false;
}

inline bool one_rtt_packet_is_ack_eliciting(const ProtectedOneRttPacket &packet) {
    return has_ack_eliciting_frame(packet.frames) || !packet.stream_frame_views.empty();
}

inline std::size_t one_rtt_packet_count(std::span<const ProtectedPacket> packets) {
    return static_cast<std::size_t>(
        std::ranges::count_if(packets, [](const ProtectedPacket &packet) {
            return std::holds_alternative<ProtectedOneRttPacket>(packet);
        }));
}

inline bool packet_is_one_rtt_ack_eliciting(const ProtectedPacket &packet) {
    const auto *one_rtt = std::get_if<ProtectedOneRttPacket>(&packet);
    return one_rtt != nullptr && one_rtt_packet_is_ack_eliciting(*one_rtt);
}

inline std::size_t one_rtt_ack_eliciting_packet_count(std::span<const ProtectedPacket> packets) {
    return static_cast<std::size_t>(
        std::ranges::count_if(packets, [](const ProtectedPacket &packet) {
            return packet_is_one_rtt_ack_eliciting(packet);
        }));
}

template <typename FrameRange> bool is_probing_only_frames(const FrameRange &frames) {
    return std::ranges::all_of(frames, [](const auto &frame) {
        return is_padding_frame(frame) | std::holds_alternative<PathChallengeFrame>(frame) |
               std::holds_alternative<PathResponseFrame>(frame) |
               std::holds_alternative<NewConnectionIdFrame>(frame);
    });
}

inline COQUIC_NO_PROFILE const ReceivedAckFrame *
single_received_ack_frame_or_null(const ReceivedFrameList &frames) {
    if (frames.size() != 1) {
        return nullptr;
    }

    return std::get_if<ReceivedAckFrame>(&frames.front());
}

inline COQUIC_NO_PROFILE const ReceivedStreamFrame *
single_received_stream_frame_or_null(const ReceivedFrameList &frames) {
    if (frames.size() != 1) {
        return nullptr;
    }

    return std::get_if<ReceivedStreamFrame>(&frames.front());
}

inline std::optional<DeadlineTrackedPacket>
latest_in_flight_ack_eliciting_packet(const PacketSpaceState &packet_space) {
    return packet_space.recovery.latest_in_flight_ack_eliciting_packet();
}

inline std::optional<DeadlineTrackedPacket>
earliest_loss_packet(const PacketSpaceState &packet_space) {
    return packet_space.recovery.earliest_loss_packet();
}

inline bool has_in_flight_ack_eliciting_packet(const PacketSpaceState &packet_space) {
    return latest_in_flight_ack_eliciting_packet(packet_space).has_value();
}

inline bool should_ignore_received_packet(const PacketSpaceState &packet_space,
                                          std::uint64_t packet_number) {
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.5
    // # Once an endpoint successfully receives a packet with a given packet
    // # number, it MUST discard all packets in the same packet number space
    // # with higher packet numbers if they cannot be successfully unprotected
    // # with either the same key, or -- if there is a key update -- a
    // # subsequent packet protection key; see Section 6.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.3
    // # A receiver MUST discard a newly unprotected packet unless it is
    // # certain that it has not processed another packet with the same packet
    // # number from the same packet number space.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.3
    // # Duplicate suppression MUST
    // # happen after removing packet protection for the reasons described in
    // # Section 9.5 of [QUIC-TLS].
    return packet_space.received_packets.should_ignore(packet_number);
}

inline void note_authenticated_packet_number(PacketSpaceState &packet_space,
                                             std::uint64_t packet_number) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.3
    // # Receivers can discard all ACK Ranges, but they MUST retain the
    // # largest packet number that has been successfully processed, as that
    // # is used to recover packet numbers from subsequent packets; see
    // # Section 17.1.
    packet_space.largest_authenticated_packet_number = std::max(
        packet_space.largest_authenticated_packet_number.value_or(packet_number), packet_number);
}

inline void note_ignored_ack_eliciting_received_packet(PacketSpaceState &packet_space,
                                                       std::uint64_t packet_number,
                                                       bool ack_eliciting, QuicCoreTimePoint now,
                                                       QuicEcnCodepoint ecn,
                                                       std::uint64_t ack_eliciting_threshold) {
    packet_space.received_packets.record_received(packet_number, ack_eliciting, now, ecn,
                                                  ack_eliciting_threshold);
    if (ack_eliciting) {
        packet_space.pending_ack_deadline = now;
        packet_space.force_ack_send |= ecn == QuicEcnCodepoint::ce;
    }
}

inline void schedule_application_ack_deadline(PacketSpaceState &packet_space, QuicCoreTimePoint now,
                                              std::uint64_t max_ack_delay_ms,
                                              QuicEcnCodepoint ecn) {
    if (ecn == QuicEcnCodepoint::ce) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
        // # Similarly, packets marked with the ECN Congestion Experienced (CE)
        // # codepoint in the IP header SHOULD be acknowledged immediately, to
        // # reduce the peer's response time to congestion events.
        packet_space.pending_ack_deadline = now;
        packet_space.force_ack_send = true;
        return;
    }

    if (packet_space.received_packets.requests_immediate_ack()) {
        packet_space.pending_ack_deadline = now;
        return;
    }

    if (!packet_space.pending_ack_deadline.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
        // # When only non-ack-eliciting packets need to
        // # be acknowledged, an endpoint MAY choose not to send an ACK frame with
        // # outgoing frames until an ack-eliciting packet has been received.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
        // # Every packet SHOULD be acknowledged at least once, and
        // # ack-eliciting packets MUST be acknowledged at least once within the
        // # maximum delay an endpoint communicated using the max_ack_delay
        // # transport parameter; see Section 18.2.
        //= https://www.rfc-editor.org/rfc/rfc9221#section-5.2
        // # Receivers SHOULD support delaying ACK frames (within the limits
        // # specified by max_ack_delay) in response to receiving packets that
        // # only contain DATAGRAM frames, since the sender takes no action if
        // # these packets are temporarily unacknowledged.
        packet_space.pending_ack_deadline =
            now + transport_parameter_milliseconds(max_ack_delay_ms);
    }
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
inline void note_ignored_application_received_packet(PacketSpaceState &packet_space,
                                                     std::uint64_t packet_number,
                                                     bool ack_eliciting, QuicCoreTimePoint now,
                                                     QuicEcnCodepoint ecn,
                                                     std::uint64_t ack_eliciting_threshold,
                                                     std::uint64_t max_ack_delay_ms) {
    packet_space.received_packets.record_received(packet_number, ack_eliciting, now, ecn,
                                                  ack_eliciting_threshold);
    if (ack_eliciting) {
        schedule_application_ack_deadline(packet_space, now, max_ack_delay_ms, ecn);
    }
}
// NOLINTEND(bugprone-easily-swappable-parameters)

template <typename Alternative, typename Variant> struct VariantContainsAlternative;

template <typename Alternative, typename... Variants>
struct VariantContainsAlternative<Alternative, std::variant<Variants...>>
    : std::bool_constant<(std::is_same_v<Alternative, Variants> || ...)> {};

template <typename Alternative, typename Variant>
inline bool holds_alternative_if_present(const Variant &variant) {
    if constexpr (VariantContainsAlternative<Alternative, std::decay_t<Variant>>::value) {
        return std::holds_alternative<Alternative>(variant);
    }
    return false;
}

template <typename FrameType>
inline bool requires_connected_application_state_for_inbound_frame(const FrameType &frame) {
    return holds_alternative_if_present<ResetStreamFrame>(frame) |
           holds_alternative_if_present<StopSendingFrame>(frame) |
           holds_alternative_if_present<DatagramFrame>(frame) |
           holds_alternative_if_present<ReceivedDatagramFrame>(frame) |
           holds_alternative_if_present<MaxStreamDataFrame>(frame) |
           holds_alternative_if_present<MaxStreamsFrame>(frame) |
           holds_alternative_if_present<DataBlockedFrame>(frame) |
           holds_alternative_if_present<StreamDataBlockedFrame>(frame) |
           holds_alternative_if_present<StreamsBlockedFrame>(frame);
}

inline bool should_defer_protected_one_rtt_packet(const ProtectedOneRttPacket &packet,
                                                  EndpointRole local_role, HandshakeStatus status) {
    if (status != HandshakeStatus::in_progress) {
        return false;
    }

    if (local_role == EndpointRole::server) {
        //= https://www.rfc-editor.org/rfc/rfc9001#section-5.7
        // # A server MUST NOT process incoming 1-RTT protected packets before
        // # the TLS handshake is complete.
        //= https://www.rfc-editor.org/rfc/rfc9001#section-5.7
        // # Received packets protected with 1-RTT keys MAY be stored and later
        // # decrypted and used once the handshake is complete.
        return true;
    }

    return std::ranges::any_of(packet.frames, [](const Frame &frame) {
        return requires_connected_application_state_for_inbound_frame(frame);
    });
}

inline bool should_defer_protected_one_rtt_packet(const ReceivedProtectedOneRttPacket &packet,
                                                  EndpointRole local_role, HandshakeStatus status) {
    if (status != HandshakeStatus::in_progress) {
        return false;
    }

    if (local_role == EndpointRole::server) {
        //= https://www.rfc-editor.org/rfc/rfc9001#section-5.7
        // # A server MUST NOT process incoming 1-RTT protected packets before
        // # the TLS handshake is complete.
        //= https://www.rfc-editor.org/rfc/rfc9001#section-5.7
        // # Received packets protected with 1-RTT keys MAY be stored and later
        // # decrypted and used once the handshake is complete.
        return true;
    }

    return std::ranges::any_of(packet.frames, [](const ReceivedFrame &frame) {
        return requires_connected_application_state_for_inbound_frame(frame);
    });
}

inline bool should_defer_protected_one_rtt_packet(const ProtectedPacket &packet,
                                                  EndpointRole local_role, HandshakeStatus status) {
    const auto *one_rtt = std::get_if<ProtectedOneRttPacket>(&packet);
    return one_rtt != nullptr ? should_defer_protected_one_rtt_packet(*one_rtt, local_role, status)
                              : false;
}

inline bool
should_defer_protected_one_rtt_packet(const ReceivedProtectedOneRttAckOnlyPacket &packet,
                                      EndpointRole local_role, HandshakeStatus status) {
    static_cast<void>(packet);
    static_cast<void>(local_role);
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.7
    // # A server MUST NOT process incoming 1-RTT protected packets before the
    // # TLS handshake is complete.
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.7
    // # Received packets protected with 1-RTT keys MAY be stored and later
    // # decrypted and used once the handshake is complete.
    return status == HandshakeStatus::in_progress && local_role == EndpointRole::server;
}

inline bool should_defer_protected_one_rtt_packet(const ReceivedProtectedOneRttStreamPacket &packet,
                                                  EndpointRole local_role, HandshakeStatus status) {
    static_cast<void>(packet);
    if (status != HandshakeStatus::in_progress) {
        return false;
    }

    return local_role == EndpointRole::server;
}

inline bool should_defer_protected_one_rtt_packet(const ReceivedProtectedPacket &packet,
                                                  EndpointRole local_role, HandshakeStatus status) {
    const auto *one_rtt = std::get_if<ReceivedProtectedOneRttPacket>(&packet);
    if (one_rtt != nullptr) {
        return should_defer_protected_one_rtt_packet(*one_rtt, local_role, status);
    }
    const auto *ack_only = std::get_if<ReceivedProtectedOneRttAckOnlyPacket>(&packet);
    if (ack_only != nullptr) {
        return should_defer_protected_one_rtt_packet(*ack_only, local_role, status);
    }
    const auto *stream = std::get_if<ReceivedProtectedOneRttStreamPacket>(&packet);
    if (stream != nullptr) {
        return should_defer_protected_one_rtt_packet(*stream, local_role, status);
    }
    return false;
}

inline std::optional<std::uint64_t>
protected_one_rtt_packet_number_for_trace(const ProtectedPacket &packet) {
    const auto *one_rtt = std::get_if<ProtectedOneRttPacket>(&packet);
    return one_rtt != nullptr ? std::optional<std::uint64_t>(one_rtt->packet_number) : std::nullopt;
}

inline std::optional<std::uint64_t>
protected_one_rtt_packet_number_for_trace(const ReceivedProtectedPacket &packet) {
    const auto *one_rtt = std::get_if<ReceivedProtectedOneRttPacket>(&packet);
    if (one_rtt != nullptr) {
        return one_rtt->packet_number;
    }
    const auto *ack_only = std::get_if<ReceivedProtectedOneRttAckOnlyPacket>(&packet);
    if (ack_only != nullptr) {
        return ack_only->packet_number;
    }
    const auto *stream = std::get_if<ReceivedProtectedOneRttStreamPacket>(&packet);
    if (stream != nullptr) {
        return stream->packet_number;
    }
    return std::nullopt;
}

inline bool packet_can_advance_tls_state(const ProtectedPacket &packet) {
    return std::visit(
        [](const auto &protected_packet) {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket> ||
                          std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                return true;
            } else {
                return std::ranges::any_of(protected_packet.frames, [](const Frame &frame) {
                    return std::holds_alternative<CryptoFrame>(frame);
                });
            }
        },
        packet);
}

inline bool packet_can_advance_tls_state(const ReceivedProtectedPacket &packet) {
    return std::visit(
        [](const auto &protected_packet) {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            if constexpr (std::is_same_v<PacketType, ReceivedProtectedInitialPacket> ||
                          std::is_same_v<PacketType, ReceivedProtectedHandshakePacket>) {
                return true;
            } else if constexpr (std::is_same_v<PacketType, ReceivedProtectedOneRttAckOnlyPacket> ||
                                 std::is_same_v<PacketType, ReceivedProtectedOneRttStreamPacket>) {
                return false;
            } else {
                return std::ranges::any_of(protected_packet.frames, [](const ReceivedFrame &frame) {
                    return std::holds_alternative<ReceivedCryptoFrame>(frame);
                });
            }
        },
        packet);
}

inline bool is_discardable_short_header_packet_error(CodecErrorCode code) {
    static constexpr std::array kDiscardableErrors = {
        CodecErrorCode::invalid_fixed_bit,
        CodecErrorCode::invalid_packet_protection_state,
        CodecErrorCode::packet_length_mismatch,
        CodecErrorCode::packet_decryption_failed,
        CodecErrorCode::header_protection_failed,
        CodecErrorCode::header_protection_sample_too_short,
    };
    return std::ranges::find(kDiscardableErrors, code) != kDiscardableErrors.end();
}

inline bool can_retry_short_header_with_next_key_phase(CodecErrorCode code) {
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.5
    // # Similarly, a packet that appears to trigger a key update but cannot be
    // # unprotected successfully MUST be discarded.
    static constexpr std::array kRetryableErrors = {
        CodecErrorCode::invalid_packet_protection_state,
        CodecErrorCode::unsupported_packet_type,
        CodecErrorCode::packet_decryption_failed,
        CodecErrorCode::header_protection_failed,
    };
    return std::ranges::find(kRetryableErrors, code) != kRetryableErrors.end();
}

inline std::optional<std::uint64_t>
confidentiality_limit_for_cipher_suite(CipherSuite cipher_suite) {
    if (cipher_suite == CipherSuite::tls_aes_128_gcm_sha256 ||
        cipher_suite == CipherSuite::tls_aes_256_gcm_sha384) {
        //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
        // # Any TLS cipher suite that is specified for use with QUIC MUST
        // # define limits on the use of the associated AEAD function that
        // # preserves margins for confidentiality and integrity.
        //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
        // # That is, limits MUST be specified for the number of packets that
        // # can be authenticated and for the number of packets that can fail
        // # authentication.
        return kAesGcmConfidentialityLimit;
    }
    return std::nullopt;
}

inline std::optional<std::uint64_t>
proactive_key_update_packet_limit_for_cipher_suite(CipherSuite cipher_suite) {
    const auto limit = confidentiality_limit_for_cipher_suite(cipher_suite);
    if (!limit.has_value()) {
        return std::nullopt;
    }
    return *limit / kProactiveKeyUpdatePacketLimitDivisor;
}

inline std::optional<std::uint64_t> integrity_limit_for_cipher_suite(CipherSuite cipher_suite) {
    if (cipher_suite == CipherSuite::tls_aes_128_gcm_sha256 ||
        cipher_suite == CipherSuite::tls_aes_256_gcm_sha384) {
        //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
        // # Any TLS cipher suite that is specified for use with QUIC MUST
        // # define limits on the use of the associated AEAD function that
        // # preserves margins for confidentiality and integrity.
        //= https://www.rfc-editor.org/rfc/rfc9001#section-6.6
        // # That is, limits MUST be specified for the number of packets that
        // # can be authenticated and for the number of packets that can fail
        // # authentication.
        return kAesGcmIntegrityLimit;
    }
    if (cipher_suite == CipherSuite::tls_chacha20_poly1305_sha256) {
        return kChaCha20Poly1305IntegrityLimit;
    }
    return std::nullopt;
}

inline bool packet_authentication_failed(CodecErrorCode code) {
    return code == CodecErrorCode::packet_decryption_failed ||
           code == CodecErrorCode::header_protection_failed ||
           code == CodecErrorCode::invalid_packet_protection_state;
}

inline bool is_discardable_packet_length_error(CodecErrorCode code) {
    static constexpr std::array kDiscardableErrors = {
        CodecErrorCode::invalid_fixed_bit,
        CodecErrorCode::unsupported_packet_type,
    };
    return std::ranges::find(kDiscardableErrors, code) != kDiscardableErrors.end();
}

inline bool peer_validated_grease_quic_bit_support(
    bool local_grease_quic_bit_enabled, bool peer_transport_parameters_validated,
    const std::optional<TransportParameters> &peer_transport_parameters) {
    //= https://www.rfc-editor.org/rfc/rfc9287#section-3.1
    // # However, a client MUST NOT set the QUIC Bit to 0
    // # unless the Initial packets it sends include a token provided by the
    // # server in a NEW_TOKEN frame (Section 19.7 of [QUIC]), received less
    // # than 604800 seconds (7 days) prior on a connection where the server
    // # also included the grease_quic_bit transport parameter.
    //= https://www.rfc-editor.org/rfc/rfc9287#section-3.1
    // # A server MUST set the QUIC Bit to 0 only after processing transport
    // # parameters from a client.
    //= https://www.rfc-editor.org/rfc/rfc9287#section-3.1
    // # A server MUST NOT remember that a client
    // # negotiated the extension in a previous connection and set the QUIC
    // # Bit to 0 based on that information.
    //= https://www.rfc-editor.org/rfc/rfc9287#section-3.1
    // # An endpoint MUST NOT set the QUIC Bit to 0 without knowing whether
    // # the peer supports the extension.
    return local_grease_quic_bit_enabled && peer_transport_parameters_validated &&
           peer_transport_parameters.has_value() && peer_transport_parameters->grease_quic_bit;
}

inline CodecResult<std::size_t>
peek_discardable_long_header_packet_length(std::span<const std::byte> bytes) {
    BufferReader reader(bytes);
    const auto first_byte = reader.read_byte();
    if (!first_byte.has_value()) {
        return CodecResult<std::size_t>::failure(first_byte.error().code,
                                                 first_byte.error().offset);
    }

    const auto header_byte = std::to_integer<std::uint8_t>(first_byte.value());
    if ((header_byte & 0x80u) == 0) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }

    const auto version = reader.read_exact(4);
    if (!version.has_value()) {
        return CodecResult<std::size_t>::failure(version.error().code, version.error().offset);
    }
    const auto version_value = read_u32_be(version.value());
    if (!is_supported_quic_version(version_value)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto destination_connection_id_length = reader.read_byte();
    if (!destination_connection_id_length.has_value()) {
        return CodecResult<std::size_t>::failure(destination_connection_id_length.error().code,
                                                 destination_connection_id_length.error().offset);
    }
    const auto destination_connection_id_length_value =
        std::to_integer<std::uint8_t>(destination_connection_id_length.value());
    if (destination_connection_id_length_value > 20) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }
    const auto destination_connection_id =
        reader.read_exact(destination_connection_id_length_value);
    if (!destination_connection_id.has_value()) {
        return CodecResult<std::size_t>::failure(destination_connection_id.error().code,
                                                 destination_connection_id.error().offset);
    }

    const auto source_connection_id_length = reader.read_byte();
    if (!source_connection_id_length.has_value()) {
        return CodecResult<std::size_t>::failure(source_connection_id_length.error().code,
                                                 source_connection_id_length.error().offset);
    }
    const auto source_connection_id_length_value =
        std::to_integer<std::uint8_t>(source_connection_id_length.value());
    if (source_connection_id_length_value > 20) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }
    const auto source_connection_id = reader.read_exact(source_connection_id_length_value);
    if (!source_connection_id.has_value()) {
        return CodecResult<std::size_t>::failure(source_connection_id.error().code,
                                                 source_connection_id.error().offset);
    }

    const auto packet_type = static_cast<std::uint8_t>((header_byte >> 4) & 0x03u);
    if (is_initial_long_header_type(version_value, packet_type)) {
        const auto token_length = decode_varint(reader);
        if (!token_length.has_value()) {
            return CodecResult<std::size_t>::failure(token_length.error().code,
                                                     token_length.error().offset);
        }
        if (token_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                     reader.offset());
        }
        static_cast<void>(reader.read_exact(static_cast<std::size_t>(token_length.value().value)));
    } else if (!is_zero_rtt_long_header_type(version_value, packet_type) &&
               !is_handshake_long_header_type(version_value, packet_type)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto payload_length = decode_varint(reader);
    if (!payload_length.has_value()) {
        return CodecResult<std::size_t>::failure(payload_length.error().code,
                                                 payload_length.error().offset);
    }
    if (payload_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                 reader.offset());
    }

    return CodecResult<std::size_t>::success(
        reader.offset() + static_cast<std::size_t>(payload_length.value().value));
}

inline bool should_discard_corrupted_long_header_packet(bool short_header_packet,
                                                        CodecErrorCode code) {
    return !short_header_packet && (code == CodecErrorCode::invalid_fixed_bit ||
                                    code == CodecErrorCode::unsupported_packet_type ||
                                    code == CodecErrorCode::packet_decryption_failed ||
                                    code == CodecErrorCode::header_protection_failed);
}

inline COQUIC_NO_PROFILE bool invalid_fixed_bit_is_rejected(std::uint8_t header_byte,
                                                            bool grease_quic_bit) {
    return (header_byte & 0x40u) == 0 && !grease_quic_bit;
}

inline std::uint64_t saturating_subtract(std::uint64_t limit, std::uint64_t used) {
    return limit - std::min(limit, used);
}

inline std::uint64_t saturating_add(std::uint64_t lhs, std::uint64_t rhs) {
    const auto max = std::numeric_limits<std::uint64_t>::max();
    return rhs > max - lhs ? max : lhs + rhs;
}

inline bool application_frame_requires_connected_state(bool require_connected,
                                                       HandshakeStatus status) {
    return require_connected & (status != HandshakeStatus::connected);
}

inline COQUIC_NO_PROFILE bool application_datagram_requires_connected_state(
    bool require_connected, bool application_read_secret_available, HandshakeStatus status) {
    const bool allow_preconnected_datagram_frame =
        application_read_secret_available && status == HandshakeStatus::in_progress;
    return application_frame_requires_connected_state(
        require_connected && !allow_preconnected_datagram_frame, status);
}

inline COQUIC_NO_PROFILE bool peer_connection_id_route_changed(
    const std::map<std::uint64_t, PeerConnectionIdRecord> &peer_connection_ids,
    const ConnectionId &source_connection_id, std::uint64_t active_peer_connection_id_sequence) {
    const auto peer = peer_connection_ids.find(0);
    if (peer == peer_connection_ids.end()) {
        return true;
    }
    if (peer->second.connection_id != source_connection_id) {
        return true;
    }
    if (peer->second.locally_retired) {
        return true;
    }
    return active_peer_connection_id_sequence != 0;
}

inline bool should_adopt_supported_client_version(EndpointRole role,
                                                  std::span<const std::uint32_t> supported_versions,
                                                  std::uint32_t packet_version,
                                                  std::uint32_t current_version) {
    return (role == EndpointRole::client) & (current_version == kQuicVersion1) &
           supports_version(supported_versions, packet_version) &
           (packet_version != current_version);
}

inline bool should_drop_wrong_version_client_long_header(
    EndpointRole role, std::span<const std::uint32_t> supported_versions,
    std::uint32_t packet_version, std::uint32_t current_version) {
    if (role != EndpointRole::client || packet_version == current_version) {
        return false;
    }
    if (current_version == kQuicVersion1 && supports_version(supported_versions, packet_version)) {
        return false;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.1
    // # If a client receives a packet that uses a different version than it
    // # initially selected, it MUST discard that packet.
    //= https://www.rfc-editor.org/rfc/rfc9369#section-4.1
    // # An endpoint MUST drop packets using any other
    // # version.
    return true;
}

inline std::optional<QuicCoreTimePoint>
earliest_of(std::initializer_list<std::optional<QuicCoreTimePoint>> deadlines) {
    std::optional<QuicCoreTimePoint> earliest;
    for (const auto &deadline : deadlines) {
        if (!deadline.has_value()) {
            continue;
        }

        if (!earliest.has_value() || *deadline < *earliest) {
            earliest = deadline;
        }
    }

    return earliest;
}

inline std::uint64_t effective_idle_timeout_ms(const TransportParameters &local,
                                               const std::optional<TransportParameters> &peer) {
    if (local.max_idle_timeout == 0) {
        return peer.has_value() ? peer->max_idle_timeout : 0;
    }
    if (!peer.has_value() || peer->max_idle_timeout == 0) {
        return local.max_idle_timeout;
    }

    return std::min(local.max_idle_timeout, peer->max_idle_timeout);
}

struct EncodedAckDelay {
    std::uint64_t value;
};

struct AckDelayExponent {
    std::uint64_t value;
};

inline std::chrono::microseconds decode_ack_delay(EncodedAckDelay ack_delay,
                                                  AckDelayExponent ack_delay_exponent) {
    if (ack_delay_exponent.value >= std::numeric_limits<std::uint64_t>::digits) {
        return std::chrono::microseconds(0);
    }

    const auto max_microseconds =
        static_cast<std::uint64_t>(std::numeric_limits<std::chrono::microseconds::rep>::max()) >>
        ack_delay_exponent.value;
    const auto bounded_ack_delay = std::min<std::uint64_t>(ack_delay.value, max_microseconds);
    return std::chrono::microseconds(bounded_ack_delay << ack_delay_exponent.value);
}

inline std::chrono::microseconds decode_ack_delay(const AckFrame &ack,
                                                  std::uint64_t ack_delay_exponent) {
    return decode_ack_delay(EncodedAckDelay{.value = ack.ack_delay},
                            AckDelayExponent{.value = ack_delay_exponent});
}

inline std::chrono::microseconds decode_ack_delay(const ReceivedAckFrame &ack,
                                                  std::uint64_t ack_delay_exponent) {
    return decode_ack_delay(EncodedAckDelay{.value = ack.ack_delay},
                            AckDelayExponent{.value = ack_delay_exponent});
}

inline std::size_t stream_fragment_bytes(std::span<const StreamFrameSendFragment> fragments) {
    std::size_t total = 0;
    for (const auto &fragment : fragments) {
        total += fragment.bytes.size();
    }

    return total;
}

inline std::size_t stream_metadata_bytes(std::span<const StreamFrameSendMetadata> metadata) {
    std::size_t total = 0;
    for (const auto &entry : metadata) {
        total += entry.length;
    }

    return total;
}

inline std::size_t stream_fragment_wire_bytes(std::span<const StreamFrameSendFragment> fragments) {
    std::size_t total = 0;
    for (const auto &fragment : fragments) {
        total += fragment.stream_frame_wire_size();
    }

    return total;
}

inline bool packet_has_stream_frames(const SentPacketRecord &packet) {
    return sent_packet_has_stream_frames(packet);
}

inline std::size_t packet_stream_frame_count(const SentPacketRecord &packet) {
    return static_cast<std::size_t>(packet.first_stream_frame_metadata.has_value()) +
           packet.stream_frame_metadata.size() + packet.stream_fragments.size();
}

inline std::size_t packet_stream_frame_bytes(const SentPacketRecord &packet) {
    return (packet.first_stream_frame_metadata.has_value()
                ? packet.first_stream_frame_metadata->length
                : 0) +
           stream_metadata_bytes(packet.stream_frame_metadata) +
           stream_fragment_bytes(packet.stream_fragments);
}

inline std::optional<std::uint64_t>
packet_first_stream_frame_offset(const SentPacketRecord &packet) {
    if (packet.first_stream_frame_metadata.has_value()) {
        return packet.first_stream_frame_metadata->offset;
    }
    if (!packet.stream_frame_metadata.empty()) {
        return packet.stream_frame_metadata.front().offset;
    }
    if (!packet.stream_fragments.empty()) {
        return packet.stream_fragments.front().offset;
    }
    return std::nullopt;
}

inline void assign_stream_frame_metadata(SentPacketRecord &packet,
                                         std::span<const StreamFrameSendFragment> fragments) {
    if (fragments.empty()) {
        packet.first_stream_frame_metadata.reset();
        packet.stream_frame_metadata.clear();
        return;
    }

    packet.first_stream_frame_metadata = stream_frame_send_metadata(fragments.front());
    packet.stream_frame_metadata.clear();
    if (fragments.size() == 1) {
        return;
    }

    packet.stream_frame_metadata.reserve(fragments.size() - 1);
    for (const auto &fragment : fragments.subspan(1)) {
        packet.stream_frame_metadata.push_back(stream_frame_send_metadata(fragment));
    }
}

template <typename Callback>
inline void for_each_stream_frame_metadata(const SentPacketRecord &packet, Callback &&callback) {
    if (packet.first_stream_frame_metadata.has_value()) {
        callback(*packet.first_stream_frame_metadata);
    }
    for (const auto &metadata : packet.stream_frame_metadata) {
        callback(metadata);
    }
}

inline std::size_t stream_frame_header_wire_size(std::uint64_t stream_id, std::uint64_t offset,
                                                 std::size_t payload_size) {
    return std::size_t{1} + encoded_varint_size(stream_id) + encoded_varint_size(offset) +
           encoded_varint_size(payload_size);
}

inline std::size_t
max_stream_frame_payload_for_wire_budget(std::uint64_t stream_id,
                                         // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                                         std::uint64_t offset, std::size_t wire_budget) {
    if (offset > kMaxQuicVarInt) {
        return 0;
    }

    const auto fixed_header_size =
        std::size_t{1} + encoded_varint_size(stream_id) + encoded_varint_size(offset);
    if (wire_budget <= fixed_header_size) {
        return 0;
    }

    const auto max_payload_by_offset = kMaxQuicVarInt - offset;
    std::size_t best = 0;
    constexpr std::array payload_varint_limits{
        std::pair{std::size_t{1}, std::uint64_t{63}},
        std::pair{std::size_t{2}, std::uint64_t{16383}},
        std::pair{std::size_t{4}, std::uint64_t{1073741823}},
        std::pair{std::size_t{8}, kMaxQuicVarInt},
    };
    for (const auto [payload_length_size, payload_length_limit] : payload_varint_limits) {
        const auto header_size = fixed_header_size + payload_length_size;
        if (wire_budget < header_size) {
            continue;
        }
        const auto candidate =
            std::min<std::uint64_t>({static_cast<std::uint64_t>(wire_budget - header_size),
                                     payload_length_limit, max_payload_by_offset});
        best = std::max(best, static_cast<std::size_t>(candidate));
    }

    return best;
}

inline COQUIC_NO_PROFILE std::size_t
short_header_minimum_payload_bytes_for_header_sample(std::uint8_t packet_number_length) {
    const auto header_protection_payload_bytes =
        packet_number_length >= kShortHeaderProtectionSampleOffset
            ? 0
            : kShortHeaderProtectionSampleOffset - packet_number_length;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # To achieve that end, the endpoint SHOULD ensure that all packets it
    // # sends are at least 22 bytes longer than the minimum connection ID length
    // # that it requests the peer to include in its packets, adding PADDING
    // # frames as necessary.
    return header_protection_payload_bytes + 1;
}

inline COQUIC_NO_PROFILE std::uint8_t
packet_number_length_for_send(const PacketSpaceState &packet_space, std::uint64_t packet_number) {
    const auto largest_acked = packet_space.recovery.largest_acked_packet_number();
    if (!largest_acked.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.1
        // # Prior to receiving an acknowledgment for a packet number space, the
        // # full packet number MUST be included; it is not to be truncated, as
        // # described below.
        return kFullPacketNumberLength;
    }

    const auto difference = packet_number >= *largest_acked ? packet_number - *largest_acked
                                                            : *largest_acked - packet_number;
    for (std::uint8_t packet_number_length = 1; packet_number_length < kFullPacketNumberLength;
         ++packet_number_length) {
        const auto range = std::uint64_t{1} << (packet_number_length * 8);
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.1
        // # After an acknowledgment is received for a packet number space, the
        // # sender MUST use a packet number size able to represent more than
        // # twice as large a range as the difference between the largest
        // # acknowledged packet number and the packet number being sent.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.1
        // # An endpoint SHOULD use a large enough packet number encoding to allow
        // # the packet number to be recovered even if the packet arrives after
        // # packets that are sent afterwards.
        if (range > difference * 2u) {
            return packet_number_length;
        }
    }
    return kFullPacketNumberLength;
}

inline COQUIC_NO_PROFILE bool one_rtt_stream_frame_must_have_length(const StreamFrame *stream,
                                                                    std::size_t frame_index,
                                                                    std::size_t frame_count,
                                                                    bool has_stream_fragments) {
    return stream != nullptr && !stream->has_length &&
           (frame_index + 1 != frame_count || has_stream_fragments);
}

inline CodecResult<std::size_t>
one_rtt_packet_fragment_view_wire_size(const ProtectedOneRttPacketFragmentView &packet) {
    const auto packet_number_offset = 1 + packet.destination_connection_id.size();
    const auto payload_offset = packet_number_offset + packet.packet_number_length;

    std::size_t payload_size = 0;
    for (std::size_t frame_index = 0; frame_index < packet.frames.size(); ++frame_index) {
        if (const auto *stream = std::get_if<StreamFrame>(&packet.frames[frame_index]);
            one_rtt_stream_frame_must_have_length(stream, frame_index, packet.frames.size(),
                                                  !packet.stream_fragments.empty())) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                     frame_index);
        }
        if (const auto *datagram = std::get_if<DatagramFrame>(&packet.frames[frame_index]);
            datagram != nullptr && !datagram->has_length &&
            (frame_index + 1 != packet.frames.size() || !packet.stream_fragments.empty())) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                     frame_index);
        }

        const auto frame_size = serialized_frame_size(packet.frames[frame_index]);
        if (!frame_size.has_value()) {
            return CodecResult<std::size_t>::failure(frame_size.error().code,
                                                     frame_size.error().offset);
        }
        payload_size += frame_size.value();
    }

    for (std::size_t fragment_index = 0; fragment_index < packet.stream_fragments.size();
         ++fragment_index) {
        const auto &fragment = packet.stream_fragments[fragment_index];
        if (fragment.offset > kMaxQuicVarInt - fragment.bytes.size()) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint,
                                                     packet.frames.size() + fragment_index);
        }
        payload_size += fragment.stream_frame_wire_size();
    }

    if (payload_size == 0) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::empty_packet_payload, 0);
    }

    const auto plaintext_payload_size =
        std::max(payload_size,
                 short_header_minimum_payload_bytes_for_header_sample(packet.packet_number_length));
    return CodecResult<std::size_t>::success(payload_offset + plaintext_payload_size +
                                             kOneRttPacketProtectionTagLength);
}

inline std::vector<StreamFrameView>
make_stream_frame_views(std::span<const StreamFrameSendFragment> fragments) {
    std::vector<StreamFrameView> views;
    views.reserve(fragments.size());
    for (const auto &fragment : fragments) {
        views.push_back(StreamFrameView{
            .fin = fragment.fin,
            .stream_id = fragment.stream_id,
            .offset = fragment.offset,
            .storage = fragment.bytes.storage(),
            .begin = fragment.bytes.begin_offset(),
            .end = fragment.bytes.end_offset(),
        });
    }

    return views;
}

inline std::size_t application_stream_frame_budget(
    std::size_t max_datagram_size, // NOLINT(bugprone-easily-swappable-parameters)
    std::size_t destination_connection_id_size, std::uint8_t packet_number_length) {
    const auto packet_overhead = std::size_t{1} + destination_connection_id_size +
                                 packet_number_length + kOneRttPacketProtectionTagLength;
    if (max_datagram_size <= packet_overhead) {
        return 0;
    }
    return max_datagram_size - packet_overhead;
}

inline void append_stream_fragments_to_frames(std::vector<Frame> &frames,
                                              std::span<const StreamFrameSendFragment> fragments) {
    for (const auto &fragment : fragments) {
        frames.emplace_back(StreamFrame{
            .fin = fragment.fin,
            .has_offset = true,
            .has_length = true,
            .stream_id = fragment.stream_id,
            .offset = fragment.offset,
            .stream_data = fragment.bytes.to_vector(),
        });
    }
}

inline ProtectedPacket make_application_protected_packet(
    bool use_zero_rtt_packet_protection, std::uint32_t version,
    const ConnectionId &destination_connection_id, const ConnectionId &source_connection_id,
    bool one_rtt_key_phase, std::uint8_t packet_number_length, std::uint64_t packet_number,
    std::vector<Frame> frames, std::span<const StreamFrameSendFragment> stream_fragments) {
    if (use_zero_rtt_packet_protection) {
        append_stream_fragments_to_frames(frames, stream_fragments);
        return ProtectedZeroRttPacket{
            .version = version,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = source_connection_id,
            .packet_number_length = packet_number_length,
            .packet_number = packet_number,
            .frames = std::move(frames),
        };
    }

    return ProtectedOneRttPacket{
        .spin_bit = false,
        .key_phase = one_rtt_key_phase,
        .destination_connection_id = destination_connection_id,
        .packet_number_length = packet_number_length,
        .packet_number = packet_number,
        .frames = std::move(frames),
        .stream_frame_views = make_stream_frame_views(stream_fragments),
    };
}

inline void set_application_packet_spin_bit(ProtectedPacket &packet, bool spin_bit) {
    if (auto *one_rtt = std::get_if<ProtectedOneRttPacket>(&packet); one_rtt != nullptr) {
        one_rtt->spin_bit = spin_bit;
    }
}

inline CodecResult<std::vector<std::byte>> serialize_locally_validated_transport_parameters(
    EndpointRole local_role, const TransportParameters &parameters,
    const TransportParametersValidationContext &validation_context) {
    const auto validation =
        validate_peer_transport_parameters(local_role, parameters, validation_context);
    if (!validation.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(validation.error().code,
                                                            validation.error().offset);
    }

    return serialize_transport_parameters(parameters);
}

inline bool max_data_frame_matches(const std::optional<MaxDataFrame> &candidate,
                                   const MaxDataFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return candidate->maximum_data == frame.maximum_data;
}

inline bool data_blocked_frame_matches(const std::optional<DataBlockedFrame> &candidate,
                                       const DataBlockedFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return candidate->maximum_data == frame.maximum_data;
}

inline bool reset_stream_frame_matches(const std::optional<ResetStreamFrame> &candidate,
                                       const ResetStreamFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->application_protocol_error_code,
                    candidate->final_size) ==
           std::tie(frame.stream_id, frame.application_protocol_error_code, frame.final_size);
}

inline bool stop_sending_frame_matches(const std::optional<StopSendingFrame> &candidate,
                                       const StopSendingFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->application_protocol_error_code) ==
           std::tie(frame.stream_id, frame.application_protocol_error_code);
}

inline bool max_stream_data_frame_matches(const std::optional<MaxStreamDataFrame> &candidate,
                                          const MaxStreamDataFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->maximum_stream_data) ==
           std::tie(frame.stream_id, frame.maximum_stream_data);
}

inline bool max_streams_frame_matches(const std::optional<MaxStreamsFrame> &candidate,
                                      const MaxStreamsFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_type, candidate->maximum_streams) ==
           std::tie(frame.stream_type, frame.maximum_streams);
}

inline bool
stream_data_blocked_frame_matches(const std::optional<StreamDataBlockedFrame> &candidate,
                                  const StreamDataBlockedFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->maximum_stream_data) ==
           std::tie(frame.stream_id, frame.maximum_stream_data);
}

inline bool should_refresh_receive_window(std::uint64_t delivered_bytes,
                                          std::uint64_t advertised_limit, std::uint64_t window,
                                          bool force) {
    if (window == 0 || advertised_limit < delivered_bytes) {
        return false;
    }

    if (force) {
        return true;
    }

    const auto remaining = advertised_limit - delivered_bytes;
    if (window <= 1) {
        return remaining == 0;
    }

    return remaining < (window / 2);
}

inline bool packet_space_is_application(const PacketSpaceState &packet_space,
                                        const PacketSpaceState &application_space) {
    return &packet_space == &application_space;
}

inline bool stream_fin_sendable(const StreamState &stream) {
    if (stream.send_fin_state != StreamSendFinState::pending ||
        !stream.send_final_size.has_value()) {
        return false;
    }

    return *stream.send_final_size <= stream.flow_control.peer_max_stream_data &&
           !stream.send_buffer.has_pending_data();
}

inline std::uint64_t fresh_sendable_bytes_for_cache(const StreamState &stream) {
    return stream.reset_state == StreamControlFrameState::none ? stream.sendable_bytes() : 0;
}

inline bool stream_receive_terminal(const StreamState &stream) {
    return !stream.id_info.local_can_receive | stream.peer_fin_delivered |
           stream.peer_reset_received;
}

inline bool stream_send_terminal(const StreamState &stream) {
    return !stream.id_info.local_can_send |
           (stream.send_fin_state == StreamSendFinState::acknowledged) |
           (stream.reset_state == StreamControlFrameState::acknowledged);
}

inline std::vector<std::uint64_t>
round_robin_stream_order(const std::map<std::uint64_t, StreamState> &streams,
                         std::optional<std::uint64_t> last_stream_id) {
    std::vector<std::uint64_t> order;
    order.reserve(streams.size());
    if (streams.empty()) {
        return order;
    }

    auto append_order = [&](auto begin, auto end) {
        for (auto it = begin; it != end; ++it) {
            order.push_back(it->first);
        }
    };

    if (!last_stream_id.has_value()) {
        append_order(streams.begin(), streams.end());
        return order;
    }

    const auto start = streams.upper_bound(*last_stream_id);
    append_order(start, streams.end());
    append_order(streams.begin(), start);
    return order;
}

inline std::vector<std::uint64_t>
unfair_stream_order(const std::map<std::uint64_t, StreamState> &streams,
                    std::optional<std::uint64_t> last_stream_id) {
    std::vector<std::uint64_t> order;
    order.reserve(streams.size());
    if (streams.empty()) {
        return order;
    }

    auto append_order = [&](auto begin, auto end) {
        for (auto it = begin; it != end; ++it) {
            order.push_back(it->first);
        }
    };

    if (!last_stream_id.has_value()) {
        append_order(streams.begin(), streams.end());
        return order;
    }

    const auto start = streams.lower_bound(*last_stream_id);
    append_order(start, streams.end());
    append_order(streams.begin(), start);
    return order;
}

inline std::vector<SentPacketRecord>
ack_eliciting_in_flight_losses(std::span<const SentPacketRecord> packets) {
    std::vector<SentPacketRecord> filtered;
    filtered.reserve(packets.size());
    for (const auto &packet : packets) {
        if (!packet.ack_eliciting || packet.bytes_in_flight == 0 || packet.is_pmtu_probe) {
            continue;
        }

        filtered.push_back(packet);
    }

    return filtered;
}

inline std::size_t sanitize_pmtud_base(std::size_t value) {
    return std::max<std::size_t>(kMinimumInitialDatagramSize, value);
}

inline std::size_t initial_congestion_datagram_size(const QuicCoreConfig &config) {
    auto datagram_size = config.transport.pmtud_enabled
                             ? sanitize_pmtud_base(config.transport.pmtud_base_datagram_size)
                             : kMinimumInitialDatagramSize;
    datagram_size = std::min(datagram_size, config.max_outbound_datagram_size);
    if (config.transport.pmtud_max_datagram_size != 0) {
        datagram_size = std::min(datagram_size, config.transport.pmtud_max_datagram_size);
    }
    return std::max<std::size_t>(kMaximumDatagramSize, datagram_size);
}

inline COQUIC_NO_PROFILE bool pmtud_probe_needs_minimum_growth(std::size_t candidate,
                                                               std::size_t low, std::size_t high) {
    return candidate - low < kPmtudMinimumProbeGrowth && candidate != high;
}

inline COQUIC_NO_PROFILE std::uint64_t
packet_number_for_sent_record(const ProtectedPacket &packet) {
    if (const auto *initial = std::get_if<ProtectedInitialPacket>(&packet)) {
        return initial->packet_number;
    }
    if (const auto *handshake = std::get_if<ProtectedHandshakePacket>(&packet)) {
        return handshake->packet_number;
    }
    if (const auto *zero_rtt = std::get_if<ProtectedZeroRttPacket>(&packet)) {
        return zero_rtt->packet_number;
    }
    return std::get<ProtectedOneRttPacket>(packet).packet_number;
}

inline COQUIC_NO_PROFILE std::size_t
close_packet_metadata_length_for_tracking(const SerializedProtectedDatagram &candidate) {
    if (candidate.packet_metadata.empty()) {
        return 0;
    }
    return candidate.packet_metadata.front().length;
}

inline std::size_t next_probe_size_between(std::size_t low, std::size_t high) {
    if (high <= low + kPmtudMinimumProbeGrowth) {
        return high;
    }

    const auto common_probe_size = [&](std::size_t candidate) -> std::optional<std::size_t> {
        if (candidate <= low || candidate > high) {
            return std::nullopt;
        }
        if (pmtud_probe_needs_minimum_growth(candidate, low, high)) {
            return std::nullopt;
        }
        return candidate;
    };

    if (const auto ipv4_ethernet_probe = common_probe_size(kPmtudIPv4EthernetUdpPayloadSize)) {
        return *ipv4_ethernet_probe;
    }
    if (const auto ipv6_ethernet_probe = common_probe_size(kPmtudIPv6EthernetUdpPayloadSize)) {
        return *ipv6_ethernet_probe;
    }

    const auto midpoint = low + ((high - low) / 2);
    return std::max(low + kPmtudMinimumProbeGrowth, midpoint);
}

inline bool pmtud_probe_size_previously_failed(const PathMtuState &mtu, std::size_t probe_size) {
    return std::find(mtu.failed_probe_sizes.begin(), mtu.failed_probe_sizes.end(), probe_size) !=
           mtu.failed_probe_sizes.end();
}

inline COQUIC_NO_PROFILE std::optional<std::uint32_t>
next_qlog_inbound_datagram_id(qlog::Session *qlog_session) {
    return qlog_session != nullptr
               ? std::optional<std::uint32_t>(qlog_session->next_inbound_datagram_id())
               : std::nullopt;
}

inline COQUIC_NO_PROFILE bool can_skip_steady_state_receive_sync(
    EndpointRole role, HandshakeStatus status, bool peer_transport_parameters_validated,
    const std::optional<TrafficSecret> &application_read_secret,
    const std::optional<TrafficSecret> &application_write_secret, bool resumption_state_emitted,
    bool peer_preferred_address_emitted,
    const std::optional<TransportParameters> &peer_transport_parameters,
    const qlog::Session *qlog_session, std::span<const std::byte> bytes,
    bool accept_greased_quic_bit = false) {
    return status == HandshakeStatus::connected && peer_transport_parameters_validated &&
           application_read_secret.has_value() && application_write_secret.has_value() &&
           (role == EndpointRole::server || resumption_state_emitted) &&
           (peer_preferred_address_emitted || !peer_transport_parameters.has_value() ||
            !peer_transport_parameters->preferred_address.has_value()) &&
           qlog_session == nullptr &&
           !datagram_starts_with_initial_packet(bytes, accept_greased_quic_bit) &&
           (std::to_integer<std::uint8_t>(bytes.front()) & 0x80u) == 0;
}

inline COQUIC_NO_PROFILE bool can_use_single_short_header_datagram_fast_path(
    bool steady_state_one_rtt_receive, bool allow_in_place_receive_decode,
    const std::optional<TrafficSecret> &previous_application_read_secret,
    std::span<const std::byte> bytes) {
    return steady_state_one_rtt_receive && allow_in_place_receive_decode &&
           !previous_application_read_secret.has_value() && !bytes.empty() &&
           (std::to_integer<std::uint8_t>(bytes.front()) & 0x80u) == 0 &&
           (std::to_integer<std::uint8_t>(bytes.front()) & 0x40u) != 0;
}

inline COQUIC_NO_PROFILE bool
traffic_secret_cache_is_primed(const std::optional<TrafficSecret> &secret) {
    return secret.has_value() && secret->cached_packet_protection_keys.has_value();
}

inline COQUIC_NO_PROFILE COQUIC_NOINLINE bool
should_defer_short_header_packet_before_server_handshake_complete(bool allow_defer,
                                                                  bool short_header_packet,
                                                                  EndpointRole role,
                                                                  HandshakeStatus status) {
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.7
    // # A server MUST NOT process incoming 1-RTT protected packets before the
    // # TLS handshake is complete.
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.7
    // # Received packets protected with 1-RTT keys MAY be stored and later
    // # decrypted and used once the handshake is complete.
    return static_cast<unsigned>(allow_defer) & static_cast<unsigned>(short_header_packet) &
           static_cast<unsigned>(role == EndpointRole::server) &
           static_cast<unsigned>(status == HandshakeStatus::in_progress);
}

inline COQUIC_NO_PROFILE bool
deferred_protected_datagram_matches(const DeferredProtectedDatagram &candidate, QuicPathId path_id,
                                    std::span<const std::byte> bytes) {
    return candidate.path_id == path_id && candidate.bytes == bytes;
}

inline COQUIC_NO_PROFILE void
queue_deferred_protected_datagram(std::vector<DeferredProtectedDatagram> &deferred_packets,
                                  std::span<const std::byte> bytes, QuicPathId path_id,
                                  std::optional<std::uint32_t> datagram_id, QuicEcnCodepoint ecn,
                                  QuicCoreTimePoint received_at) {
    for (const auto &candidate : deferred_packets) {
        if (deferred_protected_datagram_matches(candidate, path_id, bytes)) {
            return;
        }
    }
    if (deferred_packets.size() >= kMaximumDeferredProtectedPackets) {
        deferred_packets.erase(deferred_packets.begin());
    }
    deferred_packets.emplace_back(DatagramBuffer(bytes), path_id, datagram_id, ecn, received_at);
}

inline COQUIC_NO_PROFILE COQUIC_NOINLINE bool
defer_short_header_packet_before_server_handshake_complete(
    bool allow_defer, bool short_header_packet, EndpointRole role, HandshakeStatus status,
    std::vector<DeferredProtectedDatagram> &deferred_packets, std::span<const std::byte> bytes,
    QuicPathId path_id, std::optional<std::uint32_t> datagram_id, QuicEcnCodepoint ecn,
    QuicCoreTimePoint received_at) {
    if (!should_defer_short_header_packet_before_server_handshake_complete(
            allow_defer, short_header_packet, role, status)) {
        return false;
    }

    queue_deferred_protected_datagram(deferred_packets, bytes, path_id, datagram_id, ecn,
                                      received_at);
    return true;
}

template <typename Packet>
inline COQUIC_NO_PROFILE bool
should_defer_decoded_protected_packet(bool allow_defer, const Packet &packet, EndpointRole role,
                                      HandshakeStatus status) {
    return allow_defer && should_defer_protected_one_rtt_packet(packet, role, status);
}

inline COQUIC_NO_PROFILE bool inbound_packet_storage_range_is_eligible(
    bool allow_in_place_receive_decode,
    const std::optional<TrafficSecret> &previous_application_read_secret, HandshakeStatus status,
    const std::shared_ptr<std::vector<std::byte>> &storage,
    std::span<const std::byte> packet_bytes) {
    return allow_in_place_receive_decode && !previous_application_read_secret.has_value() &&
           status != HandshakeStatus::in_progress && storage != nullptr && !storage->empty() &&
           packet_bytes.data() != nullptr;
}

inline COQUIC_NO_PROFILE bool packet_bytes_start_inside_storage(std::uintptr_t packet_begin_address,
                                                                std::uintptr_t storage_begin,
                                                                std::uintptr_t storage_end) {
    return packet_begin_address >= storage_begin && packet_begin_address <= storage_end;
}

inline COQUIC_NO_PROFILE bool
trace_packet_for_connection(const ConnectionId &source_connection_id) {
    return packet_trace_matches_connection(source_connection_id);
}

inline COQUIC_NO_PROFILE void maybe_trace_pmtud_timeout(const ConnectionId &source_connection_id) {
    if (trace_packet_for_connection(source_connection_id)) {
        std::cerr << "quic-packet-trace pmtud-timeout scid="
                  << format_connection_id_hex(source_connection_id) << '\n';
    }
}

inline COQUIC_NO_PROFILE bool initial_ack_due_for_send(const PacketSpaceState &packet_space,
                                                       QuicCoreTimePoint now) {
    return packet_space.received_packets.has_ack_to_send() &&
           (packet_space.force_ack_send ||
            packet_space.pending_ack_deadline.value_or(QuicCoreTimePoint::max()) <= now);
}

inline COQUIC_NO_PROFILE bool handshake_ack_due_for_send(const PacketSpaceState &packet_space,
                                                         QuicCoreTimePoint now) {
    return packet_space.received_packets.has_ack_to_send() &&
           (packet_space.force_ack_send ||
            packet_space.pending_ack_deadline.value_or(QuicCoreTimePoint::max()) <= now);
}

inline COQUIC_NO_PROFILE bool application_ack_due_for_send(const PacketSpaceState &packet_space,
                                                           QuicCoreTimePoint now) {
    return packet_space.received_packets.has_ack_to_send() &&
           (packet_space.force_ack_send ||
            packet_space.pending_ack_deadline.value_or(QuicCoreTimePoint::max()) <= now);
}

inline COQUIC_NO_PROFILE bool should_count_inbound_bytes(bool count_inbound_bytes) {
    return count_inbound_bytes;
}

inline COQUIC_NO_PROFILE std::size_t
accounted_inbound_datagram_bytes(std::span<const std::byte> bytes,
                                 bool accept_greased_quic_bit = false) {
    return datagram_starts_with_initial_packet(bytes, accept_greased_quic_bit)
               ? std::max(bytes.size(), kMinimumInitialDatagramSize)
               : bytes.size();
}

inline COQUIC_NO_PROFILE void maybe_note_inbound_datagram_bytes(bool count_inbound_bytes,
                                                                std::span<const std::byte> bytes,
                                                                bool accept_greased_quic_bit,
                                                                const auto &note_bytes) {
    if (should_count_inbound_bytes(count_inbound_bytes)) {
        note_bytes(accounted_inbound_datagram_bytes(bytes, accept_greased_quic_bit));
    }
}

inline COQUIC_NO_PROFILE bool pmtud_deadline_due(const std::optional<QuicCoreTimePoint> &deadline,
                                                 QuicCoreTimePoint now) {
    return deadline.has_value() && now >= *deadline;
}

inline COQUIC_NO_PROFILE bool
initial_packet_space_has_sendable_data(const PacketSpaceState &packet_space,
                                       QuicCoreTimePoint now) {
    return packet_space.send_crypto.has_pending_data() ||
           packet_space.pending_probe_packet.has_value() ||
           initial_ack_due_for_send(packet_space, now);
}

inline COQUIC_NO_PROFILE bool
handshake_packet_space_has_sendable_data(const PacketSpaceState &packet_space,
                                         QuicCoreTimePoint now) {
    return packet_space.write_secret.has_value() &&
           (packet_space.send_crypto.has_pending_data() ||
            packet_space.pending_probe_packet.has_value() ||
            handshake_ack_due_for_send(packet_space, now));
}

inline COQUIC_NO_PROFILE bool
can_send_zero_rtt_application_packets(EndpointRole role, HandshakeStatus status,
                                      const PacketSpaceState &zero_rtt_space) {
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.6
    // # A client therefore MUST NOT use 0-RTT for application data unless
    // # specifically requested by the application that is in use.
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.6
    // # A server MUST NOT use 0-RTT keys to protect packets; it uses 1-RTT
    // # keys to protect acknowledgments of 0-RTT packets.
    //= https://www.rfc-editor.org/rfc/rfc9001#section-5.6
    // # Once a client has installed 1-RTT keys, it MUST NOT send any more
    // # 0-RTT packets.
    return role == EndpointRole::client && status != HandshakeStatus::connected &&
           zero_rtt_space.write_secret.has_value();
}

inline COQUIC_NO_PROFILE bool
can_send_application_packets(EndpointRole role, HandshakeStatus status,
                             const PacketSpaceState &zero_rtt_space,
                             const PacketSpaceState &application_space) {
    return application_space.write_secret.has_value() ||
           can_send_zero_rtt_application_packets(role, status, zero_rtt_space);
}

inline COQUIC_NO_PROFILE bool application_space_has_sendable_data(
    bool application_ack_due, bool pending_application_send,
    const PacketSpaceState &application_space, bool has_pending_new_token_frames,
    bool has_pending_new_connection_id_frames, bool has_pending_retire_connection_id_frames) {
    return application_ack_due || pending_application_send ||
           application_space.pending_probe_packet.has_value() || has_pending_new_token_frames ||
           has_pending_new_connection_id_frames || has_pending_retire_connection_id_frames ||
           application_space.send_crypto.has_pending_data();
}

inline COQUIC_NO_PROFILE bool
pmtud_packet_deadline_candidate_is_live(const SentPacketRecord *packet) {
    return packet != nullptr && packet->is_pmtu_probe;
}

inline COQUIC_NO_PROFILE QuicCoreTimePoint
earliest_deadline(std::optional<QuicCoreTimePoint> existing, QuicCoreTimePoint candidate) {
    return existing.has_value() ? std::min(*existing, candidate) : candidate;
}

inline COQUIC_NO_PROFILE bool
packet_space_has_no_in_flight_ack_eliciting_packet(bool discarded,
                                                   const PacketSpaceState &packet_space) {
    return discarded || !has_in_flight_ack_eliciting_packet(packet_space);
}

inline COQUIC_NO_PROFILE bool client_keepalive_has_no_in_flight_packets(
    bool initial_discarded, const PacketSpaceState &initial_space, bool handshake_discarded,
    const PacketSpaceState &handshake_space, const PacketSpaceState &application_space) {
    return packet_space_has_no_in_flight_ack_eliciting_packet(initial_discarded, initial_space) &&
           packet_space_has_no_in_flight_ack_eliciting_packet(handshake_discarded,
                                                              handshake_space) &&
           !has_in_flight_ack_eliciting_packet(application_space);
}

inline COQUIC_NO_PROFILE bool client_handshake_keepalive_is_eligible(
    EndpointRole role, HandshakeStatus status, bool handshake_confirmed,
    const std::optional<QuicCoreTimePoint> &last_peer_activity_time, bool initial_discarded,
    const PacketSpaceState &initial_space, bool handshake_discarded,
    const PacketSpaceState &handshake_space, const PacketSpaceState &application_space) {
    return role == EndpointRole::client && status == HandshakeStatus::in_progress &&
           !handshake_confirmed && last_peer_activity_time.has_value() &&
           client_keepalive_has_no_in_flight_packets(initial_discarded, initial_space,
                                                     handshake_discarded, handshake_space,
                                                     application_space);
}

inline COQUIC_NO_PROFILE bool client_receive_keepalive_is_eligible(
    EndpointRole role, HandshakeStatus status, bool handshake_confirmed,
    const std::optional<QuicCoreTimePoint> &last_peer_activity_time, bool has_receive_interest,
    bool initial_discarded, const PacketSpaceState &initial_space, bool handshake_discarded,
    const PacketSpaceState &handshake_space) {
    return role == EndpointRole::client && status == HandshakeStatus::connected &&
           handshake_confirmed && last_peer_activity_time.has_value() && has_receive_interest &&
           packet_space_has_no_in_flight_ack_eliciting_packet(initial_discarded, initial_space) &&
           packet_space_has_no_in_flight_ack_eliciting_packet(handshake_discarded, handshake_space);
}

inline COQUIC_NO_PROFILE std::optional<QuicCoreTimePoint>
make_client_receive_keepalive_reference_time(
    const std::optional<QuicCoreTimePoint> &last_peer_activity_time,
    const std::optional<QuicCoreTimePoint> &last_probe_time) {
    if (!last_peer_activity_time.has_value()) {
        return std::nullopt;
    }

    return std::max(*last_peer_activity_time, last_probe_time.value_or(QuicCoreTimePoint::min()));
}

inline COQUIC_NO_PROFILE bool
has_client_handshake_keepalive_space(const std::optional<QuicCoreTimePoint> &reference_time,
                                     bool initial_discarded, bool handshake_discarded,
                                     const PacketSpaceState &handshake_space) {
    return reference_time.has_value() &&
           (!initial_discarded ||
            (!handshake_discarded && handshake_space.write_secret.has_value()));
}

inline COQUIC_NO_PROFILE PacketSpaceState *client_handshake_keepalive_packet_space(
    const std::optional<QuicCoreTimePoint> &reference_time, bool initial_discarded,
    PacketSpaceState &initial_space, bool handshake_discarded, PacketSpaceState &handshake_space) {
    if (!has_client_handshake_keepalive_space(reference_time, initial_discarded,
                                              handshake_discarded, handshake_space)) {
        return nullptr;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # Specifically, the client
    // # MUST send an Initial packet in a UDP datagram that contains at least
    // # 1200 bytes if it does not have Handshake keys, and otherwise send a
    // # Handshake packet.
    return (!handshake_discarded && handshake_space.write_secret.has_value()) ? &handshake_space
                                                                              : &initial_space;
}

inline COQUIC_NO_PROFILE bool client_handshake_recovery_probe_has_other_space_in_flight(
    bool initial_discarded, const PacketSpaceState &initial_space,
    const PacketSpaceState &application_space) {
    return (!initial_discarded && has_in_flight_ack_eliciting_packet(initial_space)) |
           has_in_flight_ack_eliciting_packet(application_space);
}

inline COQUIC_NO_PROFILE bool simple_stream_ack_sample_collection_is_eligible(
    bool has_late_acked_packets, bool has_lost_packets, EndpointRole role, bool qlog_enabled,
    bool packet_trace_enabled, QuicCongestionControlAlgorithm algorithm) {
    if (has_late_acked_packets || has_lost_packets || role == EndpointRole::client ||
        qlog_enabled || packet_trace_enabled) {
        return false;
    }
    return algorithm == QuicCongestionControlAlgorithm::newreno ||
           algorithm == QuicCongestionControlAlgorithm::cubic ||
           algorithm == QuicCongestionControlAlgorithm::bbr ||
           algorithm == QuicCongestionControlAlgorithm::copa;
}

inline COQUIC_NO_PROFILE bool simple_stream_ack_fast_path_is_eligible(
    bool has_late_acked_packets, bool has_acked_packets, EndpointRole role, bool qlog_enabled,
    bool packet_trace_enabled, QuicCongestionControlAlgorithm algorithm) {
    if (has_late_acked_packets || has_acked_packets) {
        return false;
    }
    if (role == EndpointRole::client || qlog_enabled || packet_trace_enabled) {
        return false;
    }
    return algorithm == QuicCongestionControlAlgorithm::newreno ||
           algorithm == QuicCongestionControlAlgorithm::cubic ||
           algorithm == QuicCongestionControlAlgorithm::bbr ||
           algorithm == QuicCongestionControlAlgorithm::copa;
}

inline COQUIC_NO_PROFILE bool
simple_stream_congestion_batch_algorithm_is_supported(QuicCongestionControlAlgorithm algorithm) {
    return algorithm == QuicCongestionControlAlgorithm::newreno ||
           algorithm == QuicCongestionControlAlgorithm::cubic ||
           algorithm == QuicCongestionControlAlgorithm::bbr ||
           algorithm == QuicCongestionControlAlgorithm::copa;
}

inline COQUIC_NO_PROFILE bool
simple_stream_congestion_ack_aggregation_is_supported(QuicCongestionControlAlgorithm algorithm) {
    return algorithm == QuicCongestionControlAlgorithm::newreno ||
           algorithm == QuicCongestionControlAlgorithm::cubic;
}

inline COQUIC_NO_PROFILE bool
acked_current_key_update_generation(const SentPacketRecord *packet,
                                    std::uint64_t current_application_write_key_generation) {
    return packet != nullptr &&
           packet->protection_key_update_generation == current_application_write_key_generation;
}

inline COQUIC_NO_PROFILE bool
should_process_simple_stream_ack_ecn(bool largest_acknowledged_was_newly_acked) {
    return largest_acknowledged_was_newly_acked;
}

inline COQUIC_NO_PROFILE bool should_reset_pto_after_ack(bool suppress_pto_reset) {
    return !suppress_pto_reset;
}

inline COQUIC_NO_PROFILE bool
stream_has_lost_send_data_for_state_change(const StreamState &stream) {
    return stream.reset_state == StreamControlFrameState::none &&
           stream.send_buffer.has_lost_data();
}

inline COQUIC_NO_PROFILE bool ecn_counts_decreased(const AckEcnCounts &current,
                                                   const AckEcnCounts &previous) {
    return current.ect0 < previous.ect0 || current.ect1 < previous.ect1 ||
           current.ecn_ce < previous.ecn_ce;
}

inline COQUIC_NO_PROFILE bool
ecn_feedback_is_invalid(std::uint64_t delta_ect0, std::uint64_t delta_ect1, std::uint64_t delta_ce,
                        std::uint64_t newly_acked_ect0, std::uint64_t newly_acked_ect1,
                        std::uint64_t current_ect0, std::uint64_t current_ect1,
                        std::uint64_t total_sent_ect0, std::uint64_t total_sent_ect1) {
    return delta_ect0 + delta_ce < newly_acked_ect0 || delta_ect1 + delta_ce < newly_acked_ect1 ||
           current_ect0 > total_sent_ect0 || current_ect1 > total_sent_ect1;
}

inline COQUIC_NO_PROFILE bool should_mark_ecn_probing_path_capable(QuicPathEcnState state) {
    return state == QuicPathEcnState::probing;
}

inline COQUIC_NO_PROFILE bool
should_ensure_inbound_application_path(bool paths_empty, QuicPathId inbound_path_id,
                                       const std::optional<QuicPathId> &current_send_path_id) {
    return !paths_empty | (inbound_path_id != 0) | current_send_path_id.has_value();
}

inline COQUIC_NO_PROFILE bool zero_rtt_state_present(bool read_secret_available,
                                                     bool write_secret_available) {
    //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.3
    // # Additionally, a server MAY discard 0-RTT keys as soon as it receives
    // # a 1-RTT packet.
    //= https://www.rfc-editor.org/rfc/rfc9001#section-4.9.3
    // # Servers MAY temporarily retain 0-RTT keys to allow decrypting
    // # reordered packets without requiring their contents to be retransmitted
    // # with 1-RTT keys.
    return read_secret_available || write_secret_available;
}

inline COQUIC_NO_PROFILE bool
should_arm_zero_rtt_discard_deadline_after_application_packet(EndpointRole role,
                                                              bool zero_rtt_read_secret_available) {
    return role == EndpointRole::server && zero_rtt_read_secret_available;
}

inline COQUIC_NO_PROFILE bool
has_timer_lost_packets_for_profile(bool profile_enabled,
                                   const std::vector<SentPacketRecord> &lost_packets) {
    return profile_enabled && !lost_packets.empty();
}

inline COQUIC_NO_PROFILE bool pmtu_trace_no_probe(const ConnectionId &source_connection_id) {
    return packet_trace_matches_connection(source_connection_id);
}

inline COQUIC_NO_PROFILE void maybe_trace_pmtu_no_probe(const ConnectionId &source_connection_id,
                                                        const PathState &path) {
    if (pmtu_trace_no_probe(source_connection_id)) {
        std::cerr << "quic-packet-trace pmtud-no-probe scid="
                  << format_connection_id_hex(source_connection_id) << " path=" << path.id
                  << " validated=" << path.mtu.validated_datagram_size
                  << " ceiling=" << path.mtu.probe_ceiling << '\n';
    }
}

inline COQUIC_NO_PROFILE bool
should_refresh_connection_credit_for_data_blocked(const DataBlockedFrame &frame,
                                                  const ConnectionFlowControlState &flow_control) {
    return frame.maximum_data >= flow_control.advertised_max_data;
}

inline COQUIC_NO_PROFILE void
maybe_refresh_connection_credit_for_data_blocked(const DataBlockedFrame &frame,
                                                 const ConnectionFlowControlState &flow_control,
                                                 const auto &refresh) {
    if (should_refresh_connection_credit_for_data_blocked(frame, flow_control)) {
        refresh();
    }
}

inline COQUIC_NO_PROFILE bool
should_refresh_stream_credit_for_data_blocked(const StreamDataBlockedFrame &frame,
                                              const StreamState &stream) {
    return frame.maximum_stream_data >= stream.flow_control.advertised_max_stream_data;
}

inline COQUIC_NO_PROFILE void
maybe_refresh_stream_credit_for_data_blocked(const StreamDataBlockedFrame &frame,
                                             const StreamState &stream, const auto &refresh) {
    if (should_refresh_stream_credit_for_data_blocked(frame, stream)) {
        refresh();
    }
}

inline COQUIC_NO_PROFILE bool should_skip_available_secret(EncryptionLevel level,
                                                           bool initial_packet_space_discarded,
                                                           bool handshake_packet_space_discarded) {
    return (level == EncryptionLevel::initial && initial_packet_space_discarded) ||
           (level == EncryptionLevel::handshake && handshake_packet_space_discarded);
}

inline COQUIC_NO_PROFILE bool can_skip_outbound_tls_sync_now(
    HandshakeStatus status, bool peer_transport_parameters_validated,
    const std::optional<TrafficSecret> &application_read_secret,
    const std::optional<TrafficSecret> &application_write_secret, const qlog::Session *qlog_session,
    const std::vector<DeferredProtectedDatagram> &deferred_protected_packets) {
    return status == HandshakeStatus::connected && peer_transport_parameters_validated &&
           application_read_secret.has_value() && application_write_secret.has_value() &&
           qlog_session == nullptr && deferred_protected_packets.empty();
}

inline COQUIC_NO_PROFILE bool client_outbound_tls_sync_can_skip_resumption(
    bool resumption_state_emitted, bool peer_preferred_address_emitted,
    const std::optional<TransportParameters> &peer_transport_parameters) {
    return resumption_state_emitted &&
           (peer_preferred_address_emitted || !peer_transport_parameters.has_value() ||
            !peer_transport_parameters->preferred_address.has_value());
}

inline COQUIC_NO_PROFILE bool should_clear_outstanding_pmtu_probe(const PathMtuState &mtu,
                                                                  std::uint64_t packet_number) {
    return mtu.outstanding_probe_packet_number.has_value() &&
           *mtu.outstanding_probe_packet_number == packet_number;
}

inline COQUIC_NO_PROFILE bool
should_clear_outstanding_pmtu_probe_after_ceiling(const PathMtuState &mtu) {
    return mtu.outstanding_probe_size.has_value() &&
           *mtu.outstanding_probe_size > mtu.probe_ceiling;
}

inline COQUIC_NO_PROFILE void clear_outstanding_pmtu_probe(PathMtuState &mtu) {
    mtu.outstanding_probe_size.reset();
    mtu.outstanding_probe_packet_number.reset();
}

inline COQUIC_NO_PROFILE std::optional<QuicCoreTimePoint>
pmtud_next_probe_time(const PathMtuState &mtu, QuicCoreTimePoint now,
                      QuicCoreClock::duration delay) {
    return mtu.enabled && mtu.validated_datagram_size < mtu.probe_ceiling
               ? std::optional<QuicCoreTimePoint>{now + delay}
               : std::nullopt;
}

inline COQUIC_NO_PROFILE bool should_discard_client_long_header_with_changed_source_for_source(
    EndpointRole role, HandshakeStatus status, bool handshake_confirmed,
    const std::optional<ConnectionId> &peer_source_connection_id,
    const ConnectionId &source_connection_id) {
    return role == EndpointRole::client && status == HandshakeStatus::in_progress &&
           !handshake_confirmed && peer_source_connection_id.has_value() &&
           peer_source_connection_id.value() != source_connection_id;
}

inline COQUIC_NO_PROFILE bool
should_use_pending_pmtu_probe_size(bool allow_pmtu_probe_size, bool anti_amplification_limited,
                                   const std::optional<SentPacketRecord> &pending_probe_packet) {
    if (!allow_pmtu_probe_size || anti_amplification_limited || !pending_probe_packet.has_value()) {
        return false;
    }
    const auto &pending_probe = optional_ref_or_abort(pending_probe_packet);
    return pending_probe.is_pmtu_probe && pending_probe.pmtu_probe_size != 0;
}

inline COQUIC_NO_PROFILE bool
should_keep_searching_for_pmtu_probe_size(const PathMtuState &mtu, std::size_t next_probe_size) {
    return next_probe_size > mtu.validated_datagram_size &&
           pmtud_probe_size_previously_failed(mtu, next_probe_size);
}

inline COQUIC_NO_PROFILE bool
should_arm_pmtu_probe_after_send(const PathMtuState &mtu, bool application_write_secret_available,
                                 std::uint64_t pending_stream_bytes) {
    return mtu.enabled && application_write_secret_available &&
           pending_stream_bytes > mtu.validated_datagram_size && !mtu.next_probe_time.has_value() &&
           !mtu.outstanding_probe_packet_number.has_value() &&
           mtu.validated_datagram_size < mtu.probe_ceiling;
}

inline COQUIC_NO_PROFILE bool
append_retired_packet_if_present(std::vector<SentPacketRecord> &packets,
                                 std::optional<SentPacketRecord> packet) {
    if (!packet.has_value()) {
        return false;
    }

    packets.push_back(std::move(*packet));
    return true;
}

inline COQUIC_NO_PROFILE void
note_retirement_candidate_stream_id(std::optional<std::uint64_t> &single_candidate,
                                    std::vector<std::uint64_t> &additional_candidates,
                                    std::uint64_t stream_id) {
    if (!single_candidate.has_value()) {
        single_candidate = stream_id;
        return;
    }
    if (*single_candidate == stream_id ||
        std::find(additional_candidates.begin(), additional_candidates.end(), stream_id) !=
            additional_candidates.end()) {
        return;
    }

    additional_candidates.push_back(stream_id);
}

template <typename RetireStream>
inline COQUIC_NO_PROFILE void
for_each_retirement_candidate_stream_id(const std::optional<std::uint64_t> &single_candidate,
                                        const std::vector<std::uint64_t> &additional_candidates,
                                        RetireStream &&retire_stream) {
    if (single_candidate.has_value()) {
        retire_stream(*single_candidate);
    }
    for (const auto stream_id : additional_candidates) {
        retire_stream(stream_id);
    }
}

inline COQUIC_NO_PROFILE void record_latest_rtt_sample_for_profile(const RecoveryRttState &rtt,
                                                                   SendProfileCounters &profile) {
    if (rtt.latest_rtt.has_value()) {
        const auto latest_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(*rtt.latest_rtt).count());
        profile.latest_rtt_us_sum += latest_us;
        profile.latest_rtt_us_max = std::max(profile.latest_rtt_us_max, latest_us);
    }
}

inline COQUIC_NO_PROFILE void
record_congestion_debug_metrics_for_profile_for_tests(const QuicCongestionDebugMetrics &metrics,
                                                      SendProfileCounters &profile) {
    ++profile.cc_debug_samples;
    profile.cc_mode_last = metrics.mode;
    profile.cc_bandwidth_bps_last = metrics.bandwidth_bps;
    profile.cc_bandwidth_bps_max = std::max(profile.cc_bandwidth_bps_max, metrics.bandwidth_bps);
    profile.cc_max_bandwidth_bps_last = metrics.max_bandwidth_bps;
    profile.cc_max_bandwidth_bps_max =
        std::max(profile.cc_max_bandwidth_bps_max, metrics.max_bandwidth_bps);
    profile.cc_pacing_rate_bps_last = metrics.pacing_rate_bps;
    profile.cc_pacing_rate_bps_max =
        std::max(profile.cc_pacing_rate_bps_max, metrics.pacing_rate_bps);
    profile.cc_bdp_bytes_last = metrics.bdp_bytes;
    profile.cc_bdp_bytes_max = std::max(profile.cc_bdp_bytes_max, metrics.bdp_bytes);
    profile.cc_max_inflight_last = metrics.max_inflight;
    profile.cc_max_inflight_max = std::max(profile.cc_max_inflight_max, metrics.max_inflight);
    profile.cc_send_quantum_last = metrics.send_quantum;
    profile.cc_send_quantum_max = std::max(profile.cc_send_quantum_max, metrics.send_quantum);
    profile.cc_pacing_budget_last = metrics.pacing_budget;
    profile.cc_pacing_budget_max = std::max(profile.cc_pacing_budget_max, metrics.pacing_budget);
    if (metrics.finite_inflight_longterm) {
        ++profile.cc_inflight_longterm_finite_samples;
        profile.cc_inflight_longterm_last = metrics.inflight_longterm;
        profile.cc_inflight_longterm_max =
            std::max(profile.cc_inflight_longterm_max, metrics.inflight_longterm);
    }
    if (metrics.finite_inflight_shortterm) {
        ++profile.cc_inflight_shortterm_finite_samples;
        profile.cc_inflight_shortterm_last = metrics.inflight_shortterm;
        profile.cc_inflight_shortterm_max =
            std::max(profile.cc_inflight_shortterm_max, metrics.inflight_shortterm);
    }
    profile.cc_extra_acked_last = metrics.extra_acked;
    profile.cc_extra_acked_max = std::max(profile.cc_extra_acked_max, metrics.extra_acked);
    profile.cc_total_delivered_last = metrics.total_delivered;
    profile.cc_total_lost_last = metrics.total_lost;
    profile.cc_latest_rtt_us_last = metrics.latest_rtt_us;
    profile.cc_min_rtt_us_last = metrics.min_rtt_us;
    profile.cc_unjittered_rtt_us_last = metrics.unjittered_rtt_us;
    if (metrics.finite_target_window) {
        ++profile.cc_target_window_finite_samples;
        profile.cc_target_window_last = metrics.target_window;
        profile.cc_target_window_max =
            std::max(profile.cc_target_window_max, metrics.target_window);
    }
    profile.cc_app_limited_samples += static_cast<std::uint64_t>(metrics.app_limited);
    profile.cc_full_bw_samples += static_cast<std::uint64_t>(metrics.full_bw_reached);
    profile.cc_slow_start_samples += static_cast<std::uint64_t>(metrics.slow_start);
    profile.cc_startup_probe_complete_samples +=
        static_cast<std::uint64_t>(metrics.startup_probe_complete);
}

inline COQUIC_NO_PROFILE void
record_congestion_debug_for_profile(const QuicCongestionController &controller,
                                    QuicCoreTimePoint now, SendProfileCounters &profile) {
    record_congestion_debug_metrics_for_profile_for_tests(controller.debug_metrics(now), profile);
}

inline COQUIC_NO_PROFILE std::optional<std::size_t> prepare_pmtu_probe_packet_for_tracking(
    SentPacketRecord &packet, std::optional<std::size_t> datagram_size, std::size_t packet_length) {
    if (!packet.is_pmtu_probe) {
        return std::nullopt;
    }

    packet.bytes_in_flight = 0;
    packet.in_flight = false;
    if (datagram_size.has_value() &&
        (packet.pmtu_probe_size == 0 || packet.pmtu_probe_size > *datagram_size)) {
        packet.pmtu_probe_size = *datagram_size;
    }
    return packet.pmtu_probe_size != 0 ? packet.pmtu_probe_size : packet_length;
}

struct PacketInspectionDatagramId {
    std::uint64_t value;
};

struct PacketInspectionCount {
    std::size_t value;
};

inline COQUIC_NO_PROFILE void
maybe_record_packet_inspection_datagram_id(std::uint64_t &last_datagram_id,
                                           PacketInspectionDatagramId datagram_id,
                                           PacketInspectionCount inspection_count) {
    if (inspection_count.value != 0) {
        last_datagram_id = datagram_id.value;
    }
}

inline COQUIC_NO_PROFILE bool fin_only_stream_frame_cannot_fit(bool fin_sendable,
                                                               bool has_send_final_size) {
    return !fin_sendable || !has_send_final_size;
}

inline COQUIC_NO_PROFILE bool
stream_fragment_consumes_connection_credit(const StreamFrameSendFragment &fragment) {
    return fragment.consumes_flow_control && !fragment.bytes.empty();
}

inline COQUIC_NO_PROFILE void
restore_stream_fragment_connection_credit(const StreamFrameSendFragment &fragment,
                                          ConnectionFlowControlState &connection_flow,
                                          std::uint64_t &remaining_connection_credit) {
    if (!stream_fragment_consumes_connection_credit(fragment)) {
        return;
    }

    connection_flow.highest_sent -= static_cast<std::uint64_t>(fragment.bytes.size());
    remaining_connection_credit += static_cast<std::uint64_t>(fragment.bytes.size());
}

inline COQUIC_NO_PROFILE void restore_stream_fragment(std::map<std::uint64_t, StreamState> &streams,
                                                      const StreamFrameSendFragment &fragment,
                                                      ConnectionFlowControlState &connection_flow,
                                                      std::uint64_t &remaining_connection_credit) {
    restore_stream_fragment_connection_credit(fragment, connection_flow,
                                              remaining_connection_credit);
    streams.at(fragment.stream_id).restore_send_fragment(fragment);
}

inline COQUIC_NO_PROFILE bool
stream_fragment_needs_tail_restore(std::size_t retained_payload_size,
                                   const StreamFrameSendFragment &fragment) {
    return retained_payload_size < fragment.bytes.size();
}

inline COQUIC_NO_PROFILE void maybe_restore_stream_fragment_tail(
    StreamFrameSendFragment &fragment, std::size_t retained_payload_size,
    std::map<std::uint64_t, StreamState> &streams, ConnectionFlowControlState &connection_flow,
    std::uint64_t &remaining_connection_credit) {
    if (!stream_fragment_needs_tail_restore(retained_payload_size, fragment)) {
        return;
    }

    StreamFrameSendFragment tail_fragment{
        .stream_id = fragment.stream_id,
        .offset = fragment.offset + static_cast<std::uint64_t>(retained_payload_size),
        .bytes = fragment.bytes.subspan(retained_payload_size),
        .fin = fragment.fin,
        .consumes_flow_control = fragment.consumes_flow_control,
    };
    fragment.bytes.resize(retained_payload_size);
    fragment.fin = false;
    fragment.prime_stream_frame_header_cache();
    tail_fragment.prime_stream_frame_header_cache();
    restore_stream_fragment(streams, tail_fragment, connection_flow, remaining_connection_credit);
}

inline COQUIC_NO_PROFILE void
restore_stream_fragments_from(std::map<std::uint64_t, StreamState> &streams,
                              std::vector<StreamFrameSendFragment> &fragments, std::size_t begin,
                              ConnectionFlowControlState &connection_flow,
                              std::uint64_t &remaining_connection_credit) {
    for (auto index = fragments.size(); index > begin; --index) {
        restore_stream_fragment(streams, fragments[index - 1u], connection_flow,
                                remaining_connection_credit);
    }
    fragments.erase(fragments.begin() + static_cast<std::ptrdiff_t>(begin), fragments.end());
}

struct StreamFragmentTrimTarget {
    std::size_t index = 0;
    std::size_t budget = 0;
};

struct StreamFragmentTrimAccounting {
    ConnectionFlowControlState &connection_flow;
    std::uint64_t &remaining_connection_credit;
    std::size_t &selected_wire_bytes;
};

inline COQUIC_NO_PROFILE void trim_or_restore_oversized_stream_fragment(
    std::map<std::uint64_t, StreamState> &streams, std::vector<StreamFrameSendFragment> &fragments,
    StreamFragmentTrimTarget target, StreamFragmentTrimAccounting accounting) {
    auto &fragment = fragments[target.index];
    const auto retained_payload_size = max_stream_frame_payload_for_wire_budget(
        fragment.stream_id, fragment.offset, target.budget);
    if (retained_payload_size == 0) {
        restore_stream_fragments_from(streams, fragments, target.index, accounting.connection_flow,
                                      accounting.remaining_connection_credit);
        return;
    }

    maybe_restore_stream_fragment_tail(fragment, retained_payload_size, streams,
                                       accounting.connection_flow,
                                       accounting.remaining_connection_credit);
    accounting.selected_wire_bytes += fragment.stream_frame_wire_size();
    restore_stream_fragments_from(streams, fragments, target.index + 1u, accounting.connection_flow,
                                  accounting.remaining_connection_credit);
}

inline COQUIC_NO_PROFILE void
remember_minimum_wire_size(std::optional<std::size_t> &minimum_wire_bytes, std::size_t wire_size) {
    minimum_wire_bytes = minimum_wire_bytes.has_value() ? std::min(*minimum_wire_bytes, wire_size)
                                                        : std::optional<std::size_t>{wire_size};
}

inline COQUIC_NO_PROFILE bool
pmtu_probe_padding_already_satisfied(std::size_t target_pmtu_probe_size,
                                     std::size_t datagram_size) {
    return target_pmtu_probe_size == 0 || datagram_size >= target_pmtu_probe_size;
}

inline COQUIC_NO_PROFILE bool pmtu_probe_padding_required(std::size_t padding) {
    return padding != 0;
}

inline COQUIC_NO_PROFILE bool maybe_add_pmtu_probe_padding(std::size_t padding,
                                                           std::vector<Frame> &frames,
                                                           std::size_t &probe_padding_length) {
    if (!pmtu_probe_padding_required(padding)) {
        return false;
    }

    frames.emplace_back(PaddingFrame{.length = padding});
    probe_padding_length = padding;
    return true;
}

inline COQUIC_NO_PROFILE bool should_fail_after_probe_credit_retry(bool retried, bool failed) {
    return !retried || failed;
}

inline COQUIC_NO_PROFILE bool
ack_only_path_validation_is_ack_eliciting(const auto &path_validation_frames) {
    return path_validation_frames.response.has_value() |
           path_validation_frames.challenge.has_value();
}

inline COQUIC_NO_PROFILE std::optional<std::uint64_t>
ack_largest_for_path_validation_sent_record(bool path_validation_ack_eliciting,
                                            const OutboundAckHeader &ack_header) {
    if (!path_validation_ack_eliciting) {
        return std::nullopt;
    }
    return ack_header.largest_acknowledged;
}

template <typename NoteIdleAckElicitingSend>
inline COQUIC_NO_PROFILE void
maybe_note_path_validation_ack_eliciting_send(bool path_validation_ack_eliciting,
                                              NoteIdleAckElicitingSend &&note_send) {
    if (path_validation_ack_eliciting) {
        note_send();
    }
}

inline COQUIC_NO_PROFILE void
maybe_queue_ack_only_path_validation_packet(const auto &path_validation_frames,
                                            const auto &queue_packet) {
    if (ack_only_path_validation_is_ack_eliciting(path_validation_frames)) {
        queue_packet();
    }
}

inline COQUIC_NO_PROFILE bool
has_pending_ack_only_path_validation_frame(const std::map<QuicPathId, PathState> &paths,
                                           const std::optional<QuicPathId> &current_send_path_id) {
    const auto response_path = std::find_if(paths.begin(), paths.end(), [](const auto &entry) {
        return entry.second.pending_response.has_value();
    });
    if (response_path != paths.end()) {
        return true;
    }
    if (!current_send_path_id.has_value()) {
        return std::ranges::any_of(paths, [](const auto &entry) {
            return entry.second.challenge_pending && entry.second.outstanding_challenge.has_value();
        });
    }
    const auto path = paths.find(*current_send_path_id);
    if (path != paths.end() && path->second.challenge_pending &&
        path->second.outstanding_challenge.has_value()) {
        return true;
    }
    return std::ranges::any_of(paths, [&](const auto &entry) {
        return entry.first != *current_send_path_id && entry.second.challenge_pending &&
               entry.second.outstanding_challenge.has_value();
    });
}

inline COQUIC_NO_PROFILE void
restore_unsent_path_validation_frames_after_send_failure(const auto &path_validation_frames,
                                                         const auto &ensure_path) {
    if (path_validation_frames.response.has_value()) {
        auto &path = ensure_path(path_validation_frames.path_id);
        path.pending_response = path_validation_frames.response->data;
    }
    if (path_validation_frames.challenge.has_value()) {
        auto &path = ensure_path(path_validation_frames.path_id);
        path.challenge_pending = true;
    }
}

inline COQUIC_NO_PROFILE bool
ack_can_be_trimmed_for_stream_budget(const std::optional<OutboundAckHeader> &selected_ack_frame,
                                     const std::optional<std::size_t> &minimum_stream_wire_bytes,
                                     const CodecResult<std::size_t> &control_candidate_size,
                                     std::size_t congestion_limited_datagram_size) {
    return selected_ack_frame.has_value() && minimum_stream_wire_bytes.has_value() &&
           control_candidate_size.has_value() &&
           congestion_limited_datagram_size >= kMinimumInitialDatagramSize;
}

inline COQUIC_NO_PROFILE bool
stream_budget_can_absorb_empty_no_ack_candidate(std::size_t base_application_stream_budget,
                                                std::size_t minimum_stream_wire_bytes) {
    return base_application_stream_budget >= minimum_stream_wire_bytes;
}

inline COQUIC_NO_PROFILE bool maybe_select_empty_no_ack_candidate(
    std::size_t base_application_stream_budget, std::size_t minimum_stream_wire_bytes,
    std::optional<OutboundAckHeader> &selected_ack_frame, std::size_t &application_stream_budget,
    CodecResult<std::size_t> &control_candidate_size,
    const CodecResult<std::size_t> &no_ack_control_candidate_size) {
    if (!stream_budget_can_absorb_empty_no_ack_candidate(base_application_stream_budget,
                                                         minimum_stream_wire_bytes)) {
        return false;
    }

    selected_ack_frame = std::nullopt;
    application_stream_budget = base_application_stream_budget;
    control_candidate_size = no_ack_control_candidate_size;
    return true;
}

inline COQUIC_NO_PROFILE bool
no_ack_control_candidate_leaves_stream_budget(std::size_t no_ack_control_candidate_size,
                                              std::size_t congestion_limited_datagram_size,
                                              std::size_t minimum_stream_wire_bytes) {
    return no_ack_control_candidate_size < congestion_limited_datagram_size &&
           congestion_limited_datagram_size - no_ack_control_candidate_size >=
               minimum_stream_wire_bytes;
}

inline COQUIC_NO_PROFILE bool maybe_select_sized_no_ack_candidate(
    std::size_t congestion_limited_datagram_size, std::size_t minimum_stream_wire_bytes,
    std::optional<OutboundAckHeader> &selected_ack_frame, std::size_t &application_stream_budget,
    CodecResult<std::size_t> &control_candidate_size,
    const CodecResult<std::size_t> &no_ack_control_candidate_size) {
    if (!no_ack_control_candidate_size.has_value()) {
        return false;
    }
    if (!no_ack_control_candidate_leaves_stream_budget(no_ack_control_candidate_size.value(),
                                                       congestion_limited_datagram_size,
                                                       minimum_stream_wire_bytes)) {
        return false;
    }

    selected_ack_frame = std::nullopt;
    application_stream_budget =
        congestion_limited_datagram_size - no_ack_control_candidate_size.value();
    control_candidate_size = no_ack_control_candidate_size;
    return true;
}

inline COQUIC_NO_PROFILE bool should_fail_non_empty_packet_payload_candidate(
    const CodecResult<SerializedProtectedDatagram> &candidate) {
    return !candidate.has_value() && !is_empty_packet_payload_error(candidate);
}

inline COQUIC_NO_PROFILE std::uint64_t
optional_frame_trace_value(const std::optional<MaxDataFrame> &frame) {
    return frame.has_value() ? frame->maximum_data : 0;
}

inline COQUIC_NO_PROFILE std::uint64_t
optional_frame_trace_value(const std::optional<DataBlockedFrame> &frame) {
    return frame.has_value() ? frame->maximum_data : 0;
}

inline COQUIC_NO_PROFILE bool use_fast_serialized_one_rtt_commit_for_packet(
    EndpointRole role, bool packets_empty, const qlog::Session *qlog_session,
    bool use_zero_rtt_packet_protection, bool has_application_close) {
    return role == EndpointRole::server && packets_empty && qlog_session == nullptr &&
           !use_zero_rtt_packet_protection && !has_application_close;
}

struct SimpleApplicationAckOnlyEligibility {
    bool application_ack_due_now = false;
    bool has_base_ack_frame = false;
    bool packets_empty = false;
    bool qlog_enabled = false;
    bool use_zero_rtt_packet_protection = false;
    bool can_send_one_rtt_packets = false;
    bool pending_application_send_after_blocked_queue = false;
    bool application_probe_pending = false;
    bool has_pending_new_token_frames = false;
    bool has_pending_new_connection_id_frames = false;
    bool has_pending_retire_connection_id_frames = false;
    bool application_crypto_frames_empty = false;
    bool has_current_send_path = false;
    bool has_pending_ack_only_path_validation_frame = false;
};

inline COQUIC_NO_PROFILE bool
can_try_simple_application_ack_only(const SimpleApplicationAckOnlyEligibility &eligibility) {
    if (!eligibility.application_ack_due_now) {
        return false;
    }
    if (!eligibility.has_base_ack_frame) {
        return false;
    }
    if (!eligibility.packets_empty) {
        return false;
    }
    if (eligibility.qlog_enabled) {
        return false;
    }
    if (eligibility.use_zero_rtt_packet_protection) {
        return false;
    }
    if (!eligibility.can_send_one_rtt_packets) {
        return false;
    }
    if (eligibility.pending_application_send_after_blocked_queue) {
        return false;
    }
    if (eligibility.application_probe_pending) {
        return false;
    }
    if (eligibility.has_pending_new_token_frames) {
        return false;
    }
    if (eligibility.has_pending_new_connection_id_frames) {
        return false;
    }
    if (eligibility.has_pending_retire_connection_id_frames) {
        return false;
    }
    if (!eligibility.application_crypto_frames_empty) {
        return false;
    }
    if (!eligibility.has_current_send_path) {
        return false;
    }
    if (eligibility.has_pending_ack_only_path_validation_frame) {
        return false;
    }
    return true;
}

inline COQUIC_NO_PROFILE std::size_t
one_rtt_encrypted_packet_count_for_commit(bool has_application_close,
                                          bool use_zero_rtt_packet_protection) {
    return has_application_close || !use_zero_rtt_packet_protection ? std::size_t{1}
                                                                    : std::size_t{0};
}

inline COQUIC_NO_PROFILE bool
should_consume_selected_datagram_frame_after_commit(bool committed_empty,
                                                    bool selected_datagram_frame_has_value) {
    return !committed_empty && selected_datagram_frame_has_value;
}

inline void remember_pmtud_failed_probe_size(PathMtuState &mtu, std::size_t probe_size) {
    if (probe_size <= kMinimumInitialDatagramSize ||
        pmtud_probe_size_previously_failed(mtu, probe_size)) {
        return;
    }
    mtu.failed_probe_sizes.push_back(probe_size);
    if (mtu.failed_probe_sizes.size() > kMaximumRememberedPmtudFailedProbeSizes) {
        mtu.failed_probe_sizes.erase(mtu.failed_probe_sizes.begin());
    }
}

inline void forget_pmtud_failed_probe_size(PathMtuState &mtu, std::size_t probe_size) {
    mtu.failed_probe_sizes.erase(
        std::remove(mtu.failed_probe_sizes.begin(), mtu.failed_probe_sizes.end(), probe_size),
        mtu.failed_probe_sizes.end());
}

inline QuicCoreTimePoint latest_packet_sent_time(std::span<const SentPacketRecord> packets) {
    return std::max_element(packets.begin(), packets.end(),
                            [](const SentPacketRecord &lhs, const SentPacketRecord &rhs) {
                                return lhs.sent_time < rhs.sent_time;
                            })
        ->sent_time;
}

inline std::size_t retransmittable_probe_frame_count(const SentPacketRecord &packet) {
    return packet.crypto_ranges.size() + packet.new_token_frames.size() +
           packet.reset_stream_frames.size() + packet.stop_sending_frames.size() +
           packet.new_connection_id_frames.size() + packet.retire_connection_id_frames.size() +
           packet.max_stream_data_frames.size() + packet.max_streams_frames.size() +
           packet.streams_blocked_frames.size() + packet.stream_data_blocked_frames.size() +
           packet_stream_frame_count(packet) + static_cast<std::size_t>(packet.has_handshake_done) +
           static_cast<std::size_t>(packet.max_data_frame.has_value()) +
           static_cast<std::size_t>(packet.data_blocked_frame.has_value());
}

inline bool packet_has_only_stream_frame_metadata(const SentPacketRecord &packet) {
    return packet.crypto_ranges.empty() && packet.new_token_frames.empty() &&
           packet.reset_stream_frames.empty() && packet.stop_sending_frames.empty() &&
           packet.new_connection_id_frames.empty() && packet.retire_connection_id_frames.empty() &&
           packet.max_stream_data_frames.empty() && packet.max_streams_frames.empty() &&
           packet.streams_blocked_frames.empty() && packet.stream_data_blocked_frames.empty() &&
           packet.max_data_frame == std::nullopt && packet.data_blocked_frame == std::nullopt &&
           !packet.has_handshake_done && !packet.is_pmtu_probe && !packet.has_ping &&
           !packet.force_ack && !packet.largest_received_packet_number_acked.has_value() &&
           packet.qlog_packet_snapshot == nullptr && !packet.qlog_pto_probe &&
           packet.stream_fragments.empty() && sent_packet_has_stream_frames(packet);
}

inline bool packet_is_simple_congestion_ack(const SentPacketRecord &packet) {
    return packet.ack_eliciting && packet.in_flight && !packet.declared_lost &&
           !packet.app_limited && packet_has_only_stream_frame_metadata(packet);
}

inline SentPacketRecord make_congestion_ack_snapshot(const SentPacketRecord &packet) {
    SentPacketRecord snapshot{
        .packet_number = packet.packet_number,
        .sent_time = packet.sent_time,
        .congestion_send_sequence = packet.congestion_send_sequence,
        .ack_eliciting = packet.ack_eliciting,
        .in_flight = packet.in_flight,
        .declared_lost = packet.declared_lost,
        .first_stream_frame_metadata = packet.first_stream_frame_metadata,
        .bytes_in_flight = packet.bytes_in_flight,
        .path_id = packet.path_id,
        .ecn = packet.ecn,
        .delivered = packet.delivered,
        .delivered_time = packet.delivered_time,
        .first_sent_time = packet.first_sent_time,
        .tx_in_flight = packet.tx_in_flight,
        .lost = packet.lost,
        .app_limited = packet.app_limited,
        .protection_key_update_generation = packet.protection_key_update_generation,
    };
    snapshot.stream_frame_metadata = packet.stream_frame_metadata;
    return snapshot;
}

inline AckedStreamPacketSample make_acked_stream_packet_sample(const SentPacketRecord &packet) {
    return AckedStreamPacketSample{
        .packet_number = packet.packet_number,
        .sent_time = packet.sent_time,
        .congestion_send_sequence = packet.congestion_send_sequence,
        .bytes_in_flight = packet.bytes_in_flight,
        .path_id = packet.path_id,
        .ecn = packet.ecn,
        .delivered = packet.delivered,
        .delivered_time = packet.delivered_time,
        .first_sent_time = packet.first_sent_time,
        .tx_in_flight = packet.tx_in_flight,
        .lost = packet.lost,
        .app_limited = packet.app_limited,
    };
}

inline bool stream_frame_metadata_is_probe_worthy(const StreamState &stream,
                                                  const StreamFrameSendMetadata &metadata) {
    if (stream.reset_state != StreamControlFrameState::none) {
        return false;
    }

    if (stream.send_buffer.has_outstanding_range(metadata.offset, metadata.length)) {
        return true;
    }

    const bool missing_fin = !metadata.fin;
    const bool fin_already_acknowledged = stream.send_fin_state == StreamSendFinState::acknowledged;
    if (missing_fin | fin_already_acknowledged) {
        return false;
    }
    const auto fragment_end = metadata.offset + static_cast<std::uint64_t>(metadata.length);
    return stream.send_final_size == std::optional<std::uint64_t>{fragment_end};
}

inline bool stream_fragment_is_probe_worthy(const StreamState &stream,
                                            const StreamFrameSendFragment &fragment) {
    return stream_frame_metadata_is_probe_worthy(stream, stream_frame_send_metadata(fragment));
}

inline std::size_t application_ack_eliciting_frame_count(
    std::span<const NewTokenFrame> new_token_frames, bool include_handshake_done,
    const std::optional<MaxDataFrame> &max_data_frame,
    std::span<const NewConnectionIdFrame> new_connection_id_frames,
    std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
    bool has_path_response_frame, bool has_path_challenge_frame,
    std::span<const MaxStreamDataFrame> max_stream_data_frames,
    std::span<const MaxStreamsFrame> max_streams_frames,
    std::span<const StreamsBlockedFrame> streams_blocked_frames,
    std::span<const ResetStreamFrame> reset_stream_frames,
    std::span<const StopSendingFrame> stop_sending_frames,
    const std::optional<DataBlockedFrame> &data_blocked_frame,
    std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
    const std::optional<DatagramFrame> &datagram_frame,
    std::span<const StreamFrameSendFragment> stream_fragments) {
    return new_token_frames.size() + new_connection_id_frames.size() +
           retire_connection_id_frames.size() + max_stream_data_frames.size() +
           max_streams_frames.size() + streams_blocked_frames.size() + reset_stream_frames.size() +
           stop_sending_frames.size() + stream_data_blocked_frames.size() +
           stream_fragments.size() + static_cast<std::size_t>(include_handshake_done) +
           static_cast<std::size_t>(has_path_response_frame) +
           static_cast<std::size_t>(has_path_challenge_frame) +
           static_cast<std::size_t>(max_data_frame.has_value()) +
           static_cast<std::size_t>(data_blocked_frame.has_value()) +
           static_cast<std::size_t>(datagram_frame.has_value());
}

inline bool establishes_persistent_congestion(std::span<const SentPacketRecord> lost_packets,
                                              const RecoveryRttState &rtt,
                                              QuicCoreDuration max_ack_delay) {
    //= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2
    // # The persistent congestion period SHOULD NOT start until there is at
    // # least one RTT sample.
    if (!rtt.latest_rtt.has_value()) {
        return false;
    }

    const auto [first_loss, last_loss] =
        std::minmax_element(lost_packets.begin(), lost_packets.end(),
                            [](const SentPacketRecord &lhs, const SentPacketRecord &rhs) {
                                return lhs.sent_time < rhs.sent_time;
                            });
    if (last_loss->sent_time <= first_loss->sent_time) {
        return false;
    }

    //= https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2
    // # These two packets MUST be ack-eliciting, since a receiver is required
    // # to acknowledge only ack-eliciting packets within its maximum
    // # acknowledgment delay; see Section 13.2 of [QUIC-TRANSPORT].
    const auto persistent_congestion_duration =
        (rtt.smoothed_rtt + std::max(rtt.rttvar * 4, kGranularity) + max_ack_delay) *
        kPersistentCongestionThreshold;
    return last_loss->sent_time - first_loss->sent_time >= persistent_congestion_duration;
}

inline void reset_discarded_packet_space_state(PacketSpaceState &packet_space) {
    packet_space.largest_authenticated_packet_number = std::nullopt;
    packet_space.read_secret = std::nullopt;
    packet_space.write_secret = std::nullopt;
    packet_space.send_crypto = ReliableSendBuffer{};
    packet_space.receive_crypto = ReliableReceiveBuffer{};
    packet_space.received_packets = ReceivedPacketHistory{};
    packet_space.recovery = PacketSpaceRecovery{};
    packet_space.pending_probe_packet = std::nullopt;
    packet_space.pending_ack_deadline = std::nullopt;
    packet_space.force_ack_send = false;
}

inline void reset_packet_space_receive_state(PacketSpaceState &packet_space) {
    packet_space.largest_authenticated_packet_number = std::nullopt;
    packet_space.received_packets = ReceivedPacketHistory{};
    packet_space.pending_ack_deadline = std::nullopt;
    packet_space.force_ack_send = false;
}

} // namespace coquic::quic
