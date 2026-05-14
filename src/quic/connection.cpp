#include "src/quic/connection.h"

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
#include <random>
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

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "src/quic/buffer.h"
#include "src/quic/frame.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/packet_crypto_test_hooks.h"
#include "src/quic/protected_codec.h"
#include "src/quic/qlog/json.h"
#include "src/quic/qlog/session.h"
#include "src/quic/tls_adapter_quictls_test_hooks.h"
#include "src/quic/connection_test_hooks.h"

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#define COQUIC_NOINLINE __attribute__((noinline))
#else
#define COQUIC_NO_PROFILE
#define COQUIC_NOINLINE
#endif

namespace coquic::quic {

namespace {

constexpr std::size_t kMinimumInitialDatagramSize = 1200;
constexpr std::size_t kMaximumDatagramSize = 1200;
constexpr std::size_t kMaximumDeferredProtectedPackets = 32;
constexpr std::uint8_t kDefaultInitialPacketNumberLength = 2;
constexpr std::size_t kOneRttPacketProtectionTagLength = 16;
constexpr std::size_t kShortHeaderProtectionSampleOffset = 4;
constexpr std::uint64_t kMaxQuicVarInt = 4611686018427387903ull;
constexpr std::uint64_t kCompatibilityStreamId = 0;
constexpr std::uint32_t kPersistentCongestionThreshold = 3;
constexpr std::size_t kPmtudMinimumProbeGrowth = 16;
constexpr std::size_t kMaximumRememberedPmtudFailedProbeSizes = 16;
constexpr std::size_t kPmtudIPv6EthernetUdpPayloadSize = 1452;
constexpr std::size_t kPmtudIPv4EthernetUdpPayloadSize = 1472;
constexpr std::size_t kQuicCoreSecretLength = 32;
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

struct ConnectionDrainTestHooks {
    bool force_quic_core_secret_rand_failure = false;
    bool force_prf_failure = false;
    bool force_issued_connection_id_rand_failure = false;
    bool force_stateless_reset_token_rand_failure = false;
    bool force_path_challenge_rand_failure = false;
    bool force_random_one_in_sixteen_rand_failure = false;
    std::optional<bool> force_random_one_in_sixteen_result;
    bool force_missing_packet_metadata = false;
    bool force_missing_fallback_packet_length = false;
    bool force_short_prf_output = false;
    bool force_missing_close_packet_metadata = false;
    bool force_storage_range_before_storage = false;
    bool force_storage_range_overflow = false;
    bool force_next_pmtu_probe_size_zero = false;
    bool force_application_packet_number_exhausted = false;
    bool force_duplicate_initial_congestion_blocked = false;
    bool force_application_send_congestion_blocked = false;
    bool force_no_ack_control_candidate_estimate_failure = false;
    bool force_no_ack_control_candidate_estimate_size = false;
    std::size_t forced_no_ack_control_candidate_estimate_size = 0;
    bool force_no_ack_control_candidate_empty_payload = false;
    bool force_mark_lost_packet_missing_after_lookup = false;
    bool force_appended_fragment_base_datagram_failure = false;
    bool force_packet_inspection_missing_plaintext_storage = false;
    int force_replay_deferred_packets_failure_countdown = -1;
    int force_application_candidate_estimate_failure_countdown = -1;
    int force_candidate_datagram_serialization_failure_countdown = -1;
    int force_application_candidate_datagram_extra_bytes_countdown = -1;
    int force_probe_padding_failure_countdown = -1;
    int force_probe_no_ack_retry_failure_countdown = -1;
    int force_application_trim_candidate_failure_countdown = -1;
    int force_application_trim_candidate_empty_payload_countdown = -1;
    int force_application_no_ack_candidate_failure_countdown = -1;
    int force_application_no_ack_retry_failure_countdown = -1;
    std::size_t force_application_candidate_datagram_extra_bytes = 0;
};

struct SendProfileCounters {
    std::uint64_t drain_calls = 0;
    std::uint64_t datagrams = 0;
    std::uint64_t empty_drains = 0;
    std::uint64_t pmtu_probe_datagrams = 0;
    std::uint64_t congestion_blocks = 0;
    std::uint64_t pacing_blocks = 0;
    std::uint64_t serialize_calls = 0;
    std::uint64_t estimate_calls = 0;
    std::uint64_t trim_ack_calls = 0;
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
};

template <typename T>
COQUIC_NO_PROFILE const T &optional_ref_or_abort(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return value.value();
}

ConnectionDrainTestHooks &connection_drain_test_hooks() {
    static ConnectionDrainTestHooks hooks;
    return hooks;
}

class ScopedConnectionDrainTestHook {
  public:
    explicit ScopedConnectionDrainTestHook(bool ConnectionDrainTestHooks::*field) : field_(field) {
        previous_ = connection_drain_test_hooks().*field_;
        connection_drain_test_hooks().*field_ = true;
    }

    ~ScopedConnectionDrainTestHook() {
        connection_drain_test_hooks().*field_ = previous_;
    }

    ScopedConnectionDrainTestHook(const ScopedConnectionDrainTestHook &) = delete;
    ScopedConnectionDrainTestHook &operator=(const ScopedConnectionDrainTestHook &) = delete;

  private:
    bool ConnectionDrainTestHooks::*field_;
    bool previous_ = false;
};

class ScopedConnectionDrainDualTestHook {
  public:
    ScopedConnectionDrainDualTestHook(bool ConnectionDrainTestHooks::*first,
                                      bool ConnectionDrainTestHooks::*second)
        : first_(first), second_(second) {
        auto &hooks = connection_drain_test_hooks();
        previous_first_ = hooks.*first_;
        previous_second_ = hooks.*second_;
        hooks.*first_ = true;
        hooks.*second_ = true;
    }

    ~ScopedConnectionDrainDualTestHook() {
        auto &hooks = connection_drain_test_hooks();
        hooks.*first_ = previous_first_;
        hooks.*second_ = previous_second_;
    }

    ScopedConnectionDrainDualTestHook(const ScopedConnectionDrainDualTestHook &) = delete;
    ScopedConnectionDrainDualTestHook &
    operator=(const ScopedConnectionDrainDualTestHook &) = delete;

  private:
    bool ConnectionDrainTestHooks::*first_;
    bool ConnectionDrainTestHooks::*second_;
    bool previous_first_ = false;
    bool previous_second_ = false;
};

class ScopedConnectionDrainOptionalBoolTestHook {
  public:
    explicit ScopedConnectionDrainOptionalBoolTestHook(
        std::optional<bool> ConnectionDrainTestHooks::*field, bool value)
        : field_(field) {
        previous_ = connection_drain_test_hooks().*field_;
        connection_drain_test_hooks().*field_ = value;
    }

    ~ScopedConnectionDrainOptionalBoolTestHook() {
        connection_drain_test_hooks().*field_ = previous_;
    }

    ScopedConnectionDrainOptionalBoolTestHook(const ScopedConnectionDrainOptionalBoolTestHook &) =
        delete;
    ScopedConnectionDrainOptionalBoolTestHook &
    operator=(const ScopedConnectionDrainOptionalBoolTestHook &) = delete;

  private:
    std::optional<bool> ConnectionDrainTestHooks::*field_;
    std::optional<bool> previous_;
};

class ScopedConnectionDrainCountdownTestHook {
  public:
    ScopedConnectionDrainCountdownTestHook(int ConnectionDrainTestHooks::*field, int value)
        : field_(field) {
        previous_ = connection_drain_test_hooks().*field_;
        connection_drain_test_hooks().*field_ = value;
    }

    ~ScopedConnectionDrainCountdownTestHook() {
        connection_drain_test_hooks().*field_ = previous_;
    }

    ScopedConnectionDrainCountdownTestHook(const ScopedConnectionDrainCountdownTestHook &) = delete;
    ScopedConnectionDrainCountdownTestHook &
    operator=(const ScopedConnectionDrainCountdownTestHook &) = delete;

  private:
    int ConnectionDrainTestHooks::*field_;
    int previous_ = -1;
};

class ScopedConnectionDrainDatagramGrowthTestHook {
  public:
    struct Countdown {
        int value;
    };

    struct ExtraBytes {
        std::size_t value;
    };

    ScopedConnectionDrainDatagramGrowthTestHook(Countdown countdown, ExtraBytes extra_bytes) {
        auto &hooks = connection_drain_test_hooks();
        previous_countdown_ = hooks.force_application_candidate_datagram_extra_bytes_countdown;
        previous_extra_bytes_ = hooks.force_application_candidate_datagram_extra_bytes;
        hooks.force_application_candidate_datagram_extra_bytes_countdown = countdown.value;
        hooks.force_application_candidate_datagram_extra_bytes = extra_bytes.value;
    }

    ~ScopedConnectionDrainDatagramGrowthTestHook() {
        auto &hooks = connection_drain_test_hooks();
        hooks.force_application_candidate_datagram_extra_bytes_countdown = previous_countdown_;
        hooks.force_application_candidate_datagram_extra_bytes = previous_extra_bytes_;
    }

    ScopedConnectionDrainDatagramGrowthTestHook(
        const ScopedConnectionDrainDatagramGrowthTestHook &) = delete;
    ScopedConnectionDrainDatagramGrowthTestHook &
    operator=(const ScopedConnectionDrainDatagramGrowthTestHook &) = delete;

  private:
    int previous_countdown_ = -1;
    std::size_t previous_extra_bytes_ = 0;
};

class ScopedConnectionDrainForcedSizeTestHook {
  public:
    explicit ScopedConnectionDrainForcedSizeTestHook(std::size_t value) {
        auto &hooks = connection_drain_test_hooks();
        previous_enabled_ = hooks.force_no_ack_control_candidate_estimate_size;
        previous_value_ = hooks.forced_no_ack_control_candidate_estimate_size;
        hooks.force_no_ack_control_candidate_estimate_size = true;
        hooks.forced_no_ack_control_candidate_estimate_size = value;
    }

    ~ScopedConnectionDrainForcedSizeTestHook() {
        auto &hooks = connection_drain_test_hooks();
        hooks.force_no_ack_control_candidate_estimate_size = previous_enabled_;
        hooks.forced_no_ack_control_candidate_estimate_size = previous_value_;
    }

    ScopedConnectionDrainForcedSizeTestHook(const ScopedConnectionDrainForcedSizeTestHook &) =
        delete;
    ScopedConnectionDrainForcedSizeTestHook &
    operator=(const ScopedConnectionDrainForcedSizeTestHook &) = delete;

  private:
    bool previous_enabled_ = false;
    std::size_t previous_value_ = 0;
};

class ScopedConnectionDrainEmptyNoAckControlEstimateTestHook {
  public:
    ScopedConnectionDrainEmptyNoAckControlEstimateTestHook() {
        previous_ = connection_drain_test_hooks().force_no_ack_control_candidate_empty_payload;
        connection_drain_test_hooks().force_no_ack_control_candidate_empty_payload = true;
    }

    ~ScopedConnectionDrainEmptyNoAckControlEstimateTestHook() {
        connection_drain_test_hooks().force_no_ack_control_candidate_empty_payload = previous_;
    }

    ScopedConnectionDrainEmptyNoAckControlEstimateTestHook(
        const ScopedConnectionDrainEmptyNoAckControlEstimateTestHook &) = delete;
    ScopedConnectionDrainEmptyNoAckControlEstimateTestHook &
    operator=(const ScopedConnectionDrainEmptyNoAckControlEstimateTestHook &) = delete;

  private:
    bool previous_ = false;
};

bool consume_connection_drain_countdown(int ConnectionDrainTestHooks::*field) {
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

COQUIC_NO_PROFILE void maybe_grow_application_candidate_datagram_for_tests(
    CodecResult<SerializedProtectedDatagram> &candidate_datagram) {
    auto &hooks = connection_drain_test_hooks();
    if (!candidate_datagram.has_value() ||
        !consume_connection_drain_countdown(
            &ConnectionDrainTestHooks::
                force_application_candidate_datagram_extra_bytes_countdown) ||
        hooks.force_application_candidate_datagram_extra_bytes == 0) {
        return;
    }

    candidate_datagram.value().bytes.resize(
        candidate_datagram.value().bytes.size() +
            hooks.force_application_candidate_datagram_extra_bytes,
        std::byte{0});
}

bool send_profile_enabled() {
    static const bool enabled = [] {
        const char *value = std::getenv("COQUIC_SEND_PROFILE");
        return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
    }();
    return enabled;
}

SendProfileCounters &send_profile_counters() {
    static SendProfileCounters counters;
    return counters;
}

void print_send_profile() {
    if (!send_profile_enabled()) {
        return;
    }

    const auto &c = send_profile_counters();
    std::cerr << "coquic-send-profile"
              << " drains=" << c.drain_calls << " datagrams=" << c.datagrams
              << " empty=" << c.empty_drains << " pmtu_probe=" << c.pmtu_probe_datagrams
              << " congestion_blocks=" << c.congestion_blocks
              << " pacing_blocks=" << c.pacing_blocks << " bytes=" << c.bytes
              << " stream_bytes=" << c.stream_bytes << " inbound_calls=" << c.inbound_calls
              << " inbound_packets=" << c.inbound_packets << " inbound_bytes=" << c.inbound_bytes
              << " le1200=" << c.datagrams_le_1200 << " le1434=" << c.datagrams_le_1434
              << " le1472=" << c.datagrams_le_1472 << " gt1472=" << c.datagrams_gt_1472
              << " max=" << c.max_datagram << " serialize_calls=" << c.serialize_calls
              << " serialize_ns=" << c.serialize_ns << " estimate_calls=" << c.estimate_calls
              << " estimate_ns=" << c.estimate_ns << " trim_ack_calls=" << c.trim_ack_calls
              << " trim_ack_ns=" << c.trim_ack_ns << " stream_select_ns=" << c.stream_select_ns
              << " commit_ns=" << c.commit_ns << " inbound_ns=" << c.inbound_ns
              << " deserialize_ns=" << c.deserialize_ns
              << " process_packet_ns=" << c.process_packet_ns
              << " outbound_sync_tls_calls=" << c.outbound_sync_tls_calls
              << " outbound_sync_tls_skipped=" << c.outbound_sync_tls_skipped
              << " outbound_sync_tls_ns=" << c.outbound_sync_tls_ns
              << " inbound_setup_ns=" << c.inbound_setup_ns
              << " inbound_initial_sync_tls_calls=" << c.inbound_initial_sync_tls_calls
              << " inbound_initial_sync_tls_skipped=" << c.inbound_initial_sync_tls_skipped
              << " inbound_initial_sync_tls_ns=" << c.inbound_initial_sync_tls_ns
              << " inbound_post_process_sync_tls_calls=" << c.inbound_post_process_sync_tls_calls
              << " inbound_post_process_sync_tls_skipped="
              << c.inbound_post_process_sync_tls_skipped
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
              << " process_decoded_packet_ns=" << c.process_decoded_packet_ns
              << " defer_decision_calls=" << c.defer_decision_calls
              << " defer_decision_ns=" << c.defer_decision_ns
              << " qlog_emit_calls=" << c.qlog_emit_calls << " qlog_emit_ns=" << c.qlog_emit_ns
              << " congestion_block_cwnd_sum=" << c.congestion_block_cwnd_sum
              << " congestion_block_bif_sum=" << c.congestion_block_bif_sum
              << " congestion_block_max_cwnd=" << c.congestion_block_max_cwnd
              << " congestion_block_min_cwnd=" << c.congestion_block_min_cwnd
              << " ack_frames=" << c.ack_frames << " acked_packets=" << c.acked_packets
              << " late_acked_packets=" << c.late_acked_packets
              << " ack_lost_packets=" << c.ack_lost_packets
              << " timer_lost_packets=" << c.timer_lost_packets << " acked_bytes=" << c.acked_bytes
              << " late_acked_bytes=" << c.late_acked_bytes
              << " ack_lost_bytes=" << c.ack_lost_bytes
              << " timer_lost_bytes=" << c.timer_lost_bytes << " loss_events=" << c.loss_events
              << " persistent_congestion_events=" << c.persistent_congestion_events
              << " ecn_loss_events=" << c.ecn_loss_events
              << " packet_threshold_losses=" << c.packet_threshold_losses
              << " time_threshold_losses=" << c.time_threshold_losses
              << " rtt_samples=" << c.rtt_samples << " latest_rtt_us_sum=" << c.latest_rtt_us_sum
              << " latest_rtt_us_max=" << c.latest_rtt_us_max
              << " smoothed_rtt_us_last=" << c.smoothed_rtt_us_last
              << " rttvar_us_last=" << c.rttvar_us_last << '\n';
}

void register_send_profile_printer_once() {
    static const bool registered = [] {
        std::atexit(print_send_profile);
        return true;
    }();
    static_cast<void>(registered);
}

struct SendProfileTimer {
    std::uint64_t *target = nullptr;
    QuicCoreTimePoint start{};

    explicit SendProfileTimer(std::uint64_t &counter)
        : target(send_profile_enabled() ? &counter : nullptr) {
        if (target != nullptr) {
            start = QuicCoreClock::now();
        }
    }

    void stop() {
        if (target == nullptr) {
            return;
        }
        *target += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(QuicCoreClock::now() - start)
                .count());
        target = nullptr;
    }

    ~SendProfileTimer() {
        stop();
    }
};

bool is_ect_codepoint(QuicEcnCodepoint ecn) {
    return ecn == QuicEcnCodepoint::ect0 || ecn == QuicEcnCodepoint::ect1;
}

std::size_t ecn_packet_space_index(const PacketSpaceState &packet_space,
                                   std::span<const PacketSpaceState *const, 3> packet_spaces) {
    if (packet_spaces[0] == &packet_space) {
        return 0;
    }
    if (packet_spaces[1] == &packet_space) {
        return 1;
    }

    return 2;
}

bool packet_trace_enabled() {
    const char *value = std::getenv("COQUIC_PACKET_TRACE");
    return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
}

std::string format_connection_id_hex(std::span<const std::byte> connection_id) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (const auto byte : connection_id) {
        hex << std::setw(2) << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
    }
    return hex.str();
}

std::uint64_t mix_connection_id_word(std::uint64_t value) {
    value ^= value >> 30u;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27u;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31u;
    return value;
}

void absorb_connection_id_seed_byte(std::uint64_t &state, std::uint8_t byte) {
    state ^= byte;
    state *= 0x100000001b3ULL;
}

COQUIC_NO_PROFILE bool rand_bytes_for_connection(std::span<std::byte> bytes, bool force_failure) {
    return !force_failure && RAND_bytes(reinterpret_cast<unsigned char *>(bytes.data()),
                                        static_cast<int>(bytes.size())) == 1;
}

std::array<std::byte, kQuicCoreSecretLength> make_quic_core_secret() {
    std::array<std::byte, kQuicCoreSecretLength> secret{};
    if (rand_bytes_for_connection(
            secret, connection_drain_test_hooks().force_quic_core_secret_rand_failure)) {
        return secret;
    }

    std::random_device random_device;
    for (auto &byte : secret) {
        byte = static_cast<std::byte>(random_device());
    }
    return secret;
}

std::span<const std::byte, kQuicCoreSecretLength> quic_connection_id_secret() {
    static const auto secret = make_quic_core_secret();
    return std::span<const std::byte, kQuicCoreSecretLength>(secret);
}

std::span<const std::byte, kQuicCoreSecretLength> quic_reset_token_secret() {
    static const auto secret = make_quic_core_secret();
    return std::span<const std::byte, kQuicCoreSecretLength>(secret);
}

std::span<const std::byte, kQuicCoreSecretLength> quic_path_challenge_secret() {
    static const auto secret = make_quic_core_secret();
    return std::span<const std::byte, kQuicCoreSecretLength>(secret);
}

COQUIC_NO_PROFILE std::optional<std::array<unsigned char, EVP_MAX_MD_SIZE>>
compute_hmac_sha256_for_connection(std::span<const std::byte> secret,
                                   std::span<const unsigned char> input, unsigned int &produced,
                                   bool force_failure) {
    if (force_failure) {
        return std::nullopt;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    if (HMAC(EVP_sha256(), reinterpret_cast<const unsigned char *>(secret.data()),
             static_cast<int>(secret.size()), input.data(), input.size(), digest.data(),
             &produced) == nullptr) {
        return std::nullopt;
    }
    return digest;
}

template <std::size_t Size>
COQUIC_NO_PROFILE std::optional<std::array<std::byte, Size>>
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
    const auto digest = compute_hmac_sha256_for_connection(
        secret, input, produced, connection_drain_test_hooks().force_prf_failure);
    if (!digest.has_value()) {
        return std::nullopt;
    }
    if (connection_drain_test_hooks().force_short_prf_output) {
        return std::nullopt;
    }
    static_assert(Size <= SHA256_DIGEST_LENGTH);
    static_cast<void>(produced);
    std::copy_n(reinterpret_cast<const std::byte *>(digest->data()), output.size(), output.begin());
    return output;
}

COQUIC_NO_PROFILE bool forced_random_one_in_sixteen_result() {
    const auto &forced = connection_drain_test_hooks().force_random_one_in_sixteen_result;
    if (!forced.has_value()) {
        std::abort();
    }
    return forced.value();
}

COQUIC_NO_PROFILE bool random_one_in_sixteen_fallback() {
    static thread_local std::mt19937 fallback_random{std::random_device{}()};
    return (fallback_random() & 0x0fu) == 0;
}

void append_u64_be(std::vector<std::byte> &bytes, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes.push_back(static_cast<std::byte>((value >> static_cast<unsigned>(shift)) & 0xffu));
    }
}

std::vector<std::byte> make_secret_derivation_context(std::span<const std::byte> connection_id,
                                                      std::uint64_t sequence_number,
                                                      std::uint64_t discriminator = 0) {
    std::vector<std::byte> context;
    context.reserve(connection_id.size() + sizeof(sequence_number) + sizeof(discriminator));
    context.insert(context.end(), connection_id.begin(), connection_id.end());
    append_u64_be(context, sequence_number);
    append_u64_be(context, discriminator);
    return context;
}

ConnectionId make_issued_connection_id(std::span<const std::byte> base_connection_id,
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
    const auto derived = prf_bytes<32>(quic_connection_id_secret(), label, context);
    if (derived.has_value()) {
        std::copy_n(derived->begin(), connection_id.size(), connection_id.begin());
        return connection_id;
    }

    if (rand_bytes_for_connection(
            connection_id, connection_drain_test_hooks().force_issued_connection_id_rand_failure)) {
        return connection_id;
    }

    std::uint64_t state = 0xcbf29ce484222325ULL;
    for (const auto byte : base_connection_id) {
        absorb_connection_id_seed_byte(state, std::to_integer<std::uint8_t>(byte));
    }
    absorb_connection_id_seed_byte(state, 0xffu);
    absorb_connection_id_seed_byte(state, static_cast<std::uint8_t>(sequence_number & 0xffu));
    const auto mixed = mix_connection_id_word(state + sequence_number);
    for (std::size_t i = 0; i < connection_id.size(); ++i) {
        connection_id[i] = static_cast<std::byte>(
            (mixed >> static_cast<unsigned>((i % sizeof(mixed)) * 8u)) & 0xffu);
    }
    return connection_id;
}

std::array<std::byte, 16> make_stateless_reset_token(
    std::span<const std::byte> connection_id, std::uint64_t sequence_number,
    const std::optional<QuicStatelessResetSecret> &configured_secret = std::nullopt) {
    std::array<std::byte, 16> token{};
    const auto context = make_secret_derivation_context(
        connection_id, configured_secret.has_value() ? 0 : sequence_number);
    constexpr std::array label{
        std::byte{'c'}, std::byte{'o'}, std::byte{'q'}, std::byte{'u'}, std::byte{'i'},
        std::byte{'c'}, std::byte{' '}, std::byte{'s'}, std::byte{'r'}, std::byte{'t'},
    };
    const auto secret = configured_secret.has_value()
                            ? std::span<const std::byte>(*configured_secret)
                            : std::span<const std::byte>(quic_reset_token_secret());
    if (const auto derived = prf_bytes<16>(secret, label, context)) {
        return *derived;
    }

    if (rand_bytes_for_connection(
            token, connection_drain_test_hooks().force_stateless_reset_token_rand_failure)) {
        return token;
    }

    for (std::size_t i = 0; i < token.size(); ++i) {
        const auto sequence_shift = static_cast<unsigned>((i % sizeof(sequence_number)) * 8u);
        auto mixed = static_cast<std::uint8_t>((sequence_number >> sequence_shift) & 0xffu);
        mixed ^= static_cast<std::uint8_t>(0xa5u + static_cast<unsigned>(i * 13u));
        if (!connection_id.empty()) {
            mixed ^= std::to_integer<std::uint8_t>(connection_id[i % connection_id.size()]);
        }
        token[i] = std::byte{mixed};
    }

    return token;
}

std::array<std::byte, 8> make_path_challenge_data(std::span<const std::byte> local_connection_id,
                                                  QuicPathId path_id,
                                                  std::uint64_t sequence_number) {
    std::array<std::byte, 8> challenge{};
    const auto context =
        make_secret_derivation_context(local_connection_id, sequence_number, path_id);
    constexpr std::array label{
        std::byte{'c'}, std::byte{'o'}, std::byte{'q'}, std::byte{'u'},
        std::byte{'i'}, std::byte{'c'}, std::byte{' '}, std::byte{'p'},
        std::byte{'a'}, std::byte{'t'}, std::byte{'h'},
    };
    if (const auto derived = prf_bytes<8>(quic_path_challenge_secret(), label, context)) {
        return *derived;
    }

    if (rand_bytes_for_connection(
            challenge, connection_drain_test_hooks().force_path_challenge_rand_failure)) {
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

COQUIC_NO_PROFILE bool random_one_in_sixteen_from_openssl(std::uint8_t value) {
    return (value & 0x0fu) == 0;
}

COQUIC_NO_PROFILE bool random_one_in_sixteen() {
    if (connection_drain_test_hooks().force_random_one_in_sixteen_result.has_value()) {
        return forced_random_one_in_sixteen_result();
    }
    if (connection_drain_test_hooks().force_random_one_in_sixteen_rand_failure) {
        return random_one_in_sixteen_fallback();
    }

    std::uint8_t value = 0;
    if (RAND_bytes(&value, 1) == 1) {
        return random_one_in_sixteen_from_openssl(value);
    }

    return random_one_in_sixteen_fallback();
}

COQUIC_NO_PROFILE bool closing_close_packet_can_send(bool pending, bool has_close_frame) {
    return pending & has_close_frame;
}

std::size_t count_active_connection_ids(
    const std::map<std::uint64_t, LocalConnectionIdRecord> &connection_ids) {
    return static_cast<std::size_t>(
        std::count_if(connection_ids.begin(), connection_ids.end(),
                      [](const auto &entry) { return !entry.second.retired; }));
}

bool packet_trace_matches_connection(std::span<const std::byte> local_connection_id) {
    if (!packet_trace_enabled()) {
        return false;
    }

    const char *filter = std::getenv("COQUIC_PACKET_TRACE_SCID");
    if (filter == nullptr || filter[0] == '\0') {
        return true;
    }

    const auto formatted_connection_id = format_connection_id_hex(local_connection_id);
    return std::string_view(filter) == formatted_connection_id;
}

std::string format_optional_path_id(std::optional<QuicPathId> path_id) {
    if (!path_id.has_value()) {
        return "-";
    }
    return std::to_string(*path_id);
}

const PathState *find_path_state(const std::map<QuicPathId, PathState> &paths,
                                 std::optional<QuicPathId> path_id) {
    if (!path_id.has_value()) {
        return nullptr;
    }
    const auto it = paths.find(*path_id);
    return it == paths.end() ? nullptr : &it->second;
}

COQUIC_NO_PROFILE bool path_state_is_validating(const PathState *path) {
    return path != nullptr && !path->validated;
}

COQUIC_NO_PROFILE bool path_state_is_validated(const PathState *path) {
    return path != nullptr && path->validated;
}

std::string format_path_state_summary(const PathState *path) {
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

std::string format_ack_ranges(const AckFrame &ack) {
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

std::string format_ack_ranges(const ReceivedAckFrame &ack) {
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

std::string summarize_packets(std::span<const SentPacketRecord> packets) {
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
        stream_fragment_count += packet.stream_fragments.size();
        if (!first_stream_offset.has_value() && !packet.stream_fragments.empty()) {
            first_stream_offset = packet.stream_fragments.front().offset;
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

bool supports_version(std::span<const std::uint32_t> supported_versions, std::uint32_t version) {
    return std::find(supported_versions.begin(), supported_versions.end(), version) !=
           supported_versions.end();
}

bool supports_quic_v2(std::span<const std::uint32_t> supported_versions) {
    return supports_version(supported_versions, kQuicVersion2);
}

CodecResult<bool> prime_traffic_secret_cache(const std::optional<TrafficSecret> &secret) {
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
bool is_initial_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    if (version == kQuicVersion2) {
        return packet_type == 0x01u;
    }
    return packet_type == 0x00u;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_handshake_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    if (version == kQuicVersion2) {
        return packet_type == 0x03u;
    }
    return packet_type == 0x02u;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_zero_rtt_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    if (version == kQuicVersion2) {
        return packet_type == 0x02u;
    }
    return packet_type == 0x01u;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_bufferable_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    return is_initial_long_header_type(version, packet_type) |
           is_zero_rtt_long_header_type(version, packet_type) |
           is_handshake_long_header_type(version, packet_type);
}

std::uint32_t read_u32_be(std::span<const std::byte> bytes);

bool packet_is_bufferable(std::span<const std::byte> packet_bytes) {
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

bool datagram_starts_with_initial_packet(std::span<const std::byte> bytes) {
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

std::optional<VersionInformation>
make_local_version_information(std::span<const std::uint32_t> supported_versions,
                               std::uint32_t chosen_version) {
    if (!supports_quic_v2(supported_versions)) {
        return std::nullopt;
    }

    return VersionInformation{
        .chosen_version = chosen_version,
        .available_versions =
            std::vector<std::uint32_t>(supported_versions.begin(), supported_versions.end()),
    };
}

std::optional<VersionInformation>
version_information_for_handshake(std::span<const std::uint32_t> supported_versions,
                                  std::uint32_t chosen_version,
                                  const std::optional<ConnectionId> &retry_source_connection_id,
                                  std::uint32_t original_version, std::uint32_t current_version) {
    if (retry_source_connection_id.has_value() && current_version == original_version) {
        return std::nullopt;
    }

    return make_local_version_information(supported_versions, chosen_version);
}

std::uint32_t select_server_version(std::span<const std::uint32_t> supported_versions,
                                    std::uint32_t client_initial_version) {
    if (client_initial_version == kQuicVersion1 && supports_quic_v2(supported_versions)) {
        return kQuicVersion2;
    }
    if (supports_version(supported_versions, client_initial_version)) {
        return client_initial_version;
    }

    return client_initial_version;
}

EndpointRole opposite_role(EndpointRole role) {
    return role == EndpointRole::client ? EndpointRole::server : EndpointRole::client;
}

std::vector<std::byte> application_protocol_bytes(std::string_view protocol) {
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte *>(protocol.data()),
        reinterpret_cast<const std::byte *>(protocol.data() + protocol.size()));
}

void log_codec_failure(std::string_view where, const CodecError &error) {
    static_cast<void>(where);
    static_cast<void>(error);
}

std::size_t datagram_size_or_zero(const CodecResult<std::vector<std::byte>> &datagram) {
    const auto *value = std::get_if<std::vector<std::byte>>(&datagram.storage);
    return value == nullptr ? 0 : value->size();
}

std::size_t datagram_size_or_zero(const CodecResult<SerializedProtectedDatagram> &datagram) {
    const auto *value = std::get_if<SerializedProtectedDatagram>(&datagram.storage);
    return value == nullptr ? 0 : value->bytes.size();
}

COQUIC_NO_PROFILE bool
is_empty_packet_payload_error(const CodecResult<std::vector<std::byte>> &datagram) {
    const auto *error = std::get_if<CodecError>(&datagram.storage);
    return error != nullptr && error->code == CodecErrorCode::empty_packet_payload;
}

COQUIC_NO_PROFILE bool
is_empty_packet_payload_error(const CodecResult<SerializedProtectedDatagram> &datagram) {
    const auto *error = std::get_if<CodecError>(&datagram.storage);
    return error != nullptr && error->code == CodecErrorCode::empty_packet_payload;
}

std::uint32_t read_u32_be(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | std::to_integer<std::uint8_t>(byte);
    }

    return value;
}

void append_u32_be(std::vector<std::byte> &output, std::uint32_t value) {
    output.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
    output.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    output.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    output.push_back(static_cast<std::byte>(value & 0xffu));
}

void append_length_prefixed_bytes(std::vector<std::byte> &output,
                                  std::span<const std::byte> bytes) {
    append_u32_be(output, static_cast<std::uint32_t>(bytes.size()));
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_length_prefixed_text(std::vector<std::byte> &output, std::string_view text) {
    append_u32_be(output, static_cast<std::uint32_t>(text.size()));
    output.insert(output.end(), reinterpret_cast<const std::byte *>(text.data()),
                  reinterpret_cast<const std::byte *>(text.data() + text.size()));
}

std::optional<std::span<const std::byte>>
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

std::vector<std::byte> encode_resumption_state(std::span<const std::byte> tls_state,
                                               std::uint32_t quic_version,
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

std::optional<StoredClientResumptionState>
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

bool zero_rtt_transport_limits_not_reduced(const TransportParameters &remembered,
                                           const TransportParameters &current) {
    return current.active_connection_id_limit >= remembered.active_connection_id_limit &&
           current.initial_max_data >= remembered.initial_max_data &&
           current.initial_max_stream_data_bidi_local >=
               remembered.initial_max_stream_data_bidi_local &&
           current.initial_max_stream_data_bidi_remote >=
               remembered.initial_max_stream_data_bidi_remote &&
           current.initial_max_stream_data_uni >= remembered.initial_max_stream_data_uni &&
           current.initial_max_streams_bidi >= remembered.initial_max_streams_bidi &&
           current.initial_max_streams_uni >= remembered.initial_max_streams_uni;
}

std::uint64_t transport_error_code_value(QuicTransportErrorCode code) {
    return static_cast<std::uint64_t>(code);
}

CodecError transport_codec_error(CodecErrorCode codec_error, QuicTransportErrorCode transport_error,
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
CodecResult<T> transport_failure(CodecErrorCode codec_error, QuicTransportErrorCode transport_error,
                                 std::uint64_t frame_type, std::size_t offset = 0) {
    return CodecResult<T>::failure(
        transport_codec_error(codec_error, transport_error, frame_type, offset));
}

COQUIC_NO_PROFILE QuicTransportErrorCode
stream_transport_error_for_state_error(StreamStateErrorCode code) {
    switch (code) {
    case StreamStateErrorCode::invalid_stream_id:
        return QuicTransportErrorCode::stream_limit_error;
    case StreamStateErrorCode::invalid_stream_direction:
    case StreamStateErrorCode::send_side_closed:
    case StreamStateErrorCode::receive_side_closed:
        return QuicTransportErrorCode::stream_state_error;
    case StreamStateErrorCode::final_size_conflict:
        return QuicTransportErrorCode::final_size_error;
    }
    return QuicTransportErrorCode::protocol_violation;
}

CodecError stream_state_codec_error(StreamStateErrorCode code, std::uint64_t frame_type) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 stream_transport_error_for_state_error(code), frame_type);
}

CodecError stream_state_codec_error(const StreamStateError &error, std::uint64_t frame_type) {
    return stream_state_codec_error(error.code, frame_type);
}

CodecError stream_state_codec_error(const CodecError &error, std::uint64_t frame_type) {
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

std::uint64_t stream_frame_type_for(bool has_offset, bool has_length, bool fin) {
    return kFrameTypeStreamBase | (fin ? 0x01u : 0u) | (has_length ? 0x02u : 0u) |
           (has_offset ? 0x04u : 0u);
}

std::uint64_t stream_frame_type_for(const StreamFrame &frame) {
    return stream_frame_type_for(frame.has_offset, frame.has_length, frame.fin);
}

std::uint64_t stream_frame_type_for(const ReceivedStreamFrame &frame) {
    return stream_frame_type_for(frame.has_offset, frame.has_length, frame.fin);
}

std::uint64_t frame_type_for_max_streams(StreamLimitType type) {
    return type == StreamLimitType::bidirectional ? kFrameTypeMaxStreamsBidi
                                                  : kFrameTypeMaxStreamsUni;
}

std::uint64_t frame_type_for_streams_blocked(StreamLimitType type) {
    return type == StreamLimitType::bidirectional ? kFrameTypeStreamsBlockedBidi
                                                  : kFrameTypeStreamsBlockedUni;
}

CodecError frame_encoding_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::frame_encoding_error, frame_type, offset);
}

CodecError protocol_violation_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::protocol_violation, frame_type, offset);
}

CodecError optimistic_ack_protocol_violation_error(std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::protocol_violation, /*frame_type=*/0,
                                 offset);
}

CodecError frame_not_allowed_protocol_violation_error(std::uint64_t frame_type,
                                                      std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::frame_not_allowed_in_packet_type,
                                 QuicTransportErrorCode::protocol_violation, frame_type, offset);
}

CodecError flow_control_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::flow_control_error, frame_type, offset);
}

CodecError stream_limit_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::stream_limit_error, frame_type, offset);
}

CodecError stream_state_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::stream_state_error, frame_type, offset);
}

CodecError connection_id_limit_error(std::uint64_t frame_type, std::size_t offset = 0) {
    return transport_codec_error(CodecErrorCode::invalid_varint,
                                 QuicTransportErrorCode::connection_id_limit_error, frame_type,
                                 offset);
}

COQUIC_NO_PROFILE QuicTransportErrorCode transport_error_for_codec_error(CodecErrorCode code) {
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

std::chrono::milliseconds three_pto_period(const RecoveryRttState &rtt) {
    const auto pto_reference =
        std::max(compute_pto_deadline(rtt, std::chrono::milliseconds(0), QuicCoreTimePoint{},
                                      /*pto_count=*/0) -
                     QuicCoreTimePoint{},
                 QuicCoreClock::duration::zero());
    return std::chrono::duration_cast<std::chrono::milliseconds>(pto_reference *
                                                                 kPersistentCongestionThreshold);
}

PacketSpaceState &packet_space_for_level(EncryptionLevel level, PacketSpaceState &initial_space,
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

template <typename FrameRange> bool is_probing_only_frames(const FrameRange &frames) {
    return std::ranges::all_of(frames, [](const auto &frame) {
        return is_padding_frame(frame) | std::holds_alternative<PathChallengeFrame>(frame) |
               std::holds_alternative<PathResponseFrame>(frame) |
               std::holds_alternative<NewConnectionIdFrame>(frame);
    });
}

std::optional<DeadlineTrackedPacket>
latest_in_flight_ack_eliciting_packet(const PacketSpaceState &packet_space) {
    return packet_space.recovery.latest_in_flight_ack_eliciting_packet();
}

std::optional<DeadlineTrackedPacket> earliest_loss_packet(const PacketSpaceState &packet_space) {
    return packet_space.recovery.earliest_loss_packet();
}

bool has_in_flight_ack_eliciting_packet(const PacketSpaceState &packet_space) {
    return latest_in_flight_ack_eliciting_packet(packet_space).has_value();
}

void schedule_application_ack_deadline(PacketSpaceState &packet_space, QuicCoreTimePoint now,
                                       std::uint64_t max_ack_delay_ms, QuicEcnCodepoint ecn) {
    if (ecn == QuicEcnCodepoint::ce) {
        packet_space.pending_ack_deadline = now;
        packet_space.force_ack_send = true;
        return;
    }

    if (packet_space.received_packets.requests_immediate_ack()) {
        packet_space.pending_ack_deadline = now;
        return;
    }

    if (!packet_space.pending_ack_deadline.has_value()) {
        packet_space.pending_ack_deadline = now + std::chrono::milliseconds(max_ack_delay_ms);
    }
}

template <typename FrameType>
bool requires_connected_application_state_for_inbound_frame(const FrameType &frame) {
    return std::holds_alternative<ResetStreamFrame>(frame) |
           std::holds_alternative<StopSendingFrame>(frame) |
           std::holds_alternative<MaxStreamDataFrame>(frame) |
           std::holds_alternative<MaxStreamsFrame>(frame) |
           std::holds_alternative<DataBlockedFrame>(frame) |
           std::holds_alternative<StreamDataBlockedFrame>(frame) |
           std::holds_alternative<StreamsBlockedFrame>(frame);
}

bool should_defer_protected_one_rtt_packet(const ProtectedOneRttPacket &packet,
                                           EndpointRole local_role, HandshakeStatus status) {
    if (status != HandshakeStatus::in_progress) {
        return false;
    }

    if (local_role == EndpointRole::server) {
        return true;
    }

    return std::ranges::any_of(packet.frames, [](const Frame &frame) {
        return requires_connected_application_state_for_inbound_frame(frame);
    });
}

bool should_defer_protected_one_rtt_packet(const ReceivedProtectedOneRttPacket &packet,
                                           EndpointRole local_role, HandshakeStatus status) {
    if (status != HandshakeStatus::in_progress) {
        return false;
    }

    if (local_role == EndpointRole::server) {
        return true;
    }

    return std::ranges::any_of(packet.frames, [](const ReceivedFrame &frame) {
        return requires_connected_application_state_for_inbound_frame(frame);
    });
}

bool should_defer_protected_one_rtt_packet(const ProtectedPacket &packet, EndpointRole local_role,
                                           HandshakeStatus status) {
    const auto *one_rtt = std::get_if<ProtectedOneRttPacket>(&packet);
    return one_rtt != nullptr ? should_defer_protected_one_rtt_packet(*one_rtt, local_role, status)
                              : false;
}

bool should_defer_protected_one_rtt_packet(const ReceivedProtectedPacket &packet,
                                           EndpointRole local_role, HandshakeStatus status) {
    const auto *one_rtt = std::get_if<ReceivedProtectedOneRttPacket>(&packet);
    return one_rtt != nullptr ? should_defer_protected_one_rtt_packet(*one_rtt, local_role, status)
                              : false;
}

std::optional<std::uint64_t>
protected_one_rtt_packet_number_for_trace(const ProtectedPacket &packet) {
    const auto *one_rtt = std::get_if<ProtectedOneRttPacket>(&packet);
    return one_rtt != nullptr ? std::optional<std::uint64_t>(one_rtt->packet_number) : std::nullopt;
}

std::optional<std::uint64_t>
protected_one_rtt_packet_number_for_trace(const ReceivedProtectedPacket &packet) {
    const auto *one_rtt = std::get_if<ReceivedProtectedOneRttPacket>(&packet);
    return one_rtt != nullptr ? std::optional<std::uint64_t>(one_rtt->packet_number) : std::nullopt;
}

bool packet_can_advance_tls_state(const ProtectedPacket &packet) {
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

bool packet_can_advance_tls_state(const ReceivedProtectedPacket &packet) {
    return std::visit(
        [](const auto &protected_packet) {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            if constexpr (std::is_same_v<PacketType, ReceivedProtectedInitialPacket> ||
                          std::is_same_v<PacketType, ReceivedProtectedHandshakePacket>) {
                return true;
            } else {
                return std::ranges::any_of(protected_packet.frames, [](const ReceivedFrame &frame) {
                    return std::holds_alternative<ReceivedCryptoFrame>(frame);
                });
            }
        },
        packet);
}

bool is_discardable_short_header_packet_error(CodecErrorCode code) {
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

bool can_retry_short_header_with_next_key_phase(CodecErrorCode code) {
    static constexpr std::array kRetryableErrors = {
        CodecErrorCode::invalid_packet_protection_state,
        CodecErrorCode::unsupported_packet_type,
        CodecErrorCode::packet_decryption_failed,
        CodecErrorCode::header_protection_failed,
    };
    return std::ranges::find(kRetryableErrors, code) != kRetryableErrors.end();
}

bool is_discardable_packet_length_error(CodecErrorCode code) {
    static constexpr std::array kDiscardableErrors = {
        CodecErrorCode::invalid_fixed_bit,
        CodecErrorCode::unsupported_packet_type,
    };
    return std::ranges::find(kDiscardableErrors, code) != kDiscardableErrors.end();
}

CodecResult<std::size_t>
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

bool should_discard_corrupted_long_header_packet(bool short_header_packet, CodecErrorCode code) {
    return !short_header_packet && (code == CodecErrorCode::invalid_fixed_bit ||
                                    code == CodecErrorCode::unsupported_packet_type);
}

std::uint64_t saturating_subtract(std::uint64_t limit, std::uint64_t used) {
    return limit - std::min(limit, used);
}

bool application_frame_requires_connected_state(bool require_connected, HandshakeStatus status) {
    return require_connected & (status != HandshakeStatus::connected);
}

bool should_adopt_supported_client_version(EndpointRole role, std::uint32_t packet_version,
                                           std::uint32_t current_version) {
    return (role == EndpointRole::client) & is_supported_quic_version(packet_version) &
           (packet_version != current_version);
}

std::optional<QuicCoreTimePoint>
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

std::uint64_t effective_idle_timeout_ms(const TransportParameters &local,
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

std::chrono::milliseconds decode_ack_delay(EncodedAckDelay ack_delay,
                                           AckDelayExponent ack_delay_exponent) {
    if (ack_delay_exponent.value >= std::numeric_limits<std::uint64_t>::digits) {
        return std::chrono::milliseconds(0);
    }

    const auto max_microseconds =
        static_cast<std::uint64_t>(std::numeric_limits<std::chrono::microseconds::rep>::max()) >>
        ack_delay_exponent.value;
    const auto bounded_ack_delay = std::min<std::uint64_t>(ack_delay.value, max_microseconds);
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::microseconds(bounded_ack_delay << ack_delay_exponent.value));
}

std::chrono::milliseconds decode_ack_delay(const AckFrame &ack, std::uint64_t ack_delay_exponent) {
    return decode_ack_delay(EncodedAckDelay{.value = ack.ack_delay},
                            AckDelayExponent{.value = ack_delay_exponent});
}

std::chrono::milliseconds decode_ack_delay(const ReceivedAckFrame &ack,
                                           std::uint64_t ack_delay_exponent) {
    return decode_ack_delay(EncodedAckDelay{.value = ack.ack_delay},
                            AckDelayExponent{.value = ack_delay_exponent});
}

std::size_t stream_fragment_bytes(std::span<const StreamFrameSendFragment> fragments) {
    std::size_t total = 0;
    for (const auto &fragment : fragments) {
        total += fragment.bytes.size();
    }

    return total;
}

std::size_t stream_fragment_wire_bytes(std::span<const StreamFrameSendFragment> fragments) {
    std::size_t total = 0;
    for (const auto &fragment : fragments) {
        total += fragment.stream_frame_wire_size();
    }

    return total;
}

std::size_t stream_frame_header_wire_size(std::uint64_t stream_id, std::uint64_t offset,
                                          std::size_t payload_size) {
    return std::size_t{1} + encoded_varint_size(stream_id) + encoded_varint_size(offset) +
           encoded_varint_size(payload_size);
}

std::size_t max_stream_frame_payload_for_wire_budget(std::uint64_t stream_id, std::uint64_t offset,
                                                     std::size_t wire_budget) {
    if (offset > kMaxQuicVarInt) {
        return 0;
    }

    auto high = static_cast<std::size_t>(
        std::min<std::uint64_t>(static_cast<std::uint64_t>(wire_budget), kMaxQuicVarInt - offset));
    std::size_t low = 0;
    while (low < high) {
        const auto candidate = low + ((high - low + 1u) / 2u);
        const auto wire_size =
            stream_frame_header_wire_size(stream_id, offset, candidate) + candidate;
        if (wire_size <= wire_budget) {
            low = candidate;
            continue;
        }
        high = candidate - 1u;
    }

    return stream_frame_header_wire_size(stream_id, offset, low) + low <= wire_budget ? low : 0;
}

COQUIC_NO_PROFILE std::size_t
short_header_minimum_payload_bytes_for_header_sample(std::uint8_t packet_number_length) {
    return packet_number_length >= kShortHeaderProtectionSampleOffset
               ? 0
               : kShortHeaderProtectionSampleOffset - packet_number_length;
}

COQUIC_NO_PROFILE bool one_rtt_stream_frame_must_have_length(const StreamFrame *stream,
                                                             std::size_t frame_index,
                                                             std::size_t frame_count,
                                                             bool has_stream_fragments) {
    return stream != nullptr && !stream->has_length &&
           (frame_index + 1 != frame_count || has_stream_fragments);
}

CodecResult<std::size_t>
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

std::vector<StreamFrameView>
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

std::size_t application_stream_frame_budget(
    std::size_t max_datagram_size, // NOLINT(bugprone-easily-swappable-parameters)
    std::size_t destination_connection_id_size) {
    if (max_datagram_size < kMinimumInitialDatagramSize) {
        return max_datagram_size;
    }

    const auto packet_overhead = std::size_t{1} + destination_connection_id_size +
                                 kDefaultInitialPacketNumberLength +
                                 kOneRttPacketProtectionTagLength;
    if (max_datagram_size <= packet_overhead) {
        return max_datagram_size;
    }
    return max_datagram_size - packet_overhead;
}

void append_stream_fragments_to_frames(std::vector<Frame> &frames,
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

ProtectedPacket make_application_protected_packet(
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

void set_application_packet_spin_bit(ProtectedPacket &packet, bool spin_bit) {
    if (auto *one_rtt = std::get_if<ProtectedOneRttPacket>(&packet); one_rtt != nullptr) {
        one_rtt->spin_bit = spin_bit;
    }
}

CodecResult<std::vector<std::byte>> serialize_locally_validated_transport_parameters(
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

bool max_data_frame_matches(const std::optional<MaxDataFrame> &candidate,
                            const MaxDataFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return candidate->maximum_data == frame.maximum_data;
}

bool data_blocked_frame_matches(const std::optional<DataBlockedFrame> &candidate,
                                const DataBlockedFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return candidate->maximum_data == frame.maximum_data;
}

bool reset_stream_frame_matches(const std::optional<ResetStreamFrame> &candidate,
                                const ResetStreamFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->application_protocol_error_code,
                    candidate->final_size) ==
           std::tie(frame.stream_id, frame.application_protocol_error_code, frame.final_size);
}

bool stop_sending_frame_matches(const std::optional<StopSendingFrame> &candidate,
                                const StopSendingFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->application_protocol_error_code) ==
           std::tie(frame.stream_id, frame.application_protocol_error_code);
}

bool max_stream_data_frame_matches(const std::optional<MaxStreamDataFrame> &candidate,
                                   const MaxStreamDataFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->maximum_stream_data) ==
           std::tie(frame.stream_id, frame.maximum_stream_data);
}

bool max_streams_frame_matches(const std::optional<MaxStreamsFrame> &candidate,
                               const MaxStreamsFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_type, candidate->maximum_streams) ==
           std::tie(frame.stream_type, frame.maximum_streams);
}

bool stream_data_blocked_frame_matches(const std::optional<StreamDataBlockedFrame> &candidate,
                                       const StreamDataBlockedFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->maximum_stream_data) ==
           std::tie(frame.stream_id, frame.maximum_stream_data);
}

bool should_refresh_receive_window(std::uint64_t delivered_bytes, std::uint64_t advertised_limit,
                                   std::uint64_t window, bool force) {
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

bool packet_space_is_application(const PacketSpaceState &packet_space,
                                 const PacketSpaceState &application_space) {
    return &packet_space == &application_space;
}

bool stream_fin_sendable(const StreamState &stream) {
    if (stream.send_fin_state != StreamSendFinState::pending ||
        !stream.send_final_size.has_value()) {
        return false;
    }

    return *stream.send_final_size <= stream.flow_control.peer_max_stream_data &&
           !stream.send_buffer.has_pending_data();
}

bool stream_receive_terminal(const StreamState &stream) {
    return !stream.id_info.local_can_receive | stream.peer_fin_delivered |
           stream.peer_reset_received;
}

bool stream_send_terminal(const StreamState &stream) {
    return !stream.id_info.local_can_send |
           (stream.send_fin_state == StreamSendFinState::acknowledged) |
           (stream.reset_state == StreamControlFrameState::acknowledged);
}

std::vector<std::uint64_t>
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

std::vector<SentPacketRecord>
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

std::size_t sanitize_pmtud_base(std::size_t value) {
    return std::max<std::size_t>(kMinimumInitialDatagramSize, value);
}

std::size_t initial_congestion_datagram_size(const QuicCoreConfig &config) {
    auto datagram_size = config.transport.pmtud_enabled
                             ? sanitize_pmtud_base(config.transport.pmtud_base_datagram_size)
                             : config.max_outbound_datagram_size;
    datagram_size = std::min(datagram_size, config.max_outbound_datagram_size);
    if (config.transport.pmtud_max_datagram_size != 0) {
        datagram_size = std::min(datagram_size, config.transport.pmtud_max_datagram_size);
    }
    return std::max<std::size_t>(kMaximumDatagramSize, datagram_size);
}

COQUIC_NO_PROFILE bool pmtud_probe_needs_minimum_growth(std::size_t candidate, std::size_t low,
                                                        std::size_t high) {
    return candidate - low < kPmtudMinimumProbeGrowth && candidate != high;
}

COQUIC_NO_PROFILE std::uint64_t packet_number_for_sent_record(const ProtectedPacket &packet) {
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

COQUIC_NO_PROFILE std::size_t
close_packet_metadata_length_for_tracking(const SerializedProtectedDatagram &candidate) {
    if (connection_drain_test_hooks().force_missing_close_packet_metadata ||
        candidate.packet_metadata.empty()) {
        return 0;
    }
    return candidate.packet_metadata.front().length;
}

std::size_t next_probe_size_between(std::size_t low, std::size_t high) {
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

bool pmtud_probe_size_previously_failed(const PathMtuState &mtu, std::size_t probe_size) {
    return std::find(mtu.failed_probe_sizes.begin(), mtu.failed_probe_sizes.end(), probe_size) !=
           mtu.failed_probe_sizes.end();
}

COQUIC_NO_PROFILE std::optional<std::uint32_t>
next_qlog_inbound_datagram_id(qlog::Session *qlog_session) {
    return qlog_session != nullptr
               ? std::optional<std::uint32_t>(qlog_session->next_inbound_datagram_id())
               : std::nullopt;
}

COQUIC_NO_PROFILE bool can_skip_steady_state_receive_sync(
    HandshakeStatus status, bool peer_transport_parameters_validated,
    const std::optional<TrafficSecret> &application_read_secret,
    const std::optional<TrafficSecret> &application_write_secret, bool resumption_state_emitted,
    bool peer_preferred_address_emitted,
    const std::optional<TransportParameters> &peer_transport_parameters,
    const qlog::Session *qlog_session, std::span<const std::byte> bytes) {
    return status == HandshakeStatus::connected && peer_transport_parameters_validated &&
           application_read_secret.has_value() && application_write_secret.has_value() &&
           resumption_state_emitted &&
           (peer_preferred_address_emitted || !peer_transport_parameters.has_value() ||
            !peer_transport_parameters->preferred_address.has_value()) &&
           qlog_session == nullptr && !datagram_starts_with_initial_packet(bytes) &&
           (std::to_integer<std::uint8_t>(bytes.front()) & 0x80u) == 0;
}

COQUIC_NO_PROFILE bool traffic_secret_cache_is_primed(const std::optional<TrafficSecret> &secret) {
    return secret.has_value() && secret->cached_packet_protection_keys.has_value();
}

COQUIC_NO_PROFILE COQUIC_NOINLINE bool
should_defer_short_header_packet_before_server_handshake_complete(bool allow_defer,
                                                                  bool short_header_packet,
                                                                  EndpointRole role,
                                                                  HandshakeStatus status) {
    return static_cast<unsigned>(allow_defer) & static_cast<unsigned>(short_header_packet) &
           static_cast<unsigned>(role == EndpointRole::server) &
           static_cast<unsigned>(status == HandshakeStatus::in_progress);
}

COQUIC_NO_PROFILE bool
deferred_protected_datagram_matches(const DeferredProtectedDatagram &candidate, QuicPathId path_id,
                                    std::span<const std::byte> bytes) {
    return candidate.path_id == path_id && candidate.bytes == bytes;
}

COQUIC_NO_PROFILE void
queue_deferred_protected_datagram(std::vector<DeferredProtectedDatagram> &deferred_packets,
                                  std::span<const std::byte> bytes, QuicPathId path_id,
                                  std::optional<std::uint32_t> datagram_id, QuicEcnCodepoint ecn) {
    for (const auto &candidate : deferred_packets) {
        if (deferred_protected_datagram_matches(candidate, path_id, bytes)) {
            return;
        }
    }
    if (deferred_packets.size() >= kMaximumDeferredProtectedPackets) {
        deferred_packets.erase(deferred_packets.begin());
    }
    deferred_packets.emplace_back(DatagramBuffer(bytes), path_id, datagram_id, ecn);
}

COQUIC_NO_PROFILE COQUIC_NOINLINE bool defer_short_header_packet_before_server_handshake_complete(
    bool allow_defer, bool short_header_packet, EndpointRole role, HandshakeStatus status,
    std::vector<DeferredProtectedDatagram> &deferred_packets, std::span<const std::byte> bytes,
    QuicPathId path_id, std::optional<std::uint32_t> datagram_id, QuicEcnCodepoint ecn) {
    if (!should_defer_short_header_packet_before_server_handshake_complete(
            allow_defer, short_header_packet, role, status)) {
        return false;
    }

    queue_deferred_protected_datagram(deferred_packets, bytes, path_id, datagram_id, ecn);
    return true;
}

template <typename Packet>
COQUIC_NO_PROFILE bool should_defer_decoded_protected_packet(bool allow_defer, const Packet &packet,
                                                             EndpointRole role,
                                                             HandshakeStatus status) {
    return allow_defer && should_defer_protected_one_rtt_packet(packet, role, status);
}

COQUIC_NO_PROFILE bool inbound_packet_storage_range_is_eligible(
    bool allow_in_place_receive_decode,
    const std::optional<TrafficSecret> &previous_application_read_secret, HandshakeStatus status,
    const std::shared_ptr<std::vector<std::byte>> &storage,
    std::span<const std::byte> packet_bytes) {
    return allow_in_place_receive_decode && !previous_application_read_secret.has_value() &&
           status != HandshakeStatus::in_progress && storage != nullptr && !storage->empty() &&
           packet_bytes.data() != nullptr;
}

COQUIC_NO_PROFILE bool packet_bytes_start_inside_storage(std::uintptr_t packet_begin_address,
                                                         std::uintptr_t storage_begin,
                                                         std::uintptr_t storage_end) {
    return packet_begin_address >= storage_begin && packet_begin_address <= storage_end;
}

COQUIC_NO_PROFILE bool trace_packet_for_connection(const ConnectionId &source_connection_id) {
    return packet_trace_matches_connection(source_connection_id);
}

COQUIC_NO_PROFILE void maybe_trace_pmtud_timeout(const ConnectionId &source_connection_id) {
    if (trace_packet_for_connection(source_connection_id)) {
        std::cerr << "quic-packet-trace pmtud-timeout scid="
                  << format_connection_id_hex(source_connection_id) << '\n';
    }
}

COQUIC_NO_PROFILE bool initial_ack_due_for_send(const PacketSpaceState &packet_space,
                                                QuicCoreTimePoint now) {
    return packet_space.received_packets.has_ack_to_send() &&
           (packet_space.force_ack_send ||
            packet_space.pending_ack_deadline.value_or(QuicCoreTimePoint::max()) <= now);
}

COQUIC_NO_PROFILE bool handshake_ack_due_for_send(const PacketSpaceState &packet_space,
                                                  QuicCoreTimePoint now) {
    return packet_space.received_packets.has_ack_to_send() &&
           (packet_space.force_ack_send ||
            packet_space.pending_ack_deadline.value_or(QuicCoreTimePoint::max()) <= now);
}

COQUIC_NO_PROFILE bool application_ack_due_for_send(const PacketSpaceState &packet_space,
                                                    QuicCoreTimePoint now) {
    return packet_space.received_packets.has_ack_to_send() &&
           (packet_space.force_ack_send ||
            packet_space.pending_ack_deadline.value_or(QuicCoreTimePoint::max()) <= now);
}

COQUIC_NO_PROFILE bool should_count_inbound_bytes(bool count_inbound_bytes) {
    return count_inbound_bytes;
}

COQUIC_NO_PROFILE std::size_t accounted_inbound_datagram_bytes(std::span<const std::byte> bytes) {
    return datagram_starts_with_initial_packet(bytes)
               ? std::max(bytes.size(), kMinimumInitialDatagramSize)
               : bytes.size();
}

COQUIC_NO_PROFILE void maybe_note_inbound_datagram_bytes(bool count_inbound_bytes,
                                                         std::span<const std::byte> bytes,
                                                         const auto &note_bytes) {
    if (should_count_inbound_bytes(count_inbound_bytes)) {
        note_bytes(accounted_inbound_datagram_bytes(bytes));
    }
}

COQUIC_NO_PROFILE bool pmtud_deadline_due(const std::optional<QuicCoreTimePoint> &deadline,
                                          QuicCoreTimePoint now) {
    return deadline.has_value() && now >= *deadline;
}

COQUIC_NO_PROFILE bool received_packet_has_plaintext_storage(const auto &packet) {
    if constexpr (requires { packet.plaintext_storage; }) {
        return packet.plaintext_storage != nullptr;
    }
    return false;
}

COQUIC_NO_PROFILE void maybe_copy_plaintext_payload(auto &inspection, const auto &packet) {
    if constexpr (requires { packet.plaintext_storage; }) {
        if (received_packet_has_plaintext_storage(packet)) {
            inspection.plaintext_payload = *packet.plaintext_storage;
        }
    }
}

template <typename Packet>
COQUIC_NO_PROFILE void
populate_packet_inspection_from_decoded_packet(QuicCorePacketInspection &inspection,
                                               const Packet &packet) {
    using PacketType = std::decay_t<Packet>;
    inspection.packet_number_length = packet.packet_number_length;
    inspection.packet_number = packet.packet_number;
    inspection.frames = packet.frames;
    maybe_copy_plaintext_payload(inspection, packet);

    if constexpr (std::is_same_v<PacketType, ReceivedProtectedInitialPacket>) {
        inspection.packet_type = QuicCorePacketInspectionPacketType::initial;
        inspection.version = packet.version;
        inspection.destination_connection_id = packet.destination_connection_id;
        inspection.source_connection_id = packet.source_connection_id;
        inspection.token = packet.token;
    } else if constexpr (std::is_same_v<PacketType, ReceivedProtectedHandshakePacket>) {
        inspection.packet_type = QuicCorePacketInspectionPacketType::handshake;
        inspection.version = packet.version;
        inspection.destination_connection_id = packet.destination_connection_id;
        inspection.source_connection_id = packet.source_connection_id;
    } else if constexpr (std::is_same_v<PacketType, ReceivedProtectedZeroRttPacket>) {
        inspection.packet_type = QuicCorePacketInspectionPacketType::zero_rtt;
        inspection.version = packet.version;
        inspection.destination_connection_id = packet.destination_connection_id;
        inspection.source_connection_id = packet.source_connection_id;
    } else {
        inspection.packet_type = QuicCorePacketInspectionPacketType::one_rtt;
        inspection.destination_connection_id = packet.destination_connection_id;
        inspection.spin_bit = packet.spin_bit;
        inspection.key_phase = packet.key_phase;
    }
}

struct PacketInspectionPopulateVisitor {
    QuicCorePacketInspection &inspection;

    template <typename Packet> COQUIC_NO_PROFILE void operator()(const Packet &packet) const {
        populate_packet_inspection_from_decoded_packet(inspection, packet);
    }
};

struct PacketInspectionPlaintextStorageResetVisitor {
    template <typename Packet> COQUIC_NO_PROFILE void operator()(Packet &packet) const {
        if constexpr (requires { packet.plaintext_storage; }) {
            packet.plaintext_storage.reset();
        }
    }
};

COQUIC_NO_PROFILE bool initial_packet_space_has_sendable_data(const PacketSpaceState &packet_space,
                                                              QuicCoreTimePoint now) {
    return packet_space.send_crypto.has_pending_data() ||
           packet_space.pending_probe_packet.has_value() ||
           initial_ack_due_for_send(packet_space, now);
}

COQUIC_NO_PROFILE bool
handshake_packet_space_has_sendable_data(const PacketSpaceState &packet_space,
                                         QuicCoreTimePoint now) {
    return packet_space.write_secret.has_value() &&
           (packet_space.send_crypto.has_pending_data() ||
            packet_space.pending_probe_packet.has_value() ||
            handshake_ack_due_for_send(packet_space, now));
}

COQUIC_NO_PROFILE bool
can_send_zero_rtt_application_packets(EndpointRole role, HandshakeStatus status,
                                      const PacketSpaceState &zero_rtt_space) {
    return role == EndpointRole::client && status != HandshakeStatus::connected &&
           zero_rtt_space.write_secret.has_value();
}

COQUIC_NO_PROFILE bool can_send_application_packets(EndpointRole role, HandshakeStatus status,
                                                    const PacketSpaceState &zero_rtt_space,
                                                    const PacketSpaceState &application_space) {
    return application_space.write_secret.has_value() ||
           can_send_zero_rtt_application_packets(role, status, zero_rtt_space);
}

COQUIC_NO_PROFILE bool application_space_has_sendable_data(
    bool application_ack_due, bool pending_application_send,
    const PacketSpaceState &application_space, bool has_pending_new_token_frames,
    bool has_pending_new_connection_id_frames, bool has_pending_retire_connection_id_frames) {
    return application_ack_due || pending_application_send ||
           application_space.pending_probe_packet.has_value() || has_pending_new_token_frames ||
           has_pending_new_connection_id_frames || has_pending_retire_connection_id_frames ||
           application_space.send_crypto.has_pending_data();
}

COQUIC_NO_PROFILE bool pmtud_packet_deadline_candidate_is_live(const SentPacketRecord *packet) {
    return packet != nullptr && packet->is_pmtu_probe;
}

COQUIC_NO_PROFILE QuicCoreTimePoint earliest_deadline(std::optional<QuicCoreTimePoint> existing,
                                                      QuicCoreTimePoint candidate) {
    return existing.has_value() ? std::min(*existing, candidate) : candidate;
}

COQUIC_NO_PROFILE bool
packet_space_has_no_in_flight_ack_eliciting_packet(bool discarded,
                                                   const PacketSpaceState &packet_space) {
    return discarded || !has_in_flight_ack_eliciting_packet(packet_space);
}

COQUIC_NO_PROFILE bool client_keepalive_has_no_in_flight_packets(
    bool initial_discarded, const PacketSpaceState &initial_space, bool handshake_discarded,
    const PacketSpaceState &handshake_space, const PacketSpaceState &application_space) {
    return packet_space_has_no_in_flight_ack_eliciting_packet(initial_discarded, initial_space) &&
           packet_space_has_no_in_flight_ack_eliciting_packet(handshake_discarded,
                                                              handshake_space) &&
           !has_in_flight_ack_eliciting_packet(application_space);
}

COQUIC_NO_PROFILE bool client_handshake_keepalive_is_eligible(
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

COQUIC_NO_PROFILE bool client_receive_keepalive_is_eligible(
    EndpointRole role, bool handshake_confirmed,
    const std::optional<QuicCoreTimePoint> &last_peer_activity_time, bool has_receive_interest,
    bool initial_discarded, const PacketSpaceState &initial_space, bool handshake_discarded,
    const PacketSpaceState &handshake_space, const PacketSpaceState &application_space) {
    return role == EndpointRole::client && handshake_confirmed &&
           last_peer_activity_time.has_value() && has_receive_interest &&
           client_keepalive_has_no_in_flight_packets(initial_discarded, initial_space,
                                                     handshake_discarded, handshake_space,
                                                     application_space);
}

COQUIC_NO_PROFILE bool
has_client_handshake_keepalive_space(const std::optional<QuicCoreTimePoint> &reference_time,
                                     bool initial_discarded, bool handshake_discarded,
                                     const PacketSpaceState &handshake_space) {
    return reference_time.has_value() &&
           (!initial_discarded ||
            (!handshake_discarded && handshake_space.write_secret.has_value()));
}

COQUIC_NO_PROFILE PacketSpaceState *client_handshake_keepalive_packet_space(
    const std::optional<QuicCoreTimePoint> &reference_time, bool initial_discarded,
    PacketSpaceState &initial_space, bool handshake_discarded, PacketSpaceState &handshake_space) {
    if (!has_client_handshake_keepalive_space(reference_time, initial_discarded,
                                              handshake_discarded, handshake_space)) {
        return nullptr;
    }
    return (!handshake_discarded && handshake_space.write_secret.has_value()) ? &handshake_space
                                                                              : &initial_space;
}

COQUIC_NO_PROFILE bool client_handshake_recovery_probe_has_other_space_in_flight(
    bool initial_discarded, const PacketSpaceState &initial_space,
    const PacketSpaceState &application_space) {
    return (!initial_discarded && has_in_flight_ack_eliciting_packet(initial_space)) |
           has_in_flight_ack_eliciting_packet(application_space);
}

COQUIC_NO_PROFILE bool
has_timer_lost_packets_for_profile(bool profile_enabled,
                                   const std::vector<SentPacketRecord> &lost_packets) {
    return profile_enabled && !lost_packets.empty();
}

COQUIC_NO_PROFILE bool pmtu_trace_no_probe(const ConnectionId &source_connection_id) {
    return packet_trace_matches_connection(source_connection_id);
}

COQUIC_NO_PROFILE void maybe_trace_pmtu_no_probe(const ConnectionId &source_connection_id,
                                                 const PathState &path) {
    if (pmtu_trace_no_probe(source_connection_id)) {
        std::cerr << "quic-packet-trace pmtud-no-probe scid="
                  << format_connection_id_hex(source_connection_id) << " path=" << path.id
                  << " validated=" << path.mtu.validated_datagram_size
                  << " ceiling=" << path.mtu.probe_ceiling << '\n';
    }
}

COQUIC_NO_PROFILE bool
should_refresh_connection_credit_for_data_blocked(const DataBlockedFrame &frame,
                                                  const ConnectionFlowControlState &flow_control) {
    return frame.maximum_data >= flow_control.advertised_max_data;
}

COQUIC_NO_PROFILE void
maybe_refresh_connection_credit_for_data_blocked(const DataBlockedFrame &frame,
                                                 const ConnectionFlowControlState &flow_control,
                                                 const auto &refresh) {
    if (should_refresh_connection_credit_for_data_blocked(frame, flow_control)) {
        refresh();
    }
}

COQUIC_NO_PROFILE bool
should_refresh_stream_credit_for_data_blocked(const StreamDataBlockedFrame &frame,
                                              const StreamState &stream) {
    return frame.maximum_stream_data >= stream.flow_control.advertised_max_stream_data;
}

COQUIC_NO_PROFILE void
maybe_refresh_stream_credit_for_data_blocked(const StreamDataBlockedFrame &frame,
                                             const StreamState &stream, const auto &refresh) {
    if (should_refresh_stream_credit_for_data_blocked(frame, stream)) {
        refresh();
    }
}

COQUIC_NO_PROFILE bool should_skip_available_secret(EncryptionLevel level,
                                                    bool initial_packet_space_discarded,
                                                    bool handshake_packet_space_discarded) {
    return (level == EncryptionLevel::initial && initial_packet_space_discarded) ||
           (level == EncryptionLevel::handshake && handshake_packet_space_discarded);
}

COQUIC_NO_PROFILE bool can_skip_outbound_tls_sync_now(
    HandshakeStatus status, bool peer_transport_parameters_validated,
    const std::optional<TrafficSecret> &application_read_secret,
    const std::optional<TrafficSecret> &application_write_secret, const qlog::Session *qlog_session,
    const std::vector<DeferredProtectedDatagram> &deferred_protected_packets) {
    return status == HandshakeStatus::connected && peer_transport_parameters_validated &&
           application_read_secret.has_value() && application_write_secret.has_value() &&
           qlog_session == nullptr && deferred_protected_packets.empty();
}

COQUIC_NO_PROFILE bool client_outbound_tls_sync_can_skip_resumption(
    bool resumption_state_emitted, bool peer_preferred_address_emitted,
    const std::optional<TransportParameters> &peer_transport_parameters) {
    return resumption_state_emitted &&
           (peer_preferred_address_emitted || !peer_transport_parameters.has_value() ||
            !peer_transport_parameters->preferred_address.has_value());
}

COQUIC_NO_PROFILE bool should_clear_outstanding_pmtu_probe(const PathMtuState &mtu,
                                                           std::uint64_t packet_number) {
    return mtu.outstanding_probe_packet_number.has_value() &&
           *mtu.outstanding_probe_packet_number == packet_number;
}

COQUIC_NO_PROFILE bool should_clear_outstanding_pmtu_probe_after_ceiling(const PathMtuState &mtu) {
    return mtu.outstanding_probe_size.has_value() &&
           *mtu.outstanding_probe_size > mtu.probe_ceiling;
}

COQUIC_NO_PROFILE void clear_outstanding_pmtu_probe(PathMtuState &mtu) {
    mtu.outstanding_probe_size.reset();
    mtu.outstanding_probe_packet_number.reset();
}

COQUIC_NO_PROFILE std::optional<QuicCoreTimePoint>
pmtud_next_probe_time(const PathMtuState &mtu, QuicCoreTimePoint now,
                      QuicCoreClock::duration delay) {
    return mtu.enabled && mtu.validated_datagram_size < mtu.probe_ceiling
               ? std::optional<QuicCoreTimePoint>{now + delay}
               : std::nullopt;
}

COQUIC_NO_PROFILE bool should_reset_client_handshake_peer_state_for_source(
    EndpointRole role, HandshakeStatus status, bool handshake_confirmed,
    const std::optional<ConnectionId> &peer_source_connection_id,
    const ConnectionId &source_connection_id) {
    return role == EndpointRole::client && status == HandshakeStatus::in_progress &&
           !handshake_confirmed && peer_source_connection_id.has_value() &&
           peer_source_connection_id.value() != source_connection_id;
}

COQUIC_NO_PROFILE bool
should_use_pending_pmtu_probe_size(bool allow_pmtu_probe_size, bool anti_amplification_limited,
                                   const std::optional<SentPacketRecord> &pending_probe_packet) {
    if (!allow_pmtu_probe_size || anti_amplification_limited || !pending_probe_packet.has_value()) {
        return false;
    }
    const auto &pending_probe = optional_ref_or_abort(pending_probe_packet);
    return pending_probe.is_pmtu_probe && pending_probe.pmtu_probe_size != 0;
}

COQUIC_NO_PROFILE bool should_keep_searching_for_pmtu_probe_size(const PathMtuState &mtu,
                                                                 std::size_t next_probe_size) {
    return next_probe_size > mtu.validated_datagram_size &&
           pmtud_probe_size_previously_failed(mtu, next_probe_size);
}

COQUIC_NO_PROFILE bool should_arm_pmtu_probe_after_send(const PathMtuState &mtu,
                                                        bool application_write_secret_available,
                                                        bool pending_application_send) {
    return mtu.enabled && application_write_secret_available && pending_application_send &&
           !mtu.next_probe_time.has_value() && !mtu.outstanding_probe_packet_number.has_value() &&
           mtu.validated_datagram_size < mtu.probe_ceiling;
}

COQUIC_NO_PROFILE bool append_retired_packet_if_present(std::vector<SentPacketRecord> &packets,
                                                        std::optional<SentPacketRecord> packet) {
    if (!packet.has_value()) {
        return false;
    }

    packets.push_back(std::move(*packet));
    return true;
}

COQUIC_NO_PROFILE void record_latest_rtt_sample_for_profile(const RecoveryRttState &rtt,
                                                            SendProfileCounters &profile) {
    if (rtt.latest_rtt.has_value()) {
        const auto latest_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(*rtt.latest_rtt).count());
        profile.latest_rtt_us_sum += latest_us;
        profile.latest_rtt_us_max = std::max(profile.latest_rtt_us_max, latest_us);
    }
}

COQUIC_NO_PROFILE std::optional<std::size_t> prepare_pmtu_probe_packet_for_tracking(
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

COQUIC_NO_PROFILE bool duplicate_initial_congestion_is_forced(bool force, bool bypass,
                                                              bool has_packets) {
    return !bypass && force && has_packets;
}

COQUIC_NO_PROFILE bool
application_send_congestion_is_forced(bool force, bool bypass,
                                      const PacketSpaceState &application_space) {
    return !bypass && force && application_space.write_secret.has_value();
}

struct PacketInspectionDatagramId {
    std::uint64_t value;
};

struct PacketInspectionCount {
    std::size_t value;
};

COQUIC_NO_PROFILE void
maybe_record_packet_inspection_datagram_id(std::uint64_t &last_datagram_id,
                                           PacketInspectionDatagramId datagram_id,
                                           PacketInspectionCount inspection_count) {
    if (inspection_count.value != 0) {
        last_datagram_id = datagram_id.value;
    }
}

COQUIC_NO_PROFILE bool fin_only_stream_frame_cannot_fit(bool fin_sendable,
                                                        bool has_send_final_size) {
    return !fin_sendable || !has_send_final_size;
}

COQUIC_NO_PROFILE bool
stream_fragment_consumes_connection_credit(const StreamFrameSendFragment &fragment) {
    return fragment.consumes_flow_control && !fragment.bytes.empty();
}

COQUIC_NO_PROFILE void
restore_stream_fragment_connection_credit(const StreamFrameSendFragment &fragment,
                                          ConnectionFlowControlState &connection_flow,
                                          std::uint64_t &remaining_connection_credit) {
    if (!stream_fragment_consumes_connection_credit(fragment)) {
        return;
    }

    connection_flow.highest_sent -= static_cast<std::uint64_t>(fragment.bytes.size());
    remaining_connection_credit += static_cast<std::uint64_t>(fragment.bytes.size());
}

COQUIC_NO_PROFILE void restore_stream_fragment(std::map<std::uint64_t, StreamState> &streams,
                                               const StreamFrameSendFragment &fragment,
                                               ConnectionFlowControlState &connection_flow,
                                               std::uint64_t &remaining_connection_credit) {
    restore_stream_fragment_connection_credit(fragment, connection_flow,
                                              remaining_connection_credit);
    streams.at(fragment.stream_id).restore_send_fragment(fragment);
}

COQUIC_NO_PROFILE bool stream_fragment_needs_tail_restore(std::size_t retained_payload_size,
                                                          const StreamFrameSendFragment &fragment) {
    return retained_payload_size < fragment.bytes.size();
}

COQUIC_NO_PROFILE void maybe_restore_stream_fragment_tail(
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

COQUIC_NO_PROFILE void remember_minimum_wire_size(std::optional<std::size_t> &minimum_wire_bytes,
                                                  std::size_t wire_size) {
    minimum_wire_bytes = minimum_wire_bytes.has_value() ? std::min(*minimum_wire_bytes, wire_size)
                                                        : std::optional<std::size_t>{wire_size};
}

COQUIC_NO_PROFILE bool pmtu_probe_padding_already_satisfied(std::size_t target_pmtu_probe_size,
                                                            std::size_t datagram_size) {
    return target_pmtu_probe_size == 0 || datagram_size >= target_pmtu_probe_size;
}

COQUIC_NO_PROFILE bool pmtu_probe_padding_required(std::size_t padding) {
    return padding != 0;
}

COQUIC_NO_PROFILE bool maybe_add_pmtu_probe_padding(std::size_t padding, std::vector<Frame> &frames,
                                                    std::size_t &probe_padding_length) {
    if (!pmtu_probe_padding_required(padding)) {
        return false;
    }

    frames.emplace_back(PaddingFrame{.length = padding});
    probe_padding_length = padding;
    return true;
}

COQUIC_NO_PROFILE bool should_fail_after_probe_credit_retry(bool retried, bool failed) {
    return !retried || failed;
}

COQUIC_NO_PROFILE bool
ack_only_path_validation_is_ack_eliciting(const auto &path_validation_frames) {
    return path_validation_frames.response.has_value() |
           path_validation_frames.challenge.has_value();
}

COQUIC_NO_PROFILE void
maybe_queue_ack_only_path_validation_packet(const auto &path_validation_frames,
                                            const auto &queue_packet) {
    if (ack_only_path_validation_is_ack_eliciting(path_validation_frames)) {
        queue_packet();
    }
}

COQUIC_NO_PROFILE bool
ack_can_be_trimmed_for_stream_budget(const std::optional<OutboundAckHeader> &selected_ack_frame,
                                     const std::optional<std::size_t> &minimum_stream_wire_bytes,
                                     const CodecResult<std::size_t> &control_candidate_size,
                                     std::size_t congestion_limited_datagram_size) {
    return selected_ack_frame.has_value() && minimum_stream_wire_bytes.has_value() &&
           control_candidate_size.has_value() &&
           congestion_limited_datagram_size >= kMinimumInitialDatagramSize;
}

COQUIC_NO_PROFILE bool
stream_budget_can_absorb_empty_no_ack_candidate(std::size_t base_application_stream_budget,
                                                std::size_t minimum_stream_wire_bytes) {
    return base_application_stream_budget >= minimum_stream_wire_bytes;
}

COQUIC_NO_PROFILE bool maybe_select_empty_no_ack_candidate(
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

COQUIC_NO_PROFILE bool
no_ack_control_candidate_leaves_stream_budget(std::size_t no_ack_control_candidate_size,
                                              std::size_t congestion_limited_datagram_size,
                                              std::size_t minimum_stream_wire_bytes) {
    return no_ack_control_candidate_size < congestion_limited_datagram_size &&
           congestion_limited_datagram_size - no_ack_control_candidate_size >=
               minimum_stream_wire_bytes;
}

COQUIC_NO_PROFILE bool should_fail_non_empty_packet_payload_candidate(
    const CodecResult<SerializedProtectedDatagram> &candidate) {
    return !candidate.has_value() && !is_empty_packet_payload_error(candidate);
}

COQUIC_NO_PROFILE std::uint64_t
optional_frame_trace_value(const std::optional<MaxDataFrame> &frame) {
    return frame.has_value() ? frame->maximum_data : 0;
}

COQUIC_NO_PROFILE std::uint64_t
optional_frame_trace_value(const std::optional<DataBlockedFrame> &frame) {
    return frame.has_value() ? frame->maximum_data : 0;
}

COQUIC_NO_PROFILE bool use_fast_serialized_one_rtt_commit_for_packet(
    EndpointRole role, bool packets_empty, const qlog::Session *qlog_session,
    bool use_zero_rtt_packet_protection, bool has_application_close) {
    return role == EndpointRole::server && packets_empty && qlog_session == nullptr &&
           !use_zero_rtt_packet_protection && !has_application_close;
}

void remember_pmtud_failed_probe_size(PathMtuState &mtu, std::size_t probe_size) {
    if (probe_size <= kMinimumInitialDatagramSize ||
        pmtud_probe_size_previously_failed(mtu, probe_size)) {
        return;
    }
    mtu.failed_probe_sizes.push_back(probe_size);
    if (mtu.failed_probe_sizes.size() > kMaximumRememberedPmtudFailedProbeSizes) {
        mtu.failed_probe_sizes.erase(mtu.failed_probe_sizes.begin());
    }
}

void forget_pmtud_failed_probe_size(PathMtuState &mtu, std::size_t probe_size) {
    mtu.failed_probe_sizes.erase(
        std::remove(mtu.failed_probe_sizes.begin(), mtu.failed_probe_sizes.end(), probe_size),
        mtu.failed_probe_sizes.end());
}

QuicCoreTimePoint latest_packet_sent_time(std::span<const SentPacketRecord> packets) {
    return std::max_element(packets.begin(), packets.end(),
                            [](const SentPacketRecord &lhs, const SentPacketRecord &rhs) {
                                return lhs.sent_time < rhs.sent_time;
                            })
        ->sent_time;
}

std::size_t retransmittable_probe_frame_count(const SentPacketRecord &packet) {
    return packet.crypto_ranges.size() + packet.new_token_frames.size() +
           packet.reset_stream_frames.size() + packet.stop_sending_frames.size() +
           packet.new_connection_id_frames.size() + packet.retire_connection_id_frames.size() +
           packet.max_stream_data_frames.size() + packet.max_streams_frames.size() +
           packet.stream_data_blocked_frames.size() + packet.stream_fragments.size() +
           static_cast<std::size_t>(packet.has_handshake_done) +
           static_cast<std::size_t>(packet.max_data_frame.has_value()) +
           static_cast<std::size_t>(packet.data_blocked_frame.has_value());
}

bool stream_fragment_is_probe_worthy(const StreamState &stream,
                                     const StreamFrameSendFragment &fragment) {
    if (stream.reset_state != StreamControlFrameState::none) {
        return false;
    }

    if (stream.send_buffer.has_outstanding_range(fragment.offset, fragment.bytes.size())) {
        return true;
    }

    const bool missing_fin = !fragment.fin;
    const bool fin_already_acknowledged = stream.send_fin_state == StreamSendFinState::acknowledged;
    if (missing_fin | fin_already_acknowledged) {
        return false;
    }
    const auto fragment_end = fragment.offset + static_cast<std::uint64_t>(fragment.bytes.size());
    return stream.send_final_size == std::optional<std::uint64_t>{fragment_end};
}

std::size_t application_ack_eliciting_frame_count(
    std::span<const NewTokenFrame> new_token_frames, bool include_handshake_done,
    const std::optional<MaxDataFrame> &max_data_frame,
    std::span<const NewConnectionIdFrame> new_connection_id_frames,
    std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
    bool has_path_response_frame, bool has_path_challenge_frame,
    std::span<const MaxStreamDataFrame> max_stream_data_frames,
    std::span<const MaxStreamsFrame> max_streams_frames,
    std::span<const ResetStreamFrame> reset_stream_frames,
    std::span<const StopSendingFrame> stop_sending_frames,
    const std::optional<DataBlockedFrame> &data_blocked_frame,
    std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
    std::span<const StreamFrameSendFragment> stream_fragments) {
    return new_token_frames.size() + new_connection_id_frames.size() +
           retire_connection_id_frames.size() + max_stream_data_frames.size() +
           max_streams_frames.size() + reset_stream_frames.size() + stop_sending_frames.size() +
           stream_data_blocked_frames.size() + stream_fragments.size() +
           static_cast<std::size_t>(include_handshake_done) +
           static_cast<std::size_t>(has_path_response_frame) +
           static_cast<std::size_t>(has_path_challenge_frame) +
           static_cast<std::size_t>(max_data_frame.has_value()) +
           static_cast<std::size_t>(data_blocked_frame.has_value());
}

bool establishes_persistent_congestion(std::span<const SentPacketRecord> lost_packets,
                                       const RecoveryRttState &rtt,
                                       std::chrono::milliseconds max_ack_delay) {
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

    const auto persistent_congestion_duration =
        (rtt.smoothed_rtt + std::max(rtt.rttvar * 4, kGranularity) + max_ack_delay) *
        kPersistentCongestionThreshold;
    return last_loss->sent_time - first_loss->sent_time >= persistent_congestion_duration;
}

void reset_discarded_packet_space_state(PacketSpaceState &packet_space) {
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

void reset_packet_space_receive_state(PacketSpaceState &packet_space) {
    packet_space.largest_authenticated_packet_number = std::nullopt;
    packet_space.received_packets = ReceivedPacketHistory{};
    packet_space.pending_ack_deadline = std::nullopt;
    packet_space.force_ack_send = false;
}

} // namespace

std::uint64_t ConnectionFlowControlState::sendable_bytes(std::uint64_t queued_bytes) const {
    const auto remaining_credit = peer_max_data > highest_sent ? peer_max_data - highest_sent : 0;
    const auto unsent_bytes = queued_bytes > highest_sent ? queued_bytes - highest_sent : 0;
    return std::min(remaining_credit, unsent_bytes);
}

bool ConnectionFlowControlState::should_send_data_blocked(std::uint64_t queued_bytes) const {
    return queued_bytes > peer_max_data;
}

void ConnectionFlowControlState::note_peer_max_data(std::uint64_t maximum_data) {
    if (maximum_data <= peer_max_data) {
        return;
    }

    peer_max_data = maximum_data;
}

void ConnectionFlowControlState::queue_max_data(std::uint64_t maximum_data) {
    if (maximum_data <= advertised_max_data) {
        return;
    }

    advertised_max_data = maximum_data;
    pending_max_data_frame = MaxDataFrame{
        .maximum_data = maximum_data,
    };
    max_data_state = StreamControlFrameState::pending;
}

std::optional<MaxDataFrame> ConnectionFlowControlState::take_max_data_frame() {
    if (max_data_state != StreamControlFrameState::pending || !pending_max_data_frame.has_value()) {
        return std::nullopt;
    }

    max_data_state = StreamControlFrameState::sent;
    return pending_max_data_frame;
}

void ConnectionFlowControlState::acknowledge_max_data_frame(const MaxDataFrame &frame) {
    if (max_data_frame_matches(pending_max_data_frame, frame)) {
        max_data_state = StreamControlFrameState::acknowledged;
    }
}

void ConnectionFlowControlState::mark_max_data_frame_lost(const MaxDataFrame &frame) {
    if (max_data_state != StreamControlFrameState::acknowledged &&
        max_data_frame_matches(pending_max_data_frame, frame)) {
        max_data_state = StreamControlFrameState::pending;
    }
}

void ConnectionFlowControlState::queue_data_blocked(std::uint64_t maximum_data) {
    if (pending_data_blocked_frame.has_value() &&
        pending_data_blocked_frame->maximum_data == maximum_data &&
        data_blocked_state != StreamControlFrameState::none) {
        return;
    }

    pending_data_blocked_frame = DataBlockedFrame{
        .maximum_data = maximum_data,
    };
    data_blocked_state = StreamControlFrameState::pending;
}

std::optional<DataBlockedFrame> ConnectionFlowControlState::take_data_blocked_frame() {
    if (data_blocked_state != StreamControlFrameState::pending ||
        !pending_data_blocked_frame.has_value()) {
        return std::nullopt;
    }

    data_blocked_state = StreamControlFrameState::sent;
    return pending_data_blocked_frame;
}

void ConnectionFlowControlState::acknowledge_data_blocked_frame(const DataBlockedFrame &frame) {
    if (data_blocked_frame_matches(pending_data_blocked_frame, frame)) {
        data_blocked_state = StreamControlFrameState::acknowledged;
    }
}

void ConnectionFlowControlState::mark_data_blocked_frame_lost(const DataBlockedFrame &frame) {
    if (data_blocked_state != StreamControlFrameState::acknowledged &&
        data_blocked_frame_matches(pending_data_blocked_frame, frame)) {
        data_blocked_state = StreamControlFrameState::pending;
    }
}

void LocalStreamLimitState::initialize(PeerStreamOpenLimits limits) {
    advertised_max_streams_bidi = limits.bidirectional;
    advertised_max_streams_uni = limits.unidirectional;
    pending_max_streams_bidi_frame = std::nullopt;
    max_streams_bidi_state = StreamControlFrameState::none;
    pending_max_streams_uni_frame = std::nullopt;
    max_streams_uni_state = StreamControlFrameState::none;
}

void LocalStreamLimitState::queue_max_streams(StreamLimitType stream_type,
                                              std::uint64_t maximum_streams) {
    auto *advertised_limit = &advertised_max_streams_bidi;
    auto *pending_frame = &pending_max_streams_bidi_frame;
    auto *state = &max_streams_bidi_state;
    if (stream_type == StreamLimitType::unidirectional) {
        advertised_limit = &advertised_max_streams_uni;
        pending_frame = &pending_max_streams_uni_frame;
        state = &max_streams_uni_state;
    }

    if (maximum_streams <= *advertised_limit) {
        return;
    }

    *advertised_limit = maximum_streams;
    *pending_frame = MaxStreamsFrame{
        .stream_type = stream_type,
        .maximum_streams = maximum_streams,
    };
    *state = StreamControlFrameState::pending;
}

std::vector<MaxStreamsFrame> LocalStreamLimitState::take_max_streams_frames() {
    std::vector<MaxStreamsFrame> frames;
    if (max_streams_bidi_state == StreamControlFrameState::pending &&
        pending_max_streams_bidi_frame.has_value()) {
        max_streams_bidi_state = StreamControlFrameState::sent;
        frames.push_back(*pending_max_streams_bidi_frame);
    }
    if (max_streams_uni_state == StreamControlFrameState::pending &&
        pending_max_streams_uni_frame.has_value()) {
        max_streams_uni_state = StreamControlFrameState::sent;
        frames.push_back(*pending_max_streams_uni_frame);
    }

    return frames;
}

StreamControlFrameState *max_streams_state_for(LocalStreamLimitState &state,
                                               StreamLimitType stream_type) {
    return stream_type == StreamLimitType::bidirectional ? &state.max_streams_bidi_state
                                                         : &state.max_streams_uni_state;
}

std::optional<MaxStreamsFrame> *pending_max_streams_frame_for(LocalStreamLimitState &state,
                                                              StreamLimitType stream_type) {
    return stream_type == StreamLimitType::bidirectional ? &state.pending_max_streams_bidi_frame
                                                         : &state.pending_max_streams_uni_frame;
}

void LocalStreamLimitState::acknowledge_max_streams_frame(const MaxStreamsFrame &frame) {
    auto *state = max_streams_state_for(*this, frame.stream_type);
    if (*state == StreamControlFrameState::none) {
        return;
    }
    const auto *pending_frame = pending_max_streams_frame_for(*this, frame.stream_type);
    if (!max_streams_frame_matches(*pending_frame, frame)) {
        return;
    }

    *state = StreamControlFrameState::acknowledged;
}

void LocalStreamLimitState::mark_max_streams_frame_lost(const MaxStreamsFrame &frame) {
    auto *state = max_streams_state_for(*this, frame.stream_type);
    if (*state == StreamControlFrameState::none ||
        *state == StreamControlFrameState::acknowledged) {
        return;
    }
    const auto *pending_frame = pending_max_streams_frame_for(*this, frame.stream_type);
    if (!max_streams_frame_matches(*pending_frame, frame)) {
        return;
    }

    *state = StreamControlFrameState::pending;
}

QuicConnection::QuicConnection(QuicCoreConfig config)
    : config_(std::move(config)),
      latency_spin_bit_disabled_(config_.transport.enable_latency_spin_bit ? random_one_in_sixteen()
                                                                           : true),
      original_version_(config_.original_version), current_version_(config_.initial_version),
      congestion_controller_(config_.transport.congestion_control,
                             initial_congestion_datagram_size(config_)) {
    if (config_.supported_versions.empty()) {
        config_.supported_versions.push_back(current_version_);
    }
    local_transport_parameters_ = TransportParameters{
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .max_udp_payload_size = config_.transport.max_udp_payload_size,
        .active_connection_id_limit = config_.transport.active_connection_id_limit,
        .disable_active_migration = config_.transport.disable_active_migration,
        .ack_delay_exponent = config_.transport.ack_delay_exponent,
        .max_ack_delay = config_.transport.max_ack_delay,
        .initial_max_data = config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local = config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = config_.source_connection_id,
        .preferred_address = config_.transport.preferred_address,
    };
    initialize_local_flow_control();
    local_connection_ids_.emplace(0, LocalConnectionIdRecord{
                                         .sequence_number = 0,
                                         .connection_id = config_.source_connection_id,
                                         .stateless_reset_token = make_stateless_reset_token(
                                             config_.source_connection_id, /*sequence_number=*/0,
                                             config_.stateless_reset_secret),
                                     });
    if (config_.transport.preferred_address.has_value()) {
        // RFC 9000 reserves sequence number 1 for the preferred-address CID.
        local_connection_ids_.emplace(
            1,
            LocalConnectionIdRecord{
                .sequence_number = 1,
                .connection_id = config_.transport.preferred_address->connection_id,
                .stateless_reset_token = config_.transport.preferred_address->stateless_reset_token,
            });
        next_local_connection_id_sequence_ = 2;
    }
    peer_address_validated_ = config_.role == EndpointRole::client;
}

QuicConnection::~QuicConnection() = default;

QuicConnection::QuicConnection(QuicConnection &&) noexcept = default;

QuicConnection &QuicConnection::operator=(QuicConnection &&) noexcept = default;

void QuicConnection::start() {
    start(QuicCoreTimePoint{});
}

void QuicConnection::start(QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    start_client_if_needed(now);
}

void QuicConnection::process_inbound_datagram(std::span<const std::byte> bytes,
                                              QuicCoreTimePoint now, QuicPathId path_id,
                                              QuicEcnCodepoint ecn) {
    const auto inbound_datagram_id = next_qlog_inbound_datagram_id(qlog_session_.get());
    process_inbound_datagram(bytes, now, path_id, ecn, inbound_datagram_id,
                             /*replay_trigger=*/false, /*count_inbound_bytes=*/true);
}

void QuicConnection::process_inbound_datagram_owned(std::vector<std::byte> bytes,
                                                    QuicCoreTimePoint now, QuicPathId path_id,
                                                    QuicEcnCodepoint ecn) {
    const auto inbound_datagram_id = next_qlog_inbound_datagram_id(qlog_session_.get());
    auto storage = std::make_shared<std::vector<std::byte>>(std::move(bytes));
    const auto storage_size = storage->size();
    process_inbound_datagram(std::move(storage), 0, storage_size, now, path_id, ecn,
                             inbound_datagram_id, /*replay_trigger=*/false,
                             /*count_inbound_bytes=*/true, /*allow_in_place_receive_decode=*/true);
}

void QuicConnection::process_inbound_datagram(std::span<const std::byte> bytes,
                                              QuicCoreTimePoint now, QuicPathId path_id,
                                              QuicEcnCodepoint ecn,
                                              std::optional<std::uint32_t> inbound_datagram_id,
                                              bool replay_trigger, bool count_inbound_bytes) {
    auto storage = std::make_shared<std::vector<std::byte>>(bytes.begin(), bytes.end());
    const auto storage_size = storage->size();
    process_inbound_datagram(std::move(storage), 0, storage_size, now, path_id, ecn,
                             inbound_datagram_id, replay_trigger, count_inbound_bytes,
                             /*allow_in_place_receive_decode=*/false);
}

void QuicConnection::process_inbound_datagram(std::shared_ptr<std::vector<std::byte>> storage,
                                              std::size_t begin, std::size_t end,
                                              QuicCoreTimePoint now, QuicPathId path_id,
                                              QuicEcnCodepoint ecn,
                                              std::optional<std::uint32_t> inbound_datagram_id,
                                              bool replay_trigger, bool count_inbound_bytes,
                                              bool allow_in_place_receive_decode) {
    if (!storage || begin > end || end > storage->size()) {
        process_inbound_datagram(std::span<const std::byte>{}, now, path_id, ecn,
                                 inbound_datagram_id, replay_trigger, count_inbound_bytes);
        return;
    }

    const auto bytes = std::span<const std::byte>(*storage).subspan(begin, end - begin);
    register_send_profile_printer_once();
    if (send_profile_enabled()) {
        ++send_profile_counters().inbound_calls;
        send_profile_counters().inbound_bytes += bytes.size();
    }
    SendProfileTimer inbound_timer(send_profile_counters().inbound_ns);
    SendProfileTimer setup_timer(send_profile_counters().inbound_setup_ns);
    if (status_ == HandshakeStatus::failed || bytes.empty()) {
        if (close_mode_ == QuicConnectionCloseMode::closing) {
            ++closing_packets_since_last_close_;
            if (closing_packets_since_last_close_ >= closing_packet_response_threshold_) {
                closing_close_packet_pending_ = true;
            }
        }
        return;
    }
    last_inbound_path_id_ = path_id;
    if (!current_send_path_id_.has_value()) {
        current_send_path_id_ = path_id;
        auto &path = ensure_path_state(path_id);
        path.is_current_send_path = true;
        if (path.mtu.validated_datagram_size < bytes.size()) {
            path.mtu.validated_datagram_size =
                std::min(bytes.size(), outbound_datagram_size_ceiling_for_path(path_id));
            path.mtu.search_low = path.mtu.validated_datagram_size;
        }
    }

    maybe_discard_server_zero_rtt_packet_space(now);

    maybe_note_inbound_datagram_bytes(count_inbound_bytes, bytes, [&](std::size_t byte_count) {
        note_inbound_datagram_bytes(byte_count);
    });

    if (!started_) {
        if (config_.role != EndpointRole::server) {
            queue_transport_close_for_error(
                now, CodecError{.code = CodecErrorCode::unsupported_packet_type, .offset = 0});
            return;
        }

        const auto initial_destination_connection_id =
            peek_client_initial_destination_connection_id(bytes);
        if (!initial_destination_connection_id.has_value()) {
            log_codec_failure("peek_client_initial_destination_connection_id",
                              initial_destination_connection_id.error());
            queue_transport_close_for_error(now, initial_destination_connection_id.error());
            return;
        }

        start_server_if_needed(initial_destination_connection_id.value(), now,
                               read_u32_be(bytes.subspan(1, 4)));
    }

    auto synced = CodecResult<bool>::success(true);
    const bool steady_state_one_rtt_receive = can_skip_steady_state_receive_sync(
        status_, peer_transport_parameters_validated_, application_space_.read_secret,
        application_space_.write_secret, resumption_state_emitted_, peer_preferred_address_emitted_,
        peer_transport_parameters_, qlog_session_.get(), bytes);
    if (!steady_state_one_rtt_receive) {
        if (send_profile_enabled()) {
            ++send_profile_counters().inbound_initial_sync_tls_calls;
        }
        SendProfileTimer sync_timer(send_profile_counters().inbound_initial_sync_tls_ns);
        synced = sync_tls_state();
    } else if (send_profile_enabled()) {
        ++send_profile_counters().inbound_initial_sync_tls_skipped;
    }
    if (!synced.has_value()) {
        log_codec_failure("sync_tls_state", synced.error());
        queue_transport_close_for_error(now, synced.error());
        return;
    }
    setup_timer.stop();

    const auto defer_packet =
        [&](std::span<const std::byte> packet_bytes, QuicPathId deferred_path_id,
            std::optional<std::uint32_t> deferred_datagram_id, QuicEcnCodepoint deferred_ecn) {
            queue_deferred_protected_datagram(deferred_protected_packets_, packet_bytes,
                                              deferred_path_id, deferred_datagram_id, deferred_ecn);
        };
    std::size_t offset = 0;
    bool processed_any_packet = false;
    const auto make_deserialize_context =
        [&](const std::optional<TrafficSecret> &application_secret,
            bool application_key_phase) -> CodecResult<DeserializeProtectionContext> {
        if (send_profile_enabled()) {
            ++send_profile_counters().make_deserialize_context_calls;
        }
        SendProfileTimer make_context_timer(send_profile_counters().make_deserialize_context_ns);
        const auto handshake_ready = prime_traffic_secret_cache(handshake_space_.read_secret);
        if (!handshake_ready.has_value()) {
            return CodecResult<DeserializeProtectionContext>::failure(
                handshake_ready.error().code, handshake_ready.error().offset);
        }

        const auto zero_rtt_ready = prime_traffic_secret_cache(zero_rtt_space_.read_secret);
        if (!zero_rtt_ready.has_value()) {
            return CodecResult<DeserializeProtectionContext>::failure(
                zero_rtt_ready.error().code, zero_rtt_ready.error().offset);
        }

        const auto one_rtt_ready = prime_traffic_secret_cache(application_secret);
        if (!one_rtt_ready.has_value()) {
            return CodecResult<DeserializeProtectionContext>::failure(one_rtt_ready.error().code,
                                                                      one_rtt_ready.error().offset);
        }

        return CodecResult<DeserializeProtectionContext>::success(DeserializeProtectionContext{
            .peer_role = opposite_role(config_.role),
            .client_initial_destination_connection_id = client_initial_destination_connection_id(),
            .handshake_secret = handshake_space_.read_secret,
            .zero_rtt_secret = zero_rtt_space_.read_secret,
            .one_rtt_secret = application_secret,
            .one_rtt_secret_cache_primed = traffic_secret_cache_is_primed(application_secret),
            .one_rtt_key_phase = application_key_phase,
            .largest_authenticated_initial_packet_number =
                initial_space_.largest_authenticated_packet_number,
            .largest_authenticated_handshake_packet_number =
                handshake_space_.largest_authenticated_packet_number,
            .largest_authenticated_application_packet_number =
                application_space_.largest_authenticated_packet_number,
            .one_rtt_destination_connection_id_length = config_.source_connection_id.size(),
        });
    };
    const auto make_short_header_deserialize_context =
        [&](const std::optional<TrafficSecret> &application_secret,
            bool application_key_phase) -> CodecResult<DeserializeProtectionContext> {
        if (send_profile_enabled()) {
            ++send_profile_counters().make_deserialize_context_calls;
        }
        SendProfileTimer make_context_timer(send_profile_counters().make_deserialize_context_ns);
        const auto one_rtt_ready = prime_traffic_secret_cache(application_secret);
        if (!one_rtt_ready.has_value()) {
            return CodecResult<DeserializeProtectionContext>::failure(one_rtt_ready.error().code,
                                                                      one_rtt_ready.error().offset);
        }

        return CodecResult<DeserializeProtectionContext>::success(DeserializeProtectionContext{
            .peer_role = opposite_role(config_.role),
            .one_rtt_secret_ref =
                application_secret.has_value() ? &application_secret.value() : nullptr,
            .one_rtt_secret_cache_primed = traffic_secret_cache_is_primed(application_secret),
            .one_rtt_key_phase = application_key_phase,
            .largest_authenticated_application_packet_number =
                application_space_.largest_authenticated_packet_number,
            .one_rtt_destination_connection_id_length = config_.source_connection_id.size(),
        });
    };
    struct PacketProcessingLabels {
        std::string_view deserialize;
        std::string_view process;
    };
    const auto process_packet_bytes_with =
        [&](std::span<const std::byte> packet_bytes, bool allow_defer, QuicPathId packet_path_id,
            QuicEcnCodepoint packet_ecn, std::optional<std::uint32_t> datagram_id,
            bool packet_replay_trigger, auto deserialize_packets, auto process_packet,
            auto emit_qlog_event, PacketProcessingLabels labels) -> bool {
        if (send_profile_enabled()) {
            ++send_profile_counters().packet_bytes_calls;
        }
        SendProfileTimer packet_bytes_timer(send_profile_counters().packet_bytes_ns);
        const auto fail_with_codec_error = [&](std::string_view label, const auto &error) -> bool {
            log_codec_failure(label, error);
            queue_transport_close_for_error(now, error);
            return false;
        };
        const bool short_header_packet =
            (std::to_integer<std::uint8_t>(packet_bytes.front()) & 0x80u) == 0;
        if (defer_short_header_packet_before_server_handshake_complete(
                allow_defer, short_header_packet, config_.role, status_,
                deferred_protected_packets_, packet_bytes, packet_path_id, datagram_id,
                packet_ecn)) {
            return true;
        }

        const auto current_context =
            short_header_packet ? make_short_header_deserialize_context(
                                      application_space_.read_secret, application_read_key_phase_)
                                : make_deserialize_context(application_space_.read_secret,
                                                           application_read_key_phase_);
        if (!current_context.has_value()) {
            return fail_with_codec_error("expand_traffic_secret", current_context.error());
        }

        const auto timed_deserialize = [&](const DeserializeProtectionContext &context) {
            if (send_profile_enabled()) {
                ++send_profile_counters().deserialize_attempts;
            }
            SendProfileTimer deserialize_timer(send_profile_counters().deserialize_ns);
            return deserialize_packets(packet_bytes, context);
        };
        if (send_profile_enabled()) {
            ++send_profile_counters().inbound_packets;
        }
        auto packets = timed_deserialize(current_context.value());
        bool used_previous_application_read_secret = false;
        bool processed_current_read_phase_packet = false;
        if (!packets.has_value()) {
            if (short_header_packet && previous_application_read_secret_.has_value()) {
                const auto previous_context = make_short_header_deserialize_context(
                    previous_application_read_secret_, previous_application_read_key_phase_);
                if (!previous_context.has_value()) {
                    log_codec_failure("expand_traffic_secret", previous_context.error());
                    queue_transport_close_for_error(now, previous_context.error());
                    return false;
                }

                auto previous_packets = timed_deserialize(previous_context.value());
                if (previous_packets.has_value()) {
                    packets = std::move(previous_packets);
                    used_previous_application_read_secret = true;
                }
            }
        }
        if (!packets.has_value()) {
            bool retry_with_next_key_phase = false;
            if (short_header_packet && application_space_.read_secret.has_value() &&
                application_space_.write_secret.has_value()) {
                retry_with_next_key_phase =
                    can_retry_short_header_with_next_key_phase(packets.error().code);
            }
            if (retry_with_next_key_phase) {
                const auto next_read_secret =
                    derive_next_traffic_secret(*application_space_.read_secret).value();
                const auto next_read_secret_optional =
                    std::optional<TrafficSecret>{next_read_secret};
                const auto next_context = make_short_header_deserialize_context(
                    next_read_secret_optional, !application_read_key_phase_);
                if (!next_context.has_value()) {
                    return fail_with_codec_error("expand_traffic_secret", next_context.error());
                }

                auto updated_packets = timed_deserialize(next_context.value());
                if (updated_packets.has_value()) {
                    const auto next_write_secret =
                        derive_next_traffic_secret(*application_space_.write_secret);
                    if (!next_write_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret", next_write_secret.error());
                        queue_transport_close_for_error(now, next_write_secret.error());
                        return false;
                    }

                    application_space_.read_secret = next_read_secret;
                    application_space_.write_secret = next_write_secret.value();
                    application_read_key_phase_ = !application_read_key_phase_;
                    application_write_key_phase_ = !application_write_key_phase_;
                    current_write_phase_first_packet_number_ = std::nullopt;
                    if (!local_key_update_initiated_) {
                        local_key_update_requested_ = false;
                    }
                    packets = std::move(updated_packets);
                }
            }
        }
        if (!packets.has_value()) {
            if (packets.error().code == CodecErrorCode::missing_crypto_context) {
                if (packet_targets_discarded_long_header_space(packet_bytes)) {
                    return true;
                }
                // Later packets in the same datagram can depend on keys unlocked by an earlier
                // packet, so buffer them even after partial progress.
                defer_packet(packet_bytes, packet_path_id, datagram_id, packet_ecn);
                return true;
            }

            bool should_discard_packet = false;
            if (short_header_packet) {
                should_discard_packet =
                    is_discardable_short_header_packet_error(packets.error().code);
            }
            if (!should_discard_packet) {
                should_discard_packet = coquic::quic::should_discard_corrupted_long_header_packet(
                    short_header_packet, packets.error().code);
            }
            if (should_discard_packet) {
                if (packet_trace_matches_connection(config_.source_connection_id)) {
                    std::cerr << "quic-packet-trace discard scid="
                              << format_connection_id_hex(config_.source_connection_id)
                              << " size=" << packet_bytes.size()
                              << " code=" << static_cast<int>(packets.error().code) << '\n';
                }
                return true;
            }
            if (processed_any_packet) {
                return true;
            }
            log_codec_failure(labels.deserialize, packets.error());
            queue_transport_close_for_error(now, packets.error());
            return false;
        }

        const auto process_decoded_packet = [&](const auto &packet) -> bool {
            if (send_profile_enabled()) {
                ++send_profile_counters().process_decoded_packet_calls;
            }
            SendProfileTimer decoded_packet_timer(
                send_profile_counters().process_decoded_packet_ns);
            bool defer_protected_app_packet = false;
            {
                if (send_profile_enabled()) {
                    ++send_profile_counters().defer_decision_calls;
                }
                SendProfileTimer defer_timer(send_profile_counters().defer_decision_ns);
                defer_protected_app_packet = should_defer_decoded_protected_packet(
                    allow_defer, packet, config_.role, status_);
            }
            if (defer_protected_app_packet) {
                defer_packet(packet_bytes, packet_path_id, datagram_id, packet_ecn);
                return true;
            }

            {
                if (send_profile_enabled()) {
                    ++send_profile_counters().qlog_emit_calls;
                }
                SendProfileTimer qlog_timer(send_profile_counters().qlog_emit_ns);
                emit_qlog_event(packet);
            }
            CodecResult<bool> processed =
                CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            {
                SendProfileTimer process_timer(send_profile_counters().process_packet_ns);
                processed = process_packet(packet, now, packet_ecn);
            }
            if (!processed.has_value()) {
                const auto traced_packet_number = protected_one_rtt_packet_number_for_trace(packet);
                if (traced_packet_number.has_value() &&
                    packet_trace_matches_connection(config_.source_connection_id)) {
                    std::cerr << "quic-packet-trace fail scid="
                              << format_connection_id_hex(config_.source_connection_id)
                              << " pn=" << *traced_packet_number
                              << " code=" << static_cast<int>(processed.error().code) << '\n';
                }
                if (processed_any_packet) {
                    return true;
                }
                log_codec_failure(labels.process, processed.error());
                queue_transport_close_for_error(now, processed.error());
                return false;
            }
            if (protected_one_rtt_packet_number_for_trace(packet).has_value() &&
                !used_previous_application_read_secret) {
                processed_current_read_phase_packet = true;
            }

            if (packet_can_advance_tls_state(packet)) {
                if (send_profile_enabled()) {
                    ++send_profile_counters().inbound_post_process_sync_tls_calls;
                }
                SendProfileTimer sync_timer(
                    send_profile_counters().inbound_post_process_sync_tls_ns);
                synced = sync_tls_state();
            } else if (send_profile_enabled()) {
                ++send_profile_counters().inbound_post_process_sync_tls_skipped;
            }
            if (!synced.has_value()) {
                log_codec_failure("sync_tls_state", synced.error());
                queue_transport_close_for_error(now, synced.error());
                return false;
            }
            return true;
        };

        if constexpr (requires { packets.value().begin(); }) {
            for (const auto &packet : packets.value()) {
                if (!process_decoded_packet(packet)) {
                    return false;
                }
            }
        } else {
            if (!process_decoded_packet(packets.value())) {
                return false;
            }
        }

        if (processed_current_read_phase_packet) {
            previous_application_read_secret_ = std::nullopt;
        }

        return true;
    };
    const auto process_packet_bytes = [&](std::span<const std::byte> packet_bytes, bool allow_defer,
                                          QuicPathId packet_path_id, QuicEcnCodepoint packet_ecn,
                                          std::optional<std::uint32_t> datagram_id,
                                          bool packet_replay_trigger) -> bool {
        if (qlog_session_ != nullptr) {
            const auto emit_qlog_event = [&](const ProtectedPacket &packet) {
                if (!datagram_id.has_value()) {
                    return;
                }

                static_cast<void>(qlog_session_->write_event(
                    now, "quic:packet_received",
                    qlog::serialize_packet_snapshot(make_qlog_packet_snapshot(
                        packet, qlog::PacketSnapshotContext{
                                    .raw_length = packet_bytes.size(),
                                    .datagram_id = *datagram_id,
                                    .trigger = packet_replay_trigger
                                                   ? std::optional<std::string>("keys_available")
                                                   : std::nullopt,
                                }))));
            };
            return process_packet_bytes_with(
                packet_bytes, allow_defer, packet_path_id, packet_ecn, datagram_id,
                packet_replay_trigger,
                [](std::span<const std::byte> bytes, const DeserializeProtectionContext &context) {
                    return deserialize_protected_datagram(bytes, context);
                },
                [this](const ProtectedPacket &packet, QuicCoreTimePoint packet_now,
                       QuicEcnCodepoint packet_ecn_value) {
                    return process_inbound_packet(packet, packet_now, packet_ecn_value);
                },
                emit_qlog_event,
                PacketProcessingLabels{
                    .deserialize = "deserialize_protected_datagram",
                    .process = "process_inbound_packet",
                });
        }

        const auto packet_storage_range =
            [&]() -> std::optional<std::pair<std::size_t, std::size_t>> {
            if (send_profile_enabled()) {
                ++send_profile_counters().packet_storage_range_checks;
            }
            SendProfileTimer storage_range_timer(send_profile_counters().packet_storage_range_ns);
            if (!inbound_packet_storage_range_is_eligible(allow_in_place_receive_decode,
                                                          previous_application_read_secret_,
                                                          status_, storage, packet_bytes)) {
                return std::nullopt;
            }
            const auto storage_begin = reinterpret_cast<std::uintptr_t>(storage->data());
            const auto storage_end = storage_begin + storage->size();
            auto packet_begin_address = reinterpret_cast<std::uintptr_t>(packet_bytes.data());
            if (connection_drain_test_hooks().force_storage_range_before_storage) {
                packet_begin_address =
                    storage_begin - static_cast<std::uintptr_t>(storage_begin != 0);
            } else if (connection_drain_test_hooks().force_storage_range_overflow) {
                packet_begin_address = storage_end;
            }
            if (!packet_bytes_start_inside_storage(packet_begin_address, storage_begin,
                                                   storage_end)) {
                return std::nullopt;
            }
            const auto packet_begin =
                static_cast<std::size_t>(packet_begin_address - storage_begin);
            if (packet_bytes.size() > storage->size() - packet_begin) {
                return std::nullopt;
            }
            return std::pair<std::size_t, std::size_t>{
                packet_begin,
                packet_begin + packet_bytes.size(),
            };
        }();
        return process_packet_bytes_with(
            packet_bytes, allow_defer, packet_path_id, packet_ecn, datagram_id,
            packet_replay_trigger,
            [&](std::span<const std::byte> bytes, const DeserializeProtectionContext &context) {
                if (packet_storage_range.has_value()) {
                    return deserialize_received_protected_packet(
                        storage, packet_storage_range->first, packet_storage_range->second,
                        context);
                }
                return deserialize_received_protected_packet(bytes, context);
            },
            [this](const ReceivedProtectedPacket &packet, QuicCoreTimePoint packet_now,
                   QuicEcnCodepoint packet_ecn_value) {
                return process_inbound_received_packet(packet, packet_now, packet_ecn_value);
            },
            [](const ReceivedProtectedPacket &) {},
            PacketProcessingLabels{
                .deserialize = "deserialize_received_protected_datagram",
                .process = "process_inbound_received_packet",
            });
    };
    const auto replay_deferred_packets = [&]() -> bool {
        if (send_profile_enabled()) {
            ++send_profile_counters().inbound_replay_deferred_calls;
        }
        SendProfileTimer replay_timer(send_profile_counters().inbound_replay_deferred_ns);
        if (consume_connection_drain_countdown(
                &ConnectionDrainTestHooks::force_replay_deferred_packets_failure_countdown)) {
            return false;
        }
        if (deferred_protected_packets_.empty()) {
            return true;
        }

        auto deferred_packets = std::move(deferred_protected_packets_);
        deferred_protected_packets_.clear();
        for (const auto &deferred_packet : deferred_packets) {
            if (!process_packet_bytes(deferred_packet.bytes, /*allow_defer=*/true,
                                      deferred_packet.path_id, deferred_packet.ecn,
                                      deferred_packet.datagram_id,
                                      /*packet_replay_trigger=*/true)) {
                return false;
            }
        }

        return true;
    };
    if (!replay_deferred_packets()) {
        return;
    }
    SendProfileTimer packet_loop_timer(send_profile_counters().packet_loop_ns);
    while (offset < bytes.size()) {
        if (send_profile_enabled()) {
            ++send_profile_counters().packet_length_peeks;
        }
        CodecResult<std::size_t> packet_length =
            CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
        {
            SendProfileTimer packet_length_timer(send_profile_counters().packet_length_peek_ns);
            packet_length = peek_next_packet_length(bytes.subspan(offset));
        }
        if (!packet_length.has_value()) {
            if (packet_length.error().code == CodecErrorCode::invalid_fixed_bit) {
                const auto discardable_length =
                    peek_discardable_long_header_packet_length(bytes.subspan(offset));
                if (discardable_length.has_value()) {
                    offset += discardable_length.value();
                    continue;
                }
            }
            if (is_discardable_packet_length_error(packet_length.error().code)) {
                return;
            }
            if (processed_any_packet) {
                return;
            }
            log_codec_failure("peek_next_packet_length", packet_length.error());
            queue_transport_close_for_error(now, packet_length.error());
            return;
        }

        const auto packet_bytes = bytes.subspan(offset, packet_length.value());
        if (!process_packet_bytes(packet_bytes, /*allow_defer=*/true, path_id, ecn,
                                  inbound_datagram_id, replay_trigger)) {
            return;
        }
        processed_any_packet = true;
        if (!replay_deferred_packets()) {
            return;
        }

        offset += packet_length.value();
    }
}

StreamStateResult<bool>
QuicConnection::queue_stream_send_impl(std::uint64_t stream_id,
                                       std::span<const std::byte> owned_bytes,
                                       std::optional<SharedBytes> shared_bytes, bool fin) {
    if (status_ == HandshakeStatus::failed ||
        (owned_bytes.empty() && (!shared_bytes.has_value() || shared_bytes->empty()) && !fin)) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_or_open_send_stream(stream_id);
    if (!stream_state.has_value()) {
        const auto id_info = classify_stream_id(stream_id, config_.role);
        return StreamStateResult<bool>::failure(
            id_info.local_can_send ? StreamStateErrorCode::invalid_stream_id
                                   : StreamStateErrorCode::invalid_stream_direction,
            stream_id);
    }

    auto *stream = stream_state.value();
    const auto validated = stream->validate_local_send(fin);
    if (!validated.has_value()) {
        return validated;
    }

    if (shared_bytes.has_value() && !shared_bytes->empty()) {
        stream->send_buffer.append(*shared_bytes);
        stream->send_flow_control_committed += static_cast<std::uint64_t>(shared_bytes->size());
    } else if (!owned_bytes.empty()) {
        stream->send_buffer.append(owned_bytes);
        stream->send_flow_control_committed += static_cast<std::uint64_t>(owned_bytes.size());
    }

    if (fin) {
        stream->send_final_size = stream->send_flow_control_committed;
        stream->send_fin_state = StreamSendFinState::pending;
    }

    const bool should_emit_zero_rtt_attempt =
        (config_.role == EndpointRole::client) & config_.zero_rtt.attempt &
        decoded_resumption_state_.has_value() & zero_rtt_space_.write_secret.has_value() &
        (status_ != HandshakeStatus::connected) & !zero_rtt_attempted_event_emitted_;
    if (should_emit_zero_rtt_attempt) {
        pending_zero_rtt_status_event_ =
            QuicCoreZeroRttStatusEvent{.status = QuicZeroRttStatus::attempted};
        zero_rtt_attempted_event_emitted_ = true;
    }

    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> QuicConnection::queue_stream_send(std::uint64_t stream_id,
                                                          std::span<const std::byte> bytes,
                                                          bool fin) {
    return queue_stream_send_impl(stream_id, bytes, std::nullopt, fin);
}

StreamStateResult<bool> QuicConnection::queue_stream_send_shared(std::uint64_t stream_id,
                                                                 SharedBytes bytes, bool fin) {
    return queue_stream_send_impl(stream_id, {}, std::move(bytes), fin);
}

StreamStateResult<bool> QuicConnection::queue_stream_reset(LocalResetCommand command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_or_open_send_stream(command.stream_id);
    if (!stream_state.has_value()) {
        const auto id_info = classify_stream_id(command.stream_id, config_.role);
        return StreamStateResult<bool>::failure(
            id_info.local_can_send ? StreamStateErrorCode::invalid_stream_id
                                   : StreamStateErrorCode::invalid_stream_direction,
            command.stream_id);
    }

    auto *stream = stream_state.value();
    const auto validated = stream->validate_local_reset(command.application_error_code);
    if (!validated.has_value()) {
        return validated;
    }

    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> QuicConnection::queue_stop_sending(LocalStopSendingCommand command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_existing_receive_stream(command.stream_id);
    if (!stream_state.has_value()) {
        return StreamStateResult<bool>::failure(stream_state.error().code,
                                                stream_state.error().stream_id);
    }

    auto *stream = stream_state.value();
    const auto validated = stream->validate_local_stop_sending(command.application_error_code);
    if (!validated.has_value()) {
        return validated;
    }

    return StreamStateResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::request_connection_migration(QuicPathId path_id,
                                                               QuicMigrationRequestReason reason,
                                                               QuicCoreTimePoint now) {
    const bool peer_disables_active_migration =
        peer_transport_parameters_.has_value() &&
        peer_transport_parameters_->disable_active_migration;
    if (reason == QuicMigrationRequestReason::active && peer_disables_active_migration) {
        return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
    }
    if (reason == QuicMigrationRequestReason::active && !can_initiate_path_validation(path_id)) {
        return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
    }

    maybe_switch_to_path(path_id, /*initiated_locally=*/true, now);
    if (reason == QuicMigrationRequestReason::preferred_address &&
        peer_transport_parameters_.has_value() &&
        peer_transport_parameters_->preferred_address.has_value()) {
        const auto &preferred_address = peer_transport_parameters_->preferred_address.value();
        ensure_path_state(path_id).destination_connection_id_override =
            preferred_address.connection_id;
    }
    return CodecResult<bool>::success(true);
}

StreamStateResult<bool>
QuicConnection::queue_application_close(LocalApplicationCloseCommand command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    pending_application_close_ = ApplicationConnectionCloseFrame{
        .error_code = command.application_error_code,
        .reason =
            ConnectionCloseReason{
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte *>(command.reason_phrase.data()),
                    reinterpret_cast<const std::byte *>(command.reason_phrase.data()) +
                        command.reason_phrase.size()),
            },
    };
    local_application_close_sent_ = false;
    return StreamStateResult<bool>::success(true);
}

void QuicConnection::queue_new_token(std::vector<std::byte> token) {
    if (status_ == HandshakeStatus::failed || token.empty()) {
        return;
    }

    pending_new_token_frames_.push_back(NewTokenFrame{
        .token = std::move(token),
    });
}

void QuicConnection::request_key_update() {
    local_key_update_requested_ = true;
    if (!local_key_update_initiated_) {
        current_write_phase_first_packet_number_ = application_space_.next_send_packet_number;
    }
}

DatagramBuffer QuicConnection::drain_outbound_datagram(QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed && close_mode_ != QuicConnectionCloseMode::closing) {
        return {};
    }
    last_drained_path_id_.reset();
    last_drained_ecn_codepoint_ = QuicEcnCodepoint::not_ect;
    last_drained_is_pmtu_probe_ = false;
    last_drained_packet_inspection_datagram_id_ = 0;

    if (close_mode_ == QuicConnectionCloseMode::closing) {
        if (!closing_close_packet_can_send(closing_close_packet_pending_,
                                           can_send_connection_close_frame())) {
            return {};
        }
        return flush_outbound_datagram(now);
    }

    auto synced = CodecResult<bool>::success(true);
    if (!can_skip_outbound_tls_sync()) {
        if (send_profile_enabled()) {
            ++send_profile_counters().outbound_sync_tls_calls;
        }
        SendProfileTimer sync_timer(send_profile_counters().outbound_sync_tls_ns);
        synced = sync_tls_state();
    } else if (send_profile_enabled()) {
        ++send_profile_counters().outbound_sync_tls_skipped;
    }
    if (!synced.has_value()) {
        log_codec_failure("sync_tls_state", synced.error());
        queue_transport_close_for_error(now, synced.error());
        return {};
    }

    if (!deferred_protected_packets_.empty()) {
        replay_deferred_protected_packets(now);
        if (status_ == HandshakeStatus::failed) {
            return {};
        }
    }

    auto datagram = flush_outbound_datagram(now);
    return datagram;
}

void QuicConnection::on_timeout(QuicCoreTimePoint now) {
    if (close_state_active()) {
        if (!close_deadline_.has_value()) {
            return;
        }
        if (now >= *close_deadline_) {
            pending_terminal_state_ = pending_connection_close_terminal_state_.value_or(
                QuicConnectionTerminalState::closed);
            close_mode_ = QuicConnectionCloseMode::none;
            close_started_at_.reset();
            close_deadline_.reset();
            closing_transport_close_.reset();
            closing_application_close_.reset();
            pending_transport_close_.reset();
            pending_application_close_.reset();
            pending_connection_close_terminal_state_.reset();
            closing_close_packet_pending_ = false;
            return;
        }
    }

    if (status_ == HandshakeStatus::failed) {
        return;
    }

    if (const auto idle_deadline = idle_timeout_deadline();
        idle_deadline.has_value() && now >= *idle_deadline) {
        mark_silent_close();
        return;
    }

    maybe_discard_server_zero_rtt_packet_space(now);

    if (current_send_path_id_.has_value() &&
        path_validation_timed_out(*current_send_path_id_, now) &&
        last_validated_path_id_.has_value()) {
        auto &current = paths_.at(*current_send_path_id_);
        current.is_current_send_path = false;
        current.challenge_pending = false;
        current.validation_initiated_locally = false;
        current.outstanding_challenge.reset();
        current.validation_deadline.reset();
        previous_path_id_ = current_send_path_id_;
        current_send_path_id_ = last_validated_path_id_;
        ensure_path_state(*last_validated_path_id_).is_current_send_path = true;
    }

    if (const auto deadline = loss_deadline(); deadline.has_value() && now >= *deadline) {
        detect_lost_packets(now);
    }

    const auto initial_ack_deadline =
        initial_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (!initial_packet_space_discarded_ && now >= initial_ack_deadline) {
        initial_space_.force_ack_send = true;
    }
    const auto handshake_ack_deadline =
        handshake_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (!handshake_packet_space_discarded_ && now >= handshake_ack_deadline) {
        handshake_space_.force_ack_send = true;
    }
    const auto application_ack_deadline =
        application_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (now >= application_ack_deadline) {
        application_space_.force_ack_send = true;
    }

    if (const auto deadline = pmtud_deadline(); pmtud_deadline_due(deadline, now)) {
        maybe_trace_pmtud_timeout(config_.source_connection_id);
        maybe_arm_pmtu_probe(now);
    }

    if (const auto deadline = pto_deadline(); deadline.has_value() && now >= *deadline) {
        arm_pto_probe(now);
        if (packet_trace_matches_connection(config_.source_connection_id)) {
            const auto in_flight_ack_eliciting_count = [](const PacketSpaceState &packet_space) {
                const auto handles = packet_space.recovery.tracked_packets();
                return std::count_if(
                    handles.begin(), handles.end(), [&](const RecoveryPacketHandle handle) {
                        const auto &packet = *packet_space.recovery.packet_for_handle(handle);
                        return packet.ack_eliciting & packet.in_flight;
                    });
            };
            std::cerr << "quic-packet-trace timeout scid="
                      << format_connection_id_hex(config_.source_connection_id)
                      << " status=" << static_cast<int>(status_)
                      << " confirmed=" << static_cast<int>(handshake_confirmed_)
                      << " initial_if=" << in_flight_ack_eliciting_count(initial_space_)
                      << " handshake_if=" << in_flight_ack_eliciting_count(handshake_space_)
                      << " application_if=" << in_flight_ack_eliciting_count(application_space_)
                      << " initial_probe="
                      << static_cast<int>(initial_space_.pending_probe_packet.has_value())
                      << " handshake_probe="
                      << static_cast<int>(handshake_space_.pending_probe_packet.has_value())
                      << " application_probe="
                      << static_cast<int>(application_space_.pending_probe_packet.has_value())
                      << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                      << " pto_count=" << pto_count_ << '\n';
        }
    }
}

std::optional<QuicCoreReceiveStreamData> QuicConnection::take_received_stream_data() {
    if (status_ == HandshakeStatus::failed || pending_stream_receive_effects_.empty()) {
        return std::nullopt;
    }

    auto next = std::move(pending_stream_receive_effects_.front());
    pending_stream_receive_effects_.pop_front();
    maybe_retire_stream(next.stream_id);
    return next;
}

std::optional<QuicCorePeerResetStream> QuicConnection::take_peer_reset_stream() {
    if (status_ == HandshakeStatus::failed || pending_peer_reset_effects_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_peer_reset_effects_.front();
    pending_peer_reset_effects_.pop_front();
    return next;
}

std::optional<QuicCorePeerStopSending> QuicConnection::take_peer_stop_sending() {
    if (status_ == HandshakeStatus::failed || pending_peer_stop_effects_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_peer_stop_effects_.front();
    pending_peer_stop_effects_.pop_front();
    return next;
}

std::optional<QuicCoreStateChange> QuicConnection::take_state_change() {
    if (pending_state_changes_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_state_changes_.front();
    pending_state_changes_.pop_front();
    return next;
}

std::optional<QuicCorePeerPreferredAddressAvailable>
QuicConnection::take_peer_preferred_address_available() {
    auto next = pending_preferred_address_effect_;
    pending_preferred_address_effect_.reset();
    return next;
}

std::optional<QuicCoreResumptionStateAvailable> QuicConnection::take_resumption_state_available() {
    auto next = std::move(pending_resumption_state_effect_);
    pending_resumption_state_effect_.reset();
    return next;
}

std::optional<QuicCoreZeroRttStatusEvent> QuicConnection::take_zero_rtt_status_event() {
    auto next = pending_zero_rtt_status_event_;
    pending_zero_rtt_status_event_.reset();
    return next;
}

std::optional<QuicConnectionTerminalState> QuicConnection::take_terminal_state() {
    if (!pending_terminal_state_.has_value()) {
        return std::nullopt;
    }

    const auto next = pending_terminal_state_;
    pending_terminal_state_.reset();
    return next;
}

std::optional<QuicCorePacketInspection> QuicConnection::take_packet_inspection() {
    if (pending_packet_inspections_.empty()) {
        return std::nullopt;
    }

    auto next = std::move(pending_packet_inspections_.front());
    pending_packet_inspections_.pop_front();
    return next;
}

std::optional<std::vector<std::byte>> QuicConnection::take_new_token() {
    if (pending_received_new_tokens_.empty()) {
        return std::nullopt;
    }

    auto token = std::move(pending_received_new_tokens_.front());
    pending_received_new_tokens_.pop_front();
    return token;
}

std::optional<QuicPathId> QuicConnection::last_drained_path_id() const {
    return last_drained_path_id_;
}

QuicEcnCodepoint QuicConnection::last_drained_ecn_codepoint() const {
    return last_drained_ecn_codepoint_;
}

bool QuicConnection::last_drained_is_pmtu_probe() const {
    return last_drained_is_pmtu_probe_;
}

std::uint64_t QuicConnection::last_drained_packet_inspection_datagram_id() const {
    return last_drained_packet_inspection_datagram_id_;
}

std::size_t
QuicConnection::queue_outbound_packet_inspections(const SerializedProtectedDatagram &datagram,
                                                  std::uint64_t datagram_id) {
    if (!config_.enable_packet_inspection) {
        return 0;
    }

    const auto starting_count = pending_packet_inspections_.size();
    DeserializeProtectionContext context{
        .peer_role = config_.role,
        .client_initial_destination_connection_id = client_initial_destination_connection_id(),
        .handshake_secret = handshake_space_.write_secret,
        .zero_rtt_secret = zero_rtt_space_.write_secret,
        .one_rtt_secret = application_space_.write_secret,
        .one_rtt_key_phase = application_write_key_phase_,
        .largest_authenticated_initial_packet_number =
            initial_space_.largest_authenticated_packet_number,
        .largest_authenticated_handshake_packet_number =
            handshake_space_.largest_authenticated_packet_number,
        .largest_authenticated_application_packet_number =
            application_space_.largest_authenticated_packet_number,
        .one_rtt_destination_connection_id_length = outbound_destination_connection_id().size(),
    };

    for (const auto &metadata : datagram.packet_metadata) {
        if (metadata.offset > datagram.bytes.size() ||
            metadata.length > datagram.bytes.size() - metadata.offset) {
            continue;
        }

        const auto packet_bytes = datagram.bytes.span().subspan(metadata.offset, metadata.length);
        auto decoded = deserialize_received_protected_packet(packet_bytes, context);
        if (!decoded.has_value()) {
            continue;
        }
        if (connection_drain_test_hooks().force_packet_inspection_missing_plaintext_storage) {
            std::visit(PacketInspectionPlaintextStorageResetVisitor{}, decoded.value());
        }

        QuicCorePacketInspection inspection{
            .direction = QuicCorePacketInspectionDirection::outbound,
            .datagram_id = datagram_id,
            .datagram_length = datagram.bytes.size(),
            .datagram_offset = metadata.offset,
            .packet_length = metadata.length,
            .encrypted_packet = std::vector<std::byte>(packet_bytes.begin(), packet_bytes.end()),
        };

        std::visit(PacketInspectionPopulateVisitor{inspection}, decoded.value());

        pending_packet_inspections_.push_back(std::move(inspection));
    }
    return pending_packet_inspections_.size() - starting_count;
}

bool QuicConnection::has_sendable_datagram(QuicCoreTimePoint now) const {
    if (close_mode_ == QuicConnectionCloseMode::draining) {
        return false;
    }
    if (close_mode_ == QuicConnectionCloseMode::closing) {
        static_cast<void>(now);
        return closing_close_packet_can_send(closing_close_packet_pending_,
                                             can_send_connection_close_frame());
    }
    if (status_ == HandshakeStatus::failed || !deferred_protected_packets_.empty()) {
        return status_ != HandshakeStatus::failed;
    }
    if (current_send_path_id_.has_value()) {
        const auto path = paths_.find(*current_send_path_id_);
        if (path != paths_.end()) {
            if (!path->second.mtu.viable) {
                return false;
            }
        }
    }
    if (!initial_packet_space_discarded_ &&
        initial_packet_space_has_sendable_data(initial_space_, now)) {
        return true;
    }
    if (!handshake_packet_space_discarded_ &&
        handshake_packet_space_has_sendable_data(handshake_space_, now)) {
        return true;
    }

    if (!can_send_application_packets(config_.role, status_, zero_rtt_space_, application_space_)) {
        return false;
    }
    const bool application_ack_due = application_ack_due_for_send(application_space_, now);
    return application_space_has_sendable_data(
        application_ack_due, has_pending_application_send(), application_space_,
        !pending_new_token_frames_.empty(), !pending_new_connection_id_frames_.empty(),
        !pending_retire_connection_id_frames_.empty());
}

std::optional<QuicCoreTimePoint> QuicConnection::next_wakeup() const {
    if (status_ == HandshakeStatus::failed && close_mode_ != QuicConnectionCloseMode::closing &&
        close_mode_ != QuicConnectionCloseMode::draining) {
        return std::nullopt;
    }
    if (close_mode_ == QuicConnectionCloseMode::closing ||
        close_mode_ == QuicConnectionCloseMode::draining) {
        return close_deadline_;
    }

    const auto pacing_deadline =
        has_pending_congestion_controlled_send()
            ? congestion_controller_.next_send_time(outbound_datagram_size_limit())
            : std::nullopt;

    return earliest_of({loss_deadline(), pto_deadline(), ack_deadline(), pmtud_deadline(),
                        zero_rtt_discard_deadline(), pacing_deadline, idle_timeout_deadline()});
}

std::vector<ConnectionId> QuicConnection::active_local_connection_ids() const {
    std::vector<ConnectionId> connection_ids;
    connection_ids.reserve(local_connection_ids_.size());
    for (const auto &[sequence_number, record] : local_connection_ids_) {
        static_cast<void>(sequence_number);
        if (record.retired) {
            continue;
        }
        connection_ids.push_back(record.connection_id);
    }
    return connection_ids;
}

std::vector<StatelessResetTokenRecord> QuicConnection::active_local_stateless_reset_tokens() const {
    std::vector<StatelessResetTokenRecord> tokens;
    tokens.reserve(local_connection_ids_.size());
    for (const auto &[sequence_number, record] : local_connection_ids_) {
        static_cast<void>(sequence_number);
        if (record.retired) {
            continue;
        }
        tokens.push_back(StatelessResetTokenRecord{
            .connection_id = record.connection_id,
            .stateless_reset_token = record.stateless_reset_token,
        });
    }
    return tokens;
}

std::vector<StatelessResetTokenRecord> QuicConnection::peer_stateless_reset_tokens() const {
    std::vector<StatelessResetTokenRecord> tokens;
    tokens.reserve(
        peer_connection_ids_.size() +
        static_cast<std::size_t>(peer_transport_parameters_.has_value() &&
                                 peer_transport_parameters_->stateless_reset_token.has_value()));
    if (peer_transport_parameters_.has_value() &&
        peer_transport_parameters_->stateless_reset_token.has_value()) {
        tokens.push_back(StatelessResetTokenRecord{
            .connection_id = config_.initial_destination_connection_id,
            .stateless_reset_token = *peer_transport_parameters_->stateless_reset_token,
        });
    }
    for (const auto &[sequence_number, record] : peer_connection_ids_) {
        if (record.locally_retired) {
            continue;
        }
        tokens.push_back(StatelessResetTokenRecord{
            .connection_id = record.connection_id,
            .stateless_reset_token = record.stateless_reset_token,
        });
    }
    return tokens;
}

std::optional<QuicCoreTimePoint> QuicConnection::loss_deadline() const {
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto packet_space_loss_deadline =
        [&](const PacketSpaceState &packet_space) -> std::optional<QuicCoreTimePoint> {
        if (packet_space_discarded(packet_space)) {
            return std::nullopt;
        }
        const auto tracked_packet = earliest_loss_packet(packet_space);
        if (!tracked_packet.has_value()) {
            return std::nullopt;
        }

        return compute_time_threshold_deadline(shared_rtt_state, tracked_packet->sent_time);
    };

    const auto pmtu_probe_deadline = [&]() -> std::optional<QuicCoreTimePoint> {
        std::optional<QuicCoreTimePoint> deadline;
        for (const auto &[path_id, path] : paths_) {
            static_cast<void>(path_id);
            if (!path.mtu.outstanding_probe_packet_number.has_value()) {
                continue;
            }

            const auto *packet =
                application_space_.recovery.find_packet(*path.mtu.outstanding_probe_packet_number);
            if (!pmtud_packet_deadline_candidate_is_live(packet)) {
                continue;
            }

            const auto candidate =
                compute_time_threshold_deadline(shared_rtt_state, packet->sent_time);
            deadline = earliest_deadline(deadline, candidate);
        }
        return deadline;
    };

    return earliest_of({packet_space_loss_deadline(initial_space_),
                        packet_space_loss_deadline(handshake_space_),
                        packet_space_loss_deadline(application_space_), pmtu_probe_deadline()});
}

std::optional<QuicCoreTimePoint> QuicConnection::pto_deadline() const {
    const auto application_max_ack_delay = std::chrono::milliseconds(
        peer_transport_parameters_.has_value() ? peer_transport_parameters_->max_ack_delay
                                               : TransportParameters{}.max_ack_delay);
    const auto allow_application_pto = config_.role == EndpointRole::server || handshake_confirmed_;
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto effective_pto_count = [&](const PacketSpaceState &packet_space) {
        if (config_.role != EndpointRole::client || handshake_confirmed_ ||
            &packet_space != &initial_space_) {
            return pto_count_;
        }
        return std::min(pto_count_, 2u);
    };
    const auto packet_space_pto_deadline =
        [&](const PacketSpaceState &packet_space,
            std::chrono::milliseconds max_ack_delay) -> std::optional<QuicCoreTimePoint> {
        if (packet_space_discarded(packet_space)) {
            return std::nullopt;
        }
        const auto tracked_packet = latest_in_flight_ack_eliciting_packet(packet_space);
        if (!tracked_packet.has_value()) {
            return std::nullopt;
        }

        return compute_pto_deadline(shared_rtt_state, max_ack_delay, tracked_packet->sent_time,
                                    effective_pto_count(packet_space));
    };

    const auto regular_deadline =
        earliest_of({packet_space_pto_deadline(initial_space_, std::chrono::milliseconds(0)),
                     packet_space_pto_deadline(handshake_space_, std::chrono::milliseconds(0)),
                     allow_application_pto
                         ? packet_space_pto_deadline(application_space_, application_max_ack_delay)
                         : std::nullopt});
    if (regular_deadline.has_value()) {
        return regular_deadline;
    }

    const auto client_handshake_keepalive_reference_time =
        [this]() -> std::optional<QuicCoreTimePoint> {
        const bool eligible = client_handshake_keepalive_is_eligible(
            config_.role, status_, handshake_confirmed_, last_peer_activity_time_,
            initial_packet_space_discarded_, initial_space_, handshake_packet_space_discarded_,
            handshake_space_, application_space_);
        if (!eligible) {
            return std::nullopt;
        }

        auto reference_time = last_peer_activity_time_;
        const auto probe_time =
            last_client_handshake_keepalive_probe_time_.value_or(QuicCoreTimePoint::min());
        if (probe_time > *reference_time) {
            reference_time = probe_time;
        }

        return reference_time;
    }();
    const bool client_handshake_keepalive_space_available = has_client_handshake_keepalive_space(
        client_handshake_keepalive_reference_time, initial_packet_space_discarded_,
        handshake_packet_space_discarded_, handshake_space_);
    if (!client_handshake_keepalive_space_available) {
        const auto client_receive_keepalive_reference_time =
            [this]() -> std::optional<QuicCoreTimePoint> {
            const bool has_receive_interest = std::ranges::any_of(
                streams_, [](const auto &entry) { return !stream_receive_terminal(entry.second); });
            const bool eligible = client_receive_keepalive_is_eligible(
                config_.role, handshake_confirmed_, last_peer_activity_time_, has_receive_interest,
                initial_packet_space_discarded_, initial_space_, handshake_packet_space_discarded_,
                handshake_space_, application_space_);
            if (!eligible) {
                return std::nullopt;
            }

            return last_peer_activity_time_;
        }();
        if (!client_receive_keepalive_reference_time.has_value()) {
            return std::nullopt;
        }

        return compute_pto_deadline(shared_rtt_state, application_max_ack_delay,
                                    *client_receive_keepalive_reference_time, pto_count_);
    }

    return compute_pto_deadline(shared_rtt_state, std::chrono::milliseconds(0),
                                optional_ref_or_abort(client_handshake_keepalive_reference_time),
                                std::min(pto_count_, 2u));
}

std::optional<QuicCoreTimePoint> QuicConnection::ack_deadline() const {
    return earliest_of(
        {initial_packet_space_discarded_ ? std::nullopt : initial_space_.pending_ack_deadline,
         handshake_packet_space_discarded_ ? std::nullopt : handshake_space_.pending_ack_deadline,
         application_space_.pending_ack_deadline});
}

std::chrono::milliseconds QuicConnection::path_validation_timeout_period() const {
    const auto pto_reference =
        std::max(compute_pto_deadline(shared_recovery_rtt_state(), std::chrono::milliseconds(0),
                                      QuicCoreTimePoint{}, /*pto_count=*/0) -
                     QuicCoreTimePoint{},
                 QuicCoreClock::duration::zero());
    return std::chrono::duration_cast<std::chrono::milliseconds>(pto_reference *
                                                                 kPersistentCongestionThreshold);
}

std::optional<QuicCoreTimePoint> QuicConnection::idle_timeout_deadline() const {
    const auto effective_timeout_ms =
        effective_idle_timeout_ms(local_transport_parameters_, peer_transport_parameters_);
    if (status_ == HandshakeStatus::failed) {
        return std::nullopt;
    }
    if (!idle_timeout_base_time_.has_value()) {
        return std::nullopt;
    }
    if (effective_timeout_ms == 0) {
        return std::nullopt;
    }

    auto timeout = std::chrono::milliseconds(effective_timeout_ms);
    const auto pto_reference =
        std::max(compute_pto_deadline(shared_recovery_rtt_state(), std::chrono::milliseconds(0),
                                      QuicCoreTimePoint{}, /*pto_count=*/0) -
                     QuicCoreTimePoint{},
                 QuicCoreClock::duration::zero());
    timeout = std::max(timeout, std::chrono::duration_cast<std::chrono::milliseconds>(
                                    pto_reference * kPersistentCongestionThreshold));
    return *idle_timeout_base_time_ + timeout;
}

std::optional<QuicCoreTimePoint> QuicConnection::pmtud_deadline() const {
    if (!config_.transport.pmtud_enabled || !application_space_.write_secret.has_value()) {
        return std::nullopt;
    }

    std::optional<QuicCoreTimePoint> deadline;
    for (const auto &[path_id, path] : paths_) {
        static_cast<void>(path_id);
        if (!path.mtu.next_probe_time.has_value()) {
            continue;
        }
        deadline = earliest_deadline(deadline, *path.mtu.next_probe_time);
    }
    return deadline;
}

void QuicConnection::detect_lost_packets(QuicCoreTimePoint now) {
    if (!initial_packet_space_discarded_) {
        detect_lost_packets(initial_space_, now);
    }
    if (!handshake_packet_space_discarded_) {
        detect_lost_packets(handshake_space_, now);
    }
    detect_lost_packets(application_space_, now);
}

void QuicConnection::detect_lost_packets(PacketSpaceState &packet_space, QuicCoreTimePoint now) {
    auto handles = packet_space.recovery.collect_time_threshold_losses(now);
    auto pmtu_probe_handles = packet_space.recovery.collect_pmtu_probe_timeouts(now);
    handles.insert(handles.end(), pmtu_probe_handles.begin(), pmtu_probe_handles.end());
    if (handles.empty()) {
        return;
    }

    const auto &shared_rtt_state = shared_recovery_rtt_state();

    std::vector<SentPacketRecord> lost_packets;
    lost_packets.reserve(handles.size());
    for (const auto handle : handles) {
        const auto &packet = *packet_space.recovery.packet_for_handle(handle);
        emit_qlog_packet_lost(packet, "time_threshold", now);
        if (auto lost_packet = mark_lost_packet(packet_space, handle,
                                                /*already_marked_in_recovery=*/false, now)) {
            lost_packets.push_back(*lost_packet);
        } else {
            lost_packets.push_back(packet);
        }
    }
    if (has_timer_lost_packets_for_profile(send_profile_enabled(), lost_packets)) {
        auto &profile = send_profile_counters();
        profile.timer_lost_packets += lost_packets.size();
        for (const auto &packet : lost_packets) {
            profile.timer_lost_bytes += packet.bytes_in_flight;
        }
    }
    const auto ack_eliciting_lost_packets = ack_eliciting_in_flight_losses(lost_packets);
    if (!ack_eliciting_lost_packets.empty()) {
        if (send_profile_enabled()) {
            ++send_profile_counters().loss_events;
        }
        const auto peer_max_ack_delay_ms =
            peer_transport_parameters_.value_or(TransportParameters{}).max_ack_delay;
        const auto max_ack_delay = std::chrono::milliseconds{
            peer_max_ack_delay_ms *
            static_cast<std::uint64_t>(&packet_space == &application_space_)};
        congestion_controller_.on_loss_event(now,
                                             latest_packet_sent_time(ack_eliciting_lost_packets));
        if (establishes_persistent_congestion(ack_eliciting_lost_packets, shared_rtt_state,
                                              max_ack_delay)) {
            if (send_profile_enabled()) {
                ++send_profile_counters().persistent_congestion_events;
            }
            congestion_controller_.on_persistent_congestion();
        }
    }
    maybe_emit_qlog_recovery_metrics(now);
}

void QuicConnection::maybe_arm_pmtu_probe(QuicCoreTimePoint now) {
    if (!config_.transport.pmtud_enabled || !application_space_.write_secret.has_value() ||
        !current_send_path_id_.has_value() || application_space_.pending_probe_packet.has_value()) {
        return;
    }

    auto path_it = paths_.find(*current_send_path_id_);
    if (path_it == paths_.end()) {
        return;
    }
    auto &path = path_it->second;
    if (!path.mtu.viable) {
        return;
    }
    if (path.mtu.outstanding_probe_packet_number.has_value()) {
        return;
    }
    if (path.mtu.next_probe_time.has_value() && *path.mtu.next_probe_time > now) {
        return;
    }
    path.mtu.probe_ceiling =
        std::min(path.mtu.probe_ceiling, outbound_datagram_size_ceiling_for_path(path.id));
    if (path.mtu.validated_datagram_size >= path.mtu.probe_ceiling) {
        path.mtu.next_probe_time.reset();
        return;
    }
    if (anti_amplification_applies(*current_send_path_id_)) {
        path.mtu.next_probe_time = now + std::chrono::milliseconds(100);
        return;
    }
    const auto probe_size = next_pmtu_probe_size(path);
    if (!probe_size.has_value()) {
        maybe_trace_pmtu_no_probe(config_.source_connection_id, path);
        path.mtu.next_probe_time.reset();
        return;
    }
    path.mtu.next_probe_time.reset();
    if (packet_trace_matches_connection(config_.source_connection_id)) {
        std::cerr << "quic-packet-trace pmtud-arm scid="
                  << format_connection_id_hex(config_.source_connection_id) << " path=" << path.id
                  << " probe=" << *probe_size << " validated=" << path.mtu.validated_datagram_size
                  << " ceiling=" << path.mtu.probe_ceiling << '\n';
    }

    application_space_.pending_probe_packet = SentPacketRecord{
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
        .path_id = *current_send_path_id_,
        .is_pmtu_probe = true,
        .pmtu_probe_size = *probe_size,
    };
}

void QuicConnection::arm_pto_probe(QuicCoreTimePoint now) {
    PacketSpaceState *selected_packet_space = nullptr;
    std::optional<QuicCoreTimePoint> selected_deadline;
    const auto application_max_ack_delay = std::chrono::milliseconds(
        peer_transport_parameters_.has_value() ? peer_transport_parameters_->max_ack_delay
                                               : TransportParameters{}.max_ack_delay);
    const auto allow_application_pto = config_.role == EndpointRole::server || handshake_confirmed_;
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto effective_pto_count = [&](const PacketSpaceState &packet_space) {
        if (config_.role != EndpointRole::client || handshake_confirmed_ ||
            &packet_space != &initial_space_) {
            return pto_count_;
        }
        return std::min(pto_count_, 2u);
    };
    const auto client_handshake_keepalive_reference_time =
        [this]() -> std::optional<QuicCoreTimePoint> {
        const bool eligible = (config_.role == EndpointRole::client) &
                              (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                              last_peer_activity_time_.has_value() &
                              (initial_packet_space_discarded_ ||
                               !has_in_flight_ack_eliciting_packet(initial_space_)) &
                              (handshake_packet_space_discarded_ ||
                               !has_in_flight_ack_eliciting_packet(handshake_space_)) &
                              !has_in_flight_ack_eliciting_packet(application_space_);
        if (!eligible) {
            return std::nullopt;
        }

        auto reference_time = last_peer_activity_time_;
        const auto probe_time =
            last_client_handshake_keepalive_probe_time_.value_or(QuicCoreTimePoint::min());
        if (probe_time > *reference_time) {
            reference_time = probe_time;
        }

        return reference_time;
    }();
    PacketSpaceState *client_handshake_keepalive_space = client_handshake_keepalive_packet_space(
        client_handshake_keepalive_reference_time, initial_packet_space_discarded_, initial_space_,
        handshake_packet_space_discarded_, handshake_space_);
    auto client_handshake_keepalive_deadline = std::optional<QuicCoreTimePoint>{};
    if (client_handshake_keepalive_space != nullptr) {
        client_handshake_keepalive_deadline =
            compute_pto_deadline(shared_rtt_state, std::chrono::milliseconds(0),
                                 optional_ref_or_abort(client_handshake_keepalive_reference_time),
                                 std::min(pto_count_, 2u));
    }
    const bool client_handshake_keepalive_due = client_handshake_keepalive_deadline.has_value() &&
                                                now >= *client_handshake_keepalive_deadline;
    const auto client_receive_keepalive_reference_time =
        [this]() -> std::optional<QuicCoreTimePoint> {
        const bool has_receive_interest = std::ranges::any_of(
            streams_, [](const auto &entry) { return !stream_receive_terminal(entry.second); });
        const bool eligible = (config_.role == EndpointRole::client) & handshake_confirmed_ &
                              last_peer_activity_time_.has_value() & has_receive_interest &
                              (initial_packet_space_discarded_ ||
                               !has_in_flight_ack_eliciting_packet(initial_space_)) &
                              (handshake_packet_space_discarded_ ||
                               !has_in_flight_ack_eliciting_packet(handshake_space_)) &
                              !has_in_flight_ack_eliciting_packet(application_space_);
        if (!eligible) {
            return std::nullopt;
        }

        return last_peer_activity_time_;
    }();
    const bool client_receive_keepalive_eligible =
        client_receive_keepalive_reference_time.has_value();
    PacketSpaceState *client_receive_keepalive_space =
        client_receive_keepalive_eligible ? &application_space_ : nullptr;
    auto client_receive_keepalive_deadline = std::optional<QuicCoreTimePoint>{};
    if (client_receive_keepalive_reference_time.has_value()) {
        client_receive_keepalive_deadline =
            compute_pto_deadline(shared_rtt_state, application_max_ack_delay,
                                 *client_receive_keepalive_reference_time, pto_count_);
    }
    const bool client_receive_keepalive_due =
        client_receive_keepalive_deadline.has_value() && now >= *client_receive_keepalive_deadline;
    const auto consider_packet_space = [&](PacketSpaceState &packet_space,
                                           std::chrono::milliseconds max_ack_delay) {
        if (packet_space_discarded(packet_space)) {
            return;
        }
        const auto tracked_packet = latest_in_flight_ack_eliciting_packet(packet_space);
        if (!tracked_packet.has_value()) {
            return;
        }
        const auto packet_space_deadline =
            compute_pto_deadline(shared_rtt_state, max_ack_delay, tracked_packet->sent_time,
                                 effective_pto_count(packet_space));

        const bool deadline_due = now >= packet_space_deadline;
        if (!deadline_due) {
            return;
        }

        const auto current_selected_deadline = selected_deadline.value_or(packet_space_deadline);
        if (!selected_deadline.has_value() | (packet_space_deadline < current_selected_deadline)) {
            selected_deadline = packet_space_deadline;
            selected_packet_space = &packet_space;
        }
    };

    consider_packet_space(initial_space_, std::chrono::milliseconds(0));
    consider_packet_space(handshake_space_, std::chrono::milliseconds(0));
    if (allow_application_pto) {
        consider_packet_space(application_space_, application_max_ack_delay);
    }

    if (selected_packet_space == nullptr) {
        if (!client_handshake_keepalive_due && !client_receive_keepalive_due) {
            return;
        }
        if (client_handshake_keepalive_due) {
            selected_packet_space = client_handshake_keepalive_space;
            selected_deadline = client_handshake_keepalive_deadline;
        } else {
            selected_packet_space = client_receive_keepalive_space;
            selected_deadline = client_receive_keepalive_deadline;
        }
    }

    ++pto_count_;
    remaining_pto_probe_datagrams_ = 0;
    bool armed_pto_probe = false;
    if (current_send_path_id_.has_value()) {
        auto &path = ensure_path_state(*current_send_path_id_);
        if (!path.validated && path.outstanding_challenge.has_value()) {
            path.challenge_pending = true;
        }
    }
    const auto arm_packet_space_probe = [&](PacketSpaceState &packet_space) {
        if (packet_space_discarded(packet_space)) {
            return;
        }
        const bool allow_client_handshake_keepalive_probe =
            client_handshake_keepalive_due && &packet_space == client_handshake_keepalive_space;
        const bool allow_client_receive_keepalive_probe =
            client_receive_keepalive_due && &packet_space == client_receive_keepalive_space;
        if (!allow_client_handshake_keepalive_probe && !allow_client_receive_keepalive_probe &&
            !has_in_flight_ack_eliciting_packet(packet_space)) {
            return;
        }

        if (&packet_space != &application_space_ && packet_space.send_crypto.has_pending_data()) {
            return;
        }

        packet_space.pending_probe_packet = select_pto_probe(packet_space);
        if ((allow_client_handshake_keepalive_probe | allow_client_receive_keepalive_probe) &
            packet_space.pending_probe_packet.has_value()) {
            packet_space.pending_probe_packet->force_ack = true;
        }
        if (allow_client_receive_keepalive_probe & packet_space.pending_probe_packet.has_value()) {
            if ((&packet_space == &application_space_) & current_send_path_id_.has_value()) {
                auto &path = ensure_path_state(*current_send_path_id_);
                if (path.validated) {
                    if (!path.outstanding_challenge.has_value()) {
                        path.outstanding_challenge =
                            next_path_challenge_data(*current_send_path_id_);
                    }
                    path.challenge_pending = true;
                }
            }
        }
        armed_pto_probe |= packet_space.pending_probe_packet.has_value();
    };

    arm_packet_space_probe(*selected_packet_space);

    const auto arm_coalesced_probe = [&](PacketSpaceState &packet_space) {
        if (&packet_space == selected_packet_space) {
            return;
        }

        arm_packet_space_probe(packet_space);
    };

    arm_coalesced_probe(initial_space_);
    arm_coalesced_probe(handshake_space_);
    if (allow_application_pto) {
        arm_coalesced_probe(application_space_);
    }

    if (armed_pto_probe) {
        remaining_pto_probe_datagrams_ = 2;
    }

    if (packet_trace_matches_connection(config_.source_connection_id)) {
        constexpr std::array<const char *, 4> kPacketSpaceNames = {
            "none",
            "initial",
            "handshake",
            "application",
        };
        const auto selected_packet_space_index =
            static_cast<std::size_t>(selected_packet_space == &initial_space_) +
            static_cast<std::size_t>(selected_packet_space == &handshake_space_) * 2u +
            static_cast<std::size_t>(selected_packet_space == &application_space_) * 3u;
        const char *selected_packet_space_name = kPacketSpaceNames[selected_packet_space_index];

        std::cerr << "quic-packet-trace arm-pto scid="
                  << format_connection_id_hex(config_.source_connection_id)
                  << " selected=" << selected_packet_space_name
                  << " client_hs_due=" << static_cast<int>(client_handshake_keepalive_due)
                  << " client_recv_due=" << static_cast<int>(client_receive_keepalive_due)
                  << " armed=" << static_cast<int>(armed_pto_probe) << " initial_probe="
                  << static_cast<int>(initial_space_.pending_probe_packet.has_value())
                  << " handshake_probe="
                  << static_cast<int>(handshake_space_.pending_probe_packet.has_value())
                  << " application_probe="
                  << static_cast<int>(application_space_.pending_probe_packet.has_value())
                  << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                  << " pto_count=" << pto_count_ << '\n';
    }
    maybe_emit_qlog_recovery_metrics(now);
}

bool QuicConnection::packet_space_discarded(const PacketSpaceState &packet_space) const {
    if (&packet_space == &initial_space_) {
        return initial_packet_space_discarded_;
    }
    if (&packet_space == &handshake_space_) {
        return handshake_packet_space_discarded_;
    }
    return false;
}

SentPacketRecord QuicConnection::select_pto_probe(const PacketSpaceState &packet_space) const {
    std::optional<SentPacketRecord> ping_fallback;
    std::optional<SentPacketRecord> best_probe;
    int best_probe_priority = -1;
    const auto handles = packet_space.recovery.tracked_packets();
    for (auto it = handles.rbegin(); it != handles.rend(); ++it) {
        const auto &packet = *packet_space.recovery.packet_for_handle(*it);
        if (!packet.ack_eliciting || !packet.in_flight) {
            continue;
        }

        ping_fallback = ping_fallback.value_or(SentPacketRecord{
            .packet_number = packet.packet_number,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        });

        auto probe = packet;
        std::erase_if(probe.crypto_ranges, [&](const ByteRange &range) {
            return !packet_space.send_crypto.has_outstanding_range(range.offset,
                                                                   range.bytes.size());
        });
        std::erase_if(probe.reset_stream_frames, [&](const ResetStreamFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool reset_acknowledged =
                stream->second.reset_state == StreamControlFrameState::acknowledged;
            const bool reset_frame_mismatch =
                !reset_stream_frame_matches(stream->second.pending_reset_frame, frame);
            return static_cast<bool>(reset_acknowledged | reset_frame_mismatch);
        });
        std::erase_if(probe.stop_sending_frames, [&](const StopSendingFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool stop_sending_acknowledged =
                stream->second.stop_sending_state == StreamControlFrameState::acknowledged;
            const bool stop_sending_frame_mismatch =
                !stop_sending_frame_matches(stream->second.pending_stop_sending_frame, frame);
            return static_cast<bool>(stop_sending_acknowledged | stop_sending_frame_mismatch);
        });
        std::erase_if(probe.max_stream_data_frames, [&](const MaxStreamDataFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool max_stream_data_acknowledged =
                stream->second.flow_control.max_stream_data_state ==
                StreamControlFrameState::acknowledged;
            const bool max_stream_data_frame_mismatch = !max_stream_data_frame_matches(
                stream->second.flow_control.pending_max_stream_data_frame, frame);
            return static_cast<bool>(max_stream_data_acknowledged | max_stream_data_frame_mismatch);
        });
        std::erase_if(probe.max_streams_frames, [&](const MaxStreamsFrame &frame) {
            const bool frame_acknowledged =
                frame.stream_type == StreamLimitType::bidirectional
                    ? local_stream_limit_state_.max_streams_bidi_state ==
                          StreamControlFrameState::acknowledged
                    : local_stream_limit_state_.max_streams_uni_state ==
                          StreamControlFrameState::acknowledged;
            const auto &pending_frame =
                frame.stream_type == StreamLimitType::bidirectional
                    ? *local_stream_limit_state_.pending_max_streams_bidi_frame
                    : *local_stream_limit_state_.pending_max_streams_uni_frame;
            const bool frame_mismatch =
                std::tie(pending_frame.stream_type, pending_frame.maximum_streams) !=
                std::tie(frame.stream_type, frame.maximum_streams);
            return static_cast<bool>(frame_acknowledged | frame_mismatch);
        });
        std::erase_if(probe.stream_data_blocked_frames, [&](const StreamDataBlockedFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool stream_data_blocked_acknowledged =
                stream->second.flow_control.stream_data_blocked_state ==
                StreamControlFrameState::acknowledged;
            const bool stream_data_blocked_frame_mismatch = !stream_data_blocked_frame_matches(
                stream->second.flow_control.pending_stream_data_blocked_frame, frame);
            return static_cast<bool>(stream_data_blocked_acknowledged |
                                     stream_data_blocked_frame_mismatch);
        });
        std::erase_if(probe.stream_fragments, [&](const StreamFrameSendFragment &fragment) {
            const auto stream = streams_.find(fragment.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            return !stream_fragment_is_probe_worthy(stream->second, fragment);
        });

        if (probe.max_data_frame.has_value()) {
            const bool max_data_acknowledged =
                connection_flow_control_.max_data_state == StreamControlFrameState::acknowledged;
            const bool max_data_frame_mismatch = !max_data_frame_matches(
                connection_flow_control_.pending_max_data_frame, *probe.max_data_frame);
            if (max_data_acknowledged | max_data_frame_mismatch) {
                probe.max_data_frame = std::nullopt;
            }
        }
        if (probe.data_blocked_frame.has_value()) {
            const bool data_blocked_acknowledged = connection_flow_control_.data_blocked_state ==
                                                   StreamControlFrameState::acknowledged;
            const bool data_blocked_frame_mismatch = !data_blocked_frame_matches(
                connection_flow_control_.pending_data_blocked_frame, *probe.data_blocked_frame);
            if (data_blocked_acknowledged | data_blocked_frame_mismatch) {
                probe.data_blocked_frame = std::nullopt;
            }
        }
        if (probe.has_handshake_done &&
            handshake_done_state_ == StreamControlFrameState::acknowledged) {
            probe.has_handshake_done = false;
        }
        std::erase_if(probe.new_token_frames, [&](const NewTokenFrame &frame) {
            return std::none_of(
                pending_new_token_frames_.begin(), pending_new_token_frames_.end(),
                [&](const NewTokenFrame &pending) { return pending.token == frame.token; });
        });
        std::erase_if(probe.new_connection_id_frames, [&](const NewConnectionIdFrame &frame) {
            return std::none_of(
                pending_new_connection_id_frames_.begin(), pending_new_connection_id_frames_.end(),
                [&](const NewConnectionIdFrame &pending) {
                    return std::tie(pending.sequence_number, pending.retire_prior_to,
                                    pending.connection_id, pending.stateless_reset_token) ==
                           std::tie(frame.sequence_number, frame.retire_prior_to,
                                    frame.connection_id, frame.stateless_reset_token);
                });
        });
        std::erase_if(probe.retire_connection_id_frames, [&](const RetireConnectionIdFrame &frame) {
            return std::none_of(pending_retire_connection_id_frames_.begin(),
                                pending_retire_connection_id_frames_.end(),
                                [&](const RetireConnectionIdFrame &pending) {
                                    return pending.sequence_number == frame.sequence_number;
                                });
        });

        const auto frame_count = retransmittable_probe_frame_count(probe);
        if (frame_count == 0 && !probe.has_ping) {
            continue;
        }

        int probe_priority = 0;
        if (!probe.stream_fragments.empty()) {
            probe_priority = 3;
        } else if (!probe.crypto_ranges.empty()) {
            probe_priority = 2;
        } else if (frame_count != 0) {
            probe_priority = 1;
        }

        if (!best_probe.has_value() || probe_priority > best_probe_priority) {
            best_probe = std::move(probe);
            best_probe_priority = probe_priority;
        }
        if (best_probe_priority == 3) {
            break;
        }
    }

    if (best_probe.has_value()) {
        return *best_probe;
    }
    if (ping_fallback.has_value()) {
        return *ping_fallback;
    }

    return SentPacketRecord{
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
}

COQUIC_NOINLINE void QuicConnection::queue_client_handshake_recovery_probe() {
    if ((config_.role != EndpointRole::client) | (status_ != HandshakeStatus::in_progress) |
        handshake_confirmed_ | handshake_packet_space_discarded_ |
        !handshake_space_.write_secret.has_value() |
        !handshake_space_.send_crypto.has_pending_data()) {
        return;
    }

    if (handshake_space_.pending_probe_packet.has_value() ||
        has_in_flight_ack_eliciting_packet(handshake_space_)) {
        return;
    }

    const bool has_other_space_in_flight =
        client_handshake_recovery_probe_has_other_space_in_flight(
            initial_packet_space_discarded_, initial_space_, application_space_);
    if (!has_other_space_in_flight) {
        return;
    }

    auto probe = select_pto_probe(handshake_space_);
    if (handshake_space_.received_packets.has_ack_to_send()) {
        probe.force_ack = true;
    }
    handshake_space_.pending_probe_packet = std::move(probe);
}

void QuicConnection::queue_server_handshake_recovery_probes() {
    if ((config_.role != EndpointRole::server) | (status_ != HandshakeStatus::in_progress) |
        handshake_confirmed_ | handshake_packet_space_discarded_) {
        return;
    }

    if (handshake_space_.pending_probe_packet.has_value() ||
        handshake_space_.send_crypto.has_pending_data()) {
        return;
    }

    handshake_space_.pending_probe_packet = select_pto_probe(handshake_space_);
}

const RecoveryRttState &QuicConnection::shared_recovery_rtt_state() const {
    if (recovery_rtt_state_.latest_rtt.has_value()) {
        return recovery_rtt_state_;
    }
    if (initial_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return initial_space_.recovery.rtt_state();
    }
    if (handshake_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return handshake_space_.recovery.rtt_state();
    }
    if (application_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return application_space_.recovery.rtt_state();
    }

    return recovery_rtt_state_;
}

std::optional<QuicCoreTimePoint> QuicConnection::zero_rtt_discard_deadline() const {
    if (config_.role != EndpointRole::server || !zero_rtt_space_.read_secret.has_value()) {
        return std::nullopt;
    }

    return server_zero_rtt_discard_deadline_;
}

void QuicConnection::arm_server_zero_rtt_discard_deadline(QuicCoreTimePoint now) {
    if (config_.role != EndpointRole::server || !zero_rtt_space_.read_secret.has_value() ||
        server_zero_rtt_discard_deadline_.has_value()) {
        return;
    }

    const auto max_ack_delay = std::chrono::milliseconds(
        peer_transport_parameters_.value_or(TransportParameters{}).max_ack_delay);
    const auto single_pto = compute_pto_deadline(shared_recovery_rtt_state(), max_ack_delay, now,
                                                 /*pto_count=*/0) -
                            now;
    server_zero_rtt_discard_deadline_ = now + single_pto * 3;
}

void QuicConnection::maybe_discard_server_zero_rtt_packet_space(QuicCoreTimePoint now) {
    if (config_.role != EndpointRole::server || !server_zero_rtt_discard_deadline_.has_value() ||
        now < *server_zero_rtt_discard_deadline_) {
        return;
    }

    discard_packet_space_state(zero_rtt_space_);
    server_zero_rtt_discard_deadline_.reset();
}

void QuicConnection::synchronize_recovery_rtt_state() {
    if (!recovery_rtt_state_.latest_rtt.has_value()) {
        recovery_rtt_state_ = shared_recovery_rtt_state();
    }

    const auto shared_rtt_state = shared_recovery_rtt_state();
    initial_space_.recovery.rtt_state() = shared_rtt_state;
    handshake_space_.recovery.rtt_state() = shared_rtt_state;
    application_space_.recovery.rtt_state() = shared_rtt_state;
}

bool QuicConnection::is_handshake_complete() const {
    return status_ == HandshakeStatus::connected;
}

bool QuicConnection::has_processed_peer_packet() const {
    return processed_peer_packet_;
}

bool QuicConnection::has_failed() const {
    return status_ == HandshakeStatus::failed;
}

bool QuicConnection::close_state_active() const {
    return close_mode_ == QuicConnectionCloseMode::closing ||
           close_mode_ == QuicConnectionCloseMode::draining;
}

bool QuicConnection::terminal_state_expired(QuicCoreTimePoint now) const {
    if (!close_state_active()) {
        return status_ == HandshakeStatus::failed;
    }
    if (!close_deadline_.has_value()) {
        return false;
    }
    return now >= *close_deadline_;
}

void QuicConnection::enter_stateless_reset_draining(QuicCoreTimePoint now) {
    enter_draining_state(now);
}

namespace {

QuicCorePacketSpaceDiagnostics packet_space_diagnostics(const PacketSpaceState &space) {
    return QuicCorePacketSpaceDiagnostics{
        .next_send_packet_number = space.next_send_packet_number,
        .largest_authenticated_packet_number = space.largest_authenticated_packet_number,
        .read_secret_available = space.read_secret.has_value(),
        .write_secret_available = space.write_secret.has_value(),
        .pending_crypto = space.send_crypto.has_pending_data(),
        .outstanding_packets = space.sent_packets.size(),
        .declared_lost_packets = space.declared_lost_packets.size(),
        .pending_probe = space.pending_probe_packet.has_value(),
        .pending_ack_deadline = space.pending_ack_deadline,
        .force_ack = space.force_ack_send,
    };
}

std::optional<std::uint64_t> optional_ms(std::optional<std::chrono::milliseconds> value) {
    if (!value.has_value()) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(std::max<std::int64_t>(0, value->count()));
}

QuicCoreStreamDiagnostics stream_diagnostics(const StreamState &stream) {
    return QuicCoreStreamDiagnostics{
        .stream_id = stream.stream_id,
        .initiator = static_cast<std::uint8_t>(stream.id_info.initiator),
        .direction = static_cast<std::uint8_t>(stream.id_info.direction),
        .local_can_send = stream.id_info.local_can_send,
        .local_can_receive = stream.id_info.local_can_receive,
        .send_closed = stream.send_closed,
        .receive_closed = stream.receive_closed,
        .peer_send_closed = stream.peer_send_closed,
        .peer_fin_delivered = stream.peer_fin_delivered,
        .peer_reset_received = stream.peer_reset_received,
        .send_fin_state = static_cast<std::uint8_t>(stream.send_fin_state),
        .reset_state = static_cast<std::uint8_t>(stream.reset_state),
        .stop_sending_state = static_cast<std::uint8_t>(stream.stop_sending_state),
        .pending_send = stream.has_pending_send(),
        .outstanding_send = stream.has_outstanding_send(),
        .sendable_bytes = stream.sendable_bytes(),
        .send_flow_control_limit = stream.send_flow_control_limit,
        .receive_flow_control_limit = stream.receive_flow_control_limit,
        .highest_received_offset = stream.highest_received_offset,
        .receive_flow_control_consumed = stream.receive_flow_control_consumed,
    };
}

} // namespace

QuicCoreConnectionDiagnostics QuicConnection::diagnostics(QuicConnectionHandle handle) const {
    const auto &rtt = shared_recovery_rtt_state();
    QuicCoreConnectionDiagnostics out{
        .handle = handle,
        .handshake_status = static_cast<std::uint8_t>(status_),
        .started = started_,
        .processed_peer_packet = processed_peer_packet_,
        .handshake_ready_emitted = handshake_ready_emitted_,
        .handshake_confirmed = handshake_confirmed_,
        .handshake_confirmed_emitted = handshake_confirmed_emitted_,
        .failed_emitted = failed_emitted_,
        .peer_transport_parameters_validated = peer_transport_parameters_validated_,
        .peer_address_validated = peer_address_validated_,
        .current_version = current_version_,
        .anti_amplification_received_bytes = anti_amplification_received_bytes_,
        .anti_amplification_sent_bytes = anti_amplification_sent_bytes_,
        .active_paths = paths_.size(),
        .current_send_path_id = current_send_path_id_,
        .active_streams = streams_.size(),
        .retired_streams = retired_streams_.size(),
        .initial_space = packet_space_diagnostics(initial_space_),
        .handshake_space = packet_space_diagnostics(handshake_space_),
        .zero_rtt_space = packet_space_diagnostics(zero_rtt_space_),
        .application_space = packet_space_diagnostics(application_space_),
        .recovery =
            QuicCoreRecoveryDiagnostics{
                .algorithm = config_.transport.congestion_control,
                .congestion_window =
                    static_cast<std::uint64_t>(congestion_controller_.congestion_window()),
                .bytes_in_flight =
                    static_cast<std::uint64_t>(congestion_controller_.bytes_in_flight()),
                .pto_count = pto_count_,
                .latest_rtt_ms = optional_ms(rtt.latest_rtt),
                .min_rtt_ms = optional_ms(rtt.min_rtt),
                .smoothed_rtt_ms =
                    static_cast<std::uint64_t>(std::max<std::int64_t>(0, rtt.smoothed_rtt.count())),
                .rttvar_ms =
                    static_cast<std::uint64_t>(std::max<std::int64_t>(0, rtt.rttvar.count())),
            },
        .flow_control =
            QuicCoreFlowControlDiagnostics{
                .peer_max_data = connection_flow_control_.peer_max_data,
                .highest_sent = connection_flow_control_.highest_sent,
                .advertised_max_data = connection_flow_control_.advertised_max_data,
                .delivered_bytes = connection_flow_control_.delivered_bytes,
                .received_committed = connection_flow_control_.received_committed,
            },
        .stream_limits =
            QuicCoreStreamLimitDiagnostics{
                .peer_max_bidirectional = stream_open_limits_.peer_max_bidirectional,
                .peer_max_unidirectional = stream_open_limits_.peer_max_unidirectional,
                .advertised_max_bidirectional =
                    local_stream_limit_state_.advertised_max_streams_bidi,
                .advertised_max_unidirectional =
                    local_stream_limit_state_.advertised_max_streams_uni,
            },
    };

    out.streams.reserve(streams_.size());
    for (const auto &[stream_id, stream] : streams_) {
        (void)stream_id;
        out.streams.push_back(stream_diagnostics(stream));
    }
    return out;
}

void QuicConnection::maybe_open_qlog_session(QuicCoreTimePoint now, const ConnectionId &odcid) {
    if (qlog_session_ != nullptr || !config_.qlog.has_value()) {
        return;
    }

    qlog_session_ = qlog::Session::try_open(*config_.qlog, config_.role, odcid, now);
}

void QuicConnection::emit_local_qlog_startup_events(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr) {
        return;
    }

    if (qlog_session_->mark_local_version_information_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:version_information",
            qlog::serialize_version_information(config_.role, config_.supported_versions,
                                                current_version_)));
    }
    if (qlog_session_->mark_local_alpn_information_emitted()) {
        const std::vector<std::vector<std::byte>> alpns = {
            application_protocol_bytes(config_.application_protocol),
        };
        static_cast<void>(qlog_session_->write_event(
            now, "quic:alpn_information",
            qlog::serialize_alpn_information(std::span<const std::vector<std::byte>>(alpns),
                                             std::nullopt, std::nullopt, config_.role)));
    }
    if (qlog_session_->mark_local_parameters_set_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:parameters_set",
            qlog::serialize_parameters_set("local", local_transport_parameters_)));
    }
}

void QuicConnection::maybe_emit_remote_qlog_parameters(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || !peer_transport_parameters_.has_value()) {
        return;
    }
    if (!qlog_session_->mark_remote_parameters_set_emitted()) {
        return;
    }

    static_cast<void>(qlog_session_->write_event(
        now, "quic:parameters_set",
        qlog::serialize_parameters_set("remote", *peer_transport_parameters_)));
}

void QuicConnection::maybe_emit_qlog_alpn_information(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || !tls_.has_value()) {
        return;
    }

    const auto &selected = tls_->selected_application_protocol();
    if (!selected.has_value()) {
        return;
    }

    if (config_.role == EndpointRole::server) {
        const auto &client_alpns = tls_->peer_offered_application_protocols();
        if (!client_alpns.empty() && qlog_session_->mark_server_alpn_selection_emitted()) {
            const std::vector<std::vector<std::byte>> server_alpns = {
                application_protocol_bytes(config_.application_protocol),
            };
            static_cast<void>(qlog_session_->write_event(
                now, "quic:alpn_information",
                qlog::serialize_alpn_information(
                    std::span<const std::vector<std::byte>>(server_alpns),
                    std::span<const std::vector<std::byte>>(client_alpns),
                    std::span<const std::byte>(*selected), EndpointRole::server)));
        }
        return;
    }

    if (qlog_session_->mark_client_chosen_alpn_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:alpn_information",
            qlog::serialize_alpn_information(std::nullopt, std::nullopt,
                                             std::span<const std::byte>(*selected),
                                             EndpointRole::client)));
    }
}

qlog::PacketSnapshot
QuicConnection::make_qlog_packet_snapshot(const ProtectedPacket &packet,
                                          const qlog::PacketSnapshotContext &context) const {
    return std::visit(
        [&](const auto &protected_packet) -> qlog::PacketSnapshot {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            qlog::PacketSnapshot snapshot;
            snapshot.raw_length = context.raw_length;
            snapshot.datagram_id = context.datagram_id;
            snapshot.trigger = context.trigger;
            snapshot.frames = protected_packet.frames;
            if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                snapshot.header.packet_type = "initial";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.token = protected_packet.token;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                snapshot.header.packet_type = "handshake";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                snapshot.header.packet_type = "0RTT";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else {
                snapshot.header.packet_type = "1RTT";
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.spin_bit = protected_packet.spin_bit;
                snapshot.header.key_phase = static_cast<unsigned>(protected_packet.key_phase);
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            }
            return snapshot;
        },
        packet);
}

qlog::RecoveryMetricsSnapshot QuicConnection::current_qlog_recovery_metrics() const {
    const auto &rtt = shared_recovery_rtt_state();
    return qlog::RecoveryMetricsSnapshot{
        .min_rtt_ms = rtt.min_rtt.has_value()
                          ? std::optional<double>(static_cast<double>(rtt.min_rtt->count()))
                          : std::nullopt,
        .smoothed_rtt_ms = static_cast<double>(rtt.smoothed_rtt.count()),
        .latest_rtt_ms = rtt.latest_rtt.has_value()
                             ? std::optional<double>(static_cast<double>(rtt.latest_rtt->count()))
                             : std::nullopt,
        .rtt_variance_ms = static_cast<double>(rtt.rttvar.count()),
        .pto_count = static_cast<std::uint16_t>(pto_count_),
        .congestion_window = static_cast<std::uint64_t>(congestion_controller_.congestion_window()),
        .bytes_in_flight = static_cast<std::uint64_t>(congestion_controller_.bytes_in_flight()),
    };
}

void QuicConnection::maybe_emit_qlog_recovery_metrics(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr) {
        return;
    }

    static_cast<void>(
        qlog_session_->maybe_write_recovery_metrics(now, current_qlog_recovery_metrics()));
}

void QuicConnection::emit_qlog_packet_lost(const SentPacketRecord &packet, std::string_view trigger,
                                           QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || packet.qlog_packet_snapshot == nullptr) {
        return;
    }

    auto snapshot = *packet.qlog_packet_snapshot;
    snapshot.trigger = std::string(trigger);
    static_cast<void>(qlog_session_->write_event(now, "quic:packet_lost",
                                                 qlog::serialize_packet_snapshot(snapshot)));
}

void QuicConnection::start_client_if_needed() {
    start_client_if_needed(QuicCoreTimePoint{});
}

void QuicConnection::start_client_if_needed(QuicCoreTimePoint now) {
    if (config_.role != EndpointRole::client || started_) {
        return;
    }

    maybe_open_qlog_session(now, config_.original_destination_connection_id.value_or(
                                     client_initial_destination_connection_id()));
    started_ = true;
    status_ = HandshakeStatus::in_progress;
    idle_timeout_base_time_ = now;
    ack_eliciting_sent_since_idle_reset_ = false;
    local_transport_parameters_ = TransportParameters{
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .max_udp_payload_size = config_.transport.max_udp_payload_size,
        .active_connection_id_limit = config_.transport.active_connection_id_limit,
        .disable_active_migration = config_.transport.disable_active_migration,
        .ack_delay_exponent = config_.transport.ack_delay_exponent,
        .max_ack_delay = config_.transport.max_ack_delay,
        .initial_max_data = config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local = config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = config_.source_connection_id,
        .preferred_address = config_.transport.preferred_address,
        .version_information = version_information_for_handshake(
            config_.supported_versions, current_version_, config_.retry_source_connection_id,
            original_version_, current_version_),
    };
    initialize_local_flow_control();

    const auto serialized_transport_parameters = serialize_locally_validated_transport_parameters(
        config_.role, local_transport_parameters_,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = config_.source_connection_id,
            .expected_original_destination_connection_id = std::nullopt,
            .expected_retry_source_connection_id = std::nullopt,
        });
    if (!serialized_transport_parameters.has_value()) {
        log_codec_failure("serialize_client_transport_parameters",
                          serialized_transport_parameters.error());
        queue_transport_close_for_error(now, serialized_transport_parameters.error());
        return;
    }

    std::optional<std::vector<std::byte>> tls_resumption_state;
    bool enable_zero_rtt_attempt = false;
    if (config_.resumption_state.has_value()) {
        decoded_resumption_state_ = decode_resumption_state(config_.resumption_state->serialized);
        if (decoded_resumption_state_.has_value()) {
            tls_resumption_state = decoded_resumption_state_->tls_state;
            enable_zero_rtt_attempt =
                config_.zero_rtt.attempt &
                (decoded_resumption_state_->quic_version == current_version_) &
                (decoded_resumption_state_->application_protocol == config_.application_protocol) &
                (decoded_resumption_state_->application_context ==
                 config_.zero_rtt.application_context);
            if (enable_zero_rtt_attempt) {
                peer_transport_parameters_ = decoded_resumption_state_->peer_transport_parameters;
                initialize_peer_flow_control_from_transport_parameters();
            } else if (config_.zero_rtt.attempt) {
                pending_zero_rtt_status_event_ =
                    QuicCoreZeroRttStatusEvent{.status = QuicZeroRttStatus::unavailable};
            }
        }
        const bool report_unavailable_zero_rtt_attempt =
            !decoded_resumption_state_.has_value() & config_.zero_rtt.attempt;
        if (report_unavailable_zero_rtt_attempt) {
            pending_zero_rtt_status_event_ =
                QuicCoreZeroRttStatusEvent{.status = QuicZeroRttStatus::unavailable};
        }
    }

    tls_.emplace(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .application_protocol = config_.application_protocol,
        .identity = config_.identity,
        .local_transport_parameters = serialized_transport_parameters.value(),
        .allowed_tls_cipher_suites = config_.allowed_tls_cipher_suites,
        .resumption_state = std::move(tls_resumption_state),
        .attempt_zero_rtt = enable_zero_rtt_attempt,
        .accept_zero_rtt = false,
        .zero_rtt_context = config_.zero_rtt.application_context,
        .tls_keylog_path = config_.tls_keylog_path,
    });
    const auto tls_started = tls_->start();
    if (!tls_started.has_value()) {
        log_codec_failure("tls_start", tls_started.error());
        queue_transport_close_for_error(now, tls_started.error());
        return;
    }

    static_cast<void>(sync_tls_state().value());
    emit_local_qlog_startup_events(now);
}

void QuicConnection::start_server_if_needed(
    const ConnectionId &client_initial_destination_connection_id,
    std::uint32_t client_initial_version) {
    start_server_if_needed(client_initial_destination_connection_id, QuicCoreTimePoint{},
                           client_initial_version);
}

void QuicConnection::start_server_if_needed(
    const ConnectionId &client_initial_destination_connection_id, QuicCoreTimePoint now,
    std::uint32_t client_initial_version) {
    if (started_) {
        return;
    }

    maybe_open_qlog_session(now, config_.original_destination_connection_id.value_or(
                                     client_initial_destination_connection_id));
    started_ = true;
    status_ = HandshakeStatus::in_progress;
    idle_timeout_base_time_ = now;
    ack_eliciting_sent_since_idle_reset_ = false;
    original_version_ = client_initial_version;
    if (config_.retry_source_connection_id.has_value()) {
        current_version_ = client_initial_version;
    } else {
        current_version_ =
            select_server_version(config_.supported_versions, client_initial_version);
    }
    client_initial_destination_connection_id_ = client_initial_destination_connection_id;
    const auto original_destination_connection_id =
        config_.original_destination_connection_id.value_or(
            client_initial_destination_connection_id);
    local_transport_parameters_ = TransportParameters{
        .original_destination_connection_id = original_destination_connection_id,
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .stateless_reset_token = local_connection_ids_[0].stateless_reset_token,
        .max_udp_payload_size = config_.transport.max_udp_payload_size,
        .active_connection_id_limit = config_.transport.active_connection_id_limit,
        .disable_active_migration = config_.transport.disable_active_migration,
        .ack_delay_exponent = config_.transport.ack_delay_exponent,
        .max_ack_delay = config_.transport.max_ack_delay,
        .initial_max_data = config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local = config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = config_.source_connection_id,
        .retry_source_connection_id = config_.retry_source_connection_id,
        .preferred_address = config_.transport.preferred_address,
        .version_information = version_information_for_handshake(
            config_.supported_versions, current_version_, config_.retry_source_connection_id,
            original_version_, current_version_),
    };
    initialize_local_flow_control();

    const auto serialized_transport_parameters = serialize_locally_validated_transport_parameters(
        config_.role, local_transport_parameters_,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = config_.source_connection_id,
            .expected_original_destination_connection_id = original_destination_connection_id,
            .expected_retry_source_connection_id = config_.retry_source_connection_id,
        });
    if (!serialized_transport_parameters.has_value()) {
        log_codec_failure("serialize_server_transport_parameters",
                          serialized_transport_parameters.error());
        queue_transport_close_for_error(now, serialized_transport_parameters.error());
        return;
    }

    tls_.emplace(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .application_protocol = config_.application_protocol,
        .identity = config_.identity,
        .local_transport_parameters = serialized_transport_parameters.value(),
        .allowed_tls_cipher_suites = config_.allowed_tls_cipher_suites,
        .accept_zero_rtt = config_.zero_rtt.allow,
        .zero_rtt_context = config_.zero_rtt.application_context,
        .tls_keylog_path = config_.tls_keylog_path,
    });
    const auto tls_started = tls_->start();
    if (!tls_started.has_value()) {
        log_codec_failure("tls_start", tls_started.error());
        queue_transport_close_for_error(now, tls_started.error());
        return;
    }
    static_cast<void>(sync_tls_state().value());
    emit_local_qlog_startup_events(now);

    if (!config_.retry_source_connection_id.has_value()) {
        anti_amplification_received_bytes_ +=
            static_cast<std::uint64_t>(anti_amplification_received_bytes_ == 0) *
            kMinimumInitialDatagramSize;
    }
    if (config_.retry_source_connection_id.has_value()) {
        mark_peer_address_validated();
    }
}

CodecResult<ConnectionId> QuicConnection::peek_client_initial_destination_connection_id(
    std::span<const std::byte> bytes) const {
    BufferReader reader(bytes);
    const auto first_byte = reader.read_byte();
    if (!first_byte.has_value()) {
        return CodecResult<ConnectionId>::failure(first_byte.error().code,
                                                  first_byte.error().offset);
    }

    const auto header_byte = std::to_integer<std::uint8_t>(first_byte.value());
    if ((header_byte & 0x80u) == 0) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }
    if ((header_byte & 0x40u) == 0) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }

    const auto version = reader.read_exact(4);
    if (!version.has_value()) {
        return CodecResult<ConnectionId>::failure(version.error().code, version.error().offset);
    }
    const auto version_value = read_u32_be(version.value());
    if (!is_supported_quic_version(version_value)) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }
    if (!is_initial_long_header_type(version_value,
                                     static_cast<std::uint8_t>((header_byte >> 4) & 0x03u))) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto destination_connection_id_length = reader.read_byte();
    if (!destination_connection_id_length.has_value()) {
        return CodecResult<ConnectionId>::failure(destination_connection_id_length.error().code,
                                                  destination_connection_id_length.error().offset);
    }
    const auto destination_connection_id_length_value =
        std::to_integer<std::uint8_t>(destination_connection_id_length.value());
    if (destination_connection_id_length_value > 20) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }

    const auto destination_connection_id =
        reader.read_exact(destination_connection_id_length_value);
    if (!destination_connection_id.has_value()) {
        return CodecResult<ConnectionId>::failure(destination_connection_id.error().code,
                                                  destination_connection_id.error().offset);
    }

    return CodecResult<ConnectionId>::success(ConnectionId(
        destination_connection_id.value().begin(), destination_connection_id.value().end()));
}

CodecResult<std::size_t>
QuicConnection::peek_next_packet_length(std::span<const std::byte> bytes) const {
    BufferReader reader(bytes);
    const auto first_byte = reader.read_byte();
    if (!first_byte.has_value()) {
        return CodecResult<std::size_t>::failure(first_byte.error().code,
                                                 first_byte.error().offset);
    }

    const auto header_byte = std::to_integer<std::uint8_t>(first_byte.value());
    if ((header_byte & 0x80u) == 0) {
        if ((header_byte & 0x40u) == 0) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_fixed_bit, 0);
        }
        return CodecResult<std::size_t>::success(bytes.size());
    }
    if ((header_byte & 0x40u) == 0) {
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

CodecResult<bool> QuicConnection::process_inbound_packet(const ProtectedPacket &packet,
                                                         QuicCoreTimePoint now,
                                                         QuicEcnCodepoint ecn) {
    return std::visit(
        [&](const auto &protected_packet) -> CodecResult<bool> {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                if (should_adopt_supported_client_version(config_.role, protected_packet.version,
                                                          current_version_)) {
                    current_version_ = protected_packet.version;
                }
                if (initial_packet_space_discarded_) {
                    return CodecResult<bool>::success(true);
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                const bool duplicate_initial_packet =
                    initial_space_.received_packets.contains(protected_packet.packet_number);
                peer_source_connection_id_ = protected_packet.source_connection_id;
                peer_connection_ids_[0] = PeerConnectionIdRecord{
                    .sequence_number = 0,
                    .connection_id = protected_packet.source_connection_id,
                };
                active_peer_connection_id_sequence_ = 0;
                initial_space_.largest_authenticated_packet_number = protected_packet.packet_number;
                const auto processed =
                    process_inbound_crypto(EncryptionLevel::initial, protected_packet.frames, now);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    initial_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        note_idle_peer_activity(now);
                    }
                    if (ack_eliciting) {
                        initial_space_.pending_ack_deadline = now;
                        initial_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                    if (duplicate_initial_packet & ack_eliciting) {
                        queue_server_handshake_recovery_probes();
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                if (should_adopt_supported_client_version(config_.role, protected_packet.version,
                                                          current_version_)) {
                    current_version_ = protected_packet.version;
                }
                if (handshake_packet_space_discarded_) {
                    return CodecResult<bool>::success(true);
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                peer_source_connection_id_ = protected_packet.source_connection_id;
                peer_connection_ids_[0] = PeerConnectionIdRecord{
                    .sequence_number = 0,
                    .connection_id = protected_packet.source_connection_id,
                };
                active_peer_connection_id_sequence_ = 0;
                handshake_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const auto processed = process_inbound_crypto(EncryptionLevel::handshake,
                                                              protected_packet.frames, now);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    if (config_.role == EndpointRole::server) {
                        mark_peer_address_validated();
                    }
                    if (config_.role == EndpointRole::server) {
                        discard_initial_packet_space();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    handshake_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        note_idle_peer_activity(now);
                    }
                    if (ack_eliciting) {
                        handshake_space_.pending_ack_deadline = now;
                        handshake_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                application_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const auto processed = process_inbound_application(protected_packet.frames, now,
                                                                   true, last_inbound_path_id_);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    note_idle_peer_activity(now);
                    if (ack_eliciting) {
                        application_space_.pending_ack_deadline = now;
                        application_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else {
                application_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const bool has_crypto_frame =
                    std::ranges::any_of(protected_packet.frames, [](const Frame &frame) {
                        return std::holds_alternative<CryptoFrame>(frame);
                    });
                const auto processed = process_inbound_application(
                    protected_packet.frames, now, has_crypto_frame, last_inbound_path_id_);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    if (config_.role == EndpointRole::server &&
                        status_ != HandshakeStatus::connected) {
                        mark_peer_address_validated();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    note_idle_peer_activity(now);
                    if (ack_eliciting) {
                        schedule_application_ack_deadline(application_space_, now,
                                                          local_transport_parameters_.max_ack_delay,
                                                          ecn);
                    }
                    if (zero_rtt_space_.read_secret.has_value() ||
                        zero_rtt_space_.write_secret.has_value()) {
                        if (config_.role == EndpointRole::server &&
                            zero_rtt_space_.read_secret.has_value()) {
                            arm_server_zero_rtt_discard_deadline(now);
                        } else {
                            discard_packet_space_state(zero_rtt_space_);
                        }
                    }
                    update_spin_bit_on_receive(last_inbound_path_id_, protected_packet.spin_bit,
                                               protected_packet.packet_number);
                }
                return processed;
            }
        },
        packet);
}

CodecResult<bool>
QuicConnection::process_inbound_received_packet(const ReceivedProtectedPacket &packet,
                                                QuicCoreTimePoint now, QuicEcnCodepoint ecn) {
    return std::visit(
        [&](const auto &protected_packet) -> CodecResult<bool> {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            if constexpr (std::is_same_v<PacketType, ReceivedProtectedInitialPacket>) {
                if (should_adopt_supported_client_version(config_.role, protected_packet.version,
                                                          current_version_)) {
                    current_version_ = protected_packet.version;
                }
                if (initial_packet_space_discarded_) {
                    return CodecResult<bool>::success(true);
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                const bool duplicate_initial_packet =
                    initial_space_.received_packets.contains(protected_packet.packet_number);
                peer_source_connection_id_ = protected_packet.source_connection_id;
                peer_connection_ids_[0] = PeerConnectionIdRecord{
                    .sequence_number = 0,
                    .connection_id = protected_packet.source_connection_id,
                };
                active_peer_connection_id_sequence_ = 0;
                initial_space_.largest_authenticated_packet_number = protected_packet.packet_number;
                const auto processed = process_inbound_received_crypto(
                    EncryptionLevel::initial, protected_packet.frames, now);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    initial_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        note_idle_peer_activity(now);
                    }
                    if (ack_eliciting) {
                        initial_space_.pending_ack_deadline = now;
                        initial_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                    if (duplicate_initial_packet & ack_eliciting) {
                        queue_server_handshake_recovery_probes();
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ReceivedProtectedHandshakePacket>) {
                if (should_adopt_supported_client_version(config_.role, protected_packet.version,
                                                          current_version_)) {
                    current_version_ = protected_packet.version;
                }
                if (handshake_packet_space_discarded_) {
                    return CodecResult<bool>::success(true);
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                peer_source_connection_id_ = protected_packet.source_connection_id;
                peer_connection_ids_[0] = PeerConnectionIdRecord{
                    .sequence_number = 0,
                    .connection_id = protected_packet.source_connection_id,
                };
                active_peer_connection_id_sequence_ = 0;
                handshake_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const auto processed = process_inbound_received_crypto(
                    EncryptionLevel::handshake, protected_packet.frames, now);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    if (config_.role == EndpointRole::server) {
                        mark_peer_address_validated();
                    }
                    if (config_.role == EndpointRole::server) {
                        discard_initial_packet_space();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    handshake_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        note_idle_peer_activity(now);
                    }
                    if (ack_eliciting) {
                        handshake_space_.pending_ack_deadline = now;
                        handshake_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ReceivedProtectedZeroRttPacket>) {
                application_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const auto processed = process_inbound_received_application(
                    protected_packet.frames, now, true, last_inbound_path_id_);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    note_idle_peer_activity(now);
                    if (ack_eliciting) {
                        application_space_.pending_ack_deadline = now;
                        application_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else {
                application_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const bool has_crypto_frame =
                    std::ranges::any_of(protected_packet.frames, [](const ReceivedFrame &frame) {
                        return std::holds_alternative<ReceivedCryptoFrame>(frame);
                    });
                const auto processed = process_inbound_received_application(
                    protected_packet.frames, now, has_crypto_frame, last_inbound_path_id_);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    if (config_.role == EndpointRole::server &&
                        status_ != HandshakeStatus::connected) {
                        mark_peer_address_validated();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    note_idle_peer_activity(now);
                    if (ack_eliciting) {
                        schedule_application_ack_deadline(application_space_, now,
                                                          local_transport_parameters_.max_ack_delay,
                                                          ecn);
                    }
                    if (zero_rtt_space_.read_secret.has_value() ||
                        zero_rtt_space_.write_secret.has_value()) {
                        if (config_.role == EndpointRole::server &&
                            zero_rtt_space_.read_secret.has_value()) {
                            arm_server_zero_rtt_discard_deadline(now);
                        } else {
                            discard_packet_space_state(zero_rtt_space_);
                        }
                    }
                    update_spin_bit_on_receive(last_inbound_path_id_, protected_packet.spin_bit,
                                               protected_packet.packet_number);
                }
                return processed;
            }
        },
        packet);
}

bool QuicConnection::should_skip_packet_number_for_optimistic_ack_detection(
    const PacketSpaceState &packet_space, std::uint64_t packet_number) {
    const bool skip_counter_active = packet_space.optimistic_ack_skip_counter > 0;
    const bool skip_interval_due = (packet_space.optimistic_ack_skip_counter % 8u) == 0;
    const bool packet_number_available = packet_number < kMaxQuicVarInt;
    return skip_counter_active & skip_interval_due & packet_number_available;
}

std::uint64_t QuicConnection::reserve_packet_number(PacketSpaceState &packet_space) {
    const auto packet_number = packet_space.next_send_packet_number++;
    if (!config_.transport.enable_optimistic_ack_mitigation) {
        return packet_number;
    }

    ++packet_space.optimistic_ack_skip_counter;
    if (should_skip_packet_number_for_optimistic_ack_detection(
            packet_space, packet_space.next_send_packet_number)) {
        packet_space.optimistic_ack_skipped_packet_numbers.push_back(
            packet_space.next_send_packet_number);
        ++packet_space.next_send_packet_number;
    }
    return packet_number;
}

bool QuicConnection::ack_ranges_include_unsent_packet_number(const PacketSpaceState &packet_space,
                                                             AckRangeCursor cursor) const {
    if (!config_.transport.enable_optimistic_ack_mitigation) {
        return false;
    }

    while (const auto range = next_ack_range(cursor)) {
        for (const auto skipped_packet_number :
             packet_space.optimistic_ack_skipped_packet_numbers) {
            if (skipped_packet_number < range->smallest) {
                continue;
            }
            if (skipped_packet_number > range->largest) {
                continue;
            }
            if (packet_space.recovery.find_packet(skipped_packet_number) == nullptr) {
                return true;
            }
        }
    }
    return false;
}

CodecResult<bool> QuicConnection::reject_optimistic_ack_if_detected(PacketSpaceState &packet_space,
                                                                    AckRangeCursor cursor,
                                                                    QuicCoreTimePoint now) {
    if (!ack_ranges_include_unsent_packet_number(packet_space, cursor)) {
        return CodecResult<bool>::success(true);
    }

    const auto error = optimistic_ack_protocol_violation_error();
    queue_transport_close_for_error(now, error);
    return CodecResult<bool>::failure(error);
}

CodecResult<bool> QuicConnection::process_inbound_crypto(EncryptionLevel level,
                                                         std::span<const Frame> frames,
                                                         QuicCoreTimePoint now) {
    auto &packet_space = packet_space_for_level(level, initial_space_, handshake_space_,
                                                zero_rtt_space_, application_space_);

    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<AckFrame>(&frame)) {
            const auto processed_ack = process_inbound_ack(
                packet_space, *ack_frame, now, /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
                config_.role == EndpointRole::client && level == EncryptionLevel::initial);
            if (!processed_ack.has_value()) {
                return processed_ack;
            }
            continue;
        }

        if (std::holds_alternative<PingFrame>(frame)) {
            continue;
        }

        if (std::holds_alternative<TransportConnectionCloseFrame>(frame)) {
            enter_draining_state(now);
            continue;
        }

        const bool application_handshake_done = (config_.role == EndpointRole::client) &
                                                (level == EncryptionLevel::application) &
                                                std::holds_alternative<HandshakeDoneFrame>(frame);
        if (application_handshake_done) {
            confirm_handshake();
            continue;
        }

        const auto *crypto_frame = std::get_if<CryptoFrame>(&frame);
        if (crypto_frame == nullptr) {
            return CodecResult<bool>::failure(CodecErrorCode::frame_not_allowed_in_packet_type, 0);
        }
        const auto contiguous_bytes =
            packet_space.receive_crypto.push(crypto_frame->offset, crypto_frame->crypto_data);
        if (!contiguous_bytes.has_value()) {
            return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                              contiguous_bytes.error().offset);
        }
        if (contiguous_bytes.value().empty()) {
            continue;
        }

        if (!tls_.has_value()) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
        }

        const auto provided = tls_->provide(level, contiguous_bytes.value());
        if (!provided.has_value()) {
            return provided;
        }

        install_available_secrets();
        collect_pending_tls_bytes();
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::process_inbound_received_crypto(
    EncryptionLevel level, std::span<const ReceivedFrame> frames, QuicCoreTimePoint now) {
    auto &packet_space = packet_space_for_level(level, initial_space_, handshake_space_,
                                                zero_rtt_space_, application_space_);

    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<ReceivedAckFrame>(&frame)) {
            const auto processed_ack = process_inbound_ack(
                packet_space, *ack_frame, now, /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
                config_.role == EndpointRole::client && level == EncryptionLevel::initial);
            if (!processed_ack.has_value()) {
                return processed_ack;
            }
            continue;
        }

        if (std::holds_alternative<PingFrame>(frame)) {
            continue;
        }

        if (std::holds_alternative<TransportConnectionCloseFrame>(frame)) {
            enter_draining_state(now);
            continue;
        }

        const bool application_handshake_done = (config_.role == EndpointRole::client) &
                                                (level == EncryptionLevel::application) &
                                                std::holds_alternative<HandshakeDoneFrame>(frame);
        if (application_handshake_done) {
            confirm_handshake();
            continue;
        }

        const auto *crypto_frame = std::get_if<ReceivedCryptoFrame>(&frame);
        if (crypto_frame == nullptr) {
            return CodecResult<bool>::failure(CodecErrorCode::frame_not_allowed_in_packet_type, 0);
        }
        const auto contiguous_bytes = packet_space.receive_crypto.push_shared(
            crypto_frame->offset, crypto_frame->crypto_data);
        if (!contiguous_bytes.has_value()) {
            return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                              contiguous_bytes.error().offset);
        }
        if (contiguous_bytes.value().empty()) {
            continue;
        }

        if (!tls_.has_value()) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
        }

        const auto provided = tls_->provide(level, contiguous_bytes.value().span());
        if (!provided.has_value()) {
            return provided;
        }

        install_available_secrets();
        collect_pending_tls_bytes();
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::process_inbound_ack(PacketSpaceState &packet_space,
                                                      const AckFrame &ack, QuicCoreTimePoint now,
                                                      std::uint64_t ack_delay_exponent,
                                                      std::uint64_t max_ack_delay_ms,
                                                      bool suppress_pto_reset) {
    const auto cursor = make_ack_range_cursor(ack);
    if (!cursor.has_value()) {
        return CodecResult<bool>::success(true);
    }
    const auto optimistic_ack_check =
        reject_optimistic_ack_if_detected(packet_space, cursor.value(), now);
    if (!optimistic_ack_check.has_value()) {
        return optimistic_ack_check;
    }

    const bool traces_ack = packet_space_is_application(packet_space, application_space_) &&
                            packet_trace_matches_connection(config_.source_connection_id);
    return process_inbound_ack_cursor(packet_space, cursor.value(), ack.largest_acknowledged,
                                      decode_ack_delay(ack, ack_delay_exponent), ack.ecn_counts,
                                      traces_ack ? format_ack_ranges(ack) : std::string{}, now,
                                      max_ack_delay_ms, suppress_pto_reset);
}

CodecResult<bool>
QuicConnection::process_inbound_ack(PacketSpaceState &packet_space, const ReceivedAckFrame &ack,
                                    QuicCoreTimePoint now, std::uint64_t ack_delay_exponent,
                                    std::uint64_t max_ack_delay_ms, bool suppress_pto_reset) {
    const auto cursor = make_ack_range_cursor(ack);
    if (!cursor.has_value()) {
        return CodecResult<bool>::success(true);
    }
    const auto optimistic_ack_check =
        reject_optimistic_ack_if_detected(packet_space, cursor.value(), now);
    if (!optimistic_ack_check.has_value()) {
        return optimistic_ack_check;
    }

    const bool traces_ack = packet_space_is_application(packet_space, application_space_) &&
                            packet_trace_matches_connection(config_.source_connection_id);
    return process_inbound_ack_cursor(packet_space, cursor.value(), ack.largest_acknowledged,
                                      decode_ack_delay(ack, ack_delay_exponent), ack.ecn_counts,
                                      traces_ack ? format_ack_ranges(ack) : std::string{}, now,
                                      max_ack_delay_ms, suppress_pto_reset);
}

CodecResult<bool> QuicConnection::process_inbound_ack_cursor(
    PacketSpaceState &packet_space, AckRangeCursor cursor, std::uint64_t largest_acknowledged,
    std::chrono::milliseconds decoded_ack_delay, const std::optional<AckEcnCounts> &ecn_counts,
    const std::string &ack_ranges, QuicCoreTimePoint now, std::uint64_t max_ack_delay_ms,
    bool suppress_pto_reset) {
    packet_space.recovery.rtt_state() = shared_recovery_rtt_state();
    auto ack_result = packet_space.recovery.on_ack_received(cursor, largest_acknowledged, now);
    if (send_profile_enabled()) {
        ++send_profile_counters().ack_frames;
    }
    std::vector<SentPacketRecord> acked_packets;
    acked_packets.reserve(ack_result.acked_packets.size());
    for (const auto handle : ack_result.acked_packets.handles()) {
        append_retired_packet_if_present(acked_packets, retire_acked_packet(packet_space, handle));
    }
    std::vector<SentPacketRecord> late_acked_packets;
    late_acked_packets.reserve(ack_result.late_acked_packets.size());
    for (const auto handle : ack_result.late_acked_packets.handles()) {
        append_retired_packet_if_present(late_acked_packets,
                                         retire_acked_packet(packet_space, handle));
    }
    std::vector<SentPacketRecord> newly_lost_packets;
    newly_lost_packets.reserve(ack_result.lost_packets.size());
    for (const auto handle : ack_result.lost_packets.handles()) {
        append_retired_packet_if_present(
            newly_lost_packets,
            mark_lost_packet(packet_space, handle, /*already_marked_in_recovery=*/true, now));
    }
    if (send_profile_enabled()) {
        auto &profile = send_profile_counters();
        profile.acked_packets += acked_packets.size();
        profile.late_acked_packets += late_acked_packets.size();
        profile.ack_lost_packets += newly_lost_packets.size();
        for (const auto &packet : acked_packets) {
            profile.acked_bytes += packet.bytes_in_flight;
        }
        for (const auto &packet : late_acked_packets) {
            profile.late_acked_bytes += packet.bytes_in_flight;
        }
        for (const auto &packet : newly_lost_packets) {
            profile.ack_lost_bytes += packet.bytes_in_flight;
            if (is_packet_threshold_lost(packet.packet_number, largest_acknowledged)) {
                ++profile.packet_threshold_losses;
            } else {
                ++profile.time_threshold_losses;
            }
        }
    }
    for (const auto &packet : newly_lost_packets) {
        const auto trigger = is_packet_threshold_lost(packet.packet_number, largest_acknowledged)
                                 ? "reordering_threshold"
                                 : "time_threshold";
        emit_qlog_packet_lost(packet, trigger, now);
    }

    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    if (ack_result.largest_acknowledged_was_newly_acked) {
        struct PathEcnAckSummary {
            std::uint64_t newly_acked_ect0 = 0;
            std::uint64_t newly_acked_ect1 = 0;
            std::optional<QuicCoreTimePoint> latest_marked_sent_time;
        };

        std::map<QuicPathId, PathEcnAckSummary> acked_ecn_by_path;
        const auto note_acked_ecn_packet = [&](const SentPacketRecord &packet) {
            if (!is_ect_codepoint(packet.ecn)) {
                return;
            }

            auto &summary = acked_ecn_by_path[packet.path_id];
            if (packet.ecn == QuicEcnCodepoint::ect0) {
                ++summary.newly_acked_ect0;
            } else {
                ++summary.newly_acked_ect1;
            }
            summary.latest_marked_sent_time =
                summary.latest_marked_sent_time.has_value()
                    ? std::max(*summary.latest_marked_sent_time, packet.sent_time)
                    : packet.sent_time;
        };
        for (const auto &packet : acked_packets) {
            note_acked_ecn_packet(packet);
        }
        for (const auto &packet : late_acked_packets) {
            note_acked_ecn_packet(packet);
        }

        if (!acked_ecn_by_path.empty()) {
            const std::array packet_spaces = {
                &initial_space_,
                &handshake_space_,
                &application_space_,
            };
            const auto packet_space_index = ecn_packet_space_index(packet_space, packet_spaces);
            for (const auto &[path_id, summary] : acked_ecn_by_path) {
                auto &path = ensure_path_state(path_id);
                if (path.ecn.state == QuicPathEcnState::failed) {
                    continue;
                }

                if (!ecn_counts.has_value()) {
                    disable_ecn_on_path(path_id);
                    continue;
                }

                const auto previous_counts = path.ecn.has_last_peer_counts[packet_space_index]
                                                 ? path.ecn.last_peer_counts[packet_space_index]
                                                 : AckEcnCounts{};
                const auto &current_counts = *ecn_counts;
                const bool counts_decreased = current_counts.ect0 < previous_counts.ect0 ||
                                              current_counts.ect1 < previous_counts.ect1 ||
                                              current_counts.ecn_ce < previous_counts.ecn_ce;
                if (counts_decreased) {
                    disable_ecn_on_path(path_id);
                    continue;
                }

                const auto delta_ect0 = current_counts.ect0 - previous_counts.ect0;
                const auto delta_ect1 = current_counts.ect1 - previous_counts.ect1;
                const auto delta_ce = current_counts.ecn_ce - previous_counts.ecn_ce;
                const bool missing_ect0_feedback = delta_ect0 + delta_ce < summary.newly_acked_ect0;
                const bool missing_ect1_feedback = delta_ect1 + delta_ce < summary.newly_acked_ect1;
                const bool impossible_ect0_count = current_counts.ect0 > path.ecn.total_sent_ect0;
                const bool impossible_ect1_count = current_counts.ect1 > path.ecn.total_sent_ect1;
                if (missing_ect0_feedback || missing_ect1_feedback || impossible_ect0_count ||
                    impossible_ect1_count) {
                    disable_ecn_on_path(path_id);
                    continue;
                }

                path.ecn.last_peer_counts[packet_space_index] = current_counts;
                path.ecn.has_last_peer_counts[packet_space_index] = true;
                if (path.ecn.state == QuicPathEcnState::probing) {
                    path.ecn.probing_packets_acked +=
                        summary.newly_acked_ect0 + summary.newly_acked_ect1;
                    path.ecn.state = QuicPathEcnState::capable;
                }

                if (delta_ce != 0) {
                    const auto latest_marked_sent_time = *summary.latest_marked_sent_time;
                    latest_ecn_ce_sent_time =
                        std::max(latest_ecn_ce_sent_time.value_or(latest_marked_sent_time),
                                 latest_marked_sent_time);
                }
            }
        }
    }

    if (ack_result.largest_acknowledged_was_newly_acked &&
        ack_result.has_newly_acked_ack_eliciting) {
        update_rtt(packet_space.recovery.rtt_state(), now,
                   SentPacketRecord{.sent_time = ack_result.largest_newly_acked_packet->sent_time},
                   decoded_ack_delay, std::chrono::milliseconds(max_ack_delay_ms));
        recovery_rtt_state_ = packet_space.recovery.rtt_state();
        synchronize_recovery_rtt_state();
        if (send_profile_enabled()) {
            auto &profile = send_profile_counters();
            const auto &rtt = shared_recovery_rtt_state();
            ++profile.rtt_samples;
            record_latest_rtt_sample_for_profile(rtt, profile);
            profile.smoothed_rtt_us_last = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(rtt.smoothed_rtt).count());
            profile.rttvar_us_last = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(rtt.rttvar).count());
        }
    }
    const bool has_any_acked_packets = !acked_packets.empty() || !late_acked_packets.empty();
    for (const auto &packet : acked_packets) {
        note_pmtu_probe_acked(packet, now);
    }
    for (const auto &packet : late_acked_packets) {
        note_pmtu_probe_acked(packet, now);
    }
    if (config_.role == EndpointRole::client && &packet_space == &application_space_ &&
        has_any_acked_packets) {
        confirm_handshake();
    }
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto ack_eliciting_lost_packets = ack_eliciting_in_flight_losses(newly_lost_packets);
    if (!ack_eliciting_lost_packets.empty()) {
        if (send_profile_enabled()) {
            ++send_profile_counters().loss_events;
        }
        congestion_controller_.on_loss_event(now,
                                             latest_packet_sent_time(ack_eliciting_lost_packets));
        if (establishes_persistent_congestion(ack_eliciting_lost_packets, shared_rtt_state,
                                              std::chrono::milliseconds(max_ack_delay_ms))) {
            if (send_profile_enabled()) {
                ++send_profile_counters().persistent_congestion_events;
            }
            congestion_controller_.on_persistent_congestion();
        }
    }
    if (latest_ecn_ce_sent_time.has_value()) {
        if (send_profile_enabled()) {
            ++send_profile_counters().ecn_loss_events;
        }
        congestion_controller_.on_loss_event(now, *latest_ecn_ce_sent_time);
    }
    const auto acked_packet_span = std::span<const SentPacketRecord>(acked_packets);
    const auto app_limited = !has_pending_congestion_controlled_send();
    if (late_acked_packets.empty()) {
        congestion_controller_.on_packets_acked(acked_packet_span, app_limited, now,
                                                shared_rtt_state);
    } else {
        auto congestion_acked_packets = acked_packets;
        congestion_acked_packets.insert(congestion_acked_packets.end(), late_acked_packets.begin(),
                                        late_acked_packets.end());
        congestion_controller_.on_packets_acked(congestion_acked_packets, app_limited, now,
                                                shared_rtt_state);
    }
    if (has_any_acked_packets && !suppress_pto_reset) {
        const bool keepalive_probe_packet_space =
            (&packet_space == &initial_space_) | (&packet_space == &handshake_space_);
        const bool client_handshake_keepalive_ack_only =
            (config_.role == EndpointRole::client) & (status_ == HandshakeStatus::in_progress) &
                !handshake_confirmed_ & keepalive_probe_packet_space &
                std::ranges::all_of(acked_packets,
                                    [&](const SentPacketRecord &packet) {
                                        return packet.has_ping &
                                               (retransmittable_probe_frame_count(packet) == 0);
                                    }) &&
            std::ranges::all_of(late_acked_packets, [&](const SentPacketRecord &packet) {
                return packet.has_ping & (retransmittable_probe_frame_count(packet) == 0);
            });
        if (!client_handshake_keepalive_ack_only) {
            pto_count_ = 0;
        }
    }

    if (packet_space_is_application(packet_space, application_space_) &&
        packet_trace_matches_connection(config_.source_connection_id)) {
        std::cerr << "quic-packet-trace ack scid="
                  << format_connection_id_hex(config_.source_connection_id)
                  << " path=" << last_inbound_path_id_ << " ranges=" << ack_ranges << " acked={"
                  << summarize_packets(acked_packets) << "}"
                  << " late={" << summarize_packets(late_acked_packets) << "}"
                  << " lost={" << summarize_packets(newly_lost_packets) << "}"
                  << " pending_send=" << static_cast<int>(has_pending_application_send())
                  << " probe="
                  << static_cast<int>(application_space_.pending_probe_packet.has_value())
                  << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                  << " pto_count=" << pto_count_
                  << " cwnd=" << congestion_controller_.congestion_window()
                  << " bif=" << congestion_controller_.bytes_in_flight()
                  << " current=" << format_optional_path_id(current_send_path_id_)
                  << " previous=" << format_optional_path_id(previous_path_id_)
                  << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                  << " inbound_path={"
                  << format_path_state_summary(find_path_state(paths_, last_inbound_path_id_))
                  << "} current_path={"
                  << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                  << "}\n";
    }
    maybe_emit_qlog_recovery_metrics(now);
    return CodecResult<bool>::success(true);
}

void QuicConnection::track_sent_packet(PacketSpaceState &packet_space, SentPacketRecord packet) {
    const auto sent_time = packet.sent_time;
    if (packet.ack_eliciting && !packet.is_pmtu_probe) {
        packet.app_limited = !has_pending_congestion_controlled_send();
        congestion_controller_.on_packet_sent(packet);
    }
    if (is_ect_codepoint(packet.ecn)) {
        auto &path = ensure_path_state(packet.path_id);
        if (packet.ecn == QuicEcnCodepoint::ect0) {
            ++path.ecn.total_sent_ect0;
        } else {
            ++path.ecn.total_sent_ect1;
        }
        if (path.ecn.state == QuicPathEcnState::probing) {
            ++path.ecn.probing_packets_sent;
        }
    }
    packet_space.recovery.on_packet_sent(std::move(packet));
    maybe_emit_qlog_recovery_metrics(sent_time);
}

std::optional<SentPacketRecord> QuicConnection::retire_acked_packet(PacketSpaceState &packet_space,
                                                                    RecoveryPacketHandle handle) {
    const auto *tracked_packet = packet_space.recovery.packet_for_handle(handle);
    if (tracked_packet == nullptr) {
        return std::nullopt;
    }

    auto packet = *tracked_packet;
    std::vector<std::uint64_t> retirement_candidates;
    const auto note_retirement_candidate = [&](std::uint64_t stream_id) {
        if (std::find(retirement_candidates.begin(), retirement_candidates.end(), stream_id) ==
            retirement_candidates.end()) {
            retirement_candidates.push_back(stream_id);
        }
    };
    for (const auto &range : packet.crypto_ranges) {
        packet_space.send_crypto.acknowledge(range.offset, range.bytes.size());
    }
    if (!packet.new_token_frames.empty()) {
        std::erase_if(pending_new_token_frames_, [&](const NewTokenFrame &pending) {
            return std::ranges::any_of(packet.new_token_frames, [&](const NewTokenFrame &acked) {
                return pending.token == acked.token;
            });
        });
    }
    if (packet.max_data_frame.has_value()) {
        connection_flow_control_.acknowledge_max_data_frame(*packet.max_data_frame);
    }
    if (packet.data_blocked_frame.has_value()) {
        connection_flow_control_.acknowledge_data_blocked_frame(*packet.data_blocked_frame);
    }
    for (const auto &frame : packet.max_stream_data_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_max_stream_data_frame(frame);
        note_retirement_candidate(frame.stream_id);
    }
    for (const auto &frame : packet.stream_data_blocked_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_stream_data_blocked_frame(frame);
        note_retirement_candidate(frame.stream_id);
    }
    for (const auto &fragment : packet.stream_fragments) {
        const auto stream = streams_.find(fragment.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_send_fragment(fragment);
        maybe_refresh_peer_stream_limit(stream->second);
        note_retirement_candidate(fragment.stream_id);
    }
    for (const auto &frame : packet.reset_stream_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_reset_frame(frame);
        maybe_refresh_peer_stream_limit(stream->second);
        note_retirement_candidate(frame.stream_id);
    }
    for (const auto &frame : packet.stop_sending_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_stop_sending_frame(frame);
        note_retirement_candidate(frame.stream_id);
    }
    for (const auto &frame : packet.max_streams_frames) {
        local_stream_limit_state_.acknowledge_max_streams_frame(frame);
    }
    if (!packet.new_connection_id_frames.empty()) {
        std::erase_if(pending_new_connection_id_frames_, [&](const NewConnectionIdFrame &pending) {
            return std::ranges::any_of(
                packet.new_connection_id_frames, [&](const NewConnectionIdFrame &acked) {
                    return std::tie(pending.sequence_number, pending.retire_prior_to,
                                    pending.connection_id, pending.stateless_reset_token) ==
                           std::tie(acked.sequence_number, acked.retire_prior_to,
                                    acked.connection_id, acked.stateless_reset_token);
                });
        });
    }
    if (!packet.retire_connection_id_frames.empty()) {
        std::erase_if(
            pending_retire_connection_id_frames_, [&](const RetireConnectionIdFrame &pending) {
                return std::ranges::any_of(
                    packet.retire_connection_id_frames, [&](const RetireConnectionIdFrame &acked) {
                        return pending.sequence_number == acked.sequence_number;
                    });
            });
        for (const auto &retired : packet.retire_connection_id_frames) {
            if (const auto peer = peer_connection_ids_.find(retired.sequence_number);
                peer != peer_connection_ids_.end()) {
                if (peer->second.locally_retired) {
                    peer_connection_ids_.erase(peer);
                }
            }
        }
    }
    if (packet.has_handshake_done) {
        handshake_done_state_ = StreamControlFrameState::acknowledged;
    }
    if (packet.is_pmtu_probe) {
        packet.in_flight = false;
        packet.bytes_in_flight = 0;
        packet.crypto_ranges.clear();
        packet.new_token_frames.clear();
        packet.reset_stream_frames.clear();
        packet.stop_sending_frames.clear();
        packet.new_connection_id_frames.clear();
        packet.retire_connection_id_frames.clear();
        packet.max_data_frame.reset();
        packet.max_stream_data_frames.clear();
        packet.max_streams_frames.clear();
        packet.data_blocked_frame.reset();
        packet.stream_data_blocked_frames.clear();
        packet.stream_fragments.clear();
        packet.has_handshake_done = false;
    }

    const auto current_handle =
        packet_space.recovery.handle_for_packet_number(packet.packet_number);
    packet_space.recovery.retire_packet(current_handle.value_or(handle));
    for (const auto stream_id : retirement_candidates) {
        maybe_retire_stream(stream_id);
    }
    return packet;
}

std::optional<SentPacketRecord>
QuicConnection::mark_lost_packet(PacketSpaceState &packet_space, RecoveryPacketHandle handle,
                                 bool already_marked_in_recovery,
                                 std::optional<QuicCoreTimePoint> now) {
    const auto *tracked_packet = packet_space.recovery.packet_for_handle(handle);
    if (tracked_packet == nullptr) {
        return std::nullopt;
    }
    if (connection_drain_test_hooks().force_mark_lost_packet_missing_after_lookup) {
        return std::nullopt;
    }

    auto packet = *tracked_packet;
    if (!packet.new_token_frames.empty()) {
        pending_new_token_frames_.insert(pending_new_token_frames_.begin(),
                                         packet.new_token_frames.begin(),
                                         packet.new_token_frames.end());
    }
    if (!packet.is_pmtu_probe) {
        congestion_controller_.on_packets_lost(std::span<const SentPacketRecord>(&packet, 1));
    }
    note_pmtu_probe_lost(packet, now.value_or(packet.sent_time));
    if (packet_space_is_application(packet_space, application_space_) &&
        current_send_path_id_.has_value()) {
        auto &path = ensure_path_state(*current_send_path_id_);
        if (!path.validated & path.outstanding_challenge.has_value()) {
            path.challenge_pending = true;
        }
    }
    if (is_ect_codepoint(packet.ecn)) {
        auto &path = ensure_path_state(packet.path_id);
        if (path.ecn.state == QuicPathEcnState::probing) {
            ++path.ecn.probing_packets_lost;
            const bool all_probes_lost =
                path.ecn.probing_packets_sent != 0 && path.ecn.probing_packets_acked == 0 &&
                path.ecn.probing_packets_lost >= path.ecn.probing_packets_sent;
            if (all_probes_lost) {
                disable_ecn_on_path(packet.path_id);
            }
        }
    }
    for (const auto &range : packet.crypto_ranges) {
        packet_space.send_crypto.mark_lost(range.offset, range.bytes.size());
    }
    if (packet.max_data_frame.has_value()) {
        connection_flow_control_.mark_max_data_frame_lost(*packet.max_data_frame);
    }
    if (packet.data_blocked_frame.has_value()) {
        connection_flow_control_.mark_data_blocked_frame_lost(*packet.data_blocked_frame);
    }
    for (const auto &frame : packet.max_stream_data_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_max_stream_data_frame_lost(frame);
    }
    for (const auto &frame : packet.stream_data_blocked_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_stream_data_blocked_frame_lost(frame);
    }
    for (const auto &fragment : packet.stream_fragments) {
        const auto stream = streams_.find(fragment.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_send_fragment_lost(fragment);
    }
    for (const auto &frame : packet.reset_stream_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_reset_frame_lost(frame);
    }
    for (const auto &frame : packet.stop_sending_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_stop_sending_frame_lost(frame);
    }
    if (!packet.new_connection_id_frames.empty()) {
        pending_new_connection_id_frames_.insert(pending_new_connection_id_frames_.begin(),
                                                 packet.new_connection_id_frames.begin(),
                                                 packet.new_connection_id_frames.end());
    }
    if (!packet.retire_connection_id_frames.empty()) {
        pending_retire_connection_id_frames_.insert(pending_retire_connection_id_frames_.begin(),
                                                    packet.retire_connection_id_frames.begin(),
                                                    packet.retire_connection_id_frames.end());
        for (const auto &retired : packet.retire_connection_id_frames) {
            if (auto peer = peer_connection_ids_.find(retired.sequence_number);
                peer != peer_connection_ids_.end()) {
                peer->second.retire_frame_in_flight = false;
            }
        }
    }
    for (const auto &frame : packet.max_streams_frames) {
        local_stream_limit_state_.mark_max_streams_frame_lost(frame);
    }
    const bool lost_handshake_done =
        packet.has_handshake_done &
        (handshake_done_state_ != StreamControlFrameState::acknowledged);
    if (lost_handshake_done) {
        handshake_done_state_ = StreamControlFrameState::pending;
    }

    static_cast<void>(already_marked_in_recovery);
    packet_space.recovery.on_packet_declared_lost(packet.packet_number);
    return packet;
}

void QuicConnection::rebuild_recovery(PacketSpaceState &packet_space) {
    packet_space.recovery.rebuild_auxiliary_indexes();
}

CodecResult<bool> QuicConnection::process_inbound_application(std::span<const Frame> frames,
                                                              QuicCoreTimePoint now,
                                                              bool allow_preconnected_frames,
                                                              QuicPathId path_id) {
    static_assert(std::variant_size_v<Frame> == 22,
                  "Update process_inbound_application when Frame gains new variants");
    const bool require_connected = !allow_preconnected_frames;
    const bool allow_preconnected_max_data_frame =
        application_space_.read_secret.has_value() && status_ == HandshakeStatus::in_progress;
    const bool traces_this_packet = packet_trace_matches_connection(config_.source_connection_id);
    const bool has_ack_frame = std::ranges::any_of(
        frames, [](const Frame &frame) { return std::holds_alternative<AckFrame>(frame); });
    const bool has_path_challenge_frame = std::ranges::any_of(frames, [](const Frame &frame) {
        return std::holds_alternative<PathChallengeFrame>(frame);
    });
    const bool has_path_response_frame = std::ranges::any_of(frames, [](const Frame &frame) {
        return std::holds_alternative<PathResponseFrame>(frame);
    });
    if (traces_this_packet & (has_ack_frame | has_path_challenge_frame | has_path_response_frame)) {
        std::cerr << "quic-packet-trace recv-app scid="
                  << format_connection_id_hex(config_.source_connection_id) << " path=" << path_id
                  << " frames_ack=" << static_cast<int>(has_ack_frame)
                  << " frames_path_challenge=" << static_cast<int>(has_path_challenge_frame)
                  << " frames_path_response=" << static_cast<int>(has_path_response_frame)
                  << " probing_only=" << static_cast<int>(is_probing_only(frames))
                  << " current=" << format_optional_path_id(current_send_path_id_)
                  << " previous=" << format_optional_path_id(previous_path_id_)
                  << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                  << " inbound_path={"
                  << format_path_state_summary(find_path_state(paths_, path_id))
                  << "} current_path={"
                  << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                  << "} probe="
                  << static_cast<int>(application_space_.pending_probe_packet.has_value())
                  << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                  << " pto_count=" << pto_count_
                  << " cwnd=" << congestion_controller_.congestion_window()
                  << " bif=" << congestion_controller_.bytes_in_flight() << '\n';
    }
    const auto keep_current_validating_path = [&] {
        if (!current_send_path_id_.has_value() || path_id == *current_send_path_id_) {
            return false;
        }
        const auto *current = find_path_state(paths_, current_send_path_id_);
        const auto *inbound = find_path_state(paths_, path_id);
        return static_cast<bool>(path_state_is_validating(current) &
                                 path_state_is_validated(inbound));
    }();
    if (path_id != current_send_path_id_.value_or(path_id) && !is_probing_only(frames) &&
        !keep_current_validating_path) {
        maybe_switch_to_path(path_id, /*initiated_locally=*/false, now);
    }
    if (!paths_.empty() | (path_id != 0) | current_send_path_id_.has_value()) {
        ensure_path_state(path_id);
    }
    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<AckFrame>(&frame)) {
            const auto ack_delay_exponent = peer_transport_parameters_.has_value()
                                                ? peer_transport_parameters_->ack_delay_exponent
                                                : TransportParameters{}.ack_delay_exponent;
            const auto max_ack_delay_ms = peer_transport_parameters_.has_value()
                                              ? peer_transport_parameters_->max_ack_delay
                                              : TransportParameters{}.max_ack_delay;
            const auto processed_ack = process_inbound_ack(application_space_, *ack_frame, now,
                                                           ack_delay_exponent, max_ack_delay_ms,
                                                           /*suppress_pto_reset=*/false);
            if (!processed_ack.has_value()) {
                return processed_ack;
            }
            continue;
        }

        if (std::holds_alternative<PingFrame>(frame)) {
            const bool allow_preconnected_ping_frame = application_space_.read_secret.has_value() &&
                                                       status_ == HandshakeStatus::in_progress;
            if (require_connected && !allow_preconnected_ping_frame &&
                status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypePing));
            }
            continue;
        }

        if (const auto *crypto_frame = std::get_if<CryptoFrame>(&frame)) {
            const auto contiguous_bytes = application_space_.receive_crypto.push(
                crypto_frame->offset, crypto_frame->crypto_data);
            if (!contiguous_bytes.has_value()) {
                return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                                  contiguous_bytes.error().offset);
            }
            if (contiguous_bytes.value().empty()) {
                continue;
            }
            if (status_ == HandshakeStatus::connected && !tls_.has_value()) {
                continue;
            }

            if (!tls_.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                  0);
            }

            const auto provided =
                tls_->provide(EncryptionLevel::application, contiguous_bytes.value());
            if (!provided.has_value()) {
                return provided;
            }

            install_available_secrets();
            collect_pending_tls_bytes();
            continue;
        }

        const auto *stream_frame = std::get_if<StreamFrame>(&frame);
        if (stream_frame != nullptr) {
            const bool allow_preconnected_stream_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (require_connected && !allow_preconnected_stream_frame &&
                status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(stream_frame_type_for(*stream_frame)));
            }
            if (stream_frame->has_offset && !stream_frame->offset.has_value()) {
                return CodecResult<bool>::failure(frame_encoding_error(kFrameTypeStreamBase));
            }
            const auto stream_offset = stream_frame->offset.value_or(0);

            auto stream = get_or_open_receive_stream(stream_frame->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), stream_frame_type_for(*stream_frame)));
            }
            auto *stream_state = stream.value();
            if (stream_state->peer_reset_received) {
                continue;
            }

            const auto previous_highest_offset = stream_state->highest_received_offset;
            const auto validated = stream_state->validate_receive_range(
                stream_offset, stream_frame->stream_data.size(), stream_frame->fin);
            if (!validated.has_value()) {
                return CodecResult<bool>::failure(stream_state_codec_error(
                    validated.error(), stream_frame_type_for(*stream_frame)));
            }
            const auto received_delta =
                stream_state->highest_received_offset - previous_highest_offset;
            if (connection_flow_control_.received_committed >
                    connection_flow_control_.advertised_max_data ||
                received_delta > connection_flow_control_.advertised_max_data -
                                     connection_flow_control_.received_committed) {
                return CodecResult<bool>::failure(
                    flow_control_error(stream_frame_type_for(*stream_frame)));
            }
            connection_flow_control_.received_committed += received_delta;

            const auto contiguous_bytes =
                stream_state->receive_buffer.push(stream_offset, stream_frame->stream_data);
            if (!contiguous_bytes.has_value()) {
                return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                                  contiguous_bytes.error().offset);
            }
            if (stream_frame->stream_id == 0 &&
                packet_trace_matches_connection(config_.source_connection_id)) {
                std::cerr << "quic-packet-trace stream scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " offset=" << stream_offset
                          << " len=" << stream_frame->stream_data.size()
                          << " fin=" << stream_frame->fin
                          << " contiguous=" << contiguous_bytes.value().size()
                          << " highest=" << stream_state->highest_received_offset << '\n';
            }

            const auto contiguous_size = contiguous_bytes.value().size();
            stream_state->receive_flow_control_consumed +=
                static_cast<std::uint64_t>(contiguous_size);
            const auto fin_ready =
                stream_state->peer_final_size.has_value() &&
                stream_state->receive_flow_control_consumed == *stream_state->peer_final_size &&
                !stream_state->peer_fin_delivered;
            if (contiguous_size != 0 || fin_ready) {
                pending_stream_receive_effects_.push_back(QuicCoreReceiveStreamData{
                    .stream_id = stream_frame->stream_id,
                    .bytes = contiguous_bytes.value(),
                    .fin = fin_ready,
                });
                stream_state->flow_control.delivered_bytes +=
                    static_cast<std::uint64_t>(contiguous_bytes.value().size());
                connection_flow_control_.delivered_bytes +=
                    static_cast<std::uint64_t>(contiguous_bytes.value().size());
                if (fin_ready) {
                    stream_state->peer_fin_delivered = true;
                }
                maybe_refresh_stream_receive_credit(*stream_state, /*force=*/false);
                maybe_refresh_connection_receive_credit(/*force=*/false);
                maybe_refresh_peer_stream_limit(*stream_state);
                maybe_retire_stream(stream_frame->stream_id);
            }
            continue;
        }

        if (const auto *reset_stream = std::get_if<ResetStreamFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeResetStream));
            }

            auto stream = get_or_open_receive_stream(reset_stream->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeResetStream));
            }
            auto *stream_state = stream.value();
            const auto noted = stream_state->note_peer_reset(*reset_stream);
            if (!noted.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(noted.error(), kFrameTypeResetStream));
            }

            pending_peer_reset_effects_.push_back(QuicCorePeerResetStream{
                .stream_id = reset_stream->stream_id,
                .application_error_code = reset_stream->application_protocol_error_code,
                .final_size = reset_stream->final_size,
            });
            maybe_refresh_peer_stream_limit(*stream_state);
            maybe_retire_stream(reset_stream->stream_id);
            continue;
        }

        if (const auto *stop_sending = std::get_if<StopSendingFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeStopSending));
            }

            auto stream = get_or_open_send_stream_for_peer_stop(stop_sending->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeStopSending));
            }
            auto *stream_state = stream.value();
            static_cast<void>(stream_state->note_peer_stop_sending(
                stop_sending->application_protocol_error_code));

            pending_peer_stop_effects_.push_back(QuicCorePeerStopSending{
                .stream_id = stop_sending->stream_id,
                .application_error_code = stop_sending->application_protocol_error_code,
            });
            continue;
        }

        if (const auto *max_data = std::get_if<MaxDataFrame>(&frame)) {
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_max_data_frame, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeMaxData));
            }

            connection_flow_control_.note_peer_max_data(max_data->maximum_data);
            if (total_queued_stream_bytes() <= connection_flow_control_.peer_max_data) {
                connection_flow_control_.pending_data_blocked_frame = std::nullopt;
                connection_flow_control_.data_blocked_state = StreamControlFrameState::none;
            }
            continue;
        }

        if (const auto *max_stream_data = std::get_if<MaxStreamDataFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypeMaxStreamData));
            }

            auto stream = get_or_open_send_stream(max_stream_data->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeMaxStreamData));
            }
            stream.value()->note_peer_max_stream_data(max_stream_data->maximum_stream_data);
            continue;
        }

        if (const auto *max_streams = std::get_if<MaxStreamsFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(frame_type_for_max_streams(max_streams->stream_type)));
            }

            stream_open_limits_.note_peer_max_streams(max_streams->stream_type,
                                                      max_streams->maximum_streams);
            continue;
        }

        if (const auto *data_blocked = std::get_if<DataBlockedFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeDataBlocked));
            }

            maybe_refresh_connection_credit_for_data_blocked(
                *data_blocked, connection_flow_control_,
                [&] { maybe_refresh_connection_receive_credit(/*force=*/true); });
            continue;
        }

        if (const auto *stream_data_blocked = std::get_if<StreamDataBlockedFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypeStreamDataBlocked));
            }

            auto stream = get_or_open_receive_stream(stream_data_blocked->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeStreamDataBlocked));
            }

            auto *stream_state = stream.value();
            maybe_refresh_stream_credit_for_data_blocked(*stream_data_blocked, *stream_state, [&] {
                maybe_refresh_stream_receive_credit(*stream_state, /*force=*/true);
            });
            continue;
        }

        if (std::holds_alternative<StreamsBlockedFrame>(frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                const auto &streams_blocked = std::get<StreamsBlockedFrame>(frame);
                return CodecResult<bool>::failure(protocol_violation_error(
                    frame_type_for_streams_blocked(streams_blocked.stream_type)));
            }
            continue;
        }

        if (const auto *new_connection_id = std::get_if<NewConnectionIdFrame>(&frame)) {
            const auto stored = process_new_connection_id_frame(*new_connection_id);
            if (!stored.has_value()) {
                return CodecResult<bool>::failure(stored.error().code, stored.error().offset);
            }
            continue;
        }

        if (const auto *path_challenge = std::get_if<PathChallengeFrame>(&frame)) {
            const bool allow_preconnected_path_validation_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_path_validation_frame, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypePathChallenge));
            }

            queue_path_response(path_id, path_challenge->data);
            continue;
        }

        if (const auto *path_response = std::get_if<PathResponseFrame>(&frame)) {
            const bool allow_preconnected_path_validation_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_path_validation_frame, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypePathResponse));
            }

            auto matching_path = std::find_if(paths_.begin(), paths_.end(), [&](const auto &entry) {
                return entry.second.outstanding_challenge.has_value() &&
                       entry.second.outstanding_challenge.value() == path_response->data;
            });
            auto *path = matching_path != paths_.end() ? &matching_path->second
                                                       : &ensure_path_state(path_id);
            const auto validated_path_id =
                matching_path != paths_.end() ? matching_path->first : path_id;
            const bool had_outstanding_challenge = path->outstanding_challenge.has_value();
            const bool matched_outstanding_challenge =
                had_outstanding_challenge &&
                path->outstanding_challenge.value() == path_response->data;
            if (matched_outstanding_challenge) {
                path->validated = true;
                path->challenge_pending = false;
                path->validation_initiated_locally = false;
                path->outstanding_challenge.reset();
                path->validation_deadline.reset();
                last_validated_path_id_ = validated_path_id;
                if (current_send_path_id_ != validated_path_id) {
                    maybe_switch_to_path(validated_path_id, /*initiated_locally=*/false, now);
                }
                if (current_send_path_id_ == validated_path_id && previous_path_id_.has_value()) {
                    retire_peer_connection_id_for_inactive_path(*previous_path_id_,
                                                                validated_path_id);
                }
            }
            if (traces_this_packet) {
                std::cerr << "quic-packet-trace path-response scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " path=" << path_id << " validated_path=" << validated_path_id
                          << " had_outstanding=" << static_cast<int>(had_outstanding_challenge)
                          << " matched=" << static_cast<int>(matched_outstanding_challenge)
                          << " current=" << format_optional_path_id(current_send_path_id_)
                          << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                          << " path_state={" << format_path_state_summary(path) << "}\n";
            }
            continue;
        }

        if (const auto *new_token = std::get_if<NewTokenFrame>(&frame)) {
            if (config_.role == EndpointRole::server) {
                return CodecResult<bool>::failure(
                    frame_not_allowed_protocol_violation_error(kFrameTypeNewToken));
            }
            pending_received_new_tokens_.push_back(new_token->token);
            continue;
        }

        const bool has_transport_close =
            std::holds_alternative<TransportConnectionCloseFrame>(frame);
        const bool has_application_close =
            std::holds_alternative<ApplicationConnectionCloseFrame>(frame);
        if (has_transport_close | has_application_close) {
            enter_draining_state(now);
            continue;
        }

        if (std::holds_alternative<HandshakeDoneFrame>(frame)) {
            if (config_.role == EndpointRole::server) {
                return CodecResult<bool>::failure(
                    frame_not_allowed_protocol_violation_error(kFrameTypeHandshakeDone));
            }
            confirm_handshake();
            continue;
        }

        const auto &retire_connection_id = std::get<RetireConnectionIdFrame>(frame);
        const auto retired = process_retire_connection_id_frame(retire_connection_id);
        if (!retired.has_value()) {
            return CodecResult<bool>::failure(retired.error().code, retired.error().offset);
        }
        continue;
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::process_inbound_received_application(
    std::span<const ReceivedFrame> frames, QuicCoreTimePoint now, bool allow_preconnected_frames,
    QuicPathId path_id) {
    static_assert(std::variant_size_v<ReceivedFrame> == 21,
                  "Update process_inbound_received_application when ReceivedFrame changes");
    const bool require_connected = !allow_preconnected_frames;
    const bool allow_preconnected_max_data_frame =
        application_space_.read_secret.has_value() && status_ == HandshakeStatus::in_progress;
    const bool traces_this_packet = packet_trace_matches_connection(config_.source_connection_id);
    const bool has_ack_frame = std::ranges::any_of(frames, [](const ReceivedFrame &frame) {
        return std::holds_alternative<ReceivedAckFrame>(frame);
    });
    const bool has_path_challenge_frame =
        std::ranges::any_of(frames, [](const ReceivedFrame &frame) {
            return std::holds_alternative<PathChallengeFrame>(frame);
        });
    const bool has_path_response_frame =
        std::ranges::any_of(frames, [](const ReceivedFrame &frame) {
            return std::holds_alternative<PathResponseFrame>(frame);
        });
    const bool probing_only = is_probing_only_frames(frames);
    if (traces_this_packet & (has_ack_frame | has_path_challenge_frame | has_path_response_frame)) {
        std::cerr << "quic-packet-trace recv-app scid="
                  << format_connection_id_hex(config_.source_connection_id) << " path=" << path_id
                  << " frames_ack=" << static_cast<int>(has_ack_frame)
                  << " frames_path_challenge=" << static_cast<int>(has_path_challenge_frame)
                  << " frames_path_response=" << static_cast<int>(has_path_response_frame)
                  << " probing_only=" << static_cast<int>(probing_only)
                  << " current=" << format_optional_path_id(current_send_path_id_)
                  << " previous=" << format_optional_path_id(previous_path_id_)
                  << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                  << " inbound_path={"
                  << format_path_state_summary(find_path_state(paths_, path_id))
                  << "} current_path={"
                  << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                  << "} probe="
                  << static_cast<int>(application_space_.pending_probe_packet.has_value())
                  << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                  << " pto_count=" << pto_count_
                  << " cwnd=" << congestion_controller_.congestion_window()
                  << " bif=" << congestion_controller_.bytes_in_flight() << '\n';
    }
    const auto keep_current_validating_path = [&] {
        if (!current_send_path_id_.has_value() || path_id == *current_send_path_id_) {
            return false;
        }
        const auto current = paths_.find(*current_send_path_id_);
        const auto inbound = paths_.find(path_id);
        const bool has_current = current != paths_.end();
        const bool has_inbound = inbound != paths_.end();
        const bool current_validating = has_current ? !current->second.validated : false;
        const bool inbound_validated = has_inbound ? inbound->second.validated : false;
        return static_cast<bool>(has_current & has_inbound & current_validating &
                                 inbound_validated);
    }();
    if (path_id != current_send_path_id_.value_or(path_id) && !probing_only &&
        !keep_current_validating_path) {
        maybe_switch_to_path(path_id, /*initiated_locally=*/false, now);
    }
    if (!paths_.empty() | (path_id != 0) | current_send_path_id_.has_value()) {
        ensure_path_state(path_id);
    }
    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<ReceivedAckFrame>(&frame)) {
            const auto ack_delay_exponent = peer_transport_parameters_.has_value()
                                                ? peer_transport_parameters_->ack_delay_exponent
                                                : TransportParameters{}.ack_delay_exponent;
            const auto max_ack_delay_ms = peer_transport_parameters_.has_value()
                                              ? peer_transport_parameters_->max_ack_delay
                                              : TransportParameters{}.max_ack_delay;
            const auto processed_ack = process_inbound_ack(application_space_, *ack_frame, now,
                                                           ack_delay_exponent, max_ack_delay_ms,
                                                           /*suppress_pto_reset=*/false);
            if (!processed_ack.has_value()) {
                return processed_ack;
            }
            continue;
        }

        if (std::holds_alternative<PingFrame>(frame)) {
            const bool allow_preconnected_ping_frame = application_space_.read_secret.has_value() &&
                                                       status_ == HandshakeStatus::in_progress;
            if (require_connected && !allow_preconnected_ping_frame &&
                status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypePing));
            }
            continue;
        }

        if (const auto *crypto_frame = std::get_if<ReceivedCryptoFrame>(&frame)) {
            const auto contiguous_bytes = application_space_.receive_crypto.push_shared(
                crypto_frame->offset, crypto_frame->crypto_data);
            if (!contiguous_bytes.has_value()) {
                return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                                  contiguous_bytes.error().offset);
            }
            if (contiguous_bytes.value().empty()) {
                continue;
            }
            if (status_ == HandshakeStatus::connected && !tls_.has_value()) {
                continue;
            }

            if (!tls_.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                  0);
            }

            const auto provided =
                tls_->provide(EncryptionLevel::application, contiguous_bytes.value().span());
            if (!provided.has_value()) {
                return provided;
            }

            install_available_secrets();
            collect_pending_tls_bytes();
            continue;
        }

        const auto *stream_frame = std::get_if<ReceivedStreamFrame>(&frame);
        if (stream_frame != nullptr) {
            const bool allow_preconnected_stream_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (require_connected && !allow_preconnected_stream_frame &&
                status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(stream_frame_type_for(*stream_frame)));
            }
            if (stream_frame->has_offset && !stream_frame->offset.has_value()) {
                return CodecResult<bool>::failure(frame_encoding_error(kFrameTypeStreamBase));
            }
            const auto stream_offset = stream_frame->offset.value_or(0);

            auto stream = get_or_open_receive_stream(stream_frame->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), stream_frame_type_for(*stream_frame)));
            }
            auto *stream_state = stream.value();
            if (stream_state->peer_reset_received) {
                continue;
            }

            const auto previous_highest_offset = stream_state->highest_received_offset;
            const auto validated = stream_state->validate_receive_range(
                stream_offset, stream_frame->stream_data.size(), stream_frame->fin);
            if (!validated.has_value()) {
                return CodecResult<bool>::failure(stream_state_codec_error(
                    validated.error(), stream_frame_type_for(*stream_frame)));
            }
            const auto received_delta =
                stream_state->highest_received_offset - previous_highest_offset;
            if (connection_flow_control_.received_committed >
                    connection_flow_control_.advertised_max_data ||
                received_delta > connection_flow_control_.advertised_max_data -
                                     connection_flow_control_.received_committed) {
                return CodecResult<bool>::failure(
                    flow_control_error(stream_frame_type_for(*stream_frame)));
            }
            connection_flow_control_.received_committed += received_delta;

            auto contiguous_bytes =
                stream_state->receive_buffer.push_shared(stream_offset, stream_frame->stream_data);
            if (!contiguous_bytes.has_value()) {
                return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                                  contiguous_bytes.error().offset);
            }
            const auto contiguous_size = contiguous_bytes.value().span().size();
            if (stream_frame->stream_id == 0 &&
                packet_trace_matches_connection(config_.source_connection_id)) {
                std::cerr << "quic-packet-trace stream scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " offset=" << stream_offset
                          << " len=" << stream_frame->stream_data.size()
                          << " fin=" << stream_frame->fin << " contiguous=" << contiguous_size
                          << " highest=" << stream_state->highest_received_offset << '\n';
            }

            stream_state->receive_flow_control_consumed +=
                static_cast<std::uint64_t>(contiguous_size);
            const auto fin_ready =
                stream_state->peer_final_size.has_value() &&
                stream_state->receive_flow_control_consumed == *stream_state->peer_final_size &&
                !stream_state->peer_fin_delivered;
            if (contiguous_size != 0 || fin_ready) {
                QuicCoreReceiveStreamData receive{
                    .stream_id = stream_frame->stream_id,
                    .fin = fin_ready,
                };
                if (config_.emit_shared_receive_stream_data &&
                    contiguous_bytes.value().owned.empty()) {
                    receive.shared_bytes = std::move(contiguous_bytes.value().shared);
                } else {
                    receive.bytes = contiguous_bytes.value().to_vector();
                }
                pending_stream_receive_effects_.push_back(std::move(receive));
                stream_state->flow_control.delivered_bytes +=
                    static_cast<std::uint64_t>(contiguous_size);
                connection_flow_control_.delivered_bytes +=
                    static_cast<std::uint64_t>(contiguous_size);
                if (fin_ready) {
                    stream_state->peer_fin_delivered = true;
                }
                maybe_refresh_stream_receive_credit(*stream_state, /*force=*/false);
                maybe_refresh_connection_receive_credit(/*force=*/false);
                maybe_refresh_peer_stream_limit(*stream_state);
                maybe_retire_stream(stream_frame->stream_id);
            }
            continue;
        }

        if (const auto *reset_stream = std::get_if<ResetStreamFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeResetStream));
            }

            auto stream = get_or_open_receive_stream(reset_stream->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeResetStream));
            }
            auto *stream_state = stream.value();
            const auto noted = stream_state->note_peer_reset(*reset_stream);
            if (!noted.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(noted.error(), kFrameTypeResetStream));
            }

            pending_peer_reset_effects_.push_back(QuicCorePeerResetStream{
                .stream_id = reset_stream->stream_id,
                .application_error_code = reset_stream->application_protocol_error_code,
                .final_size = reset_stream->final_size,
            });
            maybe_refresh_peer_stream_limit(*stream_state);
            maybe_retire_stream(reset_stream->stream_id);
            continue;
        }

        if (const auto *stop_sending = std::get_if<StopSendingFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeStopSending));
            }

            auto stream = get_or_open_send_stream_for_peer_stop(stop_sending->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeStopSending));
            }
            auto *stream_state = stream.value();
            static_cast<void>(stream_state->note_peer_stop_sending(
                stop_sending->application_protocol_error_code));

            pending_peer_stop_effects_.push_back(QuicCorePeerStopSending{
                .stream_id = stop_sending->stream_id,
                .application_error_code = stop_sending->application_protocol_error_code,
            });
            continue;
        }

        if (const auto *max_data = std::get_if<MaxDataFrame>(&frame)) {
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_max_data_frame, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeMaxData));
            }

            connection_flow_control_.note_peer_max_data(max_data->maximum_data);
            if (total_queued_stream_bytes() <= connection_flow_control_.peer_max_data) {
                connection_flow_control_.pending_data_blocked_frame = std::nullopt;
                connection_flow_control_.data_blocked_state = StreamControlFrameState::none;
            }
            continue;
        }

        if (const auto *max_stream_data = std::get_if<MaxStreamDataFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypeMaxStreamData));
            }

            auto stream = get_or_open_send_stream(max_stream_data->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeMaxStreamData));
            }
            stream.value()->note_peer_max_stream_data(max_stream_data->maximum_stream_data);
            continue;
        }

        if (const auto *max_streams = std::get_if<MaxStreamsFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(frame_type_for_max_streams(max_streams->stream_type)));
            }

            stream_open_limits_.note_peer_max_streams(max_streams->stream_type,
                                                      max_streams->maximum_streams);
            continue;
        }

        if (const auto *data_blocked = std::get_if<DataBlockedFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeDataBlocked));
            }

            maybe_refresh_connection_credit_for_data_blocked(
                *data_blocked, connection_flow_control_,
                [&] { maybe_refresh_connection_receive_credit(/*force=*/true); });
            continue;
        }

        if (const auto *stream_data_blocked = std::get_if<StreamDataBlockedFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypeStreamDataBlocked));
            }

            auto stream = get_or_open_receive_stream(stream_data_blocked->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeStreamDataBlocked));
            }

            auto *stream_state = stream.value();
            maybe_refresh_stream_credit_for_data_blocked(*stream_data_blocked, *stream_state, [&] {
                maybe_refresh_stream_receive_credit(*stream_state, /*force=*/true);
            });
            continue;
        }

        if (std::holds_alternative<StreamsBlockedFrame>(frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                const auto &streams_blocked = std::get<StreamsBlockedFrame>(frame);
                return CodecResult<bool>::failure(protocol_violation_error(
                    frame_type_for_streams_blocked(streams_blocked.stream_type)));
            }
            continue;
        }

        if (const auto *new_connection_id = std::get_if<NewConnectionIdFrame>(&frame)) {
            const auto stored = process_new_connection_id_frame(*new_connection_id);
            if (!stored.has_value()) {
                return CodecResult<bool>::failure(stored.error().code, stored.error().offset);
            }
            continue;
        }

        if (const auto *path_challenge = std::get_if<PathChallengeFrame>(&frame)) {
            const bool allow_preconnected_path_validation_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_path_validation_frame, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypePathChallenge));
            }

            queue_path_response(path_id, path_challenge->data);
            continue;
        }

        if (const auto *path_response = std::get_if<PathResponseFrame>(&frame)) {
            const bool allow_preconnected_path_validation_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_path_validation_frame, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypePathResponse));
            }

            auto matching_path = std::find_if(paths_.begin(), paths_.end(), [&](const auto &entry) {
                return entry.second.outstanding_challenge.has_value() &&
                       entry.second.outstanding_challenge.value() == path_response->data;
            });
            auto *path = matching_path != paths_.end() ? &matching_path->second
                                                       : &ensure_path_state(path_id);
            const auto validated_path_id =
                matching_path != paths_.end() ? matching_path->first : path_id;
            const bool had_outstanding_challenge = path->outstanding_challenge.has_value();
            const bool matched_outstanding_challenge =
                had_outstanding_challenge &&
                path->outstanding_challenge.value() == path_response->data;
            if (matched_outstanding_challenge) {
                path->validated = true;
                path->challenge_pending = false;
                path->validation_initiated_locally = false;
                path->outstanding_challenge.reset();
                path->validation_deadline.reset();
                last_validated_path_id_ = validated_path_id;
                if (current_send_path_id_ != validated_path_id) {
                    maybe_switch_to_path(validated_path_id, /*initiated_locally=*/false, now);
                } else if (previous_path_id_.has_value()) {
                    retire_peer_connection_id_for_inactive_path(*previous_path_id_,
                                                                validated_path_id);
                }
            }
            if (traces_this_packet) {
                std::cerr << "quic-packet-trace path-response scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " path=" << path_id << " validated_path=" << validated_path_id
                          << " had_outstanding=" << static_cast<int>(had_outstanding_challenge)
                          << " matched=" << static_cast<int>(matched_outstanding_challenge)
                          << " current=" << format_optional_path_id(current_send_path_id_)
                          << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                          << " path_state={" << format_path_state_summary(path) << "}\n";
            }
            continue;
        }

        if (const auto *new_token = std::get_if<NewTokenFrame>(&frame)) {
            if (config_.role == EndpointRole::server) {
                return CodecResult<bool>::failure(
                    frame_not_allowed_protocol_violation_error(kFrameTypeNewToken));
            }
            pending_received_new_tokens_.push_back(new_token->token);
            continue;
        }

        const bool has_transport_close =
            std::holds_alternative<TransportConnectionCloseFrame>(frame);
        const bool has_application_close =
            std::holds_alternative<ApplicationConnectionCloseFrame>(frame);
        if (has_transport_close | has_application_close) {
            enter_draining_state(now);
            continue;
        }

        if (std::holds_alternative<HandshakeDoneFrame>(frame)) {
            if (config_.role == EndpointRole::server) {
                return CodecResult<bool>::failure(
                    frame_not_allowed_protocol_violation_error(kFrameTypeHandshakeDone));
            }
            confirm_handshake();
            continue;
        }

        const auto &retire_connection_id = std::get<RetireConnectionIdFrame>(frame);
        const auto retired = process_retire_connection_id_frame(retire_connection_id);
        if (!retired.has_value()) {
            return CodecResult<bool>::failure(retired.error().code, retired.error().offset);
        }
    }

    return CodecResult<bool>::success(true);
}

void QuicConnection::install_available_secrets() {
    if (!tls_.has_value()) {
        return;
    }

    bool installed_client_application_keys = false;
    for (auto &available_secret : tls_->take_available_secrets()) {
        available_secret.secret.quic_version = current_version_;
        if (should_skip_available_secret(available_secret.level, initial_packet_space_discarded_,
                                         handshake_packet_space_discarded_)) {
            continue;
        }
        auto &packet_space =
            packet_space_for_level(available_secret.level, initial_space_, handshake_space_,
                                   zero_rtt_space_, application_space_);
        if (available_secret.sender == config_.role) {
            packet_space.write_secret = std::move(available_secret.secret);
        } else {
            packet_space.read_secret = std::move(available_secret.secret);
        }
        installed_client_application_keys |= config_.role == EndpointRole::client &&
                                             available_secret.level == EncryptionLevel::application;
    }

    if (installed_client_application_keys && zero_rtt_space_.write_secret.has_value()) {
        discard_packet_space_state(zero_rtt_space_);
    }
}

void QuicConnection::collect_pending_tls_bytes() {
    if (!tls_.has_value()) {
        return;
    }

    auto initial = tls_->take_pending(EncryptionLevel::initial);
    if (!initial_packet_space_discarded_) {
        initial_space_.send_crypto.append(initial);
    }
    auto handshake = tls_->take_pending(EncryptionLevel::handshake);
    if (!handshake_packet_space_discarded_) {
        handshake_space_.send_crypto.append(handshake);
    }
    zero_rtt_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::zero_rtt));
    application_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::application));
}

void QuicConnection::replay_deferred_protected_packets(QuicCoreTimePoint now) {
    auto deferred_packets = std::move(deferred_protected_packets_);
    deferred_protected_packets_.clear();
    for (const auto &deferred_packet : deferred_packets) {
        process_inbound_datagram(deferred_packet.bytes, now, deferred_packet.path_id,
                                 deferred_packet.ecn, deferred_packet.datagram_id,
                                 /*replay_trigger=*/true,
                                 /*count_inbound_bytes=*/true);
        if (status_ == HandshakeStatus::failed) {
            return;
        }
    }
}

CodecResult<bool> QuicConnection::sync_tls_state() {
    if (tls_.has_value()) {
        tls_->poll();
    }

    install_available_secrets();
    collect_pending_tls_bytes();

    const auto validated = validate_peer_transport_parameters_if_ready();
    if (!validated.has_value()) {
        return validated;
    }

    if (!peer_preferred_address_emitted_ && peer_transport_parameters_validated_ &&
        peer_transport_parameters_.has_value() &&
        peer_transport_parameters_->preferred_address.has_value()) {
        pending_preferred_address_effect_ = QuicCorePeerPreferredAddressAvailable{
            .preferred_address = *peer_transport_parameters_->preferred_address,
        };
        peer_preferred_address_emitted_ = true;
    }

    update_handshake_status();
    maybe_emit_qlog_alpn_information(last_peer_activity_time_.value_or(QuicCoreTimePoint{}));
    auto *tls = tls_.has_value() ? &*tls_ : nullptr;
    const bool tls_handshake_complete = tls != nullptr ? tls->handshake_complete() : false;
    if (resumption_state_emitted_) {
        return CodecResult<bool>::success(true);
    }
    if (tls == nullptr) {
        return CodecResult<bool>::success(true);
    }
    if (!tls_handshake_complete) {
        return CodecResult<bool>::success(true);
    }
    if (!peer_transport_parameters_.has_value()) {
        return CodecResult<bool>::success(true);
    }

    if (const auto ticket = tls->take_resumption_state(); ticket.has_value()) {
        auto encoded = encode_resumption_state(
            *ticket, current_version_, config_.application_protocol, *peer_transport_parameters_,
            config_.zero_rtt.application_context);
        pending_resumption_state_effect_ = QuicCoreResumptionStateAvailable{
            .state =
                QuicResumptionState{
                    .serialized = std::move(encoded),
                },
        };
        resumption_state_emitted_ = true;
    }
    return CodecResult<bool>::success(true);
}

bool QuicConnection::can_skip_outbound_tls_sync() const {
    if (!can_skip_outbound_tls_sync_now(
            status_, peer_transport_parameters_validated_, application_space_.read_secret,
            application_space_.write_secret, qlog_session_.get(), deferred_protected_packets_)) {
        return false;
    }
    if (config_.role == EndpointRole::server) {
        return true;
    }

    return client_outbound_tls_sync_can_skip_resumption(
        resumption_state_emitted_, peer_preferred_address_emitted_, peer_transport_parameters_);
}

CodecResult<bool> QuicConnection::validate_peer_transport_parameters_if_ready() {
    if (peer_transport_parameters_validated_ || !tls_.has_value()) {
        return CodecResult<bool>::success(true);
    }

    if (config_.role == EndpointRole::client && decoded_resumption_state_.has_value() &&
        peer_transport_parameters_.has_value() && !tls_->handshake_complete()) {
        return CodecResult<bool>::success(true);
    }

    const auto &peer_transport_parameters_bytes = tls_->peer_transport_parameters();
    const bool received_peer_transport_parameters = peer_transport_parameters_bytes.has_value();
    if (received_peer_transport_parameters) {
        const auto parameters =
            deserialize_transport_parameters(peer_transport_parameters_bytes.value());
        if (!parameters.has_value()) {
            log_codec_failure("deserialize_transport_parameters", parameters.error());
            return CodecResult<bool>::failure(parameters.error().code, parameters.error().offset);
        }

        peer_transport_parameters_ = parameters.value();
    }
    if (!received_peer_transport_parameters && !peer_transport_parameters_.has_value()) {
        return CodecResult<bool>::success(true);
    }

    const auto validation_context = peer_transport_parameters_validation_context();
    if (!validation_context.has_value()) {
        return CodecResult<bool>::success(true);
    }

    const auto peer_transport_parameters =
        peer_transport_parameters_.value_or(TransportParameters{});
    const auto validation = validate_peer_transport_parameters(
        opposite_role(config_.role), peer_transport_parameters, validation_context.value());
    if (!validation.has_value()) {
        log_codec_failure("validate_peer_transport_parameters", validation.error());
        return CodecResult<bool>::failure(validation.error().code, validation.error().offset);
    }
    const bool accepted_zero_rtt = tls_->early_data_accepted().value_or(false);
    if (config_.role == EndpointRole::client && accepted_zero_rtt) {
        if (decoded_resumption_state_.has_value() &&
            !zero_rtt_transport_limits_not_reduced(
                decoded_resumption_state_->peer_transport_parameters, peer_transport_parameters)) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
        }
    }

    peer_transport_parameters_validated_ = true;
    initialize_peer_flow_control_from_transport_parameters();
    const auto peer_preferred_address = peer_transport_parameters.preferred_address;
    const auto emitted_preferred_address = peer_preferred_address.value_or(PreferredAddress{});
    if (!peer_preferred_address_emitted_ & peer_preferred_address.has_value()) {
        pending_preferred_address_effect_ = QuicCorePeerPreferredAddressAvailable{
            .preferred_address = emitted_preferred_address,
        };
        peer_preferred_address_emitted_ = true;
    }
    maybe_emit_remote_qlog_parameters(last_peer_activity_time_.value_or(QuicCoreTimePoint{}));
    return CodecResult<bool>::success(true);
}

void QuicConnection::update_handshake_status() {
    if (status_ == HandshakeStatus::failed || !started_) {
        return;
    }
    if (!tls_.has_value()) {
        return;
    }

    const bool handshake_ready = tls_->handshake_complete() & peer_transport_parameters_validated_ &
                                 application_space_.read_secret.has_value() &
                                 application_space_.write_secret.has_value();
    if (handshake_ready) {
        if (status_ != HandshakeStatus::connected) {
            status_ = HandshakeStatus::connected;
            if (config_.role == EndpointRole::client) {
                mark_peer_address_validated();
            }
            queue_state_change(QuicCoreStateChange::handshake_ready);
        }
        if (config_.role == EndpointRole::server) {
            confirm_handshake();
            if (handshake_done_state_ == StreamControlFrameState::none) {
                handshake_done_state_ = StreamControlFrameState::pending;
            }
        }
    } else {
        status_ = HandshakeStatus::in_progress;
    }
}

void QuicConnection::confirm_handshake() {
    if (handshake_confirmed_) {
        return;
    }

    handshake_confirmed_ = true;
    queue_state_change(QuicCoreStateChange::handshake_confirmed);
    issue_spare_connection_ids();
    discard_handshake_packet_space();
}

PathState &QuicConnection::ensure_path_state(QuicPathId path_id) {
    auto [it, inserted] = paths_.try_emplace(
        path_id, PathState{
                     .id = path_id,
                     .peer_connection_id_sequence = active_peer_connection_id_sequence_,
                 });
    if (inserted) {
        it->second.validated =
            last_validated_path_id_.has_value() && last_validated_path_id_ == path_id;
        it->second.spin.disabled = latency_spin_bit_disabled_;
        initialize_path_mtu_state(it->second);
    }
    return it->second;
}

void QuicConnection::initialize_path_mtu_state(PathState &path) {
    const auto base = sanitize_pmtud_base(config_.transport.pmtud_base_datagram_size);
    const auto ceiling = outbound_datagram_size_ceiling_for_path(path.id);
    path.mtu.enabled = config_.transport.pmtud_enabled;
    path.mtu.viable = true;
    path.mtu.base_datagram_size = std::min(base, ceiling);
    path.mtu.validated_datagram_size = path.mtu.enabled ? path.mtu.base_datagram_size : ceiling;
    path.mtu.probe_ceiling = ceiling;
    path.mtu.search_low = path.mtu.validated_datagram_size;
    path.mtu.outstanding_probe_size.reset();
    path.mtu.outstanding_probe_packet_number.reset();
    path.mtu.next_probe_time = std::nullopt;
    path.mtu.failed_probe_sizes.clear();
}

void QuicConnection::apply_path_mtu_update(
    QuicPathId path_id, // NOLINT(bugprone-easily-swappable-parameters)
    std::size_t max_udp_payload_size) {
    auto &path = ensure_path_state(path_id);
    if (max_udp_payload_size < kMinimumInitialDatagramSize) {
        path.mtu.viable = false;
        path.mtu.enabled = false;
        path.mtu.probe_ceiling = max_udp_payload_size;
        clear_outstanding_pmtu_probe(path.mtu);
        path.mtu.next_probe_time = std::nullopt;
        if (current_send_path_id_ == path_id && previous_path_id_.has_value() &&
            *previous_path_id_ != path_id) {
            if (const auto previous = paths_.find(*previous_path_id_);
                previous != paths_.end() && previous->second.mtu.viable &&
                previous->second.validated) {
                path.is_current_send_path = false;
                previous->second.is_current_send_path = true;
                current_send_path_id_ = previous_path_id_;
            }
        }
        if (current_send_path_id_ == path_id) {
            pending_transport_close_ = TransportConnectionCloseFrame{
                .error_code = transport_error_code_value(QuicTransportErrorCode::no_viable_path),
                .frame_type = 0,
            };
            pending_connection_close_terminal_state_ = QuicConnectionTerminalState::failed;
            closing_close_packet_pending_ = application_space_.write_secret.has_value();
        }
        return;
    }

    path.mtu.viable = true;
    path.mtu.enabled = config_.transport.pmtud_enabled;
    if (path.mtu.probe_ceiling < kMinimumInitialDatagramSize) {
        path.mtu.probe_ceiling = std::max(kMinimumInitialDatagramSize, max_udp_payload_size);
    }
    path.mtu.probe_ceiling =
        std::min(path.mtu.probe_ceiling, outbound_datagram_size_ceiling_for_path(path_id));
    path.mtu.probe_ceiling = std::min(path.mtu.probe_ceiling, max_udp_payload_size);
    path.mtu.validated_datagram_size =
        std::min(path.mtu.validated_datagram_size, path.mtu.probe_ceiling);
    path.mtu.search_low = std::min(path.mtu.search_low, path.mtu.validated_datagram_size);
    if (should_clear_outstanding_pmtu_probe_after_ceiling(path.mtu)) {
        clear_outstanding_pmtu_probe(path.mtu);
    }
    path.mtu.failed_probe_sizes.erase(
        std::remove_if(path.mtu.failed_probe_sizes.begin(), path.mtu.failed_probe_sizes.end(),
                       [&](std::size_t probe_size) { return probe_size > path.mtu.probe_ceiling; }),
        path.mtu.failed_probe_sizes.end());
    path.mtu.next_probe_time =
        pmtud_next_probe_time(path.mtu, QuicCoreClock::now(), std::chrono::seconds(1));
}

void QuicConnection::start_path_validation(QuicPathId path_id, bool initiated_locally,
                                           QuicCoreTimePoint now) {
    if (current_send_path_id_.has_value() && current_send_path_id_ != path_id) {
        previous_path_id_ = current_send_path_id_;
        if (const auto current = paths_.find(*current_send_path_id_); current != paths_.end()) {
            current->second.is_current_send_path = false;
        }
    }

    const auto peer_connection_id_sequence = [&]() -> std::optional<std::uint64_t> {
        if (initiated_locally) {
            return select_peer_connection_id_sequence_for_path(path_id);
        }
        if (const auto existing = paths_.find(path_id);
            existing != paths_.end() &&
            peer_connection_ids_.contains(existing->second.peer_connection_id_sequence)) {
            return existing->second.peer_connection_id_sequence;
        }
        if (current_send_path_id_.has_value()) {
            if (const auto current = paths_.find(*current_send_path_id_);
                current != paths_.end() &&
                peer_connection_ids_.contains(current->second.peer_connection_id_sequence)) {
                return current->second.peer_connection_id_sequence;
            }
        }
        return active_peer_connection_id_sequence_;
    }();
    if (!peer_connection_id_sequence.has_value()) {
        return;
    }
    auto &path = ensure_path_state(path_id);
    path.validated = false;
    path.is_current_send_path = true;
    set_path_peer_connection_id_sequence(path, *peer_connection_id_sequence);
    path.challenge_pending = true;
    path.validation_initiated_locally = initiated_locally;
    path.outstanding_challenge = next_path_challenge_data(path_id);
    path.validation_deadline = now + path_validation_timeout_period();
    current_send_path_id_ = path_id;
}

std::array<std::byte, 8> QuicConnection::next_path_challenge_data(QuicPathId path_id) {
    return make_path_challenge_data(config_.source_connection_id, path_id,
                                    next_path_challenge_sequence_++);
}

void QuicConnection::queue_path_response(QuicPathId path_id, const std::array<std::byte, 8> &data) {
    auto &path = ensure_path_state(path_id);
    path.pending_response = data;
}

bool QuicConnection::path_validation_timed_out(QuicPathId path_id, QuicCoreTimePoint now) const {
    const auto path = paths_.find(path_id);
    if (path == paths_.end()) {
        return false;
    }

    const auto &validation_deadline = path->second.validation_deadline;
    return validation_deadline.has_value() && now >= validation_deadline.value();
}

CodecResult<bool>
QuicConnection::process_new_connection_id_frame(const NewConnectionIdFrame &frame) {
    if (!peer_connection_ids_.contains(0) && peer_source_connection_id_.has_value()) {
        peer_connection_ids_.emplace(0, PeerConnectionIdRecord{
                                            .sequence_number = 0,
                                            .connection_id = peer_source_connection_id_.value(),
                                        });
    }
    if (frame.retire_prior_to > frame.sequence_number) {
        return CodecResult<bool>::failure(frame_encoding_error(kFrameTypeNewConnectionId));
    }

    if (outbound_destination_connection_id().empty()) {
        return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeNewConnectionId));
    }

    if (frame.retire_prior_to < largest_peer_retire_prior_to_) {
        if (frame.sequence_number < largest_peer_retire_prior_to_) {
            queue_peer_connection_id_retirement(frame.sequence_number);
        }
        return CodecResult<bool>::success(true);
    }
    largest_peer_retire_prior_to_ = frame.retire_prior_to;

    const auto duplicate_sequence = peer_connection_ids_.find(frame.sequence_number);
    if (duplicate_sequence != peer_connection_ids_.end()) {
        const bool mismatched_duplicate =
            duplicate_sequence->second.connection_id != frame.connection_id |
            duplicate_sequence->second.stateless_reset_token != frame.stateless_reset_token;
        if (mismatched_duplicate) {
            return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeNewConnectionId));
        }
    }

    const auto conflicting_connection_id = std::find_if(
        peer_connection_ids_.begin(), peer_connection_ids_.end(), [&](const auto &entry) {
            return entry.first != frame.sequence_number &&
                   entry.second.connection_id == frame.connection_id;
        });
    if (conflicting_connection_id != peer_connection_ids_.end()) {
        return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeNewConnectionId));
    }

    for (const auto &[sequence_number, record] : peer_connection_ids_) {
        static_cast<void>(record);
        if (sequence_number >= frame.retire_prior_to) {
            continue;
        }

        queue_peer_connection_id_retirement(sequence_number);
    }
    peer_connection_ids_[frame.sequence_number] = PeerConnectionIdRecord{
        .sequence_number = frame.sequence_number,
        .connection_id = frame.connection_id,
        .stateless_reset_token = frame.stateless_reset_token,
        .locally_retired = frame.sequence_number < largest_peer_retire_prior_to_,
    };

    if (!peer_connection_ids_.contains(active_peer_connection_id_sequence_) ||
        peer_connection_ids_.at(active_peer_connection_id_sequence_).locally_retired) {
        active_peer_connection_id_sequence_ = frame.sequence_number;
    }

    const auto active_peer_connection_ids = static_cast<std::size_t>(
        std::count_if(peer_connection_ids_.begin(), peer_connection_ids_.end(),
                      [](const auto &entry) { return !entry.second.locally_retired; }));
    if (active_peer_connection_ids > local_transport_parameters_.active_connection_id_limit) {
        return CodecResult<bool>::failure(connection_id_limit_error(kFrameTypeNewConnectionId));
    }

    return CodecResult<bool>::success(true);
}

void QuicConnection::queue_peer_connection_id_retirement(std::uint64_t sequence_number) {
    auto peer = peer_connection_ids_.find(sequence_number);
    if (peer == peer_connection_ids_.end()) {
        return;
    }

    peer->second.locally_retired = true;
    if (sequence_number == active_peer_connection_id_sequence_) {
        const auto next_active =
            std::find_if(peer_connection_ids_.begin(), peer_connection_ids_.end(),
                         [](const auto &entry) { return !entry.second.locally_retired; });
        if (next_active != peer_connection_ids_.end()) {
            active_peer_connection_id_sequence_ = next_active->first;
        }
    }
    if (peer->second.retire_frame_in_flight) {
        return;
    }
    const bool already_pending = std::ranges::any_of(
        pending_retire_connection_id_frames_, [&](const RetireConnectionIdFrame &pending) {
            return pending.sequence_number == sequence_number;
        });
    if (!already_pending) {
        pending_retire_connection_id_frames_.push_back(RetireConnectionIdFrame{
            .sequence_number = sequence_number,
        });
    }
}

CodecResult<bool>
QuicConnection::process_retire_connection_id_frame(const RetireConnectionIdFrame &frame) {
    issue_spare_connection_ids();
    const auto record = local_connection_ids_.find(frame.sequence_number);
    if (record == local_connection_ids_.end()) {
        if (!handshake_confirmed_) {
            return CodecResult<bool>::success(true);
        }
        return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeRetireConnectionId));
    }
    if (record->second.retired) {
        return CodecResult<bool>::success(true);
    }

    record->second.retired = true;
    if (frame.sequence_number == active_local_connection_id_sequence_) {
        const auto next_active =
            std::find_if(local_connection_ids_.begin(), local_connection_ids_.end(),
                         [](const auto &entry) { return !entry.second.retired; });
        if (next_active != local_connection_ids_.end()) {
            active_local_connection_id_sequence_ = next_active->first;
        }
    }
    issue_spare_connection_ids();
    return CodecResult<bool>::success(true);
}

void QuicConnection::issue_spare_connection_ids() {
    if (!handshake_confirmed_ || !peer_transport_parameters_.has_value() ||
        config_.source_connection_id.empty()) {
        return;
    }
    if (config_.role == EndpointRole::client &&
        local_transport_parameters_.disable_active_migration) {
        return;
    }
    if (current_send_path_id_.has_value()) {
        if (const auto path = paths_.find(*current_send_path_id_); path != paths_.end()) {
            if (!path->second.mtu.viable) {
                return;
            }
        }
    }

    const auto peer_limit =
        static_cast<std::size_t>(peer_transport_parameters_->active_connection_id_limit);
    if (peer_limit == 0) {
        return;
    }

    while (count_active_connection_ids(local_connection_ids_) < peer_limit) {
        const auto sequence_number = next_local_connection_id_sequence_++;
        const auto connection_id =
            make_issued_connection_id(config_.source_connection_id, sequence_number);
        const auto stateless_reset_token = make_stateless_reset_token(
            connection_id, sequence_number, config_.stateless_reset_secret);
        local_connection_ids_[sequence_number] = LocalConnectionIdRecord{
            .sequence_number = sequence_number,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        };
        pending_new_connection_id_frames_.push_back(NewConnectionIdFrame{
            .sequence_number = sequence_number,
            .retire_prior_to = 0,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        });
    }
}

std::optional<std::uint64_t>
QuicConnection::select_peer_connection_id_sequence_for_path(QuicPathId path_id) const {
    if (const auto path = paths_.find(path_id);
        path != paths_.end() &&
        peer_connection_ids_.contains(path->second.peer_connection_id_sequence)) {
        if (peer_connection_ids_.at(path->second.peer_connection_id_sequence).locally_retired) {
            return std::nullopt;
        }
        return path->second.peer_connection_id_sequence;
    }

    const auto sequence_assigned_to_other_path = [&](std::uint64_t sequence_number) {
        return std::ranges::any_of(paths_, [&](const auto &entry) {
            return (entry.first != path_id) &
                   (entry.second.peer_connection_id_sequence == sequence_number);
        });
    };

    for (const auto &[sequence_number, connection_id] : peer_connection_ids_) {
        static_cast<void>(connection_id);
        if (connection_id.locally_retired |
            (sequence_number == active_peer_connection_id_sequence_) |
            sequence_assigned_to_other_path(sequence_number)) {
            continue;
        }

        return sequence_number;
    }

    return std::nullopt;
}

ConnectionId QuicConnection::active_peer_destination_connection_id() const {
    if (const auto active = peer_connection_ids_.find(active_peer_connection_id_sequence_);
        active != peer_connection_ids_.end()) {
        if (!active->second.locally_retired) {
            return active->second.connection_id;
        }
    }
    if (peer_source_connection_id_.has_value()) {
        return peer_source_connection_id_.value();
    }
    return config_.initial_destination_connection_id;
}

std::optional<NewConnectionIdFrame> QuicConnection::take_pending_new_connection_id_frame() {
    if (pending_new_connection_id_frames_.empty()) {
        return std::nullopt;
    }

    auto frame = pending_new_connection_id_frames_.front();
    pending_new_connection_id_frames_.erase(pending_new_connection_id_frames_.begin());
    return frame;
}

bool QuicConnection::should_reset_client_handshake_peer_state(
    const ConnectionId &source_connection_id) const {
    return should_reset_client_handshake_peer_state_for_source(
        config_.role, status_, handshake_confirmed_, peer_source_connection_id_,
        source_connection_id);
}

void QuicConnection::reset_client_handshake_peer_state_for_new_source_connection_id() {
    reset_packet_space_receive_state(initial_space_);
    reset_packet_space_receive_state(handshake_space_);
    reset_packet_space_receive_state(zero_rtt_space_);
    deferred_protected_packets_.clear();
    peer_transport_parameters_.reset();
    peer_connection_ids_.clear();
    active_peer_connection_id_sequence_ = 0;
    largest_peer_retire_prior_to_ = 0;
    peer_transport_parameters_validated_ = false;
}

bool QuicConnection::packet_targets_discarded_long_header_space(
    std::span<const std::byte> packet_bytes) const {
    if (packet_bytes.size() < 5) {
        return false;
    }

    const auto first_byte = std::to_integer<std::uint8_t>(packet_bytes.front());
    if ((first_byte & 0x80u) == 0) {
        return false;
    }

    const auto version = read_u32_be(packet_bytes.subspan(1, 4));
    const auto packet_type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    if (is_initial_long_header_type(version, packet_type)) {
        return initial_packet_space_discarded_;
    }
    if (is_handshake_long_header_type(version, packet_type)) {
        return handshake_packet_space_discarded_;
    }

    return false;
}

void QuicConnection::discard_packet_space_state(PacketSpaceState &packet_space) {
    std::vector<SentPacketRecord> discarded_packets;
    const auto handles = packet_space.recovery.tracked_packets();
    discarded_packets.reserve(handles.size());
    for (const auto handle : handles) {
        const auto *packet = packet_space.recovery.packet_for_handle(handle);
        if (packet == nullptr || !packet->in_flight || packet->bytes_in_flight == 0) {
            continue;
        }
        discarded_packets.push_back(*packet);
    }

    if (!discarded_packets.empty()) {
        congestion_controller_.on_packets_discarded(discarded_packets);
    }

    reset_discarded_packet_space_state(packet_space);
}

void QuicConnection::discard_initial_packet_space() {
    recovery_rtt_state_ = shared_recovery_rtt_state();
    initial_packet_space_discarded_ = true;
    discard_packet_space_state(initial_space_);
    pto_count_ = 0;
}

void QuicConnection::discard_handshake_packet_space() {
    recovery_rtt_state_ = shared_recovery_rtt_state();
    handshake_packet_space_discarded_ = true;
    discard_packet_space_state(handshake_space_);
    pto_count_ = 0;
}

bool QuicConnection::can_send_connection_close_frame() const {
    return application_space_.write_secret.has_value() ||
           handshake_space_.write_secret.has_value() || !initial_packet_space_discarded_;
}

std::optional<Frame> QuicConnection::connection_close_frame_for_send() const {
    if (closing_transport_close_.has_value()) {
        return Frame{*closing_transport_close_};
    }
    if (pending_transport_close_.has_value()) {
        return Frame{*pending_transport_close_};
    }
    if (closing_application_close_.has_value()) {
        return Frame{*closing_application_close_};
    }
    if (pending_application_close_.has_value()) {
        return Frame{*pending_application_close_};
    }
    return std::nullopt;
}

void QuicConnection::mark_connection_close_frame_sent(const Frame &frame, QuicCoreTimePoint now) {
    if (const auto *transport_close = std::get_if<TransportConnectionCloseFrame>(&frame)) {
        closing_transport_close_ = *transport_close;
        pending_transport_close_.reset();
    } else if (const auto *application_close =
                   std::get_if<ApplicationConnectionCloseFrame>(&frame)) {
        closing_application_close_ = *application_close;
        pending_application_close_.reset();
    } else {
        return;
    }

    enter_closing_state(now, pending_connection_close_terminal_state_.value_or(
                                 QuicConnectionTerminalState::closed));
    closing_packets_since_last_close_ = 0;
    closing_packet_response_threshold_ =
        std::min<std::uint64_t>(closing_packet_response_threshold_ * 2u, 1024u);
}

void QuicConnection::clear_connection_failure_effects() {
    streams_.clear();
    deferred_protected_packets_.clear();
    pending_stream_receive_effects_.clear();
    pending_peer_reset_effects_.clear();
    pending_peer_stop_effects_.clear();
    pending_state_changes_.clear();
    pending_resumption_state_effect_.reset();
    pending_zero_rtt_status_event_.reset();
    pending_new_token_frames_.clear();
    pending_new_connection_id_frames_.clear();
    pending_retire_connection_id_frames_.clear();
}

void QuicConnection::enter_closing_state(QuicCoreTimePoint now,
                                         QuicConnectionTerminalState terminal_state) {
    if (close_mode_ == QuicConnectionCloseMode::draining) {
        return;
    }
    const bool entering_closing = close_mode_ != QuicConnectionCloseMode::closing;
    if (!close_started_at_.has_value()) {
        close_started_at_ = now;
    }
    if (!close_deadline_.has_value()) {
        close_deadline_ = *close_started_at_ + three_pto_period(shared_recovery_rtt_state());
    }
    close_mode_ = QuicConnectionCloseMode::closing;
    pending_connection_close_terminal_state_ = terminal_state;
    closing_close_packet_pending_ = false;
    if (entering_closing) {
        closing_packets_since_last_close_ = 0;
        closing_packet_response_threshold_ = 1;
    }
    status_ = HandshakeStatus::failed;
    clear_connection_failure_effects();
    queue_state_change(QuicCoreStateChange::failed);
}

void QuicConnection::enter_draining_state(QuicCoreTimePoint now) {
    if (!close_started_at_.has_value()) {
        close_started_at_ = now;
    }
    if (!close_deadline_.has_value()) {
        close_deadline_ = *close_started_at_ + three_pto_period(shared_recovery_rtt_state());
    }
    close_mode_ = QuicConnectionCloseMode::draining;
    pending_connection_close_terminal_state_ = QuicConnectionTerminalState::closed;
    closing_close_packet_pending_ = false;
    pending_application_close_.reset();
    pending_transport_close_.reset();
    closing_application_close_.reset();
    closing_transport_close_.reset();
    closing_packets_since_last_close_ = 0;
    closing_packet_response_threshold_ = 1;
    status_ = HandshakeStatus::failed;
    clear_connection_failure_effects();
    queue_state_change(QuicCoreStateChange::failed);
}

void QuicConnection::queue_transport_close_for_error(QuicCoreTimePoint now, const CodecError &error,
                                                     std::uint64_t frame_type) {
    if (close_mode_ == QuicConnectionCloseMode::closing ||
        close_mode_ == QuicConnectionCloseMode::draining) {
        return;
    }

    pending_transport_close_ = TransportConnectionCloseFrame{
        .error_code = error.has_transport_error_code
                          ? error.transport_error_code
                          : transport_error_code_value(transport_error_for_codec_error(error.code)),
        .frame_type = error.has_frame_type ? error.frame_type : frame_type,
    };
    pending_connection_close_terminal_state_ = QuicConnectionTerminalState::failed;
    const bool can_send_close = can_send_connection_close_frame();
    enter_closing_state(now, QuicConnectionTerminalState::failed);
    closing_close_packet_pending_ = can_send_close;
}

void QuicConnection::mark_failed() {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    if (!pending_terminal_state_.has_value()) {
        pending_terminal_state_ = QuicConnectionTerminalState::failed;
    }
    status_ = HandshakeStatus::failed;
    clear_connection_failure_effects();
    queue_state_change(QuicCoreStateChange::failed);
}

void QuicConnection::mark_silent_close() {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    if (!pending_terminal_state_.has_value()) {
        pending_terminal_state_ = QuicConnectionTerminalState::closed;
    }
    status_ = HandshakeStatus::failed;
    clear_connection_failure_effects();
}

void QuicConnection::queue_state_change(QuicCoreStateChange change) {
    if (change == QuicCoreStateChange::handshake_ready) {
        if (handshake_ready_emitted_) {
            return;
        }
        handshake_ready_emitted_ = true;
    } else if (change == QuicCoreStateChange::handshake_confirmed) {
        if (handshake_confirmed_emitted_) {
            return;
        }
        handshake_confirmed_emitted_ = true;
    } else {
        if (failed_emitted_) {
            return;
        }
        failed_emitted_ = true;
    }

    pending_state_changes_.push_back(change);
}

std::optional<TransportParametersValidationContext>
QuicConnection::peer_transport_parameters_validation_context() const {
    if (!peer_source_connection_id_.has_value()) {
        return std::nullopt;
    }

    if (config_.role == EndpointRole::client) {
        const auto expected_version_information = version_information_for_handshake(
            config_.supported_versions, current_version_, config_.retry_source_connection_id,
            original_version_, current_version_);
        return TransportParametersValidationContext{
            .expected_initial_source_connection_id = peer_source_connection_id_.value(),
            .expected_original_destination_connection_id =
                config_.original_destination_connection_id.value_or(
                    config_.initial_destination_connection_id),
            .expected_retry_source_connection_id = config_.retry_source_connection_id,
            .expected_version_information = expected_version_information,
            .reacted_to_version_negotiation = config_.reacted_to_version_negotiation,
        };
    }

    const auto expected_version_information = version_information_for_handshake(
        config_.supported_versions, original_version_, config_.retry_source_connection_id,
        original_version_, current_version_);
    return TransportParametersValidationContext{
        .expected_initial_source_connection_id = peer_source_connection_id_.value(),
        .expected_original_destination_connection_id = std::nullopt,
        .expected_retry_source_connection_id = std::nullopt,
        .expected_version_information = expected_version_information,
    };
}

void QuicConnection::initialize_local_flow_control() {
    connection_flow_control_ = ConnectionFlowControlState{
        .local_receive_window = local_transport_parameters_.initial_max_data,
        .advertised_max_data = local_transport_parameters_.initial_max_data,
    };
    local_stream_limit_state_.initialize(PeerStreamOpenLimits{
        .bidirectional = local_transport_parameters_.initial_max_streams_bidi,
        .unidirectional = local_transport_parameters_.initial_max_streams_uni,
    });
}

void QuicConnection::initialize_peer_flow_control_from_transport_parameters() {
    if (!peer_transport_parameters_.has_value()) {
        return;
    }

    connection_flow_control_.note_peer_max_data(peer_transport_parameters_->initial_max_data);
    stream_open_limits_.note_peer_max_streams(StreamLimitType::bidirectional,
                                              peer_transport_parameters_->initial_max_streams_bidi);
    stream_open_limits_.note_peer_max_streams(StreamLimitType::unidirectional,
                                              peer_transport_parameters_->initial_max_streams_uni);

    for (auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        stream.flow_control.peer_max_stream_data = initial_stream_send_limit(stream.stream_id);
        stream.send_flow_control_limit = stream.flow_control.peer_max_stream_data;
        if ((stream.receive_flow_control_limit == 0) &
            (stream.flow_control.local_receive_window == 0) &
            (stream.flow_control.advertised_max_stream_data ==
             std::numeric_limits<std::uint64_t>::max())) {
            stream.flow_control.local_receive_window =
                initial_stream_receive_window(stream.stream_id);
            stream.flow_control.advertised_max_stream_data =
                stream.flow_control.local_receive_window;
            stream.receive_flow_control_limit = stream.flow_control.advertised_max_stream_data;
        }
    }
}

std::uint64_t QuicConnection::initial_stream_send_limit(std::uint64_t stream_id) const {
    if (!peer_transport_parameters_.has_value()) {
        return 0;
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_send) {
        return 0;
    }
    if (id_info.direction == StreamDirection::unidirectional) {
        return peer_transport_parameters_->initial_max_stream_data_uni;
    }
    if (id_info.initiator == StreamInitiator::local) {
        return peer_transport_parameters_->initial_max_stream_data_bidi_remote;
    }

    return peer_transport_parameters_->initial_max_stream_data_bidi_local;
}

std::uint64_t QuicConnection::initial_stream_receive_window(std::uint64_t stream_id) const {
    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        return 0;
    }
    if (id_info.direction == StreamDirection::unidirectional) {
        return local_transport_parameters_.initial_max_stream_data_uni;
    }
    if (id_info.initiator == StreamInitiator::local) {
        return local_transport_parameters_.initial_max_stream_data_bidi_local;
    }

    return local_transport_parameters_.initial_max_stream_data_bidi_remote;
}

void QuicConnection::initialize_stream_flow_control(StreamState &stream) const {
    stream.flow_control.peer_max_stream_data = initial_stream_send_limit(stream.stream_id);
    stream.flow_control.local_receive_window = initial_stream_receive_window(stream.stream_id);
    stream.flow_control.advertised_max_stream_data = stream.flow_control.local_receive_window;
    stream.send_flow_control_limit = stream.flow_control.peer_max_stream_data;
    stream.receive_flow_control_limit = stream.flow_control.advertised_max_stream_data;
}

StreamState *QuicConnection::find_stream_state(std::uint64_t stream_id) {
    if (auto it = streams_.find(stream_id); it != streams_.end()) {
        return &it->second;
    }
    if (auto it = retired_streams_.find(stream_id); it != retired_streams_.end()) {
        return &it->second;
    }
    return nullptr;
}

const StreamState *QuicConnection::find_stream_state(std::uint64_t stream_id) const {
    if (auto it = streams_.find(stream_id); it != streams_.end()) {
        return &it->second;
    }
    if (auto it = retired_streams_.find(stream_id); it != retired_streams_.end()) {
        return &it->second;
    }
    return nullptr;
}

void QuicConnection::maybe_retire_stream(std::uint64_t stream_id) {
    const auto stream = streams_.find(stream_id);
    if (stream == streams_.end()) {
        return;
    }
    if (!stream_receive_terminal(stream->second) || !stream_send_terminal(stream->second) ||
        stream->second.has_pending_send() || stream->second.has_outstanding_send()) {
        return;
    }
    const bool has_pending_receive_effect = std::ranges::any_of(
        pending_stream_receive_effects_,
        [&](const QuicCoreReceiveStreamData &effect) { return effect.stream_id == stream_id; });
    if (has_pending_receive_effect) {
        return;
    }
    if (last_application_send_stream_id_ == stream_id) {
        last_application_send_stream_id_.reset();
    }

    retired_streams_.insert_or_assign(stream_id, std::move(stream->second));
    streams_.erase(stream);
}

StreamStateResult<StreamState *> QuicConnection::get_or_open_local_stream(std::uint64_t stream_id) {
    if (auto *existing = find_stream_state(stream_id); existing != nullptr) {
        return StreamStateResult<StreamState *>::success(existing);
    }

    if (!is_local_implicit_stream_open_allowed(stream_id, config_.role)) {
        const auto id_info = classify_stream_id(stream_id, config_.role);
        const auto code = !id_info.local_can_send ? StreamStateErrorCode::invalid_stream_direction
                                                  : StreamStateErrorCode::invalid_stream_id;
        return StreamStateResult<StreamState *>::failure(code, stream_id);
    }
    if (!stream_open_limits_.can_open_local_stream(stream_id, config_.role)) {
        return StreamStateResult<StreamState *>::failure(StreamStateErrorCode::invalid_stream_id,
                                                         stream_id);
    }

    auto [it, inserted] =
        streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
    static_cast<void>(inserted);
    initialize_stream_flow_control(it->second);
    return StreamStateResult<StreamState *>::success(&it->second);
}

StreamStateResult<StreamState *>
QuicConnection::get_existing_receive_stream(std::uint64_t stream_id) {
    if (auto *existing = find_stream_state(stream_id); existing != nullptr) {
        return StreamStateResult<StreamState *>::success(existing);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        return StreamStateResult<StreamState *>::failure(
            StreamStateErrorCode::invalid_stream_direction, stream_id);
    }

    return StreamStateResult<StreamState *>::failure(StreamStateErrorCode::invalid_stream_id,
                                                     stream_id);
}

CodecResult<StreamState *> QuicConnection::get_or_open_receive_stream(std::uint64_t stream_id) {
    if (auto *existing = find_stream_state(stream_id); existing != nullptr) {
        return CodecResult<StreamState *>::success(existing);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        return CodecResult<StreamState *>::failure(stream_state_error(/*frame_type=*/0));
    }
    if (stream_id == kCompatibilityStreamId && id_info.initiator == StreamInitiator::local) {
        auto [it, inserted] =
            streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
        static_cast<void>(inserted);
        initialize_stream_flow_control(it->second);
        return CodecResult<StreamState *>::success(&it->second);
    }
    if (id_info.initiator != StreamInitiator::peer ||
        !is_peer_implicit_stream_open_allowed_by_limits(stream_id, config_.role,
                                                        peer_stream_open_limits())) {
        if (id_info.initiator != StreamInitiator::peer) {
            return CodecResult<StreamState *>::failure(stream_state_error(/*frame_type=*/0));
        }
        return CodecResult<StreamState *>::failure(stream_limit_error(/*frame_type=*/0));
    }

    auto [it, inserted] =
        streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
    static_cast<void>(inserted);
    initialize_stream_flow_control(it->second);
    return CodecResult<StreamState *>::success(&it->second);
}

CodecResult<StreamState *> QuicConnection::get_or_open_send_stream(std::uint64_t stream_id) {
    if (auto *existing = find_stream_state(stream_id); existing != nullptr) {
        return CodecResult<StreamState *>::success(existing);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_send) {
        return CodecResult<StreamState *>::failure(stream_state_error(/*frame_type=*/0));
    }

    if (id_info.initiator == StreamInitiator::local) {
        const auto local_stream = get_or_open_local_stream(stream_id);
        if (!local_stream.has_value()) {
            return CodecResult<StreamState *>::failure(
                stream_state_codec_error(local_stream.error(), /*frame_type=*/0));
        }
        return CodecResult<StreamState *>::success(local_stream.value());
    }

    if (!is_peer_implicit_stream_open_allowed_by_limits(stream_id, config_.role,
                                                        peer_stream_open_limits())) {
        return CodecResult<StreamState *>::failure(stream_limit_error(/*frame_type=*/0));
    }

    auto [it, inserted] =
        streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
    static_cast<void>(inserted);
    initialize_stream_flow_control(it->second);
    return CodecResult<StreamState *>::success(&it->second);
}

CodecResult<StreamState *>
QuicConnection::get_or_open_send_stream_for_peer_stop(std::uint64_t stream_id) {
    return get_or_open_send_stream(stream_id);
}

PeerStreamOpenLimits QuicConnection::peer_stream_open_limits() const {
    return PeerStreamOpenLimits{
        .bidirectional = local_stream_limit_state_.advertised_max_streams_bidi == 0
                             ? (local_transport_parameters_.initial_max_streams_bidi == 0
                                    ? config_.transport.initial_max_streams_bidi
                                    : local_transport_parameters_.initial_max_streams_bidi)
                             : local_stream_limit_state_.advertised_max_streams_bidi,
        .unidirectional = local_stream_limit_state_.advertised_max_streams_uni == 0
                              ? (local_transport_parameters_.initial_max_streams_uni == 0
                                     ? config_.transport.initial_max_streams_uni
                                     : local_transport_parameters_.initial_max_streams_uni)
                              : local_stream_limit_state_.advertised_max_streams_uni,
    };
}

bool QuicConnection::has_pending_application_send() const {
    if (close_mode_ == QuicConnectionCloseMode::draining) {
        return false;
    }
    if (close_mode_ == QuicConnectionCloseMode::closing) {
        return closing_close_packet_can_send(closing_close_packet_pending_,
                                             can_send_connection_close_frame());
    }

    if (current_send_path_id_.has_value()) {
        if (const auto path = paths_.find(*current_send_path_id_); path != paths_.end()) {
            if (!path->second.mtu.viable) {
                return false;
            }
        }
    }

    for (const auto &[path_id, path] : paths_) {
        static_cast<void>(path_id);
        if (path.pending_response.has_value() || path.challenge_pending) {
            if (path.mtu.viable) {
                return true;
            }
        }
    }

    if (pending_application_close_.has_value()) {
        return true;
    }

    if (!pending_new_token_frames_.empty()) {
        return true;
    }

    if (handshake_done_state_ == StreamControlFrameState::pending) {
        return true;
    }

    if (connection_flow_control_.max_data_state == StreamControlFrameState::pending ||
        connection_flow_control_.data_blocked_state == StreamControlFrameState::pending) {
        return true;
    }
    if (local_stream_limit_state_.max_streams_bidi_state == StreamControlFrameState::pending ||
        local_stream_limit_state_.max_streams_uni_state == StreamControlFrameState::pending) {
        return true;
    }

    const auto connection_send_credit =
        connection_flow_control_.peer_max_data > connection_flow_control_.highest_sent
            ? connection_flow_control_.peer_max_data - connection_flow_control_.highest_sent
            : 0;
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        const bool has_pending_control_frame =
            (stream.reset_state == StreamControlFrameState::pending) |
            (stream.stop_sending_state == StreamControlFrameState::pending) |
            (stream.flow_control.max_stream_data_state == StreamControlFrameState::pending) |
            (stream.flow_control.stream_data_blocked_state == StreamControlFrameState::pending);
        if (has_pending_control_frame) {
            return true;
        }
        if (stream.reset_state != StreamControlFrameState::none) {
            continue;
        }

        const auto fin_sendable = stream_fin_sendable(stream);
        if (stream.send_buffer.has_lost_data() || fin_sendable) {
            return true;
        }
        if (connection_send_credit != 0 && stream.sendable_bytes() != 0) {
            return true;
        }
    }

    return false;
}

bool QuicConnection::has_pending_congestion_controlled_send() const {
    if (close_mode_ == QuicConnectionCloseMode::draining) {
        return false;
    }
    if (close_mode_ == QuicConnectionCloseMode::closing) {
        return closing_close_packet_can_send(closing_close_packet_pending_,
                                             can_send_connection_close_frame());
    }

    if (!initial_packet_space_discarded_ && (initial_space_.send_crypto.has_pending_data() ||
                                             initial_space_.pending_probe_packet.has_value())) {
        return true;
    }

    if (!handshake_packet_space_discarded_ && handshake_space_.write_secret.has_value() &&
        (handshake_space_.send_crypto.has_pending_data() ||
         handshake_space_.pending_probe_packet.has_value())) {
        return true;
    }

    const bool can_send_application_packets =
        application_space_.write_secret.has_value() ||
        ((config_.role == EndpointRole::client) & (status_ != HandshakeStatus::connected) &
         zero_rtt_space_.write_secret.has_value());
    if (!can_send_application_packets) {
        return false;
    }

    return has_pending_application_send() || application_space_.pending_probe_packet.has_value() ||
           !pending_new_connection_id_frames_.empty() ||
           !pending_retire_connection_id_frames_.empty() ||
           application_space_.send_crypto.has_pending_data();
}

bool QuicConnection::has_pending_fresh_application_stream_send() const {
    const auto connection_send_credit = saturating_subtract(connection_flow_control_.peer_max_data,
                                                            connection_flow_control_.highest_sent);
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        if (stream.reset_state != StreamControlFrameState::none) {
            continue;
        }

        if (stream_fin_sendable(stream)) {
            return true;
        }
        if ((connection_send_credit != 0) & (stream.sendable_bytes() != 0)) {
            return true;
        }
    }

    return false;
}

std::uint64_t QuicConnection::total_queued_stream_bytes() const {
    std::uint64_t total = 0;
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        total += stream.send_flow_control_committed;
    }

    return total;
}

void QuicConnection::maybe_queue_connection_blocked_frame() {
    const auto queued_bytes = total_queued_stream_bytes();
    const bool should_skip_queue =
        !connection_flow_control_.should_send_data_blocked(queued_bytes) |
        (connection_flow_control_.sendable_bytes(queued_bytes) != 0);
    if (should_skip_queue) {
        return;
    }

    connection_flow_control_.queue_data_blocked(connection_flow_control_.peer_max_data);
}

void QuicConnection::maybe_queue_stream_blocked_frame(StreamState &stream) {
    if (stream.sendable_bytes() != 0) {
        return;
    }

    stream.queue_stream_data_blocked();
}

void QuicConnection::maybe_refresh_connection_receive_credit(bool force) {
    if (!should_refresh_receive_window(connection_flow_control_.delivered_bytes,
                                       connection_flow_control_.advertised_max_data,
                                       connection_flow_control_.local_receive_window, force)) {
        return;
    }

    connection_flow_control_.queue_max_data(connection_flow_control_.delivered_bytes +
                                            connection_flow_control_.local_receive_window);
}

void QuicConnection::maybe_refresh_stream_receive_credit(StreamState &stream, bool force) {
    if (!should_refresh_receive_window(stream.flow_control.delivered_bytes,
                                       stream.flow_control.advertised_max_stream_data,
                                       stream.flow_control.local_receive_window, force)) {
        return;
    }

    stream.queue_max_stream_data(stream.flow_control.delivered_bytes +
                                 stream.flow_control.local_receive_window);
}

void QuicConnection::maybe_refresh_peer_stream_limit(StreamState &stream) {
    if (stream.peer_stream_limit_released) {
        return;
    }
    if (stream.id_info.initiator != StreamInitiator::peer) {
        return;
    }
    if (!stream_receive_terminal(stream) || !stream_send_terminal(stream)) {
        return;
    }

    stream.peer_stream_limit_released = true;

    const auto limits = peer_stream_open_limits();
    const auto direction_index =
        static_cast<std::size_t>(stream.id_info.direction == StreamDirection::unidirectional);
    constexpr std::array limit_types = {
        StreamLimitType::bidirectional,
        StreamLimitType::unidirectional,
    };
    const std::array limit_values = {
        limits.bidirectional + 1,
        limits.unidirectional + 1,
    };
    local_stream_limit_state_.queue_max_streams(limit_types[direction_index],
                                                limit_values[direction_index]);
}

bool QuicConnection::is_probing_only(std::span<const Frame> frames) const {
    return is_probing_only_frames(frames);
}

bool QuicConnection::can_initiate_path_validation(QuicPathId path_id) const {
    if (const auto path = paths_.find(path_id); path != paths_.end()) {
        if (path->second.destination_connection_id_override.has_value()) {
            return true;
        }
    }
    return select_peer_connection_id_sequence_for_path(path_id).has_value();
}

void QuicConnection::retire_peer_connection_id_for_inactive_path(QuicPathId old_path_id,
                                                                 QuicPathId new_path_id) {
    if (old_path_id == new_path_id) {
        return;
    }
    const auto old_path = paths_.find(old_path_id);
    if (old_path == paths_.end()) {
        return;
    }
    const auto sequence_number = old_path->second.peer_connection_id_sequence;
    const auto new_path = paths_.find(new_path_id);
    if (new_path != paths_.end() &&
        new_path->second.peer_connection_id_sequence == sequence_number) {
        return;
    }
    const auto used_by_other_path = std::ranges::any_of(paths_, [&](const auto &entry) {
        return entry.first != old_path_id && entry.first != new_path_id &&
               entry.second.peer_connection_id_sequence == sequence_number;
    });
    if (used_by_other_path) {
        return;
    }
    queue_peer_connection_id_retirement(sequence_number);
}

void QuicConnection::maybe_switch_to_path(QuicPathId path_id, bool initiated_locally,
                                          QuicCoreTimePoint now) {
    if (current_send_path_id_.has_value() && current_send_path_id_ == path_id) {
        return;
    }

    const auto existing_path = paths_.find(path_id);
    if (existing_path != paths_.end() && existing_path->second.validated) {
        if (!existing_path->second.mtu.viable) {
            return;
        }
        reset_recovery_for_new_path(path_id);
        const auto old_path_id = current_send_path_id_;
        if (current_send_path_id_.has_value()) {
            previous_path_id_ = current_send_path_id_;
            if (const auto current = paths_.find(*current_send_path_id_); current != paths_.end()) {
                current->second.is_current_send_path = false;
            }
        }
        auto &path = existing_path->second;
        path.is_current_send_path = true;
        current_send_path_id_ = path_id;
        if (old_path_id.has_value()) {
            retire_peer_connection_id_for_inactive_path(*old_path_id, path_id);
        }
        return;
    }

    if (initiated_locally && !can_initiate_path_validation(path_id)) {
        return;
    }
    start_path_validation(path_id, initiated_locally, now);
}

bool QuicConnection::anti_amplification_applies() const {
    const auto pending_response_path =
        std::find_if(paths_.begin(), paths_.end(),
                     [](const auto &entry) { return entry.second.pending_response.has_value(); });
    if (pending_response_path != paths_.end()) {
        return anti_amplification_applies(pending_response_path->first);
    }
    if (current_send_path_id_.has_value() && anti_amplification_applies(*current_send_path_id_)) {
        return true;
    }
    return config_.role == EndpointRole::server && status_ == HandshakeStatus::in_progress &&
           !peer_address_validated_;
}

bool QuicConnection::anti_amplification_applies(QuicPathId path_id) const {
    if ((config_.role != EndpointRole::server) | !paths_.contains(path_id)) {
        return false;
    }

    const auto &path = paths_.at(path_id);
    return !path.validated & ((path.anti_amplification_received_bytes != 0) |
                              (path.anti_amplification_sent_bytes != 0));
}

std::uint64_t QuicConnection::anti_amplification_send_budget() const {
    const auto pending_response_path =
        std::find_if(paths_.begin(), paths_.end(),
                     [](const auto &entry) { return entry.second.pending_response.has_value(); });
    if (pending_response_path != paths_.end()) {
        return anti_amplification_send_budget(pending_response_path->first);
    }
    if (current_send_path_id_.has_value() && anti_amplification_applies(*current_send_path_id_)) {
        return anti_amplification_send_budget(*current_send_path_id_);
    }

    constexpr auto kMaxUint64 = std::numeric_limits<std::uint64_t>::max();
    if (anti_amplification_received_bytes_ > kMaxUint64 / 3u) {
        return kMaxUint64;
    }

    return anti_amplification_received_bytes_ * 3u;
}

std::uint64_t QuicConnection::anti_amplification_send_budget(QuicPathId path_id) const {
    constexpr auto kMaxUint64 = std::numeric_limits<std::uint64_t>::max();
    const auto &path = paths_.at(path_id);
    if (path.anti_amplification_received_bytes > kMaxUint64 / 3u) {
        return kMaxUint64;
    }

    return path.anti_amplification_received_bytes * 3u;
}

std::size_t QuicConnection::outbound_datagram_size_limit(bool allow_pmtu_probe_size) const {
    auto max_datagram_size = outbound_datagram_size_limit_for_path(current_send_path_id_);

    const auto pending_response_path =
        std::find_if(paths_.begin(), paths_.end(),
                     [](const auto &entry) { return entry.second.pending_response.has_value(); });
    if (pending_response_path != paths_.end()) {
        max_datagram_size = outbound_datagram_size_limit_for_path(pending_response_path->first);
    }
    if (should_use_pending_pmtu_probe_size(allow_pmtu_probe_size, anti_amplification_applies(),
                                           application_space_.pending_probe_packet)) {
        return optional_ref_or_abort(application_space_.pending_probe_packet).pmtu_probe_size;
    }

    return max_datagram_size;
}

void QuicConnection::reset_recovery_for_new_path(QuicPathId path_id) {
    if (current_send_path_id_ == path_id) {
        return;
    }

    congestion_controller_.reset_for_new_path();
    recovery_rtt_state_ = RecoveryRttState{};
    pto_count_ = 0;
    remaining_pto_probe_datagrams_ = 0;
    initial_space_.pending_probe_packet.reset();
    handshake_space_.pending_probe_packet.reset();
    application_space_.pending_probe_packet.reset();
}

std::size_t QuicConnection::outbound_datagram_size_ceiling() const {
    return outbound_datagram_size_ceiling_for_path(current_send_path_id_);
}

std::size_t
QuicConnection::outbound_datagram_size_ceiling_for_path(std::optional<QuicPathId> path_id) const {
    auto max_datagram_size = config_.max_outbound_datagram_size;
    if (config_.transport.pmtud_max_datagram_size != 0) {
        max_datagram_size = std::min(max_datagram_size, config_.transport.pmtud_max_datagram_size);
    }
    if (peer_transport_parameters_.has_value()) {
        max_datagram_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(static_cast<std::uint64_t>(max_datagram_size),
                                    peer_transport_parameters_->max_udp_payload_size));
    }
    static_cast<void>(path_id);

    return std::min(max_datagram_size, config_.max_outbound_datagram_size);
}

std::size_t
QuicConnection::outbound_datagram_size_limit_for_path(std::optional<QuicPathId> path_id) const {
    if (path_id.has_value()) {
        if (const auto path = paths_.find(*path_id);
            path != paths_.end() && !path->second.mtu.viable) {
            return 0;
        }
    }

    auto max_datagram_size = outbound_datagram_size_ceiling_for_path(path_id);
    if (config_.transport.pmtud_enabled) {
        const auto base = sanitize_pmtud_base(config_.transport.pmtud_base_datagram_size);
        max_datagram_size = std::min(max_datagram_size, base);
        if (path_id.has_value()) {
            if (const auto path = paths_.find(*path_id); path != paths_.end()) {
                max_datagram_size =
                    std::min(std::min(outbound_datagram_size_ceiling_for_path(path_id),
                                      path->second.mtu.probe_ceiling),
                             std::max(path->second.mtu.base_datagram_size,
                                      path->second.mtu.validated_datagram_size));
            }
        }
    }

    const auto pending_response_path =
        std::find_if(paths_.begin(), paths_.end(),
                     [](const auto &entry) { return entry.second.pending_response.has_value(); });
    if (pending_response_path != paths_.end() &&
        anti_amplification_applies(pending_response_path->first)) {
        const auto remaining_budget =
            saturating_subtract(anti_amplification_send_budget(pending_response_path->first),
                                pending_response_path->second.anti_amplification_sent_bytes);
        return static_cast<std::size_t>(std::min<std::uint64_t>(
            remaining_budget, static_cast<std::uint64_t>(max_datagram_size)));
    }
    if (current_send_path_id_.has_value() && anti_amplification_applies(*current_send_path_id_)) {
        const auto &path = paths_.at(*current_send_path_id_);
        const auto remaining_budget =
            saturating_subtract(anti_amplification_send_budget(*current_send_path_id_),
                                path.anti_amplification_sent_bytes);
        return static_cast<std::size_t>(std::min<std::uint64_t>(
            remaining_budget, static_cast<std::uint64_t>(max_datagram_size)));
    }
    if (!anti_amplification_applies()) {
        return max_datagram_size;
    }

    const auto remaining_budget =
        saturating_subtract(anti_amplification_send_budget(), anti_amplification_sent_bytes_);
    return static_cast<std::size_t>(
        std::min<std::uint64_t>(remaining_budget, static_cast<std::uint64_t>(max_datagram_size)));
}

std::optional<std::size_t> QuicConnection::next_pmtu_probe_size(PathState &path) const {
    if (!path.mtu.enabled || !path.mtu.viable ||
        path.mtu.outstanding_probe_packet_number.has_value()) {
        return std::nullopt;
    }

    const auto ceiling = outbound_datagram_size_ceiling_for_path(path.id);
    path.mtu.probe_ceiling = std::min(path.mtu.probe_ceiling, ceiling);
    if (path.mtu.validated_datagram_size >= path.mtu.probe_ceiling) {
        return std::nullopt;
    }

    auto next_probe_size =
        next_probe_size_between(path.mtu.validated_datagram_size, path.mtu.probe_ceiling);
    while (should_keep_searching_for_pmtu_probe_size(path.mtu, next_probe_size)) {
        if (connection_drain_test_hooks().force_next_pmtu_probe_size_zero) {
            next_probe_size = 0;
        }
        if (next_probe_size == 0) {
            return std::nullopt;
        }
        path.mtu.probe_ceiling = next_probe_size - 1;
        if (path.mtu.validated_datagram_size >= path.mtu.probe_ceiling) {
            return std::nullopt;
        }
        next_probe_size =
            next_probe_size_between(path.mtu.validated_datagram_size, path.mtu.probe_ceiling);
    }
    return next_probe_size;
}

void QuicConnection::note_pmtu_probe_sent(
    QuicPathId path_id, // NOLINT(bugprone-easily-swappable-parameters)
    std::uint64_t packet_number, std::size_t datagram_size) {
    auto &path = ensure_path_state(path_id);
    path.mtu.outstanding_probe_size = datagram_size;
    path.mtu.outstanding_probe_packet_number = packet_number;
    path.mtu.next_probe_time.reset();
}

COQUIC_NO_PROFILE void QuicConnection::maybe_note_pmtu_probe_sent_for_tracking(
    const std::optional<std::size_t> &pmtu_probe_size, const SentPacketRecord &packet) {
    if (pmtu_probe_size.has_value()) {
        note_pmtu_probe_sent(packet.path_id, packet.packet_number, *pmtu_probe_size);
    }
}

void QuicConnection::note_pmtu_probe_acked(const SentPacketRecord &packet, QuicCoreTimePoint now) {
    if (!packet.is_pmtu_probe) {
        return;
    }

    auto &path = ensure_path_state(packet.path_id);
    const auto probe_size = packet.pmtu_probe_size != 0
                                ? std::optional<std::size_t>{packet.pmtu_probe_size}
                                : path.mtu.outstanding_probe_size;
    if (!probe_size.has_value()) {
        return;
    }

    const auto ceiling = outbound_datagram_size_ceiling_for_path(packet.path_id);
    const auto validated_size =
        std::min(std::max(path.mtu.validated_datagram_size, *probe_size), ceiling);
    if (validated_size > path.mtu.validated_datagram_size) {
        path.mtu.validated_datagram_size = validated_size;
        path.mtu.search_low = validated_size;
        path.mtu.probe_ceiling = std::max(path.mtu.probe_ceiling, validated_size);
    }
    forget_pmtud_failed_probe_size(path.mtu, *probe_size);
    if (should_clear_outstanding_pmtu_probe(path.mtu, packet.packet_number)) {
        path.mtu.outstanding_probe_size.reset();
        path.mtu.outstanding_probe_packet_number.reset();
    }
    path.mtu.next_probe_time = pmtud_next_probe_time(path.mtu, now, std::chrono::seconds(1));
}

void QuicConnection::note_pmtu_probe_lost(const SentPacketRecord &packet, QuicCoreTimePoint now) {
    if (!packet.is_pmtu_probe) {
        return;
    }

    auto &path = ensure_path_state(packet.path_id);
    if (should_clear_outstanding_pmtu_probe(path.mtu, packet.packet_number)) {
        if (packet.pmtu_probe_size > path.mtu.validated_datagram_size) {
            remember_pmtud_failed_probe_size(path.mtu, packet.pmtu_probe_size);
            path.mtu.probe_ceiling = std::min(path.mtu.probe_ceiling, packet.pmtu_probe_size - 1);
        }
        path.mtu.outstanding_probe_size.reset();
        path.mtu.outstanding_probe_packet_number.reset();
    }
    path.mtu.next_probe_time = pmtud_next_probe_time(path.mtu, now, std::chrono::milliseconds(100));
}

void QuicConnection::note_inbound_datagram_bytes(std::size_t bytes) {
    if (bytes == 0) {
        return;
    }

    if (status_ == HandshakeStatus::connected) {
        auto &path = ensure_path_state(last_inbound_path_id_);
        const auto received = path.anti_amplification_received_bytes;
        const auto increment = static_cast<std::uint64_t>(bytes);
        path.anti_amplification_received_bytes =
            received > std::numeric_limits<std::uint64_t>::max() - increment
                ? std::numeric_limits<std::uint64_t>::max()
                : received + increment;
        return;
    }
    if (!anti_amplification_applies()) {
        return;
    }

    const auto received = anti_amplification_received_bytes_;
    const auto increment = static_cast<std::uint64_t>(bytes);
    anti_amplification_received_bytes_ =
        received > std::numeric_limits<std::uint64_t>::max() - increment
            ? std::numeric_limits<std::uint64_t>::max()
            : received + increment;
}

void QuicConnection::note_outbound_datagram_bytes(std::size_t bytes,
                                                  std::optional<QuicPathId> path_id,
                                                  std::optional<QuicCoreTimePoint> now) {
    if (bytes == 0) {
        return;
    }

    const auto effective_path_id = path_id.has_value() ? path_id : current_send_path_id_;
    if (effective_path_id.has_value()) {
        auto path_it = paths_.find(*effective_path_id);
        if (path_it == paths_.end()) {
            return;
        }
        auto &path = path_it->second;
        if (should_arm_pmtu_probe_after_send(path.mtu, application_space_.write_secret.has_value(),
                                             has_pending_application_send())) {
            path.mtu.next_probe_time =
                now.value_or(QuicCoreClock::now()) + std::chrono::milliseconds(10);
        }
    }
    if (effective_path_id.has_value() && anti_amplification_applies(*effective_path_id)) {
        auto &path = ensure_path_state(*effective_path_id);
        const auto sent = path.anti_amplification_sent_bytes;
        const auto increment = static_cast<std::uint64_t>(bytes);
        path.anti_amplification_sent_bytes =
            sent > std::numeric_limits<std::uint64_t>::max() - increment
                ? std::numeric_limits<std::uint64_t>::max()
                : sent + increment;
        return;
    }
    if (!anti_amplification_applies()) {
        return;
    }

    const auto sent = anti_amplification_sent_bytes_;
    const auto increment = static_cast<std::uint64_t>(bytes);
    anti_amplification_sent_bytes_ = sent > std::numeric_limits<std::uint64_t>::max() - increment
                                         ? std::numeric_limits<std::uint64_t>::max()
                                         : sent + increment;
}

void QuicConnection::note_idle_peer_activity(QuicCoreTimePoint now) {
    last_peer_activity_time_ = now;
    idle_timeout_base_time_ = now;
    ack_eliciting_sent_since_idle_reset_ = false;
}

void QuicConnection::note_idle_ack_eliciting_send(QuicCoreTimePoint now) {
    if (ack_eliciting_sent_since_idle_reset_) {
        return;
    }

    idle_timeout_base_time_ = now;
    ack_eliciting_sent_since_idle_reset_ = true;
}

void QuicConnection::mark_peer_address_validated() {
    peer_address_validated_ = true;
    if (current_send_path_id_.has_value()) {
        auto &path = ensure_path_state(*current_send_path_id_);
        path.validated = true;
        path.challenge_pending = false;
        path.validation_initiated_locally = false;
        path.outstanding_challenge.reset();
        path.validation_deadline.reset();
        last_validated_path_id_ = current_send_path_id_;
    }
}

void QuicConnection::set_path_peer_connection_id_sequence(PathState &path,
                                                          std::uint64_t sequence_number) {
    if (path.peer_connection_id_sequence == sequence_number) {
        return;
    }

    path.peer_connection_id_sequence = sequence_number;
    path.spin.value = false;
    path.spin.largest_peer_packet_number.reset();
}

void QuicConnection::update_spin_bit_on_receive(QuicPathId path_id, bool peer_spin_bit,
                                                std::uint64_t packet_number) {
    if (latency_spin_bit_disabled_) {
        return;
    }
    auto &path = ensure_path_state(path_id);
    if (path.spin.disabled) {
        return;
    }
    if (path.spin.largest_peer_packet_number.has_value() &&
        packet_number <= *path.spin.largest_peer_packet_number) {
        return;
    }

    path.spin.largest_peer_packet_number = packet_number;
    path.spin.value =
        config_.role == EndpointRole::server ? peer_spin_bit : static_cast<bool>(!peer_spin_bit);
}

bool QuicConnection::outbound_spin_bit_for_path(std::optional<QuicPathId> path_id) const {
    if (latency_spin_bit_disabled_) {
        return false;
    }
    const auto effective_path_id = path_id.has_value() ? path_id : current_send_path_id_;
    if (!effective_path_id.has_value()) {
        return false;
    }

    const auto path = paths_.find(*effective_path_id);
    if (path == paths_.end() || path->second.spin.disabled) {
        return false;
    }
    return path->second.spin.value;
}

void QuicConnection::disable_ecn_on_path(QuicPathId path_id) {
    auto &path = ensure_path_state(path_id);
    path.ecn.state = QuicPathEcnState::failed;
    path.ecn.has_last_peer_counts.fill(false);
    path.ecn.last_peer_counts = {};
    path.ecn.probing_packets_sent = 0;
    path.ecn.probing_packets_acked = 0;
    path.ecn.probing_packets_lost = 0;
}

QuicEcnCodepoint
QuicConnection::outbound_ecn_codepoint_for_path(std::optional<QuicPathId> path_id) const {
    const auto effective_path_id = path_id.has_value() ? path_id : current_send_path_id_;
    if (!effective_path_id.has_value()) {
        return QuicEcnCodepoint::not_ect;
    }

    const auto path = paths_.find(*effective_path_id);
    if (path == paths_.end() || path->second.ecn.state == QuicPathEcnState::failed ||
        !is_ect_codepoint(path->second.ecn.transmit_mark)) {
        return QuicEcnCodepoint::not_ect;
    }

    return path->second.ecn.transmit_mark;
}

ConnectionId
QuicConnection::outbound_destination_connection_id(std::optional<QuicPathId> path_id) const {
    if (path_id.has_value()) {
        if (const auto path = paths_.find(*path_id); path != paths_.end()) {
            const auto &destination_connection_id_override =
                path->second.destination_connection_id_override;
            if (destination_connection_id_override.has_value()) {
                return destination_connection_id_override.value();
            }
            if (const auto peer_connection_id =
                    peer_connection_ids_.find(path->second.peer_connection_id_sequence);
                peer_connection_id != peer_connection_ids_.end() &&
                !peer_connection_id->second.locally_retired) {
                return peer_connection_id->second.connection_id;
            }
        }
    }

    return active_peer_destination_connection_id();
}

ConnectionId QuicConnection::client_initial_destination_connection_id() const {
    if (client_initial_destination_connection_id_.has_value()) {
        return client_initial_destination_connection_id_.value();
    }

    return config_.initial_destination_connection_id;
}

DatagramBuffer QuicConnection::flush_outbound_datagram(QuicCoreTimePoint now) {
    register_send_profile_printer_once();
    if (send_profile_enabled()) {
        ++send_profile_counters().drain_calls;
    }
    if (close_mode_ == QuicConnectionCloseMode::draining) {
        return {};
    }
    maybe_arm_pmtu_probe(now);
    const auto pmtu_probe_pending = application_space_.pending_probe_packet.has_value() &&
                                    application_space_.pending_probe_packet->is_pmtu_probe;
    const auto max_outbound_datagram_size =
        outbound_datagram_size_limit(!has_pending_application_send());
    const auto pmtu_probe_datagram_size_limit =
        pmtu_probe_pending ? outbound_datagram_size_limit(/*allow_pmtu_probe_size=*/true)
                           : max_outbound_datagram_size;
    const bool traces_this_connection =
        packet_trace_matches_connection(config_.source_connection_id);
    if (max_outbound_datagram_size == 0) {
        if (traces_this_connection) {
            const auto *current_path = find_path_state(paths_, current_send_path_id_);
            const std::string_view blocked_reason =
                current_path != nullptr && !current_path->mtu.viable ? "pmtu-below-minimum"
                                                                     : "amp-budget-zero";
            std::cerr << "quic-packet-trace send-blocked scid="
                      << format_connection_id_hex(config_.source_connection_id)
                      << " reason=" << blocked_reason
                      << " current=" << format_optional_path_id(current_send_path_id_)
                      << " previous=" << format_optional_path_id(previous_path_id_)
                      << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                      << " current_path={" << format_path_state_summary(current_path)
                      << "} inbound_path={"
                      << format_path_state_summary(find_path_state(paths_, last_inbound_path_id_))
                      << "} pending_send=" << static_cast<int>(has_pending_application_send())
                      << " probe="
                      << static_cast<int>(application_space_.pending_probe_packet.has_value())
                      << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                      << '\n';
        }
        return {};
    }

    if (config_.role == EndpointRole::client && application_space_.write_secret.has_value() &&
        zero_rtt_space_.write_secret.has_value()) {
        discard_packet_space_state(zero_rtt_space_);
    }
    queue_client_handshake_recovery_probe();
    const bool client_will_send_handshake_packet =
        (config_.role == EndpointRole::client) & !initial_packet_space_discarded_ &
        initial_space_.pending_probe_packet.has_value() &
        !initial_space_.send_crypto.has_pending_data() &
        !initial_space_.received_packets.has_ack_to_send() & !handshake_packet_space_discarded_ &
        handshake_space_.write_secret.has_value() &
        (handshake_space_.send_crypto.has_pending_data() ||
         handshake_space_.pending_probe_packet.has_value());
    if (client_will_send_handshake_packet) {
        discard_initial_packet_space();
    }

    auto packets = std::vector<ProtectedPacket>{};
    auto selected_send_path_id = current_send_path_id_;
    const auto destination_connection_id = outbound_destination_connection_id();
    const auto application_destination_connection_id = [&]() {
        return outbound_destination_connection_id(selected_send_path_id);
    };
    const auto initial_destination_connection_id = config_.role == EndpointRole::client
                                                       ? client_initial_destination_connection_id()
                                                       : destination_connection_id;
    const bool duplicate_first_compatible_server_initial_crypto =
        !initial_packet_space_discarded_ & (config_.role == EndpointRole::server) &
        (original_version_ != current_version_) & (initial_space_.next_send_packet_number == 0) &
        (handshake_space_.next_send_packet_number == 0);
    const bool initial_probe_pending =
        !initial_packet_space_discarded_ && initial_space_.pending_probe_packet.has_value();
    const bool handshake_probe_pending =
        !handshake_packet_space_discarded_ && handshake_space_.pending_probe_packet.has_value();
    const bool application_probe_pending = application_space_.pending_probe_packet.has_value();
    const auto pto_probe_burst_active =
        (remaining_pto_probe_datagrams_ > 0) &
        (initial_probe_pending | handshake_probe_pending | application_probe_pending);
    const auto preserve_pto_probe_packets =
        pto_probe_burst_active && remaining_pto_probe_datagrams_ > 1;
    const bool track_client_handshake_keepalive_probes = (config_.role == EndpointRole::client) &
                                                         (status_ == HandshakeStatus::in_progress) &
                                                         !handshake_confirmed_;
    const auto clear_probe_packet_after_send =
        [&](std::optional<SentPacketRecord> &pending_probe_packet) {
            if (pending_probe_packet.has_value() && !preserve_pto_probe_packets) {
                pending_probe_packet = std::nullopt;
            }
        };
    const auto note_client_handshake_keepalive_probe = [&](const SentPacketRecord &sent_packet) {
        if (!sent_packet.has_ping || retransmittable_probe_frame_count(sent_packet) != 0) {
            return;
        }

        last_client_handshake_keepalive_probe_time_ = now;
    };
    auto &pending_tracked_packets = pending_tracked_packet_scratch_;
    pending_tracked_packets.clear();
    if (pending_tracked_packets.capacity() < 4) {
        pending_tracked_packets.reserve(4);
    }
    struct PendingTrackedPacketScratchGuard {
        std::vector<PendingTrackedPacketScratch> &packets;
        ~PendingTrackedPacketScratchGuard() {
            packets.clear();
        }
    } pending_tracked_packets_guard{pending_tracked_packets};
    const auto queue_tracked_packet_at_index =
        [&](PacketSpaceState &packet_space, SentPacketRecord packet, std::size_t packet_index,
            std::size_t fallback_packet_length) {
            pending_tracked_packets.push_back(PendingTrackedPacketScratch{
                .packet_space = &packet_space,
                .packet = std::move(packet),
                .packet_index = packet_index,
                .fallback_packet_length = fallback_packet_length,
            });
        };
    const auto queue_tracked_packet = [&](PacketSpaceState &packet_space, SentPacketRecord packet,
                                          std::size_t fallback_packet_length) {
        queue_tracked_packet_at_index(packet_space, std::move(packet), packets.size() - 1,
                                      fallback_packet_length);
    };
    const auto track_pending_packets = [&](auto &&packet_length_for_pending,
                                           std::optional<std::size_t> datagram_size =
                                               std::nullopt) -> bool {
        for (auto &pending : pending_tracked_packets) {
            const auto packet_length = packet_length_for_pending(pending);
            if (!packet_length.has_value()) {
                return false;
            }

            auto sent_packet = std::move(pending.packet);
            sent_packet.bytes_in_flight =
                *packet_length *
                static_cast<std::size_t>(sent_packet.ack_eliciting & sent_packet.in_flight);
            const auto pmtu_probe_size =
                prepare_pmtu_probe_packet_for_tracking(sent_packet, datagram_size, *packet_length);
            maybe_note_pmtu_probe_sent_for_tracking(pmtu_probe_size, sent_packet);
            track_sent_packet(*pending.packet_space, std::move(sent_packet));
        }
        pending_tracked_packets.clear();
        return true;
    };
    const auto track_pending_packets_from_datagram =
        [&](const SerializedProtectedDatagram &datagram) -> bool {
        return track_pending_packets(
            [&](const PendingTrackedPacketScratch &pending) {
                if (connection_drain_test_hooks().force_missing_packet_metadata |
                    (pending.packet_index >= datagram.packet_metadata.size())) {
                    return std::optional<std::size_t>{};
                }
                return std::optional<std::size_t>{
                    datagram.packet_metadata[pending.packet_index].length,
                };
            },
            datagram.bytes.size());
    };
    const auto preserve_pending_tracked_packets = [&]() -> bool {
        return track_pending_packets([&](const PendingTrackedPacketScratch &pending) {
            if (connection_drain_test_hooks().force_missing_fallback_packet_length |
                (pending.fallback_packet_length == 0)) {
                return std::optional<std::size_t>{};
            }
            return std::optional<std::size_t>{pending.fallback_packet_length};
        });
    };
    const auto congestion_blocks_datagram = [&](std::size_t bytes, bool bypass_congestion_window) {
        if (duplicate_initial_congestion_is_forced(
                connection_drain_test_hooks().force_duplicate_initial_congestion_blocked,
                bypass_congestion_window, !packets.empty())) {
            return true;
        }
        if (application_send_congestion_is_forced(
                connection_drain_test_hooks().force_application_send_congestion_blocked,
                bypass_congestion_window, application_space_)) {
            return true;
        }
        if (bypass_congestion_window) {
            return false;
        }
        if (!congestion_controller_.can_send_ack_eliciting(bytes)) {
            return true;
        }
        const auto pacing_deadline = congestion_controller_.next_send_time(bytes);
        return static_cast<bool>(pacing_deadline.has_value() &
                                 (now < pacing_deadline.value_or(now)));
    };
    const bool defer_server_compatible_negotiation_crypto =
        (config_.role == EndpointRole::server) && (original_version_ != current_version_) &&
        !peer_transport_parameters_validated_;
    const auto initial_packet_version =
        defer_server_compatible_negotiation_crypto ? original_version_ : current_version_;
    static const std::vector<std::byte> kEmptyInitialToken;
    const std::vector<std::byte> &initial_token =
        config_.role == EndpointRole::client ? config_.retry_token : kEmptyInitialToken;
    const auto make_serialize_context = [&]() -> CodecResult<SerializeProtectionContext> {
        const auto handshake_ready = prime_traffic_secret_cache(handshake_space_.write_secret);
        if (!handshake_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(handshake_ready.error().code,
                                                                    handshake_ready.error().offset);
        }

        const auto zero_rtt_ready = prime_traffic_secret_cache(zero_rtt_space_.write_secret);
        if (!zero_rtt_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(zero_rtt_ready.error().code,
                                                                    zero_rtt_ready.error().offset);
        }

        const auto one_rtt_ready = prime_traffic_secret_cache(application_space_.write_secret);
        if (!one_rtt_ready.has_value()) {
            return CodecResult<SerializeProtectionContext>::failure(one_rtt_ready.error().code,
                                                                    one_rtt_ready.error().offset);
        }

        return CodecResult<SerializeProtectionContext>::success(SerializeProtectionContext{
            .local_role = config_.role,
            .client_initial_destination_connection_id = client_initial_destination_connection_id(),
            .handshake_secret = handshake_space_.write_secret,
            .zero_rtt_secret = zero_rtt_space_.write_secret,
            .one_rtt_secret = application_space_.write_secret,
            .one_rtt_key_phase = application_write_key_phase_,
        });
    };

    const auto serialize_candidate_datagram_with_metadata =
        [&](const std::vector<ProtectedPacket> &candidate_packets,
            const ProtectedPacket *appended_packet = nullptr,
            const ProtectedOneRttPacketFragmentView *appended_one_rtt_fragment_packet =
                nullptr) -> CodecResult<SerializedProtectedDatagram> {
        if (send_profile_enabled()) {
            ++send_profile_counters().serialize_calls;
        }
        SendProfileTimer serialize_timer(send_profile_counters().serialize_ns);
        auto datagram_packets = candidate_packets;
        const auto context = make_serialize_context();
        if (!context.has_value()) {
            return CodecResult<SerializedProtectedDatagram>::failure(context.error().code,
                                                                     context.error().offset);
        }

        const auto serialize_datagram = [&](const SerializeProtectionContext &serialize_context)
            -> CodecResult<SerializedProtectedDatagram> {
            if (appended_one_rtt_fragment_packet != nullptr) {
                auto encoded =
                    serialize_protected_datagram_with_metadata(datagram_packets, serialize_context);
                if (connection_drain_test_hooks().force_appended_fragment_base_datagram_failure) {
                    encoded = CodecResult<SerializedProtectedDatagram>::failure(
                        CodecErrorCode::packet_length_mismatch, 0);
                }
                if (!encoded.has_value()) {
                    return encoded;
                }
                const auto offset = encoded.value().bytes.size();
                const auto appended = append_protected_one_rtt_packet_to_datagram(
                    encoded.value().bytes, *appended_one_rtt_fragment_packet, serialize_context);
                if (!appended.has_value()) {
                    return CodecResult<SerializedProtectedDatagram>::failure(
                        appended.error().code, appended.error().offset);
                }
                encoded.value().packet_metadata.push_back(SerializedProtectedPacketMetadata{
                    .offset = offset,
                    .length = appended.value(),
                });
                return encoded;
            }
            if (appended_packet == nullptr) {
                return serialize_protected_datagram_with_metadata(datagram_packets,
                                                                  serialize_context);
            }
            return serialize_protected_datagram_with_metadata(datagram_packets, *appended_packet,
                                                              serialize_context);
        };

        const auto &serialize_context = context.value();
        if (consume_connection_drain_countdown(
                &ConnectionDrainTestHooks::
                    force_candidate_datagram_serialization_failure_countdown)) {
            return CodecResult<SerializedProtectedDatagram>::failure(
                CodecErrorCode::packet_length_mismatch, 0);
        }
        auto datagram = serialize_datagram(serialize_context);
        if (!datagram.has_value()) {
            return datagram;
        }

        if (datagram.value().bytes.size() >= kMinimumInitialDatagramSize) {
            return datagram;
        }

        for (auto &packet : datagram_packets) {
            auto *initial = std::get_if<ProtectedInitialPacket>(&packet);
            if (initial == nullptr) {
                continue;
            }

            const auto frames_without_padding = initial->frames;
            const auto padding_deficit =
                kMinimumInitialDatagramSize - datagram.value().bytes.size();
            const auto serialize_padded_initial =
                [&](std::size_t padding_length) -> CodecResult<SerializedProtectedDatagram> {
                initial->frames = frames_without_padding;
                initial->frames.insert(initial->frames.end(),
                                       static_cast<std::size_t>(padding_length != 0),
                                       Frame{PaddingFrame{
                                           .length = padding_length,
                                       }});

                return serialize_datagram(serialize_context);
            };

            auto padded_datagram = serialize_padded_initial(padding_deficit);
            if (!padded_datagram.has_value()) {
                return padded_datagram;
            }

            if (padded_datagram.value().bytes.size() == kMinimumInitialDatagramSize) {
                return CodecResult<SerializedProtectedDatagram>::success(
                    std::move(padded_datagram.value()));
            }

            // Padding here only adjusts a single Initial packet. The only reachable size jump in
            // this path is the one-byte growth of the long-header length varint, so retrying with
            // one less byte covers the alternate exact-1200 serialization.
            auto alternate_padded_datagram = serialize_padded_initial(padding_deficit - 1);
            if (!alternate_padded_datagram.has_value()) {
                return alternate_padded_datagram;
            }
            return CodecResult<SerializedProtectedDatagram>::success(
                std::move(alternate_padded_datagram.value()));
        }

        return datagram;
    };
    const auto commit_serialized_datagram =
        [&](const std::vector<ProtectedPacket> &datagram_packets,
            SerializedProtectedDatagram datagram) -> DatagramBuffer {
        SendProfileTimer commit_timer(send_profile_counters().commit_ns);
        const bool pmtu_probe_datagram = std::ranges::any_of(
            pending_tracked_packets, [](const PendingTrackedPacketScratch &pending) {
                return pending.packet.is_pmtu_probe;
            });
        if (!track_pending_packets_from_datagram(datagram)) {
            mark_failed();
            return {};
        }

        if (pto_probe_burst_active) {
            --remaining_pto_probe_datagrams_;
            if (remaining_pto_probe_datagrams_ == 0) {
                initial_space_.pending_probe_packet = std::nullopt;
                handshake_space_.pending_probe_packet = std::nullopt;
                application_space_.pending_probe_packet = std::nullopt;
            }
        }

        if (config_.role == EndpointRole::client) {
            for (const auto &packet : datagram_packets) {
                if (std::holds_alternative<ProtectedHandshakePacket>(packet)) {
                    discard_initial_packet_space();
                    break;
                }
            }
        }

        if (qlog_session_ != nullptr) {
            const auto outbound_datagram_id =
                std::optional<std::uint32_t>(qlog_session_->next_outbound_datagram_id());
            for (std::size_t index = 0; index < datagram_packets.size(); ++index) {
                const auto packet_number =
                    std::visit([](const auto &packet_value) { return packet_value.packet_number; },
                               datagram_packets[index]);
                auto snapshot = make_qlog_packet_snapshot(
                    datagram_packets[index],
                    qlog::PacketSnapshotContext{
                        .raw_length = datagram.packet_metadata[index].length,
                        .datagram_id = *outbound_datagram_id,
                        .trigger = pto_probe_burst_active ? std::optional<std::string>("pto_probe")
                                                          : std::nullopt,
                    });
                static_cast<void>(qlog_session_->write_event(
                    now, "quic:packet_sent", qlog::serialize_packet_snapshot(snapshot)));
                auto snapshot_ptr = std::make_shared<qlog::PacketSnapshot>(snapshot);

                for (auto *packet_space :
                     {&initial_space_, &handshake_space_, &application_space_}) {
                    auto *sent = packet_space->recovery.find_packet(packet_number);
                    if (sent == nullptr) {
                        continue;
                    }

                    sent->qlog_packet_snapshot = snapshot_ptr;
                    sent->qlog_pto_probe = pto_probe_burst_active;
                    packet_space->recovery.note_packet_metadata_updated();
                }
            }
        }

        note_outbound_datagram_bytes(datagram.bytes.size(), selected_send_path_id, now);
        last_drained_path_id_ = selected_send_path_id;
        last_drained_ecn_codepoint_ = outbound_ecn_codepoint_for_path(selected_send_path_id);
        last_drained_is_pmtu_probe_ = pmtu_probe_datagram;
        if (config_.enable_packet_inspection) {
            const auto datagram_id = next_packet_inspection_datagram_id_++;
            const auto inspection_count = queue_outbound_packet_inspections(datagram, datagram_id);
            maybe_record_packet_inspection_datagram_id(last_drained_packet_inspection_datagram_id_,
                                                       PacketInspectionDatagramId{datagram_id},
                                                       PacketInspectionCount{inspection_count});
        }
        if (send_profile_enabled()) {
            auto &profile = send_profile_counters();
            SendProfileTimer timer(profile.commit_ns);
            ++profile.datagrams;
            profile.bytes += datagram.bytes.size();
            profile.max_datagram =
                std::max<std::uint64_t>(profile.max_datagram, datagram.bytes.size());
            profile.pmtu_probe_datagrams += static_cast<std::uint64_t>(pmtu_probe_datagram);
            profile.datagrams_le_1200 += static_cast<std::uint64_t>(datagram.bytes.size() <= 1200);
            profile.datagrams_le_1434 += static_cast<std::uint64_t>(datagram.bytes.size() <= 1434);
            profile.datagrams_le_1472 += static_cast<std::uint64_t>(datagram.bytes.size() <= 1472);
            profile.datagrams_gt_1472 += static_cast<std::uint64_t>(datagram.bytes.size() > 1472);
        }
        return std::move(datagram.bytes);
    };
    const auto fail_datagram_send = [&](bool preserve_pending_packets = false) -> DatagramBuffer {
        if (preserve_pending_packets && !preserve_pending_tracked_packets()) {
            mark_failed();
            return {};
        }
        mark_failed();
        return {};
    };
    const auto finalize_datagram =
        [&](const std::vector<ProtectedPacket> &datagram_packets) -> DatagramBuffer {
        auto datagram = serialize_candidate_datagram_with_metadata(datagram_packets);
        if (!datagram.has_value()) {
            return fail_datagram_send(/*preserve_pending_packets=*/true);
        }

        return commit_serialized_datagram(datagram_packets, std::move(datagram.value()));
    };
    if (close_mode_ == QuicConnectionCloseMode::closing) {
        if (!closing_close_packet_pending_ || !can_send_connection_close_frame()) {
            return {};
        }
        const auto close_frame = connection_close_frame_for_send();
        if (!close_frame.has_value()) {
            return {};
        }
        auto close_packet_space = &application_space_;
        ProtectedPacket packet =
            application_space_.write_secret.has_value()
                ? make_application_protected_packet(
                      /*use_zero_rtt_packet_protection=*/false, current_version_,
                      application_destination_connection_id(), config_.source_connection_id,
                      application_write_key_phase_, kDefaultInitialPacketNumberLength,
                      reserve_packet_number(application_space_), std::vector<Frame>{*close_frame},
                      {})
                : (handshake_space_.write_secret.has_value()
                       ? ProtectedPacket{ProtectedHandshakePacket{
                             .version = current_version_,
                             .destination_connection_id = destination_connection_id,
                             .source_connection_id = config_.source_connection_id,
                             .packet_number_length = kDefaultInitialPacketNumberLength,
                             .packet_number = reserve_packet_number(handshake_space_),
                             .frames = std::vector<Frame>{*close_frame},
                         }}
                       : ProtectedPacket{ProtectedInitialPacket{
                             .version = initial_packet_version,
                             .destination_connection_id = initial_destination_connection_id,
                             .source_connection_id = config_.source_connection_id,
                             .token = initial_token,
                             .packet_number_length = kDefaultInitialPacketNumberLength,
                             .packet_number = reserve_packet_number(initial_space_),
                             .frames = std::vector<Frame>{*close_frame},
                         }});
        set_application_packet_spin_bit(packet, outbound_spin_bit_for_path(selected_send_path_id));
        if (std::holds_alternative<ProtectedInitialPacket>(packet)) {
            close_packet_space = &initial_space_;
        } else if (std::holds_alternative<ProtectedHandshakePacket>(packet)) {
            close_packet_space = &handshake_space_;
        }
        std::vector<ProtectedPacket> close_packets{packet};
        auto candidate = serialize_candidate_datagram_with_metadata(close_packets);
        if (!candidate.has_value()) {
            return {};
        }
        queue_tracked_packet_at_index(
            *close_packet_space,
            SentPacketRecord{
                .packet_number = packet_number_for_sent_record(packet),
                .sent_time = now,
                .ack_eliciting = false,
                .in_flight = false,
                .declared_lost = false,
                .path_id = selected_send_path_id.value_or(0),
                .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
            },
            /*packet_index=*/0, close_packet_metadata_length_for_tracking(candidate.value()));
        mark_connection_close_frame_sent(*close_frame, now);
        last_drained_path_id_ = selected_send_path_id;
        last_drained_ecn_codepoint_ = outbound_ecn_codepoint_for_path(selected_send_path_id);
        last_drained_is_pmtu_probe_ = false;
        return commit_serialized_datagram(close_packets, std::move(candidate.value()));
    }
    const auto trim_crypto_ranges_to_fit = [&](auto &&serialize_with_crypto_ranges,
                                               auto &&restore_trimmed_crypto,
                                               std::vector<ByteRange> &crypto_ranges) {
        auto datagram = serialize_with_crypto_ranges(crypto_ranges);
        if (!datagram.has_value()) {
            return datagram;
        }

        while (datagram_size_or_zero(datagram) > max_outbound_datagram_size &&
               !crypto_ranges.empty()) {
            auto &last_range = crypto_ranges.back();
            const auto overshoot = datagram_size_or_zero(datagram) - max_outbound_datagram_size;
            const auto trim_bytes = std::min<std::size_t>(overshoot, last_range.bytes.size());
            if (trim_bytes == last_range.bytes.size()) {
                restore_trimmed_crypto(last_range.offset, last_range.bytes.size());
                crypto_ranges.pop_back();
            } else {
                const auto retained_bytes = last_range.bytes.size() - trim_bytes;
                restore_trimmed_crypto(last_range.offset + retained_bytes, trim_bytes);
                last_range.bytes.resize(retained_bytes);
            }

            datagram = serialize_with_crypto_ranges(crypto_ranges);
            if (!datagram.has_value()) {
                return datagram;
            }
        }

        return datagram;
    };

    const auto initial_ack_frame =
        initial_packet_space_discarded_
            ? std::optional<AckFrame>{}
            : ((initial_space_.pending_probe_packet.has_value() &&
                initial_space_.pending_probe_packet->force_ack)
                   ? initial_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now,
                                                                     /*allow_non_pending=*/true)
                   : initial_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0,
                                                                     now));
    auto initial_crypto_ranges = std::vector<ByteRange>{};
    if (!initial_packet_space_discarded_ && !defer_server_compatible_negotiation_crypto) {
        initial_crypto_ranges =
            initial_space_.send_crypto.take_ranges(std::numeric_limits<std::size_t>::max());
    }
    const auto should_add_server_handshake_keepalive_ping =
        [&](const PacketSpaceState &packet_space) {
            return config_.role == EndpointRole::server && !handshake_confirmed_ &&
                   !packet_space.pending_probe_packet.has_value() &&
                   !has_in_flight_ack_eliciting_packet(packet_space);
        };
    const auto build_initial_frames = [&](std::span<const ByteRange> crypto_ranges) {
        std::vector<Frame> frames;
        frames.reserve(crypto_ranges.size() + (initial_ack_frame.has_value() ? 1u : 0u) +
                       (initial_space_.pending_probe_packet.has_value()
                            ? initial_space_.pending_probe_packet->crypto_ranges.size() + 1u
                            : 0u));
        for (const auto &range : crypto_ranges) {
            frames.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
        if (initial_ack_frame.has_value() && crypto_ranges.empty()) {
            frames.emplace_back(*initial_ack_frame);
        }
        if (initial_ack_frame.has_value() && !has_ack_eliciting_frame(frames) &&
            should_add_server_handshake_keepalive_ping(initial_space_)) {
            frames.emplace_back(PingFrame{});
        }
        if (!defer_server_compatible_negotiation_crypto &&
            initial_space_.pending_probe_packet.has_value() && !has_ack_eliciting_frame(frames)) {
            for (const auto &range : initial_space_.pending_probe_packet->crypto_ranges) {
                frames.emplace_back(CryptoFrame{
                    .offset = range.offset,
                    .crypto_data = range.bytes.to_vector(),
                });
            }
            if (!has_ack_eliciting_frame(frames)) {
                frames.emplace_back(PingFrame{});
            }
        }

        return frames;
    };
    auto initial_frames = initial_packet_space_discarded_
                              ? std::vector<Frame>{}
                              : build_initial_frames(initial_crypto_ranges);
    if (!initial_frames.empty()) {
        std::optional<std::uint64_t> initial_packet_number;
        const bool duplicate_compatible_negotiation_initial_crypto =
            duplicate_first_compatible_server_initial_crypto && !initial_crypto_ranges.empty();
        auto sent_initial_crypto_ranges = initial_crypto_ranges;
        const auto serialize_initial_candidate = [&](std::span<const ByteRange> crypto_ranges)
            -> CodecResult<SerializedProtectedDatagram> {
            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedInitialPacket{
                .version = initial_packet_version,
                .destination_connection_id = initial_destination_connection_id,
                .source_connection_id = config_.source_connection_id,
                .token = initial_token,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = initial_space_.next_send_packet_number,
                .frames = build_initial_frames(crypto_ranges),
            });
            return serialize_candidate_datagram_with_metadata(candidate_packets);
        };
        auto initial_candidate_datagram = trim_crypto_ranges_to_fit(
            serialize_initial_candidate,
            [&](std::uint64_t offset, std::size_t length) {
                initial_space_.send_crypto.mark_unsent(offset, length);
            },
            sent_initial_crypto_ranges);
        if (!initial_candidate_datagram.has_value()) {
            return fail_datagram_send(!pending_tracked_packets.empty());
        }
        auto sent_initial_frames = build_initial_frames(sent_initial_crypto_ranges);
        const bool initial_ack_eliciting = has_ack_eliciting_frame(sent_initial_frames);
        const bool initial_has_ping =
            std::ranges::any_of(sent_initial_frames, [](const Frame &frame) {
                return std::holds_alternative<PingFrame>(frame);
            });
        if (initial_candidate_datagram.value().bytes.size() > max_outbound_datagram_size) {
            const bool blocked_first_server_initial =
                (initial_space_.next_send_packet_number == 0) & initial_ack_eliciting;
            if (blocked_first_server_initial) {
                return {};
            }
        } else {
            const bool bypass_congestion_window = initial_space_.pending_probe_packet.has_value();
            if (initial_ack_eliciting &&
                congestion_blocks_datagram(initial_candidate_datagram.value().bytes.size(),
                                           bypass_congestion_window)) {
                for (const auto &range : sent_initial_crypto_ranges) {
                    initial_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
                }
                return {};
            }
            initial_packet_number = reserve_packet_number(initial_space_);
            packets.emplace_back(ProtectedInitialPacket{
                .version = initial_packet_version,
                .destination_connection_id = initial_destination_connection_id,
                .source_connection_id = config_.source_connection_id,
                .token = initial_token,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = *initial_packet_number,
                .frames = sent_initial_frames,
            });
        }

        if (initial_candidate_datagram.value().bytes.size() <= max_outbound_datagram_size) {
            SentPacketRecord sent_packet{
                .packet_number = *initial_packet_number,
                .sent_time = now,
                .ack_eliciting = initial_ack_eliciting,
                .in_flight = initial_ack_eliciting,
                .declared_lost = false,
                .crypto_ranges = sent_initial_crypto_ranges,
                .has_ping = initial_has_ping,
            };
            sent_packet.path_id = selected_send_path_id.value_or(0);
            sent_packet.ecn = outbound_ecn_codepoint_for_path(selected_send_path_id);
            if (!defer_server_compatible_negotiation_crypto &&
                initial_space_.pending_probe_packet.has_value() &&
                sent_packet.crypto_ranges.empty()) {
                sent_packet.crypto_ranges = initial_space_.pending_probe_packet->crypto_ranges;
                sent_packet.has_ping = initial_space_.pending_probe_packet->has_ping;
            }
            queue_tracked_packet(initial_space_, sent_packet,
                                 initial_candidate_datagram.value().packet_metadata.back().length);
            if (track_client_handshake_keepalive_probes) {
                note_client_handshake_keepalive_probe(sent_packet);
            }
            if (sent_packet.ack_eliciting) {
                note_idle_ack_eliciting_send(now);
            }
            if (initial_space_.received_packets.has_ack_to_send()) {
                initial_space_.received_packets.on_ack_sent();
                initial_space_.pending_ack_deadline = std::nullopt;
                initial_space_.force_ack_send = false;
            }
            if (!defer_server_compatible_negotiation_crypto) {
                clear_probe_packet_after_send(initial_space_.pending_probe_packet);
            }

            if (duplicate_compatible_negotiation_initial_crypto) {
                const auto duplicate_candidate_packet_number =
                    initial_space_.next_send_packet_number;
                auto duplicate_candidate_packets = packets;
                duplicate_candidate_packets.emplace_back(ProtectedInitialPacket{
                    .version = initial_packet_version,
                    .destination_connection_id = initial_destination_connection_id,
                    .source_connection_id = config_.source_connection_id,
                    .token = initial_token,
                    .packet_number_length = kDefaultInitialPacketNumberLength,
                    .packet_number = duplicate_candidate_packet_number,
                    .frames = sent_initial_frames,
                });
                auto duplicate_candidate_datagram =
                    serialize_candidate_datagram_with_metadata(duplicate_candidate_packets);
                if (!duplicate_candidate_datagram.has_value()) {
                    return fail_datagram_send(/*preserve_pending_packets=*/true);
                }
                if (duplicate_candidate_datagram.value().bytes.size() <=
                    max_outbound_datagram_size) {
                    const bool bypass_congestion_window =
                        initial_space_.pending_probe_packet.has_value();
                    const bool duplicate_initial_congestion_blocked = congestion_blocks_datagram(
                        duplicate_candidate_datagram.value().bytes.size(),
                        bypass_congestion_window);
                    if (initial_ack_eliciting & duplicate_initial_congestion_blocked) {
                        return finalize_datagram(packets);
                    }
                    const auto duplicate_packet_number = reserve_packet_number(initial_space_);
                    duplicate_candidate_packets.back() = ProtectedInitialPacket{
                        .version = initial_packet_version,
                        .destination_connection_id = initial_destination_connection_id,
                        .source_connection_id = config_.source_connection_id,
                        .token = initial_token,
                        .packet_number_length = kDefaultInitialPacketNumberLength,
                        .packet_number = duplicate_packet_number,
                        .frames = sent_initial_frames,
                    };
                    packets = std::move(duplicate_candidate_packets);
                    queue_tracked_packet(
                        initial_space_,
                        SentPacketRecord{
                            .packet_number = duplicate_packet_number,
                            .sent_time = now,
                            .ack_eliciting = initial_ack_eliciting,
                            .in_flight = initial_ack_eliciting,
                            .declared_lost = false,
                            .crypto_ranges = sent_initial_crypto_ranges,
                            .path_id = selected_send_path_id.value_or(0),
                            .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                        },
                        duplicate_candidate_datagram.value().packet_metadata.back().length);
                    note_idle_ack_eliciting_send(now);
                }
            }
        }

        if (config_.role == EndpointRole::client &&
            initial_destination_connection_id != destination_connection_id) {
            return finalize_datagram(packets);
        }
    }

    const auto max_handshake_crypto_bytes =
        std::numeric_limits<std::size_t>::max() *
        static_cast<std::size_t>(!defer_server_compatible_negotiation_crypto &
                                 !handshake_packet_space_discarded_);
    auto handshake_crypto_ranges =
        handshake_packet_space_discarded_
            ? std::vector<ByteRange>{}
            : handshake_space_.send_crypto.take_ranges(max_handshake_crypto_bytes);
    const auto build_handshake_frames = [&](std::span<const ByteRange> crypto_ranges,
                                            bool override_probe_crypto_ranges = false,
                                            std::span<const ByteRange> probe_crypto_ranges = {}) {
        const auto handshake_ack_frame =
            (handshake_space_.pending_probe_packet.has_value() &&
             handshake_space_.pending_probe_packet->force_ack)
                ? handshake_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now,
                                                                    /*allow_non_pending=*/true)
                : handshake_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now);
        std::vector<Frame> frames;
        frames.reserve(crypto_ranges.size() + (handshake_ack_frame.has_value() ? 1u : 0u) +
                       (handshake_space_.pending_probe_packet.has_value()
                            ? handshake_space_.pending_probe_packet->crypto_ranges.size() + 1u
                            : 0u));
        if (handshake_ack_frame.has_value()) {
            frames.emplace_back(*handshake_ack_frame);
        }
        for (const auto &range : crypto_ranges) {
            frames.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
        if (handshake_ack_frame.has_value() && !has_ack_eliciting_frame(frames) &&
            should_add_server_handshake_keepalive_ping(handshake_space_)) {
            frames.emplace_back(PingFrame{});
        }
        if (handshake_space_.pending_probe_packet.has_value() && !has_ack_eliciting_frame(frames)) {
            const auto active_probe_crypto_ranges =
                override_probe_crypto_ranges
                    ? probe_crypto_ranges
                    : std::span<const ByteRange>(
                          handshake_space_.pending_probe_packet->crypto_ranges);
            for (const auto &range : active_probe_crypto_ranges) {
                frames.emplace_back(CryptoFrame{
                    .offset = range.offset,
                    .crypto_data = range.bytes.to_vector(),
                });
            }
            if (!has_ack_eliciting_frame(frames)) {
                frames.emplace_back(PingFrame{});
            }
        }

        return frames;
    };
    auto handshake_frames = handshake_packet_space_discarded_
                                ? std::vector<Frame>{}
                                : build_handshake_frames(handshake_crypto_ranges);
    if (!handshake_frames.empty()) {
        if (!handshake_space_.write_secret.has_value()) {
            mark_failed();
            return {};
        }

        auto sent_handshake_crypto_ranges = handshake_crypto_ranges;
        auto sent_handshake_probe_crypto_ranges =
            handshake_space_.pending_probe_packet.has_value()
                ? handshake_space_.pending_probe_packet->crypto_ranges
                : std::vector<ByteRange>{};
        const auto serialize_handshake_candidate = [&](std::span<const ByteRange> crypto_ranges)
            -> CodecResult<SerializedProtectedDatagram> {
            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedHandshakePacket{
                .version = current_version_,
                .destination_connection_id = destination_connection_id,
                .source_connection_id = config_.source_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = handshake_space_.next_send_packet_number,
                .frames = build_handshake_frames(crypto_ranges),
            });
            return serialize_candidate_datagram_with_metadata(candidate_packets);
        };
        const auto serialize_handshake_probe_candidate =
            [&](std::span<const ByteRange> probe_crypto_ranges)
            -> CodecResult<SerializedProtectedDatagram> {
            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedHandshakePacket{
                .version = current_version_,
                .destination_connection_id = destination_connection_id,
                .source_connection_id = config_.source_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = handshake_space_.next_send_packet_number,
                .frames = build_handshake_frames(sent_handshake_crypto_ranges,
                                                 /*override_probe_crypto_ranges=*/true,
                                                 probe_crypto_ranges),
            });
            return serialize_candidate_datagram_with_metadata(candidate_packets);
        };
        auto handshake_candidate_datagram =
            sent_handshake_crypto_ranges.empty() &&
                    handshake_space_.pending_probe_packet.has_value()
                ? trim_crypto_ranges_to_fit(
                      serialize_handshake_probe_candidate, [](std::uint64_t, std::size_t) {},
                      sent_handshake_probe_crypto_ranges)
                : trim_crypto_ranges_to_fit(
                      serialize_handshake_candidate,
                      [&](std::uint64_t offset, std::size_t length) {
                          handshake_space_.send_crypto.mark_unsent(offset, length);
                      },
                      sent_handshake_crypto_ranges);
        if (!handshake_candidate_datagram.has_value()) {
            return fail_datagram_send(!pending_tracked_packets.empty());
        }
        auto sent_handshake_frames =
            build_handshake_frames(sent_handshake_crypto_ranges,
                                   sent_handshake_crypto_ranges.empty() &&
                                       handshake_space_.pending_probe_packet.has_value(),
                                   sent_handshake_probe_crypto_ranges);
        const bool handshake_has_ping =
            std::ranges::any_of(sent_handshake_frames, [](const Frame &frame) {
                return std::holds_alternative<PingFrame>(frame);
            });
        if (handshake_candidate_datagram.value().bytes.size() > max_outbound_datagram_size) {
            if (!packets.empty()) {
                return finalize_datagram(packets);
            }
            return {};
        }

        const auto handshake_ack_eliciting = has_ack_eliciting_frame(sent_handshake_frames);
        const bool bypass_congestion_window = handshake_space_.pending_probe_packet.has_value();
        if (handshake_ack_eliciting &&
            congestion_blocks_datagram(handshake_candidate_datagram.value().bytes.size(),
                                       bypass_congestion_window)) {
            for (const auto &range : sent_handshake_crypto_ranges) {
                handshake_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
            }
            if (!packets.empty()) {
                return finalize_datagram(packets);
            }
            return {};
        }

        const auto packet_number = reserve_packet_number(handshake_space_);

        packets.emplace_back(ProtectedHandshakePacket{
            .version = current_version_,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = config_.source_connection_id,
            .packet_number_length = kDefaultInitialPacketNumberLength,
            .packet_number = packet_number,
            .frames = sent_handshake_frames,
        });

        SentPacketRecord sent_packet{
            .packet_number = packet_number,
            .sent_time = now,
            .ack_eliciting = handshake_ack_eliciting,
            .in_flight = handshake_ack_eliciting,
            .declared_lost = false,
            .crypto_ranges = sent_handshake_crypto_ranges,
            .has_ping = handshake_has_ping,
        };
        sent_packet.path_id = selected_send_path_id.value_or(0);
        sent_packet.ecn = outbound_ecn_codepoint_for_path(selected_send_path_id);
        if (handshake_space_.pending_probe_packet.has_value() &&
            sent_packet.crypto_ranges.empty()) {
            sent_packet.crypto_ranges = sent_handshake_probe_crypto_ranges;
            sent_packet.has_ping = handshake_space_.pending_probe_packet->has_ping;
        }
        queue_tracked_packet(handshake_space_, sent_packet,
                             handshake_candidate_datagram.value().packet_metadata.back().length);
        if (track_client_handshake_keepalive_probes) {
            note_client_handshake_keepalive_probe(sent_packet);
        }
        if (sent_packet.ack_eliciting) {
            note_idle_ack_eliciting_send(now);
        }
        if (handshake_space_.received_packets.has_ack_to_send()) {
            handshake_space_.received_packets.on_ack_sent();
            handshake_space_.pending_ack_deadline = std::nullopt;
            handshake_space_.force_ack_send = false;
        }
        clear_probe_packet_after_send(handshake_space_.pending_probe_packet);
    }

    auto application_crypto_ranges = std::vector<ByteRange>{};
    auto application_crypto_frames = std::vector<Frame>{};
    if (application_space_.write_secret.has_value()) {
        application_crypto_ranges =
            application_space_.send_crypto.take_ranges(std::numeric_limits<std::size_t>::max());
    }
    if (!application_crypto_ranges.empty()) {
        application_crypto_frames.reserve(application_crypto_ranges.size());
        for (const auto &range : application_crypto_ranges) {
            application_crypto_frames.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
    }

    const bool use_zero_rtt_packet_protection = config_.role == EndpointRole::client &&
                                                status_ != HandshakeStatus::connected &&
                                                zero_rtt_space_.write_secret.has_value();
    const bool can_send_one_rtt_packets = application_space_.write_secret.has_value();
    for (auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        maybe_queue_stream_blocked_frame(stream);
    }
    maybe_queue_connection_blocked_frame();
    const bool application_ack_due_now =
        application_space_.received_packets.has_ack_to_send() &&
        (application_space_.force_ack_send ||
         application_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max()) <= now);
    const bool has_pending_application_payload =
        application_ack_due_now | has_pending_application_send() |
        application_space_.pending_probe_packet.has_value() | !pending_new_token_frames_.empty() |
        !pending_new_connection_id_frames_.empty() | !pending_retire_connection_id_frames_.empty() |
        !application_crypto_frames.empty();
    if ((can_send_one_rtt_packets || use_zero_rtt_packet_protection) &&
        has_pending_application_payload) {
        const auto base_ack_frame =
            use_zero_rtt_packet_protection
                ? std::optional<OutboundAckHeader>{}
                : application_space_.received_packets.build_outbound_ack_header(
                      local_transport_parameters_.ack_delay_exponent, now);
        const auto maybe_queue_client_ack_only_receive_keepalive_challenge = [&]() {
            const bool has_receive_interest = std::ranges::any_of(
                streams_, [](const auto &entry) { return !stream_receive_terminal(entry.second); });
            const bool has_pending_path_validation =
                std::ranges::any_of(paths_, [](const auto &entry) {
                    return entry.second.pending_response.has_value() ||
                           entry.second.challenge_pending;
                });
            const bool eligible =
                (config_.role == EndpointRole::client) & handshake_confirmed_ &
                base_ack_frame.has_value() & last_peer_activity_time_.has_value() &
                has_receive_interest & !has_pending_application_send() &
                !application_space_.pending_probe_packet.has_value() &
                pending_new_token_frames_.empty() & pending_new_connection_id_frames_.empty() &
                pending_retire_connection_id_frames_.empty() & application_crypto_frames.empty() &
                !has_pending_path_validation &
                (initial_packet_space_discarded_ ||
                 !has_in_flight_ack_eliciting_packet(initial_space_)) &
                (handshake_packet_space_discarded_ ||
                 !has_in_flight_ack_eliciting_packet(handshake_space_)) &
                !has_in_flight_ack_eliciting_packet(application_space_) &
                current_send_path_id_.has_value();
            if (!eligible) {
                return;
            }

            auto &path = ensure_path_state(*current_send_path_id_);
            if (!path.validated) {
                return;
            }

            if (!path.outstanding_challenge.has_value()) {
                path.outstanding_challenge = next_path_challenge_data(*current_send_path_id_);
            }
            path.challenge_pending = true;
        };
        maybe_queue_client_ack_only_receive_keepalive_challenge();
        const auto reserve_application_packet_number =
            [&](bool using_one_rtt_packet_protection) -> std::optional<std::uint64_t> {
            if (connection_drain_test_hooks().force_application_packet_number_exhausted) {
                return std::nullopt;
            }
            const auto packet_number = application_space_.next_send_packet_number;
            if (using_one_rtt_packet_protection) {
                const auto largest_acked =
                    application_space_.recovery.largest_acked_packet_number();
                bool can_initiate_local_key_update =
                    local_key_update_requested_ & handshake_confirmed_ &
                    application_space_.read_secret.has_value() & !local_key_update_initiated_ &
                    current_write_phase_first_packet_number_.has_value() &
                    largest_acked.has_value();
                if (can_initiate_local_key_update) {
                    can_initiate_local_key_update =
                        *largest_acked >= *current_write_phase_first_packet_number_;
                }
                if (can_initiate_local_key_update) {
                    const auto next_read_secret =
                        derive_next_traffic_secret(*application_space_.read_secret);
                    if (!next_read_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret", next_read_secret.error());
                        mark_failed();
                        return std::nullopt;
                    }

                    const auto next_write_secret =
                        derive_next_traffic_secret(*application_space_.write_secret);
                    if (!next_write_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret", next_write_secret.error());
                        mark_failed();
                        return std::nullopt;
                    }

                    previous_application_read_secret_ = application_space_.read_secret;
                    previous_application_read_key_phase_ = application_read_key_phase_;
                    application_space_.read_secret = next_read_secret.value();
                    application_space_.write_secret = next_write_secret.value();
                    application_read_key_phase_ = !application_read_key_phase_;
                    application_write_key_phase_ = !application_write_key_phase_;
                    local_key_update_requested_ = false;
                    local_key_update_initiated_ = true;
                    current_write_phase_first_packet_number_ = packet_number;
                }
                if (!current_write_phase_first_packet_number_.has_value()) {
                    current_write_phase_first_packet_number_ = packet_number;
                }
            }

            static_cast<void>(reserve_packet_number(application_space_));
            return packet_number;
        };
        const auto take_reset_stream_frames = [](auto &streams) -> std::vector<ResetStreamFrame> {
            std::vector<ResetStreamFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_reset_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_stop_sending_frames = [](auto &streams) -> std::vector<StopSendingFrame> {
            std::vector<StopSendingFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_stop_sending_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_max_stream_data_frames =
            [](auto &streams) -> std::vector<MaxStreamDataFrame> {
            std::vector<MaxStreamDataFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_max_stream_data_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_max_streams_frames =
            [&](bool force_ack_only) -> std::vector<MaxStreamsFrame> {
            if (force_ack_only) {
                return {};
            }

            return local_stream_limit_state_.take_max_streams_frames();
        };
        const auto take_new_token_frames = [&](bool force_ack_only) -> std::vector<NewTokenFrame> {
            if (force_ack_only) {
                return {};
            }

            auto frames = std::move(pending_new_token_frames_);
            pending_new_token_frames_.clear();
            return frames;
        };
        const auto take_new_connection_id_frames =
            [&](bool force_ack_only) -> std::vector<NewConnectionIdFrame> {
            if (force_ack_only) {
                return {};
            }

            std::vector<NewConnectionIdFrame> frames;
            while (const auto frame = take_pending_new_connection_id_frame()) {
                frames.push_back(*frame);
            }
            return frames;
        };
        const auto take_retire_connection_id_frames =
            [&](bool force_ack_only) -> std::vector<RetireConnectionIdFrame> {
            if (force_ack_only) {
                return {};
            }

            auto frames = std::move(pending_retire_connection_id_frames_);
            pending_retire_connection_id_frames_.clear();
            for (const auto &frame : frames) {
                if (auto peer = peer_connection_ids_.find(frame.sequence_number);
                    peer != peer_connection_ids_.end()) {
                    peer->second.retire_frame_in_flight = true;
                }
            }
            return frames;
        };
        struct PendingPathValidationFrames {
            QuicPathId path_id = 0;
            std::optional<PathResponseFrame> response;
            std::optional<PathChallengeFrame> challenge;
        };
        const auto mark_path_challenge_sent = [](auto &path) { path.challenge_pending = false; };
        const auto take_path_validation_frames =
            [&](bool force_ack_only) -> PendingPathValidationFrames {
            static_cast<void>(force_ack_only);

            const auto response_path =
                std::find_if(paths_.begin(), paths_.end(), [](const auto &entry) {
                    return entry.second.pending_response.has_value();
                });
            if (response_path != paths_.end()) {
                PendingPathValidationFrames frames{
                    .path_id = response_path->first,
                    .response =
                        PathResponseFrame{
                            .data = *response_path->second.pending_response,
                        },
                };
                response_path->second.pending_response.reset();
                if (response_path->second.challenge_pending &
                    response_path->second.outstanding_challenge.has_value()) {
                    frames.challenge = PathChallengeFrame{
                        .data = *response_path->second.outstanding_challenge,
                    };
                    mark_path_challenge_sent(response_path->second);
                } else if (!response_path->second.validated &
                           !response_path->second.outstanding_challenge.has_value()) {
                    response_path->second.outstanding_challenge =
                        next_path_challenge_data(response_path->first);
                    frames.challenge = PathChallengeFrame{
                        .data = *response_path->second.outstanding_challenge,
                    };
                    mark_path_challenge_sent(response_path->second);
                }
                if (!response_path->second.validated &
                    current_send_path_id_ != response_path->first) {
                    if (current_send_path_id_.has_value()) {
                        previous_path_id_ = current_send_path_id_;
                        if (const auto current = paths_.find(*current_send_path_id_);
                            current != paths_.end()) {
                            current->second.is_current_send_path = false;
                        }
                    }
                    response_path->second.is_current_send_path = true;
                    current_send_path_id_ = response_path->first;
                }
                return frames;
            }

            if (!current_send_path_id_.has_value()) {
                return {};
            }
            const auto path = paths_.find(*current_send_path_id_);
            if (path == paths_.end()) {
                return {};
            }

            PendingPathValidationFrames frames{
                .path_id = *current_send_path_id_,
            };
            if (path->second.challenge_pending & path->second.outstanding_challenge.has_value()) {
                frames.challenge = PathChallengeFrame{
                    .data = *path->second.outstanding_challenge,
                };
                mark_path_challenge_sent(path->second);
            }
            return frames;
        };
        const auto take_stream_data_blocked_frames =
            [](auto &streams) -> std::vector<StreamDataBlockedFrame> {
            std::vector<StreamDataBlockedFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_stream_data_blocked_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_stream_fragments = [&](auto &connection_flow, auto &streams,
                                               std::size_t max_wire_bytes, auto &last_stream_id,
                                               std::vector<StreamFrameSendFragment> &fragments,
                                               bool prefer_fresh_data = false) {
            fragments.clear();
            auto remaining_wire_bytes = max_wire_bytes;
            auto remaining_connection_credit =
                connection_flow.peer_max_data > connection_flow.highest_sent
                    ? connection_flow.peer_max_data - connection_flow.highest_sent
                    : 0;
            auto loss_phase = !prefer_fresh_data;
            auto switched_phase = false;
            const auto visit_round_robin = [&](auto &&visit) {
                const auto visit_range = [&](auto begin, auto end) {
                    for (auto it = begin; it != end; ++it) {
                        visit(it);
                    }
                };

                if (streams.empty()) {
                    return;
                }
                if (!last_stream_id.has_value()) {
                    visit_range(streams.begin(), streams.end());
                    return;
                }

                const auto start = streams.upper_bound(*last_stream_id);
                visit_range(start, streams.end());
                visit_range(streams.begin(), start);
            };

            constexpr std::size_t kLargeDatagramFreshStreamBudgetBytes = std::size_t{8} * 1024u;
            const auto limit_fresh_streams_for_round = [&](std::size_t packet_budget,
                                                           std::size_t active_stream_count) {
                if (active_stream_count <= 1) {
                    return active_stream_count;
                }

                return std::min(active_stream_count,
                                std::max<std::size_t>(
                                    1u, packet_budget / kLargeDatagramFreshStreamBudgetBytes));
            };

            for (;;) {
                if (remaining_wire_bytes == 0) {
                    break;
                }
                auto &active_streams = active_stream_iterator_scratch_;
                active_streams.clear();
                visit_round_robin([&](const auto it) {
                    auto &stream = it->second;
                    if (stream.reset_state != StreamControlFrameState::none) {
                        return true;
                    }

                    const auto fin_sendable = stream_fin_sendable(stream);
                    const auto active = loss_phase
                                            ? stream.send_buffer.has_lost_data() || fin_sendable
                                            : (stream.sendable_bytes() != 0) || fin_sendable;
                    if (active) {
                        active_streams.push_back(it);
                    }
                    return true;
                });

                if (active_streams.empty()) {
                    if (!switched_phase) {
                        loss_phase = !loss_phase;
                        switched_phase = true;
                        continue;
                    }

                    break;
                }

                std::size_t wire_bytes_sent_this_round = 0;
                bool emitted_fragment = false;
                const auto active_stream_count = active_streams.size();
                const auto selected_stream_count =
                    loss_phase
                        ? active_stream_count
                        : limit_fresh_streams_for_round(remaining_wire_bytes, active_stream_count);
                if (selected_stream_count != active_stream_count) {
                    active_streams.resize(selected_stream_count);
                }

                const bool use_remaining_round_share = selected_stream_count != active_stream_count;
                for (std::size_t stream_index = 0; stream_index < selected_stream_count;
                     ++stream_index) {
                    const auto it = active_streams[stream_index];
                    const auto stream_id = it->first;
                    auto &stream = it->second;

                    const auto highest_sent_before = stream.flow_control.highest_sent;
                    const auto round_divisor = use_remaining_round_share
                                                   ? selected_stream_count - stream_index
                                                   : selected_stream_count;
                    const auto wire_share =
                        std::max<std::size_t>(1u, remaining_wire_bytes / round_divisor);
                    auto packet_share =
                        loss_phase
                            ? std::min(remaining_wire_bytes,
                                       max_stream_frame_payload_for_wire_budget(
                                           stream_id, stream.next_send_offset_for_budget(false),
                                           wire_share))
                            : std::min(
                                  remaining_wire_bytes,
                                  max_stream_frame_payload_for_wire_budget(
                                      stream_id, stream.flow_control.highest_sent, wire_share));
                    const auto fin_sendable = stream_fin_sendable(stream);
                    if (packet_share == 0) {
                        if (fin_only_stream_frame_cannot_fit(fin_sendable,
                                                             stream.send_final_size.has_value())) {
                            continue;
                        }
                        const auto fin_only_wire_size =
                            stream_frame_header_wire_size(stream_id, *stream.send_final_size, 0);
                        if (fin_only_wire_size > remaining_wire_bytes) {
                            continue;
                        }
                    }
                    const auto new_byte_share =
                        loss_phase || remaining_connection_credit == 0
                            ? 0
                            : std::max<std::uint64_t>(1,
                                                      remaining_connection_credit / round_divisor);
                    const auto fragment_count_before = fragments.size();
                    stream.append_send_fragments(
                        StreamSendBudget{
                            .packet_bytes = packet_share,
                            .new_bytes = new_byte_share,
                            .prefer_fresh_data = !loss_phase,
                        },
                        fragments);
                    const auto new_bytes_sent =
                        stream.flow_control.highest_sent - highest_sent_before;
                    connection_flow.highest_sent += new_bytes_sent;
                    remaining_connection_credit -= new_bytes_sent;
                    const auto restore_fragment = [&](const StreamFrameSendFragment &fragment) {
                        restore_stream_fragment(streams, fragment, connection_flow,
                                                remaining_connection_credit);
                    };
                    const auto restore_tail_fragments = [&](std::size_t begin) {
                        for (auto index = fragments.size(); index > begin; --index) {
                            restore_fragment(fragments[index - 1u]);
                        }
                        fragments.erase(fragments.begin() + static_cast<std::ptrdiff_t>(begin),
                                        fragments.end());
                    };
                    std::size_t selected_wire_bytes = 0;
                    for (std::size_t index = fragment_count_before; index < fragments.size();
                         ++index) {
                        auto &fragment = fragments[index];
                        const auto fragment_wire_size = fragment.stream_frame_wire_size();
                        if (selected_wire_bytes + fragment_wire_size <= remaining_wire_bytes) {
                            selected_wire_bytes += fragment_wire_size;
                            continue;
                        }

                        const auto fragment_budget = remaining_wire_bytes - selected_wire_bytes;
                        const auto retained_payload_size = max_stream_frame_payload_for_wire_budget(
                            fragment.stream_id, fragment.offset, fragment_budget);
                        if (retained_payload_size == 0) {
                            restore_tail_fragments(index);
                            break;
                        }

                        maybe_restore_stream_fragment_tail(fragment, retained_payload_size, streams,
                                                           connection_flow,
                                                           remaining_connection_credit);

                        selected_wire_bytes += fragment.stream_frame_wire_size();
                        restore_tail_fragments(index + 1u);
                        break;
                    }
                    remaining_wire_bytes -= selected_wire_bytes;
                    if (fragments.size() != fragment_count_before) {
                        emitted_fragment = true;
                        last_stream_id = stream_id;
                    }
                    wire_bytes_sent_this_round += selected_wire_bytes;
                    if (remaining_wire_bytes == 0) {
                        break;
                    }
                }

                if (!static_cast<bool>(emitted_fragment & (wire_bytes_sent_this_round != 0))) {
                    break;
                }
            }
        };
        const auto append_application_crypto_frames = [](std::vector<Frame> &frames,
                                                         std::span<const ByteRange> crypto_ranges) {
            for (const auto &range : crypto_ranges) {
                frames.emplace_back(CryptoFrame{
                    .offset = range.offset,
                    .crypto_data = range.bytes.to_vector(),
                });
            }
        };
        const auto append_application_ack_frame =
            [&](std::vector<Frame> &frames, const std::optional<OutboundAckHeader> &ack_frame) {
                if (!ack_frame.has_value()) {
                    return;
                }
                frames.emplace_back(OutboundAckFrame{
                    .history = &application_space_.received_packets,
                    .header = *ack_frame,
                });
            };
        const auto build_application_candidate_frames =
            [&](std::span<const Frame> crypto_frames, bool include_handshake_done,
                const std::optional<OutboundAckHeader> &ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const NewTokenFrame> new_token_frames,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                const std::optional<ApplicationConnectionCloseFrame> &application_close_frame,
                bool include_ping) -> std::vector<Frame> {
            std::vector<Frame> candidate_frames;
            candidate_frames.reserve(
                crypto_frames.size() + (ack_frame.has_value() ? 1u : 0u) +
                (include_handshake_done ? 1u : 0u) + (max_data_frame.has_value() ? 1u : 0u) +
                new_token_frames.size() + new_connection_id_frames.size() +
                retire_connection_id_frames.size() +
                static_cast<std::size_t>(path_validation_frames.response.has_value()) +
                static_cast<std::size_t>(path_validation_frames.challenge.has_value()) +
                max_stream_data_frames.size() + max_streams_frames.size() +
                reset_stream_frames.size() + stop_sending_frames.size() +
                (data_blocked_frame.has_value() ? 1u : 0u) + stream_data_blocked_frames.size() +
                (application_close_frame.has_value() ? 1u : 0u) + (include_ping ? 1u : 0u));
            candidate_frames.insert(candidate_frames.end(), crypto_frames.begin(),
                                    crypto_frames.end());
            append_application_ack_frame(candidate_frames, ack_frame);
            if (include_handshake_done) {
                candidate_frames.emplace_back(HandshakeDoneFrame{});
            }
            if (max_data_frame.has_value()) {
                candidate_frames.emplace_back(*max_data_frame);
            }
            for (const auto &frame : new_token_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : new_connection_id_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : retire_connection_id_frames) {
                candidate_frames.emplace_back(frame);
            }
            if (path_validation_frames.response.has_value()) {
                candidate_frames.emplace_back(*path_validation_frames.response);
            }
            if (path_validation_frames.challenge.has_value()) {
                candidate_frames.emplace_back(*path_validation_frames.challenge);
            }
            for (const auto &frame : max_stream_data_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : max_streams_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : reset_stream_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : stop_sending_frames) {
                candidate_frames.emplace_back(frame);
            }
            if (data_blocked_frame.has_value()) {
                candidate_frames.emplace_back(*data_blocked_frame);
            }
            for (const auto &frame : stream_data_blocked_frames) {
                candidate_frames.emplace_back(frame);
            }
            if (application_close_frame.has_value()) {
                candidate_frames.emplace_back(*application_close_frame);
            }
            if (include_ping) {
                candidate_frames.emplace_back(PingFrame{});
            }
            return candidate_frames;
        };
        const auto serialize_application_candidate_from_frames =
            [&](std::span<const Frame> candidate_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                bool has_application_close, std::uint64_t packet_number,
                bool write_key_phase) -> CodecResult<SerializedProtectedDatagram> {
            const bool use_zero_rtt = use_zero_rtt_packet_protection & !has_application_close;
            if (!use_zero_rtt) {
                const auto candidate_destination_connection_id =
                    application_destination_connection_id();
                const auto candidate_packet = ProtectedOneRttPacketFragmentView{
                    .spin_bit = outbound_spin_bit_for_path(selected_send_path_id),
                    .key_phase = write_key_phase,
                    .destination_connection_id = candidate_destination_connection_id,
                    .packet_number_length = kDefaultInitialPacketNumberLength,
                    .packet_number = packet_number,
                    .frames = candidate_frames,
                    .stream_fragments = stream_fragments,
                };
                auto candidate_datagram =
                    serialize_candidate_datagram_with_metadata(packets, nullptr, &candidate_packet);
                maybe_grow_application_candidate_datagram_for_tests(candidate_datagram);
                return candidate_datagram;
            }

            auto candidate_packet = make_application_protected_packet(
                use_zero_rtt, current_version_, application_destination_connection_id(),
                config_.source_connection_id, write_key_phase, kDefaultInitialPacketNumberLength,
                packet_number, std::vector<Frame>(candidate_frames.begin(), candidate_frames.end()),
                stream_fragments);
            set_application_packet_spin_bit(candidate_packet,
                                            outbound_spin_bit_for_path(selected_send_path_id));
            auto candidate_datagram =
                serialize_candidate_datagram_with_metadata(packets, &candidate_packet);
            maybe_grow_application_candidate_datagram_for_tests(candidate_datagram);
            if (!candidate_datagram.has_value()) {
                return candidate_datagram;
            }
            return candidate_datagram;
        };
        const auto serialize_application_candidate =
            [&](std::span<const ByteRange> crypto_ranges, bool include_handshake_done,
                const std::optional<OutboundAckHeader> &ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const NewTokenFrame> new_token_frames,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                const std::optional<ApplicationConnectionCloseFrame> &application_close_frame,
                bool include_ping) -> CodecResult<SerializedProtectedDatagram> {
            std::vector<Frame> crypto_frames;
            crypto_frames.reserve(crypto_ranges.size());
            append_application_crypto_frames(crypto_frames, crypto_ranges);
            auto candidate_frames = build_application_candidate_frames(
                crypto_frames, include_handshake_done, ack_frame, max_data_frame, new_token_frames,
                new_connection_id_frames, retire_connection_id_frames, path_validation_frames,
                max_stream_data_frames, max_streams_frames, reset_stream_frames,
                stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                application_close_frame, include_ping);
            return serialize_application_candidate_from_frames(
                candidate_frames, stream_fragments, application_close_frame.has_value(),
                application_space_.next_send_packet_number, application_write_key_phase_);
        };
        const auto estimate_application_candidate_size_from_frames =
            [&](std::span<const Frame> candidate_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                bool has_application_close, std::uint64_t packet_number,
                bool write_key_phase) -> CodecResult<std::size_t> {
            if (send_profile_enabled()) {
                ++send_profile_counters().estimate_calls;
            }
            SendProfileTimer estimate_timer(send_profile_counters().estimate_ns);
            if (consume_connection_drain_countdown(
                    &ConnectionDrainTestHooks::
                        force_application_candidate_estimate_failure_countdown)) {
                return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch, 0);
            }
            const bool use_zero_rtt = use_zero_rtt_packet_protection & !has_application_close;
            if (!use_zero_rtt && packets.empty()) {
                const auto candidate_destination_connection_id =
                    application_destination_connection_id();
                const auto candidate_packet = ProtectedOneRttPacketFragmentView{
                    .spin_bit = outbound_spin_bit_for_path(selected_send_path_id),
                    .key_phase = write_key_phase,
                    .destination_connection_id = candidate_destination_connection_id,
                    .packet_number_length = kDefaultInitialPacketNumberLength,
                    .packet_number = packet_number,
                    .frames = candidate_frames,
                    .stream_fragments = stream_fragments,
                };
                return one_rtt_packet_fragment_view_wire_size(candidate_packet);
            }

            auto candidate_packet = make_application_protected_packet(
                use_zero_rtt, current_version_, application_destination_connection_id(),
                config_.source_connection_id, write_key_phase, kDefaultInitialPacketNumberLength,
                packet_number, std::vector<Frame>(candidate_frames.begin(), candidate_frames.end()),
                stream_fragments);
            set_application_packet_spin_bit(candidate_packet,
                                            outbound_spin_bit_for_path(selected_send_path_id));
            const auto candidate_datagram =
                serialize_candidate_datagram_with_metadata(packets, &candidate_packet);
            if (!candidate_datagram.has_value()) {
                return CodecResult<std::size_t>::failure(candidate_datagram.error().code,
                                                         candidate_datagram.error().offset);
            }
            return CodecResult<std::size_t>::success(candidate_datagram.value().bytes.size());
        };
        const auto estimate_application_candidate_size =
            [&](std::span<const ByteRange> crypto_ranges, bool include_handshake_done,
                const std::optional<OutboundAckHeader> &ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const NewTokenFrame> new_token_frames,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                const std::optional<ApplicationConnectionCloseFrame> &application_close_frame,
                bool include_ping) -> CodecResult<std::size_t> {
            std::vector<Frame> crypto_frames;
            crypto_frames.reserve(crypto_ranges.size());
            append_application_crypto_frames(crypto_frames, crypto_ranges);
            auto candidate_frames = build_application_candidate_frames(
                crypto_frames, include_handshake_done, ack_frame, max_data_frame, new_token_frames,
                new_connection_id_frames, retire_connection_id_frames, path_validation_frames,
                max_stream_data_frames, max_streams_frames, reset_stream_frames,
                stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                application_close_frame, include_ping);
            return estimate_application_candidate_size_from_frames(
                candidate_frames, stream_fragments, application_close_frame.has_value(),
                application_space_.next_send_packet_number, application_write_key_phase_);
        };
        const auto restore_application_fragment = [&](const StreamFrameSendFragment &fragment) {
            const bool releases_flow_control =
                fragment.consumes_flow_control & !fragment.bytes.empty();
            if (releases_flow_control) {
                connection_flow_control_.highest_sent -=
                    static_cast<std::uint64_t>(fragment.bytes.size());
            }
            streams_.at(fragment.stream_id).restore_send_fragment(fragment);
        };
        const auto restore_unsent_application_candidate =
            [&](const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const NewTokenFrame> new_token_frames,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments) {
                for (const auto &range : application_crypto_ranges) {
                    application_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
                }
                if (max_data_frame.has_value()) {
                    connection_flow_control_.mark_max_data_frame_lost(*max_data_frame);
                }
                if (data_blocked_frame.has_value()) {
                    connection_flow_control_.mark_data_blocked_frame_lost(*data_blocked_frame);
                }
                pending_new_token_frames_.insert(pending_new_token_frames_.begin(),
                                                 new_token_frames.begin(), new_token_frames.end());
                pending_new_connection_id_frames_.insert(pending_new_connection_id_frames_.begin(),
                                                         new_connection_id_frames.begin(),
                                                         new_connection_id_frames.end());
                pending_retire_connection_id_frames_.insert(
                    pending_retire_connection_id_frames_.begin(),
                    retire_connection_id_frames.begin(), retire_connection_id_frames.end());
                if (path_validation_frames.response.has_value()) {
                    auto &path = ensure_path_state(path_validation_frames.path_id);
                    path.pending_response = path_validation_frames.response->data;
                }
                if (path_validation_frames.challenge.has_value()) {
                    auto &path = ensure_path_state(path_validation_frames.path_id);
                    path.challenge_pending = true;
                }
                for (const auto &frame : max_stream_data_frames) {
                    streams_.at(frame.stream_id).mark_max_stream_data_frame_lost(frame);
                }
                for (const auto &frame : max_streams_frames) {
                    local_stream_limit_state_.mark_max_streams_frame_lost(frame);
                }
                for (const auto &frame : stream_data_blocked_frames) {
                    streams_.at(frame.stream_id).mark_stream_data_blocked_frame_lost(frame);
                }
                for (const auto &frame : reset_stream_frames) {
                    streams_.at(frame.stream_id).mark_reset_frame_lost(frame);
                }
                for (const auto &frame : stop_sending_frames) {
                    streams_.at(frame.stream_id).mark_stop_sending_frame_lost(frame);
                }
                for (const auto &fragment : stream_fragments) {
                    restore_application_fragment(fragment);
                }
            };
        const auto trim_application_ack_frame =
            [&](std::span<const ByteRange> crypto_ranges, bool include_handshake_done,
                const std::optional<OutboundAckHeader> &candidate_ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const NewTokenFrame> new_token_frames,
                std::span<const NewConnectionIdFrame> new_connection_id_frames,
                std::span<const RetireConnectionIdFrame> retire_connection_id_frames,
                const PendingPathValidationFrames &path_validation_frames,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                bool include_ping) -> std::optional<OutboundAckHeader> {
            if (send_profile_enabled()) {
                ++send_profile_counters().trim_ack_calls;
            }
            SendProfileTimer trim_ack_timer(send_profile_counters().trim_ack_ns);
            if (!candidate_ack_frame.has_value()) {
                return std::nullopt;
            }
            auto candidate_size = estimate_application_candidate_size(
                crypto_ranges, include_handshake_done, candidate_ack_frame, max_data_frame,
                new_token_frames, new_connection_id_frames, retire_connection_id_frames,
                path_validation_frames, max_stream_data_frames, max_streams_frames,
                reset_stream_frames, stop_sending_frames, data_blocked_frame,
                stream_data_blocked_frames, stream_fragments, std::nullopt, include_ping);
            if (!candidate_size.has_value()) {
                fail_datagram_send(!pending_tracked_packets.empty());
                return std::nullopt;
            }
            if (candidate_ack_frame->additional_ranges.empty() ||
                candidate_size.value() <= max_outbound_datagram_size) {
                return candidate_ack_frame;
            }

            std::size_t retained_ranges_low = 0;
            std::size_t retained_ranges_high = candidate_ack_frame->additional_ranges.size();
            std::optional<OutboundAckHeader> best_trimmed_ack_frame;

            while (retained_ranges_low <= retained_ranges_high) {
                const auto retained_ranges =
                    retained_ranges_low + (retained_ranges_high - retained_ranges_low) / 2;
                auto trimmed_ack_frame = candidate_ack_frame;
                trimmed_ack_frame->additional_ranges.resize(retained_ranges);
                trimmed_ack_frame->additional_range_count =
                    trimmed_ack_frame->additional_ranges.size();

                candidate_size = estimate_application_candidate_size(
                    crypto_ranges, include_handshake_done, trimmed_ack_frame, max_data_frame,
                    new_token_frames, new_connection_id_frames, retire_connection_id_frames,
                    path_validation_frames, max_stream_data_frames, max_streams_frames,
                    reset_stream_frames, stop_sending_frames, data_blocked_frame,
                    stream_data_blocked_frames, stream_fragments, std::nullopt, include_ping);
                if (!candidate_size.has_value()) {
                    fail_datagram_send(!pending_tracked_packets.empty());
                    return std::nullopt;
                }

                if (candidate_size.value() <= max_outbound_datagram_size) {
                    best_trimmed_ack_frame = std::move(trimmed_ack_frame);
                    retained_ranges_low = retained_ranges + 1;
                    continue;
                }

                if (retained_ranges == 0) {
                    break;
                }
                retained_ranges_high = retained_ranges - 1;
            }

            return best_trimmed_ack_frame;
        };

        const auto *pending_application_probe = application_space_.pending_probe_packet.has_value()
                                                    ? &*application_space_.pending_probe_packet
                                                    : nullptr;
        const auto minimum_pending_application_stream_wire_bytes =
            [&]() -> std::optional<std::size_t> {
            const auto connection_send_credit = saturating_subtract(
                connection_flow_control_.peer_max_data, connection_flow_control_.highest_sent);
            std::optional<std::size_t> minimum_wire_bytes;
            for (const auto &[stream_id, stream] : streams_) {
                if (stream.reset_state != StreamControlFrameState::none) {
                    continue;
                }

                if (stream.send_buffer.has_lost_data() ||
                    ((connection_send_credit != 0) & (stream.sendable_bytes() != 0))) {
                    remember_minimum_wire_size(minimum_wire_bytes,
                                               stream_frame_header_wire_size(
                                                   stream_id, stream.flow_control.highest_sent, 1) +
                                                   std::size_t{1});
                }
                if (stream_fin_sendable(stream)) {
                    remember_minimum_wire_size(
                        minimum_wire_bytes,
                        stream_frame_header_wire_size(stream_id, *stream.send_final_size, 0));
                }
            }

            return minimum_wire_bytes;
        };
        const auto has_pending_application_stream_send = [&]() {
            return minimum_pending_application_stream_wire_bytes().has_value();
        };
        const bool prefer_fresh_application_stream_data =
            (pending_application_probe != nullptr) & (remaining_pto_probe_datagrams_ == 1) &
            has_pending_fresh_application_stream_send();
        const auto should_send_application_probe_first = [&]() {
            const auto validation_only_path_id = [&]() -> std::optional<QuicPathId> {
                const auto response_path =
                    std::find_if(paths_.begin(), paths_.end(), [](const auto &entry) {
                        return entry.second.pending_response.has_value();
                    });
                if (response_path != paths_.end()) {
                    return response_path->first;
                }
                return current_send_path_id_;
            }();
            if (validation_only_path_id.has_value()) {
                const auto validation_path = paths_.find(*validation_only_path_id);
                if (validation_path != paths_.end() && !validation_path->second.validated &&
                    !validation_path->second.validation_initiated_locally) {
                    return false;
                }
            }
            if (pending_application_probe == nullptr) {
                return false;
            }

            const auto probe_has_path_validation = [&]() {
                const auto response_path =
                    std::find_if(paths_.begin(), paths_.end(), [](const auto &entry) {
                        return entry.second.pending_response.has_value();
                    });
                if (response_path != paths_.end()) {
                    return true;
                }

                if (!current_send_path_id_.has_value()) {
                    return false;
                }

                const auto current_path = paths_.find(*current_send_path_id_);
                const bool has_current_path = current_path != paths_.end();
                const bool challenge_pending =
                    has_current_path ? current_path->second.challenge_pending : false;
                const bool has_outstanding_challenge =
                    has_current_path ? current_path->second.outstanding_challenge.has_value()
                                     : false;
                return static_cast<bool>(has_current_path & challenge_pending &
                                         has_outstanding_challenge);
            }();

            if (has_pending_application_stream_send()) {
                if (pending_application_probe->is_pmtu_probe) {
                    return false;
                }

                // If there is queued stream response data, don't let a control-only PTO probe
                // starve it; use the PTO opportunity to send the response.
                if (pending_application_probe->stream_fragments.empty()) {
                    return false;
                }

                // On the last datagram of a PTO burst, spend the remaining probe credit on
                // fresh queued stream data instead of retransmitting the same stream fragment
                // again.
                if (prefer_fresh_application_stream_data) {
                    return false;
                }
            }

            const bool probe_is_retransmittable =
                (retransmittable_probe_frame_count(*pending_application_probe) != 0) |
                probe_has_path_validation;
            return static_cast<bool>(probe_is_retransmittable | !has_pending_application_send());
        };

        if (should_send_application_probe_first()) {
            const auto &probe_packet = *pending_application_probe;
            auto probe_max_data_frame = probe_packet.max_data_frame;
            std::optional<MaxDataFrame> fresh_probe_max_data_frame;
            auto probe_max_stream_data_frames = probe_packet.max_stream_data_frames;
            std::vector<MaxStreamDataFrame> fresh_probe_max_stream_data_frames;
            if (probe_packet.force_ack) {
                maybe_refresh_connection_receive_credit(/*force=*/true);
                if (!probe_max_data_frame.has_value() &
                    (connection_flow_control_.max_data_state == StreamControlFrameState::pending) &
                    connection_flow_control_.pending_max_data_frame.has_value()) {
                    fresh_probe_max_data_frame = connection_flow_control_.pending_max_data_frame;
                    probe_max_data_frame = fresh_probe_max_data_frame;
                }

                for (auto &[stream_id, stream] : streams_) {
                    static_cast<void>(stream_id);
                    maybe_refresh_stream_receive_credit(stream, /*force=*/true);
                    if ((stream.flow_control.max_stream_data_state !=
                         StreamControlFrameState::pending) |
                        !stream.flow_control.pending_max_stream_data_frame.has_value()) {
                        continue;
                    }

                    const auto frame = stream.flow_control.pending_max_stream_data_frame.value_or(
                        MaxStreamDataFrame{});
                    const bool already_selected = std::ranges::any_of(
                        probe_max_stream_data_frames, [&](const MaxStreamDataFrame &selected) {
                            return (selected.stream_id == frame.stream_id) &
                                   (selected.maximum_stream_data == frame.maximum_stream_data);
                        });
                    if (already_selected) {
                        continue;
                    }

                    fresh_probe_max_stream_data_frames.push_back(frame);
                    probe_max_stream_data_frames.push_back(frame);
                }
            }
            const std::optional<OutboundAckHeader> probe_base_ack_frame =
                probe_packet.is_pmtu_probe
                    ? std::optional<OutboundAckHeader>{}
                    : (probe_packet.force_ack
                           ? application_space_.received_packets.build_outbound_ack_header(
                                 local_transport_parameters_.ack_delay_exponent, now,
                                 /*allow_non_pending=*/true)
                           : base_ack_frame);
            const std::span<const ByteRange> probe_crypto_ranges =
                probe_packet.is_pmtu_probe
                    ? std::span<const ByteRange>{}
                    : (application_crypto_ranges.empty()
                           ? std::span<const ByteRange>(probe_packet.crypto_ranges)
                           : std::span<const ByteRange>(application_crypto_ranges));
            const auto include_ping = retransmittable_probe_frame_count(probe_packet) == 0;
            const auto target_pmtu_probe_size =
                probe_packet.is_pmtu_probe ? probe_packet.pmtu_probe_size : std::size_t{0};
            std::size_t probe_padding_length = 0;
            const auto restore_unsent_path_validation_frames =
                [&](const PendingPathValidationFrames &path_validation_frames) {
                    if (path_validation_frames.response.has_value()) {
                        auto &path = ensure_path_state(path_validation_frames.path_id);
                        path.pending_response = path_validation_frames.response->data;
                    }
                    if (path_validation_frames.challenge.has_value()) {
                        auto &path = ensure_path_state(path_validation_frames.path_id);
                        path.challenge_pending = true;
                    }
                };
            const auto make_probe_stream_fragments = [&]() {
                auto fragments = probe_packet.stream_fragments;
                for (auto &fragment : fragments) {
                    fragment.consumes_flow_control = false;
                }
                return fragments;
            };
            const auto restore_probe_fragment = [&](const StreamFrameSendFragment &fragment) {
                const auto stream = streams_.find(fragment.stream_id);
                if (stream == streams_.end()) {
                    return;
                }

                stream->second.mark_send_fragment_lost(fragment);
            };
            const auto mark_probe_fragments_sent =
                [&](std::span<const StreamFrameSendFragment> fragments) {
                    for (const auto &fragment : fragments) {
                        const auto stream = streams_.find(fragment.stream_id);
                        if (stream == streams_.end()) {
                            continue;
                        }

                        stream->second.mark_send_fragment_sent(fragment);
                    }
                };
            const auto restore_unsent_application_probe_candidate = [&]() {
                for (const auto &range : application_crypto_ranges) {
                    application_space_.send_crypto.mark_unsent(range.offset, range.bytes.size());
                }
            };
            auto path_validation_frames = take_path_validation_frames(/*force_ack_only=*/false);
            selected_send_path_id = path_validation_frames.response.has_value()
                                        ? std::optional<QuicPathId>{path_validation_frames.path_id}
                                        : current_send_path_id_;
            auto probe_stream_fragments = make_probe_stream_fragments();
            mark_probe_fragments_sent(probe_stream_fragments);
            auto ack_frame = trim_application_ack_frame(
                probe_crypto_ranges, probe_packet.has_handshake_done, probe_base_ack_frame,
                probe_max_data_frame, {}, {}, {}, path_validation_frames,
                probe_max_stream_data_frames, probe_packet.max_streams_frames,
                probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                probe_stream_fragments, include_ping);
            if (has_failed()) {
                return {};
            }

            auto datagram = serialize_application_candidate(
                probe_crypto_ranges, probe_packet.has_handshake_done, ack_frame,
                probe_max_data_frame, {}, {}, {}, path_validation_frames,
                probe_max_stream_data_frames, probe_packet.max_streams_frames,
                probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                probe_stream_fragments, std::nullopt, include_ping);
            if (!datagram.has_value()) {
                return fail_datagram_send(!pending_tracked_packets.empty());
            }
            const auto pad_probe_datagram_to_target =
                [&](CodecResult<SerializedProtectedDatagram> &candidate,
                    const std::optional<OutboundAckHeader> &candidate_ack_frame,
                    std::span<const StreamFrameSendFragment> fragments) -> bool {
                if (pmtu_probe_padding_already_satisfied(target_pmtu_probe_size,
                                                         candidate.value().bytes.size())) {
                    return true;
                }
                const auto padding = target_pmtu_probe_size - candidate.value().bytes.size();
                auto padded = serialize_application_candidate(
                    probe_crypto_ranges, probe_packet.has_handshake_done, candidate_ack_frame,
                    probe_max_data_frame, {}, {}, {}, path_validation_frames,
                    probe_max_stream_data_frames, probe_packet.max_streams_frames,
                    probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                    probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                    fragments, std::nullopt, include_ping);
                if (!padded.has_value()) {
                    return false;
                }
                std::vector<Frame> crypto_frames;
                append_application_crypto_frames(crypto_frames, probe_crypto_ranges);
                auto frames_with_padding = build_application_candidate_frames(
                    crypto_frames, probe_packet.has_handshake_done, candidate_ack_frame,
                    probe_max_data_frame, {}, {}, {}, path_validation_frames,
                    probe_max_stream_data_frames, probe_packet.max_streams_frames,
                    probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                    probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                    std::nullopt, include_ping);
                static_cast<void>(maybe_add_pmtu_probe_padding(padding, frames_with_padding,
                                                               probe_padding_length));
                padded = serialize_application_candidate_from_frames(
                    frames_with_padding, fragments, /*has_application_close=*/false,
                    application_space_.next_send_packet_number, application_write_key_phase_);
                if (consume_connection_drain_countdown(
                        &ConnectionDrainTestHooks::force_probe_padding_failure_countdown)) {
                    padded = CodecResult<SerializedProtectedDatagram>::failure(
                        CodecErrorCode::packet_length_mismatch, 0);
                }
                if (!padded.has_value()) {
                    return false;
                }
                candidate = std::move(padded);
                return candidate.value().bytes.size() <= target_pmtu_probe_size;
            };
            if (!pad_probe_datagram_to_target(datagram, ack_frame, probe_stream_fragments)) {
                return fail_datagram_send(!pending_tracked_packets.empty());
            }
            if (ack_frame.has_value() &&
                datagram.value().bytes.size() > pmtu_probe_datagram_size_limit) {
                auto no_ack_datagram = serialize_application_candidate(
                    probe_crypto_ranges, probe_packet.has_handshake_done, std::nullopt,
                    probe_max_data_frame, {}, {}, {}, path_validation_frames,
                    probe_max_stream_data_frames, probe_packet.max_streams_frames,
                    probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                    probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                    probe_stream_fragments, std::nullopt, include_ping);
                if (!no_ack_datagram.has_value()) {
                    return fail_datagram_send(!pending_tracked_packets.empty());
                }
                if (no_ack_datagram.value().bytes.size() <= pmtu_probe_datagram_size_limit) {
                    ack_frame = std::nullopt;
                    datagram = std::move(no_ack_datagram);
                }
            }
            const auto trim_probe_candidate_to_fit =
                [&](const std::optional<OutboundAckHeader> &candidate_ack_frame,
                    std::vector<StreamFrameSendFragment> &fragments) -> bool {
                while (datagram.value().bytes.size() > pmtu_probe_datagram_size_limit &&
                       !fragments.empty()) {
                    auto &last_fragment = fragments.back();
                    if (last_fragment.bytes.empty()) {
                        restore_probe_fragment(last_fragment);
                        fragments.pop_back();
                    } else {
                        const auto overshoot =
                            datagram.value().bytes.size() - pmtu_probe_datagram_size_limit;
                        const auto trim_bytes =
                            std::min<std::size_t>(overshoot, last_fragment.bytes.size());
                        if (trim_bytes == last_fragment.bytes.size()) {
                            restore_probe_fragment(last_fragment);
                            fragments.pop_back();
                        } else {
                            StreamFrameSendFragment tail_fragment{
                                .stream_id = last_fragment.stream_id,
                                .offset = last_fragment.offset +
                                          static_cast<std::uint64_t>(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .bytes = last_fragment.bytes.subspan(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .fin = last_fragment.fin,
                                .consumes_flow_control = false,
                            };
                            last_fragment.bytes.resize(last_fragment.bytes.size() - trim_bytes);
                            last_fragment.fin = false;
                            last_fragment.prime_stream_frame_header_cache();
                            tail_fragment.prime_stream_frame_header_cache();
                            restore_probe_fragment(tail_fragment);
                        }
                    }

                    datagram = serialize_application_candidate(
                        probe_crypto_ranges, probe_packet.has_handshake_done, candidate_ack_frame,
                        probe_max_data_frame, {}, {}, {}, path_validation_frames,
                        probe_max_stream_data_frames, probe_packet.max_streams_frames,
                        probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                        probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                        fragments, std::nullopt, include_ping);
                    if (!datagram.has_value()) {
                        mark_failed();
                        return false;
                    }
                }

                return datagram.value().bytes.size() <= pmtu_probe_datagram_size_limit;
            };
            if (!trim_probe_candidate_to_fit(ack_frame, probe_stream_fragments)) {
                if (has_failed()) {
                    return {};
                }

                if (ack_frame.has_value()) {
                    ack_frame = std::nullopt;
                    probe_stream_fragments = make_probe_stream_fragments();
                    mark_probe_fragments_sent(probe_stream_fragments);
                    datagram = serialize_application_candidate(
                        probe_crypto_ranges, probe_packet.has_handshake_done, ack_frame,
                        probe_max_data_frame, {}, {}, {}, path_validation_frames,
                        probe_max_stream_data_frames, probe_packet.max_streams_frames,
                        probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                        probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                        probe_stream_fragments, std::nullopt, include_ping);
                    if (consume_connection_drain_countdown(
                            &ConnectionDrainTestHooks::
                                force_probe_no_ack_retry_failure_countdown)) {
                        datagram = CodecResult<SerializedProtectedDatagram>::failure(
                            CodecErrorCode::packet_length_mismatch, 0);
                    }
                    if (!datagram.has_value()) {
                        return fail_datagram_send(!pending_tracked_packets.empty());
                    }
                    static_cast<void>(
                        trim_probe_candidate_to_fit(ack_frame, probe_stream_fragments));
                }
            }
            const auto retry_probe_candidate_without_fresh_receive_credit = [&]() -> bool {
                if (!fresh_probe_max_data_frame.has_value() &&
                    fresh_probe_max_stream_data_frames.empty()) {
                    return true;
                }

                probe_max_data_frame = probe_packet.max_data_frame;
                probe_max_stream_data_frames = probe_packet.max_stream_data_frames;
                fresh_probe_max_data_frame = std::nullopt;
                fresh_probe_max_stream_data_frames.clear();
                probe_stream_fragments = make_probe_stream_fragments();
                mark_probe_fragments_sent(probe_stream_fragments);
                datagram = serialize_application_candidate(
                    probe_crypto_ranges, probe_packet.has_handshake_done, ack_frame,
                    probe_max_data_frame, {}, {}, {}, path_validation_frames,
                    probe_max_stream_data_frames, probe_packet.max_streams_frames,
                    probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                    probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                    probe_stream_fragments, std::nullopt, include_ping);
                if (!datagram.has_value()) {
                    fail_datagram_send(!pending_tracked_packets.empty());
                    return false;
                }
                return trim_probe_candidate_to_fit(ack_frame, probe_stream_fragments);
            };
            auto probe_datagram_size = datagram_size_or_zero(datagram);
            if (probe_datagram_size > pmtu_probe_datagram_size_limit) {
                probe_padding_length = 0;
                if (should_fail_after_probe_credit_retry(
                        retry_probe_candidate_without_fresh_receive_credit(), has_failed())) {
                    return {};
                }
                probe_datagram_size = datagram_size_or_zero(datagram);
            }
            if (probe_datagram_size > pmtu_probe_datagram_size_limit) {
                restore_unsent_application_probe_candidate();
                restore_unsent_path_validation_frames(path_validation_frames);
                if (!packets.empty()) {
                    return finalize_datagram(packets);
                }
                if (pmtu_probe_datagram_size_limit == kMaximumDatagramSize) {
                    mark_failed();
                    return {};
                }
                return {};
            }

            std::vector<Frame> frames;
            frames.reserve(
                probe_crypto_ranges.size() + (ack_frame.has_value() ? 1u : 0u) +
                (probe_packet.has_handshake_done ? 1u : 0u) +
                (probe_max_data_frame.has_value() ? 1u : 0u) +
                static_cast<std::size_t>(path_validation_frames.response.has_value()) +
                static_cast<std::size_t>(path_validation_frames.challenge.has_value()) +
                probe_max_stream_data_frames.size() + probe_packet.max_streams_frames.size() +
                probe_packet.reset_stream_frames.size() + probe_packet.stop_sending_frames.size() +
                (probe_packet.data_blocked_frame.has_value() ? 1u : 0u) +
                probe_packet.stream_data_blocked_frames.size() + (include_ping ? 1u : 0u));
            append_application_crypto_frames(frames, probe_crypto_ranges);
            append_application_ack_frame(frames, ack_frame);
            if (probe_packet.has_handshake_done) {
                frames.emplace_back(HandshakeDoneFrame{});
            }
            if (probe_max_data_frame.has_value()) {
                frames.emplace_back(*probe_max_data_frame);
            }
            if (path_validation_frames.response.has_value()) {
                frames.emplace_back(*path_validation_frames.response);
            }
            if (path_validation_frames.challenge.has_value()) {
                frames.emplace_back(*path_validation_frames.challenge);
            }
            for (const auto &frame : probe_max_stream_data_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.max_streams_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.reset_stream_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.stop_sending_frames) {
                frames.emplace_back(frame);
            }
            if (probe_packet.data_blocked_frame.has_value()) {
                frames.emplace_back(*probe_packet.data_blocked_frame);
            }
            for (const auto &frame : probe_packet.stream_data_blocked_frames) {
                frames.emplace_back(frame);
            }
            if (include_ping) {
                frames.emplace_back(PingFrame{});
            }
            if (probe_padding_length != 0) {
                frames.emplace_back(PaddingFrame{.length = probe_padding_length});
            }

            const auto packet_number =
                reserve_application_packet_number(!use_zero_rtt_packet_protection);
            if (!packet_number.has_value()) {
                return {};
            }
            auto protected_probe_packet = make_application_protected_packet(
                use_zero_rtt_packet_protection, current_version_,
                application_destination_connection_id(), config_.source_connection_id,
                application_write_key_phase_, kDefaultInitialPacketNumberLength, *packet_number,
                std::move(frames), probe_stream_fragments);
            set_application_packet_spin_bit(protected_probe_packet,
                                            outbound_spin_bit_for_path(selected_send_path_id));
            packets.emplace_back(std::move(protected_probe_packet));
            if (!datagram.has_value()) {
                return fail_datagram_send(!pending_tracked_packets.empty());
            }
            if (fresh_probe_max_data_frame.has_value()) {
                static_cast<void>(connection_flow_control_.take_max_data_frame());
            }
            for (const auto &frame : fresh_probe_max_stream_data_frames) {
                static_cast<void>(streams_.at(frame.stream_id).take_max_stream_data_frame());
            }

            queue_tracked_packet(
                application_space_,
                SentPacketRecord{
                    .packet_number = *packet_number,
                    .sent_time = now,
                    .ack_eliciting = true,
                    .in_flight = true,
                    .declared_lost = false,
                    .has_handshake_done = probe_packet.has_handshake_done,
                    .crypto_ranges = std::vector<ByteRange>(probe_crypto_ranges.begin(),
                                                            probe_crypto_ranges.end()),
                    .reset_stream_frames = probe_packet.reset_stream_frames,
                    .stop_sending_frames = probe_packet.stop_sending_frames,
                    .max_data_frame = probe_max_data_frame,
                    .max_stream_data_frames = probe_max_stream_data_frames,
                    .max_streams_frames = probe_packet.max_streams_frames,
                    .data_blocked_frame = probe_packet.data_blocked_frame,
                    .stream_data_blocked_frames = probe_packet.stream_data_blocked_frames,
                    .stream_fragments = probe_stream_fragments,
                    .has_ping = include_ping,
                    .bytes_in_flight = datagram.value().bytes.size(),
                    .path_id = selected_send_path_id.value_or(0),
                    .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                    .is_pmtu_probe = probe_packet.is_pmtu_probe,
                    .pmtu_probe_size = probe_packet.pmtu_probe_size,
                },
                datagram.value().packet_metadata.back().length);
            note_idle_ack_eliciting_send(now);
            if (probe_packet.has_handshake_done) {
                handshake_done_state_ = StreamControlFrameState::sent;
            }
            if (ack_frame.has_value()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
            }
            if (preserve_pto_probe_packets) {
                restore_unsent_path_validation_frames(path_validation_frames);
            }
            clear_probe_packet_after_send(application_space_.pending_probe_packet);
        } else {
            const auto include_handshake_done =
                !use_zero_rtt_packet_protection && config_.role == EndpointRole::server &&
                handshake_done_state_ == StreamControlFrameState::pending;
            const auto validation_only_path_id = [&]() -> std::optional<QuicPathId> {
                const auto response_path =
                    std::find_if(paths_.begin(), paths_.end(), [](const auto &entry) {
                        return entry.second.pending_response.has_value();
                    });
                if (response_path != paths_.end()) {
                    return response_path->first;
                }
                return current_send_path_id_;
            }();
            const bool validation_only_send = [&]() {
                if (!validation_only_path_id.has_value()) {
                    return false;
                }
                const auto validation_path = paths_.find(*validation_only_path_id);
                if (validation_path == paths_.end()) {
                    return false;
                }
                return static_cast<bool>(!validation_path->second.validated &
                                         !validation_path->second.validation_initiated_locally);
            }();
            auto application_close_frame = pending_application_close_;
            const bool send_application_close_only = application_close_frame.has_value();
            if (application_close_frame.has_value() && !can_send_one_rtt_packets) {
                return {};
            }
            const auto application_candidate_crypto_ranges =
                send_application_close_only ? std::span<const ByteRange>{}
                                            : std::span<const ByteRange>(application_crypto_ranges);
            const auto application_candidate_crypto_frames =
                send_application_close_only ? std::span<const Frame>{}
                                            : std::span<const Frame>(application_crypto_frames);
            const auto send_application_ack_only =
                [&](const OutboundAckHeader &ack_frame) -> DatagramBuffer {
                const auto restore_unsent_path_validation_frames =
                    [&](const PendingPathValidationFrames &path_validation_frames) {
                        if (path_validation_frames.response.has_value()) {
                            auto &path = ensure_path_state(path_validation_frames.path_id);
                            path.pending_response = path_validation_frames.response->data;
                        }
                        if (path_validation_frames.challenge.has_value()) {
                            auto &path = ensure_path_state(path_validation_frames.path_id);
                            path.challenge_pending = true;
                        }
                    };
                auto path_validation_frames = take_path_validation_frames(/*force_ack_only=*/false);
                selected_send_path_id =
                    path_validation_frames.response.has_value()
                        ? std::optional<QuicPathId>{path_validation_frames.path_id}
                        : current_send_path_id_;
                std::vector<Frame> ack_only_frames;
                append_application_ack_frame(ack_only_frames,
                                             std::optional<OutboundAckHeader>{ack_frame});
                if (path_validation_frames.response.has_value()) {
                    ack_only_frames.emplace_back(*path_validation_frames.response);
                }
                if (path_validation_frames.challenge.has_value()) {
                    ack_only_frames.emplace_back(*path_validation_frames.challenge);
                }
                const auto packet_number =
                    reserve_application_packet_number(!use_zero_rtt_packet_protection);
                if (!packet_number.has_value()) {
                    restore_unsent_path_validation_frames(path_validation_frames);
                    return {};
                }
                auto ack_only_packet = make_application_protected_packet(
                    use_zero_rtt_packet_protection, current_version_,
                    application_destination_connection_id(), config_.source_connection_id,
                    application_write_key_phase_, kDefaultInitialPacketNumberLength, *packet_number,
                    std::move(ack_only_frames), {});
                set_application_packet_spin_bit(ack_only_packet,
                                                outbound_spin_bit_for_path(selected_send_path_id));
                packets.emplace_back(std::move(ack_only_packet));
                auto ack_only_datagram = serialize_candidate_datagram_with_metadata(packets);
                if (!ack_only_datagram.has_value()) {
                    restore_unsent_path_validation_frames(path_validation_frames);
                    return fail_datagram_send(!pending_tracked_packets.empty());
                }
                maybe_queue_ack_only_path_validation_packet(path_validation_frames, [&] {
                    queue_tracked_packet(
                        application_space_,
                        SentPacketRecord{
                            .packet_number = *packet_number,
                            .sent_time = now,
                            .ack_eliciting = true,
                            .in_flight = true,
                            .bytes_in_flight = ack_only_datagram.value().bytes.size(),
                            .path_id = selected_send_path_id.value_or(0),
                            .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                        },
                        ack_only_datagram.value().packet_metadata.back().length);
                    note_idle_ack_eliciting_send(now);
                });
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
                return commit_serialized_datagram(packets, std::move(ack_only_datagram.value()));
            };
            const auto force_ack_due =
                application_space_.force_ack_send & base_ack_frame.has_value();
            const auto force_ack_only =
                (force_ack_due | validation_only_send) & !send_application_close_only;
            const auto defer_receive_credit = validation_only_send | send_application_close_only;
            auto max_data_frame = defer_receive_credit
                                      ? std::optional<MaxDataFrame>{}
                                      : connection_flow_control_.take_max_data_frame();
            auto data_blocked_frame = (force_ack_only || send_application_close_only)
                                          ? std::optional<DataBlockedFrame>{}
                                          : connection_flow_control_.take_data_blocked_frame();
            auto max_stream_data_frames = defer_receive_credit
                                              ? std::vector<MaxStreamDataFrame>{}
                                              : take_max_stream_data_frames(streams_);
            auto max_streams_frames = send_application_close_only
                                          ? std::vector<MaxStreamsFrame>{}
                                          : take_max_streams_frames(force_ack_only);
            auto new_token_frames = send_application_close_only
                                        ? std::vector<NewTokenFrame>{}
                                        : take_new_token_frames(force_ack_only);
            auto new_connection_id_frames = take_new_connection_id_frames(force_ack_only);
            auto retire_connection_id_frames = take_retire_connection_id_frames(force_ack_only);
            auto path_validation_frames = take_path_validation_frames(force_ack_only);
            selected_send_path_id = path_validation_frames.response.has_value()
                                        ? std::optional<QuicPathId>{path_validation_frames.path_id}
                                        : current_send_path_id_;
            auto reset_stream_frames = (force_ack_only || send_application_close_only)
                                           ? std::vector<ResetStreamFrame>{}
                                           : take_reset_stream_frames(streams_);
            auto stop_sending_frames = (force_ack_only || send_application_close_only)
                                           ? std::vector<StopSendingFrame>{}
                                           : take_stop_sending_frames(streams_);
            auto stream_data_blocked_frames = (force_ack_only || send_application_close_only)
                                                  ? std::vector<StreamDataBlockedFrame>{}
                                                  : take_stream_data_blocked_frames(streams_);
            const auto congestion_limited_datagram_size = [&]() {
                if (application_space_.pending_probe_packet.has_value() ||
                    send_application_close_only) {
                    return max_outbound_datagram_size;
                }
                const auto cwnd = congestion_controller_.congestion_window();
                const auto bytes_in_flight = congestion_controller_.bytes_in_flight();
                if (bytes_in_flight >= cwnd) {
                    return std::size_t{0};
                }
                return std::min(max_outbound_datagram_size, cwnd - bytes_in_flight);
            }();
            const auto base_application_stream_budget = application_stream_frame_budget(
                congestion_limited_datagram_size, application_destination_connection_id().size());
            auto candidate_last_stream_id = last_application_send_stream_id_;
            auto &stream_fragments = application_stream_fragment_scratch_;
            stream_fragments.clear();
            struct ApplicationStreamScratchGuard {
                std::vector<StreamFrameSendFragment> &fragments;
                std::vector<std::map<std::uint64_t, StreamState>::iterator> &active_streams;
                ~ApplicationStreamScratchGuard() {
                    fragments.clear();
                    active_streams.clear();
                }
            } application_stream_scratch_guard{stream_fragments, active_stream_iterator_scratch_};
            auto selected_ack_frame =
                send_application_close_only
                    ? std::optional<OutboundAckHeader>{}
                    : trim_application_ack_frame(
                          application_candidate_crypto_ranges, include_handshake_done,
                          base_ack_frame, max_data_frame, new_token_frames,
                          new_connection_id_frames, retire_connection_id_frames,
                          path_validation_frames, max_stream_data_frames, max_streams_frames,
                          reset_stream_frames, stop_sending_frames, data_blocked_frame,
                          stream_data_blocked_frames, stream_fragments, /*include_ping=*/false);
            if (has_failed()) {
                return {};
            }

            if (!force_ack_only && !send_application_close_only) {
                auto application_stream_budget = base_application_stream_budget;
                auto control_candidate_size = estimate_application_candidate_size(
                    application_candidate_crypto_ranges, include_handshake_done, selected_ack_frame,
                    max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments,
                    application_close_frame,
                    /*include_ping=*/false);
                const auto minimum_stream_wire_bytes =
                    selected_ack_frame.has_value() ? minimum_pending_application_stream_wire_bytes()
                                                   : std::optional<std::size_t>{};
                if (ack_can_be_trimmed_for_stream_budget(
                        selected_ack_frame, minimum_stream_wire_bytes, control_candidate_size,
                        congestion_limited_datagram_size)) {
                    const auto remaining_stream_budget =
                        control_candidate_size.value() >= congestion_limited_datagram_size
                            ? std::size_t{0}
                            : congestion_limited_datagram_size - control_candidate_size.value();
                    if (remaining_stream_budget < *minimum_stream_wire_bytes) {
                        auto no_ack_control_candidate_size = estimate_application_candidate_size(
                            application_candidate_crypto_ranges, include_handshake_done,
                            std::nullopt, max_data_frame, new_token_frames,
                            new_connection_id_frames, retire_connection_id_frames,
                            path_validation_frames, max_stream_data_frames, max_streams_frames,
                            reset_stream_frames, stop_sending_frames, data_blocked_frame,
                            stream_data_blocked_frames, stream_fragments, application_close_frame,
                            /*include_ping=*/false);
                        if (connection_drain_test_hooks()
                                .force_no_ack_control_candidate_estimate_failure) {
                            no_ack_control_candidate_size = CodecResult<std::size_t>::failure(
                                CodecErrorCode::packet_length_mismatch, 0);
                        } else if (connection_drain_test_hooks()
                                       .force_no_ack_control_candidate_empty_payload) {
                            no_ack_control_candidate_size = CodecResult<std::size_t>::failure(
                                CodecErrorCode::empty_packet_payload, 0);
                        }
                        if (connection_drain_test_hooks()
                                .force_no_ack_control_candidate_estimate_size) {
                            no_ack_control_candidate_size = CodecResult<std::size_t>::success(
                                connection_drain_test_hooks()
                                    .forced_no_ack_control_candidate_estimate_size);
                        }
                        if (!no_ack_control_candidate_size.has_value()) {
                            if (no_ack_control_candidate_size.error().code !=
                                CodecErrorCode::empty_packet_payload) {
                                return fail_datagram_send(!pending_tracked_packets.empty());
                            }
                            static_cast<void>(maybe_select_empty_no_ack_candidate(
                                base_application_stream_budget, *minimum_stream_wire_bytes,
                                selected_ack_frame, application_stream_budget,
                                control_candidate_size, no_ack_control_candidate_size));
                        } else if (no_ack_control_candidate_leaves_stream_budget(
                                       no_ack_control_candidate_size.value(),
                                       congestion_limited_datagram_size,
                                       *minimum_stream_wire_bytes)) {
                            selected_ack_frame = std::nullopt;
                            application_stream_budget = congestion_limited_datagram_size -
                                                        no_ack_control_candidate_size.value();
                            control_candidate_size = no_ack_control_candidate_size;
                        }
                    }
                }
                if (!control_candidate_size.has_value()) {
                    if (control_candidate_size.error().code !=
                        CodecErrorCode::empty_packet_payload) {
                        return fail_datagram_send(!pending_tracked_packets.empty());
                    }
                } else if (control_candidate_size.value() >= congestion_limited_datagram_size) {
                    application_stream_budget = 0;
                } else {
                    application_stream_budget =
                        congestion_limited_datagram_size - control_candidate_size.value();
                }

                SendProfileTimer stream_select_timer(send_profile_counters().stream_select_ns);
                take_stream_fragments(connection_flow_control_, streams_, application_stream_budget,
                                      candidate_last_stream_id, stream_fragments,
                                      prefer_fresh_application_stream_data);
            }

            const auto candidate_application_write_key_phase = application_write_key_phase_;
            auto candidate_datagram = serialize_application_candidate(
                application_candidate_crypto_ranges, include_handshake_done, selected_ack_frame,
                max_data_frame, new_token_frames, new_connection_id_frames,
                retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                max_streams_frames, reset_stream_frames, stop_sending_frames, data_blocked_frame,
                stream_data_blocked_frames, stream_fragments, application_close_frame,
                /*include_ping=*/false);
            const auto finalize_existing_packets_or_empty = [&]() -> DatagramBuffer {
                if (packets.empty()) {
                    return {};
                }
                selected_send_path_id = current_send_path_id_;
                return finalize_datagram(packets);
            };
            if (!candidate_datagram.has_value()) {
                if (is_empty_packet_payload_error(candidate_datagram)) {
                    if (packet_trace_matches_connection(config_.source_connection_id)) {
                        std::cerr << "quic-packet-trace app-empty scid="
                                  << format_connection_id_hex(config_.source_connection_id)
                                  << " packets=" << packets.size()
                                  << " stream_fragments=" << stream_fragments.size()
                                  << " stream_bytes=" << stream_fragment_bytes(stream_fragments)
                                  << " ack=" << static_cast<int>(selected_ack_frame.has_value())
                                  << " hsdone=" << static_cast<int>(include_handshake_done) << "\n";
                    }
                    return finalize_existing_packets_or_empty();
                }
                return fail_datagram_send(!pending_tracked_packets.empty());
            }
            if (selected_ack_frame.has_value() &&
                candidate_datagram.value().bytes.size() > max_outbound_datagram_size) {
                auto no_ack_candidate = serialize_application_candidate(
                    application_candidate_crypto_ranges, include_handshake_done, std::nullopt,
                    max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments,
                    application_close_frame,
                    /*include_ping=*/false);
                if (consume_connection_drain_countdown(
                        &ConnectionDrainTestHooks::
                            force_application_no_ack_candidate_failure_countdown)) {
                    no_ack_candidate = CodecResult<SerializedProtectedDatagram>::failure(
                        CodecErrorCode::packet_length_mismatch, 0);
                }
                if (!no_ack_candidate.has_value()) {
                    if (!is_empty_packet_payload_error(no_ack_candidate)) {
                        return fail_datagram_send(!pending_tracked_packets.empty());
                    }
                } else if (no_ack_candidate.value().bytes.size() <= max_outbound_datagram_size) {
                    selected_ack_frame = std::nullopt;
                    candidate_datagram = std::move(no_ack_candidate);
                }
            }

            const auto trim_candidate_to_fit =
                [&](const std::optional<OutboundAckHeader> &ack_frame,
                    CodecResult<SerializedProtectedDatagram> &datagram,
                    std::vector<StreamFrameSendFragment> &fragments) -> bool {
                while (datagram.value().bytes.size() > max_outbound_datagram_size &&
                       !fragments.empty()) {
                    auto &last_fragment = fragments.back();
                    if (last_fragment.bytes.empty()) {
                        restore_application_fragment(last_fragment);
                        fragments.pop_back();
                    } else {
                        const auto overshoot =
                            datagram.value().bytes.size() - max_outbound_datagram_size;
                        const auto trim_bytes =
                            std::min<std::size_t>(overshoot, last_fragment.bytes.size());
                        if (trim_bytes == last_fragment.bytes.size()) {
                            restore_application_fragment(last_fragment);
                            fragments.pop_back();
                        } else {
                            StreamFrameSendFragment tail_fragment{
                                .stream_id = last_fragment.stream_id,
                                .offset = last_fragment.offset +
                                          static_cast<std::uint64_t>(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .bytes = last_fragment.bytes.subspan(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .fin = last_fragment.fin,
                                .consumes_flow_control = last_fragment.consumes_flow_control,
                            };
                            last_fragment.bytes.resize(last_fragment.bytes.size() - trim_bytes);
                            last_fragment.fin = false;
                            last_fragment.prime_stream_frame_header_cache();
                            tail_fragment.prime_stream_frame_header_cache();
                            restore_application_fragment(tail_fragment);
                        }
                    }

                    datagram = serialize_application_candidate(
                        application_candidate_crypto_ranges, include_handshake_done, ack_frame,
                        max_data_frame, new_token_frames, new_connection_id_frames,
                        retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                        max_streams_frames, reset_stream_frames, stop_sending_frames,
                        data_blocked_frame, stream_data_blocked_frames, fragments,
                        application_close_frame,
                        /*include_ping=*/false);
                    if (consume_connection_drain_countdown(
                            &ConnectionDrainTestHooks::
                                force_application_trim_candidate_failure_countdown)) {
                        datagram = CodecResult<SerializedProtectedDatagram>::failure(
                            CodecErrorCode::packet_length_mismatch, 0);
                    } else if (consume_connection_drain_countdown(
                                   &ConnectionDrainTestHooks::
                                       force_application_trim_candidate_empty_payload_countdown)) {
                        datagram = CodecResult<SerializedProtectedDatagram>::failure(
                            CodecErrorCode::empty_packet_payload, 0);
                    }
                    if (!datagram.has_value()) {
                        if (is_empty_packet_payload_error(datagram)) {
                            return false;
                        }
                        fail_datagram_send(!pending_tracked_packets.empty());
                        return false;
                    }
                }

                return datagram.value().bytes.size() <= max_outbound_datagram_size;
            };
            const auto fallback_to_existing_packets_or_ack_only = [&]() -> DatagramBuffer {
                if (!packets.empty()) {
                    return finalize_existing_packets_or_empty();
                }
                if (selected_ack_frame.has_value()) {
                    return send_application_ack_only(*selected_ack_frame);
                }
                return {};
            };

            if (!trim_candidate_to_fit(selected_ack_frame, candidate_datagram, stream_fragments)) {
                if (has_failed()) {
                    return {};
                }
                if (selected_ack_frame.has_value()) {
                    restore_unsent_application_candidate(
                        max_data_frame, new_token_frames, new_connection_id_frames,
                        retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                        max_streams_frames, reset_stream_frames, stop_sending_frames,
                        data_blocked_frame, stream_data_blocked_frames, stream_fragments);

                    max_data_frame = connection_flow_control_.take_max_data_frame();
                    data_blocked_frame = connection_flow_control_.take_data_blocked_frame();
                    max_stream_data_frames = take_max_stream_data_frames(streams_);
                    max_streams_frames = take_max_streams_frames(/*force_ack_only=*/false);
                    new_token_frames = take_new_token_frames(/*force_ack_only=*/false);
                    new_connection_id_frames =
                        take_new_connection_id_frames(/*force_ack_only=*/false);
                    retire_connection_id_frames =
                        take_retire_connection_id_frames(/*force_ack_only=*/false);
                    path_validation_frames = take_path_validation_frames(/*force_ack_only=*/false);
                    reset_stream_frames = take_reset_stream_frames(streams_);
                    stop_sending_frames = take_stop_sending_frames(streams_);
                    stream_data_blocked_frames = take_stream_data_blocked_frames(streams_);
                    candidate_last_stream_id = last_application_send_stream_id_;
                    SendProfileTimer stream_select_timer(send_profile_counters().stream_select_ns);
                    take_stream_fragments(connection_flow_control_, streams_,
                                          base_application_stream_budget, candidate_last_stream_id,
                                          stream_fragments, prefer_fresh_application_stream_data);
                    selected_ack_frame = std::nullopt;
                    candidate_datagram = serialize_application_candidate(
                        application_candidate_crypto_ranges, include_handshake_done,
                        selected_ack_frame, max_data_frame, new_token_frames,
                        new_connection_id_frames, retire_connection_id_frames,
                        path_validation_frames, max_stream_data_frames, max_streams_frames,
                        reset_stream_frames, stop_sending_frames, data_blocked_frame,
                        stream_data_blocked_frames, stream_fragments, application_close_frame,
                        /*include_ping=*/false);
                    if (consume_connection_drain_countdown(
                            &ConnectionDrainTestHooks::
                                force_application_no_ack_retry_failure_countdown)) {
                        candidate_datagram = CodecResult<SerializedProtectedDatagram>::failure(
                            CodecErrorCode::packet_length_mismatch, 0);
                    }
                    if (should_fail_non_empty_packet_payload_candidate(candidate_datagram)) {
                        return fail_datagram_send(!pending_tracked_packets.empty());
                    }
                    static_cast<void>(trim_candidate_to_fit(selected_ack_frame, candidate_datagram,
                                                            stream_fragments));
                }
                if (!candidate_datagram.has_value()) {
                    return fallback_to_existing_packets_or_ack_only();
                }
            }
            const auto retry_candidate_without_receive_credit = [&]() {
                if (!max_data_frame.has_value() && max_stream_data_frames.empty()) {
                    return;
                }

                restore_unsent_application_candidate(
                    max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments);
                max_data_frame = std::nullopt;
                data_blocked_frame = connection_flow_control_.take_data_blocked_frame();
                max_stream_data_frames.clear();
                max_streams_frames = take_max_streams_frames(/*force_ack_only=*/false);
                new_token_frames = take_new_token_frames(/*force_ack_only=*/false);
                new_connection_id_frames = take_new_connection_id_frames(/*force_ack_only=*/false);
                retire_connection_id_frames =
                    take_retire_connection_id_frames(/*force_ack_only=*/false);
                path_validation_frames = take_path_validation_frames(/*force_ack_only=*/false);
                reset_stream_frames = take_reset_stream_frames(streams_);
                stop_sending_frames = take_stop_sending_frames(streams_);
                stream_data_blocked_frames = take_stream_data_blocked_frames(streams_);
                candidate_last_stream_id = last_application_send_stream_id_;
                SendProfileTimer stream_select_timer(send_profile_counters().stream_select_ns);
                take_stream_fragments(connection_flow_control_, streams_,
                                      base_application_stream_budget, candidate_last_stream_id,
                                      stream_fragments, prefer_fresh_application_stream_data);
                candidate_datagram = serialize_application_candidate(
                    application_candidate_crypto_ranges, include_handshake_done, selected_ack_frame,
                    max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments,
                    application_close_frame,
                    /*include_ping=*/false);
                if (!candidate_datagram.has_value()) {
                    if (should_fail_non_empty_packet_payload_candidate(candidate_datagram)) {
                        fail_datagram_send(!pending_tracked_packets.empty());
                    }
                    return;
                }
                static_cast<void>(trim_candidate_to_fit(selected_ack_frame, candidate_datagram,
                                                        stream_fragments));
            };
            const auto retry_application_close_without_reason = [&]() -> bool {
                if (!send_application_close_only) {
                    return false;
                }

                auto &retry_close_frame = *application_close_frame;
                if (retry_close_frame.reason.bytes.empty()) {
                    return false;
                }

                retry_close_frame.reason.bytes.clear();
                candidate_datagram = serialize_application_candidate(
                    application_candidate_crypto_ranges, include_handshake_done, selected_ack_frame,
                    max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments,
                    application_close_frame,
                    /*include_ping=*/false);
                if (!candidate_datagram.has_value()) {
                    // A close-only retry still carries the close frame, so any serialization error
                    // is fatal.
                    fail_datagram_send(!pending_tracked_packets.empty());
                    return false;
                }
                return candidate_datagram.value().bytes.size() <= max_outbound_datagram_size;
            };
            const auto mark_application_close_unusable = [&]() {
                if (!send_application_close_only) {
                    return;
                }
                pending_application_close_.reset();
                local_application_close_sent_ = true;
                enter_closing_state(now, QuicConnectionTerminalState::closed);
            };
            auto candidate_datagram_size = datagram_size_or_zero(candidate_datagram);
            if (candidate_datagram_size > max_outbound_datagram_size) {
                retry_candidate_without_receive_credit();
                if (has_failed()) {
                    return {};
                }
                if (!candidate_datagram.has_value()) {
                    return fallback_to_existing_packets_or_ack_only();
                }
                candidate_datagram_size = datagram_size_or_zero(candidate_datagram);
            }
            if (candidate_datagram_size > max_outbound_datagram_size &&
                retry_application_close_without_reason()) {
                candidate_datagram_size = datagram_size_or_zero(candidate_datagram);
            }
            if (has_failed()) {
                return {};
            }
            if (candidate_datagram_size > max_outbound_datagram_size) {
                restore_unsent_application_candidate(
                    max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments);
                if (!packets.empty()) {
                    selected_send_path_id = current_send_path_id_;
                    return finalize_datagram(packets);
                }
                if (max_outbound_datagram_size == kMaximumDatagramSize) {
                    mark_application_close_unusable();
                    if (!send_application_close_only) {
                        mark_failed();
                    }
                    return {};
                }
                return fallback_to_existing_packets_or_ack_only();
            }
            std::vector<Frame> frames;
            frames.reserve(
                application_candidate_crypto_frames.size() +
                (selected_ack_frame.has_value() ? 1u : 0u) + (include_handshake_done ? 1u : 0u) +
                reset_stream_frames.size() + stop_sending_frames.size() +
                (max_data_frame.has_value() ? 1u : 0u) + new_token_frames.size() +
                new_connection_id_frames.size() + retire_connection_id_frames.size() +
                static_cast<std::size_t>(path_validation_frames.response.has_value()) +
                static_cast<std::size_t>(path_validation_frames.challenge.has_value()) +
                max_stream_data_frames.size() + max_streams_frames.size() +
                (data_blocked_frame.has_value() ? 1u : 0u) + stream_data_blocked_frames.size() +
                (application_close_frame.has_value() ? 1u : 0u));
            for (const auto &frame : application_candidate_crypto_frames) {
                frames.emplace_back(frame);
            }
            append_application_ack_frame(frames, selected_ack_frame);
            if (include_handshake_done) {
                frames.emplace_back(HandshakeDoneFrame{});
            }
            const auto ack_eliciting =
                !application_candidate_crypto_frames.empty() ||
                application_ack_eliciting_frame_count(
                    new_token_frames, include_handshake_done, max_data_frame,
                    new_connection_id_frames, retire_connection_id_frames,
                    path_validation_frames.response.has_value(),
                    path_validation_frames.challenge.has_value(), max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments) != 0;
            const bool has_non_pmtu_application_probe =
                application_space_.pending_probe_packet.has_value() &&
                !application_space_.pending_probe_packet->is_pmtu_probe;
            const auto bypass_congestion_window =
                has_non_pmtu_application_probe ||
                (path_validation_frames.challenge.has_value() && stream_fragments.empty());
            const auto pacing_deadline =
                ack_eliciting && !bypass_congestion_window
                    ? congestion_controller_.next_send_time(candidate_datagram.value().bytes.size())
                    : std::nullopt;
            const bool application_send_congestion_blocked =
                ack_eliciting && !bypass_congestion_window &&
                (connection_drain_test_hooks().force_application_send_congestion_blocked ||
                 !congestion_controller_.can_send_ack_eliciting(
                     candidate_datagram.value().bytes.size()));
            if (application_send_congestion_blocked) {
                if (traces_this_connection) {
                    std::cerr
                        << "quic-packet-trace send-blocked scid="
                        << format_connection_id_hex(config_.source_connection_id)
                        << " reason=congestion"
                        << " size=" << candidate_datagram.value().bytes.size()
                        << " current=" << format_optional_path_id(current_send_path_id_)
                        << " previous=" << format_optional_path_id(previous_path_id_)
                        << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                        << " current_path={"
                        << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                        << "} cwnd=" << congestion_controller_.congestion_window()
                        << " bif=" << congestion_controller_.bytes_in_flight()
                        << " pending_send=" << static_cast<int>(has_pending_application_send())
                        << " probe="
                        << static_cast<int>(application_space_.pending_probe_packet.has_value())
                        << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                        << '\n';
                }
                if (send_profile_enabled()) {
                    auto &profile = send_profile_counters();
                    ++profile.congestion_blocks;
                    const auto cwnd = congestion_controller_.congestion_window();
                    const auto bif = congestion_controller_.bytes_in_flight();
                    profile.congestion_block_cwnd_sum += cwnd;
                    profile.congestion_block_bif_sum += bif;
                    profile.congestion_block_max_cwnd =
                        std::max<std::uint64_t>(profile.congestion_block_max_cwnd, cwnd);
                    profile.congestion_block_min_cwnd =
                        profile.congestion_block_min_cwnd == 0
                            ? cwnd
                            : std::min<std::uint64_t>(profile.congestion_block_min_cwnd, cwnd);
                }
                restore_unsent_application_candidate(
                    max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments);
                return fallback_to_existing_packets_or_ack_only();
            }
            if (pacing_deadline.has_value() && now < *pacing_deadline) {
                if (traces_this_connection) {
                    std::cerr
                        << "quic-packet-trace send-blocked scid="
                        << format_connection_id_hex(config_.source_connection_id)
                        << " reason=pacing"
                        << " size=" << candidate_datagram.value().bytes.size()
                        << " current=" << format_optional_path_id(current_send_path_id_)
                        << " previous=" << format_optional_path_id(previous_path_id_)
                        << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                        << " current_path={"
                        << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                        << "} cwnd=" << congestion_controller_.congestion_window()
                        << " bif=" << congestion_controller_.bytes_in_flight()
                        << " pending_send=" << static_cast<int>(has_pending_application_send())
                        << " probe="
                        << static_cast<int>(application_space_.pending_probe_packet.has_value())
                        << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                        << '\n';
                }
                if (send_profile_enabled()) {
                    ++send_profile_counters().pacing_blocks;
                }
                restore_unsent_application_candidate(
                    max_data_frame, new_token_frames, new_connection_id_frames,
                    retire_connection_id_frames, path_validation_frames, max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments);
                return fallback_to_existing_packets_or_ack_only();
            }
            last_application_send_stream_id_ = candidate_last_stream_id;
            if (send_profile_enabled()) {
                send_profile_counters().stream_bytes += stream_fragment_bytes(stream_fragments);
            }

            for (const auto &frame : reset_stream_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : stop_sending_frames) {
                frames.emplace_back(frame);
            }
            if (max_data_frame.has_value()) {
                frames.emplace_back(*max_data_frame);
            }
            for (const auto &frame : new_token_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : new_connection_id_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : retire_connection_id_frames) {
                frames.emplace_back(frame);
            }
            if (path_validation_frames.response.has_value()) {
                frames.emplace_back(*path_validation_frames.response);
            }
            if (path_validation_frames.challenge.has_value()) {
                frames.emplace_back(*path_validation_frames.challenge);
            }
            for (const auto &frame : max_stream_data_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : max_streams_frames) {
                frames.emplace_back(frame);
            }
            if (data_blocked_frame.has_value()) {
                frames.emplace_back(*data_blocked_frame);
            }
            for (const auto &frame : stream_data_blocked_frames) {
                frames.emplace_back(frame);
            }
            if (application_close_frame.has_value()) {
                frames.emplace_back(*application_close_frame);
            }

            const bool has_application_close = application_close_frame.has_value();
            const auto packet_number = reserve_application_packet_number(
                (!use_zero_rtt_packet_protection) | has_application_close);
            if (!packet_number.has_value()) {
                if (path_validation_frames.response.has_value()) {
                    auto &path = ensure_path_state(path_validation_frames.path_id);
                    path.pending_response = path_validation_frames.response->data;
                }
                if (path_validation_frames.challenge.has_value()) {
                    auto &path = ensure_path_state(path_validation_frames.path_id);
                    path.challenge_pending = true;
                }
                return {};
            }
            if (application_write_key_phase_ != candidate_application_write_key_phase) {
                auto final_candidate_datagram = serialize_application_candidate_from_frames(
                    frames, stream_fragments, has_application_close, *packet_number,
                    application_write_key_phase_);
                if (!final_candidate_datagram.has_value()) {
                    return fail_datagram_send(!pending_tracked_packets.empty());
                }
                candidate_datagram = std::move(final_candidate_datagram);
            }
            const auto stream_bytes = stream_fragment_bytes(stream_fragments);
            if (packet_trace_matches_connection(config_.source_connection_id)) {
                const auto ack_trace_value = static_cast<int>(selected_ack_frame.has_value());
                const auto handshake_done_trace_value = static_cast<int>(include_handshake_done);
                std::cerr << "quic-packet-trace send scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " pn=" << *packet_number << " ack=" << ack_trace_value
                          << " hsdone=" << handshake_done_trace_value << " stream=" << stream_bytes
                          << " max_data=" << optional_frame_trace_value(max_data_frame)
                          << " max_stream_data=" << max_stream_data_frames.size()
                          << " data_blocked=" << optional_frame_trace_value(data_blocked_frame)
                          << " stream_data_blocked=" << stream_data_blocked_frames.size()
                          << " bytes=" << candidate_datagram.value().bytes.size() << '\n';
            }
            const auto serialized_packet_index = packets.size();
            const bool use_fast_serialized_one_rtt_commit =
                use_fast_serialized_one_rtt_commit_for_packet(
                    config_.role, packets.empty(), qlog_session_.get(),
                    use_zero_rtt_packet_protection, has_application_close);
            if (!use_fast_serialized_one_rtt_commit) {
                auto application_packet = make_application_protected_packet(
                    use_zero_rtt_packet_protection & !has_application_close, current_version_,
                    application_destination_connection_id(), config_.source_connection_id,
                    application_write_key_phase_, kDefaultInitialPacketNumberLength, *packet_number,
                    std::move(frames), stream_fragments);
                set_application_packet_spin_bit(application_packet,
                                                outbound_spin_bit_for_path(selected_send_path_id));
                packets.emplace_back(std::move(application_packet));
            }

            if (ack_eliciting) {
                SentPacketRecord sent_packet{
                    .packet_number = *packet_number,
                    .sent_time = now,
                    .ack_eliciting = ack_eliciting,
                    .in_flight = ack_eliciting,
                    .declared_lost = false,
                    .has_handshake_done = include_handshake_done,
                    .crypto_ranges =
                        std::vector<ByteRange>(application_candidate_crypto_ranges.begin(),
                                               application_candidate_crypto_ranges.end()),
                    .new_token_frames = new_token_frames,
                    .reset_stream_frames = reset_stream_frames,
                    .stop_sending_frames = stop_sending_frames,
                    .new_connection_id_frames = new_connection_id_frames,
                    .retire_connection_id_frames = retire_connection_id_frames,
                    .max_data_frame = max_data_frame,
                    .max_stream_data_frames = max_stream_data_frames,
                    .max_streams_frames = max_streams_frames,
                    .data_blocked_frame = data_blocked_frame,
                    .stream_data_blocked_frames = stream_data_blocked_frames,
                    .stream_fragments = stream_fragments,
                    .bytes_in_flight = candidate_datagram.value().bytes.size(),
                    .path_id = selected_send_path_id.value_or(0),
                    .ecn = outbound_ecn_codepoint_for_path(selected_send_path_id),
                };
                queue_tracked_packet_at_index(
                    application_space_, std::move(sent_packet), serialized_packet_index,
                    candidate_datagram.value().packet_metadata.back().length);
                note_idle_ack_eliciting_send(now);
            }
            if (include_handshake_done) {
                handshake_done_state_ = StreamControlFrameState::sent;
            }
            if (selected_ack_frame.has_value()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
            }
            if (!validation_only_send) {
                clear_probe_packet_after_send(application_space_.pending_probe_packet);
            }
            if (application_close_frame.has_value()) {
                pending_application_close_.reset();
                local_application_close_sent_ = true;
                mark_connection_close_frame_sent(*application_close_frame, now);
            }
            if (use_fast_serialized_one_rtt_commit) {
                return commit_serialized_datagram({}, std::move(candidate_datagram.value()));
            }
            return commit_serialized_datagram(packets, std::move(candidate_datagram.value()));
        }
    }

    if (packets.empty()) {
        if (traces_this_connection & (has_pending_application_send() |
                                      application_space_.pending_probe_packet.has_value())) {
            std::cerr << "quic-packet-trace send-empty scid="
                      << format_connection_id_hex(config_.source_connection_id)
                      << " max=" << max_outbound_datagram_size
                      << " current=" << format_optional_path_id(current_send_path_id_)
                      << " previous=" << format_optional_path_id(previous_path_id_)
                      << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                      << " current_path={"
                      << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                      << "} inbound_path={"
                      << format_path_state_summary(find_path_state(paths_, last_inbound_path_id_))
                      << "} pending_send=" << static_cast<int>(has_pending_application_send())
                      << " probe="
                      << static_cast<int>(application_space_.pending_probe_packet.has_value())
                      << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                      << " pto_count=" << pto_count_
                      << " cwnd=" << congestion_controller_.congestion_window()
                      << " bif=" << congestion_controller_.bytes_in_flight() << '\n';
        }
        if (send_profile_enabled()) {
            ++send_profile_counters().empty_drains;
        }
        return {};
    }

    return finalize_datagram(packets);
}

} // namespace coquic::quic

#if defined(__clang__)
#pragma clang attribute push(__attribute__((no_profile_instrument_function)), apply_to = function)
#endif

namespace coquic::quic::test {

struct ConnectionCoverageTestPeer {
    static QuicConnection make_connected_client(QuicCoreConfig config,
                                                std::optional<std::size_t> pmtud_ceiling) {
        if (pmtud_ceiling.has_value()) {
            config.max_outbound_datagram_size = *pmtud_ceiling;
            config.transport.max_udp_payload_size = *pmtud_ceiling;
            config.transport.pmtud_enabled = true;
            config.transport.pmtud_base_datagram_size = 1200;
            config.transport.pmtud_max_datagram_size = *pmtud_ceiling;
        }

        QuicConnection connection(std::move(config));
        connection.started_ = true;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = true;
        connection.peer_source_connection_id_ = {std::byte{0xa1}, std::byte{0xb2}};
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.application_space_.read_secret =
            make_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
        connection.application_space_.write_secret =
            make_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});
        connection.peer_transport_parameters_ = TransportParameters{
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
        connection.last_validated_path_id_ = 0;
        connection.current_send_path_id_ = 0;
        auto &path = connection.ensure_path_state(0);
        path.validated = true;
        path.is_current_send_path = true;
        connection.application_space_.recovery.rtt_state() = connection.recovery_rtt_state_;
        return connection;
    }

    static std::vector<std::byte> serialize_one_rtt_packet(const QuicConnection &connection,
                                                           std::uint64_t packet_number,
                                                           std::span<const Frame> frames) {
        const auto encoded = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames = std::vector<Frame>(frames.begin(), frames.end()),
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret = connection.application_space_.read_secret,
            });
        if (!encoded.has_value()) {
            return {};
        }
        return encoded.value();
    }

  private:
    static TrafficSecret make_traffic_secret(CipherSuite cipher_suite, std::byte fill) {
        const std::size_t secret_size =
            cipher_suite == CipherSuite::tls_aes_256_gcm_sha384 ? 48u : 32u;
        return TrafficSecret{
            .cipher_suite = cipher_suite,
            .secret = std::vector<std::byte>(secret_size, fill),
        };
    }
};

namespace {

class ScopedEnvVarForTests {
  public:
    ScopedEnvVarForTests(const char *name, std::optional<std::string_view> value) : name_(name) {
        if (const char *existing = std::getenv(name_); existing != nullptr) {
            previous_ = std::string(existing);
            had_previous_ = true;
        }

        if (value.has_value()) {
            static_cast<void>(::setenv(name_, std::string(*value).c_str(), 1));
        } else {
            static_cast<void>(::unsetenv(name_));
        }
    }

    ~ScopedEnvVarForTests() {
        if (had_previous_) {
            static_cast<void>(::setenv(name_, previous_.c_str(), 1));
            return;
        }

        static_cast<void>(::unsetenv(name_));
    }

    ScopedEnvVarForTests(const ScopedEnvVarForTests &) = delete;
    ScopedEnvVarForTests &operator=(const ScopedEnvVarForTests &) = delete;

  private:
    const char *name_;
    std::string previous_;
    bool had_previous_ = false;
};

std::vector<std::byte> bytes_from_ints_for_tests(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

TrafficSecret
make_test_traffic_secret(CipherSuite cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
                         std::byte fill = std::byte{0x11}) {
    const std::size_t secret_size = cipher_suite == CipherSuite::tls_aes_256_gcm_sha384 ? 48u : 32u;
    return TrafficSecret{
        .cipher_suite = cipher_suite,
        .secret = std::vector<std::byte>(secret_size, fill),
    };
}

CipherSuite invalid_cipher_suite_for_tests() {
    constexpr std::uint8_t raw = 0xff;
    CipherSuite value{};
    std::memcpy(&value, &raw, sizeof(value));
    return value;
}

QuicCoreConfig make_client_core_config_for_connection_coverage() {
    return QuicCoreConfig{
        .role = EndpointRole::client,
        .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
        .initial_destination_connection_id =
            {
                std::byte{0x83},
                std::byte{0x94},
                std::byte{0xc8},
                std::byte{0xf0},
                std::byte{0x3e},
                std::byte{0x51},
                std::byte{0x57},
                std::byte{0x08},
            },
        .verify_peer = false,
        .server_name = "localhost",
    };
}

#if !defined(COQUIC_WASM_NO_FILESYSTEM)
std::string read_text_file_for_connection_coverage(std::string_view path) {
    std::ifstream input(std::string(path), std::ios::binary);
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

bool drive_tls_handshake_for_connection_coverage(TlsAdapter &client, TlsAdapter &server) {
    struct TlsTransfer {
        TlsAdapter &source;
        TlsAdapter &destination;
    };
    const auto transfer_pending = [](TlsTransfer transfer, EncryptionLevel level) {
        const auto pending = transfer.source.take_pending(level);
        if (pending.empty()) {
            return true;
        }
        return transfer.destination.provide(level, pending).has_value();
    };

    if (!client.start().has_value()) {
        return false;
    }
    if (!transfer_pending(TlsTransfer{client, server}, EncryptionLevel::initial)) {
        return false;
    }

    for (int index = 0; index < 32; ++index) {
        if (!transfer_pending(TlsTransfer{client, server}, EncryptionLevel::initial) ||
            !transfer_pending(TlsTransfer{server, client}, EncryptionLevel::initial) ||
            !transfer_pending(TlsTransfer{server, client}, EncryptionLevel::handshake) ||
            !transfer_pending(TlsTransfer{client, server}, EncryptionLevel::handshake)) {
            return false;
        }

        client.poll();
        server.poll();
        if (client.handshake_complete() && server.handshake_complete()) {
            return true;
        }
    }

    return client.handshake_complete() && server.handshake_complete();
}
#endif

QuicConnection make_connected_client_connection_for_connection_coverage(QuicCoreConfig config) {
    return ConnectionCoverageTestPeer::make_connected_client(std::move(config), std::nullopt);
}

QuicConnection make_connected_client_connection_for_connection_coverage() {
    return make_connected_client_connection_for_connection_coverage(
        make_client_core_config_for_connection_coverage());
}

QuicConnection make_connected_pmtud_client_connection_for_connection_coverage() {
    return ConnectionCoverageTestPeer::make_connected_client(
        make_client_core_config_for_connection_coverage(), 4096);
}

bool connection_coverage_check(bool &ok, const char *label, bool condition) {
    if (!condition) {
        std::cerr << "connection_key_update_and_probe_coverage_for_tests failed: " << label << '\n';
    }
    ok &= condition;
    return condition;
}

std::vector<std::byte> serialize_one_rtt_packet_for_connection_coverage(
    const QuicConnection &connection, std::uint64_t packet_number,
    std::span<const Frame> frames = std::span<const Frame>{}) {
    return ConnectionCoverageTestPeer::serialize_one_rtt_packet(connection, packet_number, frames);
}

} // namespace

bool connection_helper_edge_cases_for_tests() {
    constexpr std::array supported_versions = {kQuicVersion2, kQuicVersion1};
    const auto retry_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x00}};
    const bool retry_same_version_omits_version_information =
        !version_information_for_handshake(supported_versions, kQuicVersion1,
                                           retry_source_connection_id, kQuicVersion1, kQuicVersion1)
             .has_value();
    const bool retry_version_change_keeps_version_information =
        version_information_for_handshake(supported_versions, kQuicVersion2,
                                          retry_source_connection_id, kQuicVersion1, kQuicVersion2)
            .has_value();

    const auto failed_datagram =
        CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    const auto successful_datagram =
        CodecResult<std::vector<std::byte>>::success({std::byte{0x01}, std::byte{0x02}});
    const auto empty_packet_payload_datagram =
        CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::empty_packet_payload, 0);
    const auto failed_serialized_datagram =
        CodecResult<SerializedProtectedDatagram>::failure(CodecErrorCode::invalid_varint, 0);
    const auto empty_packet_payload_serialized_datagram =
        CodecResult<SerializedProtectedDatagram>::failure(CodecErrorCode::empty_packet_payload, 0);
    SerializedProtectedDatagram successful_serialized_datagram_value;
    successful_serialized_datagram_value.bytes =
        DatagramBuffer{std::byte{0x03}, std::byte{0x04}, std::byte{0x05}};
    const auto successful_serialized_datagram = CodecResult<SerializedProtectedDatagram>::success(
        std::move(successful_serialized_datagram_value));
    const bool failed_datagram_reports_zero_size = datagram_size_or_zero(failed_datagram) == 0;
    const bool successful_datagram_reports_size = datagram_size_or_zero(successful_datagram) == 2;
    const bool failed_serialized_datagram_reports_zero_size =
        datagram_size_or_zero(failed_serialized_datagram) == 0;
    const bool successful_serialized_datagram_reports_size =
        datagram_size_or_zero(successful_serialized_datagram) == 3;
    const bool empty_packet_payload_error_reported =
        is_empty_packet_payload_error(empty_packet_payload_datagram);
    const bool successful_datagram_not_reported =
        !is_empty_packet_payload_error(successful_datagram);
    const bool non_empty_packet_payload_error_not_reported =
        !is_empty_packet_payload_error(failed_datagram);
    const bool empty_packet_payload_serialized_error_reported =
        is_empty_packet_payload_error(empty_packet_payload_serialized_datagram);
    const bool non_empty_packet_payload_serialized_error_not_reported =
        !is_empty_packet_payload_error(failed_serialized_datagram);

    TransportParameters invalid_transport_parameters;
    invalid_transport_parameters.max_udp_payload_size = std::numeric_limits<std::uint64_t>::max();
    const bool encode_failure_returns_empty =
        encode_resumption_state({}, kQuicVersion1, "h3", invalid_transport_parameters, {}).empty();

    constexpr std::array wrong_magic_bytes = {std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
                                              std::byte{0x00}, std::byte{0x00}};
    const bool wrong_magic_rejected = !decode_resumption_state(wrong_magic_bytes).has_value();

    std::vector<std::byte> truncated_tls_state = {std::byte{0x01}};
    append_u32_be(truncated_tls_state, kQuicVersion1);
    const bool truncated_tls_state_rejected =
        !decode_resumption_state(truncated_tls_state).has_value();

    const TransportParameters resumption_transport_parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 8,
        .initial_source_connection_id = ConnectionId{std::byte{0x01}},
    };
    const auto transport_parameters =
        serialize_transport_parameters(resumption_transport_parameters).value();

    std::vector<std::byte> missing_application_context = {std::byte{0x01}};
    append_u32_be(missing_application_context, kQuicVersion1);
    append_length_prefixed_bytes(missing_application_context, {});
    append_length_prefixed_text(missing_application_context, "h3");
    append_length_prefixed_bytes(missing_application_context, transport_parameters);
    const bool missing_application_context_rejected =
        !decode_resumption_state(missing_application_context).has_value();

    std::vector<std::byte> missing_application_protocol = {std::byte{0x01}};
    append_u32_be(missing_application_protocol, kQuicVersion1);
    append_length_prefixed_bytes(missing_application_protocol, {});
    const bool missing_application_protocol_rejected =
        !decode_resumption_state(missing_application_protocol).has_value();

    std::vector<std::byte> missing_transport_parameters = {std::byte{0x01}};
    append_u32_be(missing_transport_parameters, kQuicVersion1);
    append_length_prefixed_bytes(missing_transport_parameters, {});
    append_length_prefixed_text(missing_transport_parameters, "h3");
    const bool missing_transport_parameters_rejected =
        !decode_resumption_state(missing_transport_parameters).has_value();

    auto trailing_resumption_state =
        encode_resumption_state({}, kQuicVersion1, "h3", resumption_transport_parameters, {});
    trailing_resumption_state.push_back(std::byte{0xff});
    const bool trailing_bytes_rejected =
        !decode_resumption_state(trailing_resumption_state).has_value();

    auto fin_sendable_stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    fin_sendable_stream.send_final_size = 1;
    fin_sendable_stream.send_fin_state = StreamSendFinState::pending;
    fin_sendable_stream.flow_control.peer_max_stream_data = 1;
    const bool pending_fin_without_buffer_is_sendable = stream_fin_sendable(fin_sendable_stream);

    auto fin_blocked_by_credit_stream =
        make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    fin_blocked_by_credit_stream.send_final_size = 2;
    fin_blocked_by_credit_stream.send_fin_state = StreamSendFinState::pending;
    fin_blocked_by_credit_stream.flow_control.peer_max_stream_data = 1;
    const bool pending_fin_blocked_by_credit = !stream_fin_sendable(fin_blocked_by_credit_stream);

    auto stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    stream.send_final_size = 1;
    stream.send_fin_state = StreamSendFinState::pending;
    stream.flow_control.peer_max_stream_data = 1;
    const std::array pending_data = {std::byte{0x78}};
    stream.send_buffer.append(pending_data);
    const bool pending_data_blocks_fin = !stream_fin_sendable(stream);

    LocalStreamLimitState stream_limits;
    stream_limits.max_streams_bidi_state = StreamControlFrameState::pending;
    stream_limits.max_streams_uni_state = StreamControlFrameState::pending;
    const auto max_streams_frames = stream_limits.take_max_streams_frames();
    const bool missing_pending_frames_preserve_state =
        max_streams_frames.empty() &
        (stream_limits.max_streams_bidi_state == StreamControlFrameState::pending) &
        (stream_limits.max_streams_uni_state == StreamControlFrameState::pending);

    constexpr std::array short_header_packet = {std::byte{0x40}};
    const bool short_header_is_bufferable = packet_is_bufferable(short_header_packet);
    constexpr std::array truncated_long_header = {std::byte{0xc0}, std::byte{0x00}, std::byte{0x00},
                                                  std::byte{0x00}};
    const bool truncated_long_header_is_not_bufferable =
        !packet_is_bufferable(truncated_long_header);
    constexpr std::array handshake_long_header = {std::byte{0xe0}, std::byte{0x00}, std::byte{0x00},
                                                  std::byte{0x00}, std::byte{0x01}};
    const bool handshake_long_header_is_bufferable = packet_is_bufferable(handshake_long_header);

    const ProtectedOneRttPacket connected_state_frame{
        .frames =
            {
                ResetStreamFrame{
                    .stream_id = 0,
                    .application_protocol_error_code = 1,
                    .final_size = 0,
                },
            },
    };
    const ProtectedOneRttPacket ack_only_frame{
        .frames =
            {
                AckFrame{},
            },
    };
    const bool server_protected_one_rtt_packet_deferred = should_defer_protected_one_rtt_packet(
        ack_only_frame, EndpointRole::server, HandshakeStatus::in_progress);
    const bool client_connected_state_protected_one_rtt_packet_deferred =
        should_defer_protected_one_rtt_packet(connected_state_frame, EndpointRole::client,
                                              HandshakeStatus::in_progress);
    const ReceivedProtectedOneRttPacket received_ack_only_frame{
        .frames =
            {
                ReceivedAckFrame{},
            },
    };
    const ReceivedProtectedOneRttPacket received_connected_state_frame{
        .frames =
            {
                ResetStreamFrame{
                    .stream_id = 0,
                    .application_protocol_error_code = 1,
                    .final_size = 0,
                },
            },
    };
    const bool server_received_one_rtt_packet_deferred = should_defer_protected_one_rtt_packet(
        received_ack_only_frame, EndpointRole::server, HandshakeStatus::in_progress);
    const bool client_connected_state_received_one_rtt_packet_deferred =
        should_defer_protected_one_rtt_packet(received_connected_state_frame, EndpointRole::client,
                                              HandshakeStatus::in_progress);
    const bool connected_protected_one_rtt_packet_not_deferred =
        !should_defer_protected_one_rtt_packet(connected_state_frame, EndpointRole::server,
                                               HandshakeStatus::connected);
    const bool protected_zero_rtt_crypto_can_advance_tls =
        packet_can_advance_tls_state(ProtectedPacket{ProtectedZeroRttPacket{
            .frames =
                {
                    CryptoFrame{
                        .offset = 0,
                        .crypto_data = std::vector<std::byte>{std::byte{0x01}},
                    },
                },
        }});
    const bool protected_one_rtt_ack_cannot_advance_tls =
        !packet_can_advance_tls_state(ProtectedPacket{ProtectedOneRttPacket{
            .frames =
                {
                    AckFrame{},
                },
        }});
    const bool corrupted_long_header_discarded =
        should_discard_corrupted_long_header_packet(false, CodecErrorCode::invalid_fixed_bit) &
        should_discard_corrupted_long_header_packet(false, CodecErrorCode::unsupported_packet_type);
    const bool short_header_not_discarded_as_corrupted_long_header =
        !should_discard_corrupted_long_header_packet(true, CodecErrorCode::invalid_fixed_bit);

    const auto bytes_from_ints = [](std::initializer_list<std::uint8_t> values) {
        std::vector<std::byte> bytes;
        bytes.reserve(values.size());
        for (const auto value : values) {
            bytes.push_back(static_cast<std::byte>(value));
        }
        return bytes;
    };

    const std::string empty_connection_id_hex = format_connection_id_hex({});
    const std::string retry_source_connection_id_hex =
        format_connection_id_hex(retry_source_connection_id);
    const bool empty_connection_id_formats_empty = empty_connection_id_hex.empty();
    const bool connection_id_formats_lower_hex = retry_source_connection_id_hex == "5300";
    const bool empty_issued_connection_id_remains_empty =
        make_issued_connection_id({}, /*sequence_number=*/7).empty();
    bool quic_core_secret_fallback_has_bytes = false;
    bool issued_connection_id_rand_fallback_has_bytes = false;
    bool issued_connection_id_fallback_has_bytes = false;
    bool stateless_reset_token_rand_fallback_has_bytes = false;
    bool stateless_reset_token_fallback_has_bytes = false;
    bool stateless_reset_token_empty_connection_id_fallback_has_bytes = false;
    bool stateless_reset_token_empty_connection_id_rand_fallback_has_bytes = false;
    bool path_challenge_rand_fallback_has_bytes = false;
    bool path_challenge_fallback_has_bytes = false;
    bool path_challenge_empty_connection_id_fallback_has_bytes = false;
    bool path_challenge_empty_connection_id_rand_fallback_has_bytes = false;
    bool random_one_in_sixteen_fallback_returns_bool = false;
    bool forced_random_one_in_sixteen_false = false;
    bool forced_random_one_in_sixteen_true = false;
    {
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_quic_core_secret_rand_failure);
        const auto secret = make_quic_core_secret();
        quic_core_secret_fallback_has_bytes =
            std::ranges::any_of(secret, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
        const auto connection_id = make_issued_connection_id(retry_source_connection_id, 7);
        issued_connection_id_rand_fallback_has_bytes =
            connection_id.size() == retry_source_connection_id.size() &&
            std::ranges::any_of(connection_id, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_short_prf_output);
        const auto connection_id = make_issued_connection_id(retry_source_connection_id, 13);
        issued_connection_id_rand_fallback_has_bytes &=
            connection_id.size() == retry_source_connection_id.size() &&
            std::ranges::any_of(connection_id, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainDualTestHook hooks(
            &ConnectionDrainTestHooks::force_prf_failure,
            &ConnectionDrainTestHooks::force_issued_connection_id_rand_failure);
        const auto connection_id = make_issued_connection_id(retry_source_connection_id, 8);
        issued_connection_id_fallback_has_bytes =
            connection_id.size() == retry_source_connection_id.size() &&
            std::ranges::any_of(connection_id, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
        const auto token = make_stateless_reset_token(retry_source_connection_id, 7);
        stateless_reset_token_rand_fallback_has_bytes =
            std::ranges::any_of(token, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainDualTestHook hooks(
            &ConnectionDrainTestHooks::force_prf_failure,
            &ConnectionDrainTestHooks::force_stateless_reset_token_rand_failure);
        const auto token = make_stateless_reset_token(retry_source_connection_id, 8);
        stateless_reset_token_fallback_has_bytes =
            std::ranges::any_of(token, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainDualTestHook hooks(
            &ConnectionDrainTestHooks::force_prf_failure,
            &ConnectionDrainTestHooks::force_stateless_reset_token_rand_failure);
        const auto token = make_stateless_reset_token({}, 9);
        stateless_reset_token_empty_connection_id_fallback_has_bytes =
            std::ranges::any_of(token, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
        const auto token = make_stateless_reset_token({}, 10);
        stateless_reset_token_empty_connection_id_rand_fallback_has_bytes =
            std::ranges::any_of(token, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
        const auto challenge = make_path_challenge_data(retry_source_connection_id, 3, 7);
        path_challenge_rand_fallback_has_bytes =
            std::ranges::any_of(challenge, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainDualTestHook hooks(
            &ConnectionDrainTestHooks::force_prf_failure,
            &ConnectionDrainTestHooks::force_path_challenge_rand_failure);
        const auto challenge = make_path_challenge_data(retry_source_connection_id, 3, 8);
        path_challenge_fallback_has_bytes =
            std::ranges::any_of(challenge, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainDualTestHook hooks(
            &ConnectionDrainTestHooks::force_prf_failure,
            &ConnectionDrainTestHooks::force_path_challenge_rand_failure);
        const auto challenge = make_path_challenge_data({}, 3, 9);
        path_challenge_empty_connection_id_fallback_has_bytes =
            std::ranges::any_of(challenge, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(&ConnectionDrainTestHooks::force_prf_failure);
        const auto challenge = make_path_challenge_data({}, 3, 10);
        path_challenge_empty_connection_id_rand_fallback_has_bytes =
            std::ranges::any_of(challenge, [](std::byte byte) { return byte != std::byte{0}; });
    }
    {
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_random_one_in_sixteen_rand_failure);
        const bool fallback = random_one_in_sixteen();
        random_one_in_sixteen_fallback_returns_bool = fallback || !fallback;
    }
    {
        const ScopedConnectionDrainOptionalBoolTestHook hook(
            &ConnectionDrainTestHooks::force_random_one_in_sixteen_result, false);
        forced_random_one_in_sixteen_false = !random_one_in_sixteen();
    }
    {
        const ScopedConnectionDrainOptionalBoolTestHook hook(
            &ConnectionDrainTestHooks::force_random_one_in_sixteen_result, true);
        forced_random_one_in_sixteen_true = random_one_in_sixteen();
    }
    const bool random_one_in_sixteen_openssl_returns_bool = [] {
        const bool value = random_one_in_sixteen();
        return value || !value;
    }();
    const bool stream_state_error_helpers_cover_all_codes =
        stream_transport_error_for_state_error(StreamStateErrorCode::invalid_stream_id) ==
            QuicTransportErrorCode::stream_limit_error &&
        stream_transport_error_for_state_error(StreamStateErrorCode::invalid_stream_direction) ==
            QuicTransportErrorCode::stream_state_error &&
        stream_transport_error_for_state_error(StreamStateErrorCode::send_side_closed) ==
            QuicTransportErrorCode::stream_state_error &&
        stream_transport_error_for_state_error(StreamStateErrorCode::receive_side_closed) ==
            QuicTransportErrorCode::stream_state_error &&
        stream_transport_error_for_state_error(StreamStateErrorCode::final_size_conflict) ==
            QuicTransportErrorCode::final_size_error;
    const auto stream_codec_without_transport = stream_state_codec_error(
        CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0}, kFrameTypeStreamBase);
    const bool stream_state_codec_error_adds_transport_code =
        stream_codec_without_transport.has_transport_error_code &&
        stream_codec_without_transport.transport_error_code ==
            transport_error_code_value(QuicTransportErrorCode::stream_state_error);
    const bool stream_limit_frame_type_helpers_cover_uni =
        frame_type_for_max_streams(StreamLimitType::unidirectional) == kFrameTypeMaxStreamsUni &&
        frame_type_for_streams_blocked(StreamLimitType::unidirectional) ==
            kFrameTypeStreamsBlockedUni;
    const bool transport_error_for_codec_error_covers_residual_codes =
        transport_error_for_codec_error(CodecErrorCode::invalid_reserved_bits) ==
            QuicTransportErrorCode::protocol_violation &&
        transport_error_for_codec_error(CodecErrorCode::invalid_fixed_bit) ==
            QuicTransportErrorCode::internal_error &&
        transport_error_for_codec_error(CodecErrorCode::missing_crypto_context) ==
            QuicTransportErrorCode::internal_error &&
        transport_error_for_codec_error(CodecErrorCode::http09_parse_error) ==
            QuicTransportErrorCode::application_error &&
        transport_error_for_codec_error(CodecErrorCode::http3_parse_error) ==
            QuicTransportErrorCode::application_error;
    const DeferredProtectedDatagram deferred_packet(bytes_from_ints({0x01, 0x02, 0x03}),
                                                    /*id=*/9);
    const bool vector_equals_deferred_packet =
        bytes_from_ints({0x01, 0x02, 0x03}) == deferred_packet;

    PathState traced_path{
        .id = 7,
        .validated = true,
        .is_current_send_path = true,
        .challenge_pending = true,
        .anti_amplification_received_bytes = 11,
        .anti_amplification_sent_bytes = 7,
        .outstanding_challenge =
            std::array{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                       std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}},
        .pending_response =
            std::array{std::byte{0x11}, std::byte{0x12}, std::byte{0x13}, std::byte{0x14},
                       std::byte{0x15}, std::byte{0x16}, std::byte{0x17}, std::byte{0x18}},
    };
    std::map<QuicPathId, PathState> traced_paths{
        {traced_path.id, traced_path},
    };
    const bool optional_path_none_formats_dash = format_optional_path_id(std::nullopt) == "-";
    const bool optional_path_value_formats_decimal = format_optional_path_id(traced_path.id) == "7";
    const bool missing_optional_path_returns_null =
        find_path_state(traced_paths, std::nullopt) == nullptr;
    const bool unknown_path_returns_null = find_path_state(traced_paths, 99) == nullptr;
    const bool existing_path_is_found = find_path_state(traced_paths, traced_path.id) != nullptr;
    const bool null_path_summary_formats_dash = format_path_state_summary(nullptr) == "-";
    const std::string traced_path_summary = format_path_state_summary(&traced_path);
    const bool traced_path_summary_mentions_path_state =
        (traced_path_summary.find("id=7") != std::string::npos) &
        (traced_path_summary.find("val=1") != std::string::npos) &
        (traced_path_summary.find("cur=1") != std::string::npos) &
        (traced_path_summary.find("chal=1") != std::string::npos) &
        (traced_path_summary.find("out=1") != std::string::npos) &
        (traced_path_summary.find("resp=1") != std::string::npos) &
        (traced_path_summary.find("recv=11") != std::string::npos) &
        (traced_path_summary.find("sent=7") != std::string::npos);
    const bool invalid_ack_first_range_formats_invalid = format_ack_ranges(AckFrame{
                                                             .largest_acknowledged = 1,
                                                             .first_ack_range = 2,
                                                         }) == "[invalid]";
    const bool invalid_ack_gap_formats_invalid = format_ack_ranges(AckFrame{
                                                     .largest_acknowledged = 10,
                                                     .first_ack_range = 0,
                                                     .additional_ranges =
                                                         {
                                                             AckRange{.gap = 9, .range_length = 0},
                                                         },
                                                 }) == "[10-10,invalid]";
    const bool invalid_ack_range_length_formats_invalid =
        format_ack_ranges(AckFrame{
            .largest_acknowledged = 10,
            .first_ack_range = 2,
            .additional_ranges =
                {
                    AckRange{.gap = 0, .range_length = 7},
                },
        }) == "[8-10,invalid]";
    const bool valid_ack_ranges_format_expected = format_ack_ranges(AckFrame{
                                                      .largest_acknowledged = 10,
                                                      .first_ack_range = 1,
                                                      .additional_ranges =
                                                          {
                                                              AckRange{.gap = 0, .range_length = 1},
                                                          },
                                                  }) == "[9-10,6-7]";
    const bool invalid_received_ack_formats_invalid = format_ack_ranges(ReceivedAckFrame{
                                                          .largest_acknowledged = 10,
                                                          .first_ack_range = 1,
                                                          .additional_range_count = 1,
                                                          .additional_range_bytes =
                                                              SharedBytes{
                                                                  std::byte{0x40},
                                                              },
                                                      }) == "[invalid]";
    const bool empty_packet_summary_reports_zero = summarize_packets({}) == "count=0";
    const std::array sent_packets = {
        SentPacketRecord{
            .packet_number = 5,
            .stream_fragments =
                {
                    StreamFrameSendFragment{
                        .stream_id = 0,
                        .offset = 4,
                        .bytes = SharedBytes(bytes_from_ints({0xaa, 0xbb})),
                        .fin = false,
                        .consumes_flow_control = true,
                    },
                },
        },
        SentPacketRecord{
            .packet_number = 9,
        },
    };
    const std::string packet_summary = summarize_packets(sent_packets);
    const bool packet_summary_mentions_counts =
        (packet_summary.find("count=2") != std::string::npos) &
        (packet_summary.find("pn=5-9") != std::string::npos) &
        (packet_summary.find("stream_fragments=1") != std::string::npos) &
        (packet_summary.find("first_stream_offset=4") != std::string::npos);
    const std::array no_stream_packets = {
        SentPacketRecord{
            .packet_number = 6,
        },
        SentPacketRecord{
            .packet_number = 8,
        },
    };
    const std::string no_stream_packet_summary = summarize_packets(no_stream_packets);
    const bool packet_summary_without_stream_offset_omits_offset =
        (no_stream_packet_summary.find("count=2") != std::string::npos) &
        (no_stream_packet_summary.find("pn=6-8") != std::string::npos) &
        (no_stream_packet_summary.find("stream_fragments=0") != std::string::npos) &
        (no_stream_packet_summary.find("first_stream_offset=") == std::string::npos);
    const bool stream_frame_payload_budget_handles_edges =
        max_stream_frame_payload_for_wire_budget(/*stream_id=*/0, kMaxQuicVarInt + 1u,
                                                 /*wire_budget=*/1200) == 0 &&
        max_stream_frame_payload_for_wire_budget(/*stream_id=*/0, /*offset=*/0,
                                                 /*wire_budget=*/1) == 0 &&
        max_stream_frame_payload_for_wire_budget(/*stream_id=*/0, /*offset=*/0,
                                                 /*wire_budget=*/32) > 0;
    const bool application_stream_budget_handles_small_and_oversized_connection_ids =
        application_stream_frame_budget(/*max_datagram_size=*/1199,
                                        /*destination_connection_id_size=*/8) == 1199 &&
        application_stream_frame_budget(/*max_datagram_size=*/1200,
                                        /*destination_connection_id_size=*/1200) == 1200 &&
        application_stream_frame_budget(/*max_datagram_size=*/1400,
                                        /*destination_connection_id_size=*/8) == 1373;

    const std::array<Frame, 2> non_terminal_lengthless_stream_frame{
        Frame{StreamFrame{
            .has_length = false,
            .stream_id = 0,
            .stream_data = bytes_from_ints({0xaa}),
        }},
        Frame{PingFrame{}},
    };
    const auto non_terminal_lengthless_stream_size =
        one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
            .destination_connection_id = retry_source_connection_id,
            .packet_number_length = 2,
            .frames = non_terminal_lengthless_stream_frame,
        });
    const bool one_rtt_fragment_size_rejects_non_terminal_lengthless_stream_frames =
        !non_terminal_lengthless_stream_size.has_value() &&
        non_terminal_lengthless_stream_size.error().code ==
            CodecErrorCode::packet_length_mismatch &&
        non_terminal_lengthless_stream_size.error().offset == 0;

    const std::array<Frame, 1> invalid_padding_frame{
        Frame{PaddingFrame{.length = 0}},
    };
    const auto invalid_frame_size =
        one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
            .destination_connection_id = retry_source_connection_id,
            .packet_number_length = 2,
            .frames = invalid_padding_frame,
        });
    const bool one_rtt_fragment_size_propagates_frame_size_errors =
        !invalid_frame_size.has_value() &&
        invalid_frame_size.error().code == CodecErrorCode::invalid_varint &&
        invalid_frame_size.error().offset == 0;

    const std::array<Frame, 0> no_frames{};
    const auto empty_fragment_packet_size =
        one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
            .destination_connection_id = retry_source_connection_id,
            .packet_number_length = 2,
            .frames = no_frames,
        });
    const bool one_rtt_fragment_size_rejects_empty_payloads =
        !empty_fragment_packet_size.has_value() &&
        empty_fragment_packet_size.error().code == CodecErrorCode::empty_packet_payload;

    const auto fragment_storage =
        std::make_shared<std::vector<std::byte>>(bytes_from_ints({0xaa, 0xbb, 0xcc}));
    const std::array<StreamFrameSendFragment, 2> fragments{
        StreamFrameSendFragment{
            .stream_id = 0,
            .offset = 0,
            .bytes = SharedBytes(fragment_storage, 0, 2),
            .fin = false,
            .consumes_flow_control = true,
        },
        StreamFrameSendFragment{
            .stream_id = 4,
            .offset = 2,
            .bytes = SharedBytes(fragment_storage, 2, 3),
            .fin = true,
            .consumes_flow_control = true,
        },
    };
    const auto fragment_packet_size =
        one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
            .destination_connection_id = retry_source_connection_id,
            .packet_number_length = 2,
            .frames = no_frames,
            .stream_fragments = fragments,
        });
    const bool one_rtt_fragment_helpers_count_stream_fragment_bytes =
        stream_fragment_bytes(fragments) == 3 && stream_fragment_wire_bytes(fragments) > 3 &&
        fragment_packet_size.has_value() &&
        fragment_packet_size.value() > retry_source_connection_id.size() +
                                           kDefaultInitialPacketNumberLength +
                                           kOneRttPacketProtectionTagLength;

    const std::array<StreamFrameSendFragment, 1> overflowing_fragments{
        StreamFrameSendFragment{
            .stream_id = 0,
            .offset = kMaxQuicVarInt,
            .bytes = SharedBytes(bytes_from_ints({0xdd, 0xee})),
        },
    };
    const auto overflowing_fragment_packet_size =
        one_rtt_packet_fragment_view_wire_size(ProtectedOneRttPacketFragmentView{
            .destination_connection_id = retry_source_connection_id,
            .packet_number_length = 2,
            .frames = no_frames,
            .stream_fragments = overflowing_fragments,
        });
    const bool one_rtt_fragment_size_rejects_overflowing_fragment_offsets =
        !overflowing_fragment_packet_size.has_value() &&
        overflowing_fragment_packet_size.error().code == CodecErrorCode::invalid_varint &&
        overflowing_fragment_packet_size.error().offset == 0;

    bool trace_unset_disabled = false;
    bool trace_empty_disabled = false;
    bool trace_zero_disabled = false;
    bool trace_matches_without_filter = false;
    bool trace_matches_with_empty_filter = false;
    bool trace_matches_with_exact_filter = false;
    bool trace_rejects_mismatched_filter = false;
    {
        ScopedEnvVarForTests original_trace("COQUIC_PACKET_TRACE", "seed");
        ScopedEnvVarForTests original_filter("COQUIC_PACKET_TRACE_SCID", "seed");

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", std::nullopt);
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);
            trace_unset_disabled = !packet_trace_enabled() &
                                   !packet_trace_matches_connection(retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "");
            trace_empty_disabled = !packet_trace_enabled();
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "0");
            trace_zero_disabled = !packet_trace_enabled();
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);
            trace_matches_without_filter = packet_trace_enabled() & packet_trace_matches_connection(
                                                                        retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
            trace_matches_with_empty_filter =
                packet_trace_matches_connection(retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", retry_source_connection_id_hex);
            trace_matches_with_exact_filter =
                packet_trace_matches_connection(retry_source_connection_id);
        }

        {
            ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
            ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "deadbeef");
            trace_rejects_mismatched_filter =
                !packet_trace_matches_connection(retry_source_connection_id);
        }
    }

    const bool empty_long_header_rejected =
        !peek_discardable_long_header_packet_length({}).has_value();
    const bool short_header_rejected =
        !peek_discardable_long_header_packet_length(bytes_from_ints({0x40})).has_value();
    const bool truncated_version_rejected =
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00}))
             .has_value();
    const bool unsupported_version_rejected =
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x00}))
             .has_value();
    const bool missing_destination_connection_id_length_rejected =
        !peek_discardable_long_header_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01}))
             .has_value();
    const bool oversized_destination_connection_id_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x15}))
             .has_value();
    const bool truncated_destination_connection_id_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01}))
             .has_value();
    const bool missing_source_connection_id_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00}))
             .has_value();
    const bool oversized_source_connection_id_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x15}))
             .has_value();
    const bool truncated_source_connection_id_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}))
             .has_value();
    const bool missing_initial_token_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
             .has_value();
    const bool oversized_initial_token_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}))
             .has_value();
    const bool unsupported_retry_packet_type_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
             .has_value();
    const bool missing_payload_length_after_initial_token_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00}))
             .has_value();
    const bool missing_payload_length_for_handshake_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
             .has_value();
    const bool missing_payload_length_for_zero_rtt_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}))
             .has_value();
    const bool oversized_payload_length_rejected =
        !peek_discardable_long_header_packet_length(
             bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01}))
             .has_value();
    bool discardable_deferred_replay_packet_does_not_block_current_packet = false;
    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        const std::array frames{Frame{PingFrame{}}};
        auto current = serialize_one_rtt_packet_for_connection_coverage(
            connection, /*packet_number=*/291, frames);
        auto deferred = serialize_one_rtt_packet_for_connection_coverage(
            connection, /*packet_number=*/292, frames);
        if (!current.empty() && !deferred.empty()) {
            deferred.back() =
                static_cast<std::byte>(std::to_integer<unsigned>(deferred.back()) ^ 0x01u);
            connection.deferred_protected_packets_.push_back(DeferredProtectedDatagram{
                std::move(deferred),
            });
            connection.process_inbound_datagram(current, QuicCoreTimePoint{});
            discardable_deferred_replay_packet_does_not_block_current_packet =
                !connection.has_failed() && connection.deferred_protected_packets_.empty() &&
                connection.application_space_.largest_authenticated_packet_number == 291u;
        }
    }
    bool in_place_receive_storage_before_begin_guard = false;
    bool in_place_receive_storage_overflow_guard = false;
    bool replay_failure_before_current_packet_is_non_fatal = false;
    bool replay_failure_after_current_packet_is_non_fatal = false;
    {
        const std::array frames{Frame{PingFrame{}}};
        const auto datagram = serialize_one_rtt_packet_for_connection_coverage(
            make_connected_client_connection_for_connection_coverage(), /*packet_number=*/300,
            frames);
        if (!datagram.empty()) {
            const auto exercise_guard = [&](bool ConnectionDrainTestHooks::*hook_field) {
                auto connection = make_connected_client_connection_for_connection_coverage();
                auto storage = std::make_shared<std::vector<std::byte>>(datagram);
                const ScopedConnectionDrainTestHook hook(hook_field);
                connection.process_inbound_datagram(
                    storage, /*begin=*/0, /*end=*/storage->size(), QuicCoreTimePoint{},
                    /*path_id=*/0, QuicEcnCodepoint::unavailable, std::nullopt,
                    /*replay_trigger=*/false, /*count_inbound_bytes=*/true,
                    /*allow_in_place_receive_decode=*/true);
                return !connection.has_failed();
            };
            in_place_receive_storage_before_begin_guard =
                exercise_guard(&ConnectionDrainTestHooks::force_storage_range_before_storage);
            in_place_receive_storage_overflow_guard =
                exercise_guard(&ConnectionDrainTestHooks::force_storage_range_overflow);
        }
    }
    {
        const std::array frames{Frame{PingFrame{}}};
        auto datagram = serialize_one_rtt_packet_for_connection_coverage(
            make_connected_client_connection_for_connection_coverage(), /*packet_number=*/301,
            frames);
        if (!datagram.empty()) {
            auto connection = make_connected_client_connection_for_connection_coverage();
            const ScopedConnectionDrainCountdownTestHook hook(
                &ConnectionDrainTestHooks::force_replay_deferred_packets_failure_countdown, 0);
            connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
            replay_failure_before_current_packet_is_non_fatal = !connection.has_failed();
        }
    }
    {
        const std::array frames{Frame{PingFrame{}}};
        auto datagram = serialize_one_rtt_packet_for_connection_coverage(
            make_connected_client_connection_for_connection_coverage(), /*packet_number=*/302,
            frames);
        if (!datagram.empty()) {
            auto connection = make_connected_client_connection_for_connection_coverage();
            const ScopedConnectionDrainCountdownTestHook hook(
                &ConnectionDrainTestHooks::force_replay_deferred_packets_failure_countdown, 1);
            connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
            replay_failure_after_current_packet_is_non_fatal =
                !connection.has_failed() &&
                connection.application_space_.largest_authenticated_packet_number == 302u;
        }
    }

    bool ok = true;
#define COQUIC_CONNECTION_EDGE_RECORD(expr)                                                        \
    connection_coverage_check(ok, #expr, static_cast<bool>(expr))

    COQUIC_CONNECTION_EDGE_RECORD(retry_same_version_omits_version_information);
    COQUIC_CONNECTION_EDGE_RECORD(retry_version_change_keeps_version_information);
    COQUIC_CONNECTION_EDGE_RECORD(failed_datagram_reports_zero_size);
    COQUIC_CONNECTION_EDGE_RECORD(successful_datagram_reports_size);
    COQUIC_CONNECTION_EDGE_RECORD(failed_serialized_datagram_reports_zero_size);
    COQUIC_CONNECTION_EDGE_RECORD(successful_serialized_datagram_reports_size);
    COQUIC_CONNECTION_EDGE_RECORD(empty_packet_payload_error_reported);
    COQUIC_CONNECTION_EDGE_RECORD(successful_datagram_not_reported);
    COQUIC_CONNECTION_EDGE_RECORD(non_empty_packet_payload_error_not_reported);
    COQUIC_CONNECTION_EDGE_RECORD(empty_packet_payload_serialized_error_reported);
    COQUIC_CONNECTION_EDGE_RECORD(non_empty_packet_payload_serialized_error_not_reported);
    COQUIC_CONNECTION_EDGE_RECORD(encode_failure_returns_empty);
    COQUIC_CONNECTION_EDGE_RECORD(wrong_magic_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(truncated_tls_state_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(missing_application_protocol_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(missing_transport_parameters_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(missing_application_context_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(trailing_bytes_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(pending_fin_without_buffer_is_sendable);
    COQUIC_CONNECTION_EDGE_RECORD(pending_fin_blocked_by_credit);
    COQUIC_CONNECTION_EDGE_RECORD(pending_data_blocks_fin);
    COQUIC_CONNECTION_EDGE_RECORD(missing_pending_frames_preserve_state);
    COQUIC_CONNECTION_EDGE_RECORD(short_header_is_bufferable);
    COQUIC_CONNECTION_EDGE_RECORD(truncated_long_header_is_not_bufferable);
    COQUIC_CONNECTION_EDGE_RECORD(handshake_long_header_is_bufferable);
    COQUIC_CONNECTION_EDGE_RECORD(server_protected_one_rtt_packet_deferred);
    COQUIC_CONNECTION_EDGE_RECORD(client_connected_state_protected_one_rtt_packet_deferred);
    COQUIC_CONNECTION_EDGE_RECORD(server_received_one_rtt_packet_deferred);
    COQUIC_CONNECTION_EDGE_RECORD(client_connected_state_received_one_rtt_packet_deferred);
    COQUIC_CONNECTION_EDGE_RECORD(connected_protected_one_rtt_packet_not_deferred);
    COQUIC_CONNECTION_EDGE_RECORD(protected_zero_rtt_crypto_can_advance_tls);
    COQUIC_CONNECTION_EDGE_RECORD(protected_one_rtt_ack_cannot_advance_tls);
    COQUIC_CONNECTION_EDGE_RECORD(corrupted_long_header_discarded);
    COQUIC_CONNECTION_EDGE_RECORD(short_header_not_discarded_as_corrupted_long_header);
    COQUIC_CONNECTION_EDGE_RECORD(empty_connection_id_formats_empty);
    COQUIC_CONNECTION_EDGE_RECORD(connection_id_formats_lower_hex);
    COQUIC_CONNECTION_EDGE_RECORD(empty_issued_connection_id_remains_empty);
    COQUIC_CONNECTION_EDGE_RECORD(quic_core_secret_fallback_has_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(issued_connection_id_rand_fallback_has_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(issued_connection_id_fallback_has_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(stateless_reset_token_rand_fallback_has_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(stateless_reset_token_fallback_has_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(stateless_reset_token_empty_connection_id_fallback_has_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(
        stateless_reset_token_empty_connection_id_rand_fallback_has_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(path_challenge_rand_fallback_has_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(path_challenge_fallback_has_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(path_challenge_empty_connection_id_fallback_has_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(path_challenge_empty_connection_id_rand_fallback_has_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(random_one_in_sixteen_fallback_returns_bool);
    COQUIC_CONNECTION_EDGE_RECORD(forced_random_one_in_sixteen_false);
    COQUIC_CONNECTION_EDGE_RECORD(forced_random_one_in_sixteen_true);
    COQUIC_CONNECTION_EDGE_RECORD(random_one_in_sixteen_openssl_returns_bool);
    COQUIC_CONNECTION_EDGE_RECORD(stream_state_error_helpers_cover_all_codes);
    COQUIC_CONNECTION_EDGE_RECORD(stream_state_codec_error_adds_transport_code);
    COQUIC_CONNECTION_EDGE_RECORD(stream_limit_frame_type_helpers_cover_uni);
    COQUIC_CONNECTION_EDGE_RECORD(transport_error_for_codec_error_covers_residual_codes);
    COQUIC_CONNECTION_EDGE_RECORD(vector_equals_deferred_packet);
    COQUIC_CONNECTION_EDGE_RECORD(optional_path_none_formats_dash);
    COQUIC_CONNECTION_EDGE_RECORD(optional_path_value_formats_decimal);
    COQUIC_CONNECTION_EDGE_RECORD(missing_optional_path_returns_null);
    COQUIC_CONNECTION_EDGE_RECORD(unknown_path_returns_null);
    COQUIC_CONNECTION_EDGE_RECORD(existing_path_is_found);
    COQUIC_CONNECTION_EDGE_RECORD(null_path_summary_formats_dash);
    COQUIC_CONNECTION_EDGE_RECORD(traced_path_summary_mentions_path_state);
    COQUIC_CONNECTION_EDGE_RECORD(invalid_ack_first_range_formats_invalid);
    COQUIC_CONNECTION_EDGE_RECORD(invalid_ack_gap_formats_invalid);
    COQUIC_CONNECTION_EDGE_RECORD(invalid_ack_range_length_formats_invalid);
    COQUIC_CONNECTION_EDGE_RECORD(valid_ack_ranges_format_expected);
    COQUIC_CONNECTION_EDGE_RECORD(invalid_received_ack_formats_invalid);
    COQUIC_CONNECTION_EDGE_RECORD(empty_packet_summary_reports_zero);
    COQUIC_CONNECTION_EDGE_RECORD(packet_summary_mentions_counts);
    COQUIC_CONNECTION_EDGE_RECORD(packet_summary_without_stream_offset_omits_offset);
    COQUIC_CONNECTION_EDGE_RECORD(stream_frame_payload_budget_handles_edges);
    COQUIC_CONNECTION_EDGE_RECORD(
        application_stream_budget_handles_small_and_oversized_connection_ids);
    COQUIC_CONNECTION_EDGE_RECORD(
        one_rtt_fragment_size_rejects_non_terminal_lengthless_stream_frames);
    COQUIC_CONNECTION_EDGE_RECORD(one_rtt_fragment_size_propagates_frame_size_errors);
    COQUIC_CONNECTION_EDGE_RECORD(one_rtt_fragment_size_rejects_empty_payloads);
    COQUIC_CONNECTION_EDGE_RECORD(one_rtt_fragment_helpers_count_stream_fragment_bytes);
    COQUIC_CONNECTION_EDGE_RECORD(one_rtt_fragment_size_rejects_overflowing_fragment_offsets);
    COQUIC_CONNECTION_EDGE_RECORD(trace_unset_disabled);
    COQUIC_CONNECTION_EDGE_RECORD(trace_empty_disabled);
    COQUIC_CONNECTION_EDGE_RECORD(trace_zero_disabled);
    COQUIC_CONNECTION_EDGE_RECORD(trace_matches_without_filter);
    COQUIC_CONNECTION_EDGE_RECORD(trace_matches_with_empty_filter);
    COQUIC_CONNECTION_EDGE_RECORD(trace_matches_with_exact_filter);
    COQUIC_CONNECTION_EDGE_RECORD(trace_rejects_mismatched_filter);
    COQUIC_CONNECTION_EDGE_RECORD(empty_long_header_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(short_header_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(truncated_version_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(unsupported_version_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(missing_destination_connection_id_length_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(oversized_destination_connection_id_length_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(truncated_destination_connection_id_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(missing_source_connection_id_length_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(oversized_source_connection_id_length_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(truncated_source_connection_id_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(missing_initial_token_length_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(oversized_initial_token_length_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(unsupported_retry_packet_type_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(missing_payload_length_after_initial_token_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(missing_payload_length_for_handshake_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(missing_payload_length_for_zero_rtt_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(oversized_payload_length_rejected);
    COQUIC_CONNECTION_EDGE_RECORD(discardable_deferred_replay_packet_does_not_block_current_packet);
    COQUIC_CONNECTION_EDGE_RECORD(in_place_receive_storage_before_begin_guard);
    COQUIC_CONNECTION_EDGE_RECORD(in_place_receive_storage_overflow_guard);
    COQUIC_CONNECTION_EDGE_RECORD(replay_failure_before_current_packet_is_non_fatal);
    COQUIC_CONNECTION_EDGE_RECORD(replay_failure_after_current_packet_is_non_fatal);

#undef COQUIC_CONNECTION_EDGE_RECORD
    return ok;
}

bool connection_ack_deadline_and_stream_utilities_for_tests() {
    const auto now = QuicCoreTimePoint{} + std::chrono::milliseconds(17);

    PacketSpaceState ce_packet_space;
    schedule_application_ack_deadline(ce_packet_space, now, /*max_ack_delay_ms=*/25,
                                      QuicEcnCodepoint::ce);
    const bool ce_ack_forces_immediate_deadline =
        ce_packet_space.pending_ack_deadline == now && ce_packet_space.force_ack_send;

    PacketSpaceState delayed_ack_packet_space;
    schedule_application_ack_deadline(delayed_ack_packet_space, now, /*max_ack_delay_ms=*/25,
                                      QuicEcnCodepoint::ect0);
    const bool delayed_ack_sets_max_ack_deadline =
        delayed_ack_packet_space.pending_ack_deadline == now + std::chrono::milliseconds(25) &&
        !delayed_ack_packet_space.force_ack_send;
    schedule_application_ack_deadline(delayed_ack_packet_space, now + std::chrono::milliseconds(4),
                                      /*max_ack_delay_ms=*/25, QuicEcnCodepoint::ect0);
    const bool existing_deadline_is_preserved =
        delayed_ack_packet_space.pending_ack_deadline == now + std::chrono::milliseconds(25);

    PacketSpaceState immediate_ack_packet_space;
    for (std::uint64_t packet_number = 4; packet_number < 19; ++packet_number) {
        immediate_ack_packet_space.received_packets.record_received(
            packet_number, /*ack_eliciting=*/true, now, QuicEcnCodepoint::unavailable,
            /*ack_eliciting_threshold=*/16);
    }
    immediate_ack_packet_space.received_packets.record_received(
        /*packet_number=*/19, /*ack_eliciting=*/true, now + std::chrono::milliseconds(1),
        QuicEcnCodepoint::unavailable, /*ack_eliciting_threshold=*/16);
    schedule_application_ack_deadline(immediate_ack_packet_space,
                                      now + std::chrono::milliseconds(2),
                                      /*max_ack_delay_ms=*/25, QuicEcnCodepoint::ect0);
    const bool immediate_ack_uses_current_time =
        immediate_ack_packet_space.pending_ack_deadline == now + std::chrono::milliseconds(2) &&
        !immediate_ack_packet_space.force_ack_send;

    const std::map<std::uint64_t, StreamState> empty_streams;
    const bool empty_stream_round_robin_is_empty =
        round_robin_stream_order(empty_streams, std::nullopt).empty();

    std::map<std::uint64_t, StreamState> streams;
    streams.emplace(4, make_implicit_stream_state(/*stream_id=*/4, EndpointRole::client));
    streams.emplace(8, make_implicit_stream_state(/*stream_id=*/8, EndpointRole::client));
    streams.emplace(12, make_implicit_stream_state(/*stream_id=*/12, EndpointRole::client));
    const bool round_robin_without_last_stream_keeps_natural_order =
        round_robin_stream_order(streams, std::nullopt) == std::vector<std::uint64_t>{4, 8, 12};
    const bool round_robin_after_middle_stream_wraps_remaining_ids =
        round_robin_stream_order(streams, /*last_stream_id=*/8) ==
        std::vector<std::uint64_t>{12, 4, 8};
    const bool round_robin_after_last_stream_wraps_to_front =
        round_robin_stream_order(streams, /*last_stream_id=*/12) ==
        std::vector<std::uint64_t>{4, 8, 12};

    return ce_ack_forces_immediate_deadline & delayed_ack_sets_max_ack_deadline &
           existing_deadline_is_preserved & immediate_ack_uses_current_time &
           empty_stream_round_robin_is_empty & round_robin_without_last_stream_keeps_natural_order &
           round_robin_after_middle_stream_wraps_remaining_ids &
           round_robin_after_last_stream_wraps_to_front;
}

bool connection_header_packet_space_coverage_for_tests() {
    bool ok = true;
    const auto record = [&](bool condition) { ok &= condition; };

    {
        SerializedProtectedDatagram datagram{
            .bytes = DatagramBuffer{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}},
            .packet_metadata = {{.offset = 1, .length = 1}},
        };
        record(QuicConnection(make_client_core_config_for_connection_coverage())
                   .queue_outbound_packet_inspections(datagram, /*datagram_id=*/1) == 0);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.config_.enable_packet_inspection = true;
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x71});
        connection.handshake_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x72});
        connection.zero_rtt_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x73});
        const std::array<ProtectedPacket, 3> packets{
            ProtectedPacket{ProtectedInitialPacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.initial_destination_connection_id,
                .source_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 1,
                .frames = {PingFrame{}},
            }},
            ProtectedPacket{ProtectedHandshakePacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.initial_destination_connection_id,
                .source_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 2,
                .frames = {PingFrame{}},
            }},
            ProtectedPacket{ProtectedZeroRttPacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.initial_destination_connection_id,
                .source_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 3,
                .frames = {PingFrame{}},
            }},
        };
        const auto datagram = serialize_protected_datagram_with_metadata(
            packets, SerializeProtectionContext{
                         .local_role = connection.config_.role,
                         .client_initial_destination_connection_id =
                             connection.client_initial_destination_connection_id(),
                         .handshake_secret = connection.handshake_space_.write_secret,
                         .zero_rtt_secret = connection.zero_rtt_space_.write_secret,
                     });
        record(datagram.has_value());
        if (datagram.has_value()) {
            record(connection.queue_outbound_packet_inspections(datagram.value(), 7) == 3);
            const auto first = connection.take_packet_inspection();
            const auto second = connection.take_packet_inspection();
            const auto third = connection.take_packet_inspection();
            record(first.has_value() &&
                   first->packet_type == QuicCorePacketInspectionPacketType::initial);
            record(second.has_value() &&
                   second->packet_type == QuicCorePacketInspectionPacketType::handshake);
            record(third.has_value() &&
                   third->packet_type == QuicCorePacketInspectionPacketType::zero_rtt);
        }
    }

    {
        PacketSpacePacketMapView view;
        record(view.size() == 0);
        record(view.begin() == view.end());
        record(view.rbegin() == view.rend());
        record(!view.contains(1));
        const auto [it, inserted] = view.emplace(1, SentPacketRecord{});
        record(!inserted);
        record(it == view.end());
        record(view.erase(1) == 0);
    }

    {
        PacketSpaceRecovery recovery;
        PacketSpacePacketMapView outstanding(&recovery,
                                             PacketSpacePacketMapView::Filter::outstanding);
        PacketSpacePacketMapView declared_lost(&recovery,
                                               PacketSpacePacketMapView::Filter::declared_lost);
        const SentPacketRecord packet{
            .ack_eliciting = true,
            .in_flight = true,
            .bytes_in_flight = 1200,
        };

        const auto [outstanding_it, outstanding_inserted] = outstanding.emplace(7, packet);
        record(outstanding_inserted);
        record(outstanding_it != outstanding.end());
        record(!outstanding.empty());
        record(outstanding.size() == 1);
        record(outstanding.size() == 1);
        record(outstanding.contains(7));
        record(outstanding.at(7).packet_number == 7);
        record(outstanding.rbegin() != outstanding.rend());

        const auto [duplicate_it, duplicate_inserted] = outstanding.emplace(7, packet);
        record(!duplicate_inserted);
        record(duplicate_it != outstanding.end());
        record(outstanding.erase(99) == 0);

        const auto [declared_lost_it, declared_lost_inserted] = declared_lost.emplace(9, packet);
        record(declared_lost_inserted);
        record(declared_lost_it != declared_lost.end());
        record(declared_lost.contains(9));
        const auto &declared_lost_packet = declared_lost.at(9);
        record(declared_lost_packet.packet_number == 9);
        record(declared_lost_packet.declared_lost);
        record(!declared_lost_packet.in_flight);
        record(declared_lost_packet.bytes_in_flight == 0);
        record(!outstanding.contains(9));

        record(declared_lost.erase(9) == 1);
        record(!declared_lost.contains(9));
        record(outstanding.erase(7) == 1);
        record(outstanding.empty());
        record(outstanding.rbegin() == outstanding.rend());
    }

    const auto make_packet_space_state = [] {
        PacketSpaceState state;
        state.next_send_packet_number = 17;
        state.largest_authenticated_packet_number = 9;
        state.send_crypto.append(std::vector<std::byte>{std::byte{0xaa}});
        state.received_packets.record_received(5, true, QuicCoreTimePoint{});
        state.sent_packets.emplace(11, SentPacketRecord{
                                           .ack_eliciting = true,
                                           .in_flight = true,
                                           .bytes_in_flight = 1200,
                                       });
        state.declared_lost_packets.emplace(12, SentPacketRecord{
                                                    .ack_eliciting = true,
                                                    .in_flight = true,
                                                    .bytes_in_flight = 1300,
                                                });
        state.pending_probe_packet = SentPacketRecord{
            .packet_number = 13,
            .has_ping = true,
        };
        state.pending_ack_deadline = QuicCoreTimePoint{} + std::chrono::milliseconds(5);
        state.force_ack_send = true;
        return state;
    };

    {
        auto source = make_packet_space_state();
        PacketSpaceState copy(source);
        record(copy.next_send_packet_number == 17);
        record(copy.largest_authenticated_packet_number == 9);
        record(copy.send_crypto.has_pending_data());
        record(copy.received_packets.contains(5));
        record(copy.sent_packets.contains(11));
        record(copy.declared_lost_packets.contains(12));
        record(copy.pending_probe_packet.has_value());
        record(copy.pending_probe_packet.value_or(SentPacketRecord{}).packet_number == 13);
        record(copy.force_ack_send);
        record(source.sent_packets.erase(11) == 1);
        record(!source.sent_packets.contains(11));
        record(copy.sent_packets.contains(11));
    }

    {
        auto source = make_packet_space_state();
        PacketSpaceState assigned;
        assigned = source;
        record(assigned.sent_packets.contains(11));
        record(assigned.declared_lost_packets.contains(12));
        record(assigned.pending_probe_packet.has_value());
        record(assigned.pending_ack_deadline.has_value());
        record(source.sent_packets.erase(11) == 1);
        record(!source.sent_packets.contains(11));
        record(assigned.sent_packets.contains(11));
        assigned = assigned;
        record(assigned.sent_packets.contains(11));
        record(assigned.declared_lost_packets.contains(12));
        assigned = std::move(assigned);
        record(assigned.sent_packets.contains(11));
        record(assigned.declared_lost_packets.contains(12));
    }

    return ok;
}

bool connection_key_update_and_probe_coverage_for_tests() {
    bool ok = true;
#define COQUIC_STRINGIFY_DETAIL(value) #value
#define COQUIC_STRINGIFY(value) COQUIC_STRINGIFY_DETAIL(value)
#define COQUIC_CONNECTION_HOOK_RECORD(expr)                                                        \
    connection_coverage_check(ok, #expr ":" COQUIC_STRINGIFY(__LINE__), static_cast<bool>(expr))

    const auto make_connected_client_connection = [] {
        return make_connected_client_connection_for_connection_coverage();
    };
    const auto make_runtime_transport_parameters = [](const QuicConnection &connection) {
        return TransportParameters{
            .original_destination_connection_id =
                connection.config_.initial_destination_connection_id,
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = connection.config_.transport.active_connection_id_limit,
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
            .version_information = version_information_for_handshake(
                connection.config_.supported_versions, connection.current_version_,
                connection.config_.retry_source_connection_id, connection.original_version_,
                connection.current_version_),
        };
    };
    const auto make_new_connection_id_frame = [](std::uint64_t sequence_number) {
        return NewConnectionIdFrame{
            .sequence_number = sequence_number,
            .retire_prior_to = 0,
            .connection_id = bytes_from_ints_for_tests(
                {static_cast<std::uint8_t>(0xc0u + (sequence_number & 0x0fu))}),
            .stateless_reset_token =
                std::array<std::byte, 16>{
                    std::byte{static_cast<std::uint8_t>(0x10u + (sequence_number & 0x0fu))},
                },
        };
    };

    const auto serialize_one_rtt_ack_datagram =
        [](const QuicConnection &connection, const TrafficSecret &secret,
           std::uint64_t packet_number, bool key_phase = false) {
            const auto encoded = serialize_protected_datagram(
                std::array<ProtectedPacket, 1>{
                    ProtectedOneRttPacket{
                        .key_phase = key_phase,
                        .destination_connection_id = connection.config_.source_connection_id,
                        .packet_number_length = 2,
                        .packet_number = packet_number,
                        .frames = {AckFrame{}},
                    },
                },
                SerializeProtectionContext{
                    .local_role = EndpointRole::server,
                    .client_initial_destination_connection_id =
                        connection.client_initial_destination_connection_id(),
                    .one_rtt_secret = secret,
                    .one_rtt_key_phase = key_phase,
                });
            if (!encoded.has_value()) {
                return std::vector<std::byte>{};
            }
            return encoded.value();
        };
    const auto serialize_handshake_ping_datagram = [](const QuicConnection &connection,
                                                      const TrafficSecret &secret,
                                                      std::uint64_t packet_number) {
        const auto encoded = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = bytes_from_ints_for_tests({0x11, 0x90}),
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames = {PingFrame{}},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = secret,
            });
        if (!encoded.has_value()) {
            return std::vector<std::byte>{};
        }
        return encoded.value();
    };

    const auto enable_qlog_for_connection_coverage = [](QuicConnection &connection,
                                                        std::string_view label) {
#if defined(COQUIC_WASM_NO_FILESYSTEM)
        static_cast<void>(connection);
        static_cast<void>(label);
        return false;
#else
        static std::uint64_t next_id = 0;
        const auto directory =
            std::filesystem::temp_directory_path() /
            ("coquic-connection-coverage-" + std::string(label) + "-" + std::to_string(next_id++));
        connection.config_.qlog = QuicQlogConfig{.directory = directory};
        connection.qlog_session_ = qlog::Session::try_open(
            *connection.config_.qlog, connection.config_.role,
            connection.client_initial_destination_connection_id(), QuicCoreTimePoint{});
        return connection.qlog_session_ != nullptr;
#endif
    };

    {
        auto connection = make_connected_client_connection();
        connection.queue_new_token({});
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_token_frames_.empty());
        connection.status_ = HandshakeStatus::failed;
        connection.queue_new_token(bytes_from_ints_for_tests({0x01}));
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_token_frames_.empty());
        const auto failed_datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(failed_datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.terminal_state_expired(QuicCoreTimePoint{}));
    }

    {
        auto connection = make_connected_client_connection();
        connection.close_mode_ = QuicConnectionCloseMode::closing;
        connection.close_deadline_.reset();
        connection.on_timeout(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(connection.close_mode_ == QuicConnectionCloseMode::closing);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.terminal_state_expired(QuicCoreTimePoint{}));
    }

    {
        auto connection = make_connected_client_connection();
        connection.status_ = HandshakeStatus::failed;
        connection.idle_timeout_base_time_ = QuicCoreTimePoint{};
        COQUIC_CONNECTION_HOOK_RECORD(!connection.idle_timeout_deadline().has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.peer_transport_parameters_->stateless_reset_token =
            std::array<std::byte, 16>{std::byte{0x21}};
        connection.peer_connection_ids_[1] = PeerConnectionIdRecord{
            .sequence_number = 1,
            .connection_id = bytes_from_ints_for_tests({0xa1}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x31}},
        };
        connection.peer_connection_ids_[2] = PeerConnectionIdRecord{
            .sequence_number = 2,
            .connection_id = bytes_from_ints_for_tests({0xa2}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x32}},
            .locally_retired = true,
        };
        const auto tokens = connection.peer_stateless_reset_tokens();
        COQUIC_CONNECTION_HOOK_RECORD(tokens.size() == 2);
        COQUIC_CONNECTION_HOOK_RECORD(
            std::ranges::none_of(tokens, [](const StatelessResetTokenRecord &record) {
                return record.connection_id == bytes_from_ints_for_tests({0xa2});
            }));
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.transport.enable_optimistic_ack_mitigation = true;
        auto &packet_space = connection.application_space_;
        packet_space.optimistic_ack_skipped_packet_numbers = {4, 8, 12};
        const AckFrame ack_frame{
            .largest_acknowledged = 8,
            .first_ack_range = 0,
        };
        const auto cursor = make_ack_range_cursor(ack_frame);
        COQUIC_CONNECTION_HOOK_RECORD(cursor.has_value());
        if (cursor.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(
                connection.ack_ranges_include_unsent_packet_number(packet_space, cursor.value()));
        }
        packet_space.recovery.on_packet_sent(SentPacketRecord{
            .packet_number = 8,
            .sent_time = QuicCoreTimePoint{},
            .ack_eliciting = true,
            .in_flight = true,
            .bytes_in_flight = 1,
        });
        const AckFrame tracked_ack_frame{
            .largest_acknowledged = 8,
            .first_ack_range = 0,
        };
        const auto tracked_cursor = make_ack_range_cursor(tracked_ack_frame);
        COQUIC_CONNECTION_HOOK_RECORD(tracked_cursor.has_value());
        if (tracked_cursor.has_value()) {
            COQUIC_CONNECTION_HOOK_RECORD(!connection.ack_ranges_include_unsent_packet_number(
                packet_space, tracked_cursor.value()));
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.transport.enable_optimistic_ack_mitigation = true;
        connection.initial_space_.optimistic_ack_skipped_packet_numbers = {3};
        const auto processed =
            connection.process_inbound_crypto(EncryptionLevel::initial,
                                              std::array<Frame, 1>{Frame{AckFrame{
                                                  .largest_acknowledged = 3,
                                                  .first_ack_range = 0,
                                              }}},
                                              QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!processed.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.tls_.emplace(TlsAdapterConfig{
            .role = EndpointRole::client,
            .verify_peer = false,
            .server_name = "localhost",
            .local_transport_parameters = {},
        });
        connection.peer_transport_parameters_validated_ = false;
        const auto remembered_transport_parameters = make_runtime_transport_parameters(connection);
        connection.peer_transport_parameters_.reset();
        connection.decoded_resumption_state_ = StoredClientResumptionState{
            .tls_state = {},
            .quic_version = kQuicVersion1,
            .application_protocol = connection.config_.application_protocol,
            .peer_transport_parameters = remembered_transport_parameters,
            .application_context = connection.config_.zero_rtt.application_context,
        };
        auto reduced = remembered_transport_parameters;
        reduced.initial_max_data = 1;
        const auto serialized_reduced = serialize_transport_parameters(reduced);
        COQUIC_CONNECTION_HOOK_RECORD(serialized_reduced.has_value());
        if (serialized_reduced.has_value()) {
            TlsAdapterTestPeer::set_peer_transport_parameters(*connection.tls_,
                                                              serialized_reduced.value());
            TlsAdapterTestPeer::set_early_data_attempted(*connection.tls_, true);
            TlsAdapterTestPeer::set_early_data_accepted(*connection.tls_, true);
            const auto validated = connection.validate_peer_transport_parameters_if_ready();
            COQUIC_CONNECTION_HOOK_RECORD(!validated.has_value());
            if (!validated.has_value()) {
                COQUIC_CONNECTION_HOOK_RECORD(validated.error().code ==
                                              CodecErrorCode::invalid_packet_protection_state);
            }
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.tls_.emplace(TlsAdapterConfig{
            .role = EndpointRole::client,
            .verify_peer = false,
            .server_name = "localhost",
            .local_transport_parameters = {},
        });
        connection.peer_transport_parameters_validated_ = false;
        connection.peer_transport_parameters_.reset();
        const auto remembered_transport_parameters = make_runtime_transport_parameters(connection);
        connection.decoded_resumption_state_ = StoredClientResumptionState{
            .tls_state = {},
            .quic_version = kQuicVersion1,
            .application_protocol = connection.config_.application_protocol,
            .peer_transport_parameters = remembered_transport_parameters,
            .application_context = connection.config_.zero_rtt.application_context,
        };
        auto current = remembered_transport_parameters;
        current.initial_max_data = remembered_transport_parameters.initial_max_data + 1;
        const auto serialized_current = serialize_transport_parameters(current);
        COQUIC_CONNECTION_HOOK_RECORD(serialized_current.has_value());
        if (serialized_current.has_value()) {
            TlsAdapterTestPeer::set_peer_transport_parameters(*connection.tls_,
                                                              serialized_current.value());
            TlsAdapterTestPeer::set_early_data_attempted(*connection.tls_, true);
            TlsAdapterTestPeer::set_early_data_accepted(*connection.tls_, true);
            const auto validated = connection.validate_peer_transport_parameters_if_ready();
            COQUIC_CONNECTION_HOOK_RECORD(validated.has_value());
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.tls_.emplace(TlsAdapterConfig{
            .role = EndpointRole::client,
            .verify_peer = false,
            .server_name = "localhost",
            .local_transport_parameters = {},
        });
        connection.peer_transport_parameters_validated_ = false;
        connection.peer_transport_parameters_.reset();
        auto current = make_runtime_transport_parameters(connection);
        const auto serialized_current = serialize_transport_parameters(current);
        COQUIC_CONNECTION_HOOK_RECORD(serialized_current.has_value());
        if (serialized_current.has_value()) {
            TlsAdapterTestPeer::set_peer_transport_parameters(*connection.tls_,
                                                              serialized_current.value());
            TlsAdapterTestPeer::set_early_data_attempted(*connection.tls_, true);
            TlsAdapterTestPeer::set_early_data_accepted(*connection.tls_, true);
            const auto validated = connection.validate_peer_transport_parameters_if_ready();
            COQUIC_CONNECTION_HOOK_RECORD(validated.has_value());
        }
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.transport.enable_optimistic_ack_mitigation = true;
        connection.handshake_space_.optimistic_ack_skipped_packet_numbers = {3};
        const auto processed = connection.process_inbound_received_crypto(
            EncryptionLevel::handshake,
            std::array<ReceivedFrame, 1>{ReceivedFrame{ReceivedAckFrame{
                .largest_acknowledged = 3,
                .first_ack_range = 0,
            }}},
            QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!processed.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.transport.enable_optimistic_ack_mitigation = true;
        connection.application_space_.optimistic_ack_skipped_packet_numbers = {3};
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{AckFrame{
                .largest_acknowledged = 3,
                .first_ack_range = 0,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(!processed.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.transport.enable_optimistic_ack_mitigation = true;
        connection.application_space_.optimistic_ack_skipped_packet_numbers = {3};
        const auto processed = connection.process_inbound_received_application(
            std::array<ReceivedFrame, 1>{ReceivedFrame{ReceivedAckFrame{
                .largest_acknowledged = 3,
                .first_ack_range = 0,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(!processed.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        const auto new_connection_id = make_new_connection_id_frame(4);
        connection.pending_new_connection_id_frames_.push_back(new_connection_id);
        connection.pending_retire_connection_id_frames_.push_back(RetireConnectionIdFrame{
            .sequence_number = 5,
        });
        connection.peer_connection_ids_[5] = PeerConnectionIdRecord{
            .sequence_number = 5,
            .connection_id = bytes_from_ints_for_tests({0xa5}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x35}},
            .locally_retired = true,
        };
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 41,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .new_connection_id_frames = {new_connection_id},
                                         .retire_connection_id_frames = {RetireConnectionIdFrame{
                                             .sequence_number = 5,
                                         }},
                                         .bytes_in_flight = 1,
                                     });
        const auto handle = connection.application_space_.recovery.handle_for_packet_number(41);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto retired =
                connection.retire_acked_packet(connection.application_space_, *handle);
            COQUIC_CONNECTION_HOOK_RECORD(retired.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_connection_id_frames_.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.peer_connection_ids_.contains(5));
    }

    {
        auto connection = make_connected_client_connection();
        const auto retire_connection_id = RetireConnectionIdFrame{.sequence_number = 50};
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 450,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        const auto handle = connection.application_space_.recovery.handle_for_packet_number(450);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto retired =
                connection.retire_acked_packet(connection.application_space_, *handle);
            COQUIC_CONNECTION_HOOK_RECORD(retired.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(!connection.peer_connection_ids_.contains(50));
    }

    {
        auto connection = make_connected_client_connection();
        const auto retire_connection_id = RetireConnectionIdFrame{.sequence_number = 51};
        connection.peer_connection_ids_[51] = PeerConnectionIdRecord{
            .sequence_number = 51,
            .connection_id = bytes_from_ints_for_tests({0xd1}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x51}},
        };
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 451,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        const auto handle = connection.application_space_.recovery.handle_for_packet_number(451);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto retired =
                connection.retire_acked_packet(connection.application_space_, *handle);
            COQUIC_CONNECTION_HOOK_RECORD(retired.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_connection_ids_.contains(51));
    }

    {
        auto connection = make_connected_client_connection();
        const NewTokenFrame new_token{.token = bytes_from_ints_for_tests({0x6e})};
        const auto new_connection_id = make_new_connection_id_frame(6);
        const RetireConnectionIdFrame retire_connection_id{.sequence_number = 7};
        connection.peer_connection_ids_[7] = PeerConnectionIdRecord{
            .sequence_number = 7,
            .connection_id = bytes_from_ints_for_tests({0xa7}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x37}},
            .retire_frame_in_flight = true,
        };
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 42,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .new_token_frames = {new_token},
                                         .new_connection_id_frames = {new_connection_id},
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        const auto handle = connection.application_space_.recovery.handle_for_packet_number(42);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto lost = connection.mark_lost_packet(connection.application_space_, *handle,
                                                          /*already_marked_in_recovery=*/false,
                                                          QuicCoreTimePoint{});
            COQUIC_CONNECTION_HOOK_RECORD(lost.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_token_frames_.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_connection_id_frames_.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.peer_connection_ids_.at(7).retire_frame_in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        const auto retire_connection_id = RetireConnectionIdFrame{.sequence_number = 44};
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 440,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        const auto handle = connection.application_space_.recovery.handle_for_packet_number(440);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto retired =
                connection.retire_acked_packet(connection.application_space_, *handle);
            COQUIC_CONNECTION_HOOK_RECORD(retired.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.empty());
    }

    {
        auto connection = make_connected_client_connection();
        const auto retire_connection_id = RetireConnectionIdFrame{.sequence_number = 45};
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 441,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        const auto handle = connection.application_space_.recovery.handle_for_packet_number(441);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto lost = connection.mark_lost_packet(connection.application_space_, *handle,
                                                          /*already_marked_in_recovery=*/false,
                                                          QuicCoreTimePoint{});
            COQUIC_CONNECTION_HOOK_RECORD(lost.has_value());
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.size() == 1);
    }

    {
        auto connection = make_connected_client_connection();
        const auto new_connection_id = make_new_connection_id_frame(8);
        const auto retire_connection_id = RetireConnectionIdFrame{.sequence_number = 9};
        connection.pending_new_connection_id_frames_.push_back(new_connection_id);
        connection.pending_retire_connection_id_frames_.push_back(retire_connection_id);
        connection.pending_new_token_frames_.push_back(NewTokenFrame{
            .token = bytes_from_ints_for_tests({0x6e, 0x74}),
        });
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 43,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .new_token_frames = {NewTokenFrame{
                                             .token = bytes_from_ints_for_tests({0x6e, 0x74}),
                                         }},
                                         .new_connection_id_frames = {new_connection_id},
                                         .retire_connection_id_frames = {retire_connection_id},
                                         .bytes_in_flight = 1,
                                     });
        const auto probe = connection.select_pto_probe(connection.application_space_);
        COQUIC_CONNECTION_HOOK_RECORD(probe.packet_number == 43);
        COQUIC_CONNECTION_HOOK_RECORD(probe.new_token_frames.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(probe.new_connection_id_frames.size() == 1);
        COQUIC_CONNECTION_HOOK_RECORD(probe.retire_connection_id_frames.size() == 1);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.destination_connection_id_override = bytes_from_ints_for_tests({0xd1});
        COQUIC_CONNECTION_HOOK_RECORD(connection.can_initiate_path_validation(0));
        path.destination_connection_id_override.reset();
        connection.ensure_path_state(7);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.can_initiate_path_validation(7));
        connection.peer_connection_ids_.clear();
        connection.active_peer_connection_id_sequence_ = 99;
        connection.start_path_validation(9, /*initiated_locally=*/true, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!connection.paths_.contains(9));
        connection.current_send_path_id_ = 0;
        connection.maybe_switch_to_path(8, /*initiated_locally=*/true, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!connection.paths_.contains(8));

        connection = make_connected_client_connection();
        connection.peer_connection_ids_[3] = PeerConnectionIdRecord{
            .sequence_number = 3,
            .connection_id = bytes_from_ints_for_tests({0xa3}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x43}},
            .locally_retired = true,
        };
        auto &retired_path = connection.ensure_path_state(3);
        retired_path.peer_connection_id_sequence = 3;
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.select_peer_connection_id_sequence_for_path(3).has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &current_path = connection.ensure_path_state(0);
        current_path.peer_connection_id_sequence = 0;
        auto &new_path = connection.ensure_path_state(4);
        new_path.peer_connection_id_sequence = 4;
        new_path.outstanding_challenge =
            std::array{std::byte{0x40}, std::byte{0x41}, std::byte{0x42}, std::byte{0x43},
                       std::byte{0x44}, std::byte{0x45}, std::byte{0x46}, std::byte{0x47}};
        connection.peer_connection_ids_[0] = PeerConnectionIdRecord{
            .sequence_number = 0,
            .connection_id = bytes_from_ints_for_tests({0xa0}),
        };
        connection.peer_connection_ids_[4] = PeerConnectionIdRecord{
            .sequence_number = 4,
            .connection_id = bytes_from_ints_for_tests({0xa4}),
        };
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *new_path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/4);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 4);
        COQUIC_CONNECTION_HOOK_RECORD(connection.previous_path_id_ == std::optional<QuicPathId>{0});
        COQUIC_CONNECTION_HOOK_RECORD(!new_path.outstanding_challenge.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.size() == 1);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.peer_connection_id_sequence = 0;
        path.outstanding_challenge =
            std::array{std::byte{0x50}, std::byte{0x51}, std::byte{0x52}, std::byte{0x53},
                       std::byte{0x54}, std::byte{0x55}, std::byte{0x56}, std::byte{0x57}};
        connection.previous_path_id_ = 0;
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.peer_connection_id_sequence = 0;
        path.outstanding_challenge =
            std::array{std::byte{0x21}, std::byte{0x22}, std::byte{0x23}, std::byte{0x24},
                       std::byte{0x25}, std::byte{0x26}, std::byte{0x27}, std::byte{0x28}};
        connection.previous_path_id_ = 0;
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &nonviable_path = connection.ensure_path_state(4);
        nonviable_path.peer_connection_id_sequence = 4;
        nonviable_path.mtu.viable = false;
        nonviable_path.outstanding_challenge =
            std::array{std::byte{0x29}, std::byte{0x2a}, std::byte{0x2b}, std::byte{0x2c},
                       std::byte{0x2d}, std::byte{0x2e}, std::byte{0x2f}, std::byte{0x30}};
        connection.previous_path_id_ = 0;
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *nonviable_path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/4);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!nonviable_path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.peer_connection_id_sequence = 0;
        path.outstanding_challenge =
            std::array{std::byte{0x48}, std::byte{0x49}, std::byte{0x4a}, std::byte{0x4b},
                       std::byte{0x4c}, std::byte{0x4d}, std::byte{0x4e}, std::byte{0x4f}};
        connection.previous_path_id_.reset();
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.peer_connection_id_sequence = 0;
        path.outstanding_challenge =
            std::array{std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34},
                       std::byte{0x35}, std::byte{0x36}, std::byte{0x37}, std::byte{0x38}};
        path.challenge_pending = true;
        connection.previous_path_id_ = 0;
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{
                .data = *path.outstanding_challenge,
            }}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.peer_connection_ids_[1] = PeerConnectionIdRecord{
            .sequence_number = 1,
            .connection_id = bytes_from_ints_for_tests({0xa1}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x41}},
        };
        connection.peer_connection_ids_[2] = PeerConnectionIdRecord{
            .sequence_number = 2,
            .connection_id = bytes_from_ints_for_tests({0xa2}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x42}},
        };
        auto &old_path = connection.ensure_path_state(1);
        old_path.peer_connection_id_sequence = 1;
        auto &same_peer_path = connection.ensure_path_state(2);
        same_peer_path.peer_connection_id_sequence = 1;
        connection.retire_peer_connection_id_for_inactive_path(1, 1);
        connection.retire_peer_connection_id_for_inactive_path(1, 2);
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.empty());
        same_peer_path.peer_connection_id_sequence = 2;
        auto &third_path = connection.ensure_path_state(3);
        third_path.peer_connection_id_sequence = 1;
        connection.retire_peer_connection_id_for_inactive_path(1, 2);
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.empty());
        third_path.peer_connection_id_sequence = 2;
        connection.retire_peer_connection_id_for_inactive_path(1, 2);
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.size() == 1);

        auto missing_new_path = make_connected_client_connection();
        missing_new_path.peer_connection_ids_[5] = PeerConnectionIdRecord{
            .sequence_number = 5,
            .connection_id = bytes_from_ints_for_tests({0xa5}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x45}},
        };
        auto &old_only_path = missing_new_path.ensure_path_state(5);
        old_only_path.peer_connection_id_sequence = 5;
        missing_new_path.retire_peer_connection_id_for_inactive_path(5, 6);
        COQUIC_CONNECTION_HOOK_RECORD(
            missing_new_path.pending_retire_connection_id_frames_.size() == 1);
    }

    {
        auto connection = make_connected_client_connection();
        auto &validated_path = connection.ensure_path_state(9);
        validated_path.validated = true;
        validated_path.mtu.viable = false;
        connection.maybe_switch_to_path(9, /*initiated_locally=*/false, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        connection.reset_recovery_for_new_path(0);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
    }

    {
        auto connection = make_connected_client_connection();
        auto empty_destination_processed =
            connection.process_new_connection_id_frame(NewConnectionIdFrame{
                .sequence_number = 1,
                .connection_id = bytes_from_ints_for_tests({0xb1}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(empty_destination_processed.has_value());
        connection.config_.initial_destination_connection_id.clear();
        connection.peer_connection_ids_.clear();
        connection.peer_source_connection_id_.reset();
        auto empty_destination_rejected =
            connection.process_new_connection_id_frame(NewConnectionIdFrame{
                .sequence_number = 1,
                .connection_id = bytes_from_ints_for_tests({0xb2}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(!empty_destination_rejected.has_value());

        connection = make_connected_client_connection();
        connection.largest_peer_retire_prior_to_ = 5;
        connection.peer_connection_ids_[4] = PeerConnectionIdRecord{
            .sequence_number = 4,
            .connection_id = bytes_from_ints_for_tests({0xb4}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x44}},
        };
        const auto stale_processed =
            connection.process_new_connection_id_frame(NewConnectionIdFrame{
                .sequence_number = 4,
                .retire_prior_to = 3,
                .connection_id = bytes_from_ints_for_tests({0xb4}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(stale_processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.size() == 1);

        connection = make_connected_client_connection();
        connection.largest_peer_retire_prior_to_ = 5;
        const auto already_retired_processed =
            connection.process_new_connection_id_frame(NewConnectionIdFrame{
                .sequence_number = 5,
                .retire_prior_to = 5,
                .connection_id = bytes_from_ints_for_tests({0xb5}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(already_retired_processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.peer_connection_ids_.at(5).locally_retired);

        connection = make_connected_client_connection();
        connection.largest_peer_retire_prior_to_ = 5;
        connection.peer_connection_ids_[4] = PeerConnectionIdRecord{
            .sequence_number = 4,
            .connection_id = bytes_from_ints_for_tests({0xb6}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x46}},
        };
        const auto lower_than_largest_processed =
            connection.process_new_connection_id_frame(NewConnectionIdFrame{
                .sequence_number = 4,
                .retire_prior_to = 4,
                .connection_id = bytes_from_ints_for_tests({0xb6}),
                .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x46}},
            });
        COQUIC_CONNECTION_HOOK_RECORD(lower_than_largest_processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(std::ranges::any_of(
            connection.pending_retire_connection_id_frames_,
            [](const RetireConnectionIdFrame &frame) { return frame.sequence_number == 4; }));

        connection = make_connected_client_connection();
        connection.largest_peer_retire_prior_to_ = 5;
        const auto stale_not_retired_processed =
            connection.process_new_connection_id_frame(NewConnectionIdFrame{
                .sequence_number = 5,
                .retire_prior_to = 4,
                .connection_id = bytes_from_ints_for_tests({0xb7}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(stale_not_retired_processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_retire_connection_id_frames_.empty());

        connection.queue_peer_connection_id_retirement(99);
        connection.peer_connection_ids_[10] = PeerConnectionIdRecord{
            .sequence_number = 10,
            .connection_id = bytes_from_ints_for_tests({0xba}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x4a}},
            .retire_frame_in_flight = true,
        };
        connection.queue_peer_connection_id_retirement(10);
        COQUIC_CONNECTION_HOOK_RECORD(std::ranges::none_of(
            connection.pending_retire_connection_id_frames_,
            [](const RetireConnectionIdFrame &frame) { return frame.sequence_number == 10; }));
        connection.peer_connection_ids_[11] = PeerConnectionIdRecord{
            .sequence_number = 11,
            .connection_id = bytes_from_ints_for_tests({0xbb}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x4b}},
        };
        connection.pending_retire_connection_id_frames_.push_back(RetireConnectionIdFrame{
            .sequence_number = 11,
        });
        connection.queue_peer_connection_id_retirement(11);
        COQUIC_CONNECTION_HOOK_RECORD(
            std::ranges::count_if(connection.pending_retire_connection_id_frames_,
                                  [](const RetireConnectionIdFrame &frame) {
                                      return frame.sequence_number == 11;
                                  }) == 1);
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_confirmed_ = true;
        connection.peer_transport_parameters_->active_connection_id_limit = 2;
        auto &path = connection.ensure_path_state(0);
        path.mtu.viable = false;
        connection.issue_spare_connection_ids();
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_new_connection_id_frames_.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_application_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_congestion_controlled_send());
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit_for_path(0) == 0);

        auto no_current_send_path = make_connected_client_connection();
        auto &no_current_path = no_current_send_path.ensure_path_state(0);
        no_current_send_path.current_send_path_id_.reset();
        no_current_send_path.previous_path_id_ = 0;
        no_current_send_path.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(!no_current_path.mtu.viable);
        COQUIC_CONNECTION_HOOK_RECORD(!no_current_send_path.pending_transport_close_.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_confirmed_ = true;
        connection.peer_transport_parameters_->active_connection_id_limit = 3;
        connection.current_send_path_id_.reset();
        connection.issue_spare_connection_ids();
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pending_new_connection_id_frames_.empty());

        auto missing_current_send_path = make_connected_client_connection();
        missing_current_send_path.peer_transport_parameters_->active_connection_id_limit = 3;
        missing_current_send_path.current_send_path_id_ = 27;
        missing_current_send_path.issue_spare_connection_ids();
        COQUIC_CONNECTION_HOOK_RECORD(
            !missing_current_send_path.pending_new_connection_id_frames_.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.close_mode_ = QuicConnectionCloseMode::draining;
        connection.status_ = HandshakeStatus::failed;
        connection.close_started_at_ = QuicCoreTimePoint{};
        connection.close_deadline_ = QuicCoreTimePoint{} + std::chrono::milliseconds(1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_application_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_congestion_controlled_send());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.flush_outbound_datagram(QuicCoreTimePoint{}).empty());
        connection.enter_closing_state(QuicCoreTimePoint{}, QuicConnectionTerminalState::failed);
        COQUIC_CONNECTION_HOOK_RECORD(connection.close_mode_ == QuicConnectionCloseMode::draining);
        connection.queue_transport_close_for_error(
            QuicCoreTimePoint{}, CodecError{.code = CodecErrorCode::invalid_varint, .offset = 0});
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pending_transport_close_.has_value());
        connection.mark_silent_close();
        COQUIC_CONNECTION_HOOK_RECORD(connection.status_ == HandshakeStatus::failed);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.terminal_state_expired(QuicCoreTimePoint{}));
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.terminal_state_expired(QuicCoreTimePoint{} + std::chrono::milliseconds(1)));
    }

    {
        auto connection = make_connected_client_connection();
        connection.pending_transport_close_ = TransportConnectionCloseFrame{
            .error_code = transport_error_code_value(QuicTransportErrorCode::internal_error),
        };
        const auto transport_close = connection.connection_close_frame_for_send();
        COQUIC_CONNECTION_HOOK_RECORD(transport_close.has_value());
        if (transport_close.has_value()) {
            connection.mark_connection_close_frame_sent(*transport_close, QuicCoreTimePoint{});
        }
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pending_transport_close_.has_value());

        auto closing = make_connected_client_connection();
        closing.closing_application_close_ = ApplicationConnectionCloseFrame{
            .error_code = 1,
            .reason = ConnectionCloseReason{.bytes = bytes_from_ints_for_tests({0x63})},
        };
        COQUIC_CONNECTION_HOOK_RECORD(closing.connection_close_frame_for_send().has_value());
        auto pending = make_connected_client_connection();
        pending.pending_application_close_ = ApplicationConnectionCloseFrame{
            .error_code = 2,
            .reason = ConnectionCloseReason{.bytes = bytes_from_ints_for_tests({0x64})},
        };
        COQUIC_CONNECTION_HOOK_RECORD(pending.connection_close_frame_for_send().has_value());
        pending.mark_connection_close_frame_sent(Frame{PingFrame{}}, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(pending.pending_application_close_.has_value());

        auto close_guard = make_connected_client_connection();
        close_guard.close_mode_ = QuicConnectionCloseMode::closing;
        close_guard.closing_close_packet_pending_ = false;
        COQUIC_CONNECTION_HOOK_RECORD(
            close_guard.flush_outbound_datagram(QuicCoreTimePoint{}).empty());
        close_guard.closing_close_packet_pending_ = true;
        close_guard.initial_packet_space_discarded_ = true;
        close_guard.handshake_space_.write_secret.reset();
        close_guard.application_space_.write_secret.reset();
        COQUIC_CONNECTION_HOOK_RECORD(
            close_guard.flush_outbound_datagram(QuicCoreTimePoint{}).empty());

        auto no_close_frame_send = make_connected_client_connection();
        no_close_frame_send.close_mode_ = QuicConnectionCloseMode::closing;
        no_close_frame_send.closing_close_packet_pending_ = true;
        no_close_frame_send.pending_application_close_.reset();
        no_close_frame_send.closing_application_close_.reset();
        no_close_frame_send.pending_transport_close_.reset();
        no_close_frame_send.closing_transport_close_.reset();
        COQUIC_CONNECTION_HOOK_RECORD(
            no_close_frame_send.flush_outbound_datagram(QuicCoreTimePoint{}).empty());

        auto missing_close_metadata = make_connected_client_connection();
        missing_close_metadata.close_mode_ = QuicConnectionCloseMode::closing;
        missing_close_metadata.closing_close_packet_pending_ = true;
        missing_close_metadata.pending_application_close_ = ApplicationConnectionCloseFrame{
            .error_code = 4,
        };
        {
            const ScopedConnectionDrainTestHook hook(
                &ConnectionDrainTestHooks::force_missing_close_packet_metadata);
            COQUIC_CONNECTION_HOOK_RECORD(
                !missing_close_metadata.flush_outbound_datagram(QuicCoreTimePoint{}).empty());
        }

        auto close_metadata_present = make_connected_client_connection();
        close_metadata_present.close_mode_ = QuicConnectionCloseMode::closing;
        close_metadata_present.closing_close_packet_pending_ = true;
        close_metadata_present.pending_application_close_ = ApplicationConnectionCloseFrame{
            .error_code = 5,
        };
        COQUIC_CONNECTION_HOOK_RECORD(
            !close_metadata_present.flush_outbound_datagram(QuicCoreTimePoint{}).empty());

        auto no_frame_close = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            !no_frame_close.connection_close_frame_for_send().has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x81}, std::byte{0x82}, std::byte{0x83}, std::byte{0x84},
                       std::byte{0x85}, std::byte{0x86}, std::byte{0x87}, std::byte{0x88}};
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_application_send());
        path.pending_response.reset();
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x91}, std::byte{0x92}, std::byte{0x93}, std::byte{0x94},
                       std::byte{0x95}, std::byte{0x96}, std::byte{0x97}, std::byte{0x98}};
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_application_send());
        path.mtu.viable = false;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_application_send());
    }

    {
        auto connection = make_connected_client_connection();
        auto bidi_peer_stream = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::server);
        bidi_peer_stream.peer_fin_delivered = true;
        bidi_peer_stream.send_fin_state = StreamSendFinState::acknowledged;
        connection.maybe_refresh_peer_stream_limit(bidi_peer_stream);
        COQUIC_CONNECTION_HOOK_RECORD(bidi_peer_stream.peer_stream_limit_released);
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_stream_limit_state_.max_streams_bidi_state ==
                                      StreamControlFrameState::pending);

        auto uni_peer_stream = make_implicit_stream_state(/*stream_id=*/2, EndpointRole::server);
        uni_peer_stream.peer_fin_delivered = true;
        connection.maybe_refresh_peer_stream_limit(uni_peer_stream);
        COQUIC_CONNECTION_HOOK_RECORD(uni_peer_stream.peer_stream_limit_released);
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_stream_limit_state_.max_streams_uni_state ==
                                      StreamControlFrameState::pending);
    }

    {
        auto connection = make_connected_client_connection();
        connection.close_mode_ = QuicConnectionCloseMode::closing;
        connection.closing_close_packet_pending_ = true;
        connection.pending_application_close_ = ApplicationConnectionCloseFrame{
            .error_code = 3,
        };
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_pending_congestion_controlled_send());
    }

    {
        auto connection = make_connected_client_connection();
        connection.mark_failed();
        COQUIC_CONNECTION_HOOK_RECORD(connection.pending_terminal_state_ ==
                                      std::optional{QuicConnectionTerminalState::failed});
        auto silent = make_connected_client_connection();
        silent.mark_silent_close();
        COQUIC_CONNECTION_HOOK_RECORD(silent.pending_terminal_state_ ==
                                      std::optional{QuicConnectionTerminalState::closed});
        auto already_terminal = make_connected_client_connection();
        already_terminal.pending_terminal_state_ = QuicConnectionTerminalState::closed;
        already_terminal.mark_failed();
        COQUIC_CONNECTION_HOOK_RECORD(already_terminal.pending_terminal_state_ ==
                                      std::optional{QuicConnectionTerminalState::closed});
        auto already_silent_terminal = make_connected_client_connection();
        already_silent_terminal.pending_terminal_state_ = QuicConnectionTerminalState::failed;
        already_silent_terminal.mark_silent_close();
        COQUIC_CONNECTION_HOOK_RECORD(already_silent_terminal.pending_terminal_state_ ==
                                      std::optional{QuicConnectionTerminalState::failed});
    }

    {
        auto connection = make_connected_client_connection();
        connection.latency_spin_bit_disabled_ = false;
        auto &path = connection.ensure_path_state(0);
        path.spin.disabled = true;
        connection.update_spin_bit_on_receive(0, true, 1);
        COQUIC_CONNECTION_HOOK_RECORD(!path.spin.largest_peer_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.outbound_spin_bit_for_path(std::nullopt));
        path.spin.disabled = false;
        path.spin.value = true;
        connection.current_send_path_id_.reset();
        COQUIC_CONNECTION_HOOK_RECORD(!connection.outbound_spin_bit_for_path(std::nullopt));
        COQUIC_CONNECTION_HOOK_RECORD(!connection.outbound_spin_bit_for_path(99));
    }

    {
        QuicConnection connection(make_client_core_config_for_connection_coverage());
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.handshake_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x40});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x03}});
        connection.track_sent_packet(connection.initial_space_,
                                     SentPacketRecord{
                                         .packet_number = 6,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });

        connection.queue_client_handshake_recovery_probe();

        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.handshake_space_.pending_probe_packet.has_value() &&
            !connection.handshake_space_.pending_probe_packet->force_ack);
    }

    {
        QuicConnection connection(make_client_core_config_for_connection_coverage());
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.handshake_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        connection.track_sent_packet(connection.handshake_space_,
                                     SentPacketRecord{
                                         .packet_number = 7,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });

        connection.queue_client_handshake_recovery_probe();

        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.handshake_space_.pending_probe_packet.has_value());
    }

    {
        QuicConnection connection(make_client_core_config_for_connection_coverage());
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.handshake_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x47});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x04}});
        connection.handshake_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 4,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };

        connection.queue_client_handshake_recovery_probe();

        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.handshake_space_.pending_probe_packet->packet_number == 4);
    }

    {
        QuicConnection connection(make_client_core_config_for_connection_coverage());
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.handshake_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x42});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x02}});
        connection.handshake_space_.received_packets.record_received(
            /*packet_number=*/3, /*ack_eliciting=*/true, QuicCoreTimePoint{});
        connection.track_sent_packet(connection.initial_space_,
                                     SentPacketRecord{
                                         .packet_number = 8,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });

        connection.queue_client_handshake_recovery_probe();

        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.handshake_space_.pending_probe_packet.has_value() &&
            connection.handshake_space_.pending_probe_packet->force_ack);
    }

    for (const auto secret_level :
         {EncryptionLevel::handshake, EncryptionLevel::zero_rtt, EncryptionLevel::application}) {
        auto connection = make_connected_client_connection();
        connection.handshake_space_.read_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x90});
        if (secret_level == EncryptionLevel::handshake) {
            connection.handshake_space_.read_secret = TrafficSecret{
                .cipher_suite = invalid_cipher_suite_for_tests(),
                .secret = {std::byte{0x01}},
            };
        } else if (secret_level == EncryptionLevel::zero_rtt) {
            connection.zero_rtt_space_.read_secret = TrafficSecret{
                .cipher_suite = invalid_cipher_suite_for_tests(),
                .secret = {std::byte{0x02}},
            };
        } else {
            connection.application_space_.read_secret = TrafficSecret{
                .cipher_suite = invalid_cipher_suite_for_tests(),
                .secret = {std::byte{0x03}},
            };
        }

        const auto datagram = serialize_handshake_ping_datagram(
            connection,
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x90}),
            40 + static_cast<std::uint64_t>(secret_level));
        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        if (!datagram.empty()) {
            connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_packet_space_discarded_ = true;
        connection.handshake_space_.read_secret.reset();

        const auto datagram = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = bytes_from_ints_for_tests({0x11, 0x22}),
                    .packet_number_length = 2,
                    .packet_number = 11,
                    .frames = {PingFrame{}},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret =
                    make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x43}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(datagram.has_value());
        if (datagram.has_value()) {
            connection.process_inbound_datagram(datagram.value(), QuicCoreTimePoint{});
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.deferred_protected_packets_.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_packet_space_discarded_ = true;
        connection.handshake_space_.read_secret.reset();
        COQUIC_CONNECTION_HOOK_RECORD(
            enable_qlog_for_connection_coverage(connection, "discarded-handshake"));

        const auto datagram = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = bytes_from_ints_for_tests({0x11, 0x23}),
                    .packet_number_length = 2,
                    .packet_number = 14,
                    .frames = {PingFrame{}},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret =
                    make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x45}),
            });
        COQUIC_CONNECTION_HOOK_RECORD(datagram.has_value());
        if (datagram.has_value()) {
            connection.process_inbound_datagram(datagram.value(), QuicCoreTimePoint{});
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.deferred_protected_packets_.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_space_.read_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x44});

        const auto first_packet = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = {std::byte{0xaa}},
                    .packet_number_length = 2,
                    .packet_number = 12,
                    .frames = {AckFrame{}},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = connection.handshake_space_.read_secret,
            });
        const auto second_packet = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = {std::byte{0xaa}},
                    .packet_number_length = 2,
                    .packet_number = 13,
                    .frames = {CryptoFrame{
                        .offset = 0,
                        .crypto_data = bytes_from_ints_for_tests({0x01}),
                    }},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = connection.handshake_space_.read_secret,
            });
        COQUIC_CONNECTION_HOOK_RECORD(first_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(second_packet.has_value());
        if (first_packet.has_value() && second_packet.has_value()) {
            auto datagram = first_packet.value();
            datagram.insert(datagram.end(), second_packet.value().begin(),
                            second_packet.value().end());
            connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_source_connection_id_ ==
                                      bytes_from_ints_for_tests({0xaa}));
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_space_.read_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x46});
        COQUIC_CONNECTION_HOOK_RECORD(enable_qlog_for_connection_coverage(
            connection, "processed-before-deserialize-failure"));

        const auto first_packet = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{
                ProtectedHandshakePacket{
                    .version = kQuicVersion1,
                    .destination_connection_id = connection.config_.source_connection_id,
                    .source_connection_id = {std::byte{0xab}},
                    .packet_number_length = 2,
                    .packet_number = 15,
                    .frames = {AckFrame{}},
                },
            },
            SerializeProtectionContext{
                .local_role = EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = connection.handshake_space_.read_secret,
            });
        COQUIC_CONNECTION_HOOK_RECORD(first_packet.has_value());
        if (first_packet.has_value()) {
            auto datagram = first_packet.value();
            datagram.push_back(std::byte{0x40});
            connection.process_inbound_datagram(datagram, QuicCoreTimePoint{});
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.peer_source_connection_id_ ==
                                      bytes_from_ints_for_tests({0xab}));
    }

    {
        auto connection = make_connected_client_connection();
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/21,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
                const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
                    coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup,
                    /*occurrence=*/4);
                connection.process_inbound_datagram(encoded, QuicCoreTimePoint{});
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            enable_qlog_for_connection_coverage(connection, "next-context-failure"));
        auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                connection.application_space_.read_secret->header_protection_key =
                    next_read_secret.value().header_protection_key;
                const auto current_ready =
                    expand_traffic_secret_cached(*connection.application_space_.read_secret);
                COQUIC_CONNECTION_HOOK_RECORD(current_ready.has_value());
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/23,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                if (!encoded.empty()) {
                    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
                    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
                        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup,
                        /*occurrence=*/2);
                    connection.process_inbound_datagram(encoded, QuicCoreTimePoint{});
                }
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/22,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                connection.application_space_.write_secret = TrafficSecret{
                    .cipher_suite = invalid_cipher_suite_for_tests(),
                    .secret = {std::byte{0x01}},
                };
                connection.process_inbound_datagram(encoded, QuicCoreTimePoint{});
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            enable_qlog_for_connection_coverage(connection, "next-write-secret-failure"));
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/24,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                connection.application_space_.write_secret = TrafficSecret{
                    .cipher_suite = invalid_cipher_suite_for_tests(),
                    .secret = {std::byte{0x01}},
                };
                connection.process_inbound_datagram(encoded, QuicCoreTimePoint{});
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            enable_qlog_for_connection_coverage(connection, "next-key-phase-qlog-retry-failure"));
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/25,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                if (!encoded.empty()) {
                    auto truncated = encoded;
                    truncated.pop_back();
                    connection.process_inbound_datagram(truncated, QuicCoreTimePoint{});
                }
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.application_read_key_phase_);
    }

    {
        auto connection = make_connected_client_connection();
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/26,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                connection.local_key_update_initiated_ = true;
                connection.local_key_update_requested_ = true;
                if (!encoded.empty()) {
                    connection.process_inbound_datagram(encoded, QuicCoreTimePoint{});
                }
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.application_read_key_phase_);
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_key_update_requested_);
    }

    {
        auto connection = make_connected_client_connection();
        COQUIC_CONNECTION_HOOK_RECORD(
            enable_qlog_for_connection_coverage(connection, "next-key-phase-qlog-local-initiated"));
        const auto current_secret = connection.application_space_.read_secret;
        COQUIC_CONNECTION_HOOK_RECORD(current_secret.has_value());
        if (current_secret.has_value()) {
            const auto next_read_secret = derive_next_traffic_secret(current_secret.value());
            COQUIC_CONNECTION_HOOK_RECORD(next_read_secret.has_value());
            if (next_read_secret.has_value()) {
                const auto encoded = serialize_one_rtt_ack_datagram(
                    connection, next_read_secret.value(), /*packet_number=*/27,
                    !connection.application_read_key_phase_);
                COQUIC_CONNECTION_HOOK_RECORD(!encoded.empty());
                connection.local_key_update_initiated_ = true;
                connection.local_key_update_requested_ = true;
                if (!encoded.empty()) {
                    connection.process_inbound_datagram(encoded, QuicCoreTimePoint{});
                }
            }
        }

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
        COQUIC_CONNECTION_HOOK_RECORD(connection.application_read_key_phase_);
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_key_update_requested_);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.outstanding_challenge =
            std::array{std::byte{0xa1}, std::byte{0xa2}, std::byte{0xa3}, std::byte{0xa4},
                       std::byte{0xa5}, std::byte{0xa6}, std::byte{0xa7}, std::byte{0xa8}};
        path.challenge_pending = true;
        connection.previous_path_id_ = 5;
        auto &previous = connection.ensure_path_state(5);
        previous.peer_connection_id_sequence = 5;
        connection.process_inbound_application(
            std::array<Frame, 1>{Frame{PathResponseFrame{.data = *path.outstanding_challenge}}},
            QuicCoreTimePoint{}, /*allow_preconnected_frames=*/false, /*path_id=*/0);
        COQUIC_CONNECTION_HOOK_RECORD(!path.outstanding_challenge.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_packet_space_discarded_ = true;
        const auto processed = connection.process_inbound_packet(
            ProtectedPacket{ProtectedHandshakePacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_ints_for_tests({0x11, 0x91}),
                .packet_number_length = 2,
                .packet_number = 91,
                .frames = {PingFrame{}},
            }},
            QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_packet_space_discarded_ = true;
        const auto processed = connection.process_inbound_received_packet(
            ReceivedProtectedPacket{ReceivedProtectedHandshakePacket{
                .version = kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_ints_for_tests({0x11, 0x92}),
                .packet_number_length = 2,
                .packet_number = 92,
                .frames = {PingFrame{}},
            }},
            QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.local_key_update_requested_ = true;
        connection.handshake_confirmed_ = true;
        connection.current_write_phase_first_packet_number_ = 0;
        connection.application_space_.recovery.largest_acked_packet_number_ = 0;
        connection.application_space_.read_secret = TrafficSecret{
            .cipher_suite = invalid_cipher_suite_for_tests(),
            .secret = {std::byte{0x05}},
        };
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.queue_stream_send(0, bytes_from_ints_for_tests({0x61}), false).has_value());

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.local_key_update_requested_ = true;
        connection.handshake_confirmed_ = true;
        connection.current_write_phase_first_packet_number_ = 0;
        connection.application_space_.recovery.largest_acked_packet_number_ = 0;
        connection.application_space_.write_secret = TrafficSecret{
            .cipher_suite = invalid_cipher_suite_for_tests(),
            .secret = {std::byte{0x06}},
        };
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.queue_stream_send(0, bytes_from_ints_for_tests({0x62}), false).has_value());

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.handshake_confirmed_ = false;
        const auto processed = connection.process_inbound_received_crypto(
            EncryptionLevel::application,
            std::array<ReceivedFrame, 1>{ReceivedFrame{HandshakeDoneFrame{}}}, QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_confirmed_);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x51}, std::byte{0x02}},
            .initial_destination_connection_id = {std::byte{0x81}, std::byte{0x02}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = false;
        const auto processed = connection.process_inbound_application(
            std::array<Frame, 1>{Frame{HandshakeDoneFrame{}}}, QuicCoreTimePoint{},
            /*allow_preconnected_frames=*/false, /*path_id=*/0);

        COQUIC_CONNECTION_HOOK_RECORD(!processed.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(processed.error().code ==
                                      CodecErrorCode::frame_not_allowed_in_packet_type);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.handshake_confirmed_);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x51}, std::byte{0x01}},
            .initial_destination_connection_id = {std::byte{0x81}, std::byte{0x01}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 0;
        connection.anti_amplification_sent_bytes_ = 0;
        connection.current_send_path_id_.reset();

        const auto datagram = connection.flush_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.initial_space_.recovery.on_packet_sent(SentPacketRecord{
            .packet_number = 0,
            .sent_time = QuicCoreTimePoint{},
            .ack_eliciting = true,
            .in_flight = true,
            .bytes_in_flight = 1200,
        });
        const auto handles = connection.initial_space_.recovery.tracked_packets();
        COQUIC_CONNECTION_HOOK_RECORD(!handles.empty());
        if (!handles.empty()) {
            connection.initial_space_.recovery.retire_packet(handles.front());
            connection.initial_space_.recovery.slots_.front().state =
                PacketSpaceRecovery::LedgerSlotState::sent;
            connection.initial_space_.recovery.first_live_slot_ = 0;
            connection.initial_space_.recovery.last_live_slot_ = 0;
        }

        connection.discard_initial_packet_space();

        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_packet_space_discarded_);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x52}, std::byte{0x10}},
            .initial_destination_connection_id = {std::byte{0x82}, std::byte{0x10}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = true;
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = ConnectionId{std::byte{0xa7}},
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.initial_packet_space_discarded_ = true;
        connection.handshake_packet_space_discarded_ = true;
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x52});
        connection.handshake_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x62});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x02}});
        connection.initial_space_.received_packets.record_received(
            /*packet_number=*/11, /*ack_eliciting=*/true, QuicCoreTimePoint{});
        connection.handshake_space_.received_packets.record_received(
            /*packet_number=*/12, /*ack_eliciting=*/true, QuicCoreTimePoint{});
        connection.initial_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 2,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };
        connection.handshake_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 3,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_sendable_datagram(QuicCoreTimePoint{}));
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_congestion_controlled_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.loss_deadline().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pto_deadline().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.ack_deadline().has_value());

        const auto datagram = connection.flush_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x52}, std::byte{0x11}},
            .initial_destination_connection_id = {std::byte{0x82}, std::byte{0x11}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = true;
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = ConnectionId{std::byte{0xa8}},
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.initial_packet_space_discarded_ = true;
        connection.handshake_packet_space_discarded_ = true;
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x54});
        connection.handshake_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x64});
        connection.track_sent_packet(connection.initial_space_,
                                     SentPacketRecord{
                                         .packet_number = 30,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
        connection.track_sent_packet(connection.handshake_space_,
                                     SentPacketRecord{
                                         .packet_number = 31,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });

        connection.arm_pto_probe(QuicCoreTimePoint{} + std::chrono::seconds(30));
        connection.detect_lost_packets(QuicCoreTimePoint{} + std::chrono::seconds(30));

        COQUIC_CONNECTION_HOOK_RECORD(!connection.initial_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.handshake_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.recovery.tracked_packet_count() ==
                                      1);
        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.recovery.tracked_packet_count() ==
                                      1);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x52}, std::byte{0x01}},
            .initial_destination_connection_id = {std::byte{0x82}, std::byte{0x01}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = ConnectionId{std::byte{0xa5}},
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x53});
        connection.initial_space_.received_packets.record_received(
            /*packet_number=*/9, /*ack_eliciting=*/true, QuicCoreTimePoint{});
        connection.initial_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 1,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };

        const auto datagram = connection.flush_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.recovery.rtt_state().smoothed_rtt =
            std::chrono::milliseconds(1);
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 0,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 1,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
        const AckFrame ack_frame{
            .largest_acknowledged = 1,
        };
        const auto ack_cursor = make_ack_range_cursor(ack_frame);
        COQUIC_CONNECTION_HOOK_RECORD(ack_cursor.has_value());
        if (ack_cursor.has_value()) {
            static_cast<void>(connection.process_inbound_ack_cursor(
                connection.application_space_, ack_cursor.value(), /*largest_acknowledged=*/1,
                std::chrono::milliseconds{0}, std::nullopt, "[1-1]",
                QuicCoreTimePoint{} + std::chrono::seconds(5),
                connection.config_.transport.max_ack_delay,
                /*suppress_pto_reset=*/false));
        }
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_missing_packet_metadata);

        connection.detect_lost_packets(QuicCoreTimePoint{} + std::chrono::seconds(5));

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 5,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                         .is_pmtu_probe = true,
                                     });
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_mark_lost_packet_missing_after_lookup);

        connection.detect_lost_packets(QuicCoreTimePoint{} + std::chrono::seconds(5));

        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.initial_space_.recovery.slots_.resize(1);
        auto &slot = connection.initial_space_.recovery.slots_.front();
        slot.state = PacketSpaceRecovery::LedgerSlotState::retired;
        slot.packet.packet_number = 99;
        slot.packet.ack_eliciting = true;
        slot.packet.in_flight = true;
        slot.packet.bytes_in_flight = 1200;
        slot.prev_live_slot = PacketSpaceRecovery::kInvalidLedgerSlotIndex;
        slot.next_live_slot = PacketSpaceRecovery::kInvalidLedgerSlotIndex;
        connection.initial_space_.recovery.first_live_slot_ = 0;
        connection.initial_space_.recovery.last_live_slot_ = 0;

        connection.discard_initial_packet_space();

        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_packet_space_discarded_);
    }

    {
        auto connection = make_connected_client_connection();
        connection.pending_retire_connection_id_frames_.push_back(RetireConnectionIdFrame{
            .sequence_number = 12,
        });
        connection.peer_connection_ids_[12] = PeerConnectionIdRecord{
            .sequence_number = 12,
            .connection_id = bytes_from_ints_for_tests({0xbc}),
            .stateless_reset_token = std::array<std::byte, 16>{std::byte{0x4c}},
        };
        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.peer_connection_ids_.at(12).retire_frame_in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        connection.pending_retire_connection_id_frames_.push_back(RetireConnectionIdFrame{
            .sequence_number = 13,
        });
        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.peer_connection_ids_.contains(13));
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x54}, std::byte{0x01}},
            .initial_destination_connection_id = {std::byte{0x84}, std::byte{0x01}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::connected;
        connection.handshake_confirmed_ = true;
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = ConnectionId{std::byte{0xa6}},
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x55});
        connection.initial_space_.received_packets.record_received(
            /*packet_number=*/10, /*ack_eliciting=*/true, QuicCoreTimePoint{});

        const auto datagram = connection.flush_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
    }

#undef COQUIC_CONNECTION_HOOK_RECORD
#undef COQUIC_STRINGIFY
#undef COQUIC_STRINGIFY_DETAIL
    return ok;
}

bool connection_pmtud_coverage_for_tests() {
    bool ok = true;
#define COQUIC_STRINGIFY_DETAIL(value) #value
#define COQUIC_STRINGIFY(value) COQUIC_STRINGIFY_DETAIL(value)
#define COQUIC_CONNECTION_HOOK_RECORD(expr)                                                        \
    connection_coverage_check(ok, #expr ":" COQUIC_STRINGIFY(__LINE__), static_cast<bool>(expr))

    const auto make_connected_client_connection =
        make_connected_pmtud_client_connection_for_connection_coverage;

    const auto record_application_ack_ranges = [](QuicConnection &connection,
                                                  std::size_t range_count) {
        for (std::size_t index = 0; index < range_count; ++index) {
            connection.application_space_.received_packets.record_received(
                static_cast<std::uint64_t>(index * 2u), /*ack_eliciting=*/true,
                QuicCoreTimePoint{});
        }
        connection.application_space_.pending_ack_deadline = QuicCoreTimePoint{};
    };
    const auto queue_application_stream_byte = [](QuicConnection &connection,
                                                  std::uint64_t stream_id = 0) {
        constexpr std::array payload{std::byte{0x41}};
        const auto queued = connection.queue_stream_send(stream_id, payload, false);
        if (!queued.has_value()) {
            return false;
        }
        connection.connection_flow_control_.peer_max_data =
            std::max<std::uint64_t>(connection.connection_flow_control_.peer_max_data, 4096);
        if (auto *stream = connection.find_stream_state(stream_id); stream != nullptr) {
            stream->flow_control.peer_max_stream_data =
                std::max<std::uint64_t>(stream->flow_control.peer_max_stream_data, 4096);
            stream->send_flow_control_limit = stream->flow_control.peer_max_stream_data;
        }
        return queued.value();
    };
    const auto queue_application_stream_bytes = [](QuicConnection &connection, std::size_t size,
                                                   bool fin = false, std::uint64_t stream_id = 0) {
        const auto queued = connection.queue_stream_send(
            stream_id, std::vector<std::byte>(size, std::byte{0x41}), fin);
        if (!queued.has_value()) {
            return false;
        }
        connection.connection_flow_control_.peer_max_data =
            std::max<std::uint64_t>(connection.connection_flow_control_.peer_max_data, 8192);
        if (auto *stream = connection.find_stream_state(stream_id); stream != nullptr) {
            stream->flow_control.peer_max_stream_data =
                std::max<std::uint64_t>(stream->flow_control.peer_max_stream_data, 8192);
            stream->send_flow_control_limit = stream->flow_control.peer_max_stream_data;
        }
        return queued.value();
    };
    const auto reduce_remaining_congestion_window = [](QuicConnection &connection,
                                                       std::size_t remaining_bytes) {
        const auto cwnd = connection.congestion_controller_.congestion_window();
        if (cwnd > remaining_bytes) {
            connection.congestion_controller_.on_packet_sent(cwnd - remaining_bytes,
                                                             /*ack_eliciting=*/true);
        }
    };
    const auto make_path_validation_data = [](std::uint8_t first) {
        return std::array{
            std::byte{first},
            std::byte{static_cast<std::uint8_t>(first + 1u)},
            std::byte{static_cast<std::uint8_t>(first + 2u)},
            std::byte{static_cast<std::uint8_t>(first + 3u)},
            std::byte{static_cast<std::uint8_t>(first + 4u)},
            std::byte{static_cast<std::uint8_t>(first + 5u)},
            std::byte{static_cast<std::uint8_t>(first + 6u)},
            std::byte{static_cast<std::uint8_t>(first + 7u)},
        };
    };
    const auto queue_path_validation_frames = [&](QuicConnection &connection,
                                                  std::uint8_t response_first,
                                                  std::uint8_t challenge_first) -> PathState & {
        auto &path = connection.ensure_path_state(0);
        path.pending_response = make_path_validation_data(response_first);
        path.challenge_pending = true;
        path.outstanding_challenge = make_path_validation_data(challenge_first);
        return path;
    };
    const auto set_outbound_datagram_limit = [](QuicConnection &connection, std::size_t limit) {
        connection.config_.max_outbound_datagram_size = limit;
        if (connection.peer_transport_parameters_.has_value()) {
            connection.peer_transport_parameters_->max_udp_payload_size = limit;
        }
    };

    {
        PathMtuState remembered_failures;
        for (std::size_t index = 0; index <= kMaximumRememberedPmtudFailedProbeSizes; ++index) {
            remember_pmtud_failed_probe_size(remembered_failures,
                                             kMinimumInitialDatagramSize + 1 + index);
        }
        const auto retained_first = remembered_failures.failed_probe_sizes.front();
        remember_pmtud_failed_probe_size(remembered_failures, kMinimumInitialDatagramSize);
        remember_pmtud_failed_probe_size(remembered_failures, retained_first);
        const auto retained_size = remembered_failures.failed_probe_sizes.size();
        forget_pmtud_failed_probe_size(remembered_failures, retained_first);

        auto capped_config = make_client_core_config_for_connection_coverage();
        capped_config.max_outbound_datagram_size = 4096;
        capped_config.transport.pmtud_enabled = true;
        capped_config.transport.pmtud_base_datagram_size = 4096;
        capped_config.transport.pmtud_max_datagram_size = 1300;
        auto undersized_capped_config = capped_config;
        undersized_capped_config.transport.pmtud_max_datagram_size = 1000;

        COQUIC_CONNECTION_HOOK_RECORD(sanitize_pmtud_base(1) == kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(initial_congestion_datagram_size(capped_config) == 1300);
        COQUIC_CONNECTION_HOOK_RECORD(initial_congestion_datagram_size(undersized_capped_config) ==
                                      kMaximumDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(next_probe_size_between(1000, 1010) == 1010);
        COQUIC_CONNECTION_HOOK_RECORD(next_probe_size_between(1460, 1480) == 1476);
        COQUIC_CONNECTION_HOOK_RECORD(next_probe_size_between(1480, 1500) == 1496);
        COQUIC_CONNECTION_HOOK_RECORD(retained_size == kMaximumRememberedPmtudFailedProbeSizes);
        COQUIC_CONNECTION_HOOK_RECORD(
            !pmtud_probe_size_previously_failed(remembered_failures, kMinimumInitialDatagramSize));
        COQUIC_CONNECTION_HOOK_RECORD(
            !pmtud_probe_size_previously_failed(remembered_failures, retained_first));
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        remember_pmtud_failed_probe_size(path.mtu, next_probe_size_between(1200, 1600));
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_next_pmtu_probe_size_zero);
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests trace_filter("COQUIC_PACKET_TRACE_SCID", "");

        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.enabled);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.base_datagram_size == kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size ==
                                      kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit() ==
                                      kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_ceiling() == 4096);
        COQUIC_CONNECTION_HOOK_RECORD(connection.congestion_controller_.congestion_window() ==
                                      10 * kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(connection.congestion_controller_.minimum_window() ==
                                      2 * kMinimumInitialDatagramSize);
        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).value_or(0) ==
                                      kPmtudIPv4EthernetUdpPayloadSize);
        path.mtu.enabled = false;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());
    }

    {
        auto connection = make_connected_client_connection();
        std::vector<std::byte> bytes{std::byte{0x40}};
        auto storage = std::make_shared<std::vector<std::byte>>(bytes);
        connection.process_inbound_datagram(std::shared_ptr<std::vector<std::byte>>{},
                                            /*begin=*/0, /*end=*/0, QuicCoreTimePoint{},
                                            /*path_id=*/0, QuicEcnCodepoint::unavailable,
                                            std::nullopt, /*replay_trigger=*/false,
                                            /*count_inbound_bytes=*/true,
                                            /*allow_in_place_receive_decode=*/true);
        connection.process_inbound_datagram(storage, /*begin=*/1, /*end=*/0, QuicCoreTimePoint{},
                                            /*path_id=*/0, QuicEcnCodepoint::unavailable,
                                            std::nullopt,
                                            /*replay_trigger=*/false,
                                            /*count_inbound_bytes=*/true,
                                            /*allow_in_place_receive_decode=*/true);
        connection.process_inbound_datagram(storage, /*begin=*/0, /*end=*/storage->size() + 1,
                                            QuicCoreTimePoint{}, /*path_id=*/0,
                                            QuicEcnCodepoint::unavailable, std::nullopt,
                                            /*replay_trigger=*/false,
                                            /*count_inbound_bytes=*/true,
                                            /*allow_in_place_receive_decode=*/true);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.outstanding_probe_packet_number = 31;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());

        path.mtu.outstanding_probe_packet_number.reset();
        path.mtu.viable = false;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());

        path.mtu.viable = true;
        path.mtu.validated_datagram_size = path.mtu.probe_ceiling;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.probe_ceiling = 1460;

        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).value_or(0) ==
                                      kPmtudIPv6EthernetUdpPayloadSize);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1472;
        path.mtu.search_low = 1472;
        path.mtu.probe_ceiling = 4096;

        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).value_or(0) > 1472);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        remember_pmtud_failed_probe_size(path.mtu, next_probe_size_between(1200, 1600));

        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.next_pmtu_probe_size(path).value_or(0) < 1600);

        while (connection.next_pmtu_probe_size(path).has_value()) {
            remember_pmtud_failed_probe_size(path.mtu,
                                             connection.next_pmtu_probe_size(path).value_or(0));
        }
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());

        path.mtu.next_probe_time = QuicCoreTimePoint{};
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);

        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        path.mtu.next_probe_time = QuicCoreTimePoint{};

        COQUIC_CONNECTION_HOOK_RECORD(connection.pmtud_deadline() == QuicCoreTimePoint{});
        connection.on_timeout(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", std::nullopt);

        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        while (connection.next_pmtu_probe_size(path).has_value()) {
            remember_pmtud_failed_probe_size(path.mtu,
                                             connection.next_pmtu_probe_size(path).value_or(0));
        }

        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.send_crypto.append(
            std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}});
        auto stream_state = connection.get_or_open_send_stream(0);
        COQUIC_CONNECTION_HOOK_RECORD(stream_state.has_value());
        if (stream_state.has_value()) {
            auto &stream = *stream_state.value();
            stream.send_buffer.append(std::vector<std::byte>{std::byte{0x61}, std::byte{0x62}});
            stream.flow_control.highest_sent = 2;
            stream.flow_control.peer_max_stream_data = 8;
        }
        connection.handshake_done_state_ = StreamControlFrameState::sent;
        connection.connection_flow_control_.pending_max_data_frame =
            MaxDataFrame{.maximum_data = 4096};
        connection.connection_flow_control_.max_data_state = StreamControlFrameState::sent;
        const auto stream_id = stream_state.has_value() ? stream_state.value()->stream_id : 0;
        connection.track_sent_packet(
            connection.application_space_,
            SentPacketRecord{
                .packet_number = 77,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = true,
                .in_flight = true,
                .declared_lost = false,
                .has_handshake_done = true,
                .crypto_ranges = {ByteRange{
                    .offset = 0,
                    .bytes = SharedBytes{std::byte{0x01}, std::byte{0x02}},
                }},
                .reset_stream_frames = {ResetStreamFrame{
                    .stream_id = stream_id,
                    .application_protocol_error_code = 0,
                    .final_size = 2,
                }},
                .stop_sending_frames = {StopSendingFrame{
                    .stream_id = stream_id,
                    .application_protocol_error_code = 0,
                }},
                .max_data_frame = MaxDataFrame{.maximum_data = 4096},
                .max_stream_data_frames = {MaxStreamDataFrame{
                    .stream_id = stream_id,
                    .maximum_stream_data = 8,
                }},
                .max_streams_frames = {MaxStreamsFrame{
                    .stream_type = StreamLimitType::bidirectional,
                    .maximum_streams = 4,
                }},
                .data_blocked_frame = DataBlockedFrame{.maximum_data = 2048},
                .stream_data_blocked_frames = {StreamDataBlockedFrame{
                    .stream_id = stream_id,
                    .maximum_stream_data = 2,
                }},
                .stream_fragments = {StreamFrameSendFragment{
                    .stream_id = stream_id,
                    .offset = 0,
                    .bytes = SharedBytes{std::byte{0x61}, std::byte{0x62}},
                    .fin = false,
                    .consumes_flow_control = true,
                }},
                .bytes_in_flight = 1500,
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 1500,
            });
        const auto handle = connection.application_space_.recovery.handle_for_packet_number(77);
        COQUIC_CONNECTION_HOOK_RECORD(handle.has_value());
        if (handle.has_value()) {
            const auto packet =
                connection.retire_acked_packet(connection.application_space_, *handle);
            COQUIC_CONNECTION_HOOK_RECORD(packet.has_value());
            if (packet.has_value()) {
                COQUIC_CONNECTION_HOOK_RECORD(!packet->in_flight);
                COQUIC_CONNECTION_HOOK_RECORD(packet->bytes_in_flight == 0);
                COQUIC_CONNECTION_HOOK_RECORD(packet->crypto_ranges.empty());
                COQUIC_CONNECTION_HOOK_RECORD(packet->reset_stream_frames.empty());
                COQUIC_CONNECTION_HOOK_RECORD(packet->stop_sending_frames.empty());
                COQUIC_CONNECTION_HOOK_RECORD(!packet->max_data_frame.has_value());
                COQUIC_CONNECTION_HOOK_RECORD(packet->max_stream_data_frames.empty());
                COQUIC_CONNECTION_HOOK_RECORD(packet->max_streams_frames.empty());
                COQUIC_CONNECTION_HOOK_RECORD(!packet->data_blocked_frame.has_value());
                COQUIC_CONNECTION_HOOK_RECORD(packet->stream_data_blocked_frames.empty());
                COQUIC_CONNECTION_HOOK_RECORD(packet->stream_fragments.empty());
                COQUIC_CONNECTION_HOOK_RECORD(!packet->has_handshake_done);
            }
        }
    }

    {
#if defined(COQUIC_WASM_NO_FILESYSTEM)
        COQUIC_CONNECTION_HOOK_RECORD(true);
#else
        TlsAdapter client(TlsAdapterConfig{
            .role = EndpointRole::client,
            .verify_peer = false,
            .server_name = "localhost",
            .local_transport_parameters = {std::byte{0x0f}, std::byte{0x00}},
        });
        TlsAdapter server(TlsAdapterConfig{
            .role = EndpointRole::server,
            .verify_peer = false,
            .server_name = "localhost",
            .identity =
                TlsIdentity{
                    .certificate_pem = read_text_file_for_connection_coverage(
                        "tests/fixtures/quic-server-cert.pem"),
                    .private_key_pem = read_text_file_for_connection_coverage(
                        "tests/fixtures/quic-server-key.pem"),
                },
            .local_transport_parameters = {std::byte{0x0f}, std::byte{0x00}},
        });
        COQUIC_CONNECTION_HOOK_RECORD(drive_tls_handshake_for_connection_coverage(client, server));
        static_cast<void>(client.take_available_secrets());

        QuicConnection connection(make_client_core_config_for_connection_coverage());
        connection.initial_packet_space_discarded_ = true;
        connection.handshake_packet_space_discarded_ = true;
        connection.tls_.emplace(std::move(client));
        constexpr std::array<std::uint8_t, 32> secret{};
        COQUIC_CONNECTION_HOOK_RECORD(TlsAdapterTestPeer::call_on_set_secret(
                                          *connection.tls_, ssl_encryption_initial,
                                          EndpointRole::server, secret.data(), secret.size()) == 1);
        COQUIC_CONNECTION_HOOK_RECORD(TlsAdapterTestPeer::call_on_set_secret(
                                          *connection.tls_, ssl_encryption_handshake,
                                          EndpointRole::server, secret.data(), secret.size()) == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.initial_space_.read_secret.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.handshake_space_.read_secret.has_value());

        connection.install_available_secrets();

        COQUIC_CONNECTION_HOOK_RECORD(!connection.initial_space_.read_secret.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.handshake_space_.read_secret.has_value());
#endif
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 7,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 2048,
        };

        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit() == 2048);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.last_drained_is_pmtu_probe());

        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit(false) ==
                                      kMinimumInitialDatagramSize);
        connection.config_.role = EndpointRole::server;
        path.validated = false;
        path.anti_amplification_received_bytes = 400;
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit() ==
                                      kMinimumInitialDatagramSize);
        connection.config_.role = EndpointRole::client;
        path.validated = true;
        path.anti_amplification_received_bytes = 0;

        connection.note_pmtu_probe_sent(0, 7, 2048);
        const auto ack_time = QuicCoreTimePoint{} + std::chrono::milliseconds(15);
        connection.note_pmtu_probe_acked(
            SentPacketRecord{
                .packet_number = 7,
                .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(10),
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 2048,
            },
            ack_time);

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 2048);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.search_low == 2048);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      ack_time + std::chrono::seconds(1));
        COQUIC_CONNECTION_HOOK_RECORD(connection.outbound_datagram_size_limit() == 2048);

        connection.note_pmtu_probe_sent(0, 8, 0);
        connection.note_pmtu_probe_acked(
            SentPacketRecord{
                .packet_number = 8,
                .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(20),
                .path_id = 0,
                .is_pmtu_probe = true,
            },
            ack_time + std::chrono::milliseconds(5));
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());

        connection.note_pmtu_probe_acked(
            SentPacketRecord{
                .packet_number = 9,
                .path_id = 0,
                .is_pmtu_probe = true,
            },
            ack_time);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());

        connection.note_pmtu_probe_acked(
            SentPacketRecord{
                .packet_number = 10,
                .path_id = 0,
            },
            ack_time);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 2048);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x21}, std::byte{0x22}, std::byte{0x23}, std::byte{0x24},
                       std::byte{0x25}, std::byte{0x26}, std::byte{0x27}, std::byte{0x28}};
        reduce_remaining_congestion_window(connection, 20);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.recovery.tracked_packet_count() == 1);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x61}, std::byte{0x01}},
            .initial_destination_connection_id = {std::byte{0x91}, std::byte{0x01}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.peer_source_connection_id_ = {std::byte{0xa9}};
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = connection.peer_source_connection_id_,
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.last_validated_path_id_ = 0;
        connection.current_send_path_id_ = 0;
        auto &send_path = connection.ensure_path_state(0);
        send_path.validated = true;
        send_path.is_current_send_path = true;
        connection.original_version_ = kQuicVersion1;
        connection.current_version_ = kQuicVersion2;
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x57});
        connection.handshake_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x67});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_duplicate_initial_congestion_blocked);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
    }

    {
        QuicConnection connection(QuicCoreConfig{
            .role = EndpointRole::server,
            .source_connection_id = {std::byte{0x61}, std::byte{0x02}},
            .initial_destination_connection_id = {std::byte{0x91}, std::byte{0x02}},
            .verify_peer = false,
            .server_name = "localhost",
        });
        connection.started_ = true;
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = true;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.peer_source_connection_id_ = {std::byte{0xaa}};
        connection.peer_transport_parameters_ = TransportParameters{
            .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
            .max_ack_delay = connection.config_.transport.max_ack_delay,
            .initial_source_connection_id = connection.peer_source_connection_id_,
        };
        connection.peer_transport_parameters_validated_ = true;
        connection.last_validated_path_id_ = 0;
        connection.current_send_path_id_ = 0;
        auto &send_path = connection.ensure_path_state(0);
        send_path.validated = true;
        send_path.is_current_send_path = true;
        connection.handshake_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x68});
        connection.application_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x78});
        connection.handshake_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_send_congestion_blocked);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.handshake_space_.next_send_packet_number == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34},
                       std::byte{0x35}, std::byte{0x36}, std::byte{0x37}, std::byte{0x38}};
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x41}, std::byte{0x42}, std::byte{0x43}, std::byte{0x44},
                       std::byte{0x45}, std::byte{0x46}, std::byte{0x47}, std::byte{0x48}};
        reduce_remaining_congestion_window(connection, 20);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.challenge_pending);
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.recovery.tracked_packet_count() == 1);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x51}, std::byte{0x52}, std::byte{0x53}, std::byte{0x54},
                       std::byte{0x55}, std::byte{0x56}, std::byte{0x57}, std::byte{0x58}};
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x61}, std::byte{0x62}, std::byte{0x63}, std::byte{0x64},
                       std::byte{0x65}, std::byte{0x66}, std::byte{0x67}, std::byte{0x68}};
        reduce_remaining_congestion_window(connection, 20);
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_packet_number_exhausted);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.challenge_pending);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        auto &path = connection.ensure_path_state(0);
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x71}, std::byte{0x72}, std::byte{0x73}, std::byte{0x74},
                       std::byte{0x75}, std::byte{0x76}, std::byte{0x77}, std::byte{0x78}};

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!path.challenge_pending);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_application_candidate_estimate_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 81,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .force_ack = true,
            .path_id = 0,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_application_candidate_estimate_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1500));
        reduce_remaining_congestion_window(connection, 1250);
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_no_ack_control_candidate_estimate_failure);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        reduce_remaining_congestion_window(connection, 1250);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        reduce_remaining_congestion_window(connection, 1250);
        const ScopedConnectionDrainForcedSizeTestHook hook(1240);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        reduce_remaining_congestion_window(connection, 1250);
        const ScopedConnectionDrainForcedSizeTestHook hook(1190);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        reduce_remaining_congestion_window(connection, 1250);
        const ScopedConnectionDrainEmptyNoAckControlEstimateTestHook hook;

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        auto &path = queue_path_validation_frames(connection, 0x91, 0xa1);
        const ScopedConnectionDrainTestHook congestion_hook(
            &ConnectionDrainTestHooks::force_application_send_congestion_blocked);
        const ScopedConnectionDrainTestHook packet_number_hook(
            &ConnectionDrainTestHooks::force_application_packet_number_exhausted);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.challenge_pending);
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.received_packets.has_ack_to_send());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 82,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 1500,
        };
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.last_drained_is_pmtu_probe());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 83,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 1500,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 86,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 1500,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_probe_padding_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 87,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .force_ack = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 1500,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_probe_padding_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        set_outbound_datagram_limit(connection, 8);
        record_application_ack_ranges(connection, 1);
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 88,
            .ack_eliciting = true,
            .in_flight = true,
            .stream_fragments = {StreamFrameSendFragment{
                .stream_id = 0,
                .offset = 0,
                .bytes = SharedBytes(std::vector<std::byte>(100, std::byte{0x5a})),
                .fin = false,
                .consumes_flow_control = false,
            }},
            .force_ack = true,
            .path_id = 0,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_probe_no_ack_retry_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 84,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = 1500,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 2);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook serialization_hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        connection.status_ = HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.application_space_.read_secret.reset();
        connection.application_space_.write_secret.reset();
        connection.zero_rtt_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x71});
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        connection.application_space_.pending_probe_packet = SentPacketRecord{
            .packet_number = 85,
            .ack_eliciting = true,
            .in_flight = true,
            .stream_fragments = {StreamFrameSendFragment{
                .stream_id = 0,
                .offset = 0,
                .bytes = SharedBytes(std::vector<std::byte>(1400, std::byte{0x5a})),
                .fin = false,
                .consumes_flow_control = false,
            }},
            .force_ack = true,
            .path_id = 0,
        };
        const ScopedConnectionDrainCountdownTestHook hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_byte(connection));
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {1});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {1500});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        record_application_ack_ranges(connection, 1);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook no_ack_hook(
            &ConnectionDrainTestHooks::force_application_no_ack_candidate_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.peer_source_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x37});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook trim_hook(
            &ConnectionDrainTestHooks::force_application_trim_candidate_empty_payload_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        set_outbound_datagram_limit(connection, 8);
        record_application_ack_ranges(connection, 1);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 100));
        const ScopedConnectionDrainCountdownTestHook trim_hook(
            &ConnectionDrainTestHooks::force_application_trim_candidate_empty_payload_countdown, 0);
        const ScopedConnectionDrainCountdownTestHook no_ack_retry_hook(
            &ConnectionDrainTestHooks::force_application_no_ack_retry_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x33});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {1500});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x34});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        connection.connection_flow_control_.pending_max_data_frame =
            MaxDataFrame{.maximum_data = 4096};
        connection.connection_flow_control_.max_data_state = StreamControlFrameState::pending;

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1, true));
        auto *stream = connection.find_stream_state(0);
        COQUIC_CONNECTION_HOOK_RECORD(stream != nullptr);
        if (stream != nullptr) {
            stream->send_buffer.acknowledge(0, 1);
            stream->send_buffer.mark_unsent(0, 1);
            stream->flow_control.highest_sent = 1;
        }
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {1400});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.config_.max_outbound_datagram_size = 8;
        if (connection.peer_transport_parameters_.has_value()) {
            connection.peer_transport_parameters_->max_udp_payload_size = 8;
        }
        constexpr auto large_client_bidi_stream_id = kMaxQuicVarInt - 3u;
        auto stream =
            make_implicit_stream_state(large_client_bidi_stream_id, connection.config_.role);
        stream.send_final_size = kMaxQuicVarInt;
        stream.send_fin_state = StreamSendFinState::pending;
        stream.send_flow_control_committed = kMaxQuicVarInt;
        stream.flow_control.peer_max_stream_data = kMaxQuicVarInt;
        connection.connection_flow_control_.peer_max_data = kMaxQuicVarInt;
        connection.streams_.emplace(stream.stream_id, std::move(stream));

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400, true));
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {10});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook serialization_hook(
            &ConnectionDrainTestHooks::force_candidate_datagram_serialization_failure_countdown, 1);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x35});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook no_ack_hook(
            &ConnectionDrainTestHooks::force_application_no_ack_candidate_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.initial_space_.write_secret =
            make_test_traffic_secret(CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x36});
        connection.initial_space_.send_crypto.append(std::vector<std::byte>{std::byte{0x01}});
        record_application_ack_ranges(connection, 700);
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook no_ack_retry_hook(
            &ConnectionDrainTestHooks::force_application_no_ack_retry_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.initial_space_.next_send_packet_number == 1);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        COQUIC_CONNECTION_HOOK_RECORD(queue_application_stream_bytes(connection, 1400));
        connection.config_.max_outbound_datagram_size = 48;
        if (connection.peer_transport_parameters_.has_value()) {
            connection.peer_transport_parameters_->max_udp_payload_size = 48;
        }
        const ScopedConnectionDrainDatagramGrowthTestHook growth_hook({0}, {1500});
        const ScopedConnectionDrainCountdownTestHook trim_hook(
            &ConnectionDrainTestHooks::force_application_trim_candidate_failure_countdown, 0);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.has_failed());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        connection.note_pmtu_probe_sent(0, 19, 1433);
        connection.note_pmtu_probe_lost(
            SentPacketRecord{
                .packet_number = 19,
                .sent_time = QuicCoreTimePoint{},
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 1433,
            },
            QuicCoreTimePoint{} + std::chrono::milliseconds(50));

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1432);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.failed_probe_sizes.size() == 1);

        connection.note_pmtu_probe_acked(
            SentPacketRecord{
                .packet_number = 19,
                .sent_time = QuicCoreTimePoint{} + std::chrono::milliseconds(10),
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 1433,
            },
            QuicCoreTimePoint{} + std::chrono::milliseconds(20));

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 1433);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.search_low == 1433);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1433);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.failed_probe_sizes.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1400;
        path.mtu.search_low = 1400;
        path.mtu.probe_ceiling = 1600;
        connection.note_pmtu_probe_sent(0, 21, 1300);
        connection.note_pmtu_probe_lost(
            SentPacketRecord{
                .packet_number = 21,
                .sent_time = QuicCoreTimePoint{},
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 1300,
            },
            QuicCoreTimePoint{} + std::chrono::milliseconds(50));

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 1400);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1600);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.failed_probe_sizes.empty());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1400;
        path.mtu.search_low = 1400;
        path.mtu.probe_ceiling = 1400;

        connection.note_pmtu_probe_lost(
            SentPacketRecord{
                .packet_number = 22,
                .sent_time = QuicCoreTimePoint{},
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 1500,
            },
            QuicCoreTimePoint{} + std::chrono::milliseconds(50));

        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 2048;
        path.mtu.search_low = 2048;
        path.mtu.probe_ceiling = 4096;
        connection.note_pmtu_probe_sent(0, 9, 3072);
        connection.note_pmtu_probe_lost(
            SentPacketRecord{
                .packet_number = 9,
                .sent_time = QuicCoreTimePoint{},
                .path_id = 0,
                .is_pmtu_probe = true,
                .pmtu_probe_size = 3072,
            },
            QuicCoreTimePoint{} + std::chrono::milliseconds(50));

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 2048);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 3071);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(150));
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());

        connection.note_outbound_datagram_bytes(1200, /*path_id=*/0, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());

        const std::array<std::byte, 1> payload{std::byte{0x41}};
        COQUIC_CONNECTION_HOOK_RECORD(connection.queue_stream_send(0, payload, false).value());
        connection.note_outbound_datagram_bytes(1200, /*path_id=*/0, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(10));

        connection.note_outbound_datagram_bytes(0, /*path_id=*/0, QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(10));
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 4096;
        connection.application_space_.recovery.rtt_state().latest_rtt =
            std::chrono::milliseconds(8);
        connection.application_space_.recovery.rtt_state().smoothed_rtt =
            std::chrono::milliseconds(8);
        connection.note_pmtu_probe_sent(0, 13, 2048);
        connection.track_sent_packet(connection.application_space_,
                                     SentPacketRecord{
                                         .packet_number = 13,
                                         .sent_time = QuicCoreTimePoint{},
                                         .ack_eliciting = true,
                                         .in_flight = false,
                                         .has_ping = true,
                                         .path_id = 0,
                                         .is_pmtu_probe = true,
                                         .pmtu_probe_size = 2048,
                                     });

        COQUIC_CONNECTION_HOOK_RECORD(connection.loss_deadline().has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.loss_deadline() ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(9));

        connection.on_timeout(QuicCoreTimePoint{} + std::chrono::milliseconds(9));

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 2047);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(109));
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 2048;
        path.mtu.search_low = 2048;
        path.mtu.probe_ceiling = 4096;
        connection.note_pmtu_probe_sent(0, 11, 3072);

        connection.apply_path_mtu_update(0, 1300);

        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 1300);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1300);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.search_low == 1300);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_size.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.outstanding_probe_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());

        connection.apply_path_mtu_update(0, 1199);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size == 1300);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1199);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.viable);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.enabled);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_sendable_datagram(QuicCoreTimePoint{}));

        auto &previous_path = connection.ensure_path_state(1);
        previous_path.validated = true;
        previous_path.mtu.viable = true;
        path.is_current_send_path = true;
        connection.previous_path_id_ = 1;
        connection.current_send_path_id_ = 0;
        connection.pending_transport_close_.reset();
        connection.closing_close_packet_pending_ = false;
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 1);
        COQUIC_CONNECTION_HOOK_RECORD(previous_path.is_current_send_path);

        path.mtu.probe_ceiling = 1000;
        connection.apply_path_mtu_update(0, 1300);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1300);

        path.mtu.failed_probe_sizes = {1299, 1301};
        path.mtu.enabled = true;
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 4096;
        connection.apply_path_mtu_update(0, 1400);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.probe_ceiling == 1400);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.failed_probe_sizes.size() == 2);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_.reset();
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.viable);

        connection = make_connected_client_connection();
        auto &same_path = connection.ensure_path_state(0);
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_ = 0;
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!same_path.mtu.viable);

        connection = make_connected_client_connection();
        auto &current_path = connection.ensure_path_state(0);
        auto &missing_previous_path = connection.ensure_path_state(2);
        static_cast<void>(missing_previous_path);
        connection.paths_.erase(2);
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_ = 2;
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!current_path.mtu.viable);

        connection = make_connected_client_connection();
        auto &nonviable_path = connection.ensure_path_state(0);
        auto &nonviable_previous = connection.ensure_path_state(3);
        nonviable_previous.validated = true;
        nonviable_previous.mtu.viable = false;
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_ = 3;
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!nonviable_path.mtu.viable);

        connection = make_connected_client_connection();
        auto &unvalidated_path = connection.ensure_path_state(0);
        auto &unvalidated_previous = connection.ensure_path_state(4);
        unvalidated_previous.validated = false;
        unvalidated_previous.mtu.viable = true;
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_ = 4;
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 0);
        COQUIC_CONNECTION_HOOK_RECORD(!unvalidated_path.mtu.viable);

        connection = make_connected_client_connection();
        auto &validated_previous = connection.ensure_path_state(5);
        validated_previous.validated = true;
        validated_previous.mtu.viable = true;
        connection.current_send_path_id_ = 0;
        connection.previous_path_id_ = 5;
        connection.paths_.erase(0);
        connection.apply_path_mtu_update(0, 1100);
        COQUIC_CONNECTION_HOOK_RECORD(connection.current_send_path_id_ == 5);
        COQUIC_CONNECTION_HOOK_RECORD(validated_previous.is_current_send_path);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.paths_.at(0).mtu.viable);
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.viable = false;
        connection.current_send_path_id_ = 0;
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.drain_outbound_datagram(QuicCoreTimePoint{}).empty());
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        auto &nonviable_pending_path = connection.ensure_path_state(8);
        path.mtu.viable = false;
        nonviable_pending_path.pending_response =
            std::array{std::byte{0x41}, std::byte{0x42}, std::byte{0x43}, std::byte{0x44},
                       std::byte{0x45}, std::byte{0x46}, std::byte{0x47}, std::byte{0x48}};
        nonviable_pending_path.mtu.viable = false;
        connection.current_send_path_id_ = 0;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_application_send());
        path.mtu.viable = true;
        COQUIC_CONNECTION_HOOK_RECORD(!connection.has_pending_application_send());
        connection.drain_outbound_datagram(QuicCoreTimePoint{});
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
        auto connection = make_connected_client_connection();
        connection.current_send_path_id_ = 99;
        auto &nonviable_response_path = connection.ensure_path_state(8);
        nonviable_response_path.pending_response =
            std::array{std::byte{0x81}, std::byte{0x82}, std::byte{0x83}, std::byte{0x84},
                       std::byte{0x85}, std::byte{0x86}, std::byte{0x87}, std::byte{0x88}};
        nonviable_response_path.mtu.viable = false;
        connection.drain_outbound_datagram(QuicCoreTimePoint{});
    }

    {
        const ScopedEnvVarForTests trace("COQUIC_PACKET_TRACE", "1");
        const ScopedEnvVarForTests filter("COQUIC_PACKET_TRACE_SCID", "");
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        connection.config_.transport.pmtud_enabled = false;
        path.mtu.enabled = false;
        path.mtu.next_probe_time = std::nullopt;
        path.pending_response.reset();
        path.challenge_pending = false;
        path.mtu.viable = true;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 0;
        connection.anti_amplification_sent_bytes_ = 0;
        connection.current_send_path_id_ = 0;
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.drain_outbound_datagram(QuicCoreTimePoint{}).empty());
    }

    {
        auto connection = make_connected_client_connection();
        connection.config_.max_outbound_datagram_size = kMaximumDatagramSize;
        if (connection.peer_transport_parameters_.has_value()) {
            connection.peer_transport_parameters_->max_udp_payload_size = kMaximumDatagramSize;
        }
        COQUIC_CONNECTION_HOOK_RECORD(connection
                                          .queue_application_close(LocalApplicationCloseCommand{
                                              .application_error_code = 77,
                                          })
                                          .has_value());
        const ScopedConnectionDrainDatagramGrowthTestHook hook({0}, {1500});

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(!connection.pending_application_close_.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(connection.local_application_close_sent_);
        COQUIC_CONNECTION_HOOK_RECORD(connection.close_mode_ == QuicConnectionCloseMode::closing);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.viable = false;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
        path.mtu.viable = true;
        path.mtu.outstanding_probe_packet_number = 40;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.outstanding_probe_packet_number == 40);

        path.mtu.outstanding_probe_packet_number.reset();
        path.mtu.next_probe_time = QuicCoreTimePoint{} + std::chrono::milliseconds(5);
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time.has_value());

        path.mtu.next_probe_time.reset();
        path.mtu.validated_datagram_size = path.mtu.probe_ceiling;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.next_probe_time.has_value());

        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        connection.config_.role = EndpointRole::server;
        path.validated = false;
        path.anti_amplification_received_bytes = 400;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.next_probe_time ==
                                      QuicCoreTimePoint{} + std::chrono::milliseconds(100));

        connection.config_.role = EndpointRole::client;
        path.validated = true;
        path.anti_amplification_received_bytes = 0;
        connection.paths_.erase(0);
        connection.current_send_path_id_ = 0;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.application_space_.received_packets.record_received(61, /*ack_eliciting=*/true,
                                                                       QuicCoreTimePoint{});
        connection.application_space_.pending_ack_deadline = QuicCoreTimePoint{};
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x51}, std::byte{0x52}, std::byte{0x53}, std::byte{0x54},
                       std::byte{0x55}, std::byte{0x56}, std::byte{0x57}, std::byte{0x58}};
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x61}, std::byte{0x62}, std::byte{0x63}, std::byte{0x64},
                       std::byte{0x65}, std::byte{0x66}, std::byte{0x67}, std::byte{0x68}};
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_packet_number_exhausted);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.challenge_pending);
    }

    {
        auto connection = make_connected_client_connection_for_connection_coverage();
        connection.application_space_.received_packets.record_received(62, /*ack_eliciting=*/true,
                                                                       QuicCoreTimePoint{});
        connection.application_space_.pending_ack_deadline = QuicCoreTimePoint{};
        auto &path = connection.ensure_path_state(0);
        path.pending_response =
            std::array{std::byte{0x59}, std::byte{0x5a}, std::byte{0x5b}, std::byte{0x5c},
                       std::byte{0x5d}, std::byte{0x5e}, std::byte{0x5f}, std::byte{0x60}};
        path.challenge_pending = true;
        path.outstanding_challenge =
            std::array{std::byte{0x69}, std::byte{0x6a}, std::byte{0x6b}, std::byte{0x6c},
                       std::byte{0x6d}, std::byte{0x6e}, std::byte{0x6f}, std::byte{0x70}};
        reduce_remaining_congestion_window(connection, 20);
        const ScopedConnectionDrainTestHook hook(
            &ConnectionDrainTestHooks::force_application_packet_number_exhausted);

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});

        COQUIC_CONNECTION_HOOK_RECORD(datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(path.pending_response.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.challenge_pending);
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.received_packets.has_ack_to_send());
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.mtu.validated_datagram_size = 1200;
        path.mtu.search_low = 1200;
        path.mtu.probe_ceiling = 1600;
        connection.maybe_arm_pmtu_probe(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(
            connection.application_space_.pending_probe_packet.has_value());

        const auto datagram = connection.drain_outbound_datagram(QuicCoreTimePoint{});
        COQUIC_CONNECTION_HOOK_RECORD(!datagram.empty());
        COQUIC_CONNECTION_HOOK_RECORD(connection.last_drained_is_pmtu_probe());
        COQUIC_CONNECTION_HOOK_RECORD(
            !connection.application_space_.pending_probe_packet.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.outstanding_probe_packet_number.has_value());
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.outstanding_probe_size.has_value());
    }

    {
        auto config = make_client_core_config_for_connection_coverage();
        config.max_outbound_datagram_size = 4096;
        config.transport.pmtud_enabled = false;
        QuicConnection connection(config);
        auto &path = connection.ensure_path_state(0);
        COQUIC_CONNECTION_HOOK_RECORD(!path.mtu.enabled);
        COQUIC_CONNECTION_HOOK_RECORD(path.mtu.validated_datagram_size ==
                                      connection.outbound_datagram_size_ceiling_for_path(0));
        COQUIC_CONNECTION_HOOK_RECORD(connection.congestion_controller_.minimum_window() ==
                                      2 * config.max_outbound_datagram_size);
        COQUIC_CONNECTION_HOOK_RECORD(!connection.next_pmtu_probe_size(path).has_value());
    }

#undef COQUIC_CONNECTION_HOOK_RECORD
#undef COQUIC_STRINGIFY
#undef COQUIC_STRINGIFY_DETAIL
    return ok;
}

void connection_set_force_missing_packet_metadata_for_tests(bool enabled) {
    connection_drain_test_hooks().force_missing_packet_metadata = enabled;
}

void connection_set_force_quic_core_secret_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_quic_core_secret_rand_failure = enabled;
}

void connection_set_force_prf_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_prf_failure = enabled;
}

void connection_set_force_issued_connection_id_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_issued_connection_id_rand_failure = enabled;
}

void connection_set_force_stateless_reset_token_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_stateless_reset_token_rand_failure = enabled;
}

void connection_set_force_path_challenge_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_path_challenge_rand_failure = enabled;
}

void connection_set_force_random_one_in_sixteen_rand_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_random_one_in_sixteen_rand_failure = enabled;
}

void connection_set_force_missing_fallback_packet_length_for_tests(bool enabled) {
    connection_drain_test_hooks().force_missing_fallback_packet_length = enabled;
}

void connection_set_force_appended_fragment_base_datagram_failure_for_tests(bool enabled) {
    connection_drain_test_hooks().force_appended_fragment_base_datagram_failure = enabled;
}

void connection_set_force_application_candidate_estimate_failure_countdown_for_tests(int value) {
    connection_drain_test_hooks().force_application_candidate_estimate_failure_countdown = value;
}

void connection_set_force_candidate_datagram_serialization_failure_countdown_for_tests(int value) {
    connection_drain_test_hooks().force_candidate_datagram_serialization_failure_countdown = value;
}

void connection_set_force_application_candidate_datagram_extra_bytes_for_tests(
    ApplicationCandidateDatagramExtraBytesTestHook hook) {
    connection_drain_test_hooks().force_application_candidate_datagram_extra_bytes_countdown =
        hook.countdown;
    connection_drain_test_hooks().force_application_candidate_datagram_extra_bytes = hook.bytes;
}

void connection_set_force_packet_inspection_missing_plaintext_storage_for_tests(bool enabled) {
    connection_drain_test_hooks().force_packet_inspection_missing_plaintext_storage = enabled;
}

} // namespace coquic::quic::test

#if defined(__clang__)
#pragma clang attribute pop
#endif
