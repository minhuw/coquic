#include "src/quic/core.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#if !defined(COQUIC_WASM_NO_FILESYSTEM)
#include <fstream>
#endif
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <random>
#include <ranges>
#include <sstream>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "src/quic/codec/buffer.h"
#include "src/quic/connection/connection.h"
#include "src/quic/crypto/packet_crypto.h"
#include "src/quic/object_cache.h"
#include "src/quic/transport/streams.h"

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

namespace coquic::quic {

namespace {

constexpr std::size_t kPmtudIPv6EthernetUdpPayloadSize = 1452;
constexpr std::size_t kPmtudIPv4EthernetUdpPayloadSize = 1472;

template <typename... Ts> struct overloaded : Ts... {
    using Ts::operator()...;
};

template <typename... Ts> overloaded(Ts...) -> overloaded<Ts...>;

constexpr auto kStreamStateErrorMap = std::to_array<QuicCoreLocalErrorCode>({
    QuicCoreLocalErrorCode::invalid_stream_id,
    QuicCoreLocalErrorCode::invalid_stream_direction,
    QuicCoreLocalErrorCode::send_side_closed,
    QuicCoreLocalErrorCode::receive_side_closed,
    QuicCoreLocalErrorCode::flow_control_violation,
    QuicCoreLocalErrorCode::final_size_conflict,
});

struct CoreTestFaultState {
    bool force_address_validation_token_tag_failure = false;
    bool force_stateless_reset_token_derivation_failure = false;
    bool force_endpoint_connection_id_rand_failure = false;
    bool force_fill_random_bytes_rand_failure = false;
};

CoreTestFaultState &core_test_fault_state() {
    static auto state = CoreTestFaultState{};
    return state;
}

class ScopedCoreTestFault {
  public:
    explicit ScopedCoreTestFault(bool &target) : target_(target), previous_(target) {
        target_ = true;
    }

    ~ScopedCoreTestFault() {
        target_ = previous_;
    }

    ScopedCoreTestFault(const ScopedCoreTestFault &) = delete;
    ScopedCoreTestFault &operator=(const ScopedCoreTestFault &) = delete;

  private:
    bool &target_;
    bool previous_ = false;
};
constexpr std::size_t kMinimumClientInitialDatagramBytes = 1200;
//= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
// # An endpoint that uses this design MUST either use the same connection ID
// # length for all connections or encode the length of the connection ID such
// # that it can be recovered without state.
constexpr std::size_t kEndpointConnectionIdLength = 8;
constexpr std::size_t kMaxDatagramsPerDrain = 256;
constexpr QuicPathId kDefaultPathId = 0;
constexpr QuicCoreDuration kRetryTokenLifetime{10000000};
constexpr QuicCoreDuration kNewTokenLifetime{86400000000};
constexpr std::size_t kStatelessResetTokenLength = 16;
constexpr std::size_t kMinimumStatelessResetDatagramSize = 21;
constexpr std::size_t kAddressValidationTokenTagLength = 16;
constexpr std::byte kAddressValidationRetryTokenType{0x52};
constexpr std::byte kAddressValidationNewTokenType{0x4e};
constexpr std::uint32_t kGreasedReservedVersion = 0x0a0a0a0a;
constexpr std::byte kServerConnectionIdPrefix{0x53};
constexpr std::size_t kCoreEffectStorageCacheMaxBytes = std::size_t{64} * 1024;
constexpr std::size_t kCoreEffectStorageCacheBucketBytes = std::size_t{4} * 1024;
constexpr std::size_t kCoreEffectStorageCacheSlots = 128;

static_assert(kStreamStateErrorMap.size() ==
              static_cast<std::size_t>(StreamStateErrorCode::final_size_conflict) + 1);

struct CoreProfileCounters {
    std::uint64_t drain_calls = 0;
    std::uint64_t drain_datagrams = 0;
    std::uint64_t drain_send_effects = 0;
    std::uint64_t drain_ns = 0;
    std::uint64_t drain_emplace_send_ns = 0;
    std::uint64_t append_result_calls = 0;
    std::uint64_t append_result_effects = 0;
    std::uint64_t append_result_ns = 0;
};

constexpr bool kCoquicProfileHooksEnabled = COQUIC_PROFILE_HOOKS != 0;

COQUIC_NO_PROFILE bool core_profile_enabled() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return false;
    }

    static const bool enabled = [] {
        const char *value = std::getenv("COQUIC_SEND_PROFILE");
        return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
    }();
    return enabled;
}

COQUIC_NO_PROFILE CoreProfileCounters &core_profile_counters() {
    static CoreProfileCounters counters;
    return counters;
}

COQUIC_NO_PROFILE void print_core_profile() {
    if (!core_profile_enabled()) {
        return;
    }

    const auto &c = core_profile_counters();
    std::cerr << "coquic-core-profile" << " drain_calls=" << c.drain_calls
              << " drain_datagrams=" << c.drain_datagrams
              << " drain_send_effects=" << c.drain_send_effects << " drain_ns=" << c.drain_ns
              << " drain_emplace_send_ns=" << c.drain_emplace_send_ns
              << " append_result_calls=" << c.append_result_calls
              << " append_result_effects=" << c.append_result_effects
              << " append_result_ns=" << c.append_result_ns << '\n';
}

COQUIC_NO_PROFILE void register_core_profile_printer_once() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return;
    }

    static const bool registered = [] {
        std::atexit(print_core_profile);
        return true;
    }();
    static_cast<void>(registered);
}

struct CoreProfileTimer {
    std::uint64_t *target = nullptr;
    QuicCoreTimePoint start{};

    COQUIC_NO_PROFILE explicit CoreProfileTimer(std::uint64_t &counter)
        : target(kCoquicProfileHooksEnabled && core_profile_enabled() ? &counter : nullptr) {
        if (target != nullptr) {
            start = QuicCoreClock::now();
        }
    }

    COQUIC_NO_PROFILE ~CoreProfileTimer() {
        if (target == nullptr) {
            return;
        }
        *target += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(QuicCoreClock::now() - start)
                .count());
    }
};

#if COQUIC_PROFILE_HOOKS
#define COQUIC_CORE_PROFILE_TIMER(name, counter)                                                   \
    CoreProfileTimer name(core_profile_counters().counter)
#else
#define COQUIC_CORE_PROFILE_TIMER(name, counter) static_cast<void>(0)
#endif

#if !defined(COQUIC_DISABLE_CORE_EFFECT_STORAGE_CACHE)
#if defined(__wasm__)
#define COQUIC_DISABLE_CORE_EFFECT_STORAGE_CACHE 1
#else
#define COQUIC_DISABLE_CORE_EFFECT_STORAGE_CACHE 0
#endif
#endif

COQUIC_NO_PROFILE std::size_t core_effect_storage_allocation_bytes(std::size_t byte_count) {
#if COQUIC_DISABLE_CORE_EFFECT_STORAGE_CACHE != 0
    return byte_count;
#else
    if (byte_count == 0 || byte_count > kCoreEffectStorageCacheMaxBytes) {
        return byte_count;
    }

    return ((byte_count + kCoreEffectStorageCacheBucketBytes - 1) /
            kCoreEffectStorageCacheBucketBytes) *
           kCoreEffectStorageCacheBucketBytes;
#endif
}

#if COQUIC_DISABLE_CORE_EFFECT_STORAGE_CACHE == 0
using CoreEffectStorageCache = detail::FixedAlignedBlockCache<kCoreEffectStorageCacheSlots>;

COQUIC_NO_PROFILE CoreEffectStorageCache &core_effect_storage_cache() {
    thread_local CoreEffectStorageCache storage_cache;
    return storage_cache;
}
#endif

COQUIC_NO_PROFILE bool has_send_continuation(std::size_t emitted,
                                             bool last_drained_allows_send_continuation,
                                             const QuicConnection &quic_connection,
                                             QuicCoreTimePoint now) {
    static_cast<void>(quic_connection);
    static_cast<void>(now);
    return emitted == kMaxDatagramsPerDrain && last_drained_allows_send_continuation;
}

COQUIC_NO_PROFILE bool wakeup_not_due(const std::optional<QuicCoreTimePoint> &wakeup,
                                      QuicCoreTimePoint now) {
    return !wakeup.has_value() || *wakeup > now;
}

COQUIC_NO_PROFILE void merge_send_continuation_pending(QuicCoreResult &target,
                                                       const QuicCoreResult &source) {
    target.send_continuation_pending =
        target.send_continuation_pending || source.send_continuation_pending;
}

COQUIC_NO_PROFILE bool has_route_handle(const std::optional<QuicRouteHandle> &route_handle) {
    return route_handle.has_value();
}

template <typename T>
COQUIC_NO_PROFILE const T &optional_ref_or_abort(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return value.value();
}

template <typename Entry> COQUIC_NO_PROFILE bool has_legacy_entry(Entry *entry) {
    return entry != nullptr;
}

template <typename Entry>
COQUIC_NO_PROFILE void
maybe_note_legacy_send_continuation(Entry *entry, const QuicCoreResult &source_result,
                                    QuicCoreTimePoint now, const auto &note) {
    if (has_legacy_entry(entry)) {
        note(*entry, source_result, now);
    }
}

COQUIC_NO_PROFILE void
clamp_result_wakeup_to_now_if_continuation_pending(QuicCoreResult &core_result,
                                                   QuicCoreTimePoint now) {
    if (core_result.send_continuation_pending) {
        core_result.next_wakeup = std::min(core_result.next_wakeup.value_or(now), now);
    }
}

QuicCoreLocalError stream_state_error_to_local_error(const StreamStateError &error) {
    return QuicCoreLocalError{
        .connection = std::nullopt,
        .code = kStreamStateErrorMap[static_cast<std::size_t>(error.code)],
        .stream_id = error.stream_id,
    };
}

QuicCoreLocalError datagram_send_error_to_local_error(const CodecError &error) {
    switch (error.code) {
    case CodecErrorCode::invalid_packet_protection_state:
        return QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::datagram_not_supported,
            .stream_id = std::nullopt,
        };
    case CodecErrorCode::packet_length_mismatch:
        return QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::datagram_too_large,
            .stream_id = std::nullopt,
        };
    default:
        return QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        };
    }
}

COQUIC_NO_PROFILE void emit_send_datagram(QuicCoreResult &result, QuicCoreSendDatagram datagram,
                                          QuicCoreSendDatagramSink *send_sink) {
    if (send_sink == nullptr) {
        result.effects.emplace_back(std::move(datagram));
        return;
    }
    if (!send_sink->on_send_datagram(std::move(datagram))) {
        result.send_sink_failed = true;
    }
}

COQUIC_NO_PROFILE QuicCoreResult drain_connection_effects(
    QuicConnectionHandle connection_handle,
    const std::optional<QuicRouteHandle> &default_route_handle,
    const std::unordered_map<QuicPathId, QuicRouteHandle> &route_handle_by_path_id,
    QuicConnection &quic_connection, QuicCoreTimePoint now, bool continue_paced_burst = false,
    QuicCoreSendDatagramSink *send_sink = nullptr) {
    register_core_profile_printer_once();
    if (core_profile_enabled()) {
        ++core_profile_counters().drain_calls;
    }
    COQUIC_CORE_PROFILE_TIMER(core_drain_timer, drain_ns);
    QuicCoreResult drain_result;

    // Drain send-side datagrams first, because each datagram can change pacing state and route
    // metadata. After that, collect every queued application/control effect so callers can make one
    // routing/removal decision from a complete connection snapshot.
    std::size_t emitted = 0;
    bool last_drained_allows_send_continuation = false;
    if (send_sink != nullptr) {
        class FastBulkCoreSink final : public QuicConnectionDrainedDatagramSink {
          public:
            FastBulkCoreSink(QuicCoreResult &result, QuicCoreSendDatagramSink &sink,
                             QuicConnectionHandle connection,
                             const std::optional<QuicRouteHandle> &default_route,
                             const std::unordered_map<QuicPathId, QuicRouteHandle> &routes)
                : result_(result), sink_(sink), connection_(connection),
                  default_route_(default_route), routes_(routes) {
            }

            bool on_connection_datagram(QuicConnectionDrainedDatagram datagram) override {
                const auto route_it =
                    datagram.path_id.has_value() ? routes_.find(*datagram.path_id) : routes_.end();
                if (route_it != routes_.end()) {
                    if (!sink_.on_send_datagram_payload(
                            connection_, route_it->second, std::move(datagram.bytes), datagram.ecn,
                            datagram.is_pmtu_probe, datagram.packet_inspection_datagram_id)) {
                        result_.send_sink_failed = true;
                        return false;
                    }
                    return true;
                }
                if (default_route_.has_value()) {
                    if (!sink_.on_send_datagram_payload(
                            connection_, *default_route_, std::move(datagram.bytes), datagram.ecn,
                            datagram.is_pmtu_probe, datagram.packet_inspection_datagram_id)) {
                        result_.send_sink_failed = true;
                        return false;
                    }
                    return true;
                }
                auto send_datagram = QuicCoreSendDatagram{
                    .connection = connection_,
                    .route_handle = std::nullopt,
                    .bytes = std::move(datagram.bytes),
                    .ecn = datagram.ecn,
                    .is_pmtu_probe = datagram.is_pmtu_probe,
                    .packet_inspection_datagram_id = datagram.packet_inspection_datagram_id,
                };
                if (!sink_.on_send_datagram(std::move(send_datagram))) {
                    result_.send_sink_failed = true;
                    return false;
                }
                return true;
            }

          private:
            QuicCoreResult &result_;
            QuicCoreSendDatagramSink &sink_;
            QuicConnectionHandle connection_ = 0;
            const std::optional<QuicRouteHandle> &default_route_;
            const std::unordered_map<QuicPathId, QuicRouteHandle> &routes_;
        };

        FastBulkCoreSink fast_sink{drain_result, *send_sink, connection_handle,
                                   default_route_handle, route_handle_by_path_id};
        emitted = quic_connection.drain_fast_bulk_stream_datagrams(
            now, continue_paced_burst, kMaxDatagramsPerDrain, fast_sink);
        if (emitted != 0) {
            last_drained_allows_send_continuation =
                quic_connection.last_drained_allows_send_continuation();
            continue_paced_burst = last_drained_allows_send_continuation;
            if (core_profile_enabled()) {
                core_profile_counters().drain_send_effects += emitted;
            }
        }
    }
    for (; emitted < kMaxDatagramsPerDrain; ++emitted) {
        if (drain_result.send_sink_failed) {
            break;
        }
        if (!continue_paced_burst &&
            !quic_connection.has_sendable_datagram(now, continue_paced_burst)) {
            break;
        }
        auto datagram = quic_connection.drain_outbound_datagram(now, continue_paced_burst);
        if (datagram.empty()) {
            break;
        }
        last_drained_allows_send_continuation =
            quic_connection.last_drained_allows_send_continuation();
        continue_paced_burst = last_drained_allows_send_continuation;
        if (emitted == 0 && last_drained_allows_send_continuation &&
            quic_connection.has_sendable_datagram(now, /*continue_paced_burst=*/true)) {
            drain_result.effects.reserve(kMaxDatagramsPerDrain);
        }

        const auto drained_path_id = quic_connection.last_drained_path_id();
        const auto route_it = drained_path_id.has_value()
                                  ? route_handle_by_path_id.find(*drained_path_id)
                                  : route_handle_by_path_id.end();
        auto send_datagram = QuicCoreSendDatagram{
            .connection = connection_handle,
            .route_handle = route_it != route_handle_by_path_id.end()
                                ? std::optional<QuicRouteHandle>(route_it->second)
                                : default_route_handle,
            .bytes = std::move(datagram),
            .ecn = quic_connection.last_drained_ecn_codepoint(),
            .is_pmtu_probe = quic_connection.last_drained_is_pmtu_probe(),
            .packet_inspection_datagram_id =
                quic_connection.last_drained_packet_inspection_datagram_id(),
        };
        {
            COQUIC_CORE_PROFILE_TIMER(core_emplace_timer, drain_emplace_send_ns);
            emit_send_datagram(drain_result, std::move(send_datagram), send_sink);
            if (drain_result.send_sink_failed) {
                ++emitted;
                break;
            }
        }
        if (core_profile_enabled()) {
            ++core_profile_counters().drain_send_effects;
        }
    }
    if (core_profile_enabled()) {
        core_profile_counters().drain_datagrams += emitted;
    }
    if (has_send_continuation(emitted, last_drained_allows_send_continuation, quic_connection,
                              now)) {
        drain_result.next_wakeup = now;
        drain_result.send_continuation_pending = true;
    }

    while (auto received = quic_connection.take_received_stream_data()) {
        received->connection = connection_handle;
        drain_result.effects.emplace_back(std::move(*received));
    }
    while (auto received = quic_connection.take_received_datagram_data()) {
        received->connection = connection_handle;
        drain_result.effects.emplace_back(std::move(*received));
    }
    while (const auto reset = quic_connection.take_peer_reset_stream()) {
        drain_result.effects.emplace_back(QuicCorePeerResetStream{
            .connection = connection_handle,
            .stream_id = reset->stream_id,
            .application_error_code = reset->application_error_code,
            .final_size = reset->final_size,
        });
    }
    while (const auto stop = quic_connection.take_peer_stop_sending()) {
        drain_result.effects.emplace_back(QuicCorePeerStopSending{
            .connection = connection_handle,
            .stream_id = stop->stream_id,
            .application_error_code = stop->application_error_code,
        });
    }
    while (const auto event = quic_connection.take_state_change()) {
        drain_result.effects.emplace_back(QuicCoreStateEvent{
            .connection = connection_handle,
            .change = *event,
        });
    }
    while (const auto preferred = quic_connection.take_peer_preferred_address_available()) {
        drain_result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
            .connection = connection_handle,
            .preferred_address = preferred->preferred_address,
        });
    }
    while (const auto state = quic_connection.take_resumption_state_available()) {
        drain_result.effects.emplace_back(QuicCoreResumptionStateAvailable{
            .connection = connection_handle,
            .state = state->state,
        });
    }
    while (const auto status = quic_connection.take_zero_rtt_status_event()) {
        drain_result.effects.emplace_back(QuicCoreZeroRttStatusEvent{
            .connection = connection_handle,
            .status = status->status,
        });
    }
    while (auto new_token = quic_connection.take_new_token()) {
        drain_result.effects.emplace_back(QuicCoreNewTokenAvailable{
            .connection = connection_handle,
            .token = std::move(*new_token),
        });
    }
    while (auto inspection = quic_connection.take_packet_inspection()) {
        inspection->connection = connection_handle;
        drain_result.effects.emplace_back(std::move(*inspection));
    }
    if (const auto terminal = quic_connection.take_terminal_state()) {
        if (*terminal == QuicConnectionTerminalState::closed) {
            drain_result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
                .connection = connection_handle,
                .event = QuicCoreConnectionLifecycle::closed,
            });
        }
    }

    if (!drain_result.send_continuation_pending) {
        drain_result.next_wakeup = quic_connection.next_wakeup();
    }
    return drain_result;
}

COQUIC_NO_PROFILE StreamStateResult<bool>
queue_legacy_local_command(QuicConnection &quic_connection, const QuicCoreSendStreamData &input) {
    return quic_connection.queue_stream_send(input.stream_id, input.bytes, input.fin,
                                             input.priority);
}

COQUIC_NO_PROFILE StreamStateResult<bool>
queue_legacy_local_command(QuicConnection &quic_connection,
                           const QuicCoreSendSharedStreamData &input) {
    return quic_connection.queue_stream_send_shared(input.stream_id, input.bytes, input.fin,
                                                    input.priority);
}

COQUIC_NO_PROFILE CodecResult<bool>
queue_legacy_local_command(QuicConnection &quic_connection, const QuicCoreSendDatagramData &input) {
    return quic_connection.queue_datagram_send(input.bytes, input.priority);
}

COQUIC_NO_PROFILE CodecResult<bool>
queue_legacy_local_command(QuicConnection &quic_connection,
                           const QuicCoreSendSharedDatagramData &input) {
    return quic_connection.queue_datagram_send_shared(input.bytes, input.priority);
}

COQUIC_NO_PROFILE bool legacy_stream_send_batchable(const QuicCoreInput &input) {
    return std::holds_alternative<QuicCoreSendStreamData>(input) ||
           std::holds_alternative<QuicCoreSendSharedStreamData>(input);
}

COQUIC_NO_PROFILE void append_sequential_result(QuicCoreResult &target, QuicCoreResult source) {
    if (target.effects.empty()) {
        target.effects = std::move(source.effects);
    } else if (!source.effects.empty()) {
        target.effects.reserve(target.effects.size() + source.effects.size());
        target.effects.insert(target.effects.end(), std::make_move_iterator(source.effects.begin()),
                              std::make_move_iterator(source.effects.end()));
    }
    target.next_wakeup = source.next_wakeup;
    target.send_continuation_pending = source.send_continuation_pending;
    target.send_sink_failed = target.send_sink_failed || source.send_sink_failed;
    if (!target.local_error.has_value() && source.local_error.has_value()) {
        target.local_error = source.local_error;
    }
}

void append_result(QuicCoreResult &target, QuicCoreResult source) {
    if (core_profile_enabled()) {
        auto &profile = core_profile_counters();
        ++profile.append_result_calls;
        profile.append_result_effects += source.effects.size();
    }
    COQUIC_CORE_PROFILE_TIMER(append_result_timer, append_result_ns);
    if (target.effects.empty()) {
        target.effects = std::move(source.effects);
    } else if (!source.effects.empty()) {
        target.effects.reserve(target.effects.size() + source.effects.size());
        target.effects.insert(target.effects.end(), std::make_move_iterator(source.effects.begin()),
                              std::make_move_iterator(source.effects.end()));
    }
    merge_send_continuation_pending(target, source);
    target.send_sink_failed = target.send_sink_failed || source.send_sink_failed;
    if (source.next_wakeup.has_value()) {
        target.next_wakeup =
            std::min(target.next_wakeup.value_or(*source.next_wakeup), *source.next_wakeup);
    }
    if (!target.local_error.has_value() && source.local_error.has_value()) {
        target.local_error = source.local_error;
    }
}

bool has_closed_lifecycle_event(const QuicCoreResult &core_result) {
    return std::any_of(
        core_result.effects.begin(), core_result.effects.end(), [](const auto &effect) {
            const auto *event = std::get_if<QuicCoreConnectionLifecycleEvent>(&effect);
            return event != nullptr && event->event == QuicCoreConnectionLifecycle::closed;
        });
}

COQUIC_NO_PROFILE bool
should_remove_endpoint_connection_entry(const QuicConnection &quic_connection,
                                        const QuicCoreResult &drained_result,
                                        QuicCoreTimePoint now) {
    if (quic_connection.has_failed()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2
        // # Servers that retain an open socket for accepting new connections
        // # SHOULD NOT end the closing or draining state early.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2
        // # Once its closing or draining state ends, an endpoint SHOULD
        // # discard all connection state.
        return !quic_connection.close_state_active() || quic_connection.terminal_state_expired(now);
    }
    return has_closed_lifecycle_event(drained_result);
}

bool should_keep_endpoint_connection_entry(const QuicConnection &quic_connection,
                                           const QuicCoreResult &drained_result,
                                           QuicCoreTimePoint now = QuicCoreTimePoint{}) {
    const bool failed_before_handshake =
        quic_connection.has_failed() && !quic_connection.has_processed_peer_packet();
    return !failed_before_handshake &&
           !should_remove_endpoint_connection_entry(quic_connection, drained_result, now);
}

bool is_reserved_version(std::uint32_t version) {
    return (version & 0x0f0f0f0fu) == 0x0a0a0a0au;
}

void append_u16_be(std::vector<std::byte> &encoded_bytes, std::uint16_t value) {
    encoded_bytes.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    encoded_bytes.push_back(static_cast<std::byte>(value & 0xffu));
}

void append_u32_be(std::vector<std::byte> &encoded_bytes, std::uint32_t value) {
    encoded_bytes.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
    encoded_bytes.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    encoded_bytes.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    encoded_bytes.push_back(static_cast<std::byte>(value & 0xffu));
}

void append_u64_be(std::vector<std::byte> &encoded_bytes, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        encoded_bytes.push_back(
            static_cast<std::byte>((value >> static_cast<unsigned>(shift)) & 0xffu));
    }
}

COQUIC_NO_PROFILE std::optional<std::array<unsigned char, EVP_MAX_MD_SIZE>>
compute_hmac_sha256_for_core(std::span<const std::byte> secret,
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

std::optional<std::uint16_t> read_u16_be(BufferReader &reader) {
    const auto encoded_value = reader.read_exact(sizeof(std::uint16_t));
    if (!encoded_value.has_value()) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(encoded_value.value()[0])) << 8) |
        static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(encoded_value.value()[1])));
}

std::optional<std::uint32_t> read_u32_be(BufferReader &reader) {
    const auto encoded_value = reader.read_exact(sizeof(std::uint32_t));
    if (!encoded_value.has_value()) {
        return std::nullopt;
    }
    const auto value_bytes = encoded_value.value();
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(value_bytes[0])) << 24) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(value_bytes[1])) << 16) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(value_bytes[2])) << 8) |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(value_bytes[3]));
}

std::optional<std::uint64_t> read_u64_be(BufferReader &reader) {
    const auto encoded_value = reader.read_exact(sizeof(std::uint64_t));
    if (!encoded_value.has_value()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    for (const auto byte : encoded_value.value()) {
        value = (value << 8) | std::to_integer<std::uint8_t>(byte);
    }
    return value;
}

COQUIC_NO_PROFILE std::optional<std::vector<std::byte>>
read_length_prefixed_bytes(BufferReader &reader) {
    const auto size = read_u16_be(reader);
    if (!size.has_value() || reader.remaining() < *size) {
        return std::nullopt;
    }
    const auto encoded_value = reader.read_exact(*size);
    if (!encoded_value.has_value()) {
        return std::nullopt;
    }
    return std::vector<std::byte>(encoded_value.value().begin(), encoded_value.value().end());
}

COQUIC_NO_PROFILE bool append_length_prefixed_bytes(std::vector<std::byte> &encoded_bytes,
                                                    std::span<const std::byte> value) {
    if (value.size() > std::numeric_limits<std::uint16_t>::max()) {
        return false;
    }
    append_u16_be(encoded_bytes, static_cast<std::uint16_t>(value.size()));
    encoded_bytes.insert(encoded_bytes.end(), value.begin(), value.end());
    return true;
}

std::uint64_t token_timestamp_us(QuicCoreTimePoint time) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<QuicCoreDuration>(time.time_since_epoch()).count());
}

QuicCoreTimePoint token_time_from_us(std::uint64_t microseconds) {
    return QuicCoreTimePoint{} + QuicCoreDuration(static_cast<QuicCoreDuration::rep>(microseconds));
}

COQUIC_NO_PROFILE std::optional<std::array<std::byte, kAddressValidationTokenTagLength>>
compute_address_validation_token_tag(
    std::span<const std::byte> secret, // NOLINT(bugprone-easily-swappable-parameters)
    std::span<const std::byte> body) {
    constexpr std::array label{
        std::byte{'c'}, std::byte{'o'}, std::byte{'q'}, std::byte{'u'}, std::byte{'i'},
        std::byte{'c'}, std::byte{' '}, std::byte{'a'}, std::byte{'d'}, std::byte{'d'},
        std::byte{'r'}, std::byte{' '}, std::byte{'t'}, std::byte{'o'}, std::byte{'k'},
        std::byte{'e'}, std::byte{'n'},
    };
    std::vector<unsigned char> input;
    input.reserve(label.size() + body.size());
    for (const auto byte : label) {
        input.push_back(std::to_integer<unsigned char>(byte));
    }
    for (const auto byte : body) {
        input.push_back(std::to_integer<unsigned char>(byte));
    }

    unsigned int produced = 0;
    const auto digest = compute_hmac_sha256_for_core(
        secret, input, produced,
        core_test_fault_state().force_address_validation_token_tag_failure);
    if (!digest.has_value() || produced < kAddressValidationTokenTagLength) {
        return std::nullopt;
    }

    std::array<std::byte, kAddressValidationTokenTagLength> token_tag{};
    std::copy_n(reinterpret_cast<const std::byte *>(digest->data()), token_tag.size(),
                token_tag.begin());
    return token_tag;
}

struct SelfContainedAddressValidationToken {
    std::byte kind = kAddressValidationNewTokenType;
    std::uint32_t version = kQuicVersion1;
    std::optional<QuicRouteHandle> route_handle;
    std::vector<std::byte> address_validation_identity;
    ConnectionId original_destination_connection_id;
    ConnectionId retry_source_connection_id;
    std::vector<std::byte> nonce;
    QuicCoreTimePoint expires_at{};
};

COQUIC_NO_PROFILE std::optional<std::vector<std::byte>>
encode_address_validation_token_body(const SelfContainedAddressValidationToken &token_metadata) {
    std::vector<std::byte> body;
    body.reserve(96 + token_metadata.address_validation_identity.size() +
                 token_metadata.original_destination_connection_id.size() +
                 token_metadata.retry_source_connection_id.size() + token_metadata.nonce.size());
    body.push_back(std::byte{'C'});
    body.push_back(std::byte{'Q'});
    body.push_back(std::byte{'A'});
    body.push_back(std::byte{'V'});
    body.push_back(std::byte{0x01});
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.1
    // # A token sent in a NEW_TOKEN frame or a Retry packet MUST be
    // # constructed in a way that allows the server to identify how it was
    // # provided to a client.
    body.push_back(token_metadata.kind);
    append_u32_be(body, token_metadata.version);
    body.push_back(token_metadata.route_handle.has_value() ? std::byte{0x01} : std::byte{0x00});
    append_u64_be(body, token_metadata.route_handle.value_or(0));
    append_u64_be(body, token_timestamp_us(token_metadata.expires_at));
    if (!append_length_prefixed_bytes(body, token_metadata.address_validation_identity) ||
        !append_length_prefixed_bytes(body, token_metadata.original_destination_connection_id) ||
        !append_length_prefixed_bytes(body, token_metadata.retry_source_connection_id) ||
        !append_length_prefixed_bytes(body, token_metadata.nonce)) {
        return std::nullopt;
    }
    return body;
}

COQUIC_NO_PROFILE std::optional<SelfContainedAddressValidationToken>
decode_address_validation_token_body(std::span<const std::byte> body) {
    BufferReader reader(body);
    const auto magic = reader.read_exact(4);
    if (!magic.has_value() || magic.value().size() != 4 || magic.value()[0] != std::byte{'C'} ||
        magic.value()[1] != std::byte{'Q'} || magic.value()[2] != std::byte{'A'} ||
        magic.value()[3] != std::byte{'V'}) {
        return std::nullopt;
    }
    const auto format_version = reader.read_byte();
    const auto kind = reader.read_byte();
    const auto version = read_u32_be(reader);
    const auto route_present = reader.read_byte();
    const auto route_handle = read_u64_be(reader);
    const auto expires_at = read_u64_be(reader);
    if (!format_version.has_value() || format_version.value() != std::byte{0x01} ||
        !kind.has_value() ||
        (kind.value() != kAddressValidationRetryTokenType &&
         kind.value() != kAddressValidationNewTokenType) ||
        !version.has_value() || !route_present.has_value() || !route_handle.has_value() ||
        !expires_at.has_value()) {
        return std::nullopt;
    }

    auto address_validation_identity = read_length_prefixed_bytes(reader);
    auto original_destination_connection_id = read_length_prefixed_bytes(reader);
    auto retry_source_connection_id = read_length_prefixed_bytes(reader);
    auto nonce = read_length_prefixed_bytes(reader);
    if (!address_validation_identity.has_value() ||
        !original_destination_connection_id.has_value() ||
        !retry_source_connection_id.has_value() || !nonce.has_value() || reader.remaining() != 0) {
        return std::nullopt;
    }

    return SelfContainedAddressValidationToken{
        .kind = kind.value(),
        .version = *version,
        .route_handle = route_present.value() == std::byte{0x01} ? route_handle : std::nullopt,
        .address_validation_identity = std::move(*address_validation_identity),
        .original_destination_connection_id = std::move(*original_destination_connection_id),
        .retry_source_connection_id = std::move(*retry_source_connection_id),
        .nonce = std::move(*nonce),
        .expires_at = token_time_from_us(*expires_at),
    };
}

COQUIC_NO_PROFILE std::optional<std::vector<std::byte>>
seal_address_validation_token(const QuicAddressValidationTokenSecret &secret,
                              const SelfContainedAddressValidationToken &metadata) {
    auto body = encode_address_validation_token_body(metadata);
    if (!body.has_value()) {
        return std::nullopt;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # For this design to work, the token MUST be covered by integrity
    // # protection against modification or falsification by clients.
    const auto tag = compute_address_validation_token_tag(secret, *body);
    if (!tag.has_value()) {
        return std::nullopt;
    }

    std::vector<std::byte> sealed_token;
    sealed_token.reserve(body->size() + tag->size());
    sealed_token.insert(sealed_token.end(), body->begin(), body->end());
    sealed_token.insert(sealed_token.end(), tag->begin(), tag->end());
    return sealed_token;
}

COQUIC_NO_PROFILE std::optional<SelfContainedAddressValidationToken>
open_address_validation_token(const QuicAddressValidationTokenSecret &secret,
                              std::span<const std::byte> sealed_token) {
    if (sealed_token.size() <= kAddressValidationTokenTagLength) {
        return std::nullopt;
    }
    const auto body = sealed_token.first(sealed_token.size() - kAddressValidationTokenTagLength);
    const auto tag = sealed_token.last(kAddressValidationTokenTagLength);
    const auto expected = compute_address_validation_token_tag(secret, body);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # For this design to work, the token MUST be covered by integrity
    // # protection against modification or falsification by clients.
    if (!expected.has_value() ||
        CRYPTO_memcmp(expected->data(), tag.data(), expected->size()) != 0) {
        return std::nullopt;
    }
    return decode_address_validation_token_body(body);
}

std::string address_validation_token_replay_key(std::span<const std::byte> sealed_token) {
    if (sealed_token.size() >= kAddressValidationTokenTagLength) {
        const auto tag = sealed_token.last(kAddressValidationTokenTagLength);
        return std::string(reinterpret_cast<const char *>(tag.data()), tag.size());
    }
    return std::string(reinterpret_cast<const char *>(sealed_token.data()), sealed_token.size());
}

std::string hex_encode_bytes(std::span<const std::byte> bytes) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        hex << std::setw(2) << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
    }
    return hex.str();
}

COQUIC_NO_PROFILE std::optional<std::string> hex_decode_to_string(std::string_view hex) {
    if ((hex.size() % 2u) != 0u) {
        return std::nullopt;
    }

    const auto nibble = [](char ch) -> std::optional<std::uint8_t> {
        if (static_cast<unsigned>(ch - '0') <= 9u) {
            return static_cast<std::uint8_t>(ch - '0');
        }
        if (ch >= 'a' && ch <= 'f') {
            return static_cast<std::uint8_t>(10u + static_cast<unsigned>(ch - 'a'));
        }
        if (ch >= 'A' && ch <= 'F') {
            return static_cast<std::uint8_t>(10u + static_cast<unsigned>(ch - 'A'));
        }
        return std::nullopt;
    };

    std::string decoded;
    decoded.reserve(hex.size() / 2u);
    for (std::size_t offset = 0; offset < hex.size(); offset += 2u) {
        const auto high = nibble(hex[offset]);
        auto low_nibble = nibble(hex[offset + 1u]);
        if (!high.has_value() || !low_nibble.has_value()) {
            return std::nullopt;
        }
        decoded.push_back(static_cast<char>(static_cast<unsigned>(*high << 4u) |
                                            static_cast<unsigned>(*low_nibble)));
    }
    return decoded;
}

COQUIC_NO_PROFILE std::optional<std::uint64_t> parse_unsigned_decimal(std::string_view value) {
    if (value.empty()) {
        return std::nullopt;
    }

    std::uint64_t parsed = 0;
    for (const char ch : value) {
        if (ch < '0' || ch > '9') {
            return std::nullopt;
        }
        const auto digit = static_cast<std::uint64_t>(ch - '0');
        if (parsed > (std::numeric_limits<std::uint64_t>::max() - digit) / 10u) {
            return std::nullopt;
        }
        parsed = (parsed * 10u) + digit;
    }
    return parsed;
}

COQUIC_NO_PROFILE bool token_route_matches(const std::optional<QuicRouteHandle> &expected,
                                           const std::optional<QuicRouteHandle> &actual) {
    return !expected.has_value() || expected == actual;
}

bool token_identity_matches(std::span<const std::byte> expected,
                            std::span<const std::byte> actual) {
    return expected.empty() || std::ranges::equal(expected, actual);
}

std::optional<std::uint16_t>
    COQUIC_NO_PROFILE address_validation_identity_udp_port(std::span<const std::byte> identity) {
    if (identity.size() == 7 && identity.front() == std::byte{0x04}) {
        return static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(identity[5])) << 8) |
            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(identity[6])));
    }
    if (identity.size() == 19 && identity.front() == std::byte{0x06}) {
        return static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(identity[17])) << 8) |
            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(identity[18])));
    }
    return std::nullopt;
}

COQUIC_NO_PROFILE QuicRouteAddressFamily
route_address_family_from_identity(std::span<const std::byte> identity) {
    if (identity.size() == 7 && identity.front() == std::byte{0x04}) {
        return QuicRouteAddressFamily::ipv4;
    }
    if (identity.size() == 19 && identity.front() == std::byte{0x06}) {
        return QuicRouteAddressFamily::ipv6;
    }
    return QuicRouteAddressFamily::unknown;
}

COQUIC_NO_PROFILE std::size_t
default_pmtud_search_ceiling_for_route_family(QuicRouteAddressFamily family) {
    switch (family) {
    case QuicRouteAddressFamily::ipv4:
        return kPmtudIPv4EthernetUdpPayloadSize;
    case QuicRouteAddressFamily::ipv6:
    case QuicRouteAddressFamily::unknown:
        return kPmtudIPv6EthernetUdpPayloadSize;
    }
    return kPmtudIPv6EthernetUdpPayloadSize;
}

QuicAddressValidationIdentityClass COQUIC_NO_PROFILE
classify_ipv4_address_validation_identity(std::span<const std::byte> identity) {
    if (identity.size() != 7 || identity.front() != std::byte{0x04}) {
        return QuicAddressValidationIdentityClass::unknown;
    }

    const auto a = std::to_integer<std::uint8_t>(identity[1]);
    const auto b = std::to_integer<std::uint8_t>(identity[2]);
    if (a == 127) {
        return QuicAddressValidationIdentityClass::loopback;
    }
    if (a == 169 && b == 254) {
        return QuicAddressValidationIdentityClass::link_local;
    }
    if (a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168)) {
        return QuicAddressValidationIdentityClass::private_use;
    }
    return QuicAddressValidationIdentityClass::global;
}

QuicAddressValidationIdentityClass COQUIC_NO_PROFILE
classify_ipv6_address_validation_identity(std::span<const std::byte> identity) {
    if (identity.size() != 19 || identity.front() != std::byte{0x06}) {
        return QuicAddressValidationIdentityClass::unknown;
    }

    bool loopback = true;
    for (std::size_t index = 1; index < 16; ++index) {
        loopback = loopback && identity[index] == std::byte{0x00};
    }
    if (loopback && identity[16] == std::byte{0x01}) {
        return QuicAddressValidationIdentityClass::loopback;
    }

    const auto first = std::to_integer<std::uint8_t>(identity[1]);
    const auto second = std::to_integer<std::uint8_t>(identity[2]);
    if (first == 0xfe && (second & 0xc0u) == 0x80u) {
        return QuicAddressValidationIdentityClass::link_local;
    }
    if ((first & 0xfeu) == 0xfcu) {
        return QuicAddressValidationIdentityClass::unique_local;
    }
    return QuicAddressValidationIdentityClass::global;
}

QuicAddressValidationIdentityClass
classify_address_validation_identity(std::span<const std::byte> identity) {
    if (identity.empty()) {
        return QuicAddressValidationIdentityClass::unknown;
    }
    if (identity.front() == std::byte{0x04}) {
        return classify_ipv4_address_validation_identity(identity);
    }
    if (identity.front() == std::byte{0x06}) {
        return classify_ipv6_address_validation_identity(identity);
    }
    return QuicAddressValidationIdentityClass::unknown;
}

COQUIC_NO_PROFILE bool
address_class_is_private_like(QuicAddressValidationIdentityClass address_class) {
    return address_class == QuicAddressValidationIdentityClass::loopback ||
           address_class == QuicAddressValidationIdentityClass::link_local ||
           address_class == QuicAddressValidationIdentityClass::private_use ||
           address_class == QuicAddressValidationIdentityClass::unique_local;
}

COQUIC_NO_PROFILE bool
address_class_is_public_like(QuicAddressValidationIdentityClass address_class) {
    return address_class == QuicAddressValidationIdentityClass::global ||
           address_class == QuicAddressValidationIdentityClass::unique_local;
}

COQUIC_NO_PROFILE bool address_identity_allowed_by_request_forgery_policy(
    const QuicRequestForgeryPolicyConfig &policy,
    std::span<const std::byte> current_identity, // NOLINT(bugprone-easily-swappable-parameters)
    std::span<const std::byte> candidate_identity) {
    const auto candidate_class = classify_address_validation_identity(candidate_identity);
    if (policy.reject_loopback_addresses &&
        candidate_class == QuicAddressValidationIdentityClass::loopback) {
        return false;
    }
    if (policy.reject_link_local_addresses &&
        candidate_class == QuicAddressValidationIdentityClass::link_local) {
        return false;
    }
    if (policy.reject_private_use_addresses &&
        (candidate_class == QuicAddressValidationIdentityClass::private_use ||
         candidate_class == QuicAddressValidationIdentityClass::unique_local)) {
        return false;
    }
    if (policy.reject_address_space_downgrade && !current_identity.empty()) {
        const auto current_class = classify_address_validation_identity(current_identity);
        if (address_class_is_public_like(current_class) &&
            address_class_is_private_like(candidate_class)) {
            return false;
        }
    }
    if (const auto port = address_validation_identity_udp_port(candidate_identity);
        port.has_value() &&
        std::ranges::find(policy.blocked_udp_ports, *port) != policy.blocked_udp_ports.end()) {
        return false;
    }
    return true;
}

COQUIC_NO_PROFILE bool fill_endpoint_connection_id_from_openssl(ConnectionId &connection_id,
                                                                bool force_failure) {
    return !force_failure && connection_id.size() > 1 &&
           RAND_bytes(reinterpret_cast<unsigned char *>(connection_id.data() + 1),
                      static_cast<int>(connection_id.size() - 1)) == 1;
}

ConnectionId make_endpoint_connection_id(std::byte prefix, std::uint64_t sequence,
                                         std::mt19937_64 &fallback_random) {
    ConnectionId connection_id(kEndpointConnectionIdLength, std::byte{0x00});
    connection_id.front() = prefix;
    if (fill_endpoint_connection_id_from_openssl(
            connection_id, core_test_fault_state().force_endpoint_connection_id_rand_failure)) {
        return connection_id;
    }
    for (std::size_t index = 1; index < connection_id.size(); ++index) {
        connection_id[index] = static_cast<std::byte>(fallback_random());
    }
    connection_id.back() =
        static_cast<std::byte>(std::to_integer<std::uint8_t>(connection_id.back()) ^
                               static_cast<std::uint8_t>(sequence & 0xffu));
    return connection_id;
}

std::vector<std::byte> make_stateless_reset_token_context(std::span<const std::byte> connection_id,
                                                          std::uint64_t sequence_number) {
    std::vector<std::byte> context;
    context.reserve(connection_id.size() + sizeof(sequence_number) + sizeof(std::uint64_t));
    context.insert(context.end(), connection_id.begin(), connection_id.end());
    for (int shift = 56; shift >= 0; shift -= 8) {
        context.push_back(
            static_cast<std::byte>((sequence_number >> static_cast<unsigned>(shift)) & 0xffu));
    }
    for (int shift = 56; shift >= 0; shift -= 8) {
        context.push_back(std::byte{0x00});
    }
    return context;
}

COQUIC_NO_PROFILE std::optional<std::array<std::byte, kStatelessResetTokenLength>>
derive_stateless_reset_token(
    std::span<const std::byte> secret, // NOLINT(bugprone-easily-swappable-parameters)
    std::span<const std::byte> connection_id, std::uint64_t sequence_number) {
    constexpr std::array label{
        std::byte{'c'}, std::byte{'o'}, std::byte{'q'}, std::byte{'u'}, std::byte{'i'},
        std::byte{'c'}, std::byte{' '}, std::byte{'s'}, std::byte{'r'}, std::byte{'t'},
    };
    const auto context = make_stateless_reset_token_context(connection_id, sequence_number);
    std::vector<unsigned char> input;
    input.reserve(label.size() + context.size());
    for (const auto byte : label) {
        input.push_back(std::to_integer<unsigned char>(byte));
    }
    for (const auto byte : context) {
        input.push_back(std::to_integer<unsigned char>(byte));
    }

    unsigned int produced = 0;
    const auto digest = compute_hmac_sha256_for_core(
        secret, input, produced,
        core_test_fault_state().force_stateless_reset_token_derivation_failure);
    if (!digest.has_value() || produced < kStatelessResetTokenLength) {
        return std::nullopt;
    }

    std::array<std::byte, kStatelessResetTokenLength> token{};
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
    // # The stateless reset token MUST be difficult to guess.
    std::copy_n(reinterpret_cast<const std::byte *>(digest->data()), token.size(), token.begin());
    return token;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_initial_long_header_type(std::uint32_t version, std::uint8_t type) {
    if (version == kQuicVersion2) {
        return type == 0x01u;
    }
    return type == 0x00u;
}

std::optional<VersionNegotiationPacket>
parse_version_negotiation_packet(std::span<const std::byte> bytes) {
    if (bytes.size() < 5) {
        return std::nullopt;
    }
    const auto version =
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[1])) << 24) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2])) << 16) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[3])) << 8) |
        static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[4]));
    if (version != kVersionNegotiationVersion) {
        return std::nullopt;
    }

    const auto decoded = deserialize_packet(bytes, {});
    if (!decoded.has_value()) {
        return std::nullopt;
    }

    return std::get<VersionNegotiationPacket>(decoded.value().packet);
}

std::optional<RetryPacket> parse_retry_packet(std::span<const std::byte> bytes) {
    if (bytes.size() < 5) {
        return std::nullopt;
    }
    const auto version =
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[1])) << 24) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2])) << 16) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[3])) << 8) |
        static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[4]));
    if (version == kVersionNegotiationVersion) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-6.1
        // # An endpoint MUST NOT send a Version Negotiation packet
        // # in response to receiving a Version Negotiation packet.
        return std::nullopt;
    }

    const auto decoded = deserialize_packet(bytes, {});
    if (!decoded.has_value() || decoded.value().bytes_consumed != bytes.size()) {
        return std::nullopt;
    }

    if (const auto *retry = std::get_if<RetryPacket>(&decoded.value().packet)) {
        return *retry;
    }

    return std::nullopt;
}

bool token_time_expired(QuicCoreTimePoint expires_at, QuicCoreTimePoint now) {
    return expires_at != QuicCoreTimePoint{} && now > expires_at;
}

void purge_expired_consumed_address_validation_tokens(
    std::unordered_map<std::string, QuicCoreTimePoint> &tokens, QuicCoreTimePoint now) {
    if (now == QuicCoreTimePoint{}) {
        return;
    }
    for (auto it = tokens.begin(); it != tokens.end();) {
        if (token_time_expired(it->second, now)) {
            it = tokens.erase(it);
        } else {
            ++it;
        }
    }
}

COQUIC_NO_PROFILE bool fill_random_bytes_from_openssl(std::span<std::byte> bytes,
                                                      bool force_failure) {
    return !force_failure && RAND_bytes(reinterpret_cast<unsigned char *>(bytes.data()),
                                        static_cast<int>(bytes.size())) == 1;
}

void fill_random_bytes(std::span<std::byte> bytes, std::mt19937_64 &fallback_random) {
    if (bytes.empty()) {
        return;
    }
    if (fill_random_bytes_from_openssl(
            bytes, core_test_fault_state().force_fill_random_bytes_rand_failure)) {
        return;
    }
    for (auto &byte : bytes) {
        byte = static_cast<std::byte>(fallback_random());
    }
}

} // namespace

namespace detail {

COQUIC_NO_PROFILE void *allocate_core_effect_storage(CoreEffectStorageBytes bytes,
                                                     CoreEffectStorageAlignment alignment) {
    if (bytes.value == 0) {
        return nullptr;
    }

    const auto allocation_bytes = core_effect_storage_allocation_bytes(bytes.value);
#if COQUIC_DISABLE_CORE_EFFECT_STORAGE_CACHE == 0
    if (auto *cached = core_effect_storage_cache().take(allocation_bytes, alignment.value);
        cached != nullptr) {
        return cached;
    }

    return allocate_aligned_cache_storage(allocation_bytes, alignment.value);
#else
    return allocate_aligned_cache_storage(allocation_bytes, alignment.value);
#endif
}

COQUIC_NO_PROFILE void
deallocate_core_effect_storage(void *pointer, CoreEffectStorageBytes bytes,
                               CoreEffectStorageAlignment alignment) noexcept {
    if (pointer == nullptr || bytes.value == 0) {
        return;
    }

    const auto allocation_bytes = core_effect_storage_allocation_bytes(bytes.value);
#if COQUIC_DISABLE_CORE_EFFECT_STORAGE_CACHE == 0
    if (allocation_bytes <= kCoreEffectStorageCacheMaxBytes &&
        core_effect_storage_cache().put(pointer, allocation_bytes, alignment.value)) {
        return;
    }

    deallocate_aligned_cache_storage(pointer, alignment.value);
#else
    deallocate_aligned_cache_storage(pointer, alignment.value);
#endif
}

} // namespace detail

QuicCore::LegacyConnectionView &
QuicCore::LegacyConnectionView::operator=(std::unique_ptr<QuicConnection> connection) {
    owner->set_legacy_connection(std::move(connection));
    return *this;
}

QuicConnection *QuicCore::LegacyConnectionView::get() const {
    if (owner == nullptr) {
        return nullptr;
    }
    auto *entry = owner->legacy_entry();
    return entry == nullptr ? nullptr : entry->connection.get();
}

QuicConnection *QuicCore::LegacyConnectionView::operator->() const {
    return get();
}

QuicConnection &QuicCore::LegacyConnectionView::operator*() const {
    return *get();
}

QuicCore::LegacyConnectionView::operator bool() const {
    return get() != nullptr;
}

bool QuicCore::LegacyConnectionView::operator==(std::nullptr_t) const {
    return get() == nullptr;
}

bool QuicCore::LegacyConnectionView::operator!=(std::nullptr_t) const {
    return get() != nullptr;
}

QuicCore::ConnectionEntry *QuicCore::legacy_entry() {
    if (!legacy_connection_handle_.has_value()) {
        return nullptr;
    }
    const auto it = connections_.find(*legacy_connection_handle_);
    if (it == connections_.end()) {
        return nullptr;
    }
    return &it->second;
}

const QuicCore::ConnectionEntry *QuicCore::legacy_entry() const {
    if (!legacy_connection_handle_.has_value()) {
        return nullptr;
    }
    const auto it = connections_.find(*legacy_connection_handle_);
    if (it == connections_.end()) {
        return nullptr;
    }
    return &it->second;
}

QuicCore::ConnectionEntry *QuicCore::ensure_legacy_entry() {
    if (auto *entry = legacy_entry()) {
        return entry;
    }
    if (!legacy_config_.has_value()) {
        return nullptr;
    }
    if (!legacy_connection_handle_.has_value()) {
        legacy_connection_handle_ = next_connection_handle_++;
    }

    const auto handle = *legacy_connection_handle_;
    auto [it, inserted] = connections_.try_emplace(handle);
    (void)inserted;
    auto &entry = it->second;
    entry.handle = handle;
    entry.connection = std::make_unique<QuicConnection>(*legacy_config_);
    refresh_entry_wakeup(entry);
    return &it->second;
}

void QuicCore::set_legacy_connection(std::unique_ptr<QuicConnection> connection) {
    if (!legacy_connection_handle_.has_value()) {
        legacy_connection_handle_ = next_connection_handle_++;
    }
    if (connection == nullptr) {
        connections_.erase(*legacy_connection_handle_);
        return;
    }

    auto &entry = connections_[*legacy_connection_handle_];
    entry = {};
    entry.handle = *legacy_connection_handle_;
    entry.connection = std::move(connection);
    refresh_entry_wakeup(entry);
}

std::string QuicCore::connection_id_key(std::span<const std::byte> connection_id) {
    if (connection_id.empty()) {
        return {};
    }
    return std::string(reinterpret_cast<const char *>(connection_id.data()), connection_id.size());
}

std::string
QuicCore::stateless_reset_token_key(const std::array<std::byte, 16> &stateless_reset_token) {
    return std::string(reinterpret_cast<const char *>(stateless_reset_token.data()),
                       stateless_reset_token.size());
}

std::optional<QuicCore::ParsedEndpointDatagram>
QuicCore::parse_endpoint_datagram(std::span<const std::byte> bytes, bool accept_greased_quic_bit) {
    if (bytes.empty()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
        // # Endpoints MUST discard packets that are too small to be valid QUIC
        // # packets.
        return std::nullopt;
    }

    const auto first_byte = std::to_integer<std::uint8_t>(bytes.front());
    if ((first_byte & 0x80u) == 0) {
        if ((first_byte & 0x40u) == 0 && !accept_greased_quic_bit) {
            //= https://www.rfc-editor.org/rfc/rfc9287#section-3
            // # An endpoint that advertises the grease_quic_bit transport parameter
            // # MUST accept packets with the QUIC Bit set to a value of 0.
            return std::nullopt;
        }
        if (bytes.size() < 1 + kEndpointConnectionIdLength) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
            // # Endpoints MUST discard packets that are too small to be valid
            // # QUIC packets.
            return std::nullopt;
        }

        return ParsedEndpointDatagram{
            .kind = ParsedEndpointDatagram::Kind::short_header,
            .destination_connection_id =
                ConnectionId(bytes.begin() + 1, bytes.begin() + 1 + kEndpointConnectionIdLength),
        };
    }

    if ((first_byte & 0x40u) == 0 && !accept_greased_quic_bit) {
        //= https://www.rfc-editor.org/rfc/rfc9287#section-3
        // # An endpoint that advertises the grease_quic_bit transport parameter
        // # MUST accept packets with the QUIC Bit set to a value of 0.
        return std::nullopt;
    }
    if (bytes.size() < 7) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
        // # Endpoints MUST discard packets that are too small to be valid QUIC
        // # packets.
        return std::nullopt;
    }

    const auto version =
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[1])) << 24) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2])) << 16) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[3])) << 8) |
        static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[4]));
    if (version == kVersionNegotiationVersion) {
        return std::nullopt;
    }

    std::size_t offset = 5;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    // # In order to properly form a Version Negotiation packet, servers
    // # SHOULD be able to read longer connection IDs from other QUIC versions.
    auto destination_connection_id_length =
        static_cast<std::size_t>(std::to_integer<std::uint8_t>(bytes[offset++]));
    if (offset + destination_connection_id_length + 1 > bytes.size()) {
        return std::nullopt;
    }
    ConnectionId destination_connection_id(
        bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + destination_connection_id_length));
    offset += destination_connection_id_length;

    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2
    // # In order to properly form a Version Negotiation packet, servers
    // # SHOULD be able to read longer connection IDs from other QUIC versions.
    auto source_connection_id_length =
        static_cast<std::size_t>(std::to_integer<std::uint8_t>(bytes[offset++]));
    if (offset + source_connection_id_length > bytes.size()) {
        return std::nullopt;
    }
    ConnectionId source_connection_id(
        bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + source_connection_id_length));
    offset += source_connection_id_length;

    if (!is_supported_quic_version(version)) {
        return ParsedEndpointDatagram{
            .kind = ParsedEndpointDatagram::Kind::unsupported_version_long_header,
            .destination_connection_id = std::move(destination_connection_id),
            .source_connection_id = std::move(source_connection_id),
            .version = version,
        };
    }

    const auto type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    std::vector<std::byte> token;
    if (is_initial_long_header_type(version, type)) {
        BufferReader reader(bytes.subspan(offset));
        const auto token_length = decode_varint(reader);
        if (!token_length.has_value()) {
            return std::nullopt;
        }
        if (token_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
            return std::nullopt;
        }
        const auto token_bytes =
            reader.read_exact(static_cast<std::size_t>(token_length.value().value)).value();
        token.assign(token_bytes.begin(), token_bytes.end());
    }

    return ParsedEndpointDatagram{
        .kind = is_initial_long_header_type(version, type)
                    ? ParsedEndpointDatagram::Kind::supported_initial
                    : ParsedEndpointDatagram::Kind::supported_long_header,
        .destination_connection_id = std::move(destination_connection_id),
        .source_connection_id = std::move(source_connection_id),
        .version = version,
        .token = std::move(token),
    };
}

COQUIC_NO_PROFILE std::vector<std::byte> QuicCore::make_endpoint_retry_token(
    std::uint64_t sequence, const ParsedEndpointDatagram *parsed,
    const ConnectionId *retry_source_connection_id, std::optional<QuicRouteHandle> route_handle,
    std::span<const std::byte> address_validation_identity, QuicCoreTimePoint now) {
    if (endpoint_config_.address_validation_token_secret.has_value() && parsed != nullptr &&
        retry_source_connection_id != nullptr) {
        std::vector<std::byte> nonce(16, std::byte{0x00});
        fill_random_bytes(nonce, endpoint_random_);
        nonce.back() = static_cast<std::byte>(std::to_integer<std::uint8_t>(nonce.back()) ^
                                              static_cast<std::uint8_t>(sequence & 0xffu));
        if (const auto token = seal_address_validation_token(
                *endpoint_config_.address_validation_token_secret,
                SelfContainedAddressValidationToken{
                    .kind = kAddressValidationRetryTokenType,
                    .version = parsed->version,
                    .route_handle = route_handle,
                    .address_validation_identity = std::vector<std::byte>(
                        address_validation_identity.begin(), address_validation_identity.end()),
                    .original_destination_connection_id = parsed->destination_connection_id,
                    .retry_source_connection_id = *retry_source_connection_id,
                    .nonce = std::move(nonce),
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-21.3
                    // # Servers SHOULD provide mitigations for this attack by
                    // # limiting the usage and lifetime of address validation
                    // # tokens; see Section 8.1.3.
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
                    // # Servers SHOULD ensure that tokens sent in Retry packets
                    // # are only accepted for a short time, as they are returned
                    // # immediately by clients.
                    .expires_at = now + kRetryTokenLifetime,
                })) {
            return *token;
        }
    }

    std::vector<std::byte> token(16, std::byte{0x00});
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # An address validation token MUST be difficult to guess.
    fill_random_bytes(token, endpoint_random_);
    token.back() = static_cast<std::byte>(std::to_integer<std::uint8_t>(token.back()) ^
                                          static_cast<std::uint8_t>(sequence & 0xffu));
    return token;
}

COQUIC_NO_PROFILE std::vector<std::byte> QuicCore::make_endpoint_new_token(
    std::uint64_t sequence, // NOLINT(bugprone-easily-swappable-parameters)
    std::uint32_t version, std::optional<QuicRouteHandle> route_handle,
    std::span<const std::byte> address_validation_identity, QuicCoreTimePoint now) {
    if (endpoint_config_.address_validation_token_secret.has_value()) {
        std::vector<std::byte> nonce(16, std::byte{0x00});
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
        // # A server MUST ensure that every NEW_TOKEN frame it sends is unique
        // # across all clients, with the exception of those sent to repair
        // # losses of previously sent NEW_TOKEN frames.
        fill_random_bytes(nonce, endpoint_random_);
        nonce.back() = static_cast<std::byte>(std::to_integer<std::uint8_t>(nonce.back()) ^
                                              static_cast<std::uint8_t>(sequence & 0xffu));
        if (const auto token = seal_address_validation_token(
                *endpoint_config_.address_validation_token_secret,
                SelfContainedAddressValidationToken{
                    .kind = kAddressValidationNewTokenType,
                    .version = version,
                    .route_handle = route_handle,
                    .address_validation_identity = std::vector<std::byte>(
                        address_validation_identity.begin(), address_validation_identity.end()),
                    .nonce = std::move(nonce),
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-21.3
                    // # Servers SHOULD provide mitigations for this attack by
                    // # limiting the usage and lifetime of address validation
                    // # tokens; see Section 8.1.3.
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
                    // # Thus, a token SHOULD have an expiration time, which
                    // # could be either an explicit expiration time or an
                    // # issued timestamp that can be used to dynamically
                    // # calculate the expiration time.
                    .expires_at = now + kNewTokenLifetime,
                })) {
            return *token;
        }
    }

    std::vector<std::byte> token(24, std::byte{0x00});
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
    // # A server MUST ensure that every NEW_TOKEN frame it sends is unique
    // # across all clients, with the exception of those sent to repair losses
    // # of previously sent NEW_TOKEN frames.
    fill_random_bytes(token, endpoint_random_);
    token.front() = static_cast<std::byte>(std::to_integer<std::uint8_t>(token.front()) ^ 0x4eu);
    token.back() = static_cast<std::byte>(std::to_integer<std::uint8_t>(token.back()) ^
                                          static_cast<std::uint8_t>(sequence & 0xffu));
    return token;
}

COQUIC_NO_PROFILE std::optional<QuicCore::PendingRetryToken> QuicCore::take_retry_context(
    const ParsedEndpointDatagram &parsed, const std::optional<QuicRouteHandle> &route_handle,
    QuicCoreTimePoint now, std::span<const std::byte> address_validation_identity) {
    purge_expired_consumed_address_validation_tokens(consumed_address_validation_tokens_, now);
    persist_consumed_address_validation_tokens();
    const auto it = retry_tokens_.find(connection_id_key(parsed.token));
    if (it == retry_tokens_.end()) {
        if (!endpoint_config_.address_validation_token_secret.has_value()) {
            return std::nullopt;
        }

        auto metadata = open_address_validation_token(
            *endpoint_config_.address_validation_token_secret, parsed.token);
        if (!metadata.has_value()) {
            return std::nullopt;
        }

        if (metadata->kind != kAddressValidationRetryTokenType ||
            //= https://www.rfc-editor.org/rfc/rfc9000#section-21.3
            // # Servers SHOULD provide mitigations for this attack by limiting
            // # the usage and lifetime of address validation tokens; see
            // # Section 8.1.3.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
            // # Servers SHOULD ensure that tokens sent in Retry packets are only
            // # accepted for a short time, as they are returned immediately by clients.
            token_time_expired(metadata->expires_at, now) ||
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
            // # To protect against such attacks, servers MUST ensure that replay
            // # of tokens is prevented or limited.
            address_validation_token_consumed(parsed.token) ||
            !token_route_matches(metadata->route_handle, route_handle) ||
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
            // # Tokens sent in Retry packets SHOULD include information that
            // # allows the server to verify that the source IP address and port
            // # in client packets remain constant.
            !token_identity_matches(metadata->address_validation_identity,
                                    address_validation_identity) ||
            parsed.destination_connection_id != metadata->retry_source_connection_id ||
            parsed.version != metadata->version) {
            return std::nullopt;
        }

        mark_address_validation_token_consumed(parsed.token, metadata->expires_at);
        return PendingRetryToken{
            .original_destination_connection_id = metadata->original_destination_connection_id,
            .retry_source_connection_id = metadata->retry_source_connection_id,
            .original_version = metadata->version,
            .token = parsed.token,
            .route_handle = metadata->route_handle,
            .address_validation_identity = metadata->address_validation_identity,
            .expires_at = metadata->expires_at,
        };
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # To protect against such attacks, servers MUST ensure that replay of
    // # tokens is prevented or limited.
    if (address_validation_token_consumed(parsed.token)) {
        return std::nullopt;
    }

    const auto &pending = it->second;
    if (token_time_expired(pending.expires_at, now)) {
        retry_tokens_.erase(it);
        return std::nullopt;
    }
    if (pending.route_handle != route_handle ||
        !token_identity_matches(pending.address_validation_identity, address_validation_identity) ||
        parsed.destination_connection_id != pending.retry_source_connection_id ||
        parsed.version != pending.original_version) {
        return std::nullopt;
    }

    auto retry_context = pending;
    retry_tokens_.erase(it);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
    // # To protect against such attacks, servers MUST ensure that replay of
    // # tokens is prevented or limited.
    mark_address_validation_token_consumed(parsed.token, retry_context.expires_at);
    return retry_context;
}

COQUIC_NO_PROFILE std::optional<QuicCore::StoredEndpointNewToken> QuicCore::take_new_token_context(
    const ParsedEndpointDatagram &parsed, const std::optional<QuicRouteHandle> &route_handle,
    QuicCoreTimePoint now, std::span<const std::byte> address_validation_identity) {
    purge_expired_consumed_address_validation_tokens(consumed_address_validation_tokens_, now);
    persist_consumed_address_validation_tokens();
    const auto token_key = connection_id_key(parsed.token);
    const auto it = new_tokens_.find(token_key);
    if (it == new_tokens_.end()) {
        if (!endpoint_config_.address_validation_token_secret.has_value()) {
            return std::nullopt;
        }

        std::optional<SelfContainedAddressValidationToken> metadata;
        if (auto opened = open_address_validation_token(
                *endpoint_config_.address_validation_token_secret, parsed.token)) {
            metadata = std::move(opened);
        } else {
            for (const auto &previous_secret :
                 endpoint_config_.previous_address_validation_token_secrets) {
                if (auto opened_previous =
                        open_address_validation_token(previous_secret, parsed.token)) {
                    metadata = std::move(opened_previous);
                    break;
                }
            }
        }

        if (!metadata.has_value() || metadata->kind != kAddressValidationNewTokenType ||
            //= https://www.rfc-editor.org/rfc/rfc9000#section-21.3
            // # Servers SHOULD provide mitigations for this attack by limiting
            // # the usage and lifetime of address validation tokens; see
            // # Section 8.1.3.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
            // # Thus, a token SHOULD have an expiration time, which could be
            // # either an explicit expiration time or an issued timestamp that
            // # can be used to dynamically calculate the expiration time.
            token_time_expired(metadata->expires_at, now) ||
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
            // # Tokens that are provided in NEW_TOKEN frames (Section 19.7) need
            // # to be valid for longer but SHOULD NOT be accepted multiple times.
            address_validation_token_consumed(parsed.token) ||
            !token_route_matches(metadata->route_handle, route_handle) ||
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
            // # Tokens sent in NEW_TOKEN frames MUST include information that
            // # allows the server to verify that the client IP address has not
            // # changed from when the token was issued.
            !token_identity_matches(metadata->address_validation_identity,
                                    address_validation_identity) ||
            metadata->version != parsed.version) {
            return std::nullopt;
        }

        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.4
        // # Tokens that are provided in NEW_TOKEN frames (Section 19.7) need to
        // # be valid for longer but SHOULD NOT be accepted multiple times.
        mark_address_validation_token_consumed(parsed.token, metadata->expires_at);
        return StoredEndpointNewToken{
            .token = parsed.token,
            .route_handle = metadata->route_handle,
            .address_validation_identity = metadata->address_validation_identity,
            .version = metadata->version,
            .expires_at = metadata->expires_at,
            .used = true,
        };
    }

    if (address_validation_token_consumed(parsed.token)) {
        return std::nullopt;
    }

    auto token = it->second;
    if (token.used || token.version != parsed.version ||
        (token.route_handle.has_value() && token.route_handle != route_handle) ||
        !token_identity_matches(token.address_validation_identity, address_validation_identity) ||
        token_time_expired(token.expires_at, now)) {
        if (token_time_expired(token.expires_at, now)) {
            new_tokens_.erase(it);
        }
        return std::nullopt;
    }

    token.used = true;
    new_tokens_.erase(it);
    mark_address_validation_token_consumed(parsed.token, token.expires_at);
    return token;
}

COQUIC_NO_PROFILE void QuicCore::maybe_queue_server_new_token(ConnectionEntry &entry,
                                                              QuicCoreTimePoint now) {
    if (endpoint_config_.role != EndpointRole::server || entry.connection == nullptr ||
        !entry.connection->is_handshake_complete() || !entry.connection->peer_address_validated_) {
        return;
    }

    const auto route_handle = route_handle_for_path(entry, entry.connection->current_send_path_id_);
    if (!route_handle.has_value()) {
        return;
    }

    if (std::find(entry.new_token_issued_routes.begin(), entry.new_token_issued_routes.end(),
                  *route_handle) != entry.new_token_issued_routes.end()) {
        return;
    }

    const auto path_id = entry.connection->current_send_path_id_;
    const auto identity_it = path_id.has_value()
                                 ? entry.address_validation_identity_by_path_id.find(*path_id)
                                 : entry.address_validation_identity_by_path_id.end();
    const auto address_validation_identity =
        identity_it != entry.address_validation_identity_by_path_id.end()
            ? std::span<const std::byte>(identity_it->second)
            : std::span<const std::byte>{};

    auto sequence = next_server_connection_id_sequence_++;
    auto token = make_endpoint_new_token(sequence, entry.connection->current_version_, route_handle,
                                         address_validation_identity, now);
    if (token.empty()) {
        return;
    }

    new_tokens_.insert_or_assign(connection_id_key(token),
                                 StoredEndpointNewToken{
                                     .token = token,
                                     .route_handle = route_handle,
                                     .address_validation_identity =
                                         std::vector<std::byte>(address_validation_identity.begin(),
                                                                address_validation_identity.end()),
                                     .version = entry.connection->current_version_,
                                     .expires_at = now + kNewTokenLifetime,
                                     .used = false,
                                 });
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.3
    // # After verifying a new client address, the server SHOULD send new
    // # address validation tokens (Section 8) to the client.
    entry.connection->queue_new_token(std::move(token));
    entry.new_token_issued_routes.push_back(*route_handle);
}

COQUIC_NO_PROFILE void
QuicCore::drain_queued_server_new_token(ConnectionEntry &entry, QuicCoreResult &drained,
                                        QuicCoreTimePoint now,
                                        QuicCoreSendDatagramSink *send_sink) {
    maybe_queue_server_new_token(entry, now);
    if (!entry.connection->has_sendable_datagram(now)) {
        return;
    }
    auto token_drained = drain_connection_effects(entry.handle, entry.default_route_handle,
                                                  entry.route_handle_by_path_id, *entry.connection,
                                                  now, /*continue_paced_burst=*/false, send_sink);
    append_result(drained, std::move(token_drained));
}

COQUIC_NO_PROFILE void QuicCore::remember_client_new_tokens(ConnectionEntry &entry,
                                                            const QuicCoreResult &result) {
    if (endpoint_config_.role != EndpointRole::client || entry.connection == nullptr) {
        return;
    }

    for (const auto &effect : result.effects) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
        // # The client MUST NOT use the token provided in a Retry for future
        // # connections.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
        // # In comparison, a token obtained in a Retry packet MUST be used
        // # immediately during the connection attempt and cannot be used in
        // # subsequent connection attempts.
        const auto *new_token = std::get_if<QuicCoreNewTokenAvailable>(&effect);
        if (new_token == nullptr || new_token->token.empty() ||
            new_token->connection != entry.handle) {
            continue;
        }

        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
        // # A client MAY use a token from any previous connection to that server.
        const bool already_stored =
            std::ranges::any_of(client_new_tokens_, [&](const ClientStoredNewToken &stored) {
                return stored.server_name == entry.connection->config_.server_name &&
                       stored.version == entry.connection->current_version_ &&
                       stored.token == new_token->token;
            });
        if (already_stored) {
            continue;
        }

        client_new_tokens_.push_back(ClientStoredNewToken{
            .server_name = entry.connection->config_.server_name,
            .version = entry.connection->current_version_,
            .token = new_token->token,
            .used = false,
        });
    }
}

std::optional<std::vector<std::byte>> COQUIC_NO_PROFILE
QuicCore::take_client_new_token_for_open(const QuicCoreClientConnectionConfig &connection) {
    for (auto it = client_new_tokens_.rbegin(); it != client_new_tokens_.rend(); ++it) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
        // # When connecting to a server for which the client retains an
        // # applicable and unused token, it SHOULD include that token
        // # in the Token field of its Initial packet.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
        // # A client MUST NOT include a token that is not applicable to the
        // # server that it is connecting to, unless the client has the
        // # knowledge that the server that issued the token and the server the
        // # client is connecting to are jointly managing the tokens.
        if (it->used || it->server_name != connection.server_name ||
            it->version != connection.initial_version || it->token.empty()) {
            continue;
        }

        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
        // # A client SHOULD NOT reuse a token from a NEW_TOKEN frame for
        // # different connection attempts.
        it->used = true;
        return it->token;
    }
    return std::nullopt;
}

std::optional<QuicCoreResult>
    COQUIC_NO_PROFILE QuicCore::maybe_process_client_endpoint_version_negotiation(
        ConnectionEntry &entry, std::span<const std::byte> inbound_payload,
        const std::optional<QuicRouteHandle> &route_handle, QuicPathId path_id,
        QuicCoreTimePoint now, QuicCoreSendDatagramSink *send_sink) {
    if (endpoint_config_.role != EndpointRole::client || entry.connection == nullptr ||
        entry.connection->is_handshake_complete() ||
        //= https://www.rfc-editor.org/rfc/rfc9000#section-6.2
        // # A client MUST discard any Version Negotiation packet if it has
        // # received and successfully processed any other packet, including an
        // # earlier Version Negotiation packet.
        entry.connection->has_processed_peer_packet() ||
        entry.connection->config_.reacted_to_version_negotiation) {
        return std::nullopt;
    }

    const auto version_negotiation = parse_version_negotiation_packet(inbound_payload);
    if (!version_negotiation.has_value()) {
        return std::nullopt;
    }

    auto config = entry.connection->config_;
    const bool valid_destination_connection_id =
        version_negotiation->destination_connection_id == config.source_connection_id;
    const bool valid_source_connection_id =
        version_negotiation->source_connection_id == config.initial_destination_connection_id;
    const bool echoes_original_version =
        std::find(version_negotiation->supported_versions.begin(),
                  version_negotiation->supported_versions.end(),
                  config.original_version) != version_negotiation->supported_versions.end();
    if (!valid_destination_connection_id || !valid_source_connection_id) {
        return std::nullopt;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-6.2
    // # A client MUST discard a Version Negotiation packet that
    // # lists the QUIC version selected by the client.
    if (echoes_original_version) {
        return QuicCoreResult{};
    }

    for (const auto supported_version : config.supported_versions) {
        if (std::find(version_negotiation->supported_versions.begin(),
                      version_negotiation->supported_versions.end(),
                      supported_version) == version_negotiation->supported_versions.end()) {
            continue;
        }

        config.initial_version = supported_version;
        config.reacted_to_version_negotiation = true;
        erase_endpoint_connection_routes(entry);
        entry.connection = std::make_unique<QuicConnection>(std::move(config));
        entry.active_connection_id_keys.clear();
        entry.local_stateless_reset_connection_id_keys.clear();
        entry.peer_stateless_reset_token_keys.clear();
        entry.initial_destination_connection_id_key.reset();
        entry.endpoint_route_generation = 0;
        entry.default_route_handle = route_handle;
        if (route_handle.has_value()) {
            entry.path_id_by_route_handle[*route_handle] = path_id;
            entry.route_handle_by_path_id[path_id] = *route_handle;
        } else {
            entry.route_handle_by_path_id.erase(path_id);
        }
        entry.connection->last_inbound_path_id_ = path_id;
        entry.connection->current_send_path_id_ = path_id;
        entry.connection->ensure_path_state(path_id).is_current_send_path = true;
        remember_path_address_family(
            entry, path_id,
            route_address_family_from_identity(current_address_validation_identity(entry)));
        entry.connection->start(now);

        auto result = drain_connection_effects(entry.handle, entry.default_route_handle,
                                               entry.route_handle_by_path_id, *entry.connection,
                                               now, /*continue_paced_burst=*/false, send_sink);
        remember_client_new_tokens(entry, result);
        note_send_continuation(entry, result, now);
        refresh_server_connection_routes(entry);
        return result;
    }

    return QuicCoreResult{};
}

std::optional<QuicConnectionHandle>
    COQUIC_NO_PROFILE QuicCore::detect_stateless_reset(std::span<const std::byte> bytes) const {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # However, endpoints MUST treat any packet ending in a valid stateless
    // # reset token as a Stateless Reset, as other QUIC versions might allow
    // # the use of a long header.
    if (bytes.size() < kMinimumStatelessResetDatagramSize) {
        return std::nullopt;
    }

    std::array<std::byte, kStatelessResetTokenLength> token{};
    std::copy_n(bytes.end() - static_cast<std::ptrdiff_t>(token.size()), token.size(),
                token.begin());
    for (const auto &[key, route] : peer_stateless_reset_tokens_) {
        if (key.size() != token.size()) {
            continue;
        }
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.1
        // # When comparing a datagram to stateless reset token values, endpoints
        // # MUST perform the comparison without leaking information about the
        // # value of the token.
        if (CRYPTO_memcmp(key.data(), token.data(), token.size()) == 0) {
            return route.owner;
        }
    }
    return std::nullopt;
}

COQUIC_NO_PROFILE std::optional<QuicCoreSendDatagram>
QuicCore::make_stateless_reset_for_unknown_cid(const ParsedEndpointDatagram &parsed,
                                               std::span<const std::byte> inbound_bytes,
                                               const std::optional<QuicRouteHandle> &route_handle,
                                               QuicCoreTimePoint now) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # Endpoints MUST send Stateless Resets formatted as a packet with a
    // # short header.
    if (parsed.kind != ParsedEndpointDatagram::Kind::short_header ||
        inbound_bytes.size() < kMinimumStatelessResetDatagramSize) {
        return std::nullopt;
    }

    purge_expired_local_stateless_reset_tokens(now);

    const auto token_it = local_stateless_reset_tokens_by_cid_.find(
        connection_id_key(parsed.destination_connection_id));
    std::optional<LocalStatelessResetTokenRoute> derived_token_route;
    if (token_it == local_stateless_reset_tokens_by_cid_.end() &&
        endpoint_config_.stateless_reset_secret.has_value() &&
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
        // # An endpoint that uses this design MUST either use the same
        // # connection ID length for all connections or encode the length of
        // # the connection ID such that it can be recovered without state.
        parsed.destination_connection_id.size() == kEndpointConnectionIdLength &&
        parsed.destination_connection_id.front() == kServerConnectionIdPrefix) {
        if (const auto token = derive_stateless_reset_token(
                *endpoint_config_.stateless_reset_secret, parsed.destination_connection_id,
                /*sequence_number=*/0)) {
            derived_token_route = LocalStatelessResetTokenRoute{
                .owner = 0,
                .stateless_reset_token = *token,
            };
        }
    }
    const auto *token_route = token_it != local_stateless_reset_tokens_by_cid_.end()
                                  ? &token_it->second
                              : derived_token_route ? &*derived_token_route
                                                    : nullptr;
    if (token_route == nullptr) {
        return std::nullopt;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.3
    // # An endpoint MUST ensure that every Stateless Reset that it sends is
    // # smaller than the packet that triggered it, unless it maintains state
    // # sufficient to prevent looping.
    if (inbound_bytes.size() <= kMinimumStatelessResetDatagramSize) {
        return std::nullopt;
    }

    std::size_t reset_size = inbound_bytes.size() <= 43
                                 ? inbound_bytes.size() - 1u
                                 : std::min<std::size_t>(inbound_bytes.size() - 1u, 64u);
    reset_size = std::max(reset_size, kMinimumStatelessResetDatagramSize);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # An endpoint that sends a Stateless Reset in response to a packet that
    // # is 43 bytes or shorter SHOULD send a Stateless Reset that is one byte
    // # shorter than the packet it responds to.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # An endpoint MUST NOT send a Stateless Reset that is three times or
    // # more larger than the packet it receives to avoid being used for
    // # amplification.
    if (reset_size >= inbound_bytes.size() * 3u) {
        reset_size = std::max(kMinimumStatelessResetDatagramSize, inbound_bytes.size() - 1u);
    }

    DatagramBuffer bytes;
    bytes.resize(reset_size, std::byte{0x00});
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # The remainder of the first byte and an arbitrary number of bytes
    // # following it are set to values that SHOULD be indistinguishable from
    // # random.
    fill_random_bytes(bytes.span(), endpoint_random_);
    auto reset_bytes = bytes.span();
    reset_bytes.front() = static_cast<std::byte>(
        0x40u | (std::to_integer<std::uint8_t>(reset_bytes.front()) & 0x3fu));
    std::copy(token_route->stateless_reset_token.begin(), token_route->stateless_reset_token.end(),
              bytes.end() - static_cast<std::ptrdiff_t>(kStatelessResetTokenLength));

    return QuicCoreSendDatagram{
        .connection = token_route->owner,
        .route_handle = route_handle,
        .bytes = std::move(bytes),
    };
}

COQUIC_NO_PROFILE void QuicCore::load_consumed_address_validation_tokens() {
    consumed_address_validation_tokens_.clear();
#if defined(COQUIC_WASM_NO_FILESYSTEM)
    return;
#else
    if (!endpoint_config_.address_validation_replay_store_path.has_value()) {
        return;
    }

    std::ifstream input(*endpoint_config_.address_validation_replay_store_path);
    if (!input.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(input, line)) {
        const auto separator = line.find(' ');
        if (separator == std::string::npos) {
            continue;
        }
        const auto key = hex_decode_to_string(std::string_view(line).substr(0, separator));
        const auto expires_at_us =
            parse_unsigned_decimal(std::string_view(line).substr(separator + 1u));
        if (!key.has_value() || !expires_at_us.has_value() || key->empty()) {
            continue;
        }
        consumed_address_validation_tokens_[*key] = token_time_from_us(*expires_at_us);
    }
#endif
}

COQUIC_NO_PROFILE void QuicCore::persist_consumed_address_validation_tokens() {
#if defined(COQUIC_WASM_NO_FILESYSTEM)
    return;
#else
    if (!endpoint_config_.address_validation_replay_store_path.has_value()) {
        return;
    }

    const auto &path = *endpoint_config_.address_validation_replay_store_path;
    std::error_code ignored;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ignored);
    }

    const auto temporary = path.string() + ".tmp";
    {
        std::ofstream output(temporary, std::ios::trunc);
        if (!output.is_open()) {
            return;
        }
        for (const auto &[key, expires_at] : consumed_address_validation_tokens_) {
            const auto key_bytes = std::as_bytes(std::span(key.data(), key.size()));
            output << hex_encode_bytes(key_bytes) << ' ' << token_timestamp_us(expires_at) << '\n';
        }
    }

    std::filesystem::rename(temporary, path, ignored);
    if (ignored) {
        std::filesystem::remove(path, ignored);
        std::filesystem::rename(temporary, path, ignored);
    }
#endif
}

bool QuicCore::address_validation_token_consumed(std::span<const std::byte> token) const {
    return consumed_address_validation_tokens_.contains(address_validation_token_replay_key(token));
}

void QuicCore::mark_address_validation_token_consumed(std::span<const std::byte> token,
                                                      QuicCoreTimePoint expires_at) {
    consumed_address_validation_tokens_[address_validation_token_replay_key(token)] = expires_at;
    persist_consumed_address_validation_tokens();
}

std::span<const std::byte>
QuicCore::current_address_validation_identity(const ConnectionEntry &entry) const {
    if (entry.connection == nullptr || !entry.connection->current_send_path_id_.has_value()) {
        return {};
    }
    const auto identity_it =
        entry.address_validation_identity_by_path_id.find(*entry.connection->current_send_path_id_);
    if (identity_it == entry.address_validation_identity_by_path_id.end()) {
        return {};
    }
    return identity_it->second;
}

COQUIC_NO_PROFILE std::vector<std::byte> QuicCore::effective_address_validation_identity_for_route(
    const ConnectionEntry &entry, QuicRouteHandle route_handle,
    std::span<const std::byte> proposed_identity) const {
    if (!proposed_identity.empty()) {
        return std::vector<std::byte>(proposed_identity.begin(), proposed_identity.end());
    }

    const auto path_it = entry.path_id_by_route_handle.find(route_handle);
    if (path_it == entry.path_id_by_route_handle.end()) {
        return {};
    }
    const auto identity_it = entry.address_validation_identity_by_path_id.find(path_it->second);
    if (identity_it == entry.address_validation_identity_by_path_id.end()) {
        return {};
    }
    return identity_it->second;
}

bool QuicCore::address_validation_identity_allowed_for_new_route(
    const ConnectionEntry *entry, std::span<const std::byte> address_validation_identity) const {
    if (address_validation_identity.empty()) {
        return true;
    }

    const auto current_identity = entry != nullptr ? current_address_validation_identity(*entry)
                                                   : std::span<const std::byte>{};
    return address_identity_allowed_by_request_forgery_policy(
        endpoint_config_.request_forgery_policy, current_identity, address_validation_identity);
}

std::vector<std::byte> COQUIC_NO_PROFILE QuicCore::make_version_negotiation_packet_bytes(
    const ParsedEndpointDatagram &parsed, std::span<const std::uint32_t> supported_versions,
    bool grease_reserved_versions) {
    if (!parsed.source_connection_id.has_value() || supported_versions.empty()) {
        return {};
    }

    std::vector<std::uint32_t> advertised_versions(supported_versions.begin(),
                                                   supported_versions.end());
    if (grease_reserved_versions &&
        std::none_of(advertised_versions.begin(), advertised_versions.end(), is_reserved_version)) {
        advertised_versions.push_back(kGreasedReservedVersion);
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    // # The server MUST include the value from the Source Connection ID field
    // # of the packet it receives in the Destination Connection ID field.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
    // # The value for Source Connection ID MUST be copied from the
    // # Destination Connection ID of the received packet, which is initially
    // # randomly selected by a client.
    const auto encoded = serialize_packet(VersionNegotiationPacket{
        .destination_connection_id = *parsed.source_connection_id,
        .source_connection_id = parsed.destination_connection_id,
        .supported_versions = std::move(advertised_versions),
    });
    return encoded.has_value() ? DatagramBuffer(encoded.value()) : DatagramBuffer{};
}

std::vector<std::byte> QuicCore::make_retry_packet_bytes(const ParsedEndpointDatagram &parsed,
                                                         const PendingRetryToken &pending) {
    if (!parsed.source_connection_id.has_value()) {
        return {};
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
    // # This value MUST NOT be equal to the Destination
    // # Connection ID field of the packet sent by the client.
    if (pending.retry_source_connection_id == parsed.destination_connection_id) {
        return {};
    }

    RetryPacket packet{
        .version = parsed.version,
        .retry_unused_bits = 0,
        .destination_connection_id = *parsed.source_connection_id,
        .source_connection_id = pending.retry_source_connection_id,
        .retry_token = pending.token,
    };
    const auto integrity_tag =
        compute_retry_integrity_tag(packet, parsed.destination_connection_id);
    if (!integrity_tag.has_value()) {
        return {};
    }
    packet.retry_integrity_tag = integrity_tag.value();

    // Computing the Retry integrity tag already serialized the same validated Retry packet.
    return DatagramBuffer(serialize_packet(packet).value());
}

std::optional<QuicConnectionHandle>
QuicCore::find_endpoint_connection_for_datagram(const ParsedEndpointDatagram &parsed) const {
    const auto destination_connection_id_key = connection_id_key(parsed.destination_connection_id);
    const auto connection_it = connection_id_routes_.find(destination_connection_id_key);
    if (connection_it != connection_id_routes_.end()) {
        return connection_it->second;
    }

    if (parsed.kind != ParsedEndpointDatagram::Kind::supported_initial &&
        parsed.kind != ParsedEndpointDatagram::Kind::supported_long_header) {
        return std::nullopt;
    }

    const auto initial_it = initial_destination_routes_.find(destination_connection_id_key);
    if (initial_it == initial_destination_routes_.end()) {
        return std::nullopt;
    }
    return initial_it->second;
}

COQUIC_NO_PROFILE void QuicCore::erase_endpoint_connection_routes(const ConnectionEntry &entry) {
    for (const auto &connection_id_key_value : entry.active_connection_id_keys) {
        const auto it = connection_id_routes_.find(connection_id_key_value);
        if (it != connection_id_routes_.end() && it->second == entry.handle) {
            connection_id_routes_.erase(it);
        }
    }
    if (entry.initial_destination_connection_id_key.has_value()) {
        const auto it =
            initial_destination_routes_.find(*entry.initial_destination_connection_id_key);
        if (it != initial_destination_routes_.end() && it->second == entry.handle) {
            initial_destination_routes_.erase(it);
        }
    }
    for (const auto &connection_id_key_value : entry.local_stateless_reset_connection_id_keys) {
        const auto it = local_stateless_reset_tokens_by_cid_.find(connection_id_key_value);
        if (it != local_stateless_reset_tokens_by_cid_.end() && it->second.owner == entry.handle) {
            local_stateless_reset_tokens_by_cid_.erase(it);
        }
    }
    for (const auto &token_key : entry.peer_stateless_reset_token_keys) {
        const auto it = peer_stateless_reset_tokens_.find(token_key);
        if (it != peer_stateless_reset_tokens_.end() && it->second.owner == entry.handle) {
            peer_stateless_reset_tokens_.erase(it);
        }
    }
}

COQUIC_NO_PROFILE void QuicCore::retire_endpoint_connection_routes(const ConnectionEntry &entry,
                                                                   QuicCoreTimePoint now) {
    for (const auto &connection_id_key_value : entry.active_connection_id_keys) {
        const auto it = connection_id_routes_.find(connection_id_key_value);
        if (it != connection_id_routes_.end() && it->second == entry.handle) {
            connection_id_routes_.erase(it);
        }
    }
    if (entry.initial_destination_connection_id_key.has_value()) {
        const auto it =
            initial_destination_routes_.find(*entry.initial_destination_connection_id_key);
        if (it != initial_destination_routes_.end() && it->second == entry.handle) {
            initial_destination_routes_.erase(it);
        }
    }

    const auto reset_token_expiry =
        endpoint_config_.retain_stateless_reset_tokens_after_connection_close
            ? std::optional<QuicCoreTimePoint>{now +
                                               endpoint_config_.stateless_reset_token_retention}
            : std::nullopt;
    for (const auto &connection_id_key_value : entry.local_stateless_reset_connection_id_keys) {
        const auto it = local_stateless_reset_tokens_by_cid_.find(connection_id_key_value);
        if (it == local_stateless_reset_tokens_by_cid_.end() || it->second.owner != entry.handle) {
            continue;
        }
        if (reset_token_expiry.has_value()) {
            it->second.expires_at = reset_token_expiry;
        } else {
            local_stateless_reset_tokens_by_cid_.erase(it);
        }
    }
    for (const auto &token_key : entry.peer_stateless_reset_token_keys) {
        const auto it = peer_stateless_reset_tokens_.find(token_key);
        if (it != peer_stateless_reset_tokens_.end() && it->second.owner == entry.handle) {
            peer_stateless_reset_tokens_.erase(it);
        }
    }
}

COQUIC_NO_PROFILE void QuicCore::purge_expired_local_stateless_reset_tokens(QuicCoreTimePoint now) {
    if (now == QuicCoreTimePoint{}) {
        return;
    }
    for (auto it = local_stateless_reset_tokens_by_cid_.begin();
         it != local_stateless_reset_tokens_by_cid_.end();) {
        if (it->second.expires_at.has_value() && *it->second.expires_at <= now) {
            it = local_stateless_reset_tokens_by_cid_.erase(it);
        } else {
            ++it;
        }
    }
}

COQUIC_NO_PROFILE void QuicCore::refresh_server_connection_routes(ConnectionEntry &entry) {
    const auto current_generation = entry.connection->endpoint_route_generation();
    if (entry.endpoint_route_generation == current_generation) {
        return;
    }
    entry.endpoint_route_generation = current_generation;

    std::vector<std::string> active_connection_id_keys;
    for (const auto &connection_id : entry.connection->active_local_connection_ids()) {
        auto key = connection_id_key(connection_id);
        if (key.empty()) {
            continue;
        }
        connection_id_routes_[key] = entry.handle;
        active_connection_id_keys.push_back(std::move(key));
    }
    if (entry.connection->config_.role == EndpointRole::server &&
        entry.connection->config_.retry_source_connection_id.has_value() &&
        entry.connection->config_.original_destination_connection_id.has_value()) {
        auto key = connection_id_key(*entry.connection->config_.original_destination_connection_id);
        const auto key_already_active =
            std::find(active_connection_id_keys.begin(), active_connection_id_keys.end(), key) !=
            active_connection_id_keys.end();
        const auto existing_route = connection_id_routes_.find(key);
        if (!key.empty() && !key_already_active &&
            (existing_route == connection_id_routes_.end() ||
             existing_route->second == entry.handle)) {
            connection_id_routes_[key] = entry.handle;
            active_connection_id_keys.push_back(std::move(key));
        }
    }

    for (const auto &existing_key : entry.active_connection_id_keys) {
        if (std::find(active_connection_id_keys.begin(), active_connection_id_keys.end(),
                      existing_key) != active_connection_id_keys.end()) {
            continue;
        }
        const auto route_it = connection_id_routes_.find(existing_key);
        if (route_it != connection_id_routes_.end() && route_it->second == entry.handle) {
            connection_id_routes_.erase(route_it);
        }
    }
    entry.active_connection_id_keys = std::move(active_connection_id_keys);

    std::vector<std::string> local_stateless_reset_connection_id_keys;
    for (const auto &record : entry.connection->active_local_stateless_reset_tokens()) {
        auto key = connection_id_key(record.connection_id);
        if (key.empty()) {
            continue;
        }
        local_stateless_reset_tokens_by_cid_[key] = LocalStatelessResetTokenRoute{
            .owner = entry.handle,
            .stateless_reset_token = record.stateless_reset_token,
        };
        local_stateless_reset_connection_id_keys.push_back(std::move(key));
    }
    for (const auto &existing_key : entry.local_stateless_reset_connection_id_keys) {
        if (std::find(local_stateless_reset_connection_id_keys.begin(),
                      local_stateless_reset_connection_id_keys.end(),
                      existing_key) != local_stateless_reset_connection_id_keys.end()) {
            continue;
        }
        const auto route_it = local_stateless_reset_tokens_by_cid_.find(existing_key);
        if (route_it != local_stateless_reset_tokens_by_cid_.end() &&
            route_it->second.owner == entry.handle) {
            local_stateless_reset_tokens_by_cid_.erase(route_it);
        }
    }
    entry.local_stateless_reset_connection_id_keys =
        std::move(local_stateless_reset_connection_id_keys);

    std::vector<std::string> peer_stateless_reset_token_keys;
    for (const auto &record : entry.connection->peer_stateless_reset_tokens()) {
        auto key = stateless_reset_token_key(record.stateless_reset_token);
        peer_stateless_reset_tokens_[key] = PeerStatelessResetTokenRoute{
            .owner = entry.handle,
        };
        peer_stateless_reset_token_keys.push_back(std::move(key));
    }
    for (const auto &existing_key : entry.peer_stateless_reset_token_keys) {
        if (std::find(peer_stateless_reset_token_keys.begin(),
                      peer_stateless_reset_token_keys.end(),
                      existing_key) != peer_stateless_reset_token_keys.end()) {
            continue;
        }
        const auto route_it = peer_stateless_reset_tokens_.find(existing_key);
        if (route_it != peer_stateless_reset_tokens_.end() &&
            route_it->second.owner == entry.handle) {
            peer_stateless_reset_tokens_.erase(route_it);
        }
    }
    entry.peer_stateless_reset_token_keys = std::move(peer_stateless_reset_token_keys);

    auto next_initial_destination_key =
        connection_id_key(entry.connection->client_initial_destination_connection_id());
    if (entry.initial_destination_connection_id_key.has_value() &&
        entry.initial_destination_connection_id_key != next_initial_destination_key) {
        const auto initial_it =
            initial_destination_routes_.find(*entry.initial_destination_connection_id_key);
        if (initial_it != initial_destination_routes_.end() && initial_it->second == entry.handle) {
            initial_destination_routes_.erase(initial_it);
        }
    }

    if (next_initial_destination_key.empty()) {
        entry.initial_destination_connection_id_key.reset();
        return;
    }

    initial_destination_routes_[next_initial_destination_key] = entry.handle;
    entry.initial_destination_connection_id_key = next_initial_destination_key;
}

void QuicCore::remember_address_validation_identity(
    ConnectionEntry &entry, QuicPathId path_id,
    std::span<const std::byte> address_validation_identity) {
    if (address_validation_identity.empty()) {
        return;
    }

    auto identity_it = entry.address_validation_identity_by_path_id.find(path_id);
    if (identity_it != entry.address_validation_identity_by_path_id.end()) {
        if (std::ranges::equal(identity_it->second, address_validation_identity)) {
            return;
        }
        identity_it->second.assign(address_validation_identity.begin(),
                                   address_validation_identity.end());
        return;
    }

    entry.address_validation_identity_by_path_id.emplace(
        path_id, std::vector<std::byte>(address_validation_identity.begin(),
                                        address_validation_identity.end()));
}

void QuicCore::remember_path_address_family(ConnectionEntry &entry, QuicPathId path_id,
                                            QuicRouteAddressFamily family) {
    if (family == QuicRouteAddressFamily::unknown) {
        return;
    }

    const auto [it, inserted] = entry.address_family_by_path_id.try_emplace(path_id, family);
    if (!inserted && it->second == family) {
        return;
    }
    if (!inserted) {
        it->second = family;
    }
    if (entry.connection != nullptr) {
        entry.connection->set_path_default_pmtud_search_ceiling(
            path_id, QuicDefaultPmtudSearchCeiling{
                         .value = default_pmtud_search_ceiling_for_route_family(family),
                     });
    }
}

COQUIC_NO_PROFILE QuicPathId
QuicCore::remember_inbound_path(ConnectionEntry &entry, QuicRouteHandle route_handle,
                                std::span<const std::byte> address_validation_identity) {
    const auto address_family = route_address_family_from_identity(address_validation_identity);
    if (!entry.default_route_handle.has_value()) {
        entry.default_route_handle = route_handle;
    }

    const auto existing = entry.path_id_by_route_handle.find(route_handle);
    if (existing != entry.path_id_by_route_handle.end()) {
        remember_address_validation_identity(entry, existing->second, address_validation_identity);
        remember_path_address_family(entry, existing->second, address_family);
        return existing->second;
    }

    QuicPathId path_id =
        entry.route_handle_by_path_id.empty() ? kDefaultPathId : entry.next_path_id++;
    while (entry.route_handle_by_path_id.contains(path_id)) {
        path_id = entry.next_path_id++;
    }

    entry.path_id_by_route_handle.emplace(route_handle, path_id);
    entry.route_handle_by_path_id.emplace(path_id, route_handle);
    remember_address_validation_identity(entry, path_id, address_validation_identity);
    remember_path_address_family(entry, path_id, address_family);
    return path_id;
}

std::optional<QuicPathId> COQUIC_NO_PROFILE QuicCore::path_id_for_inbound_route(
    ConnectionEntry &entry, const std::optional<QuicRouteHandle> &route_handle,
    std::span<const std::byte> address_validation_identity) {
    if (route_handle.has_value()) {
        const auto existing = entry.path_id_by_route_handle.find(*route_handle);
        if (existing != entry.path_id_by_route_handle.end()) {
            remember_address_validation_identity(entry, existing->second,
                                                 address_validation_identity);
            return existing->second;
        }
        if (!endpoint_config_.allow_peer_address_change) {
            return std::nullopt;
        }
        if (!address_validation_identity_allowed_for_new_route(&entry,
                                                               address_validation_identity)) {
            return std::nullopt;
        }
        return remember_inbound_path(entry, *route_handle, address_validation_identity);
    }

    if (entry.default_route_handle.has_value()) {
        return remember_inbound_path(entry, *entry.default_route_handle,
                                     address_validation_identity);
    }
    return kDefaultPathId;
}

std::optional<QuicRouteHandle>
QuicCore::route_handle_for_path(const ConnectionEntry &entry,
                                const std::optional<QuicPathId> &path_id) {
    if (path_id.has_value()) {
        const auto route_it = entry.route_handle_by_path_id.find(*path_id);
        if (route_it != entry.route_handle_by_path_id.end()) {
            return route_it->second;
        }
    }
    return entry.default_route_handle;
}

bool QuicCore::should_run_connection_timeout(const ConnectionEntry &entry, QuicCoreTimePoint now) {
    return !entry.send_continuation_wakeup.has_value() &&
           entry.connection->non_pacing_wakeup_due(now);
}

void QuicCore::maybe_run_connection_timeout(ConnectionEntry &entry, QuicCoreTimePoint now) {
    if (should_run_connection_timeout(entry, now)) {
        entry.connection->on_timeout(now);
    }
}

template <typename Entry>
COQUIC_NO_PROFILE void store_send_continuation_wakeup(Entry &entry, bool send_continuation_pending,
                                                      QuicCoreTimePoint now) {
    entry.send_continuation_wakeup =
        send_continuation_pending ? std::optional<QuicCoreTimePoint>{now} : std::nullopt;
    entry.send_continuation_drain = send_continuation_pending;
}

template <typename Entry>
COQUIC_NO_PROFILE std::optional<QuicCoreTimePoint> next_entry_wakeup(const Entry &entry) {
    return entry.send_continuation_wakeup.has_value() ? entry.send_continuation_wakeup
                                                      : entry.connection->next_wakeup();
}

template <typename Entry>
COQUIC_NO_PROFILE std::optional<QuicPathId>
path_id_for_route_handle(const Entry &entry, const std::optional<QuicRouteHandle> &route_handle) {
    if (!has_route_handle(route_handle)) {
        return std::nullopt;
    }
    const auto route_handle_value = optional_ref_or_abort(route_handle);
    const auto path_it = entry.path_id_by_route_handle.find(route_handle_value);
    if (path_it == entry.path_id_by_route_handle.end()) {
        return std::nullopt;
    }
    return path_it->second;
}

QuicCore::QuicCore(QuicCoreEndpointConfig config)
    : endpoint_config_(std::move(config)), endpoint_random_(std::random_device{}()),
      connection_(this) {
    load_consumed_address_validation_tokens();
}

QuicCore::QuicCore(QuicCoreConfig config)
    : endpoint_config_(QuicCoreEndpointConfig{
          .role = config.role,
          .supported_versions = config.supported_versions,
          .verify_peer = config.verify_peer,
          .application_protocol = config.application_protocol,
          .identity = config.identity,
          .transport = config.transport,
          .allowed_tls_cipher_suites = config.allowed_tls_cipher_suites,
          .zero_rtt = config.zero_rtt,
          .qlog = config.qlog,
          .tls_keylog_path = config.tls_keylog_path,
          .stateless_reset_secret = config.stateless_reset_secret,
          .address_validation_token_secret = config.address_validation_token_secret,
          .previous_address_validation_token_secrets =
              config.previous_address_validation_token_secrets,
          .address_validation_replay_store_path = config.address_validation_replay_store_path,
          .request_forgery_policy = config.request_forgery_policy,
          .emit_shared_receive_stream_data = config.emit_shared_receive_stream_data,
          .enable_packet_inspection = config.enable_packet_inspection,
      }),
      legacy_config_(std::move(config)), endpoint_random_(std::random_device{}()),
      connection_(this) {
    load_consumed_address_validation_tokens();
    static_cast<void>(ensure_legacy_entry());
}

QuicCore::~QuicCore() = default;

QuicCore::QuicCore(QuicCore &&other) noexcept
    : endpoint_config_(std::move(other.endpoint_config_)),
      legacy_config_(std::move(other.legacy_config_)), connections_(std::move(other.connections_)),
      connection_id_routes_(std::move(other.connection_id_routes_)),
      initial_destination_routes_(std::move(other.initial_destination_routes_)),
      retry_tokens_(std::move(other.retry_tokens_)), new_tokens_(std::move(other.new_tokens_)),
      consumed_address_validation_tokens_(std::move(other.consumed_address_validation_tokens_)),
      client_new_tokens_(std::move(other.client_new_tokens_)),
      local_stateless_reset_tokens_by_cid_(std::move(other.local_stateless_reset_tokens_by_cid_)),
      peer_stateless_reset_tokens_(std::move(other.peer_stateless_reset_tokens_)),
      legacy_connection_handle_(other.legacy_connection_handle_),
      next_connection_handle_(other.next_connection_handle_),
      next_server_connection_id_sequence_(other.next_server_connection_id_sequence_),
      endpoint_random_(other.endpoint_random_), connection_(this),
      wakeup_heap_(std::move(other.wakeup_heap_)),
      wakeup_cache_initialized_(other.wakeup_cache_initialized_) {
    other.connection_.owner = &other;
    other.wakeup_cache_initialized_ = false;
    other.wakeup_heap_ = {};
}

QuicCore &QuicCore::operator=(QuicCore &&other) noexcept {
    if (this == &other) {
        return *this;
    }
    endpoint_config_ = std::move(other.endpoint_config_);
    legacy_config_ = std::move(other.legacy_config_);
    connections_ = std::move(other.connections_);
    connection_id_routes_ = std::move(other.connection_id_routes_);
    initial_destination_routes_ = std::move(other.initial_destination_routes_);
    retry_tokens_ = std::move(other.retry_tokens_);
    new_tokens_ = std::move(other.new_tokens_);
    consumed_address_validation_tokens_ = std::move(other.consumed_address_validation_tokens_);
    client_new_tokens_ = std::move(other.client_new_tokens_);
    local_stateless_reset_tokens_by_cid_ = std::move(other.local_stateless_reset_tokens_by_cid_);
    peer_stateless_reset_tokens_ = std::move(other.peer_stateless_reset_tokens_);
    legacy_connection_handle_ = other.legacy_connection_handle_;
    next_connection_handle_ = other.next_connection_handle_;
    next_server_connection_id_sequence_ = other.next_server_connection_id_sequence_;
    endpoint_random_ = other.endpoint_random_;
    connection_.owner = this;
    other.connection_.owner = &other;
    wakeup_heap_ = std::move(other.wakeup_heap_);
    wakeup_cache_initialized_ = other.wakeup_cache_initialized_;
    other.wakeup_cache_initialized_ = false;
    other.wakeup_heap_ = {};
    return *this;
}

void QuicCore::rebuild_wakeup_cache() const {
    wakeup_heap_ = {};
    for (const auto &[handle, entry] : connections_) {
        (void)handle;
        if (entry.connection == nullptr) {
            entry.cached_next_wakeup = std::nullopt;
            ++entry.wakeup_generation;
            continue;
        }
        entry.cached_next_wakeup = next_entry_wakeup(entry);
        ++entry.wakeup_generation;
        if (entry.cached_next_wakeup.has_value()) {
            wakeup_heap_.push(WakeupHeapEntry{
                .wakeup = *entry.cached_next_wakeup,
                .connection = entry.handle,
                .generation = entry.wakeup_generation,
            });
        }
    }
    wakeup_cache_initialized_ = true;
}

void QuicCore::refresh_entry_wakeup(const ConnectionEntry &entry) const {
    if (!wakeup_cache_initialized_) {
        return;
    }
    entry.cached_next_wakeup =
        entry.connection == nullptr ? std::optional<QuicCoreTimePoint>{} : next_entry_wakeup(entry);
    ++entry.wakeup_generation;
    if (entry.cached_next_wakeup.has_value()) {
        wakeup_heap_.push(WakeupHeapEntry{
            .wakeup = *entry.cached_next_wakeup,
            .connection = entry.handle,
            .generation = entry.wakeup_generation,
        });
    }
}

void QuicCore::ensure_wakeup_cache() const {
    if (!wakeup_cache_initialized_) {
        rebuild_wakeup_cache();
    }
}

std::optional<QuicCoreTimePoint> QuicCore::next_wakeup() const {
    ensure_wakeup_cache();
    while (!wakeup_heap_.empty()) {
        const auto top = wakeup_heap_.top();
        const auto entry_it = connections_.find(top.connection);
        if (entry_it == connections_.end() || entry_it->second.connection == nullptr ||
            entry_it->second.wakeup_generation != top.generation ||
            !entry_it->second.cached_next_wakeup.has_value() ||
            *entry_it->second.cached_next_wakeup != top.wakeup) {
            wakeup_heap_.pop();
            continue;
        }
        return top.wakeup;
    }
    return std::nullopt;
}

std::vector<QuicConnectionHandle> QuicCore::due_connection_handles(QuicCoreTimePoint now) const {
    ensure_wakeup_cache();
    std::vector<QuicConnectionHandle> due;
    for (std::uint8_t attempt = 0; attempt < 2; ++attempt) {
        while (!wakeup_heap_.empty()) {
            const auto top = wakeup_heap_.top();
            const auto entry_it = connections_.find(top.connection);
            if (entry_it == connections_.end() || entry_it->second.connection == nullptr ||
                entry_it->second.wakeup_generation != top.generation ||
                !entry_it->second.cached_next_wakeup.has_value() ||
                *entry_it->second.cached_next_wakeup != top.wakeup) {
                wakeup_heap_.pop();
                continue;
            }
            if (top.wakeup > now) {
                break;
            }
            due.push_back(top.connection);
            wakeup_heap_.pop();
            ++entry_it->second.wakeup_generation;
            entry_it->second.cached_next_wakeup = std::nullopt;
        }
        if (!due.empty() || attempt != 0) {
            break;
        }
        rebuild_wakeup_cache();
    }
    return due;
}

void QuicCore::note_send_continuation(ConnectionEntry &entry, const QuicCoreResult &result,
                                      QuicCoreTimePoint now) const {
    store_send_continuation_wakeup(entry, result.send_continuation_pending, now);
    refresh_entry_wakeup(entry);
}

bool QuicCore::take_send_continuation_drain(ConnectionEntry &entry) {
    const bool continue_paced_burst = entry.send_continuation_drain;
    entry.send_continuation_drain = false;
    return continue_paced_burst;
}

QuicCoreResult QuicCore::finalize_endpoint_result(QuicCoreResult result, QuicCoreTimePoint now) {
    result.next_wakeup = next_wakeup();
    clamp_result_wakeup_to_now_if_continuation_pending(result, now);
    return result;
}

QuicCoreResult QuicCore::finalize_legacy_result(QuicCoreResult result, QuicCoreTimePoint now) {
    maybe_note_legacy_send_continuation(
        legacy_entry(), result, now,
        [&](ConnectionEntry &entry, const QuicCoreResult &legacy_result,
            QuicCoreTimePoint wakeup_time) {
            note_send_continuation(entry, legacy_result, wakeup_time);
        });
    result.next_wakeup = next_wakeup();
    clamp_result_wakeup_to_now_if_continuation_pending(result, now);
    return result;
}

std::size_t QuicCore::connection_count() const {
    return connections_.size();
}

std::vector<QuicCoreConnectionDiagnostics> QuicCore::connection_diagnostics() const {
    std::vector<QuicCoreConnectionDiagnostics> out;
    out.reserve(connections_.size());
    for (const auto &[handle, entry] : connections_) {
        if (entry.connection == nullptr) {
            continue;
        }
        out.push_back(entry.connection->diagnostics(handle));
    }
    return out;
}

bool QuicCore::has_send_continuation_pending() const {
    const bool pending =
        std::any_of(connections_.begin(), connections_.end(), [](const auto &entry) {
            return entry.second.connection != nullptr &&
                   entry.second.send_continuation_wakeup.has_value();
        });
    if (pending) {
        rebuild_wakeup_cache();
    }
    return pending;
}

QuicCoreResult QuicCore::advance_endpoint(QuicCoreEndpointInput input, QuicCoreTimePoint now) {
    return advance_endpoint_impl(std::move(input), now, nullptr);
}

QuicCoreResult QuicCore::advance_endpoint(QuicCoreEndpointInput input, QuicCoreTimePoint now,
                                          QuicCoreSendDatagramSink &send_sink) {
    return advance_endpoint_impl(std::move(input), now, &send_sink);
}

QuicCoreResult QuicCore::advance_endpoint_impl(QuicCoreEndpointInput input, QuicCoreTimePoint now,
                                               QuicCoreSendDatagramSink *send_sink) {
    if (const auto *open = std::get_if<QuicCoreOpenConnection>(&input)) {
        if (endpoint_config_.role != EndpointRole::client) {
            (void)now;
            QuicCoreResult result;
            result.local_error = QuicCoreLocalError{
                .connection = std::nullopt,
                .code = QuicCoreLocalErrorCode::unsupported_operation,
                .stream_id = std::nullopt,
            };
            result.next_wakeup = next_wakeup();
            return result;
        }

        auto retry_token = open->connection.retry_token;
        if (retry_token.empty()) {
            if (auto stored_token = take_client_new_token_for_open(open->connection)) {
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
                // # When connecting to a server for which the client retains an
                // # applicable and unused token, it SHOULD include that token
                // # in the Token field of its Initial packet.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
                // # The client MUST NOT use the token provided in a Retry for
                // # future connections.
                //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
                // # In comparison, a token obtained in a Retry packet MUST be
                // # used immediately during the connection attempt and cannot be
                // # used in subsequent connection attempts.
                retry_token = std::move(*stored_token);
            }
        }

        QuicCoreConfig config{
            .role = endpoint_config_.role,
            .source_connection_id = open->connection.source_connection_id,
            .initial_destination_connection_id = open->connection.initial_destination_connection_id,
            .original_destination_connection_id =
                open->connection.original_destination_connection_id,
            .retry_source_connection_id = open->connection.retry_source_connection_id,
            .retry_token = std::move(retry_token),
            .original_version = open->connection.original_version,
            .initial_version = open->connection.initial_version,
            .supported_versions = endpoint_config_.supported_versions,
            .reacted_to_version_negotiation = open->connection.reacted_to_version_negotiation,
            .verify_peer = endpoint_config_.verify_peer,
            .server_name = open->connection.server_name,
            .application_protocol = endpoint_config_.application_protocol,
            .identity = endpoint_config_.identity,
            .transport = endpoint_config_.transport,
            .max_outbound_datagram_size = endpoint_config_.max_outbound_datagram_size,
            .allowed_tls_cipher_suites = endpoint_config_.allowed_tls_cipher_suites,
            .resumption_state = open->connection.resumption_state,
            .zero_rtt = open->connection.zero_rtt,
            .qlog = endpoint_config_.qlog,
            .tls_keylog_path = endpoint_config_.tls_keylog_path,
            .stateless_reset_secret = endpoint_config_.stateless_reset_secret,
            .address_validation_token_secret = endpoint_config_.address_validation_token_secret,
            .previous_address_validation_token_secrets =
                endpoint_config_.previous_address_validation_token_secrets,
            .address_validation_replay_store_path =
                endpoint_config_.address_validation_replay_store_path,
            .request_forgery_policy = endpoint_config_.request_forgery_policy,
            .emit_shared_receive_stream_data = endpoint_config_.emit_shared_receive_stream_data,
            .enable_packet_inspection = endpoint_config_.enable_packet_inspection,
        };

        auto handle = next_connection_handle_++;
        auto inserted_connection = connections_.try_emplace(handle);
        auto connection_iter = inserted_connection.first;
        auto &entry = connection_iter->second;
        entry = {};
        entry.handle = handle;
        entry.default_route_handle = open->initial_route_handle;
        entry.connection = std::make_unique<QuicConnection>(std::move(config));
        entry.path_id_by_route_handle.emplace(open->initial_route_handle, 0);
        entry.route_handle_by_path_id.emplace(0, open->initial_route_handle);
        if (!open->address_validation_identity.empty()) {
            if (!address_validation_identity_allowed_for_new_route(
                    nullptr, open->address_validation_identity)) {
                connections_.erase(connection_iter);
                QuicCoreResult denied;
                denied.local_error = QuicCoreLocalError{
                    .connection = handle,
                    .code = QuicCoreLocalErrorCode::unsupported_operation,
                    .stream_id = std::nullopt,
                };
                return finalize_endpoint_result(std::move(denied), now);
            }
            entry.address_validation_identity_by_path_id.emplace(0,
                                                                 open->address_validation_identity);
        }
        remember_path_address_family(
            entry, kDefaultPathId,
            route_address_family_from_identity(open->address_validation_identity));
        entry.connection->start(now);
        refresh_server_connection_routes(entry);

        auto result =
            drain_connection_effects(handle, entry.default_route_handle,
                                     entry.route_handle_by_path_id, *entry.connection, now,
                                     /*continue_paced_burst=*/false, send_sink);
        result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
            .connection = handle,
            .event = QuicCoreConnectionLifecycle::created,
        });
        note_send_continuation(entry, result, now);
        return finalize_endpoint_result(std::move(result), now);
    }

    if (auto *inbound = std::get_if<QuicCoreInboundDatagram>(&input); inbound != nullptr) {
        QuicCoreResult result;
        const auto inbound_payload = inbound->payload();
        const auto drain_stateless_reset_owner = [&](QuicConnectionHandle owner) -> bool {
            const auto entry_it = connections_.find(owner);
            if (entry_it == connections_.end() || entry_it->second.connection == nullptr) {
                return false;
            }

            entry_it->second.connection->enter_stateless_reset_draining(now);
            auto drained = drain_connection_effects(
                entry_it->second.handle, entry_it->second.default_route_handle,
                entry_it->second.route_handle_by_path_id, *entry_it->second.connection, now,
                /*continue_paced_burst=*/false, send_sink);
            append_result(result, std::move(drained));
            bool remove_entry =
                should_remove_endpoint_connection_entry(*entry_it->second.connection, result, now);
            refresh_server_connection_routes(entry_it->second);
            if (remove_entry) {
                retire_endpoint_connection_routes(entry_it->second, now);
                ++entry_it->second.wakeup_generation;
                connections_.erase(entry_it);
            } else {
                refresh_entry_wakeup(entry_it->second);
            }
            return true;
        };

        if (endpoint_config_.role == EndpointRole::client &&
            parse_version_negotiation_packet(inbound_payload).has_value()) {
            for (auto &[handle, entry] : connections_) {
                (void)handle;
                if (entry.connection == nullptr) {
                    continue;
                }
                const auto path_id = path_id_for_inbound_route(
                    entry, inbound->route_handle, inbound->address_validation_identity);
                if (!path_id.has_value()) {
                    continue;
                }
                auto version_negotiation = maybe_process_client_endpoint_version_negotiation(
                    entry, inbound_payload, inbound->route_handle, *path_id, now, send_sink);
                if (!version_negotiation.has_value()) {
                    continue;
                }
                if (should_remove_endpoint_connection_entry(*entry.connection, *version_negotiation,
                                                            now)) {
                    retire_endpoint_connection_routes(entry, now);
                    ++entry.wakeup_generation;
                    connections_.erase(handle);
                } else {
                    refresh_entry_wakeup(entry);
                }
                return finalize_endpoint_result(std::move(*version_negotiation), now);
            }
        }

        auto parsed =
            parse_endpoint_datagram(inbound_payload, endpoint_config_.transport.grease_quic_bit);
        if (!parsed.has_value()) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.1
            // # However, the comparison MUST be performed when the first
            // # packet in an incoming datagram either cannot be associated with
            // # a connection or cannot be decrypted.
            if (const auto reset_owner = detect_stateless_reset(inbound_payload);
                reset_owner.has_value()) {
                static_cast<void>(drain_stateless_reset_owner(*reset_owner));
            }
            return finalize_endpoint_result(std::move(result), now);
        }

        if (const auto handle = find_endpoint_connection_for_datagram(*parsed);
            handle.has_value()) {
            auto entry_it = connections_.find(*handle);
            if (entry_it != connections_.end()) {
                auto &entry = entry_it->second;
                //= https://www.rfc-editor.org/rfc/rfc9000#section-11
                // # A stateless reset MUST NOT be used by an endpoint that has
                // # the state necessary to send a frame on the connection.
                const auto path_id = path_id_for_inbound_route(
                    entry, inbound->route_handle, inbound->address_validation_identity);
                if (!path_id.has_value()) {
                    return finalize_endpoint_result(std::move(result), now);
                }
                QuicInboundDatagramResult inbound_result;
                if (inbound->shared_bytes != nullptr) {
                    inbound_result = entry.connection->process_inbound_datagram_shared(
                        std::move(inbound->shared_bytes), inbound->begin, inbound->end, now,
                        *path_id, inbound->ecn);
                } else {
                    inbound_result = entry.connection->process_inbound_datagram_owned(
                        std::move(inbound->bytes), now, *path_id, inbound->ecn);
                }
                if (!inbound_result.processed_any_packet) {
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.1
                    // # However, the comparison MUST be performed when the
                    // # first packet in an incoming datagram either cannot be
                    // # associated with a connection or cannot be decrypted.
                    if (const auto reset_owner = detect_stateless_reset(inbound_payload);
                        reset_owner.has_value()) {
                        static_cast<void>(drain_stateless_reset_owner(*reset_owner));
                        return finalize_endpoint_result(std::move(result), now);
                    }
                }

                auto drained = drain_connection_effects(
                    entry.handle, entry.default_route_handle, entry.route_handle_by_path_id,
                    *entry.connection, now, take_send_continuation_drain(entry), send_sink);
                drain_queued_server_new_token(entry, drained, now, send_sink);
                bool remove_entry =
                    should_remove_endpoint_connection_entry(*entry.connection, drained, now);
                remember_client_new_tokens(entry, drained);
                note_send_continuation(entry, drained, now);
                append_result(result, std::move(drained));
                refresh_server_connection_routes(entry);
                if (remove_entry) {
                    retire_endpoint_connection_routes(entry, now);
                    ++entry.wakeup_generation;
                    connections_.erase(entry_it);
                }
                return finalize_endpoint_result(std::move(result), now);
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.1
        // # However, the comparison MUST be performed when the first packet in
        // # an incoming datagram either cannot be associated with a connection
        // # or cannot be decrypted.
        if (const auto reset_owner = detect_stateless_reset(inbound_payload);
            reset_owner.has_value()) {
            static_cast<void>(drain_stateless_reset_owner(*reset_owner));
            return finalize_endpoint_result(std::move(result), now);
        }

        if (endpoint_config_.role != EndpointRole::server) {
            return finalize_endpoint_result(std::move(result), now);
        }

        const bool endpoint_supports_version =
            std::find(endpoint_config_.supported_versions.begin(),
                      endpoint_config_.supported_versions.end(),
                      parsed->version) != endpoint_config_.supported_versions.end();
        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
        // # Version-specific rules for the connection ID therefore MUST NOT
        // # influence a decision about whether to send a Version Negotiation
        // # packet.
        bool should_send_version_negotiation =
            parsed->kind == ParsedEndpointDatagram::Kind::unsupported_version_long_header ||
            ((parsed->kind == ParsedEndpointDatagram::Kind::supported_initial ||
              parsed->kind == ParsedEndpointDatagram::Kind::supported_long_header) &&
             !endpoint_supports_version);
        if (should_send_version_negotiation) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
            // # If a server receives a packet that indicates an unsupported version
            // # and if the packet is large enough to initiate a new connection for
            // # any supported version, the server SHOULD send a Version Negotiation
            // # packet as described in Section 6.1.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
            // # Servers SHOULD respond with a Version
            // # Negotiation packet, provided that the datagram is sufficiently long.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
            // # Servers MUST drop smaller packets that specify unsupported versions.
            if (inbound_payload.size() >= kMinimumClientInitialDatagramBytes) {
                const auto advertised_versions = endpoint_config_.supported_versions;
                auto bytes = make_version_negotiation_packet_bytes(
                    *parsed, advertised_versions,
                    endpoint_config_.transport.grease_reserved_versions);
                if (!bytes.empty()) {
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.1
                    // # A server MUST NOT send more than one Version Negotiation packet
                    // # in response to a single UDP datagram.
                    emit_send_datagram(result,
                                       QuicCoreSendDatagram{
                                           .connection = 0,
                                           .route_handle = inbound->route_handle,
                                           .bytes = DatagramBuffer(std::move(bytes)),
                                       },
                                       send_sink);
                }
            }
            return finalize_endpoint_result(std::move(result), now);
        }

        if (parsed->kind != ParsedEndpointDatagram::Kind::supported_initial) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
            // # Clients are not able to send Handshake packets prior to
            // # receiving a server response, so servers SHOULD ignore any such
            // # packets.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-5.2.2
            // # Servers MUST drop incoming packets under all other circumstances.
            if (auto reset = make_stateless_reset_for_unknown_cid(*parsed, inbound_payload,
                                                                  inbound->route_handle, now)) {
                emit_send_datagram(result, std::move(*reset), send_sink);
            }
            return finalize_endpoint_result(std::move(result), now);
        }

        if (inbound_payload.size() < kMinimumClientInitialDatagramBytes) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
            // # A server MUST discard an Initial packet that is carried in a
            // # UDP datagram with a payload that is smaller than the smallest
            // # allowed maximum datagram size of 1200 bytes.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14
            // # Therefore, an endpoint MUST NOT close a connection when it
            // # receives a datagram that does not meet size constraints; the
            // # endpoint MAY discard such datagrams.
            return finalize_endpoint_result(std::move(result), now);
        }
        if (!address_validation_identity_allowed_for_new_route(
                nullptr, inbound->address_validation_identity)) {
            return finalize_endpoint_result(std::move(result), now);
        }

        std::optional<PendingRetryToken> retry_context;
        std::optional<StoredEndpointNewToken> new_token_context;
        if (!parsed->token.empty()) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
            // # When a server receives an Initial packet with an address
            // # validation token, it MUST attempt to validate the token,
            // # unless it has already completed address validation.
            new_token_context = take_new_token_context(*parsed, inbound->route_handle, now,
                                                       inbound->address_validation_identity);
        }
        if (endpoint_config_.retry_enabled) {
            retry_context = take_retry_context(*parsed, inbound->route_handle, now,
                                               inbound->address_validation_identity);
            if (!retry_context.has_value()) {
                if (!parsed->token.empty() && !new_token_context.has_value()) {
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
                    // # Servers MAY discard any Initial packet that does not
                    // # carry the expected token.
                    return finalize_endpoint_result(std::move(result), now);
                }

                const auto sequence = next_server_connection_id_sequence_++;
                auto retry_source_connection_id = make_endpoint_connection_id(
                    kServerConnectionIdPrefix, sequence, endpoint_random_);
                PendingRetryToken pending{
                    .original_destination_connection_id = parsed->destination_connection_id,
                    .retry_source_connection_id = retry_source_connection_id,
                    .original_version = parsed->version,
                    .token = make_endpoint_retry_token(
                        sequence, &*parsed, &retry_source_connection_id, inbound->route_handle,
                        inbound->address_validation_identity, now),
                    .route_handle = inbound->route_handle,
                    .address_validation_identity = inbound->address_validation_identity,
                    .expires_at = now + kRetryTokenLifetime,
                };
                retry_tokens_.insert_or_assign(connection_id_key(pending.token), pending);

                auto bytes = make_retry_packet_bytes(*parsed, pending);
                if (!bytes.empty()) {
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
                    // # A server MUST NOT send more than one Retry
                    // # packet in response to a single UDP datagram.
                    emit_send_datagram(result,
                                       QuicCoreSendDatagram{
                                           .connection = 0,
                                           .route_handle = inbound->route_handle,
                                           .bytes = DatagramBuffer(std::move(bytes)),
                                       },
                                       send_sink);
                }
                return finalize_endpoint_result(std::move(result), now);
            }
        }

        QuicCoreConfig config{
            .role = EndpointRole::server,
            .source_connection_id =
                retry_context.has_value()
                    ? retry_context->retry_source_connection_id
                    : make_endpoint_connection_id(kServerConnectionIdPrefix,
                                                  next_server_connection_id_sequence_++,
                                                  endpoint_random_),
            .original_version = parsed->version,
            .initial_version = parsed->version,
            .supported_versions = endpoint_config_.supported_versions,
            .verify_peer = endpoint_config_.verify_peer,
            .application_protocol = endpoint_config_.application_protocol,
            .identity = endpoint_config_.identity,
            .transport = endpoint_config_.transport,
            .max_outbound_datagram_size = endpoint_config_.max_outbound_datagram_size,
            .allowed_tls_cipher_suites = endpoint_config_.allowed_tls_cipher_suites,
            .zero_rtt = endpoint_config_.zero_rtt,
            .qlog = endpoint_config_.qlog,
            .tls_keylog_path = endpoint_config_.tls_keylog_path,
            .stateless_reset_secret = endpoint_config_.stateless_reset_secret,
            .address_validation_token_secret = endpoint_config_.address_validation_token_secret,
            .previous_address_validation_token_secrets =
                endpoint_config_.previous_address_validation_token_secrets,
            .address_validation_replay_store_path =
                endpoint_config_.address_validation_replay_store_path,
            .request_forgery_policy = endpoint_config_.request_forgery_policy,
            .emit_shared_receive_stream_data = endpoint_config_.emit_shared_receive_stream_data,
            .enable_packet_inspection = endpoint_config_.enable_packet_inspection,
        };
        if (retry_context.has_value()) {
            config.initial_destination_connection_id = retry_context->retry_source_connection_id;
            config.original_destination_connection_id =
                retry_context->original_destination_connection_id;
            config.retry_source_connection_id = retry_context->retry_source_connection_id;
            config.original_version = retry_context->original_version;
            config.initial_version = retry_context->original_version;
        }

        auto entry = ConnectionEntry{
            .handle = next_connection_handle_++,
            .default_route_handle = inbound->route_handle,
            .connection = std::make_unique<QuicConnection>(std::move(config)),
        };
        auto path_id = inbound->route_handle.has_value()
                           ? remember_inbound_path(entry, *inbound->route_handle,
                                                   inbound->address_validation_identity)
                           : kDefaultPathId;
        if (!inbound->route_handle.has_value() && !inbound->address_validation_identity.empty()) {
            entry.address_validation_identity_by_path_id[path_id] =
                inbound->address_validation_identity;
        }
        if (inbound->shared_bytes != nullptr) {
            entry.connection->process_inbound_datagram_shared(std::move(inbound->shared_bytes),
                                                              inbound->begin, inbound->end, now,
                                                              path_id, inbound->ecn);
        } else {
            entry.connection->process_inbound_datagram_owned(std::move(inbound->bytes), now,
                                                             path_id, inbound->ecn);
        }
        if (new_token_context.has_value()) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
            // # If the validation succeeds, the server SHOULD then allow the
            // # handshake to proceed.
            entry.connection->mark_peer_address_validated();
        }

        auto drained =
            drain_connection_effects(entry.handle, entry.default_route_handle,
                                     entry.route_handle_by_path_id, *entry.connection, now,
                                     /*continue_paced_burst=*/false, send_sink);
        drain_queued_server_new_token(entry, drained, now, send_sink);
        bool keep_entry = should_keep_endpoint_connection_entry(*entry.connection, drained, now);
        append_result(result, std::move(drained));
        result.effects.insert(result.effects.begin(),
                              QuicCoreConnectionLifecycleEvent{
                                  .connection = entry.handle,
                                  .event = QuicCoreConnectionLifecycle::accepted,
                              });

        if (keep_entry) {
            const auto handle = entry.handle;
            store_send_continuation_wakeup(entry, result.send_continuation_pending, now);
            auto inserted_connection = connections_.emplace(handle, std::move(entry));
            auto connection_iter = inserted_connection.first;
            refresh_entry_wakeup(connection_iter->second);
            refresh_server_connection_routes(connection_iter->second);
        }
        return finalize_endpoint_result(std::move(result), now);
    }

    if (const auto *mtu = std::get_if<QuicCorePathMtuUpdate>(&input); mtu != nullptr) {
        QuicCoreResult result;
        for (auto &[handle, entry] : connections_) {
            static_cast<void>(handle);
            const auto path_id = path_id_for_route_handle(entry, mtu->route_handle);
            if (!path_id.has_value()) {
                continue;
            }
            entry.connection->apply_path_mtu_update(*path_id, mtu->max_udp_payload_size);
            auto drained = drain_connection_effects(
                entry.handle, entry.default_route_handle, entry.route_handle_by_path_id,
                *entry.connection, now, take_send_continuation_drain(entry), send_sink);
            note_send_continuation(entry, drained, now);
            append_result(result, std::move(drained));
            refresh_server_connection_routes(entry);
            break;
        }
        return finalize_endpoint_result(std::move(result), now);
    }

    if (const auto *command = std::get_if<QuicCoreConnectionCommand>(&input)) {
        auto entry_it = connections_.find(command->connection);
        if (entry_it == connections_.end()) {
            return QuicCoreResult{
                .next_wakeup = next_wakeup(),
                .local_error =
                    QuicCoreLocalError{
                        .connection = command->connection,
                        .code = QuicCoreLocalErrorCode::unsupported_operation,
                        .stream_id = std::nullopt,
                    },
            };
        }

        auto &entry = entry_it->second;
        QuicCoreResult result;
        std::visit(
            overloaded{
                [&](const QuicCoreSendStreamData &in) {
                    const auto queued = entry.connection->queue_stream_send(in.stream_id, in.bytes,
                                                                            in.fin, in.priority);
                    if (!queued.has_value()) {
                        result.local_error = stream_state_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreSendSharedStreamData &in) {
                    const auto queued = entry.connection->queue_stream_send_shared(
                        in.stream_id, in.bytes, in.fin, in.priority);
                    if (!queued.has_value()) {
                        result.local_error = stream_state_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreSendDatagramData &in) {
                    const auto queued =
                        entry.connection->queue_datagram_send(in.bytes, in.priority);
                    if (!queued.has_value()) {
                        result.local_error = datagram_send_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreSendSharedDatagramData &in) {
                    const auto queued =
                        entry.connection->queue_datagram_send_shared(in.bytes, in.priority);
                    if (!queued.has_value()) {
                        result.local_error = datagram_send_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreResetStream &in) {
                    const auto queued = entry.connection->queue_stream_reset(LocalResetCommand{
                        .stream_id = in.stream_id,
                        .application_error_code = in.application_error_code,
                    });
                    if (!queued.has_value()) {
                        result.local_error = stream_state_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreStopSending &in) {
                    const auto queued =
                        entry.connection->queue_stop_sending(LocalStopSendingCommand{
                            .stream_id = in.stream_id,
                            .application_error_code = in.application_error_code,
                        });
                    if (!queued.has_value()) {
                        result.local_error = stream_state_error_to_local_error(queued.error());
                        result.local_error->connection = entry.handle;
                    }
                },
                [&](const QuicCoreCloseConnection &in) {
                    static_cast<void>(
                        entry.connection->queue_application_close(LocalApplicationCloseCommand{
                            .application_error_code = in.application_error_code,
                            .reason_phrase = in.reason_phrase,
                        }));
                },
                [&](const QuicCoreRequestKeyUpdate &) { entry.connection->request_key_update(); },
                [&](const QuicCoreRequestConnectionMigration &in) {
                    if (!endpoint_config_.allow_peer_address_change) {
                        result.local_error = QuicCoreLocalError{
                            .connection = entry.handle,
                            .code = QuicCoreLocalErrorCode::unsupported_operation,
                            .stream_id = std::nullopt,
                        };
                        return;
                    }
                    const auto effective_identity = effective_address_validation_identity_for_route(
                        entry, in.route_handle, in.address_validation_identity);
                    if (!address_validation_identity_allowed_for_new_route(&entry,
                                                                           effective_identity)) {
                        result.local_error = QuicCoreLocalError{
                            .connection = entry.handle,
                            .code = QuicCoreLocalErrorCode::unsupported_operation,
                            .stream_id = std::nullopt,
                        };
                        return;
                    }
                    const auto path_id =
                        remember_inbound_path(entry, in.route_handle, effective_identity);
                    auto requested =
                        entry.connection->request_connection_migration(path_id, in.reason, now);
                    if (!requested.has_value()) {
                        result.local_error = QuicCoreLocalError{
                            .connection = entry.handle,
                            .code = QuicCoreLocalErrorCode::unsupported_operation,
                            .stream_id = std::nullopt,
                        };
                    }
                },
                [&](const auto &) {},
            },
            command->input);

        auto drained = drain_connection_effects(
            entry.handle, entry.default_route_handle, entry.route_handle_by_path_id,
            *entry.connection, now, take_send_continuation_drain(entry), send_sink);
        bool remove_entry =
            should_remove_endpoint_connection_entry(*entry.connection, drained, now);
        note_send_continuation(entry, drained, now);
        append_result(result, std::move(drained));
        refresh_server_connection_routes(entry);
        if (remove_entry) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2
            // # Once its closing or draining state ends, an endpoint SHOULD
            // # discard all connection state.
            retire_endpoint_connection_routes(entry, now);
            ++entry.wakeup_generation;
            connections_.erase(entry_it);
        }
        return finalize_endpoint_result(std::move(result), now);
    }

    QuicCoreResult result;
    for (const auto handle : due_connection_handles(now)) {
        auto entry_it = connections_.find(handle);
        if (entry_it == connections_.end() || entry_it->second.connection == nullptr) {
            continue;
        }
        auto &entry = entry_it->second;

        const bool continue_paced_burst = take_send_continuation_drain(entry);
        maybe_run_connection_timeout(entry, now);
        auto drained = drain_connection_effects(entry.handle, entry.default_route_handle,
                                                entry.route_handle_by_path_id, *entry.connection,
                                                now, continue_paced_burst, send_sink);
        const bool remove_entry =
            should_remove_endpoint_connection_entry(*entry.connection, drained, now);
        note_send_continuation(entry, drained, now);
        append_result(result, std::move(drained));
        refresh_server_connection_routes(entry);
        if (remove_entry) {
            retire_endpoint_connection_routes(entry, now);
            ++entry.wakeup_generation;
            connections_.erase(entry_it);
        }
    }
    return finalize_endpoint_result(std::move(result), now);
}

QuicCoreResult QuicCore::advance(QuicCoreInput input, QuicCoreTimePoint now) {
    QuicCoreResult result;
    if (!legacy_config_.has_value()) {
        result.local_error = QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        };
        result.next_wakeup = next_wakeup();
        return result;
    }

    // advance() already returned above when legacy mode is unavailable, so the legacy entry
    // is expected to exist here.
    auto &entry = *ensure_legacy_entry();
    if (entry.connection == nullptr) {
        return finalize_legacy_result(std::move(result), now);
    }
    auto config = legacy_config_.value_or(QuicCoreConfig{});
    auto *connection = entry.connection.get();

    std::visit(
        overloaded{
            [&](const QuicCoreStart &) { connection->start(now); },
            [&](const QuicCoreInboundDatagram &in) {
                const auto path_id = path_id_for_inbound_route(entry, in.route_handle,
                                                               in.address_validation_identity);
                if (!path_id.has_value()) {
                    return;
                }
                const auto inbound_payload = in.payload();
                if (config.role == EndpointRole::client) {
                    if (!connection->is_handshake_complete() &&
                        //= https://www.rfc-editor.org/rfc/rfc9000#section-6.2
                        // # A client MUST discard any Version Negotiation packet if it has
                        // # received and successfully processed any other packet, including an
                        // # earlier Version Negotiation packet.
                        !connection->has_processed_peer_packet() &&
                        !config.reacted_to_version_negotiation) {
                        const auto version_negotiation =
                            parse_version_negotiation_packet(inbound_payload);
                        if (version_negotiation.has_value()) {
                            const bool valid_destination_connection_id =
                                version_negotiation->destination_connection_id ==
                                config.source_connection_id;
                            const bool valid_source_connection_id =
                                version_negotiation->source_connection_id ==
                                config.initial_destination_connection_id;
                            const bool echoes_original_version =
                                std::find(version_negotiation->supported_versions.begin(),
                                          version_negotiation->supported_versions.end(),
                                          config.original_version) !=
                                version_negotiation->supported_versions.end();
                            //= https://www.rfc-editor.org/rfc/rfc9000#section-6.2
                            // # A client MUST discard a Version Negotiation packet that
                            // # lists the QUIC version selected by the client.
                            if (valid_destination_connection_id && valid_source_connection_id &&
                                !echoes_original_version) {
                                for (const auto supported_version : config.supported_versions) {
                                    if (std::find(version_negotiation->supported_versions.begin(),
                                                  version_negotiation->supported_versions.end(),
                                                  supported_version) ==
                                        version_negotiation->supported_versions.end()) {
                                        continue;
                                    }
                                    //= https://www.rfc-editor.org/rfc/rfc9000#section-6.2
                                    // # A client that supports only this version of QUIC MUST
                                    // # abandon the current connection attempt if it receives a
                                    // # Version Negotiation packet, with the following two
                                    // # exceptions.
                                    config.initial_version = supported_version;
                                    config.reacted_to_version_negotiation = true;
                                    entry.connection = std::make_unique<QuicConnection>(config);
                                    connection = entry.connection.get();
                                    if (const auto family =
                                            entry.address_family_by_path_id.find(*path_id);
                                        family != entry.address_family_by_path_id.end()) {
                                        remember_path_address_family(entry, *path_id,
                                                                     family->second);
                                    }
                                    connection->last_inbound_path_id_ = *path_id;
                                    connection->current_send_path_id_ = path_id;
                                    connection->ensure_path_state(*path_id).is_current_send_path =
                                        true;
                                    connection->start(now);
                                    return;
                                }
                            }
                            return;
                        }
                    }

                    const auto retry = parse_retry_packet(inbound_payload);
                    if (retry.has_value()) {
                        const auto original_destination_connection_id =
                            config.original_destination_connection_id.value_or(
                                config.initial_destination_connection_id);
                        const auto retry_integrity_valid = validate_retry_integrity_tag(
                            *retry, original_destination_connection_id);
                        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
                        // # A client MUST accept and process at most one Retry packet for each
                        // # connection attempt.
                        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
                        // # After the client has received and processed an
                        // # Initial or Retry packet from the server, it MUST discard any
                        // # subsequent Retry packets that it receives.
                        const bool can_process_retry =
                            !connection->is_handshake_complete() &&
                            !connection->has_processed_peer_packet() &&
                            !config.retry_source_connection_id.has_value();
                        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
                        // # Clients MUST discard Retry packets that have a Retry Integrity Tag
                        // # that cannot be validated; see Section 5.8 of [QUIC-TLS].
                        const bool valid_integrity =
                            retry_integrity_valid.has_value() && retry_integrity_valid.value();
                        const bool valid_destination_connection_id =
                            retry->destination_connection_id == config.source_connection_id;
                        const bool valid_version = retry->version == config.original_version;
                        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
                        // # A client MUST discard a Retry packet that contains a Source
                        // # Connection ID field that is identical to the Destination
                        // # Connection ID field of its Initial packet.
                        const bool valid_source_connection_id =
                            retry->source_connection_id != original_destination_connection_id;
                        //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
                        // # A client
                        // # MUST discard a Retry packet with a zero-length Retry Token field.
                        const bool valid_retry_token = !retry->retry_token.empty();
                        if (can_process_retry && valid_integrity &&
                            valid_destination_connection_id && valid_version &&
                            valid_source_connection_id && valid_retry_token) {
                            //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.3
                            // # A client MUST NOT reset the packet number for any packet number
                            // # space after processing a Retry packet.
                            const auto next_initial_send_packet_number =
                                connection->initial_space_.next_send_packet_number;
                            config.original_destination_connection_id =
                                original_destination_connection_id;
                            config.retry_source_connection_id = retry->source_connection_id;
                            //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.2
                            // # The client MUST NOT change the Source Connection ID because the
                            // # server could include the connection ID as part of its token
                            // # validation logic; see Section 8.1.4.
                            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.2
                            // # This token MUST be repeated by the client in all
                            // # Initial packets it sends for that connection after it receives the
                            // # Retry packet.
                            //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1.3
                            // # The client MUST include the token in all Initial packets it
                            // # sends, unless a Retry replaces the token with a newer one.
                            config.retry_token = retry->retry_token;
                            //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.1
                            // # The client MUST use the value from the Source
                            // # Connection ID field of the Retry packet in the Destination
                            // # Connection ID field of subsequent packets that it sends.
                            config.initial_destination_connection_id = retry->source_connection_id;
                            entry.connection = std::make_unique<QuicConnection>(config);
                            connection = entry.connection.get();
                            if (const auto family = entry.address_family_by_path_id.find(*path_id);
                                family != entry.address_family_by_path_id.end()) {
                                remember_path_address_family(entry, *path_id, family->second);
                            }
                            //= https://www.rfc-editor.org/rfc/rfc9000#section-17.2.5.3
                            // # A client MUST NOT reset the packet number for any packet number
                            // # space after processing a Retry packet.
                            connection->initial_space_.next_send_packet_number =
                                next_initial_send_packet_number;
                            connection->last_inbound_path_id_ = *path_id;
                            connection->current_send_path_id_ = path_id;
                            connection->ensure_path_state(*path_id).is_current_send_path = true;
                            connection->start(now);
                        }
                        return;
                    }
                }
                if (in.shared_bytes != nullptr) {
                    connection->process_inbound_datagram_shared(in.shared_bytes, in.begin, in.end,
                                                                now, *path_id, in.ecn);
                } else {
                    connection->process_inbound_datagram(inbound_payload, now, *path_id, in.ecn);
                }
            },
            [&](const QuicCorePathMtuUpdate &in) {
                if (!in.route_handle.has_value()) {
                    return;
                }
                const auto path_it = entry.path_id_by_route_handle.find(*in.route_handle);
                if (path_it == entry.path_id_by_route_handle.end()) {
                    return;
                }
                connection->apply_path_mtu_update(path_it->second, in.max_udp_payload_size);
            },
            [&](const QuicCoreSendStreamData &in) {
                const auto queued =
                    connection->queue_stream_send(in.stream_id, in.bytes, in.fin, in.priority);
                if (!queued.has_value()) {
                    result.local_error = stream_state_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreSendSharedStreamData &in) {
                const auto queued = connection->queue_stream_send_shared(in.stream_id, in.bytes,
                                                                         in.fin, in.priority);
                if (!queued.has_value()) {
                    result.local_error = stream_state_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreSendDatagramData &in) {
                const auto queued = queue_legacy_local_command(*connection, in);
                if (!queued.has_value()) {
                    result.local_error = datagram_send_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreSendSharedDatagramData &in) {
                const auto queued = queue_legacy_local_command(*connection, in);
                if (!queued.has_value()) {
                    result.local_error = datagram_send_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreResetStream &in) {
                const auto queued = connection->queue_stream_reset(LocalResetCommand{
                    .stream_id = in.stream_id,
                    .application_error_code = in.application_error_code,
                });
                if (!queued.has_value()) {
                    result.local_error = stream_state_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreStopSending &in) {
                const auto queued = connection->queue_stop_sending(LocalStopSendingCommand{
                    .stream_id = in.stream_id,
                    .application_error_code = in.application_error_code,
                });
                if (!queued.has_value()) {
                    result.local_error = stream_state_error_to_local_error(queued.error());
                }
            },
            [&](const QuicCoreCloseConnection &in) {
                static_cast<void>(connection->queue_application_close(LocalApplicationCloseCommand{
                    .application_error_code = in.application_error_code,
                    .reason_phrase = in.reason_phrase,
                }));
            },
            [&](const QuicCoreRequestKeyUpdate &) { connection->request_key_update(); },
            [&](const QuicCoreRequestConnectionMigration &in) {
                if (!endpoint_config_.allow_peer_address_change) {
                    result.local_error = QuicCoreLocalError{
                        .connection = std::nullopt,
                        .code = QuicCoreLocalErrorCode::unsupported_operation,
                        .stream_id = std::nullopt,
                    };
                    return;
                }
                const auto effective_identity = effective_address_validation_identity_for_route(
                    entry, in.route_handle, in.address_validation_identity);
                if (!address_validation_identity_allowed_for_new_route(&entry,
                                                                       effective_identity)) {
                    result.local_error = QuicCoreLocalError{
                        .connection = std::nullopt,
                        .code = QuicCoreLocalErrorCode::unsupported_operation,
                        .stream_id = std::nullopt,
                    };
                    return;
                }
                const auto path_id =
                    remember_inbound_path(entry, in.route_handle, effective_identity);
                auto requested = connection->request_connection_migration(path_id, in.reason, now);
                if (!requested.has_value()) {
                    result.local_error = QuicCoreLocalError{
                        .connection = std::nullopt,
                        .code = QuicCoreLocalErrorCode::unsupported_operation,
                        .stream_id = std::nullopt,
                    };
                }
            },
            [&](const QuicCoreTimerExpired &) { maybe_run_connection_timeout(entry, now); },
        },
        input);

    auto drained = drain_connection_effects(entry.handle, entry.default_route_handle,
                                            entry.route_handle_by_path_id, *connection, now,
                                            take_send_continuation_drain(entry));
    append_result(result, std::move(drained));
    legacy_config_ = std::move(config);
    return finalize_legacy_result(std::move(result), now);
}

QuicCoreResult QuicCore::advance(std::span<const QuicCoreInput> inputs, QuicCoreTimePoint now) {
    QuicCoreResult combined;
    for (std::size_t index = 0; index < inputs.size();) {
        if (!legacy_stream_send_batchable(inputs[index])) {
            auto step = advance(inputs[index], now);
            append_sequential_result(combined, std::move(step));
            if (combined.local_error.has_value()) {
                break;
            }
            ++index;
            continue;
        }

        if (!legacy_config_.has_value()) {
            auto step = advance(inputs[index], now);
            append_sequential_result(combined, std::move(step));
            break;
        }

        QuicCoreResult result;
        auto *entry = ensure_legacy_entry();
        if (entry->connection == nullptr) {
            result = finalize_legacy_result(std::move(result), now);
            append_sequential_result(combined, std::move(result));
            ++index;
            continue;
        }

        std::size_t run_end = index;
        for (; run_end < inputs.size() && legacy_stream_send_batchable(inputs[run_end]);
             ++run_end) {
            std::visit(
                overloaded{
                    [&](const QuicCoreSendStreamData &in) {
                        const auto queued = queue_legacy_local_command(*entry->connection, in);
                        if (!queued.has_value()) {
                            result.local_error = stream_state_error_to_local_error(queued.error());
                        }
                    },
                    [&](const QuicCoreSendSharedStreamData &in) {
                        const auto queued = queue_legacy_local_command(*entry->connection, in);
                        if (!queued.has_value()) {
                            result.local_error = stream_state_error_to_local_error(queued.error());
                        }
                    },
                    [](const auto &) COQUIC_NO_PROFILE {},
                },
                inputs[run_end]);
            if (result.local_error.has_value()) {
                ++run_end;
                break;
            }
        }

        auto drained = drain_connection_effects(entry->handle, entry->default_route_handle,
                                                entry->route_handle_by_path_id, *entry->connection,
                                                now, take_send_continuation_drain(*entry));
        append_result(result, std::move(drained));
        result = finalize_legacy_result(std::move(result), now);
        append_sequential_result(combined, std::move(result));
        if (combined.local_error.has_value()) {
            break;
        }
        index = run_end;
    }
    return combined;
}

std::vector<ConnectionId> QuicCore::active_local_connection_ids() const {
    if (const auto *entry = legacy_entry()) {
        return entry->connection->active_local_connection_ids();
    }
    return {};
}

bool QuicCore::is_handshake_complete() const {
    if (const auto *entry = legacy_entry()) {
        return entry->connection->is_handshake_complete();
    }
    return false;
}

bool QuicCore::has_failed() const {
    if (const auto *entry = legacy_entry()) {
        return entry->connection->has_failed();
    }
    return false;
}

} // namespace coquic::quic
