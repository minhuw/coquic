#include "src/perf/perf_loop.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <utility>

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

#ifndef COQUIC_PROFILE_HOOKS
#define COQUIC_PROFILE_HOOKS 1
#endif

namespace coquic::perf {

namespace {

constexpr std::size_t kMaxBufferedSendDatagrams = 64;
constexpr bool kCoquicProfileHooksEnabled = COQUIC_PROFILE_HOOKS != 0;

struct PerfLoopProfileCounters {
    std::uint64_t send_buffer_appends = 0;
    std::uint64_t send_buffer_send_effects = 0;
    std::uint64_t send_buffer_flushes = 0;
    std::uint64_t send_buffer_flushed_datagrams = 0;
    std::uint64_t send_buffer_append_ns = 0;
    std::uint64_t send_buffer_flush_ns = 0;
};

COQUIC_NO_PROFILE bool perf_loop_profile_enabled() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return false;
    }

    static const bool enabled = [] {
        const char *value = std::getenv("COQUIC_SEND_PROFILE");
        return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
    }();
    return enabled;
}

COQUIC_NO_PROFILE PerfLoopProfileCounters &perf_loop_profile_counters() {
    static PerfLoopProfileCounters counters;
    return counters;
}

COQUIC_NO_PROFILE void print_perf_loop_profile() {
    if (!perf_loop_profile_enabled()) {
        return;
    }

    const auto &c = perf_loop_profile_counters();
    std::cerr << "coquic-perf-loop-profile"
              << " send_buffer_appends=" << c.send_buffer_appends
              << " send_buffer_send_effects=" << c.send_buffer_send_effects
              << " send_buffer_flushes=" << c.send_buffer_flushes
              << " send_buffer_flushed_datagrams=" << c.send_buffer_flushed_datagrams
              << " send_buffer_append_ns=" << c.send_buffer_append_ns
              << " send_buffer_flush_ns=" << c.send_buffer_flush_ns << '\n';
}

COQUIC_NO_PROFILE void register_perf_loop_profile_printer_once() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return;
    }

    static const bool registered = [] {
        std::atexit(print_perf_loop_profile);
        return true;
    }();
    static_cast<void>(registered);
}

struct PerfLoopProfileTimer {
    std::uint64_t *target = nullptr;
    quic::QuicCoreTimePoint start{};

    COQUIC_NO_PROFILE explicit PerfLoopProfileTimer(std::uint64_t &counter)
        : target(kCoquicProfileHooksEnabled && perf_loop_profile_enabled() ? &counter : nullptr) {
        if (target != nullptr) {
            start = quic::QuicCoreClock::now();
        }
    }

    COQUIC_NO_PROFILE ~PerfLoopProfileTimer() {
        if (target == nullptr) {
            return;
        }
        *target += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(quic::QuicCoreClock::now() - start)
                .count());
    }
};

#if COQUIC_PROFILE_HOOKS
#define COQUIC_PERF_LOOP_PROFILE_TIMER(name, counter)                                              \
    PerfLoopProfileTimer name(perf_loop_profile_counters().counter)
#else
#define COQUIC_PERF_LOOP_PROFILE_TIMER(name, counter) static_cast<void>(0)
#endif

bool result_has_send_datagram(const quic::QuicCoreResult &result) {
    return std::any_of(result.effects.begin(), result.effects.end(), [](const auto &effect) {
        return std::holds_alternative<quic::QuicCoreSendDatagram>(effect);
    });
}

} // namespace

std::optional<quic::QuicCoreEndpointInput>
make_endpoint_input_from_io_event(io::QuicIoEvent &event) {
    switch (event.kind) {
    case io::QuicIoEvent::Kind::rx_datagram:
        if (event.datagram.has_value()) {
            return quic::QuicCoreInboundDatagram{
                .bytes = std::move(event.datagram->bytes),
                .route_handle = event.datagram->route_handle,
                .address_validation_identity =
                    std::move(event.datagram->address_validation_identity),
                .ecn = event.datagram->ecn,
                .shared_bytes = std::move(event.datagram->shared_bytes),
                .begin = event.datagram->begin,
                .end = event.datagram->end,
            };
        }
        break;
    case io::QuicIoEvent::Kind::path_mtu_update:
        if (event.path_mtu.has_value()) {
            return quic::QuicCorePathMtuUpdate{
                .route_handle = event.path_mtu->route_handle,
                .max_udp_payload_size = event.path_mtu->max_udp_payload_size,
            };
        }
        break;
    case io::QuicIoEvent::Kind::timer_expired:
        return quic::QuicCoreTimerExpired{};
    case io::QuicIoEvent::Kind::idle_timeout:
    case io::QuicIoEvent::Kind::shutdown:
        break;
    }
    return std::nullopt;
}

bool flush_send_effects(io::QuicIoBackend &backend, const quic::QuicCoreResult &result) {
    if (!result_has_send_datagram(result)) {
        return true;
    }

    std::vector<io::QuicIoTxDatagram> datagrams;
    datagrams.reserve(result.effects.size());
    for (const auto &effect : result.effects) {
        if (const auto *send = std::get_if<quic::QuicCoreSendDatagram>(&effect)) {
            if (!send->route_handle.has_value()) {
                return false;
            }
            datagrams.push_back(io::QuicIoTxDatagram{
                .route_handle = *send->route_handle,
                .bytes_view = send->bytes.span(),
                .ecn = send->ecn,
                .is_pmtu_probe = send->is_pmtu_probe,
            });
        }
    }
    return backend.send_many(datagrams);
}

bool PerfSendBuffer::append_or_flush(io::QuicIoBackend &backend, quic::QuicCoreResult &result) {
    register_perf_loop_profile_printer_once();
    if (perf_loop_profile_enabled()) {
        auto &profile = perf_loop_profile_counters();
        ++profile.send_buffer_appends;
        profile.send_buffer_send_effects += result.effects.size();
    }
    COQUIC_PERF_LOOP_PROFILE_TIMER(perf_append_timer, send_buffer_append_ns);
    if (!result_has_send_datagram(result)) {
        return true;
    }
    if (datagrams_.size() + result.effects.size() > kMaxBufferedSendDatagrams && !flush(backend)) {
        return false;
    }
    datagrams_.reserve(std::max(datagrams_.capacity(), datagrams_.size() + result.effects.size()));
    for (auto &effect : result.effects) {
        if (auto *send = std::get_if<quic::QuicCoreSendDatagram>(&effect)) {
            if (!send->route_handle.has_value()) {
                return false;
            }
            datagrams_.push_back(io::QuicIoTxDatagram{
                .route_handle = *send->route_handle,
                .bytes = std::move(send->bytes),
                .ecn = send->ecn,
                .is_pmtu_probe = send->is_pmtu_probe,
            });
        }
    }
    if (datagrams_.size() >= kMaxBufferedSendDatagrams) {
        return flush(backend);
    }
    return true;
}

bool PerfSendBuffer::flush(io::QuicIoBackend &backend) {
    if (datagrams_.empty()) {
        return true;
    }
    if (perf_loop_profile_enabled()) {
        auto &profile = perf_loop_profile_counters();
        ++profile.send_buffer_flushes;
        profile.send_buffer_flushed_datagrams += datagrams_.size();
    }
    COQUIC_PERF_LOOP_PROFILE_TIMER(perf_flush_timer, send_buffer_flush_ns);
    const bool ok = backend.send_many(datagrams_);
    datagrams_.clear();
    return ok;
}

bool PerfSendBuffer::empty() const {
    return datagrams_.empty();
}

std::size_t PerfSendBuffer::size() const {
    return datagrams_.size();
}

} // namespace coquic::perf
