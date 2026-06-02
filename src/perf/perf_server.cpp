#include "src/perf/perf_server.h"

#include <algorithm>
#include <cstdlib>
#include <span>
#include <string_view>

namespace coquic::perf {
namespace {

constexpr std::size_t kMaxPendingBackendEventsBeforeFlush = 64;

std::vector<std::byte> make_payload(std::size_t bytes) {
    return std::vector<std::byte>(bytes, std::byte{0x5a});
}

bool env_flag_enabled(const char *name) {
    const char *value = std::getenv(name);
    return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
}

} // namespace

std::optional<std::string> validate_perf_session_start(const QuicPerfSessionStart &start) {
    if (start.protocol_version != kQuicPerfProtocolVersion &&
        start.protocol_version != kQuicPerfProtocolVersionLegacy) {
        return "unsupported protocol version";
    }
    if (start.streams == 0) {
        return "streams must be greater than zero";
    }
    if (start.connections == 0) {
        return "connections must be greater than zero";
    }
    if (start.requests_in_flight == 0) {
        return "requests_in_flight must be greater than zero";
    }
    return std::nullopt;
}

QuicPerfServer::QuicPerfServer(const QuicPerfConfig &config,
                               std::unique_ptr<io::QuicIoBackend> backend)
    : config_(config), core_(make_perf_server_endpoint_config(config)),
      backend_(std::move(backend)) {
}

quic::SharedBytes QuicPerfServer::cached_download_payload(std::size_t bytes) {
    if (bytes == 0) {
        return {};
    }

    auto [it, inserted] = download_payload_cache_.try_emplace(bytes);
    if (inserted) {
        it->second = quic::SharedBytes(make_payload(bytes));
    }
    return it->second;
}

int run_perf_server(const QuicPerfConfig &config) {
    auto bootstrap = io::bootstrap_server_io_backend(
        io::QuicIoBackendBootstrapConfig{
            .kind = config.io_backend,
            .backend =
                io::QuicUdpBackendConfig{
                    .role_name = "perf-server",
                    .idle_timeout_ms = 1000,
                },
        },
        config.host, std::span<const std::uint16_t>(&config.port, 1));
    if (!bootstrap.has_value()) {
        return 1;
    }

    QuicPerfServer server(config, std::move(bootstrap->backend));
    return server.run();
}

int QuicPerfServer::run() {
    for (;;) {
        const auto current = quic::QuicCoreClock::now();
        const auto next_wakeup = core_.next_wakeup();
        if (next_wakeup.has_value() && *next_wakeup <= current) {
            if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, current),
                               current)) {
                return 1;
            }
            if (!flush_pending_sends()) {
                return 1;
            }
            if (should_exit_on_session_complete()) {
                return 0;
            }
            continue;
        }

        auto event = backend_->wait(next_wakeup);
        if (!event.has_value()) {
            return 1;
        }

        switch (event->kind) {
        case io::QuicIoEvent::Kind::idle_timeout:
            if (!flush_pending_sends()) {
                return 1;
            }
            if (should_exit_on_idle_empty() || should_exit_on_session_complete()) {
                return 0;
            }
            continue;
        case io::QuicIoEvent::Kind::shutdown:
            (void)flush_pending_sends();
            return 1;
        case io::QuicIoEvent::Kind::timer_expired:
            if (!flush_pending_sends()) {
                return 1;
            }
            if (should_exit_on_session_complete()) {
                return 0;
            }
            if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, event->now),
                               event->now)) {
                return 1;
            }
            if (!flush_pending_sends()) {
                return 1;
            }
            if (should_exit_on_session_complete()) {
                return 0;
            }
            continue;
        case io::QuicIoEvent::Kind::path_mtu_update:
        case io::QuicIoEvent::Kind::rx_datagram:
            break;
        }

        if (auto input = make_endpoint_input_from_io_event(*event); input.has_value()) {
            if (!handle_result(core_.advance_endpoint(std::move(*input), event->now), event->now)) {
                return 1;
            }
        }
        if (!flush_pending_sends()) {
            return 1;
        }
        if (should_exit_on_session_complete()) {
            return 0;
        }
    }
}

bool QuicPerfServer::handle_result(quic::QuicCoreResult result, quic::QuicCoreTimePoint now) {
    if (result.local_error.has_value()) {
        return false;
    }
    if (!send_buffer_.append_or_flush(*backend_, result)) {
        return false;
    }

    for (const auto &effect : result.effects) {
        if (const auto *lifecycle = std::get_if<quic::QuicCoreConnectionLifecycleEvent>(&effect)) {
            if (lifecycle->event == quic::QuicCoreConnectionLifecycle::accepted) {
                accepted_session_ = true;
                sessions_.insert_or_assign(lifecycle->connection,
                                           Session{.connection = lifecycle->connection});
            } else if (lifecycle->event == quic::QuicCoreConnectionLifecycle::closed) {
                sessions_.erase(lifecycle->connection);
            }
            continue;
        }

        if (const auto *received = std::get_if<quic::QuicCoreReceiveStreamData>(&effect)) {
            auto session_it = sessions_.find(received->connection);
            if (session_it == sessions_.end()) {
                continue;
            }
            if (!handle_stream_data(session_it->second, *received, now)) {
                return false;
            }
        }
    }

    return true;
}

bool QuicPerfServer::drain_pending_backend_events() {
    if (backend_ == nullptr) {
        return true;
    }

    for (std::size_t drained = 0;
         drained < kMaxPendingBackendEventsBeforeFlush && backend_->has_pending_events();
         ++drained) {
        auto event = backend_->wait(std::nullopt);
        if (!event.has_value()) {
            return false;
        }

        switch (event->kind) {
        case io::QuicIoEvent::Kind::idle_timeout:
            return true;
        case io::QuicIoEvent::Kind::shutdown:
            return false;
        case io::QuicIoEvent::Kind::timer_expired:
            if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, event->now),
                               event->now)) {
                return false;
            }
            continue;
        case io::QuicIoEvent::Kind::path_mtu_update:
        case io::QuicIoEvent::Kind::rx_datagram:
            break;
        }

        if (auto input = make_endpoint_input_from_io_event(*event); input.has_value()) {
            if (!handle_result(core_.advance_endpoint(std::move(*input), event->now), event->now)) {
                return false;
            }
        }
    }

    return true;
}

bool QuicPerfServer::flush_pending_sends() {
    if (!send_buffer_.empty() && !send_buffer_.flush(*backend_)) {
        return false;
    }
    if (!drain_pending_backend_events()) {
        return false;
    }
    return send_buffer_.flush(*backend_);
}

bool QuicPerfServer::should_exit_on_idle_empty() const {
    return accepted_session_ && sessions_.empty() &&
           env_flag_enabled("COQUIC_PERF_SERVER_EXIT_ON_IDLE_EMPTY");
}

bool QuicPerfServer::should_exit_on_session_complete() const {
    return accepted_session_ && completed_session_seen_ &&
           env_flag_enabled("COQUIC_PERF_SERVER_EXIT_ON_SESSION_COMPLETE") &&
           completed_sessions_drained_for_exit();
}

bool QuicPerfServer::completed_sessions_drained_for_exit() const {
    if (!send_buffer_.empty() || core_.has_send_continuation_pending()) {
        return false;
    }
    if (!std::all_of(sessions_.begin(), sessions_.end(),
                     [](const auto &entry) { return entry.second.complete_sent; })) {
        return false;
    }

    const auto diagnostics = core_.connection_diagnostics();
    return std::none_of(diagnostics.begin(), diagnostics.end(), [](const auto &connection) {
        return std::any_of(connection.streams.begin(), connection.streams.end(),
                           [](const auto &stream) { return stream.pending_send; });
    });
}

bool QuicPerfServer::handle_stream_data(Session &session,
                                        const quic::QuicCoreReceiveStreamData &received,
                                        quic::QuicCoreTimePoint now) {
    if (received.stream_id != kQuicPerfControlStreamId) {
        // Data streams are ignored until the control stream has delivered a valid session start.
        if (!session.start.has_value()) {
            return true;
        }

        session.bytes_received += received.byte_count();
        if (received.fin) {
            ++session.requests_completed;
        }

        if (session.start->mode == QuicPerfMode::bulk &&
            session.start->direction == QuicPerfDirection::download &&
            !session.start->total_bytes.has_value() && received.fin) {
            // Unbounded bulk download replies with the configured payload on each finished stream.
            const auto response_bytes = static_cast<std::size_t>(session.start->response_bytes);
            auto send_result = core_.advance_endpoint(
                quic::QuicCoreConnectionCommand{
                    .connection = session.connection,
                    .input =
                        quic::QuicCoreSendSharedStreamData{
                            .stream_id = received.stream_id,
                            .bytes = cached_download_payload(response_bytes),
                            .fin = true,
                        },
                },
                now);
            if (send_result.local_error.has_value() ||
                !send_buffer_.append_or_flush(*backend_, send_result)) {
                return false;
            }
            session.bytes_sent += response_bytes;
            return true;
        }

        if (session.start->mode == QuicPerfMode::bulk &&
            session.start->direction == QuicPerfDirection::download && received.fin) {
            // Bounded bulk download divides total bytes across all requested streams.
            const auto stream_index = session.requests_completed - 1;
            const auto total_bytes = session.start->total_bytes.value_or(0);
            const auto per_stream = total_bytes / session.start->streams;
            const auto remainder = total_bytes % session.start->streams;
            const auto target_bytes = per_stream + (stream_index < remainder ? 1u : 0u);
            auto send_result = core_.advance_endpoint(
                quic::QuicCoreConnectionCommand{
                    .connection = session.connection,
                    .input =
                        quic::QuicCoreSendStreamData{
                            .stream_id = received.stream_id,
                            .bytes = make_payload(static_cast<std::size_t>(target_bytes)),
                            .fin = true,
                        },
                },
                now);
            if (send_result.local_error.has_value() ||
                !send_buffer_.append_or_flush(*backend_, send_result)) {
                return false;
            }
            session.bytes_sent += target_bytes;
            if (session.requests_completed >= session.start->streams) {
                session.complete_sent = true;
                completed_session_seen_ = true;
                return send_control(session, QuicPerfSessionComplete{
                                                 .bytes_sent = session.bytes_sent,
                                                 .bytes_received = session.bytes_received,
                                                 .requests_completed = session.requests_completed,
                                             });
            }
            return true;
        }

        if (session.start->mode == QuicPerfMode::bulk &&
            session.start->direction == QuicPerfDirection::upload &&
            session.requests_completed >= session.start->streams) {
            // Bulk upload completes once every client upload stream reaches FIN.
            session.complete_sent = true;
            completed_session_seen_ = true;
            return send_control(session, QuicPerfSessionComplete{
                                             .bytes_sent = session.bytes_sent,
                                             .bytes_received = session.bytes_received,
                                             .requests_completed = session.requests_completed,
                                         });
        }

        if ((session.start->mode == QuicPerfMode::rr || session.start->mode == QuicPerfMode::crr) &&
            received.fin) {
            // Request/response modes answer each finished request stream with one response body.
            const auto response_bytes = static_cast<std::size_t>(session.start->response_bytes);
            auto send_result = core_.advance_endpoint(
                quic::QuicCoreConnectionCommand{
                    .connection = session.connection,
                    .input =
                        quic::QuicCoreSendStreamData{
                            .stream_id = received.stream_id,
                            .bytes = make_payload(response_bytes),
                            .fin = true,
                        },
                },
                now);
            if (send_result.local_error.has_value() ||
                !send_buffer_.append_or_flush(*backend_, send_result)) {
                return false;
            }
            session.bytes_sent += response_bytes;
            if (session.start->mode == QuicPerfMode::rr && session.start->requests.has_value() &&
                session.requests_completed >= *session.start->requests) {
                session.complete_sent = true;
                completed_session_seen_ = true;
                return send_control(session, QuicPerfSessionComplete{
                                                 .bytes_sent = session.bytes_sent,
                                                 .bytes_received = session.bytes_received,
                                                 .requests_completed = session.requests_completed,
                                             });
            }
        }
        return true;
    }

    // Control frames are accumulated until FIN, then decoded as a single perf message.
    const auto control_payload = received.payload();
    session.control_bytes.insert(session.control_bytes.end(), control_payload.begin(),
                                 control_payload.end());
    if (!received.fin) {
        return true;
    }

    const auto decoded = decode_perf_control_message(session.control_bytes);
    session.control_bytes.clear();
    if (!decoded.has_value()) {
        return send_control(session, QuicPerfSessionError{.reason = "invalid control message"});
    }

    const auto *start = std::get_if<QuicPerfSessionStart>(&*decoded);
    if (start == nullptr) {
        return send_control(session, QuicPerfSessionError{.reason = "expected session_start"});
    }

    if (const auto error = validate_perf_session_start(*start); error.has_value()) {
        return send_control(session, QuicPerfSessionError{.reason = *error});
    }

    // A valid start message arms the session and acknowledges readiness on the control stream.
    session.start = *start;
    session.ready_sent = true;
    return send_control(session,
                        QuicPerfSessionReady{.protocol_version = kQuicPerfProtocolVersion});
}

bool QuicPerfServer::send_control(Session &session, const QuicPerfControlMessage &message) {
    const bool fin = std::holds_alternative<QuicPerfSessionError>(message) ||
                     std::holds_alternative<QuicPerfSessionComplete>(message);
    auto result = core_.advance_endpoint(
        quic::QuicCoreConnectionCommand{
            .connection = session.connection,
            .input =
                quic::QuicCoreSendStreamData{
                    .stream_id = kQuicPerfControlStreamId,
                    .bytes = encode_perf_control_message(message),
                    .fin = fin,
                },
        },
        quic::QuicCoreClock::now());
    if (result.local_error.has_value()) {
        return false;
    }
    return send_buffer_.append_or_flush(*backend_, result);
}

} // namespace coquic::perf
