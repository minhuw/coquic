#include "src/perf/perf_server.h"

#include <span>

namespace coquic::perf {
namespace {

std::vector<std::byte> make_payload(std::size_t bytes) {
    return std::vector<std::byte>(bytes, std::byte{0x5a});
}

} // namespace

std::optional<std::string> validate_perf_session_start(const QuicPerfSessionStart &start) {
    if (start.protocol_version != kQuicPerfProtocolVersion) {
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
            continue;
        }

        const auto event = backend_->wait(next_wakeup);
        if (!event.has_value()) {
            return 1;
        }

        switch (event->kind) {
        case io::QuicIoEvent::Kind::idle_timeout:
            continue;
        case io::QuicIoEvent::Kind::shutdown:
            return 1;
        case io::QuicIoEvent::Kind::timer_expired:
            if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, event->now),
                               event->now)) {
                return 1;
            }
            continue;
        case io::QuicIoEvent::Kind::rx_datagram:
            break;
        }

        for (auto input : make_endpoint_inputs_from_io_event(*event)) {
            if (!handle_result(core_.advance_endpoint(std::move(input), event->now), event->now)) {
                return 1;
            }
        }
    }
}

bool QuicPerfServer::handle_result(const quic::QuicCoreResult &result,
                                   quic::QuicCoreTimePoint now) {
    if (result.local_error.has_value()) {
        return false;
    }
    if (!flush_send_effects(*backend_, result)) {
        return false;
    }

    for (const auto &effect : result.effects) {
        if (const auto *lifecycle = std::get_if<quic::QuicCoreConnectionLifecycleEvent>(&effect)) {
            if (lifecycle->event == quic::QuicCoreConnectionLifecycle::accepted) {
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

bool QuicPerfServer::handle_stream_data(Session &session,
                                        const quic::QuicCoreReceiveStreamData &received,
                                        quic::QuicCoreTimePoint now) {
    if (received.stream_id != kQuicPerfControlStreamId) {
        if (!session.start.has_value()) {
            return true;
        }

        session.bytes_received += received.bytes.size();
        if (received.fin) {
            ++session.requests_completed;
        }

        if (session.start->mode == QuicPerfMode::bulk &&
            session.start->direction == QuicPerfDirection::download &&
            !session.start->total_bytes.has_value() && received.fin) {
            const auto response_bytes = static_cast<std::size_t>(session.start->response_bytes);
            const auto send_result = core_.advance_endpoint(
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
                !flush_send_effects(*backend_, send_result)) {
                return false;
            }
            session.bytes_sent += response_bytes;
            return true;
        }

        if (session.start->mode == QuicPerfMode::bulk &&
            session.start->direction == QuicPerfDirection::download && received.fin) {
            const auto stream_index = session.requests_completed - 1;
            const auto total_bytes = session.start->total_bytes.value_or(0);
            const auto per_stream = total_bytes / session.start->streams;
            const auto remainder = total_bytes % session.start->streams;
            const auto target_bytes = per_stream + (stream_index < remainder ? 1u : 0u);
            const auto send_result = core_.advance_endpoint(
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
                !flush_send_effects(*backend_, send_result)) {
                return false;
            }
            session.bytes_sent += target_bytes;
            if (session.requests_completed >= session.start->streams) {
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
            return send_control(session, QuicPerfSessionComplete{
                                             .bytes_sent = session.bytes_sent,
                                             .bytes_received = session.bytes_received,
                                             .requests_completed = session.requests_completed,
                                         });
        }

        if ((session.start->mode == QuicPerfMode::rr || session.start->mode == QuicPerfMode::crr) &&
            received.fin) {
            const auto response_bytes = static_cast<std::size_t>(session.start->response_bytes);
            const auto send_result = core_.advance_endpoint(
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
                !flush_send_effects(*backend_, send_result)) {
                return false;
            }
            session.bytes_sent += response_bytes;
            if (session.start->mode == QuicPerfMode::rr && session.start->requests.has_value() &&
                session.requests_completed >= *session.start->requests) {
                return send_control(session, QuicPerfSessionComplete{
                                                 .bytes_sent = session.bytes_sent,
                                                 .bytes_received = session.bytes_received,
                                                 .requests_completed = session.requests_completed,
                                             });
            }
        }
        return true;
    }

    session.control_bytes.insert(session.control_bytes.end(), received.bytes.begin(),
                                 received.bytes.end());
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
    return flush_send_effects(*backend_, result);
}

} // namespace coquic::perf
