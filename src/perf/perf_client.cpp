#include "src/perf/perf_client.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <utility>

namespace coquic::perf {
namespace {
std::vector<std::byte> make_payload(std::size_t bytes) {
    std::vector<std::byte> out(bytes, std::byte{0x5a});
    return out;
}

quic::ConnectionId make_connection_id(std::byte prefix, std::uint64_t sequence) {
    quic::ConnectionId connection_id(8, std::byte{0x00});
    connection_id.front() = prefix;
    for (std::size_t index = 1; index < connection_id.size(); ++index) {
        const auto shift = static_cast<unsigned>((connection_id.size() - 1 - index) * 8);
        connection_id[index] = static_cast<std::byte>((sequence >> shift) & 0xffu);
    }
    return connection_id;
}

std::chrono::milliseconds elapsed_ms_since(quic::QuicCoreTimePoint start) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(quic::QuicCoreClock::now() -
                                                                 start);
}

std::optional<QuicPerfControlMessage> take_control_message(std::vector<std::byte> &buffer) {
    if (buffer.size() < 5) {
        return std::nullopt;
    }

    std::uint32_t payload_size = 0;
    for (std::size_t index = 1; index < 5; ++index) {
        payload_size = (payload_size << 8) | static_cast<std::uint8_t>(buffer[index]);
    }
    const auto frame_size = static_cast<std::size_t>(payload_size) + 5;
    if (buffer.size() < frame_size) {
        return std::nullopt;
    }

    std::vector<std::byte> frame(buffer.begin(),
                                 buffer.begin() + static_cast<std::ptrdiff_t>(frame_size));
    buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(frame_size));
    return decode_perf_control_message(frame);
}

QuicPerfSessionStart make_session_start(const QuicPerfConfig &config) {
    return QuicPerfSessionStart{
        .protocol_version = kQuicPerfProtocolVersion,
        .mode = config.mode,
        .direction = config.direction,
        .request_bytes = config.request_bytes,
        .response_bytes = config.response_bytes,
        .total_bytes =
            config.total_bytes.has_value()
                ? std::optional<std::uint64_t>{static_cast<std::uint64_t>(*config.total_bytes)}
                : std::nullopt,
        .requests = config.requests.has_value()
                        ? std::optional<std::uint64_t>{static_cast<std::uint64_t>(*config.requests)}
                        : std::nullopt,
        .warmup_ms = static_cast<std::uint64_t>(config.warmup.count()),
        .duration_ms = static_cast<std::uint64_t>(config.duration.count()),
        .streams = config.streams,
        .connections = config.connections,
        .requests_in_flight = config.requests_in_flight,
    };
}

std::size_t initial_connection_target(const QuicPerfConfig &config) {
    if (config.mode == QuicPerfMode::rr) {
        return 1;
    }
    if (config.mode == QuicPerfMode::crr) {
        return 0;
    }
    return config.connections;
}

} // namespace

int run_perf_client(const QuicPerfConfig &config) {
    QuicPerfClient client(config);
    return client.run();
}

QuicPerfClient::QuicPerfClient(const QuicPerfConfig &config)
    : config_(config), core_(make_perf_client_endpoint_config(config)) {
    summary_.mode = config.mode;
    summary_.direction = config.direction;
    summary_.backend = config.io_backend == io::QuicIoBackendKind::io_uring ? "io_uring" : "socket";
    summary_.remote_host = config.host;
    summary_.remote_port = config.port;
    summary_.alpn = std::string(kQuicPerfApplicationProtocol);
    summary_.streams = config.streams;
    summary_.connections = config.connections;
    summary_.requests_in_flight = config.requests_in_flight;
    summary_.request_bytes = config.request_bytes;
    summary_.response_bytes = config.response_bytes;
    summary_.warmup = config.warmup;
}

int QuicPerfClient::run() {
    const auto start = quic::QuicCoreClock::now();
    const auto emit_results = [&]() {
        std::cout << render_perf_summary(summary_) << '\n';
        return flush_json_result();
    };
    const auto fail = [&](std::string reason) {
        summary_.status = "failed";
        if (!summary_.failure_reason.has_value()) {
            summary_.failure_reason = std::move(reason);
        }
        summary_.elapsed = elapsed_ms_since(start);
        finalize_perf_run_summary(summary_);
        (void)emit_results();
        return 1;
    };

    auto bootstrap = io::bootstrap_client_io_backend(
        io::QuicIoBackendBootstrapConfig{
            .kind = config_.io_backend,
            .backend =
                io::QuicUdpBackendConfig{
                    .role_name = "perf-client",
                    .idle_timeout_ms = 1000,
                },
        },
        config_.host, config_.port);
    if (!bootstrap.has_value()) {
        return fail("client bootstrap failed");
    }
    backend_ = std::move(bootstrap->backend);
    primary_route_handle_ = bootstrap->primary_route_handle;

    if (!open_initial_connection(start)) {
        return fail("open connection failed");
    }

    for (;;) {
        if (run_complete()) {
            summary_.status = "ok";
            summary_.elapsed = elapsed_ms_since(start);
            finalize_perf_run_summary(summary_);
            return emit_results() ? 0 : 1;
        }

        const auto current = quic::QuicCoreClock::now();
        const auto next_wakeup = core_.next_wakeup();
        if (next_wakeup.has_value() && *next_wakeup <= current) {
            if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, current),
                               current)) {
                return fail("client timer handling failed");
            }
            continue;
        }

        if (!maybe_open_crr_connections(current)) {
            return fail("open crr connection failed");
        }
        const auto event = backend_->wait(next_wakeup);
        if (!event.has_value()) {
            return fail("client wait failed");
        }

        switch (event->kind) {
        case io::QuicIoEvent::Kind::idle_timeout:
            return fail("client timed out waiting for progress");
        case io::QuicIoEvent::Kind::shutdown:
            return fail("client backend shutdown");
        case io::QuicIoEvent::Kind::timer_expired:
            if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, event->now),
                               event->now)) {
                return fail("client timer event failed");
            }
            continue;
        case io::QuicIoEvent::Kind::rx_datagram:
            if (!event->datagram.has_value()) {
                return fail("client missing rx datagram");
            }
            const auto inbound_result = core_.advance_endpoint(
                quic::QuicCoreInboundDatagram{
                    .bytes = event->datagram->bytes,
                    .route_handle = event->datagram->route_handle,
                    .ecn = event->datagram->ecn,
                },
                event->now);
            if (!handle_result(inbound_result, event->now)) {
                return fail("client inbound datagram failed");
            }
            continue;
        }
    }
}

bool QuicPerfClient::open_initial_connection(quic::QuicCoreTimePoint now) {
    bool ok = true;
    for (std::size_t index = 0; index < initial_connection_target(config_); ++index) {
        const auto result = core_.advance_endpoint(
            quic::QuicCoreOpenConnection{
                .connection = make_client_open_config(index),
                .initial_route_handle = primary_route_handle_,
            },
            now);
        ok = ok && handle_result(result, now);
    }
    return ok;
}

bool QuicPerfClient::handle_result(const quic::QuicCoreResult &result,
                                   quic::QuicCoreTimePoint now) {
    if (result.local_error.has_value()) {
        summary_.failure_reason =
            "client local error code=" + std::to_string(static_cast<int>(result.local_error->code));
        if (result.local_error->stream_id.has_value()) {
            summary_.failure_reason = *summary_.failure_reason + " stream_id=" +
                                      std::to_string(*result.local_error->stream_id);
        }
        return false;
    }
    if (!flush_send_effects(*backend_, result)) {
        summary_.failure_reason = "client flush send effects failed";
        return false;
    }

    for (const auto &effect : result.effects) {
        if (const auto *lifecycle = std::get_if<quic::QuicCoreConnectionLifecycleEvent>(&effect)) {
            if (lifecycle->event == quic::QuicCoreConnectionLifecycle::created) {
                connections_.insert_or_assign(lifecycle->connection,
                                              ConnectionState{
                                                  .handle = lifecycle->connection,
                                                  .route_handle = primary_route_handle_,
                                              });
            } else if (lifecycle->event == quic::QuicCoreConnectionLifecycle::closed) {
                auto it = connections_.find(lifecycle->connection);
                if (it == connections_.end()) {
                    continue;
                }
                if (config_.mode == QuicPerfMode::crr) {
                    connections_.erase(it);
                } else {
                    it->second.control_complete = true;
                }
            }
            continue;
        }

        if (const auto *state = std::get_if<quic::QuicCoreStateEvent>(&effect)) {
            if (state->change == quic::QuicCoreStateChange::failed) {
                if (config_.mode == QuicPerfMode::crr &&
                    closing_connections_.contains(state->connection)) {
                    continue;
                }
                summary_.failure_reason = "client core state failed";
                return false;
            }
            if (state->change == quic::QuicCoreStateChange::handshake_ready) {
                const auto connection_it = connections_.find(state->connection);
                if (connection_it == connections_.end()) {
                    continue;
                }
                const auto command_result = core_.advance_endpoint(
                    quic::QuicCoreConnectionCommand{
                        .connection = state->connection,
                        .input =
                            quic::QuicCoreSendStreamData{
                                .stream_id = kQuicPerfControlStreamId,
                                .bytes = encode_perf_control_message(
                                    QuicPerfControlMessage{make_session_start(config_)}),
                                .fin = true,
                            },
                    },
                    now);
                if (command_result.local_error.has_value()) {
                    summary_.failure_reason = "client session_start local error";
                    return false;
                }
                if (!flush_send_effects(*backend_, command_result)) {
                    summary_.failure_reason = "client session_start flush failed";
                    return false;
                }
            }
            continue;
        }

        if (const auto *received = std::get_if<quic::QuicCoreReceiveStreamData>(&effect)) {
            auto connection_it = connections_.find(received->connection);
            if (connection_it == connections_.end()) {
                continue;
            }
            if (!handle_stream_data(connection_it->second, *received, now)) {
                if (!summary_.failure_reason.has_value()) {
                    summary_.failure_reason = "client stream handling failed";
                }
                return false;
            }
        }
    }

    return true;
}

bool QuicPerfClient::handle_stream_data(ConnectionState &connection,
                                        const quic::QuicCoreReceiveStreamData &received,
                                        quic::QuicCoreTimePoint now) {
    if (received.stream_id == kQuicPerfControlStreamId) {
        connection.control_bytes.insert(connection.control_bytes.end(), received.bytes.begin(),
                                        received.bytes.end());
        while (true) {
            const auto decoded = take_control_message(connection.control_bytes);
            if (!decoded.has_value()) {
                return !received.fin || connection.control_bytes.empty();
            }
            if (const auto *ready = std::get_if<QuicPerfSessionReady>(&*decoded)) {
                (void)ready;
                connection.session_ready = true;
                maybe_start_bulk_streams(connection, now);
                if (!maybe_issue_rr_requests(connection, now) ||
                    !maybe_issue_crr_request(connection, now)) {
                    return false;
                }
                continue;
            }
            if (const auto *error = std::get_if<QuicPerfSessionError>(&*decoded)) {
                summary_.status = "failed";
                summary_.failure_reason = error->reason;
                connection.control_complete = true;
                return false;
            }
            if (const auto *complete = std::get_if<QuicPerfSessionComplete>(&*decoded)) {
                summary_.server_bytes_sent = complete->bytes_sent;
                summary_.server_bytes_received = complete->bytes_received;
                summary_.server_requests_completed = complete->requests_completed;
                summary_.requests_completed = complete->requests_completed;
                connection.control_complete = true;
                continue;
            }
            return false;
        }
    }

    connection.bytes_received += received.bytes.size();
    summary_.bytes_received += received.bytes.size();

    if (config_.mode == QuicPerfMode::rr || config_.mode == QuicPerfMode::crr) {
        const auto request_it = connection.outstanding_requests.find(received.stream_id);
        if (request_it == connection.outstanding_requests.end()) {
            return true;
        }

        request_it->second.received_bytes += received.bytes.size();
        if (!received.fin) {
            return true;
        }

        summary_.latency_samples.push_back(now - request_it->second.started_at);
        ++summary_.requests_completed;
        connection.outstanding_requests.erase(request_it);
        if (config_.mode == QuicPerfMode::rr) {
            return maybe_issue_rr_requests(connection, now);
        }

        if (!connection.close_requested) {
            connection.close_requested = true;
            closing_connections_.insert(connection.handle);
            const auto close_result = core_.advance_endpoint(
                quic::QuicCoreConnectionCommand{
                    .connection = connection.handle,
                    .input =
                        quic::QuicCoreCloseConnection{
                            .application_error_code = 0,
                            .reason_phrase = "done",
                        },
                },
                now);
            if (!handle_result(close_result, now)) {
                if (!summary_.failure_reason.has_value()) {
                    summary_.failure_reason = "client crr close handling failed";
                }
                return false;
            }
        }
        return true;
    }

    return true;
}

bool QuicPerfClient::run_complete() const {
    if (config_.mode != QuicPerfMode::crr && connections_.empty()) {
        return false;
    }

    switch (config_.mode) {
    case QuicPerfMode::bulk: {
        const bool control_complete =
            std::all_of(connections_.begin(), connections_.end(),
                        [](const auto &entry) { return entry.second.control_complete; });
        if (!control_complete) {
            return false;
        }
        if (config_.total_bytes.has_value()) {
            if (config_.direction == QuicPerfDirection::download) {
                return summary_.bytes_received >= *config_.total_bytes;
            }
            return summary_.bytes_sent >= *config_.total_bytes;
        }
        return true;
    }
    case QuicPerfMode::rr:
        if (!config_.requests.has_value() || summary_.requests_completed < *config_.requests) {
            return false;
        }
        return std::all_of(connections_.begin(), connections_.end(), [](const auto &entry) {
            return entry.second.control_complete && entry.second.outstanding_requests.empty();
        });
    case QuicPerfMode::crr:
        return config_.requests.has_value() && summary_.requests_completed >= *config_.requests &&
               connections_.empty();
    }
    return false;
}

void QuicPerfClient::maybe_start_bulk_streams(ConnectionState &connection,
                                              quic::QuicCoreTimePoint now) {
    if (config_.mode != QuicPerfMode::bulk || !connection.session_ready ||
        connection.control_complete || connection.next_stream_id != kQuicPerfFirstDataStreamId) {
        return;
    }

    const auto total_bytes = config_.total_bytes.value_or(0);
    const auto per_stream = total_bytes / config_.streams;
    const auto remainder = total_bytes % config_.streams;

    for (std::size_t index = 0; index < config_.streams; ++index) {
        const auto stream_id = connection.next_stream_id;
        connection.next_stream_id = next_client_perf_stream_id(stream_id);
        const auto target_bytes = per_stream + (index < remainder ? 1u : 0u);

        const auto send_result = core_.advance_endpoint(
            quic::QuicCoreConnectionCommand{
                .connection = connection.handle,
                .input =
                    quic::QuicCoreSendStreamData{
                        .stream_id = stream_id,
                        .bytes = config_.direction == QuicPerfDirection::upload
                                     ? make_payload(static_cast<std::size_t>(target_bytes))
                                     : std::vector<std::byte>{},
                        .fin = true,
                    },
            },
            now);
        flush_send_effects(*backend_, send_result);
        if (config_.direction == QuicPerfDirection::upload) {
            connection.bytes_sent += target_bytes;
            summary_.bytes_sent += target_bytes;
        }
    }
}

bool QuicPerfClient::maybe_issue_rr_requests(ConnectionState &connection,
                                             quic::QuicCoreTimePoint now) {
    if (config_.mode != QuicPerfMode::rr || !connection.session_ready ||
        connection.control_complete) {
        return true;
    }

    while (connection.outstanding_requests.size() < config_.requests_in_flight &&
           (!config_.requests.has_value() || requests_started_ < *config_.requests)) {
        const auto stream_id = connection.next_stream_id;
        connection.next_stream_id = next_client_perf_stream_id(stream_id);
        const auto [request_it, inserted] = connection.outstanding_requests.emplace(
            stream_id, OutstandingRequest{.started_at = now});
        if (!inserted) {
            summary_.failure_reason = "client duplicate rr stream id";
            return false;
        }

        const auto send_result = core_.advance_endpoint(
            quic::QuicCoreConnectionCommand{
                .connection = connection.handle,
                .input =
                    quic::QuicCoreSendStreamData{
                        .stream_id = stream_id,
                        .bytes = make_payload(config_.request_bytes),
                        .fin = true,
                    },
            },
            now);
        if (send_result.local_error.has_value()) {
            summary_.failure_reason = "client rr request local error";
            connection.outstanding_requests.erase(request_it);
            return false;
        }
        if (!flush_send_effects(*backend_, send_result)) {
            summary_.failure_reason = "client rr request flush failed";
            connection.outstanding_requests.erase(request_it);
            return false;
        }

        ++requests_started_;
        connection.bytes_sent += config_.request_bytes;
        summary_.bytes_sent += config_.request_bytes;
    }

    return true;
}

bool QuicPerfClient::maybe_issue_crr_request(ConnectionState &connection,
                                             quic::QuicCoreTimePoint now) {
    if (config_.mode != QuicPerfMode::crr || !connection.session_ready ||
        connection.control_complete || connection.close_requested ||
        !connection.outstanding_requests.empty()) {
        return true;
    }

    const auto stream_id = connection.next_stream_id;
    connection.next_stream_id = next_client_perf_stream_id(stream_id);
    const auto [request_it, inserted] =
        connection.outstanding_requests.emplace(stream_id, OutstandingRequest{.started_at = now});
    if (!inserted) {
        summary_.failure_reason = "client duplicate crr stream id";
        return false;
    }

    const auto send_result = core_.advance_endpoint(
        quic::QuicCoreConnectionCommand{
            .connection = connection.handle,
            .input =
                quic::QuicCoreSendStreamData{
                    .stream_id = stream_id,
                    .bytes = make_payload(config_.request_bytes),
                    .fin = true,
                },
        },
        now);
    if (send_result.local_error.has_value()) {
        summary_.failure_reason = "client crr request local error";
        connection.outstanding_requests.erase(request_it);
        return false;
    }
    if (!flush_send_effects(*backend_, send_result)) {
        summary_.failure_reason = "client crr request flush failed";
        connection.outstanding_requests.erase(request_it);
        return false;
    }

    connection.bytes_sent += config_.request_bytes;
    summary_.bytes_sent += config_.request_bytes;
    return true;
}

quic::QuicCoreClientConnectionConfig
QuicPerfClient::make_client_open_config(std::uint64_t index) const {
    const auto id = static_cast<std::uint8_t>(index + 1);
    return quic::QuicCoreClientConnectionConfig{
        .source_connection_id = make_connection_id(std::byte{0xc1}, static_cast<std::uint64_t>(id)),
        .initial_destination_connection_id =
            make_connection_id(std::byte{0x83}, static_cast<std::uint64_t>(0x40u + id)),
        .server_name = config_.server_name,
    };
}

bool QuicPerfClient::maybe_open_crr_connections(quic::QuicCoreTimePoint now) {
    if (config_.mode != QuicPerfMode::crr || !config_.requests.has_value()) {
        return true;
    }

    while (connections_.size() < config_.connections && crr_requests_opened_ < *config_.requests) {
        const auto result = core_.advance_endpoint(
            quic::QuicCoreOpenConnection{
                .connection = make_client_open_config(next_connection_index_++),
                .initial_route_handle = primary_route_handle_,
            },
            now);
        ++crr_requests_opened_;
        if (!handle_result(result, now)) {
            return false;
        }
    }
    return true;
}

bool QuicPerfClient::flush_json_result() const {
    if (!config_.json_out.has_value()) {
        return true;
    }

    std::ofstream output(*config_.json_out, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        return false;
    }
    const auto json = render_perf_json(summary_);
    output << json;
    return output.good();
}

} // namespace coquic::perf
