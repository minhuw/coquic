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
    if (config.mode == QuicPerfMode::rr && config.requests.has_value()) {
        return 1;
    }
    if (config.mode == QuicPerfMode::crr) {
        return 0;
    }
    return config.connections;
}

bool timed_bulk_download_drain_connection_complete(bool close_requested,
                                                   std::size_t active_bulk_streams) {
    return close_requested && active_bulk_streams == 0;
}

bool timed_rr_drain_connection_complete(bool close_requested, std::size_t outstanding_requests) {
    return close_requested && outstanding_requests == 0;
}

quic::QuicCoreClientConnectionConfig make_client_open_config_for_index(const QuicPerfConfig &config,
                                                                       std::uint64_t index) {
    const auto id = index + 1;
    return quic::QuicCoreClientConnectionConfig{
        .source_connection_id = make_connection_id(std::byte{0xc1}, id),
        .initial_destination_connection_id = make_connection_id(std::byte{0x83}, 0x40u + id),
        .server_name = config.server_name,
    };
}

} // namespace

int run_perf_client(const QuicPerfConfig &config) {
    QuicPerfClient client(config);
    return client.run();
}

std::size_t initial_connection_target_for_test(const QuicPerfConfig &config) {
    return initial_connection_target(config);
}

quic::QuicCoreClientConnectionConfig make_client_open_config_for_test(const QuicPerfConfig &config,
                                                                      std::uint64_t index) {
    return make_client_open_config_for_index(config, index);
}

bool timed_bulk_download_drain_complete_for_test(
    std::span<const QuicPerfDrainStateSnapshot> connections) {
    return std::all_of(connections.begin(), connections.end(), [](const auto &connection) {
        return timed_bulk_download_drain_connection_complete(connection.close_requested,
                                                             connection.active_bulk_streams);
    });
}

bool timed_rr_drain_complete_for_test(std::span<const QuicPerfDrainStateSnapshot> connections) {
    return std::all_of(connections.begin(), connections.end(), [](const auto &connection) {
        return timed_rr_drain_connection_complete(connection.close_requested,
                                                  connection.outstanding_requests);
    });
}

bool timed_crr_drain_complete_for_test(std::span<const QuicPerfDrainStateSnapshot> connections) {
    return std::all_of(connections.begin(), connections.end(), [](const auto &connection) {
        return timed_rr_drain_connection_complete(connection.close_requested,
                                                  connection.outstanding_requests);
    });
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

bool QuicPerfClient::timed_rr_mode() const {
    return config_.mode == QuicPerfMode::rr && !config_.requests.has_value();
}

bool QuicPerfClient::timed_crr_mode() const {
    return config_.mode == QuicPerfMode::crr && !config_.requests.has_value();
}

bool QuicPerfClient::timed_bulk_download_mode() const {
    return config_.mode == QuicPerfMode::bulk && config_.direction == QuicPerfDirection::download &&
           !config_.total_bytes.has_value();
}

bool QuicPerfClient::benchmark_accepts_new_work() const {
    return phase_ != BenchmarkPhase::drain;
}

std::chrono::milliseconds QuicPerfClient::result_elapsed(quic::QuicCoreTimePoint now) const {
    if (timed_rr_mode() || timed_crr_mode() || timed_bulk_download_mode()) {
        if (phase_ == BenchmarkPhase::warmup) {
            return std::chrono::milliseconds{0};
        }
        const auto measurement_now = phase_ == BenchmarkPhase::drain ? measure_deadline_ : now;
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::max(measurement_now, measure_started_at_) - measure_started_at_);
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - run_started_at_);
}

void QuicPerfClient::enter_measure_phase(quic::QuicCoreTimePoint now) {
    phase_ = BenchmarkPhase::measure;
    measure_started_at_ = now;
    measure_deadline_ = now + config_.duration;
    reset_perf_run_summary_measurement(summary_);
    for (auto &[_, connection] : connections_) {
        for (auto &[stream_id, request] : connection.outstanding_requests) {
            (void)stream_id;
            request.counts_toward_measurement = false;
        }
        for (auto &[stream_id, counts_toward_measurement] : connection.active_bulk_streams) {
            (void)stream_id;
            counts_toward_measurement = false;
        }
    }
}

void QuicPerfClient::enter_drain_phase(quic::QuicCoreTimePoint now) {
    phase_ = BenchmarkPhase::drain;
    summary_.elapsed = result_elapsed(now);
    if (config_.mode == QuicPerfMode::rr) {
        for (auto &[_, connection] : connections_) {
            if (connection.outstanding_requests.empty()) {
                (void)maybe_close_rr_connection(connection, now);
            }
        }
    } else if (config_.mode == QuicPerfMode::crr) {
        std::vector<quic::QuicConnectionHandle> idle_connections;
        idle_connections.reserve(connections_.size());
        for (const auto &[handle, connection] : connections_) {
            if (connection.outstanding_requests.empty()) {
                idle_connections.push_back(handle);
            }
        }
        for (const auto handle : idle_connections) {
            auto it = connections_.find(handle);
            if (it != connections_.end()) {
                (void)maybe_close_crr_connection(it->second, now);
            }
        }
    } else if (timed_bulk_download_mode()) {
        for (auto &[_, connection] : connections_) {
            if (connection.active_bulk_streams.empty()) {
                (void)maybe_close_bulk_connection(connection, now);
            }
        }
    }
}

void QuicPerfClient::advance_benchmark_phase(quic::QuicCoreTimePoint now) {
    if (!(timed_rr_mode() || timed_crr_mode() || timed_bulk_download_mode())) {
        return;
    }
    if (phase_ == BenchmarkPhase::warmup && now - run_started_at_ >= config_.warmup) {
        enter_measure_phase(now);
    }
    if (phase_ == BenchmarkPhase::measure && now >= measure_deadline_) {
        enter_drain_phase(now);
    }
}

int QuicPerfClient::run() {
    const auto start = quic::QuicCoreClock::now();
    run_started_at_ = start;
    measure_started_at_ = start;
    phase_ = BenchmarkPhase::warmup;
    if ((timed_rr_mode() || timed_crr_mode() || timed_bulk_download_mode()) &&
        config_.warmup == std::chrono::milliseconds{0}) {
        enter_measure_phase(start);
    }

    const auto emit_results = [&]() {
        std::cout << render_perf_summary(summary_) << '\n';
        return flush_json_result();
    };
    const auto fail = [&](std::string reason) {
        const auto failed_at = quic::QuicCoreClock::now();
        advance_benchmark_phase(failed_at);
        summary_.status = "failed";
        if (!summary_.failure_reason.has_value()) {
            summary_.failure_reason = std::move(reason);
        }
        summary_.elapsed = result_elapsed(failed_at);
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
        const auto current = quic::QuicCoreClock::now();
        advance_benchmark_phase(current);

        if (run_complete()) {
            summary_.status = "ok";
            summary_.elapsed = result_elapsed(current);
            if (timed_rr_mode() || timed_crr_mode()) {
                summary_.server_bytes_sent = summary_.bytes_received;
                summary_.server_bytes_received = summary_.bytes_sent;
                summary_.server_requests_completed = summary_.requests_completed;
            }
            finalize_perf_run_summary(summary_);
            return emit_results() ? 0 : 1;
        }

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
            advance_benchmark_phase(event->now);
            if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, event->now),
                               event->now)) {
                return fail("client timer event failed");
            }
            continue;
        case io::QuicIoEvent::Kind::rx_datagram:
            if (!event->datagram.has_value()) {
                return fail("client missing rx datagram");
            }
            advance_benchmark_phase(event->now);
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
    advance_benchmark_phase(now);

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
                if (closing_connections_.contains(state->connection)) {
                    continue;
                }
                summary_.failure_reason =
                    "client core state failed connection=" + std::to_string(state->connection);
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
                if (!maybe_start_bulk_streams(connection, now) ||
                    !maybe_issue_rr_requests(connection, now) ||
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
                if (!(timed_rr_mode() || timed_crr_mode())) {
                    summary_.requests_completed = complete->requests_completed;
                }
                connection.control_complete = true;
                continue;
            }
            return false;
        }
    }

    connection.bytes_received += received.bytes.size();

    if (timed_bulk_download_mode()) {
        const auto stream_it = connection.active_bulk_streams.find(received.stream_id);
        if (stream_it != connection.active_bulk_streams.end() && stream_it->second) {
            summary_.bytes_received += received.bytes.size();
        }

        if (!received.fin) {
            return true;
        }

        if (stream_it != connection.active_bulk_streams.end()) {
            connection.active_bulk_streams.erase(stream_it);
        }

        while (benchmark_accepts_new_work() &&
               connection.active_bulk_streams.size() < config_.streams) {
            if (!open_bulk_stream(connection, now, phase_ == BenchmarkPhase::measure)) {
                return false;
            }
        }

        if (phase_ == BenchmarkPhase::drain && connection.active_bulk_streams.empty()) {
            return maybe_close_bulk_connection(connection, now);
        }
        return true;
    }

    if (config_.mode == QuicPerfMode::rr || config_.mode == QuicPerfMode::crr) {
        const auto request_it = connection.outstanding_requests.find(received.stream_id);
        if (request_it == connection.outstanding_requests.end()) {
            return true;
        }

        request_it->second.received_bytes += received.bytes.size();
        if (request_it->second.counts_toward_measurement) {
            summary_.bytes_received += received.bytes.size();
        }
        if (!received.fin) {
            return true;
        }

        if (request_it->second.counts_toward_measurement) {
            summary_.latency_samples.push_back(now - request_it->second.started_at);
            ++summary_.requests_completed;
        }
        connection.outstanding_requests.erase(request_it);
        if (config_.mode == QuicPerfMode::rr) {
            if (phase_ == BenchmarkPhase::drain && connection.outstanding_requests.empty()) {
                return maybe_close_rr_connection(connection, now);
            }
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

    summary_.bytes_received += received.bytes.size();

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
        if (timed_bulk_download_mode()) {
            if (phase_ != BenchmarkPhase::drain) {
                return false;
            }
            return std::all_of(connections_.begin(), connections_.end(), [](const auto &entry) {
                return timed_bulk_download_drain_connection_complete(
                    entry.second.close_requested, entry.second.active_bulk_streams.size());
            });
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
        if (timed_rr_mode()) {
            if (phase_ != BenchmarkPhase::drain) {
                return false;
            }
            return std::all_of(connections_.begin(), connections_.end(), [](const auto &entry) {
                return timed_rr_drain_connection_complete(entry.second.close_requested,
                                                          entry.second.outstanding_requests.size());
            });
        }
        if (!config_.requests.has_value() || summary_.requests_completed < *config_.requests) {
            return false;
        }
        return std::all_of(connections_.begin(), connections_.end(), [](const auto &entry) {
            return entry.second.control_complete && entry.second.outstanding_requests.empty();
        });
    case QuicPerfMode::crr:
        if (timed_crr_mode()) {
            if (phase_ != BenchmarkPhase::drain) {
                return false;
            }
            return std::all_of(connections_.begin(), connections_.end(), [](const auto &entry) {
                return timed_rr_drain_connection_complete(entry.second.close_requested,
                                                          entry.second.outstanding_requests.size());
            });
        }
        return config_.requests.has_value() && summary_.requests_completed >= *config_.requests &&
               connections_.empty();
    }
    return false;
}

bool QuicPerfClient::open_bulk_stream(ConnectionState &connection, quic::QuicCoreTimePoint now,
                                      bool counts_toward_measurement) {
    const auto stream_id = connection.next_stream_id;
    connection.next_stream_id = next_client_perf_stream_id(stream_id);
    connection.active_bulk_streams.emplace(stream_id, counts_toward_measurement);

    const auto send_result = core_.advance_endpoint(
        quic::QuicCoreConnectionCommand{
            .connection = connection.handle,
            .input =
                quic::QuicCoreSendStreamData{
                    .stream_id = stream_id,
                    .bytes = {},
                    .fin = true,
                },
        },
        now);
    if (send_result.local_error.has_value() || !flush_send_effects(*backend_, send_result)) {
        connection.active_bulk_streams.erase(stream_id);
        summary_.failure_reason = "client timed bulk request flush failed";
        return false;
    }
    return true;
}

bool QuicPerfClient::maybe_start_bulk_streams(ConnectionState &connection,
                                              quic::QuicCoreTimePoint now) {
    if (config_.mode != QuicPerfMode::bulk || !connection.session_ready ||
        connection.control_complete) {
        return true;
    }

    if (timed_bulk_download_mode()) {
        while (connection.active_bulk_streams.size() < config_.streams &&
               benchmark_accepts_new_work()) {
            if (!open_bulk_stream(connection, now, phase_ == BenchmarkPhase::measure)) {
                return false;
            }
        }
        return true;
    }

    if (connection.next_stream_id != kQuicPerfFirstDataStreamId) {
        return true;
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
    return true;
}

bool QuicPerfClient::maybe_issue_rr_requests(ConnectionState &connection,
                                             quic::QuicCoreTimePoint now) {
    if (config_.mode != QuicPerfMode::rr || !connection.session_ready ||
        connection.control_complete || !benchmark_accepts_new_work()) {
        return true;
    }

    while (connection.outstanding_requests.size() < config_.requests_in_flight &&
           (!config_.requests.has_value() || requests_started_ < *config_.requests)) {
        const auto stream_id = connection.next_stream_id;
        connection.next_stream_id = next_client_perf_stream_id(stream_id);
        const auto [request_it, inserted] = connection.outstanding_requests.emplace(
            stream_id, OutstandingRequest{
                           .started_at = now,
                           .counts_toward_measurement =
                               config_.requests.has_value() || phase_ == BenchmarkPhase::measure,
                       });
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
        if (request_it->second.counts_toward_measurement) {
            summary_.bytes_sent += config_.request_bytes;
        }
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

    if (!benchmark_accepts_new_work()) {
        return maybe_close_crr_connection(connection, now);
    }

    const auto stream_id = connection.next_stream_id;
    connection.next_stream_id = next_client_perf_stream_id(stream_id);
    const auto [request_it, inserted] = connection.outstanding_requests.emplace(
        stream_id, OutstandingRequest{
                       .started_at = now,
                       .counts_toward_measurement =
                           config_.requests.has_value() || phase_ == BenchmarkPhase::measure,
                   });
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
    if (request_it->second.counts_toward_measurement) {
        summary_.bytes_sent += config_.request_bytes;
    }
    return true;
}

bool QuicPerfClient::maybe_close_rr_connection(ConnectionState &connection,
                                               quic::QuicCoreTimePoint now) {
    if (connection.close_requested || !connection.outstanding_requests.empty()) {
        return true;
    }

    connection.close_requested = true;
    closing_connections_.insert(connection.handle);
    const auto close_result = core_.advance_endpoint(
        quic::QuicCoreConnectionCommand{
            .connection = connection.handle,
            .input =
                quic::QuicCoreCloseConnection{
                    .application_error_code = 0,
                    .reason_phrase = "timed rr drain complete",
                },
        },
        now);
    return handle_result(close_result, now);
}

bool QuicPerfClient::maybe_close_bulk_connection(ConnectionState &connection,
                                                 quic::QuicCoreTimePoint now) {
    if (connection.close_requested || !connection.active_bulk_streams.empty()) {
        return true;
    }

    connection.close_requested = true;
    closing_connections_.insert(connection.handle);
    const auto close_result = core_.advance_endpoint(
        quic::QuicCoreConnectionCommand{
            .connection = connection.handle,
            .input =
                quic::QuicCoreCloseConnection{
                    .application_error_code = 0,
                    .reason_phrase = "timed bulk drain complete",
                },
        },
        now);
    return handle_result(close_result, now);
}

bool QuicPerfClient::maybe_close_crr_connection(ConnectionState &connection,
                                                quic::QuicCoreTimePoint now) {
    if (connection.close_requested || !connection.outstanding_requests.empty()) {
        return true;
    }

    connection.close_requested = true;
    closing_connections_.insert(connection.handle);
    const auto close_result = core_.advance_endpoint(
        quic::QuicCoreConnectionCommand{
            .connection = connection.handle,
            .input =
                quic::QuicCoreCloseConnection{
                    .application_error_code = 0,
                    .reason_phrase = "timed crr drain complete",
                },
        },
        now);
    return handle_result(close_result, now);
}

quic::QuicCoreClientConnectionConfig
QuicPerfClient::make_client_open_config(std::uint64_t index) const {
    return make_client_open_config_for_index(config_, index);
}

bool QuicPerfClient::maybe_open_crr_connections(quic::QuicCoreTimePoint now) {
    if (config_.mode != QuicPerfMode::crr || !benchmark_accepts_new_work()) {
        return true;
    }

    while (connections_.size() < config_.connections &&
           (!config_.requests.has_value() || crr_requests_opened_ < *config_.requests)) {
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
