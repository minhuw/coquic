#include "src/quic/http09_client.h"

#include <cstddef>
#include <fstream>
#include <utility>

namespace coquic::quic {

QuicHttp09ClientEndpoint::QuicHttp09ClientEndpoint(QuicHttp09ClientConfig config)
    : config_(std::move(config)) {
}

QuicHttp09EndpointUpdate QuicHttp09ClientEndpoint::on_core_result(const QuicCoreResult &result,
                                                                  QuicCoreTimePoint /*now*/) {
    if (failed_ || result.local_error.has_value()) {
        failed_ = true;
        clear_state();
        return make_failure_update();
    }

    for (const auto &effect : result.effects) {
        if (const auto *event = std::get_if<QuicCoreStateEvent>(&effect)) {
            if (event->change == QuicCoreStateChange::handshake_ready) {
                handshake_ready_ = true;
            } else if (event->change == QuicCoreStateChange::failed) {
                failed_ = true;
                clear_state();
                return make_failure_update();
            }
            continue;
        }

        const auto *received = std::get_if<QuicCoreReceiveStreamData>(&effect);
        if (received == nullptr) {
            continue;
        }

        if (!process_receive_stream_data(*received)) {
            failed_ = true;
            clear_state();
            return make_failure_update();
        }
    }

    if (!complete_ && requests_issued_ && all_streams_complete()) {
        complete_ = true;
    }

    auto update = drain_pending_inputs();
    update.terminal_success = complete_;
    return update;
}

QuicHttp09EndpointUpdate QuicHttp09ClientEndpoint::poll(QuicCoreTimePoint /*now*/) {
    if (failed_) {
        return make_failure_update();
    }

    if (handshake_ready_ && !requests_issued_) {
        for (std::size_t index = 0; index < config_.requests.size(); ++index) {
            const auto stream_id = static_cast<std::uint64_t>(index) * 4u;
            const auto &request = config_.requests[index];
            const std::string line = "GET " + request.request_target + "\r\n";
            pending_core_inputs_.emplace_back(QuicCoreSendStreamData{
                .stream_id = stream_id,
                .bytes = std::vector<std::byte>(reinterpret_cast<const std::byte *>(line.data()),
                                                reinterpret_cast<const std::byte *>(line.data()) +
                                                    line.size()),
                .fin = true,
            });
            request_streams_.insert_or_assign(stream_id,
                                              RequestState{
                                                  .request_target = request.request_target,
                                                  .complete = false,
                                              });
        }
        requests_issued_ = true;
        if (request_streams_.empty()) {
            complete_ = true;
        }
    }

    auto update = drain_pending_inputs();
    update.terminal_success = complete_;
    return update;
}

bool QuicHttp09ClientEndpoint::is_complete() const {
    return complete_;
}

bool QuicHttp09ClientEndpoint::has_failed() const {
    return failed_;
}

QuicHttp09EndpointUpdate QuicHttp09ClientEndpoint::make_failure_update() const {
    return QuicHttp09EndpointUpdate{
        .terminal_failure = true,
    };
}

QuicHttp09EndpointUpdate QuicHttp09ClientEndpoint::drain_pending_inputs() {
    QuicHttp09EndpointUpdate update;
    while (!pending_core_inputs_.empty()) {
        update.core_inputs.push_back(std::move(pending_core_inputs_.front()));
        pending_core_inputs_.pop_front();
    }

    const bool waiting_to_issue_requests = handshake_ready_ && !requests_issued_;
    update.has_pending_work = waiting_to_issue_requests || !pending_core_inputs_.empty();
    return update;
}

bool QuicHttp09ClientEndpoint::process_receive_stream_data(
    const QuicCoreReceiveStreamData &received) {
    const auto it = request_streams_.find(received.stream_id);
    if (it == request_streams_.end()) {
        return false;
    }
    if (it->second.complete) {
        return false;
    }

    const auto resolved_path =
        resolve_http09_path_under_root(config_.download_root, it->second.request_target);
    if (!resolved_path.has_value()) {
        return false;
    }

    std::filesystem::create_directories(resolved_path.value().parent_path());
    std::ofstream output(resolved_path.value(), std::ios::binary | std::ios::app);
    if (!output.is_open()) {
        return false;
    }

    for (const auto byte : received.bytes) {
        output.put(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }

    if (!output.good()) {
        return false;
    }

    if (received.fin) {
        it->second.complete = true;
    }
    return true;
}

bool QuicHttp09ClientEndpoint::all_streams_complete() const {
    if (!requests_issued_) {
        return false;
    }

    for (const auto &[stream_id, state] : request_streams_) {
        (void)stream_id;
        if (!state.complete) {
            return false;
        }
    }
    return true;
}

void QuicHttp09ClientEndpoint::clear_state() {
    request_streams_.clear();
    pending_core_inputs_.clear();
}

} // namespace coquic::quic
