#include "src/http09/http09_client.h"

#include <cstddef>
#include <fstream>
#include <system_error>
#include <utility>

namespace coquic::http09 {

using quic::QuicCoreLocalError;
using quic::QuicCoreLocalErrorCode;
using quic::QuicCoreReceiveStreamData;
using quic::QuicCoreRequestKeyUpdate;
using quic::QuicCoreResult;
using quic::QuicCoreSendStreamData;
using quic::QuicCoreStateChange;
using quic::QuicCoreStateEvent;
using quic::QuicCoreTimePoint;

QuicHttp09ClientEndpoint::QuicHttp09ClientEndpoint(QuicHttp09ClientConfig config)
    : config_(std::move(config)) {
}

QuicHttp09EndpointUpdate QuicHttp09ClientEndpoint::on_core_result(const QuicCoreResult &result,
                                                                  QuicCoreTimePoint /*now*/) {
    if (failed_) {
        return fail_endpoint();
    }

    bool handled_local_error = false;
    if (result.local_error.has_value()) {
        handled_local_error = handle_local_error(*result.local_error);
        if (!handled_local_error) {
            return fail_endpoint();
        }
    } else if (blocked_on_stream_limit_) {
        blocked_on_stream_limit_ = false;
    } else if (pending_open_request_.has_value()) {
        activate_pending_request();
    }

    for (const auto &effect : result.effects) {
        if (const auto *event = std::get_if<QuicCoreStateEvent>(&effect)) {
            if (event->change == QuicCoreStateChange::handshake_ready) {
                handshake_ready_ = true;
            } else if (event->change == QuicCoreStateChange::failed) {
                return fail_endpoint();
            }
            continue;
        }

        const auto *received = std::get_if<QuicCoreReceiveStreamData>(&effect);
        if (received == nullptr) {
            continue;
        }

        if (!process_receive_stream_data(*received)) {
            return fail_endpoint();
        }
    }

    if (!complete_ && next_request_index_ >= config_.requests.size() && !pending_open_request_ &&
        all_streams_complete()) {
        complete_ = true;
    }

    auto update = drain_pending_inputs();
    update.terminal_success = complete_;
    update.handled_local_error = handled_local_error;
    return update;
}

QuicHttp09EndpointUpdate QuicHttp09ClientEndpoint::poll(QuicCoreTimePoint /*now*/) {
    if (failed_) {
        return make_failure_update();
    }

    if (requests_may_be_issued() && !complete_) {
        if (config_.requests.empty()) {
            complete_ = true;
        } else if (can_issue_next_request()) {
            const auto request_index = next_request_index_;
            const auto stream_id = static_cast<std::uint64_t>(request_index) * 4u;
            const auto &request = config_.requests[request_index];
            const std::string line = "GET " + request.request_target + "\r\n";
            pending_core_inputs_.emplace_back(QuicCoreSendStreamData{
                .stream_id = stream_id,
                .bytes = std::vector<std::byte>(reinterpret_cast<const std::byte *>(line.data()),
                                                reinterpret_cast<const std::byte *>(line.data()) +
                                                    line.size()),
                .fin = true,
            });
            pending_open_request_ = PendingOpenRequest{
                .request_index = request_index,
                .stream_id = stream_id,
            };
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

QuicHttp09EndpointUpdate QuicHttp09ClientEndpoint::fail_endpoint() {
    failed_ = true;
    handshake_ready_ = false;
    complete_ = false;
    clear_state();
    return make_failure_update();
}

QuicHttp09EndpointUpdate QuicHttp09ClientEndpoint::drain_pending_inputs() {
    QuicHttp09EndpointUpdate update;
    while (!pending_core_inputs_.empty()) {
        update.core_inputs.push_back(std::move(pending_core_inputs_.front()));
        pending_core_inputs_.pop_front();
    }

    update.has_pending_work = can_issue_next_request() ||
                              (requests_may_be_issued() && !complete_ && config_.requests.empty());
    return update;
}

bool QuicHttp09ClientEndpoint::handle_local_error(const QuicCoreLocalError &error) {
    if (error.code != QuicCoreLocalErrorCode::invalid_stream_id || !error.stream_id.has_value() ||
        !pending_open_request_.has_value() ||
        *error.stream_id != pending_open_request_->stream_id) {
        return false;
    }

    if (!max_concurrent_requests_.has_value()) {
        const auto active_requests = active_request_count();
        if (active_requests == 0) {
            return false;
        }
        max_concurrent_requests_ = active_requests;
    }
    blocked_on_stream_limit_ = true;
    pending_open_request_.reset();
    return true;
}

void QuicHttp09ClientEndpoint::activate_pending_request() {
    if (!pending_open_request_.has_value()) {
        return;
    }

    const auto request_index = pending_open_request_->request_index;
    const auto stream_id = pending_open_request_->stream_id;
    request_streams_.insert_or_assign(
        stream_id, RequestState{
                       .request_target = config_.requests[request_index].request_target,
                       .complete = false,
                   });
    if (config_.request_key_update && !key_update_requested_ && request_index == 0) {
        // Intentionally queued immediately after first request activation; transport-side legality
        // for when the update is actually applied is deferred to later key-update tasks.
        pending_core_inputs_.emplace_back(QuicCoreRequestKeyUpdate{});
        key_update_requested_ = true;
    }
    next_request_index_ = request_index + 1;
    pending_open_request_.reset();
}

bool QuicHttp09ClientEndpoint::requests_may_be_issued() const {
    return handshake_ready_ || config_.allow_requests_before_handshake_ready;
}

bool QuicHttp09ClientEndpoint::can_issue_next_request() const {
    if (!requests_may_be_issued() || failed_ || complete_ || blocked_on_stream_limit_ ||
        pending_open_request_.has_value() || next_request_index_ >= config_.requests.size()) {
        return false;
    }
    if (max_concurrent_requests_.has_value() &&
        active_request_count() >= *max_concurrent_requests_) {
        return false;
    }
    return true;
}

std::size_t QuicHttp09ClientEndpoint::active_request_count() const {
    std::size_t active = 0;
    for (const auto &[stream_id, state] : request_streams_) {
        (void)stream_id;
        if (!state.complete) {
            ++active;
        }
    }
    return active;
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

    std::error_code mkdir_error;
    const auto &parent_path = resolved_path.value().parent_path();
    std::filesystem::create_directories(parent_path, mkdir_error);
    if (mkdir_error) {
        return false;
    }

    std::ofstream output(resolved_path.value(), std::ios::binary | std::ios::app);
    if (!output.is_open()) {
        return false;
    }

    if (!received.bytes.empty()) {
        output.write(reinterpret_cast<const char *>(received.bytes.data()),
                     static_cast<std::streamsize>(received.bytes.size()));
    }

    output.close();
    if (output.fail()) {
        return false;
    }

    if (received.fin) {
        it->second.complete = true;
    }
    return true;
}

bool QuicHttp09ClientEndpoint::all_streams_complete() const {
    for (const auto &[stream_id, state] : request_streams_) {
        (void)stream_id;
        if (!state.complete) {
            return false;
        }
    }
    return true;
}

void QuicHttp09ClientEndpoint::clear_state() {
    blocked_on_stream_limit_ = false;
    pending_open_request_.reset();
    request_streams_.clear();
    pending_core_inputs_.clear();
}

} // namespace coquic::http09
