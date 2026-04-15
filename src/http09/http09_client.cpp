#include <algorithm>
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
    } else {
        blocked_on_stream_limit_ = false;
        while (!pending_open_requests_.empty()) {
            activate_pending_request();
        }
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

    if (!complete_ && !has_unissued_requests() && pending_open_requests_.empty() &&
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
        if (!has_unissued_requests() && pending_open_requests_.empty() && all_streams_complete()) {
            complete_ = true;
        } else {
            const bool batch_resumed_requests = config_.allow_requests_before_handshake_ready;
            do {
                if (!can_issue_next_request()) {
                    break;
                }

                const auto next_request = take_next_request_to_issue();
                if (!next_request.has_value()) {
                    break;
                }

                queue_request_send(*next_request);
            } while (batch_resumed_requests);
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
        pending_open_requests_.empty()) {
        return false;
    }

    const auto failed_stream_id = *error.stream_id;
    const auto failed_request =
        std::find_if(pending_open_requests_.begin(), pending_open_requests_.end(),
                     [failed_stream_id](const PendingOpenRequest &request) {
                         return request.stream_id == failed_stream_id;
                     });
    if (failed_request == pending_open_requests_.end()) {
        return false;
    }

    while (!pending_open_requests_.empty() &&
           pending_open_requests_.front().stream_id != failed_stream_id) {
        activate_pending_request();
    }

    if (pending_open_requests_.empty() ||
        pending_open_requests_.front().stream_id != failed_stream_id) {
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
    while (!pending_open_requests_.empty()) {
        retry_open_requests_.push_back(pending_open_requests_.front());
        pending_open_requests_.pop_front();
    }
    return true;
}

void QuicHttp09ClientEndpoint::activate_pending_request() {
    if (pending_open_requests_.empty()) {
        return;
    }

    const auto request_index = pending_open_requests_.front().request_index;
    const auto stream_id = pending_open_requests_.front().stream_id;
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
    next_request_index_ = std::max(next_request_index_, request_index + 1);
    pending_open_requests_.pop_front();
}

bool QuicHttp09ClientEndpoint::has_unissued_requests() const {
    return !retry_open_requests_.empty() || next_request_index_ < config_.requests.size();
}

bool QuicHttp09ClientEndpoint::requests_may_be_issued() const {
    return handshake_ready_ || config_.allow_requests_before_handshake_ready;
}

bool QuicHttp09ClientEndpoint::can_issue_next_request() const {
    if (!requests_may_be_issued() || failed_ || complete_ || blocked_on_stream_limit_ ||
        !has_unissued_requests()) {
        return false;
    }

    const auto in_flight_requests = in_flight_request_count();
    if (max_concurrent_requests_.has_value() && in_flight_requests >= *max_concurrent_requests_) {
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

std::size_t QuicHttp09ClientEndpoint::in_flight_request_count() const {
    return active_request_count() + pending_open_requests_.size();
}

std::optional<QuicHttp09ClientEndpoint::PendingOpenRequest>
QuicHttp09ClientEndpoint::take_next_request_to_issue() {
    if (!retry_open_requests_.empty()) {
        auto request = retry_open_requests_.front();
        retry_open_requests_.pop_front();
        return request;
    }
    if (next_request_index_ >= config_.requests.size()) {
        return std::nullopt;
    }

    const auto request_index = next_request_index_++;
    return PendingOpenRequest{
        .request_index = request_index,
        .stream_id = static_cast<std::uint64_t>(request_index) * 4u,
    };
}

void QuicHttp09ClientEndpoint::queue_request_send(const PendingOpenRequest &request) {
    const auto &target = config_.requests[request.request_index].request_target;
    const std::string line = "GET " + target + "\r\n";
    pending_core_inputs_.emplace_back(QuicCoreSendStreamData{
        .stream_id = request.stream_id,
        .bytes =
            std::vector<std::byte>(reinterpret_cast<const std::byte *>(line.data()),
                                   reinterpret_cast<const std::byte *>(line.data()) + line.size()),
        .fin = true,
    });
    pending_open_requests_.push_back(request);
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
    pending_open_requests_.clear();
    retry_open_requests_.clear();
    request_streams_.clear();
    pending_core_inputs_.clear();
}

} // namespace coquic::http09
