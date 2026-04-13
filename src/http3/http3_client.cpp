#include "src/http3/http3_client.h"

#include <utility>

namespace coquic::http3 {

namespace {

Http3ClientEndpointUpdate make_failure_update(bool handled_local_error = false) {
    return Http3ClientEndpointUpdate{
        .terminal_failure = true,
        .handled_local_error = handled_local_error,
    };
}

bool merge_connection_update(Http3ClientEndpointUpdate &out, Http3EndpointUpdate &update) {
    for (auto &input : update.core_inputs) {
        out.core_inputs.push_back(std::move(input));
    }
    out.has_pending_work = out.has_pending_work || update.has_pending_work;
    if (update.terminal_failure) {
        out.terminal_failure = true;
        return false;
    }
    return true;
}

bool request_submission_ready(const Http3Connection &connection) {
    return connection.state().local_control_stream_id.has_value();
}

Http3Result<bool> submit_request_to_connection(Http3Connection &connection, std::uint64_t stream_id,
                                               const Http3Request &request) {
    const auto head = connection.submit_request_head(stream_id, request.head);
    if (!head.has_value()) {
        return Http3Result<bool>::failure(head.error());
    }
    if (!request.body.empty()) {
        const auto body =
            connection.submit_request_body(stream_id, request.body, request.trailers.empty());
        if (!body.has_value()) {
            return Http3Result<bool>::failure(body.error());
        }
        if (!request.trailers.empty()) {
            return connection.submit_request_trailers(stream_id, request.trailers);
        }
        return Http3Result<bool>::success(true);
    }
    if (!request.trailers.empty()) {
        return connection.submit_request_trailers(stream_id, request.trailers);
    }
    return connection.finish_request(stream_id);
}

} // namespace

Http3ClientEndpoint::Http3ClientEndpoint(Http3ClientConfig config)
    : config_(config), connection_(Http3ConnectionConfig{
                           .role = Http3ConnectionRole::client,
                           .local_settings = config_.local_settings,
                       }) {
}

Http3Result<std::uint64_t> Http3ClientEndpoint::submit_request(Http3Request request) {
    if (failed_) {
        return Http3Result<std::uint64_t>::failure(Http3Error{
            .code = Http3ErrorCode::general_protocol_error,
            .detail = "client endpoint has failed",
        });
    }

    const auto stream_id = next_request_stream_id_;
    const auto peer_goaway_id = connection_.state().goaway_id;
    if (peer_goaway_id.has_value() && stream_id >= peer_goaway_id.value()) {
        return Http3Result<std::uint64_t>::failure(Http3Error{
            .code = Http3ErrorCode::request_rejected,
            .detail = "peer goaway prevents issuing a new request",
            .stream_id = stream_id,
        });
    }

    next_request_stream_id_ += 4u;
    if (request_submission_ready(connection_)) {
        const auto submitted = submit_request_to_connection(connection_, stream_id, request);
        if (!submitted.has_value()) {
            return Http3Result<std::uint64_t>::failure(submitted.error());
        }
        active_requests_.insert_or_assign(stream_id, std::move(request));
        return Http3Result<std::uint64_t>::success(stream_id);
    }

    pending_requests_.push_back(PendingRequest{
        .stream_id = stream_id,
        .request = std::move(request),
    });
    return Http3Result<std::uint64_t>::success(stream_id);
}

Http3ClientEndpointUpdate Http3ClientEndpoint::on_core_result(const quic::QuicCoreResult &result,
                                                              quic::QuicCoreTimePoint now) {
    if (failed_) {
        return make_failure_update();
    }
    if (result.local_error.has_value()) {
        failed_ = true;
        pending_requests_.clear();
        active_requests_.clear();
        pending_responses_.clear();
        return make_failure_update(/*handled_local_error=*/true);
    }

    Http3ClientEndpointUpdate update;
    auto connection_update = connection_.on_core_result(result, now);
    if (!merge_connection_update(update, connection_update)) {
        failed_ = true;
        pending_requests_.clear();
        active_requests_.clear();
        pending_responses_.clear();
        return update;
    }
    if (!handle_connection_events(update, connection_update.events)) {
        return make_failure_update();
    }

    update.has_pending_work = update.has_pending_work || !pending_requests_.empty();
    return update;
}

Http3ClientEndpointUpdate Http3ClientEndpoint::poll(quic::QuicCoreTimePoint now) {
    if (failed_) {
        return make_failure_update();
    }

    if (request_submission_ready(connection_)) {
        while (!pending_requests_.empty()) {
            auto pending = std::move(pending_requests_.front());
            pending_requests_.pop_front();
            const auto submitted =
                submit_request_to_connection(connection_, pending.stream_id, pending.request);
            if (!submitted.has_value()) {
                failed_ = true;
                pending_requests_.clear();
                active_requests_.clear();
                pending_responses_.clear();
                return make_failure_update();
            }
            active_requests_.insert_or_assign(pending.stream_id, std::move(pending.request));
        }
    }

    Http3ClientEndpointUpdate update;
    auto connection_update = connection_.poll(now);
    if (!merge_connection_update(update, connection_update)) {
        failed_ = true;
        pending_requests_.clear();
        active_requests_.clear();
        pending_responses_.clear();
        return update;
    }
    if (!handle_connection_events(update, connection_update.events)) {
        return make_failure_update();
    }

    update.has_pending_work = update.has_pending_work || !pending_requests_.empty();
    return update;
}

bool Http3ClientEndpoint::has_failed() const {
    return failed_;
}

bool Http3ClientEndpoint::handle_connection_events(Http3ClientEndpointUpdate &update,
                                                   std::span<const Http3EndpointEvent> events) {
    for (const auto &event : events) {
        if (const auto *interim = std::get_if<Http3PeerInformationalResponseEvent>(&event)) {
            pending_responses_[interim->stream_id].interim_heads.push_back(interim->head);
            continue;
        }

        if (const auto *head = std::get_if<Http3PeerResponseHeadEvent>(&event)) {
            pending_responses_[head->stream_id].head = head->head;
            continue;
        }

        if (const auto *body = std::get_if<Http3PeerResponseBodyEvent>(&event)) {
            auto &pending = pending_responses_[body->stream_id];
            pending.body.insert(pending.body.end(), body->body.begin(), body->body.end());
            continue;
        }

        if (const auto *trailers = std::get_if<Http3PeerResponseTrailersEvent>(&event)) {
            pending_responses_[trailers->stream_id].trailers = trailers->trailers;
            continue;
        }

        if (const auto *reset = std::get_if<Http3PeerResponseResetEvent>(&event)) {
            const auto request_it = active_requests_.find(reset->stream_id);
            pending_responses_.erase(reset->stream_id);
            if (request_it == active_requests_.end()) {
                continue;
            }

            update.request_error_events.push_back(Http3ClientRequestErrorEvent{
                .stream_id = reset->stream_id,
                .request = std::move(request_it->second),
                .application_error_code = reset->application_error_code,
            });
            active_requests_.erase(request_it);
            continue;
        }

        const auto *complete = std::get_if<Http3PeerResponseCompleteEvent>(&event);
        if (complete == nullptr) {
            continue;
        }

        const auto request_it = active_requests_.find(complete->stream_id);
        const auto response_it = pending_responses_.find(complete->stream_id);
        if (request_it == active_requests_.end() || response_it == pending_responses_.end() ||
            !response_it->second.head.has_value()) {
            failed_ = true;
            pending_requests_.clear();
            active_requests_.clear();
            pending_responses_.clear();
            return false;
        }

        auto response_head = std::move(response_it->second.head).value_or(Http3ResponseHead{});
        update.events.push_back(Http3ClientResponseEvent{
            .stream_id = complete->stream_id,
            .request = std::move(request_it->second),
            .response =
                Http3Response{
                    .interim_heads = std::move(response_it->second.interim_heads),
                    .head = std::move(response_head),
                    .body = std::move(response_it->second.body),
                    .trailers = std::move(response_it->second.trailers),
                },
        });
        active_requests_.erase(request_it);
        pending_responses_.erase(response_it);
    }

    return true;
}

} // namespace coquic::http3
