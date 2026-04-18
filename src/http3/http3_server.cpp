#include "src/http3/http3_server.h"
#include "src/http3/http3_demo_routes.h"

#include <limits>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace coquic::http3 {

namespace {

constexpr Http3DemoRouteLimits kDefaultDemoRouteLimits{};

Http3ServerEndpointUpdate make_failure_update(bool handled_local_error = false) {
    return Http3ServerEndpointUpdate{
        .terminal_failure = true,
        .handled_local_error = handled_local_error,
    };
}

Http3Response built_in_or_buffered_handler_response(const Http3ServerConfig &config,
                                                    const Http3Request &request) {
    if (const auto response = try_demo_route_response(request); response.has_value()) {
        return *response;
    }

    if (config.request_handler) {
        return config.request_handler(request);
    }

    if (config.fallback_request_handler) {
        return config.fallback_request_handler(request);
    }

    return Http3Response{
        .head =
            {
                .status = 404,
                .content_length = 0,
            },
    };
}

Http3Result<bool> submit_response(Http3Connection &connection, std::uint64_t stream_id,
                                  const Http3RequestHead &request_head,
                                  const Http3Response &response) {
    for (const auto &interim : response.interim_heads) {
        const auto submitted = connection.submit_response_head(stream_id, interim);
        if (!submitted.has_value()) {
            return submitted;
        }
    }

    auto final_head = response.head;
    const bool head_request = request_head.method == "HEAD";
    if (head_request && !final_head.content_length.has_value()) {
        if (response.body.size() >
            static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max())) {
            return Http3Result<bool>::failure(Http3Error{
                .code = Http3ErrorCode::internal_error,
                .detail = "response body exceeds representable content-length",
                .stream_id = stream_id,
            });
        }
        final_head.content_length = static_cast<std::uint64_t>(response.body.size());
    }

    auto head_submit = connection.submit_response_head(stream_id, final_head);
    if (!head_submit.has_value()) {
        return head_submit;
    }

    if (head_request) {
        return connection.finish_response(stream_id, /*enforce_content_length=*/false);
    }

    if (!response.body.empty()) {
        const auto body_submit =
            connection.submit_response_body(stream_id, response.body, response.trailers.empty());
        if (!body_submit.has_value()) {
            return body_submit;
        }
    }

    if (!response.trailers.empty()) {
        return connection.submit_response_trailers(stream_id, response.trailers);
    }

    if (response.body.empty()) {
        return connection.finish_response(stream_id);
    }

    return Http3Result<bool>::success(true);
}

std::string_view request_path_without_query(std::string_view path) {
    const auto query = path.find('?');
    return query == std::string_view::npos ? path : path.substr(0, query);
}

bool is_default_speed_upload_request(const Http3RequestHead &request_head) {
    return request_head.method == "POST" &&
           request_path_without_query(request_head.path) == "/_coquic/speed/upload";
}

Http3Response speed_upload_limit_response() {
    return Http3Response{
        .head =
            {
                .status = 400,
                .content_length = 0,
                .headers = {{"cache-control", "no-store"}},
            },
    };
}

std::optional<Http3Response> default_route_head_response(const Http3RequestHead &request_head) {
    if (!is_default_speed_upload_request(request_head)) {
        return std::nullopt;
    }
    if (!request_head.content_length.has_value() ||
        *request_head.content_length <= kDefaultDemoRouteLimits.max_speed_upload_bytes) {
        return std::nullopt;
    }
    return speed_upload_limit_response();
}

bool would_exceed_body_limit(std::size_t buffered_bytes, std::size_t incoming_bytes,
                             std::size_t limit) {
    return buffered_bytes > limit || incoming_bytes > limit - buffered_bytes;
}

bool commit_early_response(Http3Connection &connection, std::uint64_t stream_id,
                           const Http3RequestHead &request_head, const Http3Response &response,
                           bool request_completed,
                           std::unordered_set<std::uint64_t> &ignored_request_streams,
                           bool &dispatched_response) {
    const auto submitted = submit_response(connection, stream_id, request_head, response);
    if (!submitted.has_value()) {
        return false;
    }

    ignored_request_streams.insert(stream_id);
    if (!request_completed) {
        const auto aborted = connection.abort_request_body(
            stream_id, static_cast<std::uint64_t>(Http3ErrorCode::no_error));
        if (!aborted.has_value()) {
            return false;
        }
    }

    dispatched_response = true;
    return true;
}

bool merge_connection_update(Http3ServerEndpointUpdate &out, Http3EndpointUpdate &update) {
    for (auto &input : update.core_inputs) {
        out.core_inputs.push_back(std::move(input));
    }
    if (update.terminal_failure) {
        out.terminal_failure = true;
        return false;
    }
    return true;
}

} // namespace

Http3ServerEndpoint::Http3ServerEndpoint(Http3ServerConfig config)
    : config_(std::move(config)), connection_(Http3ConnectionConfig{
                                      .role = Http3ConnectionRole::server,
                                      .local_settings = config_.local_settings,
                                  }) {
}

Http3ServerEndpointUpdate Http3ServerEndpoint::on_core_result(const quic::QuicCoreResult &result,
                                                              quic::QuicCoreTimePoint now) {
    if (failed_) {
        return make_failure_update();
    }
    if (result.local_error.has_value()) {
        failed_ = true;
        pending_requests_.clear();
        return make_failure_update(/*handled_local_error=*/true);
    }

    Http3ServerEndpointUpdate update;
    auto connection_update = connection_.on_core_result(result, now);
    if (!merge_connection_update(update, connection_update)) {
        failed_ = true;
        pending_requests_.clear();
        return update;
    }

    std::unordered_set<std::uint64_t> completed_request_streams;
    for (const auto &event : connection_update.events) {
        if (const auto *complete = std::get_if<Http3PeerRequestCompleteEvent>(&event)) {
            completed_request_streams.insert(complete->stream_id);
        }
    }

    bool dispatched_response = false;
    std::unordered_set<std::uint64_t> ignored_request_streams;
    for (const auto &event : connection_update.events) {
        if (const auto *head = std::get_if<Http3PeerRequestHeadEvent>(&event)) {
            auto &pending = pending_requests_[head->stream_id];
            pending.head = head->head;

            std::optional<Http3Response> response;
            if (config_.request_head_handler) {
                response = config_.request_head_handler(head->head);
            }
            if (!response.has_value()) {
                response = default_route_head_response(head->head);
                if (!response.has_value()) {
                    continue;
                }
            }

            if (!commit_early_response(connection_, head->stream_id, head->head, response.value(),
                                       completed_request_streams.contains(head->stream_id),
                                       ignored_request_streams, dispatched_response)) {
                failed_ = true;
                pending_requests_.clear();
                return make_failure_update();
            }

            pending.early_response_committed = true;
            continue;
        }

        if (const auto *body = std::get_if<Http3PeerRequestBodyEvent>(&event)) {
            if (ignored_request_streams.contains(body->stream_id)) {
                continue;
            }

            const auto pending_it = pending_requests_.find(body->stream_id);
            if (pending_it != pending_requests_.end() &&
                pending_it->second.early_response_committed) {
                continue;
            }

            if (pending_it != pending_requests_.end()) {
                const auto &pending = pending_it->second;
                const auto &request_head = pending.head;
                if (request_head.has_value() &&
                    is_default_speed_upload_request(request_head.value()) &&
                    would_exceed_body_limit(pending.body.size(), body->body.size(),
                                            kDefaultDemoRouteLimits.max_speed_upload_bytes)) {
                    if (!commit_early_response(connection_, body->stream_id, request_head.value(),
                                               speed_upload_limit_response(),
                                               completed_request_streams.contains(body->stream_id),
                                               ignored_request_streams, dispatched_response)) {
                        failed_ = true;
                        pending_requests_.clear();
                        return make_failure_update();
                    }

                    pending_it->second.early_response_committed = true;
                    continue;
                }
            }

            auto &pending = pending_requests_[body->stream_id];
            pending.body.insert(pending.body.end(), body->body.begin(), body->body.end());
            continue;
        }

        if (const auto *trailers = std::get_if<Http3PeerRequestTrailersEvent>(&event)) {
            if (ignored_request_streams.contains(trailers->stream_id)) {
                continue;
            }

            const auto pending_it = pending_requests_.find(trailers->stream_id);
            if (pending_it != pending_requests_.end() &&
                pending_it->second.early_response_committed) {
                continue;
            }

            pending_requests_[trailers->stream_id].trailers = trailers->trailers;
            continue;
        }

        if (const auto *reset = std::get_if<Http3PeerRequestResetEvent>(&event)) {
            const auto pending_it = pending_requests_.find(reset->stream_id);
            if (ignored_request_streams.contains(reset->stream_id)) {
                pending_requests_.erase(reset->stream_id);
                continue;
            }
            if (pending_it == pending_requests_.end()) {
                continue;
            }
            if (pending_it->second.early_response_committed) {
                pending_requests_.erase(pending_it);
                continue;
            }

            update.request_cancelled_events.push_back(Http3ServerRequestCancelledEvent{
                .stream_id = reset->stream_id,
                .head = std::move(pending_it->second.head),
                .body = std::move(pending_it->second.body),
                .trailers = std::move(pending_it->second.trailers),
                .application_error_code = reset->application_error_code,
            });
            pending_requests_.erase(pending_it);
            continue;
        }

        const auto *complete = std::get_if<Http3PeerRequestCompleteEvent>(&event);
        if (complete == nullptr) {
            continue;
        }

        const auto pending_it = pending_requests_.find(complete->stream_id);
        if (ignored_request_streams.contains(complete->stream_id)) {
            pending_requests_.erase(complete->stream_id);
            continue;
        }
        if (pending_it == pending_requests_.end() || !pending_it->second.head.has_value()) {
            failed_ = true;
            pending_requests_.clear();
            return make_failure_update();
        }
        if (pending_it->second.early_response_committed) {
            pending_requests_.erase(pending_it);
            continue;
        }

        Http3Request request;
        if (const auto &request_head = pending_it->second.head; request_head.has_value()) {
            request = Http3Request{
                .head = *request_head,
                .body = pending_it->second.body,
                .trailers = pending_it->second.trailers,
            };
        } else {
            failed_ = true;
            pending_requests_.clear();
            return make_failure_update();
        }
        auto response = built_in_or_buffered_handler_response(config_, request);

        const auto submitted =
            submit_response(connection_, complete->stream_id, request.head, response);
        if (!submitted.has_value()) {
            failed_ = true;
            pending_requests_.clear();
            return make_failure_update();
        }

        pending_requests_.erase(pending_it);
        dispatched_response = true;
    }

    for (const auto stream_id : ignored_request_streams) {
        pending_requests_.erase(stream_id);
    }

    if (dispatched_response) {
        auto follow_up = connection_.poll(now);
        if (!merge_connection_update(update, follow_up)) {
            failed_ = true;
            pending_requests_.clear();
            return update;
        }
    }

    return update;
}

Http3ServerEndpointUpdate Http3ServerEndpoint::poll(quic::QuicCoreTimePoint now) {
    if (failed_) {
        return make_failure_update();
    }

    Http3ServerEndpointUpdate update;
    auto connection_update = connection_.poll(now);
    if (!merge_connection_update(update, connection_update)) {
        failed_ = true;
        pending_requests_.clear();
    }
    return update;
}

bool Http3ServerEndpoint::has_failed() const {
    return failed_;
}

} // namespace coquic::http3
