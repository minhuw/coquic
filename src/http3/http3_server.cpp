#include "src/http3/http3_server.h"

#include <limits>
#include <string>
#include <utility>

namespace coquic::http3 {

namespace {

Http3ServerEndpointUpdate make_failure_update(bool handled_local_error = false) {
    return Http3ServerEndpointUpdate{
        .terminal_failure = true,
        .handled_local_error = handled_local_error,
    };
}

void append_json_escaped(std::string &out, std::string_view value) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    out.push_back('"');
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (ch < 0x20u) {
                out += "\\u00";
                out.push_back(kHexDigits[(ch >> 4u) & 0x0fu]);
                out.push_back(kHexDigits[ch & 0x0fu]);
            } else {
                out.push_back(static_cast<char>(ch));
            }
            break;
        }
    }
    out.push_back('"');
}

std::vector<std::byte> inspect_json_body(const Http3Request &request) {
    std::string json = "{\"method\":";
    append_json_escaped(json, request.head.method);
    json += ",\"content_length\":";
    if (request.head.content_length.has_value()) {
        json += std::to_string(*request.head.content_length);
    } else {
        json += "null";
    }
    json += ",\"body_bytes\":";
    json += std::to_string(request.body.size());
    json += ",\"trailers\":[";
    for (std::size_t index = 0; index < request.trailers.size(); ++index) {
        if (index != 0) {
            json.push_back(',');
        }
        json += "{\"name\":";
        append_json_escaped(json, request.trailers[index].name);
        json += ",\"value\":";
        append_json_escaped(json, request.trailers[index].value);
        json.push_back('}');
    }
    json += "]}";

    return std::vector<std::byte>(reinterpret_cast<const std::byte *>(json.data()),
                                  reinterpret_cast<const std::byte *>(json.data()) + json.size());
}

Http3Response default_route_response(const Http3Request &request) {
    if (request.head.path == "/_coquic/echo") {
        if (request.head.method != "POST") {
            return Http3Response{
                .head =
                    {
                        .status = 405,
                        .content_length = 0,
                        .headers = {{"allow", "POST"}},
                    },
            };
        }

        return Http3Response{
            .head =
                {
                    .status = 200,
                    .content_length = static_cast<std::uint64_t>(request.body.size()),
                    .headers = {{"content-type", "application/octet-stream"}},
                },
            .body = request.body,
        };
    }

    if (request.head.path == "/_coquic/inspect") {
        if (request.head.method != "POST") {
            return Http3Response{
                .head =
                    {
                        .status = 405,
                        .content_length = 0,
                        .headers = {{"allow", "POST"}},
                    },
            };
        }

        auto body = inspect_json_body(request);
        return Http3Response{
            .head =
                {
                    .status = 200,
                    .content_length = static_cast<std::uint64_t>(body.size()),
                    .headers = {{"content-type", "application/json"}},
                },
            .body = std::move(body),
        };
    }

    return Http3Response{
        .head =
            {
                .status = 404,
                .content_length = 0,
            },
    };
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

    bool dispatched_response = false;
    for (const auto &event : connection_update.events) {
        if (const auto *head = std::get_if<Http3PeerRequestHeadEvent>(&event)) {
            auto &pending = pending_requests_[head->stream_id];
            pending.head = head->head;
            continue;
        }

        if (const auto *body = std::get_if<Http3PeerRequestBodyEvent>(&event)) {
            auto &pending = pending_requests_[body->stream_id];
            pending.body.insert(pending.body.end(), body->body.begin(), body->body.end());
            continue;
        }

        if (const auto *trailers = std::get_if<Http3PeerRequestTrailersEvent>(&event)) {
            pending_requests_[trailers->stream_id].trailers = trailers->trailers;
            continue;
        }

        if (const auto *reset = std::get_if<Http3PeerRequestResetEvent>(&event)) {
            const auto pending_it = pending_requests_.find(reset->stream_id);
            if (pending_it == pending_requests_.end()) {
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
        if (pending_it == pending_requests_.end() || !pending_it->second.head.has_value()) {
            failed_ = true;
            pending_requests_.clear();
            return make_failure_update();
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
        auto response = config_.request_handler ? config_.request_handler(request)
                                                : default_route_response(request);

        for (const auto &interim : response.interim_heads) {
            const auto submitted = connection_.submit_response_head(complete->stream_id, interim);
            if (!submitted.has_value()) {
                failed_ = true;
                pending_requests_.clear();
                return make_failure_update();
            }
        }

        auto final_head = response.head;
        const bool head_request = request.head.method == "HEAD";
        if (head_request && !final_head.content_length.has_value()) {
            if (response.body.size() >
                static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max())) {
                failed_ = true;
                pending_requests_.clear();
                return make_failure_update();
            }
            final_head.content_length = static_cast<std::uint64_t>(response.body.size());
        }

        const auto head_submit = connection_.submit_response_head(complete->stream_id, final_head);
        if (!head_submit.has_value()) {
            failed_ = true;
            pending_requests_.clear();
            return make_failure_update();
        }

        if (head_request) {
            const auto finished = connection_.finish_response(complete->stream_id,
                                                              /*enforce_content_length=*/false);
            if (!finished.has_value()) {
                failed_ = true;
                pending_requests_.clear();
                return make_failure_update();
            }
        } else if (!response.body.empty()) {
            const auto body_submit = connection_.submit_response_body(
                complete->stream_id, response.body, response.trailers.empty());
            if (!body_submit.has_value()) {
                failed_ = true;
                pending_requests_.clear();
                return make_failure_update();
            }
            if (!response.trailers.empty()) {
                const auto trailers_submit =
                    connection_.submit_response_trailers(complete->stream_id, response.trailers);
                if (!trailers_submit.has_value()) {
                    failed_ = true;
                    pending_requests_.clear();
                    return make_failure_update();
                }
            }
        } else if (!response.trailers.empty()) {
            const auto trailers_submit =
                connection_.submit_response_trailers(complete->stream_id, response.trailers);
            if (!trailers_submit.has_value()) {
                failed_ = true;
                pending_requests_.clear();
                return make_failure_update();
            }
        } else {
            const auto finished = connection_.finish_response(complete->stream_id);
            if (!finished.has_value()) {
                failed_ = true;
                pending_requests_.clear();
                return make_failure_update();
            }
        }

        pending_requests_.erase(pending_it);
        dispatched_response = true;
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
