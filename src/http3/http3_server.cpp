#include "src/http3/http3_server.h"

#include <limits>
#include <string>
#include <unordered_set>
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

std::vector<Http3Field> request_fields_for_test(const Http3RequestHead &head) {
    std::vector<Http3Field> fields;
    fields.reserve(head.headers.size() + 5u);
    fields.push_back(Http3Field{
        .name = ":method",
        .value = head.method,
    });
    fields.push_back(Http3Field{
        .name = ":scheme",
        .value = head.scheme,
    });
    fields.push_back(Http3Field{
        .name = ":authority",
        .value = head.authority,
    });
    fields.push_back(Http3Field{
        .name = ":path",
        .value = head.path,
    });
    if (head.content_length.has_value()) {
        fields.push_back(Http3Field{
            .name = "content-length",
            .value = std::to_string(*head.content_length),
        });
    }
    fields.insert(fields.end(), head.headers.begin(), head.headers.end());
    return fields;
}

std::vector<std::byte> request_headers_frame_for_test(const Http3RequestHead &head,
                                                      std::uint64_t stream_id) {
    Http3QpackEncoderContext encoder;
    const auto encoded =
        encode_http3_field_section(encoder, stream_id, request_fields_for_test(head)).value();
    auto field_section = encoded.prefix;
    field_section.insert(field_section.end(), encoded.payload.begin(), encoded.payload.end());
    return serialize_http3_frame(Http3Frame{
                                     Http3HeadersFrame{
                                         .field_section = std::move(field_section),
                                     },
                                 })
        .value();
}

std::vector<quic::QuicCoreSendStreamData>
send_stream_inputs_for_test(const Http3EndpointUpdate &update) {
    std::vector<quic::QuicCoreSendStreamData> sends;
    sends.reserve(update.core_inputs.size());
    for (const auto &input : update.core_inputs) {
        sends.push_back(std::get<quic::QuicCoreSendStreamData>(input));
    }
    return sends;
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
        if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
            if (response.body.size() >
                static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max())) {
                return Http3Result<bool>::failure(Http3Error{
                    .code = Http3ErrorCode::internal_error,
                    .detail = "response body exceeds representable content-length",
                    .stream_id = stream_id,
                });
            }
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

            if (!config_.request_head_handler) {
                continue;
            }

            const auto response = config_.request_head_handler(head->head);
            if (!response.has_value()) {
                continue;
            }

            const auto submitted =
                submit_response(connection_, head->stream_id, head->head, response.value());
            if (!submitted.has_value()) {
                failed_ = true;
                pending_requests_.clear();
                return make_failure_update();
            }

            pending.early_response_committed = true;
            ignored_request_streams.insert(head->stream_id);
            if (!completed_request_streams.contains(head->stream_id)) {
                static_cast<void>(connection_.abort_request_body(
                    head->stream_id, static_cast<std::uint64_t>(Http3ErrorCode::no_error)));
            }
            dispatched_response = true;
            continue;
        }

        if (const auto *body = std::get_if<Http3PeerRequestBodyEvent>(&event)) {
            if (ignored_request_streams.contains(body->stream_id)) {
                continue;
            }

            auto &pending = pending_requests_[body->stream_id];
            pending.body.insert(pending.body.end(), body->body.begin(), body->body.end());
            continue;
        }

        if (const auto *trailers = std::get_if<Http3PeerRequestTrailersEvent>(&event)) {
            if (ignored_request_streams.contains(trailers->stream_id)) {
                continue;
            }

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

        const auto &complete = std::get<Http3PeerRequestCompleteEvent>(event);
        if (ignored_request_streams.contains(complete.stream_id)) {
            pending_requests_.erase(complete.stream_id);
            continue;
        }

        auto pending_it = pending_requests_.find(complete.stream_id);
        if (pending_it == pending_requests_.end()) {
            failed_ = true;
            pending_requests_.clear();
            return make_failure_update();
        }

        auto &pending = pending_it->second;
        auto request_head = pending.head;
        if (!request_head.has_value()) {
            failed_ = true;
            pending_requests_.clear();
            return make_failure_update();
        }
        Http3Request request{
            .head = *request_head,
            .body = pending.body,
            .trailers = pending.trailers,
        };
        auto response = config_.request_handler ? config_.request_handler(request)
                                                : default_route_response(request);

        const auto submitted =
            submit_response(connection_, complete.stream_id, request.head, response);
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
        static_cast<void>(merge_connection_update(update, follow_up));
    }

    return update;
}

Http3ServerEndpointUpdate Http3ServerEndpoint::poll(quic::QuicCoreTimePoint now) {
    if (failed_) {
        return make_failure_update();
    }

    Http3ServerEndpointUpdate update;
    auto connection_update = connection_.poll(now);
    static_cast<void>(merge_connection_update(update, connection_update));
    return update;
}

bool Http3ServerEndpoint::has_failed() const {
    return failed_;
}

Http3ServerEndpointUpdate server_make_failure_update_for_test(bool handled_local_error) {
    return make_failure_update(handled_local_error);
}

std::string server_append_json_escaped_for_test(std::string_view value) {
    std::string out;
    append_json_escaped(out, value);
    return out;
}

std::string server_inspect_json_body_for_test(const Http3Request &request) {
    const auto body = inspect_json_body(request);
    return std::string(reinterpret_cast<const char *>(body.data()), body.size());
}

Http3Response server_default_route_response_for_test(const Http3Request &request) {
    return default_route_response(request);
}

bool server_merge_connection_update_for_test(Http3ServerEndpointUpdate &out,
                                             Http3EndpointUpdate &update) {
    return merge_connection_update(out, update);
}

Http3Result<std::vector<quic::QuicCoreSendStreamData>>
server_submit_response_for_test(bool prepare_request_stream, std::uint64_t stream_id,
                                const Http3RequestHead &request_head,
                                const Http3Response &response) {
    Http3Connection connection(Http3ConnectionConfig{
        .role = Http3ConnectionRole::server,
    });

    quic::QuicCoreResult handshake_ready;
    handshake_ready.effects.push_back(quic::QuicCoreEffect{
        quic::QuicCoreStateEvent{
            .change = quic::QuicCoreStateChange::handshake_ready,
        },
    });
    static_cast<void>(connection.on_core_result(handshake_ready, quic::QuicCoreTimePoint{}));

    if (prepare_request_stream) {
        quic::QuicCoreResult request_headers;
        request_headers.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreReceiveStreamData{
                .stream_id = stream_id,
                .bytes = request_headers_frame_for_test(request_head, stream_id),
                .fin = false,
            },
        });
        static_cast<void>(connection.on_core_result(request_headers, quic::QuicCoreTimePoint{}));
    }

    const auto submitted = submit_response(connection, stream_id, request_head, response);
    if (!submitted.has_value()) {
        return Http3Result<std::vector<quic::QuicCoreSendStreamData>>::failure(submitted.error());
    }

    const auto update = connection.poll(quic::QuicCoreTimePoint{});
    return Http3Result<std::vector<quic::QuicCoreSendStreamData>>::success(
        send_stream_inputs_for_test(update));
}

} // namespace coquic::http3
