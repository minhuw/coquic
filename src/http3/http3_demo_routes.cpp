#include "src/http3/http3_demo_routes.h"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace coquic::http3 {
namespace {

constexpr std::string_view kNoStoreValue = "no-store";

void append_json_escaped_impl(std::string &out, std::string_view value) {
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

std::vector<std::byte> inspect_json_body_impl(const Http3Request &request) {
    std::string json = "{\"method\":";
    append_json_escaped_impl(json, request.head.method);
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
        append_json_escaped_impl(json, request.trailers[index].name);
        json += ",\"value\":";
        append_json_escaped_impl(json, request.trailers[index].value);
        json.push_back('}');
    }
    json += "]}";

    return std::vector<std::byte>(reinterpret_cast<const std::byte *>(json.data()),
                                  reinterpret_cast<const std::byte *>(json.data()) + json.size());
}

std::string request_path_without_query(std::string_view path) {
    const auto query = path.find('?');
    return std::string(query == std::string_view::npos ? path : path.substr(0, query));
}

std::optional<std::size_t> parse_bytes_query(std::string_view path) {
    const auto query = path.find('?');
    if (query == std::string_view::npos) {
        return std::nullopt;
    }
    constexpr auto expected = std::string_view{"bytes="};
    const auto tail = path.substr(query + 1);

    std::optional<std::size_t> parsed_bytes;
    std::size_t param_begin = 0;
    while (true) {
        const auto param_end = tail.find('&', param_begin);
        const auto param =
            tail.substr(param_begin, param_end == std::string_view::npos ? std::string_view::npos
                                                                         : param_end - param_begin);
        if (param.starts_with(expected)) {
            if (parsed_bytes.has_value()) {
                return std::nullopt;
            }

            std::size_t parsed = 0;
            const auto value = param.substr(expected.size());
            const auto *begin = value.data();
            const auto *end = value.data() + value.size();
            const auto result = std::from_chars(begin, end, parsed);
            if (result.ec != std::errc{} || result.ptr != end || parsed == 0) {
                return std::nullopt;
            }
            parsed_bytes = parsed;
        }

        if (param_end == std::string_view::npos) {
            break;
        }
        param_begin = param_end + 1;
    }

    return parsed_bytes;
}

std::vector<std::byte> make_demo_download_payload(std::size_t bytes) {
    std::vector<std::byte> payload(bytes);
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::byte>('A' + (index % 23));
    }
    return payload;
}

std::vector<std::byte> upload_summary_json(std::size_t received_bytes) {
    const auto json = std::string("{\"received_bytes\":") + std::to_string(received_bytes) + "}";
    return std::vector<std::byte>(reinterpret_cast<const std::byte *>(json.data()),
                                  reinterpret_cast<const std::byte *>(json.data()) + json.size());
}

} // namespace

void append_json_escaped(std::string &out, std::string_view value) {
    append_json_escaped_impl(out, value);
}

std::vector<std::byte> inspect_json_body(const Http3Request &request) {
    return inspect_json_body_impl(request);
}

std::optional<Http3Response> try_demo_route_response(const Http3Request &request,
                                                     const Http3DemoRouteLimits &limits) {
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

        auto body = inspect_json_body_impl(request);
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

    const auto path = request_path_without_query(request.head.path);
    if (path == "/_coquic/speed/ping") {
        if (request.head.method != "GET" && request.head.method != "HEAD") {
            return Http3Response{
                .head =
                    {
                        .status = 405,
                        .content_length = 0,
                        .headers = {{"allow", "GET, HEAD"}},
                    },
            };
        }
        return Http3Response{
            .head =
                {
                    .status = 204,
                    .content_length = 0,
                    .headers = {{"cache-control", std::string(kNoStoreValue)}},
                },
        };
    }

    if (path == "/_coquic/speed/download") {
        if (request.head.method != "GET" && request.head.method != "HEAD") {
            return Http3Response{
                .head =
                    {
                        .status = 405,
                        .content_length = 0,
                        .headers = {{"allow", "GET, HEAD"}},
                    },
            };
        }
        const auto bytes = parse_bytes_query(request.head.path);
        if (!bytes.has_value() || *bytes > limits.max_speed_download_bytes) {
            return Http3Response{
                .head =
                    {
                        .status = 400,
                        .content_length = 0,
                        .headers = {{"cache-control", std::string(kNoStoreValue)}},
                    },
            };
        }
        auto body = make_demo_download_payload(*bytes);
        return Http3Response{
            .head =
                {
                    .status = 200,
                    .content_length = static_cast<std::uint64_t>(body.size()),
                    .headers =
                        {
                            {"content-type", "application/octet-stream"},
                            {"cache-control", std::string(kNoStoreValue)},
                        },
                },
            .body = std::move(body),
        };
    }

    if (path == "/_coquic/speed/upload") {
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
        if (request.body.size() > limits.max_speed_upload_bytes) {
            return Http3Response{
                .head =
                    {
                        .status = 400,
                        .content_length = 0,
                        .headers = {{"cache-control", std::string(kNoStoreValue)}},
                    },
            };
        }
        auto body = upload_summary_json(request.body.size());
        return Http3Response{
            .head =
                {
                    .status = 200,
                    .content_length = static_cast<std::uint64_t>(body.size()),
                    .headers =
                        {
                            {"content-type", "application/json"},
                            {"cache-control", std::string(kNoStoreValue)},
                        },
                },
            .body = std::move(body),
        };
    }

    return std::nullopt;
}

} // namespace coquic::http3
