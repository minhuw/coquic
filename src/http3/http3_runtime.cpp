#include "src/http3/http3_runtime.h"

#include "src/http3/http3_bootstrap.h"
#include "src/http3/http3_client.h"
#include "src/http3/http3_server.h"
#include "src/io/io_backend_factory.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <fstream>
#include <functional>
#include <future>
#include <iterator>
#include <iostream>
#include <limits>
#include <span>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>

namespace coquic::http3 {
namespace {

constexpr std::string_view kHttp3ServerUsageLine =
    "usage: h3-server [--host HOST] [--port PORT] [--bootstrap-port PORT] "
    "[--alt-svc-max-age SECONDS] [--io-backend socket|io_uring] "
    "[--certificate-chain PATH] [--private-key PATH] [--document-root PATH]";

constexpr std::string_view kHttp3ClientUsageLine =
    "usage: h3-client URL [--method GET|HEAD|POST] [--header NAME:VALUE] "
    "[--data TEXT] [--body-file PATH] [--output PATH] [--server-name NAME] "
    "[--verify-peer] [--host HOST] [--port PORT] [--io-backend socket|io_uring]";

enum class Http3CliMode : std::uint8_t { server, client };

struct ParsedHttp3Authority {
    std::string host;
    std::optional<std::uint16_t> port;
};

struct ParsedHttpsUrl {
    std::string authority;
    std::string host;
    std::uint16_t port = 443;
    std::string path = "/";
};

struct Http3ClientExecutionPlan {
    std::string host;
    std::uint16_t port = 443;
    std::string server_name;
    Http3Request request;
};

struct Http3ClientTransferPlan {
    Http3ClientExecutionPlan execution;
    std::filesystem::path output_path;
};

void print_usage(Http3CliMode mode) {
    std::cerr << (mode == Http3CliMode::server ? kHttp3ServerUsageLine : kHttp3ClientUsageLine)
              << '\n';
}

std::optional<std::string> read_text_file(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

std::optional<std::vector<std::byte>> read_binary_file(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }

    std::vector<char> chars((std::istreambuf_iterator<char>(input)),
                            std::istreambuf_iterator<char>());
    std::vector<std::byte> out;
    out.reserve(chars.size());
    for (const char ch : chars) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    return out;
}

bool write_binary_file(const std::filesystem::path &path, std::span<const std::byte> bytes) {
    std::error_code ignored;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ignored);
    }

    std::ofstream output(path, std::ios::binary);
    if (!output) {
        return false;
    }
    if (!bytes.empty()) {
        output.write(reinterpret_cast<const char *>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
    }
    return static_cast<bool>(output);
}

std::string trim_copy(std::string_view value) {
    std::size_t begin = 0;
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }

    std::size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }

    return std::string(value.substr(begin, end - begin));
}

std::string lowercase_ascii(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return out;
}

std::string uppercase_ascii(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
    return out;
}

std::optional<std::size_t> parse_size_arg(std::string_view value) {
    std::size_t parsed = 0;
    const auto *begin = value.data();
    const auto *end = value.data() + value.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<io::QuicIoBackendKind> parse_io_backend_arg(std::string_view value) {
    if (value == "socket") {
        return io::QuicIoBackendKind::socket;
    }
    if (value == "io_uring") {
        return io::QuicIoBackendKind::io_uring;
    }
    return std::nullopt;
}

std::optional<Http3RuntimeHeader> parse_header_arg(std::string_view value) {
    const auto colon = value.find(':');
    if (colon == std::string_view::npos || colon == 0) {
        return std::nullopt;
    }

    const auto name = lowercase_ascii(trim_copy(value.substr(0, colon)));
    const auto header_value = trim_copy(value.substr(colon + 1));
    if (name.empty() || header_value.empty()) {
        return std::nullopt;
    }
    if (name.front() == ':' || name == "content-length" || name == "transfer-encoding") {
        return std::nullopt;
    }

    return Http3RuntimeHeader{
        .name = name,
        .value = header_value,
    };
}

std::optional<ParsedHttp3Authority> parse_http3_authority(std::string_view authority) {
    if (authority.empty()) {
        return std::nullopt;
    }

    ParsedHttp3Authority parsed;
    if (authority.front() == '[') {
        const auto closing = authority.find(']');
        if (closing == std::string_view::npos || closing == 1) {
            return std::nullopt;
        }
        parsed.host = std::string(authority.substr(1, closing - 1));
        const auto suffix = authority.substr(closing + 1);
        if (suffix.empty()) {
            return parsed;
        }
        if (!suffix.starts_with(':')) {
            return std::nullopt;
        }
        const auto port = parse_size_arg(suffix.substr(1));
        if (!port.has_value() || *port > 65535u) {
            return std::nullopt;
        }
        parsed.port = static_cast<std::uint16_t>(*port);
        return parsed;
    }

    const auto first_colon = authority.find(':');
    const auto last_colon = authority.rfind(':');
    if (first_colon != std::string_view::npos && first_colon == last_colon) {
        parsed.host = std::string(authority.substr(0, first_colon));
        const auto port = parse_size_arg(authority.substr(first_colon + 1));
        if (parsed.host.empty() || !port.has_value() || *port > 65535u) {
            return std::nullopt;
        }
        parsed.port = static_cast<std::uint16_t>(*port);
        return parsed;
    }

    parsed.host = std::string(authority);
    return parsed.host.empty() ? std::nullopt : std::optional<ParsedHttp3Authority>{parsed};
}

std::optional<ParsedHttpsUrl> parse_https_url(std::string_view url) {
    constexpr std::string_view scheme = "https://";
    if (!url.starts_with(scheme)) {
        return std::nullopt;
    }

    const auto remainder = url.substr(scheme.size());
    if (remainder.empty()) {
        return std::nullopt;
    }

    const auto authority_end = remainder.find_first_of("/?#");
    const auto authority =
        authority_end == std::string_view::npos ? remainder : remainder.substr(0, authority_end);
    if (authority.empty()) {
        return std::nullopt;
    }

    std::string path = "/";
    if (authority_end != std::string_view::npos) {
        if (remainder[authority_end] == '/') {
            path = std::string(remainder.substr(authority_end));
        } else if (remainder[authority_end] == '?') {
            path = "/" + std::string(remainder.substr(authority_end));
        }
    }

    const auto fragment = path.find('#');
    if (fragment != std::string::npos) {
        path.erase(fragment);
    }
    if (path.empty()) {
        path = "/";
    }

    const auto parsed_authority = parse_http3_authority(authority);
    if (!parsed_authority.has_value()) {
        return std::nullopt;
    }

    return ParsedHttpsUrl{
        .authority = std::string(authority),
        .host = parsed_authority->host,
        .port = parsed_authority->port.value_or(443),
        .path = std::move(path),
    };
}

std::vector<std::byte> bytes_from_string(std::string_view text) {
    return std::vector<std::byte>(reinterpret_cast<const std::byte *>(text.data()),
                                  reinterpret_cast<const std::byte *>(text.data()) + text.size());
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
    return bytes_from_string(json);
}

bool path_has_prefix(const std::filesystem::path &path, const std::filesystem::path &prefix) {
    auto path_it = path.begin();
    auto prefix_it = prefix.begin();
    for (; prefix_it != prefix.end(); ++prefix_it, ++path_it) {
        if (path_it == path.end() || *path_it != *prefix_it) {
            return false;
        }
    }
    return true;
}

bool has_raw_dot_segment(const std::filesystem::path &path) {
    return std::any_of(path.begin(), path.end(), [](const std::filesystem::path &part) {
        return part == "." || part == "..";
    });
}

std::optional<std::filesystem::path> &forced_read_failure_path_for_test() {
    static std::optional<std::filesystem::path> path;
    return path;
}

std::optional<std::vector<std::byte>> read_runtime_file_bytes(const std::filesystem::path &path) {
    const auto &forced_failure = forced_read_failure_path_for_test();
    if (forced_failure.has_value() && path == *forced_failure) {
        return std::nullopt;
    }
    return read_binary_file(path);
}

std::optional<std::filesystem::path>
resolve_runtime_path_under_root(const std::filesystem::path &root, std::string_view request_path) {
    if (request_path.empty() || request_path.front() != '/') {
        return std::nullopt;
    }

    auto path_only = std::string(request_path);
    const auto query = path_only.find('?');
    if (query != std::string::npos) {
        path_only.erase(query);
    }
    if (path_only.empty()) {
        path_only = "/";
    }

    if (path_only == "/") {
        path_only = "/index.html";
    }

    const auto normalized_root = root.lexically_normal();
    const std::filesystem::path raw_relative(path_only.substr(1));
    if (raw_relative.is_absolute() || has_raw_dot_segment(raw_relative)) {
        return std::nullopt;
    }

    const auto relative = raw_relative.lexically_normal();
    auto candidate = (normalized_root / relative).lexically_normal();
    if (!path_has_prefix(candidate, normalized_root)) {
        return std::nullopt;
    }
    return candidate;
}

std::string content_type_for_path(const std::filesystem::path &path) {
    const auto extension = lowercase_ascii(path.extension().string());
    if (extension == ".html" || extension == ".htm") {
        return "text/html; charset=utf-8";
    }
    if (extension == ".txt") {
        return "text/plain; charset=utf-8";
    }
    if (extension == ".json") {
        return "application/json";
    }
    if (extension == ".css") {
        return "text/css; charset=utf-8";
    }
    if (extension == ".js" || extension == ".mjs") {
        return "text/javascript; charset=utf-8";
    }
    if (extension == ".svg") {
        return "image/svg+xml";
    }
    return "application/octet-stream";
}

Http3Response runtime_server_response(const std::filesystem::path &document_root,
                                      const Http3Request &request) {
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

    const auto resolved = resolve_runtime_path_under_root(document_root, request.head.path);
    if (!resolved.has_value()) {
        return Http3Response{
            .head =
                {
                    .status = 404,
                    .content_length = 0,
                },
        };
    }

    std::error_code status_error;
    if (!std::filesystem::exists(*resolved, status_error) ||
        !std::filesystem::is_regular_file(*resolved, status_error)) {
        return Http3Response{
            .head =
                {
                    .status = 404,
                    .content_length = 0,
                },
        };
    }

    const auto file_size = std::filesystem::file_size(*resolved, status_error);
    if (status_error) {
        return Http3Response{
            .head =
                {
                    .status = 500,
                    .content_length = 0,
                },
        };
    }

    Http3Response response{
        .head =
            {
                .status = 200,
                .content_length = file_size,
                .headers = {{"content-type", content_type_for_path(*resolved)}},
            },
    };

    if (request.head.method == "GET") {
        const auto body = read_runtime_file_bytes(*resolved);
        if (!body.has_value()) {
            return Http3Response{
                .head =
                    {
                        .status = 500,
                        .content_length = 0,
                    },
            };
        }
        response.body = *body;
    }

    return response;
}

std::optional<std::vector<std::byte>> load_request_body(const Http3RuntimeConfig &config) {
    if (config.body_text.has_value() && config.body_file_path.has_value()) {
        return std::nullopt;
    }
    if (config.body_text.has_value()) {
        return bytes_from_string(*config.body_text);
    }
    if (config.body_file_path.has_value()) {
        return read_binary_file(*config.body_file_path);
    }
    return std::vector<std::byte>{};
}

std::optional<Http3ClientExecutionPlan> make_client_execution_plan(const Http3RuntimeConfig &config,
                                                                   std::string_view url) {
    const auto parsed_url = parse_https_url(url);
    if (!parsed_url.has_value()) {
        return std::nullopt;
    }

    const auto body = load_request_body(config);
    if (!body.has_value()) {
        return std::nullopt;
    }

    const auto method = config.method.empty() ? std::string(body->empty() ? "GET" : "POST")
                                              : uppercase_ascii(config.method);
    if (method != "GET" && method != "HEAD" && method != "POST") {
        return std::nullopt;
    }
    if (method == "HEAD" && !body->empty()) {
        return std::nullopt;
    }

    Http3Headers headers;
    headers.reserve(config.headers.size());
    for (const auto &header : config.headers) {
        headers.push_back(Http3Field{
            .name = header.name,
            .value = header.value,
        });
    }

    Http3Request request{
        .head =
            {
                .method = method,
                .scheme = "https",
                .authority = parsed_url->authority,
                .path = parsed_url->path,
                .content_length =
                    body->empty() ? std::optional<std::uint64_t>{}
                                  : std::optional<std::uint64_t>{
                                        static_cast<std::uint64_t>(body->size()),
                                    },
                .headers = std::move(headers),
            },
        .body = *body,
    };

    return Http3ClientExecutionPlan{
        .host = parsed_url->host,
        .port = parsed_url->port,
        .server_name = config.server_name.empty() ? parsed_url->host : config.server_name,
        .request = std::move(request),
    };
}

std::optional<Http3ClientExecutionPlan>
make_client_execution_plan(const Http3RuntimeConfig &config) {
    return make_client_execution_plan(config, config.url);
}

std::optional<std::vector<Http3ClientTransferPlan>>
make_client_transfer_plans(const Http3RuntimeConfig &config,
                           std::span<const Http3RuntimeTransferJob> jobs) {
    if (jobs.empty()) {
        return std::nullopt;
    }

    std::vector<Http3ClientTransferPlan> plans;
    plans.reserve(jobs.size());
    for (const auto &job : jobs) {
        if (job.url.empty() || job.output_path.empty()) {
            return std::nullopt;
        }
        auto plan = make_client_execution_plan(config, job.url);
        if (!plan.has_value()) {
            return std::nullopt;
        }
        plans.push_back(Http3ClientTransferPlan{
            .execution = std::move(*plan),
            .output_path = job.output_path,
        });
    }

    const auto &first = plans.front().execution;
    for (std::size_t index = 1; index < plans.size(); ++index) {
        const auto &candidate = plans[index].execution;
        if (candidate.host != first.host || candidate.port != first.port ||
            candidate.server_name != first.server_name) {
            return std::nullopt;
        }
    }

    return plans;
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

quic::QuicCoreClientConnectionConfig make_client_open_config(const Http3ClientExecutionPlan &plan) {
    return quic::QuicCoreClientConnectionConfig{
        .source_connection_id = make_connection_id(std::byte{0xc1}, 1),
        .initial_destination_connection_id = make_connection_id(std::byte{0x83}, 0x41),
        .server_name = plan.server_name,
    };
}

std::vector<quic::QuicCoreEndpointInput>
make_endpoint_inputs_from_io_event(const io::QuicIoEvent &event) {
    std::vector<quic::QuicCoreEndpointInput> inputs;
    switch (event.kind) {
    case io::QuicIoEvent::Kind::rx_datagram:
        if (event.datagram.has_value()) {
            inputs.push_back(quic::QuicCoreInboundDatagram{
                .bytes = event.datagram->bytes,
                .route_handle = event.datagram->route_handle,
                .ecn = event.datagram->ecn,
            });
        }
        break;
    case io::QuicIoEvent::Kind::timer_expired:
        inputs.push_back(quic::QuicCoreTimerExpired{});
        break;
    case io::QuicIoEvent::Kind::idle_timeout:
    case io::QuicIoEvent::Kind::shutdown:
        break;
    }
    return inputs;
}

bool flush_send_effects(io::QuicIoBackend &backend, const quic::QuicCoreResult &result) {
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<quic::QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }
        if (!send->route_handle.has_value()) {
            return false;
        }
        if (!backend.send(io::QuicIoTxDatagram{
                .route_handle = *send->route_handle,
                .bytes = send->bytes,
                .ecn = send->ecn,
            })) {
            return false;
        }
    }
    return true;
}

std::optional<quic::QuicConnectionHandle>
connection_handle_of_effect(const quic::QuicCoreEffect &effect) {
    return std::visit(
        [](const auto &value) -> std::optional<quic::QuicConnectionHandle> {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, quic::QuicCoreSendDatagram> ||
                          std::is_same_v<T, quic::QuicCoreReceiveStreamData> ||
                          std::is_same_v<T, quic::QuicCorePeerResetStream> ||
                          std::is_same_v<T, quic::QuicCorePeerStopSending> ||
                          std::is_same_v<T, quic::QuicCoreStateEvent> ||
                          std::is_same_v<T, quic::QuicCoreConnectionLifecycleEvent> ||
                          std::is_same_v<T, quic::QuicCorePeerPreferredAddressAvailable> ||
                          std::is_same_v<T, quic::QuicCoreResumptionStateAvailable> ||
                          std::is_same_v<T, quic::QuicCoreZeroRttStatusEvent>) {
                return value.connection;
            }
            return std::nullopt;
        },
        effect);
}

bool effect_is_endpoint_relevant(const quic::QuicCoreEffect &effect) {
    return std::holds_alternative<quic::QuicCoreReceiveStreamData>(effect) ||
           std::holds_alternative<quic::QuicCorePeerResetStream>(effect) ||
           std::holds_alternative<quic::QuicCorePeerStopSending>(effect) ||
           std::holds_alternative<quic::QuicCoreStateEvent>(effect) ||
           std::holds_alternative<quic::QuicCoreConnectionLifecycleEvent>(effect);
}

std::vector<quic::QuicConnectionHandle> affected_connections(const quic::QuicCoreResult &result) {
    std::vector<quic::QuicConnectionHandle> out;
    std::unordered_set<quic::QuicConnectionHandle> seen;
    if (result.local_error.has_value() && result.local_error->connection.has_value()) {
        seen.insert(*result.local_error->connection);
        out.push_back(*result.local_error->connection);
    }
    for (const auto &effect : result.effects) {
        const auto handle = connection_handle_of_effect(effect);
        if (!handle.has_value() || !seen.insert(*handle).second) {
            continue;
        }
        out.push_back(*handle);
    }
    return out;
}

quic::QuicCoreResult filter_result_for_connection(const quic::QuicCoreResult &result,
                                                  quic::QuicConnectionHandle connection) {
    quic::QuicCoreResult filtered;
    filtered.next_wakeup = result.next_wakeup;
    if (result.local_error.has_value() && result.local_error->connection == connection) {
        filtered.local_error = result.local_error;
    }
    for (const auto &effect : result.effects) {
        if (!effect_is_endpoint_relevant(effect)) {
            continue;
        }
        const auto handle = connection_handle_of_effect(effect);
        if (handle.has_value() && *handle == connection) {
            filtered.effects.push_back(effect);
        }
    }
    return filtered;
}

std::optional<quic::QuicCoreConnectionCommand>
make_connection_command(quic::QuicConnectionHandle connection, quic::QuicCoreInput input) {
    if (std::holds_alternative<quic::QuicCoreSendStreamData>(input)) {
        return quic::QuicCoreConnectionCommand{
            .connection = connection,
            .input = std::get<quic::QuicCoreSendStreamData>(std::move(input)),
        };
    }
    if (std::holds_alternative<quic::QuicCoreResetStream>(input)) {
        return quic::QuicCoreConnectionCommand{
            .connection = connection,
            .input = std::get<quic::QuicCoreResetStream>(std::move(input)),
        };
    }
    if (std::holds_alternative<quic::QuicCoreStopSending>(input)) {
        return quic::QuicCoreConnectionCommand{
            .connection = connection,
            .input = std::get<quic::QuicCoreStopSending>(std::move(input)),
        };
    }
    if (std::holds_alternative<quic::QuicCoreCloseConnection>(input)) {
        return quic::QuicCoreConnectionCommand{
            .connection = connection,
            .input = std::get<quic::QuicCoreCloseConnection>(std::move(input)),
        };
    }
    if (std::holds_alternative<quic::QuicCoreRequestKeyUpdate>(input)) {
        return quic::QuicCoreConnectionCommand{
            .connection = connection,
            .input = std::get<quic::QuicCoreRequestKeyUpdate>(std::move(input)),
        };
    }
    if (std::holds_alternative<quic::QuicCoreRequestConnectionMigration>(input)) {
        return quic::QuicCoreConnectionCommand{
            .connection = connection,
            .input = std::get<quic::QuicCoreRequestConnectionMigration>(std::move(input)),
        };
    }
    return std::nullopt;
}

Http3BootstrapConfig make_http3_bootstrap_config(const Http3RuntimeConfig &config) {
    return Http3BootstrapConfig{
        .host = config.host,
        .port = config.bootstrap_port == 0 ? config.port : config.bootstrap_port,
        .h3_port = config.port,
        .alt_svc_max_age = config.alt_svc_max_age,
        .document_root = config.document_root,
        .certificate_chain_path = config.certificate_chain_path,
        .private_key_path = config.private_key_path,
    };
}

int run_http3_bootstrap_server_guarded(const Http3BootstrapConfig &config,
                                       const std::atomic<bool> *stop_requested) noexcept {
    try {
        return run_http3_bootstrap_server(config, stop_requested);
    } catch (...) {
        return 1;
    }
}

bool server_update_has_immediate_work(const Http3ServerEndpointUpdate &update) {
    return !update.core_inputs.empty() || !update.request_cancelled_events.empty() ||
           update.terminal_failure;
}

bool client_update_has_immediate_work(const Http3ClientEndpointUpdate &update) {
    return !update.core_inputs.empty() || !update.events.empty() ||
           !update.request_error_events.empty() || update.terminal_failure;
}

class Http3ServerRuntime {
  public:
    Http3ServerRuntime(const Http3RuntimeConfig &config,
                       quic::QuicCoreEndpointConfig endpoint_config,
                       std::unique_ptr<io::QuicIoBackend> backend)
        : config_(config), core_(std::move(endpoint_config)), backend_(std::move(backend)) {
    }

    int run() {
        for (;;) {
            const auto current = quic::QuicCoreClock::now();
            const auto next_wakeup = core_.next_wakeup();
            if (next_wakeup.has_value() && *next_wakeup <= current) {
                if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, current),
                                   current)) {
                    return 1;
                }
                continue;
            }

            const auto event = backend_->wait(next_wakeup);
            if (!event.has_value()) {
                return 1;
            }

            switch (event->kind) {
            case io::QuicIoEvent::Kind::idle_timeout:
                continue;
            case io::QuicIoEvent::Kind::shutdown:
                return 1;
            case io::QuicIoEvent::Kind::timer_expired:
                if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, event->now),
                                   event->now)) {
                    return 1;
                }
                continue;
            case io::QuicIoEvent::Kind::rx_datagram:
                break;
            }

            for (auto input : make_endpoint_inputs_from_io_event(*event)) {
                if (!handle_result(core_.advance_endpoint(std::move(input), event->now),
                                   event->now)) {
                    return 1;
                }
            }
        }
    }

  private:
    bool handle_result(const quic::QuicCoreResult &result, quic::QuicCoreTimePoint now) {
        if (result.local_error.has_value() && !result.local_error->connection.has_value()) {
            return false;
        }

        std::unordered_set<quic::QuicConnectionHandle> closed_connections;
        for (const auto &effect : result.effects) {
            const auto *lifecycle = std::get_if<quic::QuicCoreConnectionLifecycleEvent>(&effect);
            if (lifecycle == nullptr) {
                continue;
            }
            if (lifecycle->event == quic::QuicCoreConnectionLifecycle::accepted) {
                endpoints_.try_emplace(
                    lifecycle->connection,
                    Http3ServerEndpoint(Http3ServerConfig{
                        .request_handler =
                            [document_root = config_.document_root](const Http3Request &request) {
                                return runtime_server_response(document_root, request);
                            },
                    }));
            } else if (lifecycle->event == quic::QuicCoreConnectionLifecycle::closed) {
                closed_connections.insert(lifecycle->connection);
            }
        }

        if (!flush_send_effects(*backend_, result)) {
            return false;
        }

        for (const auto connection : affected_connections(result)) {
            auto endpoint_it = endpoints_.find(connection);
            if (endpoint_it == endpoints_.end()) {
                continue;
            }

            auto filtered = filter_result_for_connection(result, connection);
            if (filtered.effects.empty() && !filtered.local_error.has_value()) {
                continue;
            }

            auto update = endpoint_it->second.on_core_result(filtered, now);
            if (!drain_endpoint(connection, std::move(update), now)) {
                return false;
            }
        }

        if (result.local_error.has_value() && result.local_error->connection.has_value()) {
            endpoints_.erase(*result.local_error->connection);
        }
        for (const auto connection : closed_connections) {
            endpoints_.erase(connection);
        }

        return true;
    }

    bool submit_endpoint_commands(quic::QuicConnectionHandle connection,
                                  std::vector<quic::QuicCoreInput> inputs,
                                  quic::QuicCoreTimePoint now) {
        for (auto &input : inputs) {
            auto command = make_connection_command(connection, std::move(input));
            if (!command.has_value()) {
                return false;
            }
            if (!handle_result(core_.advance_endpoint(std::move(*command), now), now)) {
                return false;
            }
        }
        return true;
    }

    bool drain_endpoint(quic::QuicConnectionHandle connection, Http3ServerEndpointUpdate update,
                        quic::QuicCoreTimePoint now) {
        if (!submit_endpoint_commands(connection, std::move(update.core_inputs), now)) {
            return false;
        }
        if (update.terminal_failure) {
            endpoints_.erase(connection);
            return true;
        }

        while (update.has_pending_work) {
            auto endpoint_it = endpoints_.find(connection);
            if (endpoint_it == endpoints_.end()) {
                return true;
            }
            update = endpoint_it->second.poll(now);
            if (!server_update_has_immediate_work(update)) {
                return true;
            }
            if (!submit_endpoint_commands(connection, std::move(update.core_inputs), now)) {
                return false;
            }
            if (update.terminal_failure) {
                endpoints_.erase(connection);
                return true;
            }
        }
        return true;
    }

    const Http3RuntimeConfig &config_;
    quic::QuicCore core_;
    std::unique_ptr<io::QuicIoBackend> backend_;
    std::unordered_map<quic::QuicConnectionHandle, Http3ServerEndpoint> endpoints_;
};

class Http3ClientRuntime {
  public:
    Http3ClientRuntime(const Http3RuntimeConfig &config,
                       std::vector<Http3ClientTransferPlan> transfers,
                       quic::QuicRouteHandle primary_route_handle,
                       std::unique_ptr<io::QuicIoBackend> backend)
        : transfers_(std::move(transfers)), core_(make_http3_client_endpoint_config(config)),
          backend_(std::move(backend)), primary_route_handle_(primary_route_handle) {
    }

    int run() {
        if (transfers_.empty()) {
            return 1;
        }
        for (const auto &transfer : transfers_) {
            const auto submitted = endpoint_.submit_request(transfer.execution.request);
            if (!submitted.has_value()) {
                return 1;
            }
            pending_outputs_.insert_or_assign(submitted.value(), transfer.output_path);
        }
        expected_responses_ = pending_outputs_.size();

        const auto start = quic::QuicCoreClock::now();
        if (!handle_result(
                core_.advance_endpoint(
                    quic::QuicCoreOpenConnection{
                        .connection = make_client_open_config(transfers_.front().execution),
                        .initial_route_handle = primary_route_handle_,
                    },
                    start),
                start)) {
            return 1;
        }

        for (;;) {
            if (completed_responses_ == expected_responses_) {
                return 0;
            }

            const auto current = quic::QuicCoreClock::now();
            const auto next_wakeup = core_.next_wakeup();
            if (next_wakeup.has_value() && *next_wakeup <= current) {
                if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, current),
                                   current)) {
                    return 1;
                }
                continue;
            }

            const auto event = backend_->wait(next_wakeup);
            if (!event.has_value()) {
                return 1;
            }

            switch (event->kind) {
            case io::QuicIoEvent::Kind::idle_timeout:
            case io::QuicIoEvent::Kind::shutdown:
                return 1;
            case io::QuicIoEvent::Kind::timer_expired:
                if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, event->now),
                                   event->now)) {
                    return 1;
                }
                continue;
            case io::QuicIoEvent::Kind::rx_datagram:
                break;
            }

            for (auto input : make_endpoint_inputs_from_io_event(*event)) {
                if (!handle_result(core_.advance_endpoint(std::move(input), event->now),
                                   event->now)) {
                    return 1;
                }
            }
        }
    }

  private:
    bool handle_result(const quic::QuicCoreResult &result, quic::QuicCoreTimePoint now) {
        if (result.local_error.has_value()) {
            return false;
        }
        if (!flush_send_effects(*backend_, result)) {
            return false;
        }

        bool saw_closed = false;
        for (const auto &effect : result.effects) {
            const auto *lifecycle = std::get_if<quic::QuicCoreConnectionLifecycleEvent>(&effect);
            if (lifecycle == nullptr) {
                continue;
            }
            if (lifecycle->event == quic::QuicCoreConnectionLifecycle::created) {
                connection_ = lifecycle->connection;
            } else if (lifecycle->event == quic::QuicCoreConnectionLifecycle::closed) {
                saw_closed = true;
            }
        }

        if (connection_.has_value()) {
            auto filtered = filter_result_for_connection(result, *connection_);
            if (!filtered.effects.empty() || filtered.local_error.has_value()) {
                auto update = endpoint_.on_core_result(filtered, now);
                if (!drain_endpoint(std::move(update), now)) {
                    return false;
                }
            }
        }

        if (saw_closed && completed_responses_ != expected_responses_) {
            return false;
        }
        return true;
    }

    bool submit_endpoint_commands(std::vector<quic::QuicCoreInput> inputs,
                                  quic::QuicCoreTimePoint now) {
        const auto connection = connection_;
        if (!connection.has_value()) {
            return false;
        }
        for (auto &input : inputs) {
            auto command = make_connection_command(*connection, std::move(input));
            if (!command.has_value()) {
                return false;
            }
            if (!handle_result(core_.advance_endpoint(std::move(*command), now), now)) {
                return false;
            }
        }
        return true;
    }

    bool drain_endpoint(Http3ClientEndpointUpdate update, quic::QuicCoreTimePoint now) {
        for (auto &event : update.events) {
            const auto output_it = pending_outputs_.find(event.stream_id);
            if (output_it == pending_outputs_.end()) {
                return false;
            }
            if (!write_binary_file(output_it->second, event.response.body)) {
                return false;
            }
            pending_outputs_.erase(output_it);
            ++completed_responses_;
        }
        if (!update.request_error_events.empty()) {
            return false;
        }

        if (!submit_endpoint_commands(std::move(update.core_inputs), now)) {
            return false;
        }
        if (update.terminal_failure) {
            return completed_responses_ == expected_responses_;
        }

        while (completed_responses_ != expected_responses_ && update.has_pending_work) {
            update = endpoint_.poll(now);
            if (!client_update_has_immediate_work(update)) {
                return true;
            }
            for (auto &event : update.events) {
                const auto output_it = pending_outputs_.find(event.stream_id);
                if (output_it == pending_outputs_.end()) {
                    return false;
                }
                if (!write_binary_file(output_it->second, event.response.body)) {
                    return false;
                }
                pending_outputs_.erase(output_it);
                ++completed_responses_;
            }
            if (!update.request_error_events.empty()) {
                return false;
            }
            if (!submit_endpoint_commands(std::move(update.core_inputs), now)) {
                return false;
            }
            if (update.terminal_failure) {
                return completed_responses_ == expected_responses_;
            }
        }
        return true;
    }

    std::vector<Http3ClientTransferPlan> transfers_;
    quic::QuicCore core_;
    Http3ClientEndpoint endpoint_;
    std::unique_ptr<io::QuicIoBackend> backend_;
    quic::QuicRouteHandle primary_route_handle_ = 0;
    std::optional<quic::QuicConnectionHandle> connection_;
    std::unordered_map<std::uint64_t, std::filesystem::path> pending_outputs_;
    std::size_t expected_responses_ = 0;
    std::size_t completed_responses_ = 0;
};

} // namespace

Http3Response runtime_server_response_for_test(const std::filesystem::path &document_root,
                                               const Http3Request &request) {
    return runtime_server_response(document_root, request);
}

void runtime_set_forced_file_read_failure_path_for_test(const std::filesystem::path &path) {
    forced_read_failure_path_for_test() = path.lexically_normal();
}

void runtime_clear_forced_file_read_failure_path_for_test() {
    forced_read_failure_path_for_test().reset();
}

std::optional<std::vector<std::byte>>
runtime_load_request_body_for_test(const Http3RuntimeConfig &config) {
    return load_request_body(config);
}

bool runtime_make_client_execution_plan_for_test(const Http3RuntimeConfig &config,
                                                 std::string_view url) {
    return make_client_execution_plan(config, url).has_value();
}

bool runtime_make_client_transfer_plans_for_test(const Http3RuntimeConfig &config,
                                                 std::span<const Http3RuntimeTransferJob> jobs) {
    return make_client_transfer_plans(config, jobs).has_value();
}

std::optional<Http3RuntimeConfig> parse_http3_args(int argc, char **argv, Http3CliMode mode) {
    if (argc < 1) {
        print_usage(mode);
        return std::nullopt;
    }

    Http3RuntimeConfig config;
    config.mode =
        mode == Http3CliMode::server ? Http3RuntimeMode::server : Http3RuntimeMode::client;

    int index = 1;
    while (index < argc) {
        const std::string_view arg = argv[index++];
        const bool is_server_mode = mode == Http3CliMode::server;
        auto require_value = [&](std::string_view) -> std::optional<std::string_view> {
            if (index >= argc) {
                print_usage(mode);
                return std::nullopt;
            }
            return std::string_view(argv[index++]);
        };

        if (arg == "--verify-peer") {
            config.verify_peer = true;
            continue;
        }
        if (arg == "--host") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.host = std::string(*value);
            continue;
        }
        if (arg == "--port") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto port = parse_size_arg(*value);
            if (!port.has_value() || *port > 65535u) {
                print_usage(mode);
                return std::nullopt;
            }
            config.port = static_cast<std::uint16_t>(*port);
            continue;
        }
        if (arg == "--bootstrap-port") {
            if (!is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto port = parse_size_arg(*value);
            if (!port.has_value() || *port > 65535u) {
                print_usage(mode);
                return std::nullopt;
            }
            config.bootstrap_port = static_cast<std::uint16_t>(*port);
            continue;
        }
        if (arg == "--alt-svc-max-age") {
            if (!is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto max_age = parse_size_arg(*value);
            if (!max_age.has_value()) {
                print_usage(mode);
                return std::nullopt;
            }
            config.alt_svc_max_age = static_cast<std::uint64_t>(*max_age);
            continue;
        }
        if (arg == "--io-backend") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto kind = parse_io_backend_arg(*value);
            if (!kind.has_value()) {
                print_usage(mode);
                return std::nullopt;
            }
            config.io_backend = *kind;
            continue;
        }
        if (arg == "--document-root") {
            if (!is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.document_root = std::filesystem::path(*value);
            continue;
        }
        if (arg == "--certificate-chain") {
            if (!is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.certificate_chain_path = std::filesystem::path(*value);
            continue;
        }
        if (arg == "--private-key") {
            if (!is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.private_key_path = std::filesystem::path(*value);
            continue;
        }
        if (arg == "--method") {
            if (is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.method = uppercase_ascii(*value);
            continue;
        }
        if (arg == "--header") {
            if (is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_header_arg(*value);
            if (!parsed.has_value()) {
                print_usage(mode);
                return std::nullopt;
            }
            config.headers.push_back(*parsed);
            continue;
        }
        if (arg == "--data") {
            if (is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            if (config.body_file_path.has_value()) {
                print_usage(mode);
                return std::nullopt;
            }
            config.body_text = std::string(*value);
            continue;
        }
        if (arg == "--body-file") {
            if (is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            if (config.body_text.has_value()) {
                print_usage(mode);
                return std::nullopt;
            }
            config.body_file_path = std::filesystem::path(*value);
            continue;
        }
        if (arg == "--output") {
            if (is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.output_path = std::filesystem::path(*value);
            continue;
        }
        if (arg == "--server-name") {
            if (is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.server_name = std::string(*value);
            continue;
        }

        if (arg.starts_with("--")) {
            print_usage(mode);
            return std::nullopt;
        }

        if (!arg.empty() && arg.front() != '-') {
            if (mode != Http3CliMode::client || !config.url.empty()) {
                print_usage(mode);
                return std::nullopt;
            }
            config.url = std::string(arg);
            continue;
        }

        if (!arg.empty() && arg.front() == '-') {
            print_usage(mode);
            return std::nullopt;
        }
    }

    if (config.mode == Http3RuntimeMode::client) {
        if (config.url.empty() || !make_client_execution_plan(config).has_value()) {
            print_usage(mode);
            return std::nullopt;
        }
    } else if (config.bootstrap_port == 0) {
        config.bootstrap_port = config.port;
    }

    return config;
}

std::optional<Http3RuntimeConfig> parse_http3_server_args(int argc, char **argv) {
    return parse_http3_args(argc, argv, Http3CliMode::server);
}

std::optional<Http3RuntimeConfig> parse_http3_client_args(int argc, char **argv) {
    return parse_http3_args(argc, argv, Http3CliMode::client);
}

std::optional<Http3RuntimeConfig> parse_http3_runtime_args(int argc, char **argv) {
    if (argc < 2) {
        return std::nullopt;
    }

    const std::string_view subcommand = argv[1];
    if (subcommand == "h3-server") {
        return parse_http3_server_args(argc - 1, argv + 1);
    }
    if (subcommand == "h3-client") {
        return parse_http3_client_args(argc - 1, argv + 1);
    }
    return std::nullopt;
}

quic::QuicCoreEndpointConfig make_http3_client_endpoint_config(const Http3RuntimeConfig &config) {
    auto endpoint = quic::QuicCoreEndpointConfig{
        .role = quic::EndpointRole::client,
        .verify_peer = config.verify_peer,
        .application_protocol = std::string(kHttp3ApplicationProtocol),
    };
    return endpoint;
}

std::optional<quic::QuicCoreEndpointConfig>
make_http3_server_endpoint_config(const Http3RuntimeConfig &config) {
    const auto certificate = read_text_file(config.certificate_chain_path);
    const auto private_key = read_text_file(config.private_key_path);
    if (!certificate.has_value() || !private_key.has_value()) {
        return std::nullopt;
    }

    return quic::QuicCoreEndpointConfig{
        .role = quic::EndpointRole::server,
        .verify_peer = config.verify_peer,
        .application_protocol = std::string(kHttp3ApplicationProtocol),
        .identity =
            quic::TlsIdentity{
                .certificate_pem = *certificate,
                .private_key_pem = *private_key,
            },
    };
}

int run_http3_client_transfers(const Http3RuntimeConfig &config,
                               std::span<const Http3RuntimeTransferJob> jobs) {
    const auto plans = make_client_transfer_plans(config, jobs);
    if (!plans.has_value()) {
        return 1;
    }

    auto bootstrap = io::bootstrap_client_io_backend(
        io::QuicIoBackendBootstrapConfig{
            .kind = config.io_backend,
            .backend =
                io::QuicUdpBackendConfig{
                    .role_name = "h3-client",
                    .idle_timeout_ms = 1000,
                },
        },
        plans->front().execution.host, plans->front().execution.port);
    if (!bootstrap.has_value()) {
        return 1;
    }

    Http3ClientRuntime runtime(config, *plans, bootstrap->primary_route_handle,
                               std::move(bootstrap->backend));
    return runtime.run();
}

int run_http3_server(const Http3RuntimeConfig &config) {
    const auto endpoint = make_http3_server_endpoint_config(config);
    if (!endpoint.has_value()) {
        return 1;
    }

    auto bootstrap = io::bootstrap_server_io_backend(
        io::QuicIoBackendBootstrapConfig{
            .kind = config.io_backend,
            .backend =
                io::QuicUdpBackendConfig{
                    .role_name = "h3-server",
                    .idle_timeout_ms = 1000,
                },
        },
        config.host, std::span<const std::uint16_t>(&config.port, 1));
    if (!bootstrap.has_value()) {
        return 1;
    }

    std::optional<std::future<int>> bootstrap_result;
    std::optional<std::thread> bootstrap_thread;
    std::atomic<bool> bootstrap_stop_requested = false;
    if (config.enable_bootstrap) {
        const auto bootstrap_config = make_http3_bootstrap_config(config);
        std::packaged_task<int()> bootstrap_task(std::bind(
            run_http3_bootstrap_server_guarded, bootstrap_config, &bootstrap_stop_requested));
        bootstrap_result.emplace(bootstrap_task.get_future());
        bootstrap_thread.emplace(std::move(bootstrap_task));
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        if (bootstrap_result->wait_for(std::chrono::milliseconds{0}) == std::future_status::ready) {
            const int bootstrap_exit_code = bootstrap_result->get();
            bootstrap_thread->join();
            return bootstrap_exit_code;
        }
    }

    Http3ServerRuntime runtime(config, *endpoint, std::move(bootstrap->backend));
    const int runtime_exit_code = runtime.run();

    if (bootstrap_thread.has_value()) {
        bootstrap_stop_requested.store(true, std::memory_order_relaxed);
        bootstrap_thread->join();
        if (bootstrap_result.has_value() && bootstrap_result->valid()) {
            const int bootstrap_exit_code = bootstrap_result->get();
            if (runtime_exit_code == 0) {
                return bootstrap_exit_code;
            }
        }
    }

    return runtime_exit_code;
}

int run_http3_client(const Http3RuntimeConfig &config) {
    std::filesystem::path output_path;
    if (config.output_path.has_value()) {
        output_path = *config.output_path;
    } else {
        output_path =
            std::filesystem::temp_directory_path() /
            ("coquic-h3-client-" +
             std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".bin");
    }

    const std::array jobs{Http3RuntimeTransferJob{
        .url = config.url,
        .output_path = output_path,
    }};
    const int transfer_result = run_http3_client_transfers(config, jobs);
    if (transfer_result != 0 || config.output_path.has_value()) {
        return transfer_result;
    }

    const auto body = read_binary_file(output_path);
    std::error_code ignored;
    std::filesystem::remove(output_path, ignored);
    if (!body.has_value() || body->empty()) {
        return body.has_value() ? 0 : 1;
    }
    std::cout.write(reinterpret_cast<const char *>(body->data()),
                    static_cast<std::streamsize>(body->size()));
    return static_cast<bool>(std::cout) ? 0 : 1;
}

int run_http3_runtime(const Http3RuntimeConfig &config) {
    return config.mode == Http3RuntimeMode::server ? run_http3_server(config)
                                                   : run_http3_client(config);
}

} // namespace coquic::http3
