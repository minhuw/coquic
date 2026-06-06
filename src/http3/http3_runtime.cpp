#include "src/http3/http3_runtime.h"

#include "src/http3/http3_bootstrap.h"
#include "src/http3/http3_client.h"
#include "src/http3/http3_demo_routes.h"
#include "src/http3/http3_server.h"
#include "src/io/io_backend_factory.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <functional>
#include <future>
#include <iterator>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <span>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

namespace coquic::http3 {

std::optional<io::QuicIoEvent> first_send_datagram_as_rx_event(const quic::QuicCoreResult &result,
                                                               quic::QuicCoreTimePoint now);
std::optional<io::QuicIoEvent> make_live_initial_rx_event(const Http3RuntimeConfig &client_config,
                                                          quic::QuicCoreTimePoint now);
int run_http3_server_runtime_with_backend(const Http3RuntimeConfig &config,
                                          const quic::QuicCoreEndpointConfig &endpoint,
                                          std::unique_ptr<io::QuicIoBackend> backend);
int finish_http3_server_run(int runtime_exit_code,
                            std::optional<std::future<int>> &bootstrap_result,
                            std::optional<std::thread> &bootstrap_thread,
                            std::atomic<bool> &bootstrap_stop_requested);

struct Http3ServerEndpointTestAccess {
    static Http3Connection &connection(Http3ServerEndpoint &endpoint) {
        return endpoint.connection_;
    }

    static void add_pending_deferred_response(Http3ServerEndpoint &endpoint,
                                              std::uint64_t stream_id, Http3RequestHead head) {
        endpoint.pending_deferred_responses_.insert_or_assign(
            stream_id, Http3ServerEndpoint::PendingDeferredResponse{.head = std::move(head)});
    }

    static bool start_deferred_request(Http3ServerEndpoint &endpoint, std::uint64_t stream_id,
                                       Http3Request request) {
        return endpoint.config_.deferred_request_handler != nullptr &&
               endpoint.config_.deferred_request_handler(stream_id, std::move(request));
    }

    static std::optional<Http3ResponsePart>
    take_deferred_response_part(Http3ServerEndpoint &endpoint, std::uint64_t stream_id) {
        if (!endpoint.config_.deferred_response_part_handler) {
            return std::nullopt;
        }
        return endpoint.config_.deferred_response_part_handler(stream_id);
    }

    static bool cancel_deferred_request(Http3ServerEndpoint &endpoint, std::uint64_t stream_id) {
        if (!endpoint.config_.deferred_request_cancel_handler) {
            return false;
        }
        endpoint.config_.deferred_request_cancel_handler(stream_id);
        return true;
    }
};

struct Http3ClientEndpointTestAccess {
    static Http3Connection &connection(Http3ClientEndpoint &endpoint) {
        return endpoint.connection_;
    }
};

struct Http3ConnectionTestAccess {
    static void queue_core_input(Http3Connection &connection, quic::QuicCoreInput input) {
        connection.pending_core_inputs_.push_back(std::move(input));
    }

    static void queue_event(Http3Connection &connection, const Http3EndpointEvent &event) {
        connection.pending_events_.push_back(event);
    }
};

namespace {

constexpr std::uint64_t kHttp3RuntimeActiveConnectionIdLimit = 8;

constexpr std::string_view kHttp3ServerUsageLine =
    "usage: h3-server [--host HOST] [--port PORT] [--bootstrap-port PORT] "
    "[--alt-svc-max-age SECONDS] [--io-backend socket|io_uring] "
    "[--congestion-control newreno|cubic|bbr|copa] "
    "[--certificate-chain PATH] [--private-key PATH] [--document-root PATH] "
    "[--reverse-proxy http://HOST:PORT]";

constexpr std::string_view kHttp3ClientUsageLine =
    "usage: h3-client URL [--method GET|HEAD|POST] [--header NAME:VALUE] "
    "[--data TEXT] [--body-file PATH] [--output PATH] [--server-name NAME] "
    "[--verify-peer] [--no-verify-peer] [--host HOST] [--port PORT] "
    "[--io-backend socket|io_uring] "
    "[--congestion-control newreno|cubic|bbr|copa]";

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
    const bool invalid_parse = (result.ec != std::errc{}) || (result.ptr != end);
    if (invalid_parse) {
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
        if (!port.has_value()) {
            return std::nullopt;
        }
        if (*port > 65535u) {
            return std::nullopt;
        }
        parsed.port = static_cast<std::uint16_t>(*port);
        return parsed;
    }

    const auto first_colon = authority.find(':');
    const auto last_colon = authority.rfind(':');
    if (first_colon == std::string_view::npos) {
        parsed.host = std::string(authority);
        return parsed;
    }
    if (first_colon != last_colon) {
        parsed.host = std::string(authority);
        return parsed;
    }

    parsed.host = std::string(authority.substr(0, first_colon));
    if (parsed.host.empty()) {
        return std::nullopt;
    }
    const auto port = parse_size_arg(authority.substr(first_colon + 1));
    if (!port.has_value()) {
        return std::nullopt;
    }
    if (*port > 65535u) {
        return std::nullopt;
    }
    parsed.port = static_cast<std::uint16_t>(*port);
    return parsed;
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

bool path_has_prefix(const std::filesystem::path &path, const std::filesystem::path &prefix) {
    auto path_it = path.begin();
    auto prefix_it = prefix.begin();
    for (; prefix_it != prefix.end(); ++prefix_it, ++path_it) {
        if (path_it == path.end()) {
            return false;
        }
        if (*path_it != *prefix_it) {
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

std::optional<std::filesystem::path> &forced_file_size_failure_path_for_test() {
    static std::optional<std::filesystem::path> path;
    return path;
}

std::atomic<bool> &force_bootstrap_guard_failure_for_test() {
    static std::atomic<bool> enabled = false;
    return enabled;
}

std::optional<quic::QuicCoreEndpointConfig> &forced_server_endpoint_config_for_test() {
    static std::optional<quic::QuicCoreEndpointConfig> endpoint_config;
    return endpoint_config;
}

std::optional<quic::QuicCoreEndpointConfig> take_forced_server_endpoint_config_for_test() {
    auto endpoint_config = std::move(forced_server_endpoint_config_for_test());
    forced_server_endpoint_config_for_test().reset();
    return endpoint_config;
}

std::optional<io::QuicServerIoBootstrap> &forced_server_bootstrap_for_test() {
    static std::optional<io::QuicServerIoBootstrap> bootstrap;
    return bootstrap;
}

std::optional<io::QuicServerIoBootstrap> take_forced_server_bootstrap_for_test() {
    auto bootstrap = std::move(forced_server_bootstrap_for_test());
    forced_server_bootstrap_for_test().reset();
    return bootstrap;
}

std::optional<std::vector<std::byte>> read_runtime_file_bytes(const std::filesystem::path &path) {
    const auto &forced_failure = forced_read_failure_path_for_test();
    if (forced_failure.has_value()) {
        if (path == *forced_failure) {
            return std::nullopt;
        }
    }
    return read_binary_file(path);
}

std::optional<std::filesystem::path>
resolve_runtime_path_under_root(const std::filesystem::path &root, std::string_view request_path) {
    if (request_path.empty()) {
        return std::nullopt;
    }
    if (request_path.front() != '/') {
        return std::nullopt;
    }

    auto path_only = std::string(request_path);
    const auto query = path_only.find('?');
    if (query != std::string::npos) {
        path_only.erase(query);
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
    return (normalized_root / relative).lexically_normal();
}

std::optional<std::filesystem::path>
resolve_existing_runtime_path_under_root(const std::filesystem::path &root,
                                         std::string_view request_path) {
    auto resolved = resolve_runtime_path_under_root(root, request_path);
    if (!resolved.has_value()) {
        return std::nullopt;
    }

    std::error_code status_error;
    if (std::filesystem::exists(*resolved, status_error) &&
        std::filesystem::is_regular_file(*resolved, status_error)) {
        return resolved;
    }

    if (resolved->has_extension()) {
        return resolved;
    }

    auto html_candidate = *resolved;
    html_candidate += ".html";
    status_error.clear();
    if (std::filesystem::exists(html_candidate, status_error) &&
        std::filesystem::is_regular_file(html_candidate, status_error)) {
        return html_candidate.lexically_normal();
    }

    return resolved;
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
    if (extension == ".wasm") {
        return "application/wasm";
    }
    if (extension == ".svg") {
        return "image/svg+xml";
    }
    return "application/octet-stream";
}

Http3Response runtime_server_response(const Http3RuntimeConfig &config,
                                      const Http3Request &request) {
    if (const auto demo_route = try_demo_route_response(request); demo_route.has_value()) {
        return *demo_route;
    }

    if (config.reverse_proxy.has_value()) {
        return fetch_http_reverse_proxy_response(*config.reverse_proxy, request);
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

    const auto resolved =
        resolve_existing_runtime_path_under_root(config.document_root, request.head.path);
    if (!resolved.has_value()) {
        return Http3Response{
            .head =
                {
                    .status = 404,
                    .content_length = 0,
                },
        };
    }

    std::error_code exists_error;
    const bool exists = std::filesystem::exists(*resolved, exists_error);
    std::error_code type_error;
    const bool regular = std::filesystem::is_regular_file(*resolved, type_error);
    if (!exists || !regular) {
        return Http3Response{
            .head =
                {
                    .status = 404,
                    .content_length = 0,
                },
        };
    }

    std::uintmax_t file_size = 0;
    const auto &forced_file_size_failure = forced_file_size_failure_path_for_test();
    std::error_code status_error;
    if (forced_file_size_failure.has_value()) {
        if (*resolved == *forced_file_size_failure) {
            status_error = std::make_error_code(std::errc::io_error);
        } else {
            file_size = std::filesystem::file_size(*resolved, status_error);
        }
    } else {
        file_size = std::filesystem::file_size(*resolved, status_error);
    }
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
        const bool mismatched_target = (candidate.host != first.host) ||
                                       (candidate.port != first.port) ||
                                       (candidate.server_name != first.server_name);
        if (mismatched_target) {
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
    if (event.kind == io::QuicIoEvent::Kind::rx_datagram) {
        if (event.datagram.has_value()) {
            inputs.push_back(quic::QuicCoreInboundDatagram{
                .bytes = event.datagram->bytes,
                .route_handle = event.datagram->route_handle,
                .address_validation_identity = event.datagram->address_validation_identity,
                .ecn = event.datagram->ecn,
                .shared_bytes = event.datagram->shared_bytes,
                .begin = event.datagram->begin,
                .end = event.datagram->end,
            });
        }
        return inputs;
    }
    if (event.kind == io::QuicIoEvent::Kind::path_mtu_update) {
        if (event.path_mtu.has_value()) {
            inputs.push_back(quic::QuicCorePathMtuUpdate{
                .route_handle = event.path_mtu->route_handle,
                .max_udp_payload_size = event.path_mtu->max_udp_payload_size,
            });
        }
        return inputs;
    }
    if (event.kind == io::QuicIoEvent::Kind::timer_expired) {
        inputs.push_back(quic::QuicCoreTimerExpired{});
        return inputs;
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
                .is_pmtu_probe = send->is_pmtu_probe,
            })) {
            return false;
        }
    }
    return true;
}

quic::QuicConnectionHandle connection_handle_of_effect(const quic::QuicCoreEffect &effect) {
    return std::visit(
        [](const auto &value) -> quic::QuicConnectionHandle { return value.connection; }, effect);
}

bool effect_is_endpoint_relevant(const quic::QuicCoreEffect &effect) {
    return std::holds_alternative<quic::QuicCoreReceiveStreamData>(effect) ||
           std::holds_alternative<quic::QuicCorePeerResetStream>(effect) ||
           std::holds_alternative<quic::QuicCorePeerStopSending>(effect) ||
           std::holds_alternative<quic::QuicCoreStateEvent>(effect) ||
           std::holds_alternative<quic::QuicCoreConnectionLifecycleEvent>(effect);
}

std::uint64_t runtime_result_uint64_or(const Http3Result<std::uint64_t> &result,
                                       std::uint64_t fallback) {
    if (result.has_value()) {
        return result.value();
    }
    return fallback;
}

Http3EncodedFieldSection
runtime_result_field_section_or_empty(const Http3Result<Http3EncodedFieldSection> &result) {
    if (result.has_value()) {
        return result.value();
    }
    return {};
}

Http3EncodedFieldSection
runtime_result_field_section_or_empty(const quic::CodecResult<Http3EncodedFieldSection> &result) {
    if (result.has_value()) {
        return result.value();
    }
    return {};
}

std::vector<std::byte>
runtime_result_bytes_or_empty(const Http3Result<std::vector<std::byte>> &result) {
    if (result.has_value()) {
        return result.value();
    }
    return {};
}

std::vector<std::byte>
runtime_result_bytes_or_empty(const quic::CodecResult<std::vector<std::byte>> &result) {
    if (result.has_value()) {
        return result.value();
    }
    return {};
}

std::vector<quic::QuicConnectionHandle> affected_connections(const quic::QuicCoreResult &result) {
    std::vector<quic::QuicConnectionHandle> out;
    std::unordered_set<quic::QuicConnectionHandle> seen;
    if (result.local_error.has_value()) {
        if (result.local_error->connection.has_value()) {
            seen.insert(*result.local_error->connection);
            out.push_back(*result.local_error->connection);
        }
    }
    for (const auto &effect : result.effects) {
        const auto handle = connection_handle_of_effect(effect);
        if (!seen.insert(handle).second) {
            continue;
        }
        out.push_back(handle);
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
        if (handle == connection) {
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
        .reverse_proxy = config.reverse_proxy,
        .certificate_chain_path = config.certificate_chain_path,
        .private_key_path = config.private_key_path,
    };
}

int run_http3_bootstrap_server_guarded(const Http3BootstrapConfig &config,
                                       const std::atomic<bool> *stop_requested) noexcept {
    try {
        if (force_bootstrap_guard_failure_for_test().exchange(false)) {
            throw 1;
        }
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

class RuntimeTestBackend final : public io::QuicIoBackend {
  public:
    std::optional<quic::QuicRouteHandle> ensure_route(const io::QuicIoRemote &remote) override {
        last_remote = remote;
        ++ensure_route_calls;
        return ensured_route;
    }

    std::optional<io::QuicIoEvent>
    wait(std::optional<quic::QuicCoreTimePoint> next_wakeup) override {
        last_next_wakeup = next_wakeup;
        ++wait_calls;
        if (wait_index >= wait_results.size()) {
            return std::nullopt;
        }
        return wait_results[wait_index++];
    }

    bool send(const io::QuicIoTxDatagram &datagram) override {
        sends.push_back(datagram);
        return send_result;
    }

    std::optional<quic::QuicRouteHandle> ensured_route = 1;
    std::vector<std::optional<io::QuicIoEvent>> wait_results;
    std::vector<io::QuicIoTxDatagram> sends;
    std::optional<quic::QuicCoreTimePoint> last_next_wakeup;
    std::optional<io::QuicIoRemote> last_remote;
    std::size_t ensure_route_calls = 0;
    std::size_t wait_calls = 0;
    std::size_t wait_index = 0;
    bool send_result = true;
};

class RuntimeScopedTempDir {
  public:
    RuntimeScopedTempDir()
        : path_(std::filesystem::temp_directory_path() /
                ("coquic-h3-runtime-" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))) {
        std::error_code ignored;
        std::filesystem::create_directories(path_, ignored);
    }

    ~RuntimeScopedTempDir() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path &path() const {
        return path_;
    }

    bool write_file(const std::filesystem::path &relative_path, std::string_view contents) const {
        const auto full_path = path_ / relative_path;
        std::error_code ignored;
        std::filesystem::create_directories(full_path.parent_path(), ignored);
        std::ofstream output(full_path, std::ios::binary);
        if (!output) {
            return false;
        }
        output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        return static_cast<bool>(output);
    }

  private:
    std::filesystem::path path_;
};

class StreamingReverseProxyDispatcher {
  public:
    static constexpr std::size_t kMaxJobsPerConnection = 16;

    explicit StreamingReverseProxyDispatcher(Http3ReverseProxyConfig config)
        : config_(std::move(config)) {
    }

    ~StreamingReverseProxyDispatcher() {
        cancel_all();
        wait_for_all();
    }

    StreamingReverseProxyDispatcher(const StreamingReverseProxyDispatcher &) = delete;
    StreamingReverseProxyDispatcher &operator=(const StreamingReverseProxyDispatcher &) = delete;

    bool start(std::uint64_t stream_id, Http3Request request) {
        drain_finished();
        if (jobs_.contains(stream_id)) {
            return true;
        }
        if (jobs_.size() >= kMaxJobsPerConnection) {
            return store_ready_part(stream_id, reverse_proxy_unavailable_part());
        }

        auto queue = std::make_shared<PartQueue>();
        auto [job_it, inserted] = jobs_.try_emplace(stream_id, Job{.queue = queue});
        if (!inserted) {
            return true;
        }

        try {
            job_it->second.worker =
                std::thread([config = config_, request = std::move(request), queue]() mutable {
                    stream_http_reverse_proxy_response(config, request,
                                                       [queue](Http3ResponsePart part) {
                                                           queue->push(std::move(part));
                                                           return !queue->cancelled();
                                                       });
                    queue->mark_finished();
                });
        } catch (...) {
            job_it->second.queue->push(reverse_proxy_unavailable_part());
            job_it->second.queue->mark_finished();
        }
        return true;
    }

    std::optional<Http3ResponsePart> take_part(std::uint64_t stream_id) {
        const auto job_it = jobs_.find(stream_id);
        if (job_it == jobs_.end()) {
            return std::nullopt;
        }
        auto part = job_it->second.queue->pop();
        if (job_it->second.queue->done()) {
            join_and_erase(job_it);
        }
        return part;
    }

    void cancel(std::uint64_t stream_id) {
        const auto job_it = jobs_.find(stream_id);
        if (job_it != jobs_.end()) {
            job_it->second.queue->cancel();
        }
        drain_finished();
    }

    void cancel_all() {
        for (auto &[_, job] : jobs_) {
            job.queue->cancel();
        }
        drain_finished();
    }

    void drain_finished() {
        for (auto it = jobs_.begin(); it != jobs_.end();) {
            if (!it->second.queue->done()) {
                ++it;
                continue;
            }
            it = join_and_erase(it);
        }
    }

    void wait_for_all() {
        for (auto &[_, job] : jobs_) {
            job.queue->cancel();
            if (job.worker.joinable()) {
                job.worker.join();
            }
        }
        jobs_.clear();
    }

    COQUIC_NO_PROFILE bool has_job_for_test(std::uint64_t stream_id) const {
        return jobs_.contains(stream_id);
    }

  private:
    class PartQueue {
      public:
        void push(Http3ResponsePart part) {
            std::lock_guard lock(mutex_);
            if (cancelled_) {
                return;
            }
            parts_.push_back(std::move(part));
        }

        std::optional<Http3ResponsePart> pop() {
            std::lock_guard lock(mutex_);
            if (parts_.empty()) {
                return std::nullopt;
            }
            auto part = std::move(parts_.front());
            parts_.pop_front();
            return part;
        }

        void cancel() {
            std::lock_guard lock(mutex_);
            cancelled_ = true;
        }

        bool cancelled() const {
            std::lock_guard lock(mutex_);
            return cancelled_;
        }

        void mark_finished() {
            std::lock_guard lock(mutex_);
            finished_ = true;
        }

        bool done() const {
            std::lock_guard lock(mutex_);
            return finished_ && parts_.empty();
        }

      private:
        mutable std::mutex mutex_;
        std::deque<Http3ResponsePart> parts_;
        bool cancelled_ = false;
        bool finished_ = false;
    };

    struct Job {
        std::shared_ptr<PartQueue> queue;
        std::thread worker;
    };

    static Http3ResponsePart reverse_proxy_unavailable_part() {
        return Http3ResponsePart{
            .head =
                Http3ResponseHead{
                    .status = 503,
                    .content_length = 0,
                    .headers = {{"cache-control", "no-store"}},
                },
            .complete = true,
        };
    }

    bool store_ready_part(std::uint64_t stream_id, Http3ResponsePart part) {
        try {
            auto queue = std::make_shared<PartQueue>();
            queue->push(std::move(part));
            queue->mark_finished();
            jobs_.insert_or_assign(stream_id, Job{.queue = std::move(queue)});
        } catch (...) {
            return false;
        }
        return true;
    }

    auto join_and_erase(std::unordered_map<std::uint64_t, Job>::iterator it)
        -> std::unordered_map<std::uint64_t, Job>::iterator {
        if (it->second.worker.joinable()) {
            it->second.worker.join();
        }
        return jobs_.erase(it);
    }

    Http3ReverseProxyConfig config_;
    std::unordered_map<std::uint64_t, Job> jobs_;
};

bool runtime_internal_check(bool condition, std::string_view hook, std::string_view label) {
    if (!condition) {
        std::cerr << hook << " failed: " << label << '\n';
    }
    return condition;
}

constexpr std::uint64_t kRuntimeLoopMaskEnsureRoute = 1ull << 0;
constexpr std::uint64_t kRuntimeLoopMaskServerIdleTimeout = 1ull << 1;
constexpr std::uint64_t kRuntimeLoopMaskServerShutdown = 1ull << 2;
constexpr std::uint64_t kRuntimeLoopMaskServerTimerExpired = 1ull << 3;
constexpr std::uint64_t kRuntimeLoopMaskServerRxDatagramWithoutPayload = 1ull << 4;
constexpr std::uint64_t kRuntimeLoopMaskClientIdleTimeout = 1ull << 5;
constexpr std::uint64_t kRuntimeLoopMaskClientShutdown = 1ull << 6;
constexpr std::uint64_t kRuntimeLoopMaskClientTimerExpired = 1ull << 7;
constexpr std::uint64_t kRuntimeLoopMaskClientRxDatagramWithoutPayload = 1ull << 8;
constexpr std::uint64_t kRuntimeLoopMaskServerRxDatagramWithPayload = 1ull << 9;
constexpr std::uint64_t kRuntimeLoopMaskClientPollResponseWrite = 1ull << 10;
constexpr std::uint64_t kRuntimeLoopExpectedBranchMask =
    kRuntimeLoopMaskEnsureRoute | kRuntimeLoopMaskServerIdleTimeout |
    kRuntimeLoopMaskServerShutdown | kRuntimeLoopMaskServerTimerExpired |
    kRuntimeLoopMaskServerRxDatagramWithoutPayload | kRuntimeLoopMaskClientIdleTimeout |
    kRuntimeLoopMaskClientShutdown | kRuntimeLoopMaskClientTimerExpired |
    kRuntimeLoopMaskClientRxDatagramWithoutPayload | kRuntimeLoopMaskServerRxDatagramWithPayload |
    kRuntimeLoopMaskClientPollResponseWrite;
constexpr auto kAsyncReverseProxyPollInterval = std::chrono::milliseconds{25};

Http3RuntimeConfig make_runtime_server_config_for_test(const std::filesystem::path &document_root) {
    return Http3RuntimeConfig{
        .mode = Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 4433,
        .document_root = document_root,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
}

Http3RuntimeConfig make_runtime_client_config_for_test() {
    return Http3RuntimeConfig{
        .mode = Http3RuntimeMode::client,
        .url = "https://example.test/resource.txt",
        .verify_peer = false,
    };
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
            const auto poll_now = quic::QuicCoreClock::now();
            if (!poll_endpoints(poll_now)) {
                return 1;
            }
            const auto current = quic::QuicCoreClock::now();
            const auto core_next_wakeup = core_.next_wakeup();
            if (core_next_wakeup.has_value() && *core_next_wakeup <= current) {
                if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, current),
                                   current)) {
                    return 1;
                }
                continue;
            }

            const auto next_wakeup = next_wait_wakeup(current, core_next_wakeup);
            const auto event = backend_->wait(next_wakeup);
            if (!event.has_value()) {
                return 1;
            }

            if (event->kind == io::QuicIoEvent::Kind::idle_timeout) {
                continue;
            }
            if (event->kind == io::QuicIoEvent::Kind::shutdown) {
                return 1;
            }
            if (event->kind == io::QuicIoEvent::Kind::timer_expired) {
                if (!core_next_wakeup.has_value() || *core_next_wakeup > event->now) {
                    continue;
                }
                if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, event->now),
                                   event->now)) {
                    return 1;
                }
                continue;
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
        std::optional<quic::QuicConnectionHandle> local_error_connection;
        if (result.local_error.has_value()) {
            if (!result.local_error->connection.has_value()) {
                return false;
            }
            local_error_connection = result.local_error->connection;
        }

        std::unordered_set<quic::QuicConnectionHandle> closed_connections;
        for (const auto &effect : result.effects) {
            const auto *lifecycle = std::get_if<quic::QuicCoreConnectionLifecycleEvent>(&effect);
            if (lifecycle == nullptr) {
                continue;
            }
            if (lifecycle->event == quic::QuicCoreConnectionLifecycle::accepted) {
                auto streaming_proxy =
                    config_.reverse_proxy.has_value()
                        ? std::make_shared<StreamingReverseProxyDispatcher>(*config_.reverse_proxy)
                        : nullptr;
                endpoints_.try_emplace(lifecycle->connection,
                                       Http3ServerEndpoint(Http3ServerConfig{
                                           .fallback_request_handler =
                                               [config = config_](const Http3Request &request) {
                                                   return runtime_server_response(config, request);
                                               },
                                           .deferred_request_handler =
                                               streaming_proxy == nullptr
                                                   ? std::function<bool(std::uint64_t, Http3Request)>()
                                                   : [streaming_proxy](std::uint64_t stream_id,
                                                                       Http3Request request) {
                                                         return streaming_proxy->start(
                                                             stream_id, std::move(request));
                                                     },
                                           .deferred_response_part_handler =
                                               streaming_proxy == nullptr
                                                   ? std::function<std::optional<Http3ResponsePart>(
                                                         std::uint64_t)>()
                                                   : [streaming_proxy](std::uint64_t stream_id) {
                                                         return streaming_proxy->take_part(stream_id);
                                                     },
                                           .deferred_request_cancel_handler =
                                               streaming_proxy == nullptr
                                                   ? std::function<void(std::uint64_t)>()
                                                   : [streaming_proxy](std::uint64_t stream_id) {
                                                         streaming_proxy->cancel(stream_id);
                                                     },
                                       }));
            }
            if (lifecycle->event == quic::QuicCoreConnectionLifecycle::closed) {
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

        if (local_error_connection.has_value()) {
            endpoints_.erase(local_error_connection.value());
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

    bool has_pending_deferred_responses() const {
        return std::any_of(endpoints_.begin(), endpoints_.end(), [](const auto &entry) {
            return entry.second.has_pending_deferred_responses();
        });
    }

    std::optional<quic::QuicCoreTimePoint>
    next_wait_wakeup(quic::QuicCoreTimePoint now,
                     std::optional<quic::QuicCoreTimePoint> core_next_wakeup) const {
        if (!has_pending_deferred_responses()) {
            return core_next_wakeup;
        }
        const auto proxy_poll_wakeup = now + kAsyncReverseProxyPollInterval;
        if (!core_next_wakeup.has_value() || proxy_poll_wakeup < *core_next_wakeup) {
            return proxy_poll_wakeup;
        }
        return core_next_wakeup;
    }

    bool poll_endpoints(quic::QuicCoreTimePoint now) {
        for (auto it = endpoints_.begin(); it != endpoints_.end();) {
            const auto connection = it->first;
            auto update = it->second.poll(now);
            if (!server_update_has_immediate_work(update)) {
                ++it;
                continue;
            }
            if (!drain_endpoint(connection, std::move(update), now)) {
                return false;
            }
            it = endpoints_.find(connection);
            if (it == endpoints_.end()) {
                continue;
            }
            ++it;
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
                       std::vector<std::byte> primary_address_validation_identity,
                       std::unique_ptr<io::QuicIoBackend> backend)
        : transfers_(std::move(transfers)), core_(make_http3_client_endpoint_config(config)),
          backend_(std::move(backend)), primary_route_handle_(primary_route_handle),
          primary_address_validation_identity_(std::move(primary_address_validation_identity)) {
    }

    int run() {
        if (transfers_.empty()) {
            return 1;
        }
        for (const auto &transfer : transfers_) {
            auto submitted = endpoint_.submit_request(transfer.execution.request);
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
                        .address_validation_identity = primary_address_validation_identity_,
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
            const bool wakeup_due =
                next_wakeup.value_or(current + std::chrono::nanoseconds{1}) <= current;
            if (wakeup_due) {
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

            if (event->kind == io::QuicIoEvent::Kind::idle_timeout ||
                event->kind == io::QuicIoEvent::Kind::shutdown) {
                return 1;
            }
            if (event->kind == io::QuicIoEvent::Kind::timer_expired) {
                if (!handle_result(core_.advance_endpoint(quic::QuicCoreTimerExpired{}, event->now),
                                   event->now)) {
                    return 1;
                }
                continue;
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
            }
            if (lifecycle->event == quic::QuicCoreConnectionLifecycle::closed) {
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

        if (saw_closed && (completed_responses_ != expected_responses_)) {
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
    std::vector<std::byte> primary_address_validation_identity_;
    std::optional<quic::QuicConnectionHandle> connection_;
    std::unordered_map<std::uint64_t, std::filesystem::path> pending_outputs_;
    std::size_t expected_responses_ = 0;
    std::size_t completed_responses_ = 0;
};

} // namespace

Http3Response runtime_server_response_for_test(const std::filesystem::path &document_root,
                                               const Http3Request &request) {
    return runtime_server_response(
        Http3RuntimeConfig{
            .document_root = document_root,
        },
        request);
}

Http3Response runtime_server_response_for_test(const Http3RuntimeConfig &config,
                                               const Http3Request &request) {
    return runtime_server_response(config, request);
}

void runtime_set_forced_file_read_failure_path_for_test(const std::filesystem::path &path) {
    forced_read_failure_path_for_test() = path.lexically_normal();
}

void runtime_clear_forced_file_read_failure_path_for_test() {
    forced_read_failure_path_for_test().reset();
}

void runtime_set_force_bootstrap_guard_failure_for_test(bool enabled) {
    force_bootstrap_guard_failure_for_test().store(enabled);
}

void runtime_set_forced_server_endpoint_config_for_test(
    std::optional<quic::QuicCoreEndpointConfig> endpoint) {
    forced_server_endpoint_config_for_test() = std::move(endpoint);
}

void runtime_set_forced_server_bootstrap_for_test(
    std::optional<io::QuicServerIoBootstrap> bootstrap) {
    forced_server_bootstrap_for_test() = std::move(bootstrap);
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

    // The option loop validates mode-specific switches as soon as each argument is consumed.
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
        if (arg == "--no-verify-peer") {
            config.verify_peer = false;
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
            if (!port.has_value()) {
                print_usage(mode);
                return std::nullopt;
            }
            if (*port > 65535u) {
                print_usage(mode);
                return std::nullopt;
            }
            config.port = static_cast<std::uint16_t>(*port);
            continue;
        }

        // Server transport/listener options are rejected in client mode.
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
            if (!port.has_value()) {
                print_usage(mode);
                return std::nullopt;
            }
            if (*port > 65535u) {
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

        // Backend and congestion control options are shared by client and server modes.
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
        if (arg == "--congestion-control") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = quic::parse_congestion_control_algorithm(*value);
            if (!parsed.has_value()) {
                print_usage(mode);
                return std::nullopt;
            }
            config.congestion_control = *parsed;
            continue;
        }

        // Server content and TLS options are accepted only by h3-server.
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
        if (arg == "--reverse-proxy") {
            if (!is_server_mode) {
                print_usage(mode);
                return std::nullopt;
            }
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_http_reverse_proxy_target(*value);
            if (!parsed.has_value()) {
                print_usage(mode);
                return std::nullopt;
            }
            config.reverse_proxy = *parsed;
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

        // Client request-shaping options are accepted only by h3-client.
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

        // The remaining bare argument is the client URL; anything dash-prefixed is invalid here.
        if (arg.starts_with("--")) {
            print_usage(mode);
            return std::nullopt;
        }

        const bool arg_is_empty = arg.empty();
        const bool arg_has_single_dash = !arg_is_empty && arg.front() == '-';
        if (!arg_is_empty && !arg_has_single_dash) {
            if (mode != Http3CliMode::client || !config.url.empty()) {
                print_usage(mode);
                return std::nullopt;
            }
            config.url = std::string(arg);
            continue;
        }

        if (!arg_is_empty && arg_has_single_dash) {
            print_usage(mode);
            return std::nullopt;
        }
    }

    // Final validation either resolves the client execution plan or fills the bootstrap port.
    if (config.mode == Http3RuntimeMode::client) {
        if (config.url.empty()) {
            print_usage(mode);
            return std::nullopt;
        }
        if (!make_client_execution_plan(config).has_value()) {
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
    endpoint.transport.congestion_control = config.congestion_control;
    endpoint.transport.active_connection_id_limit = kHttp3RuntimeActiveConnectionIdLimit;
    return endpoint;
}

std::optional<quic::QuicCoreEndpointConfig>
make_http3_server_endpoint_config(const Http3RuntimeConfig &config) {
    const auto certificate = read_text_file(config.certificate_chain_path);
    const auto private_key = read_text_file(config.private_key_path);
    if (!certificate.has_value() || !private_key.has_value()) {
        return std::nullopt;
    }

    auto endpoint = quic::QuicCoreEndpointConfig{
        .role = quic::EndpointRole::server,
        .verify_peer = config.verify_peer,
        .application_protocol = std::string(kHttp3ApplicationProtocol),
        .identity =
            quic::TlsIdentity{
                .certificate_pem = *certificate,
                .private_key_pem = *private_key,
            },
    };
    endpoint.transport.congestion_control = config.congestion_control;
    endpoint.transport.active_connection_id_limit = kHttp3RuntimeActiveConnectionIdLimit;
    return endpoint;
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
                               std::move(bootstrap->primary_address_validation_identity),
                               std::move(bootstrap->backend));
    return runtime.run();
}

std::optional<io::QuicIoEvent> first_send_datagram_as_rx_event(const quic::QuicCoreResult &result,
                                                               quic::QuicCoreTimePoint now) {
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<quic::QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }
        if (!send->route_handle.has_value()) {
            continue;
        }
        return io::QuicIoEvent{
            .kind = io::QuicIoEvent::Kind::rx_datagram,
            .now = now,
            .datagram =
                io::QuicIoRxDatagram{
                    .route_handle = *send->route_handle,
                    .bytes = std::vector<std::byte>(send->bytes.begin(), send->bytes.end()),
                    .ecn = send->ecn,
                },
        };
    }
    return std::nullopt;
}

std::optional<io::QuicIoEvent> make_live_initial_rx_event(const Http3RuntimeConfig &client_config,
                                                          quic::QuicCoreTimePoint now) {
    const auto plan = make_client_execution_plan(client_config);
    if (!plan.has_value()) {
        return std::nullopt;
    }

    quic::QuicCore client_core(make_http3_client_endpoint_config(client_config));
    const auto opened = client_core.advance_endpoint(
        quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(*plan),
            .initial_route_handle = 1,
        },
        now);
    return first_send_datagram_as_rx_event(opened, now);
}

int run_http3_server_runtime_with_backend(const Http3RuntimeConfig &config,
                                          const quic::QuicCoreEndpointConfig &endpoint,
                                          std::unique_ptr<io::QuicIoBackend> backend) {
    Http3ServerRuntime runtime(config, endpoint, std::move(backend));
    return runtime.run();
}

int finish_http3_server_run(int runtime_exit_code,
                            std::optional<std::future<int>> &bootstrap_result,
                            std::optional<std::thread> &bootstrap_thread,
                            std::atomic<bool> &bootstrap_stop_requested) {
    if (bootstrap_thread.has_value()) {
        bootstrap_stop_requested.store(true, std::memory_order_relaxed);
        bootstrap_thread->join();
        if (bootstrap_result.has_value()) {
            if (bootstrap_result->valid()) {
                const int bootstrap_exit_code = bootstrap_result->get();
                if (runtime_exit_code == 0) {
                    return bootstrap_exit_code;
                }
            }
        }
    }
    return runtime_exit_code;
}

int run_http3_server(const Http3RuntimeConfig &config) {
    auto endpoint = take_forced_server_endpoint_config_for_test();
    if (!endpoint.has_value()) {
        endpoint = make_http3_server_endpoint_config(config);
    }
    if (!endpoint.has_value()) {
        return 1;
    }

    auto bootstrap = take_forced_server_bootstrap_for_test();
    if (!bootstrap.has_value()) {
        bootstrap = io::bootstrap_server_io_backend(
            io::QuicIoBackendBootstrapConfig{
                .kind = config.io_backend,
                .backend =
                    io::QuicUdpBackendConfig{
                        .role_name = "h3-server",
                        .idle_timeout_ms = 1000,
                    },
            },
            config.host, std::span<const std::uint16_t>(&config.port, 1));
    }
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

    const int runtime_exit_code =
        run_http3_server_runtime_with_backend(config, *endpoint, std::move(bootstrap->backend));
    return finish_http3_server_run(runtime_exit_code, bootstrap_result, bootstrap_thread,
                                   bootstrap_stop_requested);
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
    if (!body.has_value()) {
        return 1;
    }
    if (body->empty()) {
        return 0;
    }
    std::cout.write(reinterpret_cast<const char *>(body->data()),
                    static_cast<std::streamsize>(body->size()));
    return !static_cast<bool>(std::cout);
}

int run_http3_runtime(const Http3RuntimeConfig &config) {
    if (config.mode == Http3RuntimeMode::server) {
        return run_http3_server(config);
    }
    return run_http3_client(config);
}

} // namespace coquic::http3
