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
#include <fstream>
#include <functional>
#include <future>
#include <iterator>
#include <iostream>
#include <limits>
#include <span>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>

namespace coquic::http3 {

bool runtime_misc_internal_coverage_for_test();
bool runtime_loop_internal_coverage_for_test();
std::uint64_t runtime_loop_internal_coverage_mask_for_test();
std::uint64_t runtime_connection_handle_effect_coverage_mask_for_test();
bool runtime_additional_internal_coverage_for_test();
bool runtime_server_local_error_without_connection_coverage_for_test();
bool runtime_tail_internal_coverage_for_test();
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
    const bool invalid_parse = (result.ec != std::errc{}) | (result.ptr != end);
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
    if (name.empty() | header_value.empty()) {
        return std::nullopt;
    }
    if ((name.front() == ':') | (name == "content-length") | (name == "transfer-encoding")) {
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
        return (part == ".") | (part == "..");
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

bool &force_bootstrap_guard_failure_for_test() {
    static bool enabled = false;
    return enabled;
}

std::optional<std::size_t> &force_server_handle_result_failure_after_calls_for_test() {
    static std::optional<std::size_t> remaining_calls;
    return remaining_calls;
}

std::optional<std::size_t> &force_client_handle_result_failure_after_calls_for_test() {
    static std::optional<std::size_t> remaining_calls;
    return remaining_calls;
}

std::size_t &force_server_due_timer_count_for_test() {
    static std::size_t count = 0;
    return count;
}

std::size_t &force_client_due_timer_count_for_test() {
    static std::size_t count = 0;
    return count;
}

std::size_t &force_server_drain_failure_count_for_test() {
    static std::size_t count = 0;
    return count;
}

std::size_t &force_server_polled_submit_failure_count_for_test() {
    static std::size_t count = 0;
    return count;
}

std::size_t &force_client_initial_submit_failure_count_for_test() {
    static std::size_t count = 0;
    return count;
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

bool consume_forced_failure_after_calls(std::optional<std::size_t> &remaining_calls) {
    if (!remaining_calls.has_value()) {
        return false;
    }
    if (*remaining_calls == 0) {
        remaining_calls.reset();
        return true;
    }
    --*remaining_calls;
    return false;
}

bool consume_forced_count(std::size_t &count) {
    if (count == 0) {
        return false;
    }
    --count;
    return true;
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

std::string content_type_for_path(const std::filesystem::path &path) {
    const auto extension = lowercase_ascii(path.extension().string());
    if ((extension == ".html") | (extension == ".htm")) {
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
    if (const auto demo_route = try_demo_route_response(request); demo_route.has_value()) {
        return *demo_route;
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

    std::error_code exists_error;
    const bool exists = std::filesystem::exists(*resolved, exists_error);
    std::error_code type_error;
    const bool regular = std::filesystem::is_regular_file(*resolved, type_error);
    if ((!exists) | (!regular)) {
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
        const bool mismatched_target = (candidate.host != first.host) |
                                       (candidate.port != first.port) |
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
                .ecn = event.datagram->ecn,
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
    return std::holds_alternative<quic::QuicCoreReceiveStreamData>(effect) |
           std::holds_alternative<quic::QuicCorePeerResetStream>(effect) |
           std::holds_alternative<quic::QuicCorePeerStopSending>(effect) |
           std::holds_alternative<quic::QuicCoreStateEvent>(effect) |
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
        .certificate_chain_path = config.certificate_chain_path,
        .private_key_path = config.private_key_path,
    };
}

int run_http3_bootstrap_server_guarded(const Http3BootstrapConfig &config,
                                       const std::atomic<bool> *stop_requested) noexcept {
    try {
        if (force_bootstrap_guard_failure_for_test()) {
            throw 1;
        }
        return run_http3_bootstrap_server(config, stop_requested);
    } catch (...) {
        return 1;
    }
}

bool server_update_has_immediate_work(const Http3ServerEndpointUpdate &update) {
    return !update.core_inputs.empty() | !update.request_cancelled_events.empty() |
           update.terminal_failure;
}

bool client_update_has_immediate_work(const Http3ClientEndpointUpdate &update) {
    return !update.core_inputs.empty() | !update.events.empty() |
           !update.request_error_events.empty() | update.terminal_failure;
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
    RuntimeScopedTempDir() {
        path_ = std::filesystem::temp_directory_path() /
                ("coquic-h3-runtime-" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
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
constexpr std::uint64_t kRuntimeLoopExpectedCoverageMask =
    kRuntimeLoopMaskEnsureRoute | kRuntimeLoopMaskServerIdleTimeout |
    kRuntimeLoopMaskServerShutdown | kRuntimeLoopMaskServerTimerExpired |
    kRuntimeLoopMaskServerRxDatagramWithoutPayload | kRuntimeLoopMaskClientIdleTimeout |
    kRuntimeLoopMaskClientShutdown | kRuntimeLoopMaskClientTimerExpired |
    kRuntimeLoopMaskClientRxDatagramWithoutPayload | kRuntimeLoopMaskServerRxDatagramWithPayload |
    kRuntimeLoopMaskClientPollResponseWrite;

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
            const auto current = quic::QuicCoreClock::now();
            const auto next_wakeup = core_.next_wakeup();
            if (consume_forced_count(force_server_due_timer_count_for_test()) ||
                (next_wakeup.has_value() && *next_wakeup <= current)) {
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

            if (event->kind == io::QuicIoEvent::Kind::idle_timeout) {
                continue;
            }
            if (event->kind == io::QuicIoEvent::Kind::shutdown) {
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
    friend bool coquic::http3::runtime_loop_internal_coverage_for_test();
    friend std::uint64_t coquic::http3::runtime_loop_internal_coverage_mask_for_test();
    friend bool coquic::http3::runtime_additional_internal_coverage_for_test();
    friend bool coquic::http3::runtime_server_local_error_without_connection_coverage_for_test();
    friend bool coquic::http3::runtime_tail_internal_coverage_for_test();

    bool handle_result(const quic::QuicCoreResult &result, quic::QuicCoreTimePoint now) {
        if (consume_forced_failure_after_calls(
                force_server_handle_result_failure_after_calls_for_test())) {
            return false;
        }
        if (result.local_error.has_value()) {
            if (!result.local_error->connection.has_value()) {
                return false;
            }
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
                        .fallback_request_handler =
                            [document_root = config_.document_root](const Http3Request &request) {
                                return runtime_server_response(document_root, request);
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
            if (filtered.effects.empty() & !filtered.local_error.has_value()) {
                continue;
            }

            auto update = endpoint_it->second.on_core_result(filtered, now);
            if (!drain_endpoint(connection, std::move(update), now)) {
                return false;
            }
        }

        if (result.local_error.has_value()) {
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
        if (consume_forced_count(force_server_drain_failure_count_for_test())) {
            return false;
        }
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
            const bool force_submit_failure =
                consume_forced_count(force_server_polled_submit_failure_count_for_test());
            if (force_submit_failure) {
                return false;
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
            auto submitted = endpoint_.submit_request(transfer.execution.request);
            if (consume_forced_count(force_client_initial_submit_failure_count_for_test())) {
                submitted = Http3Result<std::uint64_t>::failure(Http3Error{
                    .detail = "forced initial request submission failure for test coverage",
                });
            }
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
            const bool wakeup_due =
                next_wakeup.value_or(current + std::chrono::nanoseconds{1}) <= current;
            if (consume_forced_count(force_client_due_timer_count_for_test()) | wakeup_due) {
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
    friend bool coquic::http3::runtime_loop_internal_coverage_for_test();
    friend std::uint64_t coquic::http3::runtime_loop_internal_coverage_mask_for_test();
    friend bool coquic::http3::runtime_additional_internal_coverage_for_test();

    bool handle_result(const quic::QuicCoreResult &result, quic::QuicCoreTimePoint now) {
        if (consume_forced_failure_after_calls(
                force_client_handle_result_failure_after_calls_for_test())) {
            return false;
        }
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
            if (!filtered.effects.empty() | filtered.local_error.has_value()) {
                auto update = endpoint_.on_core_result(filtered, now);
                if (!drain_endpoint(std::move(update), now)) {
                    return false;
                }
            }
        }

        if (saw_closed & (completed_responses_ != expected_responses_)) {
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

void runtime_set_force_bootstrap_guard_failure_for_test(bool enabled) {
    force_bootstrap_guard_failure_for_test() = enabled;
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

bool runtime_misc_internal_coverage_for_test() {
    bool ok = true;
    const auto check = [&](bool condition, std::string_view label) {
        ok &= runtime_internal_check(condition, "runtime_misc_internal_coverage_for_test", label);
    };

    std::string escaped;
    append_json_escaped(escaped, "\"\\\b\f\n\r\t");
    check(escaped == "\"\\\"\\\\\\b\\f\\n\\r\\t\"", "append_json_escaped escapes control chars");
    std::string escaped_control;
    append_json_escaped(escaped_control, std::string_view("\x01", 1));
    check(escaped_control == "\"\\u0001\"", "append_json_escaped hex-encodes other control bytes");

    const auto inspect_body = inspect_json_body(Http3Request{
        .head =
            {
                .method = "POST",
                .content_length = 5,
            },
        .trailers =
            {
                {"first", "1"},
                {"second", "2"},
            },
    });
    const std::string inspect_text(reinterpret_cast<const char *>(inspect_body.data()),
                                   inspect_body.size());
    check(inspect_text.find(",{\"name\":\"second\"") != std::string::npos,
          "inspect_json_body serializes trailer separators");
    check(inspect_text.find("\"content_length\":5") != std::string::npos,
          "inspect_json_body serializes content length values");

    RuntimeScopedTempDir document_root;
    check(document_root.write_file("payload.txt", "payload"),
          "write temp payload for runtime_server_response");
    check(!document_root.write_file(".", "x"),
          "temp runtime directory rejects writes targeting directories");
    check(!read_binary_file(document_root.path() / "missing.bin").has_value(),
          "read_binary_file rejects missing files");
    check(!write_binary_file(document_root.path(), bytes_from_string("x")),
          "write_binary_file rejects directory targets");
    check(!runtime_internal_check(false, "runtime_misc_internal_coverage_for_test",
                                  "forced false branch"),
          "runtime_internal_check reports failures");
    check(runtime_result_uint64_or(Http3Result<std::uint64_t>::failure(Http3Error{
                                       .detail = "fallback",
                                   }),
                                   42) == 42,
          "runtime_result_value_or returns fallback values for error results");
    check(runtime_result_uint64_or(
              Http3Result<std::uint64_t>{
                  .storage = std::variant<std::uint64_t, Http3Error>{std::uint64_t{7}},
              },
              42) == 7,
          "runtime_result_value_or preserves success values");
    {
        const auto no_parent_path = std::filesystem::path("coquic-runtime-no-parent.bin");
        std::error_code ignored;
        std::filesystem::remove(no_parent_path, ignored);
        check(write_binary_file(no_parent_path, bytes_from_string("np")),
              "write_binary_file accepts relative paths without parent components");
        check(read_binary_file(no_parent_path).value_or(std::vector<std::byte>{}) ==
                  bytes_from_string("np"),
              "write_binary_file persists data for relative paths without parents");
        std::filesystem::remove(no_parent_path, ignored);
    }

    {
        const auto parsed = parse_header_arg(" X-Test : value \t");
        const auto parsed_header = parsed.value_or(Http3RuntimeHeader{});
        check(parsed.has_value(), "parse_header_arg accepts trimmed header input");
        check(parsed_header.name == "x-test", "parse_header_arg lowercases header names");
        check(parsed_header.value == "value", "parse_header_arg trims header values");
    }
    check(parse_io_backend_arg("socket") ==
              std::optional<io::QuicIoBackendKind>{io::QuicIoBackendKind::socket},
          "parse_io_backend_arg accepts socket");
    check(parse_io_backend_arg("io_uring") ==
              std::optional<io::QuicIoBackendKind>{io::QuicIoBackendKind::io_uring},
          "parse_io_backend_arg accepts io_uring");
    check(!parse_http3_authority("").has_value(), "parse_http3_authority rejects empty authority");
    {
        const auto authority = parse_http3_authority("[::1]");
        const auto parsed_authority = authority.value_or(ParsedHttp3Authority{});
        check(authority.has_value(), "parse_http3_authority accepts bracketed IPv6 authorities");
        check(parsed_authority.host == "::1",
              "parse_http3_authority preserves bracketed IPv6 hosts");
        check(!parsed_authority.port.has_value(),
              "parse_http3_authority leaves IPv6 ports unset when omitted");
    }
    check(!parse_http3_authority("[::1]suffix").has_value(),
          "parse_http3_authority rejects IPv6 suffixes without port separators");
    check(!parse_http3_authority("[::1]:99999").has_value(),
          "parse_http3_authority rejects oversized IPv6 ports");
    check(!parse_http3_authority("[::1]:abc").has_value(),
          "parse_http3_authority rejects invalid IPv6 port text");
    check(!parse_http3_authority("localhost:").has_value(),
          "parse_http3_authority rejects empty port suffixes");
    {
        const auto bare_ipv6 = parse_http3_authority("2001:db8::1");
        check(bare_ipv6.has_value(), "parse_http3_authority accepts bare IPv6 literals");
        check(bare_ipv6.value_or(ParsedHttp3Authority{}).host == "2001:db8::1",
              "parse_http3_authority preserves bare IPv6 literal text");
    }
    check(!parse_http3_authority(":443").has_value(),
          "parse_http3_authority rejects empty hosts before port separators");
    check(!parse_http3_authority("localhost:99999").has_value(),
          "parse_http3_authority rejects oversized non-IPv6 ports");
    {
        const auto url = parse_https_url("https://localhost?x=1");
        const auto parsed_url = url.value_or(ParsedHttpsUrl{});
        check(url.has_value(), "parse_https_url accepts query-only targets");
        check(parsed_url.host == "localhost", "parse_https_url preserves the parsed host");
        check(parsed_url.port == 443, "parse_https_url defaults ports to 443");
        check(parsed_url.path == "/?x=1",
              "parse_https_url keeps query-only targets rooted at slash");
    }
    check(!parse_https_url("https://").has_value(), "parse_https_url rejects empty authorities");
    {
        const auto fragment_url = parse_https_url("https://localhost#frag");
        check(fragment_url.has_value(), "parse_https_url accepts fragment-only targets");
        check(fragment_url.value_or(ParsedHttpsUrl{}).path == "/",
              "parse_https_url leaves fragment-only targets rooted at slash");
    }
    check(!path_has_prefix(document_root.path() / "other", document_root.path() / "payload.txt"),
          "path_has_prefix detects mismatched prefixes");
    check(!path_has_prefix(document_root.path(), document_root.path() / "payload.txt"),
          "path_has_prefix rejects prefixes that extend beyond the candidate path");
    check(!resolve_runtime_path_under_root(document_root.path(), "payload.txt").has_value(),
          "resolve_runtime_path_under_root rejects non-absolute request paths");
    check(!resolve_runtime_path_under_root(document_root.path(), "").has_value(),
          "resolve_runtime_path_under_root rejects empty request paths");
    check(!resolve_runtime_path_under_root(document_root.path(), "/./payload.txt").has_value(),
          "resolve_runtime_path_under_root rejects raw dot path segments");
    check(content_type_for_path("page.htm") == "text/html; charset=utf-8",
          "content_type_for_path treats .htm files as HTML");

    const auto method_not_allowed =
        runtime_server_response(document_root.path(), Http3Request{
                                                          .head =
                                                              {
                                                                  .method = "POST",
                                                                  .path = "/payload.txt",
                                                              },
                                                      });
    check(method_not_allowed.head.status == 405, "runtime_server_response rejects POST");
    const auto allow_header_count =
        std::count_if(method_not_allowed.head.headers.begin(),
                      method_not_allowed.head.headers.end(), [](const Http3Field &header) {
                          return (header.name == "allow") & (header.value == "GET, HEAD");
                      });
    check(method_not_allowed.head.headers.size() == 1,
          "runtime_server_response emits a single allow header");
    check(allow_header_count == 1, "runtime_server_response advertises GET/HEAD allow header");

    forced_file_size_failure_path_for_test() =
        (document_root.path() / "payload.txt").lexically_normal();
    const auto file_size_failure =
        runtime_server_response(document_root.path(), Http3Request{
                                                          .head =
                                                              {
                                                                  .method = "HEAD",
                                                                  .path = "/payload.txt",
                                                              },
                                                      });
    forced_file_size_failure_path_for_test().reset();
    check(file_size_failure.head.status == 500,
          "runtime_server_response surfaces file_size failure");
    forced_read_failure_path_for_test() = (document_root.path() / "other.bin").lexically_normal();
    const auto unaffected_read =
        runtime_server_response(document_root.path(), Http3Request{
                                                          .head =
                                                              {
                                                                  .method = "GET",
                                                                  .path = "/payload.txt",
                                                              },
                                                      });
    forced_read_failure_path_for_test().reset();
    check(unaffected_read.head.status == 200,
          "runtime_server_response ignores forced read failures for unrelated paths");
    forced_file_size_failure_path_for_test() =
        (document_root.path() / "other.bin").lexically_normal();
    const auto unaffected_file_size =
        runtime_server_response(document_root.path(), Http3Request{
                                                          .head =
                                                              {
                                                                  .method = "HEAD",
                                                                  .path = "/payload.txt",
                                                              },
                                                      });
    forced_file_size_failure_path_for_test().reset();
    check(unaffected_file_size.head.status == 200,
          "runtime_server_response ignores forced file-size failures for unrelated paths");
    {
        std::error_code ignored;
        std::filesystem::create_directory(document_root.path() / "assets", ignored);
        const auto directory_request =
            runtime_server_response(document_root.path(), Http3Request{
                                                              .head =
                                                                  {
                                                                      .method = "GET",
                                                                      .path = "/assets",
                                                                  },
                                                          });
        check(directory_request.head.status == 404,
              "runtime_server_response rejects directory targets as non-regular files");
    }

    {
        const auto inputs = make_endpoint_inputs_from_io_event(io::QuicIoEvent{
            .kind = io::QuicIoEvent::Kind::timer_expired,
        });
        const auto timer_expired_count =
            std::count_if(inputs.begin(), inputs.end(), [](const auto &input) {
                return std::holds_alternative<quic::QuicCoreTimerExpired>(input);
            });
        check(inputs.size() == 1, "timer events produce exactly one core input");
        check(timer_expired_count == 1, "timer events become timer core inputs");
    }
    check(make_endpoint_inputs_from_io_event(io::QuicIoEvent{
                                                 .kind = io::QuicIoEvent::Kind::idle_timeout,
                                             })
              .empty(),
          "idle timeout produces no core inputs");
    check(make_endpoint_inputs_from_io_event(io::QuicIoEvent{
                                                 .kind = io::QuicIoEvent::Kind::shutdown,
                                             })
              .empty(),
          "shutdown produces no core inputs");

    {
        RuntimeTestBackend backend;
        const auto waited = backend.wait(std::nullopt);
        check(!waited.has_value(),
              "runtime test backend returns nullopt after scripted waits are exhausted");
        check(backend.wait_calls == 1, "runtime test backend records wait calls");
    }

    {
        RuntimeTestBackend backend;
        quic::QuicCoreResult result;
        result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreSendDatagram{
                .connection = 1,
                .bytes = bytes_from_string("x"),
            },
        });
        check(!flush_send_effects(backend, result), "flush_send_effects rejects missing route");
    }

    {
        RuntimeTestBackend backend;
        backend.send_result = false;
        quic::QuicCoreResult result;
        result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreSendDatagram{
                .connection = 1,
                .route_handle = 7,
                .bytes = bytes_from_string("x"),
            },
        });
        check(!flush_send_effects(backend, result), "flush_send_effects propagates send failure");
    }

    {
        RuntimeTestBackend backend;
        quic::QuicCoreResult result;
        result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreStateEvent{
                .connection = 4,
                .change = quic::QuicCoreStateChange::handshake_ready,
            },
        });
        result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreSendDatagram{
                .connection = 4,
                .route_handle = 9,
                .bytes = bytes_from_string("ok"),
                .ecn = quic::QuicEcnCodepoint::ect0,
            },
        });
        check(flush_send_effects(backend, result), "flush_send_effects sends datagrams");
        const auto route_handle_count =
            std::count_if(backend.sends.begin(), backend.sends.end(),
                          [](const auto &send) { return send.route_handle == 9; });
        check(backend.sends.size() == 1, "flush_send_effects emits a single datagram");
        check(route_handle_count == 1, "flush_send_effects preserves route handles");
    }

    {
        const auto handle = connection_handle_of_effect(
            quic::QuicCoreEffect{quic::QuicCorePeerPreferredAddressAvailable{
                .connection = 5,
            }});
        check(handle == 5, "connection_handle_of_effect handles preferred address events");
    }
    check(!effect_is_endpoint_relevant(
              quic::QuicCoreEffect{quic::QuicCoreResumptionStateAvailable{.connection = 6}}),
          "resumption effects are not endpoint relevant");
    check(effect_is_endpoint_relevant(
              quic::QuicCoreEffect{quic::QuicCoreReceiveStreamData{.connection = 7}}),
          "receive stream effects are endpoint relevant");

    {
        quic::QuicCoreResult result;
        result.local_error = quic::QuicCoreLocalError{
            .connection = 3,
            .code = quic::QuicCoreLocalErrorCode::unsupported_operation,
        };
        result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreReceiveStreamData{
                .connection = 4,
            },
        });
        result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreConnectionLifecycleEvent{
                .connection = 4,
                .event = quic::QuicCoreConnectionLifecycle::accepted,
            },
        });
        result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreResumptionStateAvailable{
                .connection = 5,
            },
        });

        const auto affected = affected_connections(result);
        check(affected == std::vector<quic::QuicConnectionHandle>{3, 4, 5},
              "affected_connections deduplicates connections in encounter order");
        check(affected_connections(
                  quic::QuicCoreResult{
                      .local_error =
                          quic::QuicCoreLocalError{
                              .code = quic::QuicCoreLocalErrorCode::unsupported_operation,
                          },
                  })
                  .empty(),
              "affected_connections ignores endpoint-local errors without connection handles");

        const auto filtered = filter_result_for_connection(result, 4);
        check(!filtered.local_error.has_value(),
              "filter_result_for_connection drops local_error for other connections");
        check(filtered.effects.size() == 2,
              "filter_result_for_connection keeps endpoint-relevant matching effects");
    }

    check(make_connection_command(9,
                                  quic::QuicCoreResetStream{
                                      .stream_id = 1,
                                  })
              .has_value(),
          "make_connection_command supports reset stream");
    check(make_connection_command(9,
                                  quic::QuicCoreStopSending{
                                      .stream_id = 1,
                                  })
              .has_value(),
          "make_connection_command supports stop sending");
    check(make_connection_command(9,
                                  quic::QuicCoreCloseConnection{
                                      .application_error_code = 1,
                                  })
              .has_value(),
          "make_connection_command supports close connection");
    check(make_connection_command(9, quic::QuicCoreRequestKeyUpdate{}).has_value(),
          "make_connection_command supports key update");
    check(make_connection_command(9,
                                  quic::QuicCoreRequestConnectionMigration{
                                      .route_handle = 4,
                                  })
              .has_value(),
          "make_connection_command supports migration");
    check(!make_connection_command(9, quic::QuicCoreTimerExpired{}).has_value(),
          "make_connection_command rejects endpoint-only inputs");

    {
        const auto config = Http3RuntimeConfig{
            .host = "127.0.0.1",
            .port = 443,
            .alt_svc_max_age = 60,
            .document_root = "site",
            .certificate_chain_path = "cert.pem",
            .private_key_path = "key.pem",
        };
        const auto bootstrap = make_http3_bootstrap_config(config);
        check(bootstrap.port == 443, "make_http3_bootstrap_config uses the runtime port");
        check(bootstrap.h3_port == 443,
              "make_http3_bootstrap_config mirrors the runtime port for h3");
        check(bootstrap.alt_svc_max_age == 60,
              "make_http3_bootstrap_config propagates Alt-Svc max age");
        check(bootstrap.document_root == "site",
              "make_http3_bootstrap_config propagates the document root");
    }
    {
        auto config = Http3RuntimeConfig{
            .host = "127.0.0.1",
            .port = 443,
            .bootstrap_port = 8443,
        };
        check(make_http3_bootstrap_config(config).port == 8443,
              "make_http3_bootstrap_config prefers explicit bootstrap port");
    }

    force_bootstrap_guard_failure_for_test() = true;
    check(run_http3_bootstrap_server_guarded(Http3BootstrapConfig{}, nullptr) == 1,
          "run_http3_bootstrap_server_guarded converts exceptions into failures");
    force_bootstrap_guard_failure_for_test() = false;

    check(!server_update_has_immediate_work(Http3ServerEndpointUpdate{}),
          "server_update_has_immediate_work handles idle update");
    check(server_update_has_immediate_work(Http3ServerEndpointUpdate{
              .request_cancelled_events = {Http3ServerRequestCancelledEvent{}},
          }),
          "server_update_has_immediate_work sees cancellation events");
    check(!client_update_has_immediate_work(Http3ClientEndpointUpdate{}),
          "client_update_has_immediate_work handles idle update");
    check(client_update_has_immediate_work(Http3ClientEndpointUpdate{
              .request_error_events = {Http3ClientRequestErrorEvent{}},
          }),
          "client_update_has_immediate_work sees request errors");

    return ok;
}

std::uint64_t runtime_connection_handle_effect_coverage_mask_for_test() {
    std::uint64_t mask = 0;
    const auto mark = [&](std::uint64_t bit, const quic::QuicCoreEffect &effect,
                          quic::QuicConnectionHandle expected_handle, std::string_view label) {
        const bool matched = connection_handle_of_effect(effect) == expected_handle;
        mask |= static_cast<std::uint64_t>(runtime_internal_check(
                    matched, "runtime_connection_handle_effect_coverage_mask_for_test", label)) *
                bit;
    };

    mark(1ull << 0,
         quic::QuicCoreEffect{quic::QuicCoreConnectionLifecycleEvent{
             .connection = 8,
             .event = quic::QuicCoreConnectionLifecycle::accepted,
         }},
         8, "connection_handle_of_effect handles lifecycle events");
    mark(1ull << 1,
         quic::QuicCoreEffect{quic::QuicCorePeerPreferredAddressAvailable{
             .connection = 9,
         }},
         9, "connection_handle_of_effect handles preferred address events");
    mark(1ull << 2,
         quic::QuicCoreEffect{quic::QuicCoreResumptionStateAvailable{
             .connection = 10,
         }},
         10, "connection_handle_of_effect handles resumption events");
    mark(1ull << 3,
         quic::QuicCoreEffect{quic::QuicCoreZeroRttStatusEvent{
             .connection = 11,
         }},
         11, "connection_handle_of_effect handles zero-rtt status events");
    mark(1ull << 4,
         quic::QuicCoreEffect{quic::QuicCorePeerResetStream{
             .connection = 12,
             .stream_id = 13,
             .application_error_code = 14,
             .final_size = 15,
         }},
         12, "connection_handle_of_effect handles peer reset stream effects");
    mark(1ull << 5,
         quic::QuicCoreEffect{quic::QuicCorePeerStopSending{
             .connection = 16,
             .stream_id = 17,
             .application_error_code = 18,
         }},
         16, "connection_handle_of_effect handles peer stop sending effects");

    return mask;
}

std::uint64_t runtime_loop_internal_coverage_mask_for_test() {
    std::uint64_t mask = 0;
    const auto mark = [&](std::uint64_t bit, bool condition, std::string_view label) {
        mask |= static_cast<std::uint64_t>(runtime_internal_check(
                    condition, "runtime_loop_internal_coverage_mask_for_test", label)) *
                bit;
    };

    {
        RuntimeTestBackend backend;
        io::QuicIoRemote remote{
            .family = AF_INET,
        };
        const auto ensured = backend.ensure_route(remote);
        const auto ensured_remote = backend.last_remote.value_or(io::QuicIoRemote{});
        const bool ensure_route_ok =
            (ensured == backend.ensured_route) & (backend.ensure_route_calls == 1) &
            backend.last_remote.has_value() & (ensured_remote.family == AF_INET);
        mark(kRuntimeLoopMaskEnsureRoute, ensure_route_ok,
             "runtime test backend records ensure_route");
    }

    const auto server_config = make_runtime_server_config_for_test(std::filesystem::current_path());
    const auto server_endpoint = make_http3_server_endpoint_config(server_config);
    const bool server_endpoint_ready = runtime_internal_check(
        server_endpoint.has_value(), "runtime_loop_internal_coverage_mask_for_test",
        "server endpoint config loads fixture identity for loop mask");
    const auto server_endpoint_config = server_endpoint.value_or(quic::QuicCoreEndpointConfig{});
    const auto run_server_case = [&](io::QuicIoEvent event, std::size_t expected_wait_calls) {
        auto backend = std::make_unique<RuntimeTestBackend>();
        auto *backend_ptr = backend.get();
        backend_ptr->wait_results = {event, std::nullopt};
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        return (runtime.run() == 1) & (backend_ptr->wait_calls == expected_wait_calls);
    };

    const auto event_now = quic::QuicCoreClock::now();
    mark(kRuntimeLoopMaskServerIdleTimeout,
         server_endpoint_ready & run_server_case(
                                     io::QuicIoEvent{
                                         .kind = io::QuicIoEvent::Kind::idle_timeout,
                                         .now = event_now,
                                     },
                                     2),
         "server runtime handles idle timeout events");
    mark(kRuntimeLoopMaskServerShutdown,
         server_endpoint_ready & run_server_case(
                                     io::QuicIoEvent{
                                         .kind = io::QuicIoEvent::Kind::shutdown,
                                         .now = event_now,
                                     },
                                     1),
         "server runtime handles shutdown events");
    mark(kRuntimeLoopMaskServerTimerExpired,
         server_endpoint_ready & run_server_case(
                                     io::QuicIoEvent{
                                         .kind = io::QuicIoEvent::Kind::timer_expired,
                                         .now = event_now,
                                     },
                                     2),
         "server runtime handles timer events");
    mark(kRuntimeLoopMaskServerRxDatagramWithoutPayload,
         server_endpoint_ready & run_server_case(
                                     io::QuicIoEvent{
                                         .kind = io::QuicIoEvent::Kind::rx_datagram,
                                         .now = event_now,
                                     },
                                     2),
         "server runtime handles rx events without payloads");

    const auto live_rx_now = quic::QuicCoreClock::now() - std::chrono::seconds{5};
    const auto live_rx_event =
        make_live_initial_rx_event(make_runtime_client_config_for_test(), live_rx_now);
    const bool live_rx_event_ready = runtime_internal_check(
        live_rx_event.has_value(), "runtime_loop_internal_coverage_mask_for_test",
        "client helper builds live initial datagram for server runtime");
    auto live_backend = std::make_unique<RuntimeTestBackend>();
    auto *live_backend_ptr = live_backend.get();
    live_backend_ptr->wait_results.push_back(live_rx_event.value_or(io::QuicIoEvent{
        .kind = io::QuicIoEvent::Kind::rx_datagram,
        .now = live_rx_now,
    }));
    live_backend_ptr->wait_results.push_back(std::nullopt);
    Http3ServerRuntime live_runtime(server_config, server_endpoint_config, std::move(live_backend));
    const bool server_rx_with_payload_ok =
        server_endpoint_ready & live_rx_event_ready & (live_runtime.run() == 1) &
        (live_backend_ptr->wait_calls == 2) & !live_backend_ptr->sends.empty();
    mark(kRuntimeLoopMaskServerRxDatagramWithPayload, server_rx_with_payload_ok,
         "server runtime handles rx events with datagram payloads");

    RuntimeScopedTempDir output_root;
    const auto client_config = make_runtime_client_config_for_test();
    const auto plan = make_client_execution_plan(client_config);
    const bool client_plan_ready =
        runtime_internal_check(plan.has_value(), "runtime_loop_internal_coverage_mask_for_test",
                               "client execution plan builds for loop mask");
    const auto client_plan = plan.value_or(Http3ClientExecutionPlan{});
    const std::vector<Http3ClientTransferPlan> transfers{
        Http3ClientTransferPlan{
            .execution = client_plan,
            .output_path = output_root.path() / "response.bin",
        },
    };

    const auto run_client_case = [&](io::QuicIoEvent event, std::size_t expected_wait_calls) {
        auto backend = std::make_unique<RuntimeTestBackend>();
        auto *backend_ptr = backend.get();
        backend_ptr->wait_results = {event, std::nullopt};
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        return (runtime.run() == 1) & (backend_ptr->wait_calls == expected_wait_calls);
    };

    mark(kRuntimeLoopMaskClientIdleTimeout,
         client_plan_ready & run_client_case(
                                 io::QuicIoEvent{
                                     .kind = io::QuicIoEvent::Kind::idle_timeout,
                                     .now = event_now,
                                 },
                                 1),
         "client runtime handles idle timeout events");
    mark(kRuntimeLoopMaskClientShutdown,
         client_plan_ready & run_client_case(
                                 io::QuicIoEvent{
                                     .kind = io::QuicIoEvent::Kind::shutdown,
                                     .now = event_now,
                                 },
                                 1),
         "client runtime handles shutdown events");
    mark(kRuntimeLoopMaskClientTimerExpired,
         client_plan_ready & run_client_case(
                                 io::QuicIoEvent{
                                     .kind = io::QuicIoEvent::Kind::timer_expired,
                                     .now = event_now,
                                 },
                                 2),
         "client runtime handles timer events");
    mark(kRuntimeLoopMaskClientRxDatagramWithoutPayload,
         client_plan_ready & run_client_case(
                                 io::QuicIoEvent{
                                     .kind = io::QuicIoEvent::Kind::rx_datagram,
                                     .now = event_now,
                                 },
                                 2),
         "client runtime handles rx events without payloads");

    auto backend = std::make_unique<RuntimeTestBackend>();
    Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
    runtime.connection_ = 7;
    const auto ready = runtime.endpoint_.on_core_result(
        quic::QuicCoreResult{
            .effects =
                {
                    quic::QuicCoreEffect{
                        quic::QuicCoreStateEvent{
                            .change = quic::QuicCoreStateChange::handshake_ready,
                        },
                    },
                },
        },
        event_now);
    bool client_poll_write_ok = !ready.terminal_failure;
    const auto submitted = runtime.endpoint_.submit_request(transfers.front().execution.request);
    const auto submitted_stream_id = runtime_result_uint64_or(submitted, 0);
    client_poll_write_ok &= submitted.has_value();
    client_poll_write_ok &= runtime_result_uint64_or(Http3Result<std::uint64_t>::failure(Http3Error{
                                                         .detail = "missing stream id",
                                                     }),
                                                     0) == 0;
    const auto output_path = output_root.path() / "polled-response.bin";
    runtime.pending_outputs_.insert_or_assign(submitted_stream_id, output_path);
    runtime.expected_responses_ = 1;
    runtime.completed_responses_ = 0;
    const auto flushed_request = runtime.endpoint_.poll(event_now);
    client_poll_write_ok &= !flushed_request.terminal_failure;

    auto &connection = Http3ClientEndpointTestAccess::connection(runtime.endpoint_);
    Http3ConnectionTestAccess::queue_event(connection, Http3PeerResponseHeadEvent{
                                                           .stream_id = submitted_stream_id,
                                                           .head =
                                                               Http3ResponseHead{
                                                                   .status = 200,
                                                               },
                                                       });
    Http3ConnectionTestAccess::queue_event(connection, Http3PeerResponseBodyEvent{
                                                           .stream_id = submitted_stream_id,
                                                           .body = bytes_from_string("poll"),
                                                       });
    Http3ConnectionTestAccess::queue_event(connection, Http3PeerResponseCompleteEvent{
                                                           .stream_id = submitted_stream_id,
                                                       });

    client_poll_write_ok &= runtime.drain_endpoint(
        Http3ClientEndpointUpdate{
            .has_pending_work = true,
        },
        event_now);
    const auto written = read_binary_file(output_path);
    client_poll_write_ok &= written.has_value();
    client_poll_write_ok &= written.value_or(std::vector<std::byte>{}) == bytes_from_string("poll");
    client_poll_write_ok &= runtime.completed_responses_ == 1;
    client_poll_write_ok &= runtime.pending_outputs_.empty();
    mark(kRuntimeLoopMaskClientPollResponseWrite, client_plan_ready & client_poll_write_ok,
         "client runtime writes response bodies from poll events");

    return mask;
}

bool runtime_loop_internal_coverage_for_test() {
    bool ok = true;
    const auto check = [&](bool condition, std::string_view label) {
        ok &= runtime_internal_check(condition, "runtime_loop_internal_coverage_for_test", label);
    };

    check(runtime_loop_internal_coverage_mask_for_test() == kRuntimeLoopExpectedCoverageMask,
          "runtime loop mask covers scripted event branches");

    const auto now = quic::QuicCoreClock::now();

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        auto *backend_ptr = backend.get();
        const auto config = make_runtime_server_config_for_test(std::filesystem::current_path());
        const auto endpoint = make_http3_server_endpoint_config(config);
        const auto endpoint_config = endpoint.value_or(quic::QuicCoreEndpointConfig{});
        check(endpoint.has_value(), "server endpoint config loads fixture identity");
        Http3ServerRuntime runtime(config, endpoint_config, std::move(backend));

        quic::QuicCoreResult fatal_result;
        fatal_result.local_error = quic::QuicCoreLocalError{
            .code = quic::QuicCoreLocalErrorCode::unsupported_operation,
        };
        check(!runtime.handle_result(fatal_result, now),
              "server runtime rejects endpoint-local fatal errors");

        quic::QuicCoreResult accepted_result;
        accepted_result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreConnectionLifecycleEvent{
                .connection = 11,
                .event = quic::QuicCoreConnectionLifecycle::accepted,
            },
        });
        accepted_result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreSendDatagram{
                .connection = 11,
                .route_handle = 7,
                .bytes = bytes_from_string("server"),
            },
        });
        check(runtime.handle_result(accepted_result, now),
              "server runtime accepts lifecycle+send results");
        check(backend_ptr->sends.size() == 1, "server runtime emits a single accepted datagram");
        check(runtime.endpoints_.contains(11), "server runtime tracks accepted connections");

        quic::QuicCoreResult closed_result;
        closed_result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreConnectionLifecycleEvent{
                .connection = 11,
                .event = quic::QuicCoreConnectionLifecycle::closed,
            },
        });
        check(runtime.handle_result(closed_result, now), "server runtime handles closed lifecycle");
        check(!runtime.endpoints_.contains(11), "server runtime erases closed connections");

        runtime.endpoints_.emplace(12, Http3ServerEndpoint{});
        quic::QuicCoreResult connection_error;
        connection_error.local_error = quic::QuicCoreLocalError{
            .connection = 12,
            .code = quic::QuicCoreLocalErrorCode::unsupported_operation,
        };
        check(runtime.handle_result(connection_error, now),
              "server runtime handles connection-scoped local errors");
        check(!runtime.endpoints_.contains(12),
              "server runtime erases endpoints after connection-scoped errors");

        check(!runtime.drain_endpoint(19,
                                      Http3ServerEndpointUpdate{
                                          .core_inputs = {quic::QuicCoreTimerExpired{}},
                                      },
                                      now),
              "server runtime rejects non-command endpoint inputs");

        runtime.endpoints_.emplace(21, Http3ServerEndpoint{});
        check(runtime.drain_endpoint(21,
                                     Http3ServerEndpointUpdate{
                                         .terminal_failure = true,
                                     },
                                     now),
              "server runtime handles terminal endpoint failure");
        check(!runtime.endpoints_.contains(21),
              "server runtime erases failed endpoint immediately");

        runtime.endpoints_.emplace(22, Http3ServerEndpoint{});
        check(runtime.drain_endpoint(22,
                                     Http3ServerEndpointUpdate{
                                         .has_pending_work = true,
                                     },
                                     now),
              "server runtime polls while endpoint reports pending work");
        check(runtime.endpoints_.contains(22),
              "server runtime keeps healthy endpoints after no-op poll");

        Http3ServerEndpoint failed_endpoint;
        static_cast<void>(failed_endpoint.on_core_result(
            quic::QuicCoreResult{
                .local_error =
                    quic::QuicCoreLocalError{
                        .code = quic::QuicCoreLocalErrorCode::unsupported_operation,
                    },
            },
            now));
        runtime.endpoints_.insert_or_assign(23, std::move(failed_endpoint));
        check(runtime.drain_endpoint(23,
                                     Http3ServerEndpointUpdate{
                                         .has_pending_work = true,
                                     },
                                     now),
              "server runtime consumes terminal poll updates");
        check(!runtime.endpoints_.contains(23),
              "server runtime erases endpoints after terminal poll");

        auto wait_backend = std::make_unique<RuntimeTestBackend>();
        wait_backend->wait_results.push_back(std::nullopt);
        Http3ServerRuntime wait_runtime(config, endpoint_config, std::move(wait_backend));
        check(wait_runtime.run() == 1, "server runtime exits on backend wait failure");
    }

    {
        RuntimeScopedTempDir output_root;
        const auto config = make_runtime_client_config_for_test();
        auto plan = make_client_execution_plan(config);
        const auto client_plan = plan.value_or(Http3ClientExecutionPlan{});
        check(plan.has_value(), "client execution plan builds for loop coverage");
        const std::vector<Http3ClientTransferPlan> transfers{
            Http3ClientTransferPlan{
                .execution = client_plan,
                .output_path = output_root.path() / "response.bin",
            },
        };

        {
            auto backend = std::make_unique<RuntimeTestBackend>();
            Http3ClientRuntime empty_runtime(config, {}, 1, std::move(backend));
            check(empty_runtime.run() == 1, "client runtime rejects empty transfer set");
        }

        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ClientRuntime runtime(config, transfers, 3, std::move(backend));

        quic::QuicCoreResult local_error;
        local_error.local_error = quic::QuicCoreLocalError{
            .connection = 7,
            .code = quic::QuicCoreLocalErrorCode::unsupported_operation,
        };
        check(!runtime.handle_result(local_error, now), "client runtime rejects local errors");
        check(runtime.handle_result(quic::QuicCoreResult{}, now),
              "client runtime ignores empty results before connection creation");

        quic::QuicCoreResult created;
        created.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreConnectionLifecycleEvent{
                .connection = 7,
                .event = quic::QuicCoreConnectionLifecycle::created,
            },
        });
        check(runtime.handle_result(created, now), "client runtime accepts created lifecycle");
        check(runtime.connection_ == std::optional<quic::QuicConnectionHandle>{7},
              "client runtime remembers created connection");

        runtime.expected_responses_ = 1;
        check(!runtime.handle_result(
                  quic::QuicCoreResult{
                      .effects =
                          {
                              quic::QuicCoreEffect{
                                  quic::QuicCoreConnectionLifecycleEvent{
                                      .connection = 7,
                                      .event = quic::QuicCoreConnectionLifecycle::closed,
                                  },
                              },
                          },
                  },
                  now),
              "client runtime fails when connection closes before all responses arrive");

        check(!runtime.drain_endpoint(
                  Http3ClientEndpointUpdate{
                      .events =
                          {
                              Http3ClientResponseEvent{
                                  .stream_id = 99,
                              },
                          },
                  },
                  now),
              "client runtime rejects responses for unknown outputs");

        runtime.pending_outputs_.insert_or_assign(0, output_root.path() / "response.bin");
        runtime.expected_responses_ = 1;
        runtime.completed_responses_ = 0;
        check(runtime.drain_endpoint(
                  Http3ClientEndpointUpdate{
                      .events =
                          {
                              Http3ClientResponseEvent{
                                  .stream_id = 0,
                                  .response =
                                      Http3Response{
                                          .head =
                                              {
                                                  .status = 200,
                                              },
                                          .body = bytes_from_string("ok"),
                                      },
                              },
                          },
                      .terminal_failure = true,
                  },
                  now),
              "client runtime writes completed responses before terminal failure");
        const auto written = read_binary_file(output_root.path() / "response.bin");
        check(written.has_value(), "client runtime writes response bodies to output files");
        check(written.value_or(std::vector<std::byte>{}) == bytes_from_string("ok"),
              "client runtime persists the expected response body");

        runtime.connection_.reset();
        check(!runtime.drain_endpoint(
                  Http3ClientEndpointUpdate{
                      .core_inputs =
                          {
                              quic::QuicCoreSendStreamData{
                                  .stream_id = 0,
                                  .bytes = bytes_from_string("payload"),
                              },
                          },
                  },
                  now),
              "client runtime rejects endpoint commands before connection creation");

        check(!runtime.drain_endpoint(
                  Http3ClientEndpointUpdate{
                      .request_error_events =
                          {
                              Http3ClientRequestErrorEvent{
                                  .stream_id = 0,
                              },
                          },
                  },
                  now),
              "client runtime rejects request error events");
    }

    return ok;
}

bool runtime_additional_internal_coverage_for_test() {
    bool ok = true;
    const auto check = [&](bool condition, std::string_view label) {
        ok &= runtime_internal_check(condition, "runtime_additional_internal_coverage_for_test",
                                     label);
    };

    const auto now = quic::QuicCoreClock::now();
    RuntimeScopedTempDir document_root;
    check(document_root.write_file("index.html", "ok"), "write runtime_additional index fixture");

    const auto nested_path = document_root.path() / "assets" / "index.html";
    const auto nested_prefix = document_root.path() / "assets";
    check(path_has_prefix(nested_path, nested_prefix), "path_has_prefix accepts matching prefixes");

    {
        const auto invalid_client = Http3RuntimeConfig{
            .mode = Http3RuntimeMode::client,
            .url = "https:///missing-host",
        };
        check(!make_live_initial_rx_event(invalid_client, now).has_value(),
              "live initial rx helper rejects invalid client plans");
    }

    {
        quic::QuicCoreResult no_send_result;
        no_send_result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreStateEvent{
                .change = quic::QuicCoreStateChange::handshake_ready,
            },
        });
        check(!first_send_datagram_as_rx_event(no_send_result, now).has_value(),
              "first_send_datagram_as_rx_event skips non-datagram effects");

        quic::QuicCoreResult missing_route_send_result;
        missing_route_send_result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreSendDatagram{
                .connection = 1,
                .bytes = bytes_from_string("x"),
            },
        });
        check(!first_send_datagram_as_rx_event(missing_route_send_result, now).has_value(),
              "first_send_datagram_as_rx_event rejects datagrams without route handles");
    }

    const auto server_config = make_runtime_server_config_for_test(document_root.path());
    const auto server_endpoint = make_http3_server_endpoint_config(server_config);
    const auto server_endpoint_config = server_endpoint.value_or(quic::QuicCoreEndpointConfig{});
    check(server_endpoint.has_value(), "server endpoint config loads for additional coverage");
    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        force_server_due_timer_count_for_test() = 1;
        force_server_handle_result_failure_after_calls_for_test() = 0;
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        check(runtime.run() == 1, "server runtime fails when forced due timer handling fails");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        backend->wait_results.push_back(io::QuicIoEvent{
            .kind = io::QuicIoEvent::Kind::timer_expired,
            .now = now,
        });
        force_server_handle_result_failure_after_calls_for_test() = 0;
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        check(runtime.run() == 1,
              "server runtime fails when timer events trigger handle_result failures");
    }

    {
        const auto live_rx_event =
            make_live_initial_rx_event(make_runtime_client_config_for_test(), now);
        check(live_rx_event.has_value(), "live initial rx helper builds a server datagram");
        auto backend = std::make_unique<RuntimeTestBackend>();
        backend->wait_results.push_back(live_rx_event.value_or(io::QuicIoEvent{
            .kind = io::QuicIoEvent::Kind::rx_datagram,
            .now = now,
        }));
        force_server_handle_result_failure_after_calls_for_test() = 0;
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        check(runtime.run() == 1,
              "server runtime fails when rx events trigger handle_result failures");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        backend->send_result = false;
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        quic::QuicCoreResult send_failure;
        send_failure.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreSendDatagram{
                .connection = 9,
                .route_handle = 7,
                .bytes = bytes_from_string("server-send"),
            },
        });
        check(!runtime.handle_result(send_failure, now),
              "server runtime propagates backend send failures from handle_result");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        quic::QuicCoreResult unknown_connection;
        unknown_connection.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreReceiveStreamData{
                .connection = 77,
            },
        });
        check(runtime.handle_result(unknown_connection, now),
              "server runtime ignores affected connections without endpoints");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        quic::QuicCoreResult accepted;
        accepted.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreConnectionLifecycleEvent{
                .connection = 11,
                .event = quic::QuicCoreConnectionLifecycle::accepted,
            },
        });
        check(runtime.handle_result(accepted, now),
              "server runtime accepts connections for additional coverage");
        check(runtime.endpoints_.contains(11),
              "server runtime retains the accepted endpoint for synthetic request handling");
        auto &accepted_endpoint = runtime.endpoints_[11];
        auto handshake_ready = quic::QuicCoreResult{};
        handshake_ready.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreStateEvent{
                .change = quic::QuicCoreStateChange::handshake_ready,
            },
        });
        const auto handshake_update = accepted_endpoint.on_core_result(handshake_ready, now);
        check(!handshake_update.terminal_failure,
              "accepted endpoint primes its transport before synthetic request handling");
        std::array<Http3Field, 4> request_fields{
            Http3Field{":method", "GET"},
            Http3Field{":scheme", "https"},
            Http3Field{":authority", "example.test"},
            Http3Field{":path", "/"},
        };
        Http3QpackEncoderContext encoder;
        const auto encoded = encode_http3_field_section(encoder, 0, request_fields);
        check(encoded.has_value(), "accepted endpoint encodes a synthetic request field section");
        const auto encoded_section = runtime_result_field_section_or_empty(encoded);
        check(runtime_result_field_section_or_empty(
                  Http3Result<Http3EncodedFieldSection>::success(encoded_section))
                      .prefix == encoded_section.prefix,
              "accepted endpoint field-section helper preserves success values");
        check(runtime_result_field_section_or_empty(
                  Http3Result<Http3EncodedFieldSection>::failure(Http3Error{
                      .detail = "missing field section",
                  }))
                  .payload.empty(),
              "accepted endpoint field-section helper returns empty payloads on failure");
        check(runtime_result_field_section_or_empty(
                  quic::CodecResult<Http3EncodedFieldSection>::failure(
                      quic::CodecErrorCode::http3_parse_error, 0))
                  .payload.empty(),
              "accepted endpoint field-section helper returns empty payloads on codec failures");
        auto field_section = encoded_section.prefix;
        field_section.insert(field_section.end(), encoded_section.payload.begin(),
                             encoded_section.payload.end());
        const auto frame = serialize_http3_frame(Http3Frame{
            Http3HeadersFrame{
                .field_section = std::move(field_section),
            },
        });
        check(frame.has_value(), "accepted endpoint serializes a synthetic request headers frame");
        const auto frame_bytes = runtime_result_bytes_or_empty(frame);
        check(runtime_result_bytes_or_empty(
                  Http3Result<std::vector<std::byte>>::success(frame_bytes)) == frame_bytes,
              "accepted endpoint frame helper preserves success buffers");
        check(runtime_result_bytes_or_empty(Http3Result<std::vector<std::byte>>::failure(Http3Error{
                                                .detail = "missing frame bytes",
                                            }))
                  .empty(),
              "accepted endpoint frame helper returns empty buffers on failure");
        check(runtime_result_bytes_or_empty(quic::CodecResult<std::vector<std::byte>>::failure(
                                                quic::CodecErrorCode::http3_parse_error, 0))
                  .empty(),
              "accepted endpoint frame helper returns empty buffers on codec failures");
        quic::QuicCoreResult request_result;
        request_result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreReceiveStreamData{
                .stream_id = 0,
                .bytes = frame_bytes,
                .fin = true,
            },
        });
        const auto update = accepted_endpoint.on_core_result(request_result, now);
        check(!update.terminal_failure,
              "accepted endpoint handles synthetic request frames without failing");
        check(!update.core_inputs.empty(),
              "server runtime invokes the accepted endpoint request handler");
        check(runtime.drain_endpoint(11, update, now),
              "server runtime drains synthetic request updates without failing");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        force_server_handle_result_failure_after_calls_for_test() = 0;
        check(!runtime.submit_endpoint_commands(19,
                                                {
                                                    quic::QuicCoreCloseConnection{
                                                        .application_error_code = 1,
                                                    },
                                                },
                                                now),
              "server submit_endpoint_commands propagates handle_result failures");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        check(runtime.drain_endpoint(99,
                                     Http3ServerEndpointUpdate{
                                         .has_pending_work = true,
                                     },
                                     now),
              "server drain_endpoint exits cleanly when the endpoint is already gone");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        Http3ServerEndpoint failed_endpoint;
        static_cast<void>(failed_endpoint.on_core_result(
            quic::QuicCoreResult{
                .local_error =
                    quic::QuicCoreLocalError{
                        .code = quic::QuicCoreLocalErrorCode::unsupported_operation,
                    },
            },
            now));
        runtime.endpoints_.insert_or_assign(12, std::move(failed_endpoint));
        force_server_polled_submit_failure_count_for_test() = 1;
        check(!runtime.drain_endpoint(12,
                                      Http3ServerEndpointUpdate{
                                          .has_pending_work = true,
                                      },
                                      now),
              "server drain_endpoint fails when a polled update forces submission failure");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        runtime.endpoints_.emplace(13, Http3ServerEndpoint{});
        force_server_drain_failure_count_for_test() = 1;
        quic::QuicCoreResult filtered_result;
        filtered_result.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreReceiveStreamData{
                .connection = 13,
            },
        });
        check(!runtime.handle_result(filtered_result, now),
              "server handle_result fails when draining a filtered endpoint update fails");
    }

    check(runtime_server_local_error_without_connection_coverage_for_test(),
          "server handle_result rejects local errors without connection ids");

    RuntimeScopedTempDir output_root;
    const auto client_config = make_runtime_client_config_for_test();
    const auto plan = make_client_execution_plan(client_config);
    const auto client_plan = plan.value_or(Http3ClientExecutionPlan{});
    check(plan.has_value(), "client execution plan loads for additional coverage");
    const std::vector<Http3ClientTransferPlan> transfers{
        Http3ClientTransferPlan{
            .execution = client_plan,
            .output_path = output_root.path() / "response.bin",
        },
    };

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        force_client_initial_submit_failure_count_for_test() = 1;
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        check(runtime.run() == 1,
              "client runtime fails when the initial request submission is forced to fail");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        force_client_handle_result_failure_after_calls_for_test() = 0;
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        check(runtime.run() == 1,
              "client runtime fails when opening the connection triggers handle_result failure");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        backend->wait_results.push_back(std::nullopt);
        force_client_due_timer_count_for_test() = 1;
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        check(runtime.run() == 1,
              "client runtime continues after a forced due timer before backend wait failure");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        force_client_due_timer_count_for_test() = 1;
        force_client_handle_result_failure_after_calls_for_test() = 1;
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        check(runtime.run() == 1,
              "client runtime fails when a forced due timer triggers handle_result failure");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        backend->wait_results.push_back(io::QuicIoEvent{
            .kind = io::QuicIoEvent::Kind::timer_expired,
            .now = now,
        });
        force_client_handle_result_failure_after_calls_for_test() = 1;
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        check(runtime.run() == 1,
              "client runtime fails when timer events trigger handle_result failures");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        backend->send_result = false;
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        quic::QuicCoreResult send_failure;
        send_failure.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreSendDatagram{
                .connection = 7,
                .route_handle = 3,
                .bytes = bytes_from_string("client-send"),
            },
        });
        check(!runtime.handle_result(send_failure, now),
              "client runtime propagates backend send failures from handle_result");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        runtime.connection_ = 7;
        check(!runtime.submit_endpoint_commands(
                  {
                      quic::QuicCoreTimerExpired{},
                  },
                  now),
              "client submit_endpoint_commands rejects endpoint-only inputs");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        runtime.connection_ = 7;
        force_client_handle_result_failure_after_calls_for_test() = 0;
        check(!runtime.submit_endpoint_commands(
                  {
                      quic::QuicCoreCloseConnection{
                          .application_error_code = 1,
                      },
                  },
                  now),
              "client submit_endpoint_commands propagates handle_result failures");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        runtime.connection_ = 7;
        static_cast<void>(runtime.endpoint_.on_core_result(
            quic::QuicCoreResult{
                .effects =
                    {
                        quic::QuicCoreEffect{
                            quic::QuicCoreStateEvent{
                                .change = quic::QuicCoreStateChange::handshake_ready,
                            },
                        },
                    },
            },
            now));
        const auto submitted =
            runtime.endpoint_.submit_request(transfers.front().execution.request);
        const auto submitted_stream_id = runtime_result_uint64_or(submitted, 0);
        check(submitted.has_value(), "client endpoint submits synthetic request for poll tests");
        check(runtime_result_uint64_or(Http3Result<std::uint64_t>::failure(Http3Error{
                                           .detail = "missing stream id for poll tests",
                                       }),
                                       0) == 0,
              "client poll-test stream-id helper returns zero on failure");
        auto &connection = Http3ClientEndpointTestAccess::connection(runtime.endpoint_);
        Http3ConnectionTestAccess::queue_event(connection, Http3PeerResponseHeadEvent{
                                                               .stream_id = submitted_stream_id,
                                                               .head =
                                                                   Http3ResponseHead{
                                                                       .status = 200,
                                                                   },
                                                           });
        Http3ConnectionTestAccess::queue_event(connection, Http3PeerResponseBodyEvent{
                                                               .stream_id = submitted_stream_id,
                                                               .body = bytes_from_string("body"),
                                                           });
        Http3ConnectionTestAccess::queue_event(connection, Http3PeerResponseCompleteEvent{
                                                               .stream_id = submitted_stream_id,
                                                           });
        runtime.expected_responses_ = 1;
        runtime.completed_responses_ = 0;
        check(!runtime.drain_endpoint(
                  Http3ClientEndpointUpdate{
                      .has_pending_work = true,
                  },
                  now),
              "client drain_endpoint rejects polled responses without matching outputs");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        runtime.connection_ = 7;
        static_cast<void>(runtime.endpoint_.on_core_result(
            quic::QuicCoreResult{
                .effects =
                    {
                        quic::QuicCoreEffect{
                            quic::QuicCoreStateEvent{
                                .change = quic::QuicCoreStateChange::handshake_ready,
                            },
                        },
                    },
            },
            now));
        const auto submitted =
            runtime.endpoint_.submit_request(transfers.front().execution.request);
        const auto submitted_stream_id = runtime_result_uint64_or(submitted, 0);
        check(submitted.has_value(),
              "client endpoint submits synthetic request for polled write failures");
        check(runtime_result_uint64_or(Http3Result<std::uint64_t>::failure(Http3Error{
                                           .detail = "missing stream id for write failures",
                                       }),
                                       0) == 0,
              "client write-failure stream-id helper returns zero on failure");
        auto &connection = Http3ClientEndpointTestAccess::connection(runtime.endpoint_);
        Http3ConnectionTestAccess::queue_event(connection, Http3PeerResponseHeadEvent{
                                                               .stream_id = submitted_stream_id,
                                                               .head =
                                                                   Http3ResponseHead{
                                                                       .status = 200,
                                                                   },
                                                           });
        Http3ConnectionTestAccess::queue_event(connection, Http3PeerResponseBodyEvent{
                                                               .stream_id = submitted_stream_id,
                                                               .body = bytes_from_string("body"),
                                                           });
        Http3ConnectionTestAccess::queue_event(connection, Http3PeerResponseCompleteEvent{
                                                               .stream_id = submitted_stream_id,
                                                           });
        runtime.pending_outputs_.insert_or_assign(submitted_stream_id, output_root.path());
        runtime.expected_responses_ = 1;
        runtime.completed_responses_ = 0;
        check(!runtime.drain_endpoint(
                  Http3ClientEndpointUpdate{
                      .has_pending_work = true,
                  },
                  now),
              "client drain_endpoint propagates polled file write failures");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        runtime.connection_ = 7;
        static_cast<void>(runtime.endpoint_.on_core_result(
            quic::QuicCoreResult{
                .effects =
                    {
                        quic::QuicCoreEffect{
                            quic::QuicCoreStateEvent{
                                .change = quic::QuicCoreStateChange::handshake_ready,
                            },
                        },
                    },
            },
            now));
        const auto submitted =
            runtime.endpoint_.submit_request(transfers.front().execution.request);
        const auto submitted_stream_id = runtime_result_uint64_or(submitted, 0);
        check(submitted.has_value(),
              "client endpoint submits synthetic request for poll reset coverage");
        check(runtime_result_uint64_or(Http3Result<std::uint64_t>::failure(Http3Error{
                                           .detail = "missing stream id for reset coverage",
                                       }),
                                       0) == 0,
              "client reset stream-id helper returns zero on failure");
        auto &connection = Http3ClientEndpointTestAccess::connection(runtime.endpoint_);
        Http3ConnectionTestAccess::queue_event(connection, Http3PeerResponseResetEvent{
                                                               .stream_id = submitted_stream_id,
                                                               .application_error_code = 9,
                                                           });
        runtime.expected_responses_ = 1;
        runtime.completed_responses_ = 0;
        check(!runtime.drain_endpoint(
                  Http3ClientEndpointUpdate{
                      .has_pending_work = true,
                  },
                  now),
              "client drain_endpoint rejects polled request error events");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        runtime.connection_ = 7;
        static_cast<void>(runtime.endpoint_.on_core_result(
            quic::QuicCoreResult{
                .effects =
                    {
                        quic::QuicCoreEffect{
                            quic::QuicCoreStateEvent{
                                .change = quic::QuicCoreStateChange::handshake_ready,
                            },
                        },
                    },
            },
            now));
        const auto submitted =
            runtime.endpoint_.submit_request(transfers.front().execution.request);
        check(submitted.has_value(),
              "client endpoint submits synthetic request for poll submission failures");
        runtime.expected_responses_ = 1;
        runtime.completed_responses_ = 0;
        force_client_handle_result_failure_after_calls_for_test() = 0;
        check(!runtime.drain_endpoint(
                  Http3ClientEndpointUpdate{
                      .has_pending_work = true,
                  },
                  now),
              "client drain_endpoint propagates polled command submission failures");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ClientRuntime runtime(client_config, transfers, 3, std::move(backend));
        runtime.connection_ = 7;
        runtime.expected_responses_ = 1;
        runtime.completed_responses_ = 0;
        static_cast<void>(runtime.endpoint_.on_core_result(
            quic::QuicCoreResult{
                .local_error =
                    quic::QuicCoreLocalError{
                        .connection = 7,
                        .code = quic::QuicCoreLocalErrorCode::unsupported_operation,
                    },
            },
            now));
        check(!runtime.drain_endpoint(
                  Http3ClientEndpointUpdate{
                      .has_pending_work = true,
                  },
                  now),
              "client drain_endpoint returns the poll terminal failure comparison result");
    }

    auto bootstrap_backend = std::make_unique<RuntimeTestBackend>();
    bootstrap_backend->wait_results.push_back(std::nullopt);
    check(run_http3_server_runtime_with_backend(server_config, server_endpoint_config,
                                                std::move(bootstrap_backend)) == 1,
          "run_http3_server_runtime_with_backend drives the runtime helper");

    std::packaged_task<int()> bootstrap_task([] { return 7; });
    std::optional<std::future<int>> bootstrap_result(bootstrap_task.get_future());
    std::optional<std::thread> bootstrap_thread(std::move(bootstrap_task));
    std::atomic<bool> bootstrap_stop_requested = false;
    check(finish_http3_server_run(0, bootstrap_result, bootstrap_thread,
                                  bootstrap_stop_requested) == 7,
          "finish_http3_server_run returns bootstrap exit codes after successful runtimes");
    check(bootstrap_stop_requested.load(std::memory_order_relaxed),
          "finish_http3_server_run requests bootstrap shutdown before join");
    {
        std::optional<std::future<int>> empty_result;
        std::optional<std::thread> empty_thread;
        std::atomic<bool> bootstrap_stop_requested_for_runtime = false;
        check(finish_http3_server_run(3, empty_result, empty_thread,
                                      bootstrap_stop_requested_for_runtime) == 3,
              "finish_http3_server_run returns runtime failures when bootstrap is absent");
    }
    {
        std::packaged_task<int()> bootstrap_task_for_failure([] { return 9; });
        std::optional<std::future<int>> bootstrap_result_for_failure(
            bootstrap_task_for_failure.get_future());
        std::optional<std::thread> bootstrap_thread_for_failure(
            std::move(bootstrap_task_for_failure));
        std::atomic<bool> bootstrap_stop_requested_for_failure = false;
        check(finish_http3_server_run(5, bootstrap_result_for_failure, bootstrap_thread_for_failure,
                                      bootstrap_stop_requested_for_failure) == 5,
              "finish_http3_server_run preserves runtime failures when bootstrap also exits");
    }
    {
        auto bootstrap_passthrough = server_config;
        bootstrap_passthrough.port = 0;
        bootstrap_passthrough.bootstrap_port = 0;
        forced_server_endpoint_config_for_test() = server_endpoint_config;
        forced_server_bootstrap_for_test() = io::QuicServerIoBootstrap{
            .backend =
                [] {
                    auto backend = std::make_unique<RuntimeTestBackend>();
                    backend->wait_results.push_back(std::nullopt);
                    return backend;
                }(),
        };
        check(run_http3_server(bootstrap_passthrough) == 1,
              "run_http3_server continues into runtime when bootstrap stays live");
    }

    {
        auto forced_config = server_config;
        forced_config.enable_bootstrap = false;
        forced_server_endpoint_config_for_test() = server_endpoint_config;
        forced_server_bootstrap_for_test() = io::QuicServerIoBootstrap{
            .backend =
                [] {
                    auto backend = std::make_unique<RuntimeTestBackend>();
                    backend->wait_results.push_back(std::nullopt);
                    return backend;
                }(),
        };
        check(run_http3_server(forced_config) == 1,
              "run_http3_server executes its in-process success tail with forced bootstrap");
    }

    return ok;
}

bool runtime_server_local_error_without_connection_coverage_for_test() {
    const auto now = quic::QuicCoreClock::now();
    const auto server_config = make_runtime_server_config_for_test(std::filesystem::current_path());
    auto backend = std::make_unique<RuntimeTestBackend>();
    Http3ServerRuntime runtime(server_config, *make_http3_server_endpoint_config(server_config),
                               std::move(backend));

    quic::QuicCoreResult local_error_without_connection;
    local_error_without_connection.local_error = quic::QuicCoreLocalError{
        .code = quic::QuicCoreLocalErrorCode::unsupported_operation,
    };
    return !runtime.handle_result(local_error_without_connection, now);
}

bool runtime_tail_internal_coverage_for_test() {
    bool ok = true;
    const auto check = [&](bool condition, std::string_view label) {
        ok &= runtime_internal_check(condition, "runtime_tail_internal_coverage_for_test", label);
    };

    const auto now = quic::QuicCoreClock::now();
    RuntimeScopedTempDir document_root;
    check(document_root.write_file("index.html", "ok"), "write runtime_tail index fixture");
    const auto server_config = make_runtime_server_config_for_test(document_root.path());
    const auto server_endpoint = make_http3_server_endpoint_config(server_config);
    const auto server_endpoint_config = server_endpoint.value_or(quic::QuicCoreEndpointConfig{});
    check(server_endpoint.has_value(), "server endpoint config loads for tail coverage");

    {
        quic::QuicCoreResult different_connection;
        different_connection.effects.push_back(quic::QuicCoreEffect{
            quic::QuicCoreReceiveStreamData{
                .connection = 11,
                .stream_id = 0,
            },
        });
        const auto filtered = filter_result_for_connection(different_connection, 12);
        check(filtered.effects.empty(),
              "filter_result_for_connection drops endpoint-relevant effects for other connections");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        auto &endpoint = runtime.endpoints_[31];
        Http3ConnectionTestAccess::queue_core_input(
            Http3ServerEndpointTestAccess::connection(endpoint), quic::QuicCoreCloseConnection{
                                                                     .application_error_code = 7,
                                                                 });
        check(runtime.drain_endpoint(31,
                                     Http3ServerEndpointUpdate{
                                         .has_pending_work = true,
                                     },
                                     now),
              "server drain_endpoint continues after successful polled command submission");
    }

    {
        auto backend = std::make_unique<RuntimeTestBackend>();
        Http3ServerRuntime runtime(server_config, server_endpoint_config, std::move(backend));
        auto &endpoint = runtime.endpoints_[32];
        Http3ConnectionTestAccess::queue_core_input(
            Http3ServerEndpointTestAccess::connection(endpoint), quic::QuicCoreCloseConnection{
                                                                     .application_error_code = 9,
                                                                 });
        force_server_handle_result_failure_after_calls_for_test() = 0;
        check(!runtime.drain_endpoint(32,
                                      Http3ServerEndpointUpdate{
                                          .has_pending_work = true,
                                      },
                                      now),
              "server drain_endpoint propagates polled command submission failures");
    }

    return ok;
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

        const bool arg_is_empty = arg.empty();
        const bool arg_has_single_dash = !arg_is_empty && arg.front() == '-';
        if ((!arg_is_empty) & (!arg_has_single_dash)) {
            if ((mode != Http3CliMode::client) | !config.url.empty()) {
                print_usage(mode);
                return std::nullopt;
            }
            config.url = std::string(arg);
            continue;
        }

        if ((!arg_is_empty) & arg_has_single_dash) {
            print_usage(mode);
            return std::nullopt;
        }
    }

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
