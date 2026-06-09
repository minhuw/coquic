#include "src/http3/http3_bootstrap.h"

#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <poll.h>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

namespace coquic::http3 {
namespace {

constexpr int kBootstrapListenBacklog = 16;
constexpr int kBootstrapPollTimeoutMs = 100;
constexpr int kBootstrapConnectionTimeoutMs = 2000;
constexpr std::size_t kBootstrapRequestLimitBytes = std::size_t{16} * 1024u;

struct SocketTimeoutOption {
    int name;
};

class ScopedFd {
  public:
    explicit ScopedFd(int fd) : fd_(fd) {
    }

    ~ScopedFd() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;

    ScopedFd(ScopedFd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {
    }

    ScopedFd &operator=(ScopedFd &&other) noexcept {
        if (this == &other) {
            return *this;
        }
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = std::exchange(other.fd_, -1);
        return *this;
    }

    int get() const {
        return fd_;
    }

    int release() {
        return std::exchange(fd_, -1);
    }

  private:
    int fd_ = -1;
};

using SslContext = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslConnection = std::unique_ptr<SSL, decltype(&SSL_free)>;
using AddrInfo = std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>;

struct BootstrapRequest {
    std::string method;
    std::string target;
    Http3Headers headers;
    std::vector<std::byte> body;
    std::optional<std::uint64_t> content_length;
};

struct BootstrapResponse {
    int status_code = 200;
    std::string content_type;
    std::optional<std::string> allow;
    std::uintmax_t content_length = 0;
    std::string body;
};

bool bootstrap_method_is_allowed(std::string_view method, bool reverse_proxy_enabled) {
    return method == "GET" || method == "HEAD" || (reverse_proxy_enabled && method == "POST");
}

bool is_stop_requested(const std::atomic<bool> *stop_requested) {
    return stop_requested != nullptr && stop_requested->load(std::memory_order_relaxed);
}

bool is_transient_accept_errno(int accept_errno) {
    if (accept_errno == EINTR || accept_errno == EAGAIN) {
        return true;
    }
#if EWOULDBLOCK != EAGAIN
    if (accept_errno == EWOULDBLOCK) {
        return true;
    }
#endif
    return false;
}

std::string lowercase_ascii(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return out;
}

std::string_view trim_ascii(std::string_view value) {
    std::size_t begin = 0;
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }
    std::size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    return value.substr(begin, end - begin);
}

std::optional<std::uint64_t> parse_size(std::string_view value) {
    std::uint64_t parsed = 0;
    const auto *begin = value.data();
    const auto *end = value.data() + value.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end) {
        return std::nullopt;
    }
    return parsed;
}

std::string authority_from_headers(const Http3Headers &headers) {
    for (const auto &header : headers) {
        if (lowercase_ascii(header.name) == "host") {
            return header.value;
        }
    }
    return {};
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

std::optional<std::filesystem::path> &forced_file_size_failure_path_for_test() {
    static std::optional<std::filesystem::path> path;
    return path;
}

struct ForcedPollResult {
    int ready = 0;
    short revents = 0;
    int error_number = 0;
};

struct ForcedAcceptResult {
    int fd = -1;
    int error_number = 0;
};

struct BootstrapTestHooks {
    std::size_t remaining_pipe_failures = 0;
    std::size_t pipe_call_index_to_fail = 0;
    std::size_t pipe_call_count = 0;
    std::size_t remaining_listen_socket_failures = 0;
    std::size_t remaining_listen_failures = 0;
    std::size_t remaining_socket_timeout_failures = 0;
    bool fail_ssl_ctx_new = false;
    bool fail_ssl_ctx_min_proto = false;
    bool fail_ssl_ctx_check_private_key = false;
    bool fail_ssl_new = false;
    bool fail_ssl_set_fd = false;
    int move_constructor_expectation_mismatch_stage = 0;
    int move_assignment_expectation_mismatch_index = 0;
    int self_move_expectation_mismatch_stage = 0;
    std::vector<ForcedPollResult> forced_poll_results;
    std::size_t forced_poll_index = 0;
    std::vector<ForcedAcceptResult> forced_accept_results;
    std::size_t forced_accept_index = 0;
    std::vector<std::string> forced_ssl_read_chunks;
    std::size_t forced_ssl_read_index = 0;
    std::vector<int> forced_ssl_write_results;
    std::size_t forced_ssl_write_index = 0;
    std::optional<Http3Response> forced_fetch_proxy_response;
    std::optional<std::vector<Http3ResponsePart>> forced_stream_proxy_parts;
    bool forced_stream_proxy_ignores_emit_result = false;
};

BootstrapTestHooks &bootstrap_test_hooks() {
    static BootstrapTestHooks hooks;
    return hooks;
}

void reset_bootstrap_test_hooks() {
    bootstrap_test_hooks() = BootstrapTestHooks{};
}

bool consume_test_hook_count(std::size_t &count) {
    if (count == 0) {
        return false;
    }
    --count;
    return true;
}

COQUIC_NO_PROFILE bool bootstrap_timeout_option_is_forced_to_fail(int option_name,
                                                                  std::size_t &remaining_failures) {
    return (option_name == SO_RCVTIMEO || option_name == SO_SNDTIMEO) &&
           consume_test_hook_count(remaining_failures);
}

int bootstrap_pipe(int pipe_fds[2]) {
    auto &hooks = bootstrap_test_hooks();
    ++hooks.pipe_call_count;
    if (hooks.pipe_call_index_to_fail != 0 &&
        hooks.pipe_call_count == hooks.pipe_call_index_to_fail) {
        errno = EMFILE;
        return -1;
    }
    if (consume_test_hook_count(hooks.remaining_pipe_failures)) {
        errno = EMFILE;
        return -1;
    }
    return ::pipe(pipe_fds);
}

int bootstrap_socket(int family, int type, int protocol) {
    auto &hooks = bootstrap_test_hooks();
    if (consume_test_hook_count(hooks.remaining_listen_socket_failures)) {
        errno = EMFILE;
        return -1;
    }
    return ::socket(family, type, protocol);
}

int bootstrap_listen(int fd, int backlog) {
    auto &hooks = bootstrap_test_hooks();
    if (consume_test_hook_count(hooks.remaining_listen_failures)) {
        errno = EADDRINUSE;
        return -1;
    }
    return ::listen(fd, backlog);
}

int bootstrap_setsockopt(int fd, int level, int option_name, const void *option_value,
                         socklen_t option_length) {
    auto &hooks = bootstrap_test_hooks();
    if (bootstrap_timeout_option_is_forced_to_fail(option_name,
                                                   hooks.remaining_socket_timeout_failures)) {
        errno = ENOPROTOOPT;
        return -1;
    }
    return ::setsockopt(fd, level, option_name, option_value, option_length);
}

int bootstrap_ssl_read(SSL *ssl, void *buffer, int buffer_size) {
    auto &hooks = bootstrap_test_hooks();
    if (hooks.forced_ssl_read_index < hooks.forced_ssl_read_chunks.size()) {
        const auto &chunk = hooks.forced_ssl_read_chunks[hooks.forced_ssl_read_index++];
        const auto bytes =
            std::min<std::size_t>(static_cast<std::size_t>(buffer_size), chunk.size());
        std::copy_n(chunk.data(), bytes, static_cast<char *>(buffer));
        return static_cast<int>(bytes);
    }
    if (ssl == nullptr) {
        return 0;
    }
    return SSL_read(ssl, buffer, buffer_size);
}

int bootstrap_ssl_write(SSL *ssl, const void *buffer, int buffer_size) {
    auto &hooks = bootstrap_test_hooks();
    if (hooks.forced_ssl_write_index < hooks.forced_ssl_write_results.size()) {
        return hooks.forced_ssl_write_results[hooks.forced_ssl_write_index++];
    }
    return SSL_write(ssl, buffer, buffer_size);
}

void bootstrap_stream_http_reverse_proxy_response(
    const Http3ReverseProxyConfig &config, const Http3Request &request,
    const std::function<bool(Http3ResponsePart)> &emit) {
    auto &hooks = bootstrap_test_hooks();
    if (hooks.forced_stream_proxy_parts.has_value()) {
        for (auto part : hooks.forced_stream_proxy_parts.value()) {
            const bool accepted = emit(std::move(part));
            if (!accepted && !hooks.forced_stream_proxy_ignores_emit_result) {
                break;
            }
        }
        return;
    }
    stream_http_reverse_proxy_response(config, request, emit);
}

Http3Response bootstrap_fetch_http_reverse_proxy_response(const Http3ReverseProxyConfig &config,
                                                          const Http3Request &request) {
    auto &hooks = bootstrap_test_hooks();
    if (hooks.forced_fetch_proxy_response.has_value()) {
        return hooks.forced_fetch_proxy_response.value();
    }
    return fetch_http_reverse_proxy_response(config, request);
}

int bootstrap_poll(pollfd *fds, nfds_t count, int timeout_ms) {
    auto &hooks = bootstrap_test_hooks();
    if (hooks.forced_poll_index < hooks.forced_poll_results.size()) {
        const auto forced = hooks.forced_poll_results[hooks.forced_poll_index++];
        if (count > 0) {
            fds[0].revents = forced.revents;
        }
        if (forced.ready < 0) {
            errno = forced.error_number;
        }
        return forced.ready;
    }
    return ::poll(fds, count, timeout_ms);
}

int bootstrap_accept(int fd, sockaddr *address, socklen_t *address_length) {
    auto &hooks = bootstrap_test_hooks();
    if (hooks.forced_accept_index < hooks.forced_accept_results.size()) {
        const auto forced = hooks.forced_accept_results[hooks.forced_accept_index++];
        if (forced.fd < 0) {
            errno = forced.error_number;
        }
        return forced.fd;
    }
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    return ::accept(fd, address, address_length);
}

SSL_CTX *bootstrap_ssl_ctx_new(const SSL_METHOD *method) {
    auto &hooks = bootstrap_test_hooks();
    if (hooks.fail_ssl_ctx_new) {
        hooks.fail_ssl_ctx_new = false;
        return nullptr;
    }
    return SSL_CTX_new(method);
}

int bootstrap_ssl_ctx_set_min_proto_version(SSL_CTX *context, int version) {
    auto &hooks = bootstrap_test_hooks();
    if (hooks.fail_ssl_ctx_min_proto) {
        hooks.fail_ssl_ctx_min_proto = false;
        return 0;
    }
    return SSL_CTX_set_min_proto_version(context, version);
}

int bootstrap_ssl_ctx_check_private_key(SSL_CTX *context) {
    auto &hooks = bootstrap_test_hooks();
    if (hooks.fail_ssl_ctx_check_private_key) {
        hooks.fail_ssl_ctx_check_private_key = false;
        return 0;
    }
    return SSL_CTX_check_private_key(context);
}

SSL *bootstrap_ssl_new(SSL_CTX *context) {
    auto &hooks = bootstrap_test_hooks();
    if (hooks.fail_ssl_new) {
        hooks.fail_ssl_new = false;
        return nullptr;
    }
    return SSL_new(context);
}

int bootstrap_ssl_set_fd(SSL *ssl, int fd) {
    auto &hooks = bootstrap_test_hooks();
    if (hooks.fail_ssl_set_fd) {
        hooks.fail_ssl_set_fd = false;
        return 0;
    }
    return SSL_set_fd(ssl, fd);
}

timeval socket_timeout_from_ms(int timeout_ms) {
    return timeval{
        .tv_sec = timeout_ms / 1000,
        .tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000),
    };
}

bool set_socket_timeout(int fd, SocketTimeoutOption option, int timeout_ms) {
    const auto timeout = socket_timeout_from_ms(timeout_ms);
    return bootstrap_setsockopt(fd, SOL_SOCKET, option.name, &timeout, sizeof(timeout)) == 0;
}

COQUIC_NO_PROFILE bool bootstrap_socket_timeouts_were_set(bool receive_set, bool send_set) {
    return receive_set && send_set;
}

bool set_bootstrap_connection_timeouts(int fd) {
    const bool receive_set =
        set_socket_timeout(fd, SocketTimeoutOption{SO_RCVTIMEO}, kBootstrapConnectionTimeoutMs);
    const bool send_set =
        set_socket_timeout(fd, SocketTimeoutOption{SO_SNDTIMEO}, kBootstrapConnectionTimeoutMs);
    return bootstrap_socket_timeouts_were_set(receive_set, send_set);
}

std::optional<std::filesystem::path>
resolve_bootstrap_path_under_root(const std::filesystem::path &root,
                                  std::string_view request_path) {
    if (request_path.empty() || request_path.front() != '/') {
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
resolve_existing_bootstrap_path_under_root(const std::filesystem::path &root,
                                           std::string_view request_path) {
    auto resolved = resolve_bootstrap_path_under_root(root, request_path);
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

std::optional<std::string> read_binary_file(const std::filesystem::path &path) {
    const auto normalized_path = path.lexically_normal();
    if (forced_read_failure_path_for_test() == normalized_path) {
        return std::nullopt;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
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

const char *reason_phrase_for_status(int status_code) {
    switch (status_code) {
    case 200:
        return "OK";
    case 400:
        return "Bad Request";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 500:
        return "Internal Server Error";
    default:
        return "Error";
    }
}

std::optional<BootstrapRequest> parse_bootstrap_request(std::string_view request_text) {
    const auto request_line_end = request_text.find("\r\n");
    if (request_line_end == std::string_view::npos) {
        return std::nullopt;
    }

    const auto request_line = request_text.substr(0, request_line_end);
    const auto first_space = request_line.find(' ');
    if (first_space == std::string_view::npos || first_space == 0) {
        return std::nullopt;
    }
    const auto second_space = request_line.find(' ', first_space + 1);
    if (second_space == std::string_view::npos || second_space == first_space + 1) {
        return std::nullopt;
    }

    const auto method = request_line.substr(0, first_space);
    const auto target = request_line.substr(first_space + 1, second_space - first_space - 1);
    const auto version = request_line.substr(second_space + 1);
    if (version != "HTTP/1.1" && version != "HTTP/1.0") {
        return std::nullopt;
    }

    const auto header_end = request_text.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        return std::nullopt;
    }

    Http3Headers headers;
    std::optional<std::uint64_t> content_length;
    std::size_t line_begin = request_line_end + 2;
    while (line_begin < header_end) {
        const auto line_end = request_text.find("\r\n", line_begin);
        const auto line = request_text.substr(line_begin, line_end - line_begin);
        const auto colon = line.find(':');
        if (colon != std::string_view::npos && colon != 0) {
            const auto raw_name = trim_ascii(line.substr(0, colon));
            if (raw_name.empty()) {
                return std::nullopt;
            }
            const auto value = trim_ascii(line.substr(colon + 1));
            headers.push_back(Http3Field{
                .name = std::string(raw_name),
                .value = std::string(value),
            });
            const auto name = lowercase_ascii(raw_name);
            if (name == "content-length") {
                const auto length = parse_size(value);
                if (!length.has_value()) {
                    return std::nullopt;
                }
                if (content_length.has_value() && *content_length != *length) {
                    return std::nullopt;
                }
                content_length = length;
            }
        }
        line_begin = line_end + 2;
    }

    const auto body_text = request_text.substr(header_end + 4);
    if (content_length.has_value()) {
        if (*content_length > kBootstrapRequestLimitBytes ||
            body_text.size() != static_cast<std::size_t>(*content_length)) {
            return std::nullopt;
        }
    } else if (!body_text.empty()) {
        return std::nullopt;
    }

    return BootstrapRequest{
        .method = std::string(method),
        .target = std::string(target),
        .headers = std::move(headers),
        .body = std::vector<std::byte>(reinterpret_cast<const std::byte *>(body_text.data()),
                                       reinterpret_cast<const std::byte *>(body_text.data()) +
                                           body_text.size()),
        .content_length = content_length,
    };
}

Http3Request make_proxy_request(const BootstrapRequest &request) {
    return Http3Request{
        .head =
            {
                .method = request.method,
                .scheme = "https",
                .authority = authority_from_headers(request.headers),
                .path = request.target,
                .content_length = request.content_length,
                .headers = request.headers,
            },
        .body = request.body,
    };
}

BootstrapResponse make_bootstrap_response_from_proxied_response(const BootstrapRequest &request,
                                                                Http3Response proxied) {
    BootstrapResponse response{
        .status_code = proxied.head.status,
        .content_length = proxied.body.size(),
        .body =
            std::string(reinterpret_cast<const char *>(proxied.body.data()), proxied.body.size()),
    };
    for (const auto &header : proxied.head.headers) {
        if (lowercase_ascii(header.name) == "content-type") {
            response.content_type = header.value;
        }
    }
    if (request.method == "HEAD") {
        response.body.clear();
    }
    return response;
}

BootstrapResponse make_bootstrap_response(const Http3BootstrapConfig &config,
                                          const BootstrapRequest &request) {
    const auto reverse_proxy_enabled = config.reverse_proxy.has_value();
    if (!bootstrap_method_is_allowed(request.method, reverse_proxy_enabled)) {
        return BootstrapResponse{
            .status_code = 405,
            .allow =
                reverse_proxy_enabled ? std::string("GET, HEAD, POST") : std::string("GET, HEAD"),
        };
    }

    if (reverse_proxy_enabled) {
        auto proxy_request = make_proxy_request(request);
        auto proxied =
            bootstrap_fetch_http_reverse_proxy_response(*config.reverse_proxy, proxy_request);
        return make_bootstrap_response_from_proxied_response(request, std::move(proxied));
    }

    const auto resolved =
        resolve_existing_bootstrap_path_under_root(config.document_root, request.target);
    if (!resolved.has_value()) {
        return BootstrapResponse{
            .status_code = 404,
        };
    }

    std::error_code status_error;
    if (!std::filesystem::exists(*resolved, status_error) ||
        !std::filesystem::is_regular_file(*resolved, status_error)) {
        return BootstrapResponse{
            .status_code = 404,
        };
    }

    std::uintmax_t file_size = 0;
    const auto &forced_file_size_failure = forced_file_size_failure_path_for_test();
    if (forced_file_size_failure.has_value() &&
        resolved->lexically_normal() == *forced_file_size_failure) {
        status_error = std::make_error_code(std::errc::io_error);
    } else {
        file_size = std::filesystem::file_size(*resolved, status_error);
    }
    if (status_error) {
        return BootstrapResponse{
            .status_code = 500,
        };
    }

    BootstrapResponse response{
        .status_code = 200,
        .content_type = content_type_for_path(*resolved),
        .content_length = file_size,
    };

    if (request.method == "GET") {
        const auto body = read_binary_file(*resolved);
        if (!body.has_value()) {
            return BootstrapResponse{
                .status_code = 500,
            };
        }
        response.body = *body;
    }

    return response;
}

bool write_all_ssl(SSL *ssl, std::string_view bytes) {
    std::size_t written = 0;
    while (written < bytes.size()) {
        const auto remaining = bytes.size() - written;
        const auto chunk_size = std::min<std::size_t>(
            remaining, static_cast<std::size_t>(std::numeric_limits<int>::max()));
        const int result =
            bootstrap_ssl_write(ssl, bytes.data() + written, static_cast<int>(chunk_size));
        if (result <= 0) {
            return false;
        }
        written += static_cast<std::size_t>(result);
    }
    return true;
}

bool write_all_ssl(SSL *ssl, std::span<const std::byte> bytes) {
    return write_all_ssl(
        ssl, std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()));
}

enum class HttpRequestReadProgress : std::uint8_t {
    incomplete,
    complete,
    invalid,
};

HttpRequestReadProgress append_http_request_bytes(std::string &request_text,
                                                  std::string_view bytes) {
    request_text.append(bytes);
    if (request_text.size() >= kBootstrapRequestLimitBytes) {
        return HttpRequestReadProgress::invalid;
    }
    const auto header_end = request_text.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return HttpRequestReadProgress::incomplete;
    }

    std::optional<std::uint64_t> content_length;
    std::size_t line_begin = request_text.find("\r\n");
    line_begin += 2;
    while (line_begin < header_end) {
        const auto line_end = request_text.find("\r\n", line_begin);
        const auto line = std::string_view(request_text).substr(line_begin, line_end - line_begin);
        const auto colon = line.find(':');
        if (colon != std::string_view::npos && colon != 0) {
            const auto name = lowercase_ascii(trim_ascii(line.substr(0, colon)));
            const auto value = trim_ascii(line.substr(colon + 1));
            if (name == "content-length") {
                const auto length = parse_size(value);
                if (!length.has_value()) {
                    return HttpRequestReadProgress::invalid;
                }
                if (content_length.has_value() && *content_length != *length) {
                    return HttpRequestReadProgress::invalid;
                }
                content_length = length;
            }
        }
        line_begin = line_end + 2;
    }

    const auto body_size = request_text.size() - (header_end + 4);
    if (!content_length.has_value()) {
        return body_size == 0 ? HttpRequestReadProgress::complete
                              : HttpRequestReadProgress::invalid;
    }
    if (*content_length > kBootstrapRequestLimitBytes) {
        return HttpRequestReadProgress::invalid;
    }
    if (body_size > *content_length) {
        return HttpRequestReadProgress::invalid;
    }
    if (body_size == *content_length) {
        return HttpRequestReadProgress::complete;
    }
    return HttpRequestReadProgress::incomplete;
}

COQUIC_NO_PROFILE bool http_request_read_is_terminal(HttpRequestReadProgress progress) {
    return progress != HttpRequestReadProgress::incomplete;
}

COQUIC_NO_PROFILE bool http_request_read_is_complete(HttpRequestReadProgress progress) {
    return progress == HttpRequestReadProgress::complete;
}

COQUIC_NO_PROFILE std::optional<std::string>
http_request_read_result(std::string request_text, HttpRequestReadProgress progress) {
    return http_request_read_is_complete(progress)
               ? std::optional<std::string>{std::move(request_text)}
               : std::nullopt;
}

template <typename ReadChunk>
std::optional<std::string> read_http_request_with_reader(ReadChunk &&read_chunk) {
    std::string request_text;
    std::array<char, 4096> buffer{};
    while (true) {
        const int read = read_chunk(buffer.data(), buffer.size());
        if (read <= 0) {
            return std::nullopt;
        }
        const auto progress = append_http_request_bytes(
            request_text, std::string_view(buffer.data(), static_cast<std::size_t>(read)));
        if (http_request_read_is_terminal(progress)) {
            return http_request_read_result(std::move(request_text), progress);
        }
    }
}

std::optional<std::string> read_http_request(SSL *ssl) {
    return read_http_request_with_reader([&](char *buffer, std::size_t buffer_size) {
        return bootstrap_ssl_read(ssl, buffer, static_cast<int>(buffer_size));
    });
}

std::string serialize_response(const Http3BootstrapConfig &config,
                               const BootstrapResponse &response) {
    std::string output = "HTTP/1.1 ";
    output += std::to_string(response.status_code);
    output.push_back(' ');
    output += reason_phrase_for_status(response.status_code);
    output += "\r\nAlt-Svc: ";
    output += make_http3_alt_svc_value(config);
    output += "\r\nConnection: close\r\nContent-Length: ";
    output += std::to_string(response.content_length);
    output += "\r\n";
    if (!response.content_type.empty()) {
        output += "Content-Type: ";
        output += response.content_type;
        output += "\r\n";
    }
    if (response.allow.has_value()) {
        output += "Allow: ";
        output += *response.allow;
        output += "\r\n";
    }
    output += "\r\n";
    output += response.body;
    return output;
}

bool write_bootstrap_response(SSL *ssl, const Http3BootstrapConfig &config,
                              const BootstrapResponse &response) {
    return write_all_ssl(ssl, serialize_response(config, response));
}

bool write_bootstrap_proxy_head(SSL *ssl, const Http3BootstrapConfig &config,
                                const Http3ResponseHead &head, bool chunked_body) {
    std::string output = "HTTP/1.1 ";
    output += std::to_string(head.status);
    output.push_back(' ');
    output += reason_phrase_for_status(head.status);
    output += "\r\nAlt-Svc: ";
    output += make_http3_alt_svc_value(config);
    output += "\r\nConnection: close\r\n";
    if (chunked_body) {
        output += "Transfer-Encoding: chunked\r\n";
    } else {
        output += "Content-Length: ";
        output += std::to_string(head.content_length.value_or(0));
        output += "\r\n";
    }
    for (const auto &header : head.headers) {
        output += header.name;
        output += ": ";
        output += header.value;
        output += "\r\n";
    }
    output += "\r\n";
    return write_all_ssl(ssl, output);
}

bool write_bootstrap_chunk(SSL *ssl, std::span<const std::byte> body) {
    if (body.empty()) {
        return true;
    }
    std::string prefix = std::to_string(body.size());
    static constexpr char kHexDigits[] = "0123456789abcdef";
    prefix.clear();
    auto value = body.size();
    do {
        prefix.push_back(kHexDigits[value & 0xfu]);
        value >>= 4u;
    } while (value != 0);
    std::reverse(prefix.begin(), prefix.end());
    prefix += "\r\n";
    return write_all_ssl(ssl, prefix) && write_all_ssl(ssl, body) && write_all_ssl(ssl, "\r\n");
}

bool stream_bootstrap_proxy_response(SSL *ssl, const Http3BootstrapConfig &config,
                                     const BootstrapRequest &request) {
    if (!bootstrap_method_is_allowed(request.method, /*reverse_proxy_enabled=*/true)) {
        return write_bootstrap_response(
            ssl, config,
            BootstrapResponse{.status_code = 405, .allow = std::string("GET, HEAD, POST")});
    }

    bool head_sent = false;
    bool chunked_body = false;
    bool ok = true;
    auto proxy_request = make_proxy_request(request);

    const Http3ReverseProxyConfig *reverse_proxy = nullptr;
    if (config.reverse_proxy.has_value()) {
        reverse_proxy = &(*config.reverse_proxy);
    }
    if (reverse_proxy == nullptr) {
        return write_bootstrap_response(ssl, config, BootstrapResponse{.status_code = 502});
    }

    bootstrap_stream_http_reverse_proxy_response(
        *reverse_proxy, proxy_request, [&](Http3ResponsePart part) {
            if (!ok) {
                return false;
            }
            if (!head_sent) {
                if (!part.head.has_value()) {
                    ok = false;
                    return false;
                }
                chunked_body = request.method != "HEAD" && !part.head->content_length.has_value() &&
                               !part.complete;
                ok = write_bootstrap_proxy_head(ssl, config, *part.head, chunked_body);
                head_sent = ok;
                if (!ok) {
                    return false;
                }
            }
            if (request.method != "HEAD") {
                if (chunked_body) {
                    ok = write_bootstrap_chunk(ssl, part.body);
                } else if (!part.body.empty()) {
                    ok = write_all_ssl(ssl, part.body);
                }
            }
            if (ok && part.complete && chunked_body) {
                ok = write_all_ssl(ssl, "0\r\n\r\n");
            }
            return ok;
        });

    if (!head_sent && ok) {
        return write_bootstrap_response(ssl, config, BootstrapResponse{.status_code = 502});
    }
    return ok;
}

void serve_bootstrap_connection(const Http3BootstrapConfig &config, SSL_CTX *ssl_context,
                                int client_fd) {
    if (!set_bootstrap_connection_timeouts(client_fd)) {
        return;
    }

    SslConnection ssl(bootstrap_ssl_new(ssl_context), &SSL_free);
    if (ssl == nullptr) {
        return;
    }

    if (bootstrap_ssl_set_fd(ssl.get(), client_fd) != 1) {
        return;
    }
    if (SSL_accept(ssl.get()) != 1) {
        return;
    }

    const auto request_text = read_http_request(ssl.get());
    if (!request_text.has_value()) {
        (void)write_bootstrap_response(ssl.get(), config, BootstrapResponse{.status_code = 400});
    } else {
        const auto request = parse_bootstrap_request(*request_text);
        if (!request.has_value()) {
            (void)write_bootstrap_response(ssl.get(), config,
                                           BootstrapResponse{.status_code = 400});
        } else if (config.reverse_proxy.has_value()) {
            (void)stream_bootstrap_proxy_response(ssl.get(), config, *request);
        } else {
            (void)write_bootstrap_response(ssl.get(), config,
                                           make_bootstrap_response(config, *request));
        }
    }

    (void)SSL_shutdown(ssl.get());
}

SslContext make_ssl_context(const Http3BootstrapConfig &config) {
    SSL_library_init();
    SSL_load_error_strings();

    SslContext context(bootstrap_ssl_ctx_new(TLS_server_method()), &SSL_CTX_free);
    if (context == nullptr) {
        return SslContext(nullptr, &SSL_CTX_free);
    }

    if (bootstrap_ssl_ctx_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1) {
        return SslContext(nullptr, &SSL_CTX_free);
    }
    if (SSL_CTX_use_certificate_chain_file(context.get(), config.certificate_chain_path.c_str()) !=
        1) {
        return SslContext(nullptr, &SSL_CTX_free);
    }
    if (SSL_CTX_use_PrivateKey_file(context.get(), config.private_key_path.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
        return SslContext(nullptr, &SSL_CTX_free);
    }
    if (bootstrap_ssl_ctx_check_private_key(context.get()) != 1) {
        return SslContext(nullptr, &SSL_CTX_free);
    }

    return context;
}

int make_listen_socket(const Http3BootstrapConfig &config) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    if (config.host.empty()) {
        hints.ai_flags |= AI_PASSIVE;
    }

    addrinfo *raw_results = nullptr;
    const auto port_text = std::to_string(config.port);
    const int lookup_result = ::getaddrinfo(config.host.empty() ? nullptr : config.host.c_str(),
                                            port_text.c_str(), &hints, &raw_results);
    if (lookup_result != 0) {
        return -1;
    }
    AddrInfo results(raw_results, &freeaddrinfo);

    for (auto *candidate = results.get(); candidate != nullptr; candidate = candidate->ai_next) {
        const int socket_fd =
            bootstrap_socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (socket_fd < 0) {
            continue;
        }
        ScopedFd socket_guard(socket_fd);

        const int reuse = 1;
        (void)::setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        if (::bind(socket_fd, candidate->ai_addr, candidate->ai_addrlen) != 0) {
            continue;
        }
        if (bootstrap_listen(socket_fd, kBootstrapListenBacklog) != 0) {
            continue;
        }
        return socket_guard.release();
    }

    return -1;
}

} // namespace

std::string make_http3_alt_svc_value(const Http3BootstrapConfig &config) {
    if (config.alt_svc_max_age == 0) {
        return "clear";
    }
    return std::string("h3=\":") + std::to_string(config.h3_port) +
           "\"; ma=" + std::to_string(config.alt_svc_max_age);
}

int run_http3_bootstrap_server(const Http3BootstrapConfig &config,
                               const std::atomic<bool> *stop_requested,
                               std::atomic<bool> *listener_ready) {
    if (listener_ready != nullptr) {
        listener_ready->store(false, std::memory_order_relaxed);
    }

    auto ssl_context = make_ssl_context(config);
    if (ssl_context == nullptr) {
        return 1;
    }

    ScopedFd listen_socket(make_listen_socket(config));
    if (listen_socket.get() < 0) {
        return 1;
    }
    if (listener_ready != nullptr) {
        listener_ready->store(true, std::memory_order_release);
    }

    while (!is_stop_requested(stop_requested)) {
        pollfd listen_poll{
            .fd = listen_socket.get(),
            .events = POLLIN,
            .revents = 0,
        };
        const int ready = bootstrap_poll(&listen_poll, 1, kBootstrapPollTimeoutMs);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 1;
        }
        if (ready == 0 || (listen_poll.revents & POLLIN) == 0) {
            continue;
        }

        const int client_fd = bootstrap_accept(listen_socket.get(), nullptr, nullptr);
        if (client_fd < 0) {
            if (is_transient_accept_errno(errno)) {
                continue;
            }
            return 1;
        }

        ScopedFd client_socket(client_fd);
        if (is_stop_requested(stop_requested)) {
            return 0;
        }
        serve_bootstrap_connection(config, ssl_context.get(), client_socket.get());
    }

    return 0;
}

bool bootstrap_scoped_fd_move_constructor_for_test() {
    int pipe_fds[2] = {-1, -1};
    if (bootstrap_pipe(pipe_fds) != 0) {
        return false;
    }

    const int original_read_fd = pipe_fds[0];
    const int original_write_fd = pipe_fds[1];
    ScopedFd read_end(pipe_fds[0]);
    ScopedFd write_end(pipe_fds[1]);
    ScopedFd moved(std::move(read_end));
    int expected_read_fd = original_read_fd;
    int expected_write_fd = original_write_fd;
    switch (bootstrap_test_hooks().move_constructor_expectation_mismatch_stage) {
    case 1:
        expected_read_fd = -1;
        break;
    case 2:
        expected_write_fd = -1;
        break;
    default:
        break;
    }
    bootstrap_test_hooks().move_constructor_expectation_mismatch_stage = 0;
    return moved.get() == expected_read_fd && write_end.get() == expected_write_fd;
}

bool bootstrap_scoped_fd_move_assignment_for_test() {
    int pipe_a[2] = {-1, -1};
    if (bootstrap_pipe(pipe_a) != 0) {
        return false;
    }
    int pipe_b[2] = {-1, -1};
    if (bootstrap_pipe(pipe_b) != 0) {
        ::close(pipe_a[0]);
        ::close(pipe_a[1]);
        return false;
    }

    const int original_source_fd = pipe_a[0];
    const int original_source_peer_fd = pipe_a[1];
    const int original_destination_peer_fd = pipe_b[1];
    ScopedFd source(pipe_a[0]);
    ScopedFd source_peer(pipe_a[1]);
    ScopedFd destination(pipe_b[0]);
    ScopedFd destination_peer(pipe_b[1]);
    destination = std::move(source);

    int expected_destination_fd = original_source_fd;
    int expected_source_peer_fd = original_source_peer_fd;
    int expected_destination_peer_fd = original_destination_peer_fd;
    switch (bootstrap_test_hooks().move_assignment_expectation_mismatch_index) {
    case 1:
        expected_destination_fd = -1;
        break;
    case 2:
        expected_source_peer_fd = -1;
        break;
    case 3:
        expected_destination_peer_fd = -1;
        break;
    default:
        break;
    }
    bootstrap_test_hooks().move_assignment_expectation_mismatch_index = 0;
    return destination.get() == expected_destination_fd &&
           source_peer.get() == expected_source_peer_fd &&
           destination_peer.get() == expected_destination_peer_fd;
}

bool bootstrap_scoped_fd_self_move_assignment_for_test() {
    int pipe_fds[2] = {-1, -1};
    if (bootstrap_pipe(pipe_fds) != 0) {
        return false;
    }

    const int original_fd = pipe_fds[0];
    const int original_peer_fd = pipe_fds[1];
    ScopedFd fd(pipe_fds[0]);
    ScopedFd peer(pipe_fds[1]);
    fd = std::move(fd);
    int expected_fd = original_fd;
    int expected_peer_fd = original_peer_fd;
    switch (bootstrap_test_hooks().self_move_expectation_mismatch_stage) {
    case 1:
        expected_fd = -1;
        break;
    case 2:
        expected_peer_fd = -1;
        break;
    default:
        break;
    }
    bootstrap_test_hooks().self_move_expectation_mismatch_stage = 0;
    return fd.get() == expected_fd && peer.get() == expected_peer_fd;
}

bool bootstrap_parse_request_for_test(std::string_view request_text) {
    return parse_bootstrap_request(request_text).has_value();
}

std::optional<std::string>
bootstrap_read_http_request_chunks_for_test(const std::vector<std::string> &chunks) {
    std::size_t chunk_index = 0;
    std::size_t chunk_offset = 0;
    return read_http_request_with_reader([&](char *buffer, std::size_t buffer_size) -> int {
        if (chunk_index >= chunks.size()) {
            return 0;
        }

        const auto &chunk = chunks[chunk_index];
        const auto remaining = chunk.size() - chunk_offset;
        const auto bytes = std::min(buffer_size, remaining);
        std::copy_n(chunk.data() + static_cast<std::ptrdiff_t>(chunk_offset), bytes, buffer);
        chunk_offset += bytes;
        if (chunk_offset == chunk.size()) {
            ++chunk_index;
            chunk_offset = 0;
        }
        return static_cast<int>(bytes);
    });
}

bool bootstrap_rejects_oversized_request_without_terminator_for_test(
    std::string_view request_text) {
    std::string buffered_request;
    std::size_t offset = 0;
    constexpr std::size_t kChunkSize = 4096;
    while (offset < request_text.size()) {
        const auto chunk_size = std::min(kChunkSize, request_text.size() - offset);
        const auto progress =
            append_http_request_bytes(buffered_request, request_text.substr(offset, chunk_size));
        if (progress == HttpRequestReadProgress::complete) {
            return false;
        }
        if (progress == HttpRequestReadProgress::invalid) {
            return true;
        }
        offset += chunk_size;
    }
    return false;
}

bool bootstrap_accept_errno_is_transient_for_test(int accept_errno) {
    return is_transient_accept_errno(accept_errno);
}

bool bootstrap_path_has_prefix_for_test(const std::filesystem::path &path,
                                        const std::filesystem::path &prefix) {
    return path_has_prefix(path, prefix);
}

std::optional<std::filesystem::path>
bootstrap_resolve_path_under_root_for_test(const std::filesystem::path &root,
                                           std::string_view request_path) {
    return resolve_bootstrap_path_under_root(root, request_path);
}

std::optional<std::filesystem::path>
bootstrap_resolve_existing_path_under_root_for_test(const std::filesystem::path &root,
                                                    std::string_view request_path) {
    return resolve_existing_bootstrap_path_under_root(root, request_path);
}

std::optional<std::string> bootstrap_read_binary_file_for_test(const std::filesystem::path &path) {
    return read_binary_file(path);
}

std::string bootstrap_content_type_for_path_for_test(const std::filesystem::path &path) {
    return content_type_for_path(path);
}

void bootstrap_set_forced_file_read_failure_path_for_test(const std::filesystem::path &path) {
    forced_read_failure_path_for_test() = path.lexically_normal();
}

void bootstrap_clear_forced_file_read_failure_path_for_test() {
    forced_read_failure_path_for_test().reset();
}

void bootstrap_set_forced_file_size_failure_path_for_test(const std::filesystem::path &path) {
    forced_file_size_failure_path_for_test() = path.lexically_normal();
}

void bootstrap_clear_forced_file_size_failure_path_for_test() {
    forced_file_size_failure_path_for_test().reset();
}

void bootstrap_check_listen_socket_failure_hook(bool &ok, const Http3BootstrapConfig &config) {
    reset_bootstrap_test_hooks();
    bootstrap_test_hooks().remaining_listen_socket_failures = 1;
    ok &= run_http3_bootstrap_server(config, nullptr) == 1;
}

void bootstrap_check_listen_failure_hook(bool &ok, const Http3BootstrapConfig &config) {
    reset_bootstrap_test_hooks();
    bootstrap_test_hooks().remaining_listen_failures = 1;
    ok &= run_http3_bootstrap_server(config, nullptr) == 1;
}

std::string bootstrap_serialize_unknown_status_response_for_test(const Http3BootstrapConfig &config,
                                                                 int status_code) {
    BootstrapResponse response{
        .status_code = status_code,
    };
    return serialize_response(config, response);
}

} // namespace coquic::http3
