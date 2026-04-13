#include "src/http3/http3_bootstrap.h"

#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <poll.h>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

namespace coquic::http3 {
namespace {

constexpr int kBootstrapListenBacklog = 16;
constexpr int kBootstrapPollTimeoutMs = 100;
constexpr std::size_t kBootstrapRequestLimitBytes = std::size_t{16} * 1024u;

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
};

struct BootstrapResponse {
    int status_code = 200;
    std::string content_type;
    std::optional<std::string> allow;
    std::uintmax_t content_length = 0;
    std::string body;
};

bool is_stop_requested(const std::atomic<bool> *stop_requested) {
    return stop_requested != nullptr && stop_requested->load(std::memory_order_relaxed);
}

std::string lowercase_ascii(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return out;
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

std::optional<std::string> read_binary_file(const std::filesystem::path &path) {
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

    return BootstrapRequest{
        .method = std::string(method),
        .target = std::string(target),
    };
}

BootstrapResponse make_bootstrap_response(const Http3BootstrapConfig &config,
                                          const BootstrapRequest &request) {
    if (request.method != "GET" && request.method != "HEAD") {
        return BootstrapResponse{
            .status_code = 405,
            .allow = std::string("GET, HEAD"),
        };
    }

    const auto resolved = resolve_bootstrap_path_under_root(config.document_root, request.target);
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

    const auto file_size = std::filesystem::file_size(*resolved, status_error);
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
        const int result = SSL_write(ssl, bytes.data() + written, static_cast<int>(chunk_size));
        if (result <= 0) {
            return false;
        }
        written += static_cast<std::size_t>(result);
    }
    return true;
}

std::optional<std::string> read_http_request(SSL *ssl) {
    std::string request_text;
    std::array<char, 4096> buffer{};
    while (request_text.size() < kBootstrapRequestLimitBytes) {
        const int read = SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()));
        if (read <= 0) {
            return std::nullopt;
        }
        request_text.append(buffer.data(), static_cast<std::size_t>(read));
        if (request_text.find("\r\n\r\n") != std::string::npos) {
            return request_text;
        }
    }
    return std::nullopt;
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

void serve_bootstrap_connection(const Http3BootstrapConfig &config, SSL_CTX *ssl_context,
                                int client_fd) {
    SslConnection ssl(SSL_new(ssl_context), &SSL_free);
    if (ssl == nullptr) {
        return;
    }

    if (SSL_set_fd(ssl.get(), client_fd) != 1) {
        return;
    }
    if (SSL_accept(ssl.get()) != 1) {
        return;
    }

    BootstrapResponse response;
    const auto request_text = read_http_request(ssl.get());
    if (!request_text.has_value()) {
        response.status_code = 400;
    } else {
        const auto request = parse_bootstrap_request(*request_text);
        if (!request.has_value()) {
            response.status_code = 400;
        } else {
            response = make_bootstrap_response(config, *request);
        }
    }

    const auto response_text = serialize_response(config, response);
    (void)write_all_ssl(ssl.get(), response_text);
    (void)SSL_shutdown(ssl.get());
}

SslContext make_ssl_context(const Http3BootstrapConfig &config) {
    SSL_library_init();
    SSL_load_error_strings();

    SslContext context(SSL_CTX_new(TLS_server_method()), &SSL_CTX_free);
    if (context == nullptr) {
        return SslContext(nullptr, &SSL_CTX_free);
    }

    if (SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1) {
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
    if (SSL_CTX_check_private_key(context.get()) != 1) {
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
            ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (socket_fd < 0) {
            continue;
        }
        ScopedFd socket_guard(socket_fd);

        const int reuse = 1;
        (void)::setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        if (::bind(socket_fd, candidate->ai_addr, candidate->ai_addrlen) != 0) {
            continue;
        }
        if (::listen(socket_fd, kBootstrapListenBacklog) != 0) {
            continue;
        }
        return socket_guard.release();
    }

    return -1;
}

} // namespace

std::string make_http3_alt_svc_value(const Http3BootstrapConfig &config) {
    return std::string("h3=\":") + std::to_string(config.h3_port) +
           "\"; ma=" + std::to_string(config.alt_svc_max_age);
}

int run_http3_bootstrap_server(const Http3BootstrapConfig &config,
                               const std::atomic<bool> *stop_requested) {
    auto ssl_context = make_ssl_context(config);
    if (ssl_context == nullptr) {
        return 1;
    }

    ScopedFd listen_socket(make_listen_socket(config));
    if (listen_socket.get() < 0) {
        return 1;
    }

    while (!is_stop_requested(stop_requested)) {
        pollfd listen_poll{
            .fd = listen_socket.get(),
            .events = POLLIN,
            .revents = 0,
        };
        const int ready = ::poll(&listen_poll, 1, kBootstrapPollTimeoutMs);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 1;
        }
        if (ready == 0 || (listen_poll.revents & POLLIN) == 0) {
            continue;
        }

        const int client_fd = ::accept(listen_socket.get(), nullptr, nullptr);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
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

} // namespace coquic::http3
