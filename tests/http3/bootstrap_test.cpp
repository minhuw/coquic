#include <gtest/gtest.h>

#include <chrono>
#include <csignal>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <future>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/http3/http3_bootstrap.h"
#include "tests/support/quic_test_utils.h"

namespace {

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

    int get() const {
        return fd_;
    }

  private:
    int fd_ = -1;
};

std::uint16_t allocate_tcp_loopback_port() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 0;
    }
    ScopedFd socket_guard(fd);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(0);
    if (::bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        return 0;
    }

    sockaddr_in bound{};
    socklen_t bound_length = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &bound_length) != 0) {
        return 0;
    }

    return ntohs(bound.sin_port);
}

int run_bootstrap_server_guarded(const coquic::http3::Http3BootstrapConfig &config,
                                 const std::atomic<bool> *stop_requested) noexcept;

class ScopedBootstrapProcess {
  public:
    explicit ScopedBootstrapProcess(const coquic::http3::Http3BootstrapConfig &config)
        : host_(config.host), port_(config.port),
          stop_requested_(std::make_shared<std::atomic<bool>>(false)),
          future_(std::async(std::launch::async, run_bootstrap_server_guarded, config,
                             stop_requested_.get())) {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }

    ~ScopedBootstrapProcess() {
        terminate();
    }

    ScopedBootstrapProcess(const ScopedBootstrapProcess &) = delete;
    ScopedBootstrapProcess &operator=(const ScopedBootstrapProcess &) = delete;

    std::optional<int> wait_for_exit(std::chrono::milliseconds timeout) {
        if (cached_status_.has_value()) {
            return cached_status_;
        }
        if (!future_.valid()) {
            return std::nullopt;
        }
        if (future_.wait_for(timeout) != std::future_status::ready) {
            return std::nullopt;
        }
        cached_status_ = future_.get();
        return cached_status_;
    }

    void terminate() {
        if (cached_status_.has_value() || !future_.valid()) {
            return;
        }
        stop_requested_->store(true);
        wake();
        if (future_.wait_for(std::chrono::seconds{5}) == std::future_status::ready) {
            cached_status_ = future_.get();
        }
    }

  private:
    void wake() const {
        const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return;
        }
        ScopedFd socket_guard(fd);

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port_);
        if (::inet_pton(AF_INET, host_.c_str(), &address.sin_addr) != 1) {
            return;
        }
        const int connect_result =
            ::connect(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address));
        if (connect_result != 0) {
            return;
        }
    }

    std::string host_;
    std::uint16_t port_ = 0;
    std::shared_ptr<std::atomic<bool>> stop_requested_;
    std::future<int> future_;
    std::optional<int> cached_status_;
};

int run_bootstrap_server_guarded(const coquic::http3::Http3BootstrapConfig &config,
                                 const std::atomic<bool> *stop_requested) noexcept {
    try {
        return coquic::http3::run_http3_bootstrap_server(config, stop_requested);
    } catch (...) {
        return 1;
    }
}

struct SimpleHttpsResponse {
    int status_code = 0;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

std::optional<SimpleHttpsResponse> https_request(std::string_view host, std::uint16_t port,
                                                 std::string_view method, std::string_view target) {
    SSL_library_init();
    SSL_load_error_strings();

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_client_method()),
                                                          &SSL_CTX_free);
    if (ctx == nullptr) {
        return std::nullopt;
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return std::nullopt;
    }
    ScopedFd socket_guard(fd);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, std::string(host).c_str(), &address.sin_addr) != 1) {
        return std::nullopt;
    }
    if (::connect(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        return std::nullopt;
    }

    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), &SSL_free);
    if (ssl == nullptr) {
        return std::nullopt;
    }
    SSL_set_fd(ssl.get(), fd);
    SSL_set_tlsext_host_name(ssl.get(), std::string(host).c_str());
    if (SSL_connect(ssl.get()) != 1) {
        return std::nullopt;
    }

    const std::string request = std::string(method) + " " + std::string(target) +
                                " HTTP/1.1\r\nHost: " + std::string(host) +
                                "\r\nConnection: close\r\n\r\n";
    if (SSL_write(ssl.get(), request.data(), static_cast<int>(request.size())) <= 0) {
        return std::nullopt;
    }

    std::string response_text;
    std::array<char, 4096> buffer{};
    while (true) {
        const int read = SSL_read(ssl.get(), buffer.data(), static_cast<int>(buffer.size()));
        if (read <= 0) {
            break;
        }
        response_text.append(buffer.data(), static_cast<std::size_t>(read));
    }

    const auto header_end = response_text.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return std::nullopt;
    }

    SimpleHttpsResponse response;
    const auto status_end = response_text.find("\r\n");
    if (status_end == std::string::npos) {
        return std::nullopt;
    }
    const auto status_line = response_text.substr(0, status_end);
    const auto first_space = status_line.find(' ');
    if (first_space == std::string::npos) {
        return std::nullopt;
    }
    response.status_code = std::stoi(status_line.substr(first_space + 1, 3));

    std::size_t line_start = status_end + 2;
    while (line_start < header_end) {
        const auto line_end = response_text.find("\r\n", line_start);
        if (line_end == std::string::npos || line_end > header_end) {
            break;
        }
        const auto line = response_text.substr(line_start, line_end - line_start);
        const auto colon = line.find(':');
        if (colon != std::string::npos) {
            auto name = line.substr(0, colon);
            auto value = line.substr(colon + 1);
            while (!value.empty() && value.front() == ' ') {
                value.erase(value.begin());
            }
            response.headers.insert_or_assign(name, value);
        }
        line_start = line_end + 2;
    }

    response.body = response_text.substr(header_end + 4);
    return response;
}

TEST(QuicHttp3BootstrapTest, FormatsAltSvcValueFromBootstrapConfig) {
    const auto config = coquic::http3::Http3BootstrapConfig{
        .port = 4433,
        .h3_port = 4433,
        .alt_svc_max_age = 60,
    };

    EXPECT_EQ(coquic::http3::make_http3_alt_svc_value(config), "h3=\":4433\"; ma=60");
}

TEST(QuicHttp3BootstrapTest, HttpsGetServesStaticFileAndAdvertisesAltSvc) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-bootstrap");

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = coquic::http3::Http3BootstrapConfig{
        .host = "127.0.0.1",
        .port = bootstrap_port,
        .h3_port = 4433,
        .alt_svc_max_age = 60,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    ScopedBootstrapProcess server(config);
    const auto response = https_request("127.0.0.1", bootstrap_port, "GET", "/hello.txt");

    ASSERT_TRUE(response.has_value());
    if (!response.has_value()) {
        return;
    }
    const auto &received = response.value();
    EXPECT_EQ(received.status_code, 200);
    EXPECT_EQ(received.body, "hello-bootstrap");
    ASSERT_TRUE(received.headers.contains("Alt-Svc"));
    EXPECT_EQ(received.headers.at("Alt-Svc"), "h3=\":4433\"; ma=60");
}

TEST(QuicHttp3BootstrapTest, HttpsHeadSuppressesBodyButAdvertisesAltSvc) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-bootstrap");

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = coquic::http3::Http3BootstrapConfig{
        .host = "127.0.0.1",
        .port = bootstrap_port,
        .h3_port = 4433,
        .alt_svc_max_age = 60,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    ScopedBootstrapProcess server(config);
    const auto response = https_request("127.0.0.1", bootstrap_port, "HEAD", "/hello.txt");

    ASSERT_TRUE(response.has_value());
    if (!response.has_value()) {
        return;
    }
    const auto &received = response.value();
    EXPECT_EQ(received.status_code, 200);
    EXPECT_TRUE(received.body.empty());
    ASSERT_TRUE(received.headers.contains("Alt-Svc"));
    EXPECT_EQ(received.headers.at("Alt-Svc"), "h3=\":4433\"; ma=60");
    ASSERT_TRUE(received.headers.contains("Content-Length"));
    EXPECT_EQ(received.headers.at("Content-Length"), "15");
}

} // namespace
