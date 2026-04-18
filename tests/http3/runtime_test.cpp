#include <gtest/gtest.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/http3/http3.h"
#include "src/http3/http3_runtime.h"
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

  private:
    int fd_ = -1;
};

class ScopedStdoutCapture {
  public:
    ScopedStdoutCapture() {
        std::fflush(stdout);
        old_stdout_fd_ = ::dup(STDOUT_FILENO);
        if (old_stdout_fd_ < 0) {
            return;
        }

        int pipe_fds[2] = {-1, -1};
        if (::pipe(pipe_fds) != 0) {
            ::close(old_stdout_fd_);
            old_stdout_fd_ = -1;
            return;
        }

        read_fd_ = pipe_fds[0];
        write_fd_ = pipe_fds[1];
        if (::dup2(write_fd_, STDOUT_FILENO) < 0) {
            ::close(read_fd_);
            ::close(write_fd_);
            ::close(old_stdout_fd_);
            read_fd_ = -1;
            write_fd_ = -1;
            old_stdout_fd_ = -1;
        }
    }

    ~ScopedStdoutCapture() {
        restore_stdout();
        if (read_fd_ >= 0) {
            ::close(read_fd_);
        }
    }

    ScopedStdoutCapture(const ScopedStdoutCapture &) = delete;
    ScopedStdoutCapture &operator=(const ScopedStdoutCapture &) = delete;

    std::string finish_and_read() {
        restore_stdout();

        std::string captured;
        if (read_fd_ < 0) {
            return captured;
        }

        std::array<char, 4096> buffer{};
        while (true) {
            const auto bytes = ::read(read_fd_, buffer.data(), buffer.size());
            if (bytes <= 0) {
                break;
            }
            captured.append(buffer.data(), static_cast<std::size_t>(bytes));
        }
        return captured;
    }

  private:
    void restore_stdout() {
        if (stdout_restored_ || old_stdout_fd_ < 0) {
            return;
        }

        std::cout.flush();
        std::fflush(stdout);
        ::dup2(old_stdout_fd_, STDOUT_FILENO);
        ::close(old_stdout_fd_);
        old_stdout_fd_ = -1;
        if (write_fd_ >= 0) {
            ::close(write_fd_);
            write_fd_ = -1;
        }
        stdout_restored_ = true;
    }

    int old_stdout_fd_ = -1;
    int read_fd_ = -1;
    int write_fd_ = -1;
    bool stdout_restored_ = false;
};

std::uint16_t allocate_udp_loopback_port() {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
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

bool udp_port_is_bound(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }
    ScopedFd socket_guard(fd);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (::bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0) {
        return false;
    }

    return errno == EADDRINUSE;
}

bool tcp_port_is_accepting(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }
    ScopedFd socket_guard(fd);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    return ::connect(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0;
}

bool wait_for_http3_server_ready(pid_t pid, const coquic::http3::Http3RuntimeConfig &config) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        const pid_t waited = ::waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            return false;
        }

        if (!udp_port_is_bound(config.port)) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
            continue;
        }

        const bool bootstrap_ready =
            !config.enable_bootstrap ||
            tcp_port_is_accepting(config.bootstrap_port == 0 ? config.port : config.bootstrap_port);
        if (bootstrap_ready) {
            return true;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return false;
}

class ScopedHttp3Process {
  public:
    explicit ScopedHttp3Process(const coquic::http3::Http3RuntimeConfig &config) {
        pid_ = ::fork();
        if (pid_ == 0) {
            _exit(coquic::http3::run_http3_runtime(config));
        }
        if (!wait_for_http3_server_ready(pid_, config)) {
            ADD_FAILURE() << "timed out waiting for HTTP/3 runtime to bind loopback listeners";
            terminate();
        }
    }

    ~ScopedHttp3Process() {
        terminate();
    }

    ScopedHttp3Process(const ScopedHttp3Process &) = delete;
    ScopedHttp3Process &operator=(const ScopedHttp3Process &) = delete;

    std::optional<int> wait_for_exit(std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            int status = 0;
            const pid_t waited = ::waitpid(pid_, &status, WNOHANG);
            if (waited == pid_) {
                pid_ = -1;
                if (WIFEXITED(status)) {
                    return WEXITSTATUS(status);
                }
                return std::nullopt;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        return std::nullopt;
    }

    void terminate() {
        if (pid_ <= 0) {
            return;
        }
        ::kill(pid_, SIGTERM);
        int status = 0;
        ::waitpid(pid_, &status, 0);
        pid_ = -1;
    }

  private:
    pid_t pid_ = -1;
};

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

TEST(QuicHttp3RuntimeTest, ParsesServerInvocation) {
    const char *argv[] = {
        "h3-server",
        "--host",
        "127.0.0.1",
        "--port",
        "9443",
        "--bootstrap-port",
        "9443",
        "--alt-svc-max-age",
        "120",
        "--document-root",
        "site",
        "--certificate-chain",
        "tests/fixtures/quic-server-cert.pem",
        "--private-key",
        "tests/fixtures/quic-server-key.pem",
    };

    const auto config = coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                               const_cast<char **>(argv));

    ASSERT_TRUE(config.has_value());
    if (!config.has_value()) {
        return;
    }
    const auto &parsed = config.value();
    EXPECT_EQ(parsed.mode, coquic::http3::Http3RuntimeMode::server);
    EXPECT_EQ(parsed.host, "127.0.0.1");
    EXPECT_EQ(parsed.port, 9443);
    EXPECT_EQ(parsed.bootstrap_port, 9443);
    EXPECT_EQ(parsed.alt_svc_max_age, 120u);
    EXPECT_EQ(parsed.document_root, std::filesystem::path("site"));
    EXPECT_EQ(parsed.certificate_chain_path,
              std::filesystem::path("tests/fixtures/quic-server-cert.pem"));
    EXPECT_EQ(parsed.private_key_path, std::filesystem::path("tests/fixtures/quic-server-key.pem"));
}

TEST(QuicHttp3RuntimeTest, ParsesClientInvocation) {
    const char *argv[] = {
        "h3-client",     "https://localhost:9443/_coquic/echo",
        "--method",      "POST",
        "--header",      "x-test: 1",
        "--header",      "content-type: text/plain",
        "--data",        "ping",
        "--output",      "reply.bin",
        "--server-name", "localhost",
    };

    const auto config = coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                               const_cast<char **>(argv));

    ASSERT_TRUE(config.has_value());
    if (!config.has_value()) {
        return;
    }
    const auto &parsed = config.value();
    EXPECT_EQ(parsed.mode, coquic::http3::Http3RuntimeMode::client);
    EXPECT_EQ(parsed.url, "https://localhost:9443/_coquic/echo");
    EXPECT_EQ(parsed.method, "POST");
    ASSERT_EQ(parsed.headers.size(), 2u);
    EXPECT_EQ(parsed.headers[0].name, "x-test");
    EXPECT_EQ(parsed.headers[0].value, "1");
    EXPECT_EQ(parsed.headers[1].name, "content-type");
    EXPECT_EQ(parsed.headers[1].value, "text/plain");
    ASSERT_TRUE(parsed.body_text.has_value());
    if (!parsed.body_text.has_value()) {
        return;
    }
    EXPECT_EQ(*parsed.body_text, "ping");
    ASSERT_TRUE(parsed.output_path.has_value());
    if (!parsed.output_path.has_value()) {
        return;
    }
    EXPECT_EQ(*parsed.output_path, std::filesystem::path("reply.bin"));
    EXPECT_EQ(parsed.server_name, "localhost");
}

TEST(QuicHttp3RuntimeTest, ParsesStandaloneServerInvocation) {
    const char *argv[] = {
        "h3-server",
        "--host",
        "127.0.0.1",
        "--port",
        "9443",
        "--bootstrap-port",
        "9443",
        "--alt-svc-max-age",
        "120",
        "--document-root",
        "site",
        "--certificate-chain",
        "tests/fixtures/quic-server-cert.pem",
        "--private-key",
        "tests/fixtures/quic-server-key.pem",
    };

    const auto config = coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                               const_cast<char **>(argv));

    ASSERT_TRUE(config.has_value());
    if (!config.has_value()) {
        return;
    }
    const auto &parsed = config.value();
    EXPECT_EQ(parsed.mode, coquic::http3::Http3RuntimeMode::server);
    EXPECT_EQ(parsed.host, "127.0.0.1");
    EXPECT_EQ(parsed.port, 9443);
    EXPECT_EQ(parsed.bootstrap_port, 9443);
    EXPECT_EQ(parsed.alt_svc_max_age, 120u);
    EXPECT_EQ(parsed.document_root, std::filesystem::path("site"));
}

TEST(QuicHttp3RuntimeTest, ParsesStandaloneClientInvocation) {
    const char *argv[] = {
        "h3-client",     "https://localhost:9443/_coquic/echo",
        "--method",      "POST",
        "--header",      "x-test: 1",
        "--data",        "ping",
        "--output",      "reply.bin",
        "--server-name", "localhost",
    };

    const auto config = coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                               const_cast<char **>(argv));

    ASSERT_TRUE(config.has_value());
    if (!config.has_value()) {
        return;
    }
    const auto &parsed = config.value();
    EXPECT_EQ(parsed.mode, coquic::http3::Http3RuntimeMode::client);
    EXPECT_EQ(parsed.url, "https://localhost:9443/_coquic/echo");
    EXPECT_EQ(parsed.method, "POST");
    ASSERT_TRUE(parsed.body_text.has_value());
    if (!parsed.body_text.has_value()) {
        return;
    }
    EXPECT_EQ(*parsed.body_text, "ping");
    ASSERT_TRUE(parsed.output_path.has_value());
    if (!parsed.output_path.has_value()) {
        return;
    }
    EXPECT_EQ(*parsed.output_path, std::filesystem::path("reply.bin"));
    EXPECT_EQ(parsed.server_name, "localhost");
}

TEST(QuicHttp3RuntimeTest, RejectsInvalidSingleDashArg) {
    const char *argv[] = {
        "h3-client",
        "https://localhost:9443/_coquic/echo",
        "-bad",
    };

    const auto config = coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                               const_cast<char **>(argv));
    EXPECT_FALSE(config.has_value());
}

TEST(QuicHttp3RuntimeTest, ServerParserRejectsClientOnlyFlag) {
    const char *argv[] = {
        "h3-server",
        "--output",
        "reply.bin",
    };

    const auto config = coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                               const_cast<char **>(argv));
    EXPECT_FALSE(config.has_value());
}

TEST(QuicHttp3RuntimeTest, ClientParserRejectsServerOnlyFlag) {
    const char *argv[] = {
        "h3-client",
        "https://localhost:9443/_coquic/echo",
        "--document-root",
        "site",
    };

    const auto config = coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                               const_cast<char **>(argv));
    EXPECT_FALSE(config.has_value());
}

TEST(QuicHttp3RuntimeTest, CoreEndpointConfigsUseH3Alpn) {
    const auto client = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:9443/hello.txt",
    };

    const auto client_core = coquic::http3::make_http3_client_endpoint_config(client);
    EXPECT_EQ(client_core.role, coquic::quic::EndpointRole::client);
    EXPECT_EQ(client_core.application_protocol,
              std::string(coquic::http3::kHttp3ApplicationProtocol));

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    const auto server_core = coquic::http3::make_http3_server_endpoint_config(server);
    ASSERT_TRUE(server_core.has_value());
    if (!server_core.has_value()) {
        return;
    }
    const auto &server_endpoint = server_core.value();
    EXPECT_EQ(server_endpoint.role, coquic::quic::EndpointRole::server);
    EXPECT_EQ(server_endpoint.application_protocol,
              std::string(coquic::http3::kHttp3ApplicationProtocol));
    ASSERT_TRUE(server_endpoint.identity.has_value());
    if (!server_endpoint.identity.has_value()) {
        return;
    }
    const auto &identity = server_endpoint.identity.value();
    EXPECT_EQ(identity.certificate_pem,
              coquic::quic::test::read_text_file("tests/fixtures/quic-server-cert.pem"));
    EXPECT_EQ(identity.private_key_pem,
              coquic::quic::test::read_text_file("tests/fixtures/quic-server-key.pem"));
}

TEST(QuicHttp3RuntimeTest, ServesStaticFileOverLoopback) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir output_root;
    document_root.write_file("hello.txt", "hello-http3");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    ScopedHttp3Process server_process(server);

    const auto client = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:" + std::to_string(port) + "/hello.txt",
        .output_path = output_root.path() / "hello.txt",
    };

    EXPECT_EQ(coquic::http3::run_http3_runtime(client), 0);
    EXPECT_EQ(coquic::quic::test::read_text_file(output_root.path() / "hello.txt"), "hello-http3");
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

TEST(QuicHttp3RuntimeTest, EchoesPostedBodyOverLoopback) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir output_root;

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    ScopedHttp3Process server_process(server);

    const auto client = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:" + std::to_string(port) + "/_coquic/echo",
        .method = "POST",
        .headers =
            {
                {
                    .name = "content-type",
                    .value = "text/plain",
                },
            },
        .body_text = "ping",
        .output_path = output_root.path() / "echo.bin",
    };

    EXPECT_EQ(coquic::http3::run_http3_runtime(client), 0);
    EXPECT_EQ(coquic::quic::test::read_text_file(output_root.path() / "echo.bin"), "ping");
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

TEST(QuicHttp3RuntimeTest, SpeedPingRouteReturnsNoBodyOverLoopback) {
    coquic::quic::test::ScopedTempDir document_root;

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    ScopedHttp3Process server_process(server);

    const auto client = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:" + std::to_string(port) + "/_coquic/speed/ping",
    };

    ScopedStdoutCapture capture;
    EXPECT_EQ(coquic::http3::run_http3_runtime(client), 0);
    EXPECT_EQ(capture.finish_and_read(), "");
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

TEST(QuicHttp3RuntimeTest, SpeedDownloadRouteWritesSizedBodyOverLoopback) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir output_root;

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    ScopedHttp3Process server_process(server);

    const auto client = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:" + std::to_string(port) + "/_coquic/speed/download?bytes=131072",
        .output_path = output_root.path() / "download.bin",
    };

    ScopedStdoutCapture capture;
    EXPECT_EQ(coquic::http3::run_http3_runtime(client), 0);
    EXPECT_EQ(capture.finish_and_read(), "");
    EXPECT_EQ(std::filesystem::file_size(output_root.path() / "download.bin"), 131072u);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

TEST(QuicHttp3RuntimeTest, SpeedUploadRouteReturnsReceivedByteSummaryOverLoopback) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir output_root;

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    ScopedHttp3Process server_process(server);

    const auto client = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:" + std::to_string(port) + "/_coquic/speed/upload",
        .method = "POST",
        .body_text = std::string(4096, 'x'),
        .output_path = output_root.path() / "upload.json",
    };

    ScopedStdoutCapture capture;
    EXPECT_EQ(coquic::http3::run_http3_runtime(client), 0);
    EXPECT_EQ(capture.finish_and_read(), "");
    EXPECT_EQ(coquic::quic::test::read_text_file(output_root.path() / "upload.json"),
              "{\"received_bytes\":4096}");
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

TEST(QuicHttp3RuntimeTest, ServesBootstrapAndHttp3FromOneServerProcess) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir output_root;
    document_root.write_file("hello.txt", "hello-http3");

    const auto h3_port = allocate_udp_loopback_port();
    ASSERT_NE(h3_port, 0);
    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = h3_port,
        .bootstrap_port = bootstrap_port,
        .alt_svc_max_age = 120,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    ScopedHttp3Process server_process(server);

    const auto bootstrap_response = https_request("127.0.0.1", bootstrap_port, "GET", "/hello.txt");
    ASSERT_TRUE(bootstrap_response.has_value());
    if (!bootstrap_response.has_value()) {
        return;
    }
    const auto &received = bootstrap_response.value();
    EXPECT_EQ(received.status_code, 200);
    EXPECT_EQ(received.body, "hello-http3");
    ASSERT_TRUE(received.headers.contains("Alt-Svc"));
    EXPECT_EQ(received.headers.at("Alt-Svc"),
              std::string("h3=\":") + std::to_string(h3_port) + "\"; ma=120");

    const auto client = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:" + std::to_string(h3_port) + "/hello.txt",
        .output_path = output_root.path() / "hello.txt",
    };

    EXPECT_EQ(coquic::http3::run_http3_runtime(client), 0);
    EXPECT_EQ(coquic::quic::test::read_text_file(output_root.path() / "hello.txt"), "hello-http3");
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

TEST(QuicHttp3RuntimeTest, ServerModeCanDisableBootstrapListener) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-http3");

    const auto h3_port = allocate_udp_loopback_port();
    ASSERT_NE(h3_port, 0);

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = h3_port,
        .enable_bootstrap = false,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    ScopedHttp3Process server_process(server);

    const auto client = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:" + std::to_string(h3_port) + "/hello.txt",
    };

    EXPECT_EQ(coquic::http3::run_http3_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

TEST(QuicHttp3RuntimeTest, ClientWithoutOutputWritesBodyToStdout) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-http3");

    const auto h3_port = allocate_udp_loopback_port();
    ASSERT_NE(h3_port, 0);

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = h3_port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    ScopedHttp3Process server_process(server);

    const auto client = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:" + std::to_string(h3_port) + "/hello.txt",
    };

    ScopedStdoutCapture stdout_capture;
    EXPECT_EQ(coquic::http3::run_http3_client(client), 0);
    EXPECT_EQ(stdout_capture.finish_and_read(), "hello-http3");
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

} // namespace
