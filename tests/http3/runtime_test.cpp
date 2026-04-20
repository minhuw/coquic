#include <gtest/gtest.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <future>
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
#include "src/io/io_backend_factory.h"
#include "tests/support/quic_test_utils.h"

namespace coquic::http3 {
Http3Response runtime_server_response_for_test(const std::filesystem::path &document_root,
                                               const Http3Request &request);
void runtime_set_forced_file_read_failure_path_for_test(const std::filesystem::path &path);
void runtime_clear_forced_file_read_failure_path_for_test();
std::optional<std::vector<std::byte>>
runtime_load_request_body_for_test(const Http3RuntimeConfig &config);
bool runtime_make_client_execution_plan_for_test(const Http3RuntimeConfig &config,
                                                 std::string_view url);
bool runtime_make_client_transfer_plans_for_test(const Http3RuntimeConfig &config,
                                                 std::span<const Http3RuntimeTransferJob> jobs);
bool runtime_misc_internal_coverage_for_test();
bool runtime_loop_internal_coverage_for_test();
std::uint64_t runtime_loop_internal_coverage_mask_for_test();
std::uint64_t runtime_connection_handle_effect_coverage_mask_for_test();
bool runtime_additional_internal_coverage_for_test();
bool runtime_tail_internal_coverage_for_test();
void runtime_set_force_bootstrap_guard_failure_for_test(bool enabled);
void runtime_set_forced_server_endpoint_config_for_test(
    std::optional<coquic::quic::QuicCoreEndpointConfig> endpoint);
void runtime_set_forced_server_bootstrap_for_test(
    std::optional<coquic::io::QuicServerIoBootstrap> bootstrap);
int finish_http3_server_run(int runtime_exit_code,
                            std::optional<std::future<int>> &bootstrap_result,
                            std::optional<std::thread> &bootstrap_thread,
                            std::atomic<bool> &bootstrap_stop_requested);
} // namespace coquic::http3

namespace {

class ScopedEnvVar {
  public:
    ScopedEnvVar(std::string name, std::optional<std::string> value) : name_(std::move(name)) {
        if (const char *existing = std::getenv(name_.c_str()); existing != nullptr) {
            previous_ = std::string(existing);
            had_previous_ = true;
        }
        if (value.has_value()) {
            EXPECT_EQ(::setenv(name_.c_str(), value->c_str(), 1), 0);
        } else {
            EXPECT_EQ(::unsetenv(name_.c_str()), 0);
        }
    }

    ~ScopedEnvVar() {
        if (had_previous_) {
            ::setenv(name_.c_str(), previous_.c_str(), 1);
            return;
        }
        ::unsetenv(name_.c_str());
    }

    ScopedEnvVar(const ScopedEnvVar &) = delete;
    ScopedEnvVar &operator=(const ScopedEnvVar &) = delete;

  private:
    std::string name_;
    std::string previous_;
    bool had_previous_ = false;
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

  private:
    int fd_ = -1;
};

class ScopedTcpLoopbackListener {
  public:
    explicit ScopedTcpLoopbackListener(std::uint16_t port) {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) {
            return;
        }

        const int enable = 1;
        if (::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
            ::close(fd_);
            fd_ = -1;
            return;
        }

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        if (::bind(fd_, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
            ::close(fd_);
            fd_ = -1;
            return;
        }

        if (::listen(fd_, 1) != 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    ~ScopedTcpLoopbackListener() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    ScopedTcpLoopbackListener(const ScopedTcpLoopbackListener &) = delete;
    ScopedTcpLoopbackListener &operator=(const ScopedTcpLoopbackListener &) = delete;

    bool ready() const {
        return fd_ >= 0;
    }

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

class ScriptedIoBackend final : public coquic::io::QuicIoBackend {
  public:
    std::optional<coquic::quic::QuicRouteHandle>
    ensure_route(const coquic::io::QuicIoRemote &) override {
        return 1;
    }

    std::optional<coquic::io::QuicIoEvent>
    wait(std::optional<coquic::quic::QuicCoreTimePoint>) override {
        if (wait_index_ >= wait_results.size()) {
            return std::nullopt;
        }
        return std::move(wait_results[wait_index_++]);
    }

    bool send(const coquic::io::QuicIoTxDatagram &) override {
        return true;
    }

    std::vector<std::optional<coquic::io::QuicIoEvent>> wait_results;

  private:
    std::size_t wait_index_ = 0;
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

std::vector<std::byte> bytes_from_text(std::string_view text) {
    return std::vector<std::byte>(reinterpret_cast<const std::byte *>(text.data()),
                                  reinterpret_cast<const std::byte *>(text.data()) + text.size());
}

class ScopedForcedFileReadFailure {
  public:
    explicit ScopedForcedFileReadFailure(const std::filesystem::path &path) {
        coquic::http3::runtime_set_forced_file_read_failure_path_for_test(path);
    }

    ~ScopedForcedFileReadFailure() {
        coquic::http3::runtime_clear_forced_file_read_failure_path_for_test();
    }

    ScopedForcedFileReadFailure(const ScopedForcedFileReadFailure &) = delete;
    ScopedForcedFileReadFailure &operator=(const ScopedForcedFileReadFailure &) = delete;
};

std::optional<std::string_view> find_header_value(const coquic::http3::Http3Headers &headers,
                                                  std::string_view name) {
    for (const auto &header : headers) {
        if (header.name == name) {
            return header.value;
        }
    }
    return std::nullopt;
}

void expect_header_value(const coquic::http3::Http3ResponseHead &head,
                         std::pair<std::string_view, std::string_view> expected_header) {
    const auto value = find_header_value(head.headers, expected_header.first);
    ASSERT_TRUE(value.has_value());
    if (!value.has_value()) {
        return;
    }
    EXPECT_EQ(value.value(), expected_header.second);
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

TEST(QuicHttp3RuntimeTest, ParsersAcceptVerifyPeerAndIoBackendSelections) {
    {
        const char *argv[] = {
            "h3-server", "--host", "127.0.0.1", "--port", "9443", "--io-backend", "socket",
        };
        const auto config = coquic::http3::parse_http3_server_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(config.has_value());
        if (!config.has_value()) {
            return;
        }
        EXPECT_EQ(config->io_backend, coquic::io::QuicIoBackendKind::socket);
    }

    {
        const char *argv[] = {
            "h3-client", "https://localhost:9443/_coquic/echo", "--verify-peer", "--io-backend",
            "io_uring",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(config.has_value());
        if (!config.has_value()) {
            return;
        }
        EXPECT_TRUE(config->verify_peer);
        EXPECT_EQ(config->io_backend, coquic::io::QuicIoBackendKind::io_uring);
    }
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

TEST(QuicHttp3RuntimeTest, ServerParserRejectsMalformedNumericAndBackendValues) {
    {
        const char *argv[] = {
            "h3-server",
            "--port",
            "abc",
        };
        const auto config = coquic::http3::parse_http3_server_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-server",
            "--bootstrap-port",
            "99999",
        };
        const auto config = coquic::http3::parse_http3_server_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-server",
            "--alt-svc-max-age",
            "-1",
        };
        const auto config = coquic::http3::parse_http3_server_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-server",
            "--io-backend",
            "epoll",
        };
        const auto config = coquic::http3::parse_http3_server_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }
}

TEST(QuicHttp3RuntimeTest, ParsersRejectMissingOptionValuesAndRepeatedUrls) {
    {
        const char *argv[] = {"h3-server", "--host"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--port"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--bootstrap-port"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--alt-svc-max-age"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--io-backend"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--document-root"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--certificate-chain"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--private-key"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }

    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--method"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--header"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--data"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--body-file"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--output"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--server-name"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {
            "h3-client",
            "https://localhost:9443/first",
            "https://localhost:9443/second",
        };
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
}

TEST(QuicHttp3RuntimeTest, ParsersRejectWrongModeFlagsUnknownOptionsAndEmptyArgv) {
    EXPECT_FALSE(coquic::http3::parse_http3_server_args(0, nullptr).has_value());
    EXPECT_FALSE(coquic::http3::parse_http3_client_args(0, nullptr).has_value());

    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--bootstrap-port", "9444"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--alt-svc-max-age", "60"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--certificate-chain",
                              "cert.pem"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--private-key", "key.pem"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--document-root", "site"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }

    {
        const char *argv[] = {"h3-server", "--method", "GET"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--header", "x-test: 1"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--data", "inline"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--body-file", "body.bin"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--output", "reply.bin"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-server", "--server-name", "localhost"};
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }

    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "--bogus"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
    {
        const char *argv[] = {"h3-client", "https://localhost:9443/ok", "-"};
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
}

TEST(QuicHttp3RuntimeTest, ClientParserRejectsMalformedHeadersAndUrls) {
    {
        const char *argv[] = {
            "h3-client",
            "https://localhost:9443/ok",
            "--header",
            "x-no-colon",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "https://localhost:9443/ok",
            "--header",
            ":value",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "https://localhost:9443/ok",
            "--header",
            "x-empty: ",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "https://localhost:9443/ok",
            "--header",
            ":path: /",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "https://localhost:9443/ok",
            "--header",
            "content-length: 1",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "https://localhost:9443/ok",
            "--header",
            "transfer-encoding: chunked",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "http://localhost:9443/ok",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "https:///ok",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "https://[::1",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "https://[]:443",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }
}

TEST(QuicHttp3RuntimeTest, ClientParserAcceptsBodyFileAndRejectsBodySourceConflicts) {
    {
        coquic::quic::test::ScopedTempDir body_root;
        body_root.write_file("body.bin", "payload");
        const auto body_path = body_root.path() / "body.bin";
        const auto body_path_text = body_path.string();
        const char *argv[] = {
            "h3-client",
            "https://localhost:9443/upload",
            "--body-file",
            body_path_text.c_str(),
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(config.has_value());
        if (!config.has_value()) {
            return;
        }
        const auto parsed_body_path = config->body_file_path;
        ASSERT_TRUE(parsed_body_path.has_value());
        if (!parsed_body_path.has_value()) {
            return;
        }
        EXPECT_EQ(*parsed_body_path, body_path);
        EXPECT_FALSE(config->body_text.has_value());
    }

    {
        const char *argv[] = {
            "h3-client", "https://localhost:9443/upload", "--data", "inline", "--body-file",
            "body.bin",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client", "https://localhost:9443/upload", "--body-file", "body.bin", "--data",
            "inline",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }
}

TEST(QuicHttp3RuntimeTest, ClientParserAcceptsIpv6AndPortAuthorities) {
    {
        const char *argv[] = {
            "h3-client",
            "https://[::1]:9443/ok",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "https://localhost:8443/ok",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "https://localhost:9443?x=1",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(config.has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "https://localhost:9443/#section",
        };
        const auto config = coquic::http3::parse_http3_client_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(config.has_value());
    }
}

TEST(QuicHttp3RuntimeTest, ParsersRejectAdditionalArgumentEdgeCases) {
    {
        const char *argv[] = {
            "h3-server",
            "--port",
            "65536",
        };
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }

    {
        const char *argv[] = {
            "h3-server",
            "--bootstrap-port",
            "abc",
        };
        EXPECT_FALSE(coquic::http3::parse_http3_server_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
        };
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }

    {
        const char *argv[] = {
            "h3-client",
            "",
        };
        EXPECT_FALSE(coquic::http3::parse_http3_client_args(static_cast<int>(std::size(argv)),
                                                            const_cast<char **>(argv))
                         .has_value());
    }
}

TEST(QuicHttp3RuntimeTest, RuntimeLoadRequestBodyHandlesConflictsEmptyAndFileInputs) {
    {
        coquic::quic::test::ScopedTempDir body_root;
        body_root.write_file("body.txt", "payload");
        const auto config = coquic::http3::Http3RuntimeConfig{
            .mode = coquic::http3::Http3RuntimeMode::client,
            .body_text = "inline",
            .body_file_path = body_root.path() / "body.txt",
        };
        EXPECT_FALSE(coquic::http3::runtime_load_request_body_for_test(config).has_value());
    }

    {
        const auto config = coquic::http3::Http3RuntimeConfig{
            .mode = coquic::http3::Http3RuntimeMode::client,
        };
        const auto body = coquic::http3::runtime_load_request_body_for_test(config);
        ASSERT_TRUE(body.has_value());
        if (!body.has_value()) {
            return;
        }
        EXPECT_TRUE(body->empty());
    }

    {
        coquic::quic::test::ScopedTempDir body_root;
        body_root.write_file("body.txt", "file-payload");
        const auto config = coquic::http3::Http3RuntimeConfig{
            .mode = coquic::http3::Http3RuntimeMode::client,
            .body_file_path = body_root.path() / "body.txt",
        };
        const auto body = coquic::http3::runtime_load_request_body_for_test(config);
        ASSERT_TRUE(body.has_value());
        if (!body.has_value()) {
            return;
        }
        EXPECT_EQ(*body, bytes_from_text("file-payload"));
    }
}

TEST(QuicHttp3RuntimeTest, RuntimeLoadRequestBodyRejectsMissingBodyFile) {
    const auto config = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .body_file_path = "tests/fixtures/does-not-exist-body.bin",
    };
    EXPECT_FALSE(coquic::http3::runtime_load_request_body_for_test(config).has_value());
}

TEST(QuicHttp3RuntimeTest, RuntimeExecutionPlanRejectsInvalidMethodUrlAndBodySources) {
    {
        const auto config = coquic::http3::Http3RuntimeConfig{
            .mode = coquic::http3::Http3RuntimeMode::client,
            .method = "PUT",
            .url = "https://localhost:9443/ok",
        };
        EXPECT_FALSE(
            coquic::http3::runtime_make_client_execution_plan_for_test(config, config.url));
    }

    {
        const auto config = coquic::http3::Http3RuntimeConfig{
            .mode = coquic::http3::Http3RuntimeMode::client,
            .method = "HEAD",
            .body_text = "not-allowed",
            .url = "https://localhost:9443/ok",
        };
        EXPECT_FALSE(
            coquic::http3::runtime_make_client_execution_plan_for_test(config, config.url));
    }

    {
        const auto config = coquic::http3::Http3RuntimeConfig{
            .mode = coquic::http3::Http3RuntimeMode::client,
            .url = "https:///missing-host",
        };
        EXPECT_FALSE(
            coquic::http3::runtime_make_client_execution_plan_for_test(config, config.url));
    }

    {
        coquic::quic::test::ScopedTempDir body_root;
        body_root.write_file("body.txt", "payload");
        const auto config = coquic::http3::Http3RuntimeConfig{
            .mode = coquic::http3::Http3RuntimeMode::client,
            .body_text = "inline",
            .body_file_path = body_root.path() / "body.txt",
            .url = "https://localhost:9443/ok",
        };
        EXPECT_FALSE(
            coquic::http3::runtime_make_client_execution_plan_for_test(config, config.url));
    }
}

TEST(QuicHttp3RuntimeTest, RuntimeTransferPlansRejectInvalidJobSets) {
    const auto config = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
    };

    {
        const std::array<coquic::http3::Http3RuntimeTransferJob, 0> jobs{};
        EXPECT_FALSE(coquic::http3::runtime_make_client_transfer_plans_for_test(config, jobs));
    }

    {
        const std::array jobs{coquic::http3::Http3RuntimeTransferJob{
            .url = "",
            .output_path = "out.bin",
        }};
        EXPECT_FALSE(coquic::http3::runtime_make_client_transfer_plans_for_test(config, jobs));
    }

    {
        const std::array jobs{coquic::http3::Http3RuntimeTransferJob{
            .url = "https://localhost:9443/ok",
            .output_path = "",
        }};
        EXPECT_FALSE(coquic::http3::runtime_make_client_transfer_plans_for_test(config, jobs));
    }

    {
        const std::array jobs{coquic::http3::Http3RuntimeTransferJob{
            .url = "https:///missing-host",
            .output_path = "out.bin",
        }};
        EXPECT_FALSE(coquic::http3::runtime_make_client_transfer_plans_for_test(config, jobs));
    }

    {
        const std::array jobs{
            coquic::http3::Http3RuntimeTransferJob{
                .url = "https://localhost:9443/a",
                .output_path = "a.bin",
            },
            coquic::http3::Http3RuntimeTransferJob{
                .url = "https://localhost:9444/b",
                .output_path = "b.bin",
            },
        };
        EXPECT_FALSE(coquic::http3::runtime_make_client_transfer_plans_for_test(config, jobs));
    }
}

TEST(QuicHttp3RuntimeTest, RuntimeParserDispatchesServerAndClientSubcommands) {
    {
        const char *argv[] = {
            "coquic-http3", "h3-server", "--host", "127.0.0.1", "--port", "9555",
        };
        const auto config = coquic::http3::parse_http3_runtime_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(config.has_value());
        if (!config.has_value()) {
            return;
        }
        EXPECT_EQ(config->mode, coquic::http3::Http3RuntimeMode::server);
        EXPECT_EQ(config->host, "127.0.0.1");
        EXPECT_EQ(config->port, 9555);
    }

    {
        const char *argv[] = {
            "coquic-http3",  "h3-client", "https://localhost:9443/ok", "--method", "HEAD",
            "--server-name", "localhost",
        };
        const auto config = coquic::http3::parse_http3_runtime_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(config.has_value());
        if (!config.has_value()) {
            return;
        }
        EXPECT_EQ(config->mode, coquic::http3::Http3RuntimeMode::client);
        EXPECT_EQ(config->url, "https://localhost:9443/ok");
        EXPECT_EQ(config->method, "HEAD");
        EXPECT_EQ(config->server_name, "localhost");
    }
}

TEST(QuicHttp3RuntimeTest, RuntimeParserRejectsMissingAndUnsupportedSubcommands) {
    {
        const char *argv[] = {"coquic-http3"};
        const auto config = coquic::http3::parse_http3_runtime_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }

    {
        const char *argv[] = {"coquic-http3", "h3-proxy"};
        const auto config = coquic::http3::parse_http3_runtime_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(config.has_value());
    }
}

TEST(QuicHttp3RuntimeTest, RuntimeMiscInternalCoverageHookReturnsTrue) {
    EXPECT_TRUE(coquic::http3::runtime_misc_internal_coverage_for_test());
}

TEST(QuicHttp3RuntimeTest, RuntimeLoopInternalCoverageHookReturnsTrue) {
    EXPECT_TRUE(coquic::http3::runtime_loop_internal_coverage_for_test());
}

TEST(QuicHttp3RuntimeTest, RuntimeLoopInternalCoverageMaskIncludesScriptedBranches) {
    constexpr std::uint64_t kExpectedMask = (1ull << 0) | (1ull << 1) | (1ull << 2) | (1ull << 3) |
                                            (1ull << 4) | (1ull << 5) | (1ull << 6) | (1ull << 7) |
                                            (1ull << 8) | (1ull << 9) | (1ull << 10);
    EXPECT_EQ(coquic::http3::runtime_loop_internal_coverage_mask_for_test(), kExpectedMask);
}

TEST(QuicHttp3RuntimeTest, RuntimeConnectionHandleCoverageMaskIncludesEventEffects) {
    constexpr std::uint64_t kExpectedMask =
        (1ull << 0) | (1ull << 1) | (1ull << 2) | (1ull << 3) | (1ull << 4) | (1ull << 5);
    EXPECT_EQ(coquic::http3::runtime_connection_handle_effect_coverage_mask_for_test(),
              kExpectedMask);
}

TEST(QuicHttp3RuntimeTest, RuntimeAdditionalInternalCoverageHookReturnsTrue) {
    EXPECT_TRUE(coquic::http3::runtime_additional_internal_coverage_for_test());
}

TEST(QuicHttp3RuntimeTest, RuntimeTailInternalCoverageHookReturnsTrue) {
    EXPECT_TRUE(coquic::http3::runtime_tail_internal_coverage_for_test());
}

TEST(QuicHttp3RuntimeTest, ServerEndpointConfigRejectsUnreadableIdentityFiles) {
    const auto base = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    {
        auto config = base;
        config.certificate_chain_path = "tests/fixtures/does-not-exist-cert.pem";
        EXPECT_FALSE(coquic::http3::make_http3_server_endpoint_config(config).has_value());
    }

    {
        auto config = base;
        config.private_key_path = "tests/fixtures/does-not-exist-key.pem";
        EXPECT_FALSE(coquic::http3::make_http3_server_endpoint_config(config).has_value());
    }
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

TEST(QuicHttp3RuntimeTest, RunHttp3ServerFailsWhenBootstrapPortAlreadyInUse) {
    coquic::quic::test::ScopedTempDir document_root;
    const auto h3_port = allocate_udp_loopback_port();
    ASSERT_NE(h3_port, 0);
    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    ScopedTcpLoopbackListener occupied_listener(bootstrap_port);
    ASSERT_TRUE(occupied_listener.ready());

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = h3_port,
        .bootstrap_port = bootstrap_port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_NE(coquic::http3::run_http3_server(server), 0);
}

TEST(QuicHttp3RuntimeTest, RunHttp3ServerFailsWhenIdentityOrUdpBootstrapSetupIsInvalid) {
    {
        coquic::quic::test::ScopedTempDir document_root;
        const auto h3_port = allocate_udp_loopback_port();
        ASSERT_NE(h3_port, 0);

        const auto server = coquic::http3::Http3RuntimeConfig{
            .mode = coquic::http3::Http3RuntimeMode::server,
            .host = "127.0.0.1",
            .port = h3_port,
            .document_root = document_root.path(),
            .certificate_chain_path = "tests/fixtures/does-not-exist-cert.pem",
            .private_key_path = "tests/fixtures/quic-server-key.pem",
        };

        EXPECT_NE(coquic::http3::run_http3_server(server), 0);
    }

    {
        coquic::quic::test::ScopedTempDir document_root;
        const auto h3_port = allocate_udp_loopback_port();
        ASSERT_NE(h3_port, 0);

        const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT_GE(fd, 0);
        ScopedFd occupied_socket(fd);

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(h3_port);
        ASSERT_EQ(::bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)), 0);

        const auto server = coquic::http3::Http3RuntimeConfig{
            .mode = coquic::http3::Http3RuntimeMode::server,
            .host = "127.0.0.1",
            .port = h3_port,
            .document_root = document_root.path(),
            .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
            .private_key_path = "tests/fixtures/quic-server-key.pem",
        };

        EXPECT_NE(coquic::http3::run_http3_server(server), 0);
    }
}

TEST(QuicHttp3RuntimeTest, FinishHttp3ServerRunHandlesMissingAndInvalidBootstrapResults) {
    {
        std::packaged_task<int()> bootstrap_task([] { return 7; });
        std::optional<std::future<int>> bootstrap_result;
        std::optional<std::thread> bootstrap_thread(std::move(bootstrap_task));
        std::atomic<bool> bootstrap_stop_requested = false;

        EXPECT_EQ(coquic::http3::finish_http3_server_run(4, bootstrap_result, bootstrap_thread,
                                                         bootstrap_stop_requested),
                  4);
        EXPECT_TRUE(bootstrap_stop_requested.load(std::memory_order_relaxed));
    }

    {
        std::packaged_task<int()> bootstrap_task([] { return 8; });
        std::optional<std::future<int>> bootstrap_result(bootstrap_task.get_future());
        std::optional<std::thread> bootstrap_thread(std::move(bootstrap_task));
        ASSERT_TRUE(bootstrap_result->valid());
        bootstrap_result->wait();
        EXPECT_EQ(bootstrap_result->get(), 8);
        EXPECT_FALSE(bootstrap_result->valid());

        std::atomic<bool> bootstrap_stop_requested = false;
        EXPECT_EQ(coquic::http3::finish_http3_server_run(6, bootstrap_result, bootstrap_thread,
                                                         bootstrap_stop_requested),
                  6);
        EXPECT_TRUE(bootstrap_stop_requested.load(std::memory_order_relaxed));
    }
}

TEST(QuicHttp3RuntimeTest, RunHttp3ServerReturnsImmediateBootstrapFailureBeforeRuntimeStarts) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-http3");

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 4433,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    const auto endpoint = coquic::http3::make_http3_server_endpoint_config(server);
    ASSERT_TRUE(endpoint.has_value());
    if (!endpoint.has_value()) {
        return;
    }

    coquic::http3::runtime_set_force_bootstrap_guard_failure_for_test(true);
    coquic::http3::runtime_set_forced_server_endpoint_config_for_test(endpoint);
    coquic::http3::runtime_set_forced_server_bootstrap_for_test(coquic::io::QuicServerIoBootstrap{
        .backend = std::make_unique<ScriptedIoBackend>(),
    });

    EXPECT_EQ(coquic::http3::run_http3_server(server), 1);
    coquic::http3::runtime_set_force_bootstrap_guard_failure_for_test(false);
}

TEST(QuicHttp3RuntimeTest, RunHttp3RuntimeUsesServerPathInProcess) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-http3");

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 4433,
        .enable_bootstrap = false,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    const auto endpoint = coquic::http3::make_http3_server_endpoint_config(server);
    ASSERT_TRUE(endpoint.has_value());
    if (!endpoint.has_value()) {
        return;
    }

    auto backend = std::make_unique<ScriptedIoBackend>();
    backend->wait_results.push_back(std::nullopt);
    coquic::http3::runtime_set_forced_server_endpoint_config_for_test(endpoint);
    coquic::http3::runtime_set_forced_server_bootstrap_for_test(coquic::io::QuicServerIoBootstrap{
        .backend = std::move(backend),
    });

    EXPECT_EQ(coquic::http3::run_http3_runtime(server), 1);
}

TEST(QuicHttp3RuntimeTest, RunHttp3ClientTransfersRejectsInvalidPlans) {
    const auto config = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:9443/ok",
    };

    {
        const std::array<coquic::http3::Http3RuntimeTransferJob, 0> jobs{};
        EXPECT_NE(coquic::http3::run_http3_client_transfers(config, jobs), 0);
    }

    {
        const std::array jobs{
            coquic::http3::Http3RuntimeTransferJob{
                .url = "https://localhost:9443/a",
                .output_path = "a.bin",
            },
            coquic::http3::Http3RuntimeTransferJob{
                .url = "https://localhost:9444/b",
                .output_path = "b.bin",
            },
        };
        EXPECT_NE(coquic::http3::run_http3_client_transfers(config, jobs), 0);
    }
}

TEST(QuicHttp3RuntimeTest, RunHttp3ClientTransfersFailsWhenBootstrapCannotResolvePeer) {
    const auto config = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://256.256.256.256:9443/ok",
    };
    const std::array jobs{coquic::http3::Http3RuntimeTransferJob{
        .url = config.url,
        .output_path = "out.bin",
    }};
    EXPECT_NE(coquic::http3::run_http3_client_transfers(config, jobs), 0);
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

TEST(QuicHttp3RuntimeTest, HeadClientWithoutOutputReturnsSuccessWithEmptyStdout) {
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
        .method = "HEAD",
    };

    ScopedStdoutCapture stdout_capture;
    EXPECT_EQ(coquic::http3::run_http3_client(client), 0);
    EXPECT_TRUE(stdout_capture.finish_and_read().empty());
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

TEST(QuicHttp3RuntimeTest, ClientReturnsFailureWhenOutputPathIsDirectory) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir output_root;
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
        .output_path = output_root.path(),
    };

    EXPECT_NE(coquic::http3::run_http3_client(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

TEST(QuicHttp3RuntimeTest, ClientReturnsFailureWhenTemporaryOutputDisappearsBeforeReadback) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir temp_root;
    document_root.write_file("large.txt", std::string(1 << 20, 'x'));

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
    ScopedEnvVar tmpdir("TMPDIR", temp_root.path().string());

    std::atomic<bool> stop_requested = false;
    std::thread remover([&] {
        while (!stop_requested.load(std::memory_order_relaxed)) {
            for (const auto &entry : std::filesystem::directory_iterator(temp_root.path())) {
                if (!entry.is_regular_file()) {
                    continue;
                }
                if (!entry.path().filename().string().starts_with("coquic-h3-client-")) {
                    continue;
                }
                std::error_code ignored;
                std::filesystem::remove(entry.path(), ignored);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    });

    const auto client = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::client,
        .url = "https://localhost:" + std::to_string(h3_port) + "/large.txt",
    };

    EXPECT_NE(coquic::http3::run_http3_client(client), 0);
    stop_requested.store(true, std::memory_order_relaxed);
    remover.join();
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

TEST(QuicHttp3RuntimeTest, RuntimeServerResponseCoversPathAndMimeBranches) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("index.html", "<h1>home</h1>");
    document_root.write_file("plain.txt", "plain");
    document_root.write_file("payload.json", "{\"ok\":true}");
    document_root.write_file("style.css", "body{}");
    document_root.write_file("app.js", "console.log('js')");
    document_root.write_file("module.mjs", "export const value = 1;");
    document_root.write_file("vector.svg", "<svg></svg>");
    document_root.write_file("blob.bin", "\x01\x02");
    document_root.write_file("secret.txt", "hidden");

    const auto request = [](std::string method, std::string path) {
        return coquic::http3::Http3Request{
            .head =
                {
                    .method = std::move(method),
                    .path = std::move(path),
                },
        };
    };

    auto root_get =
        coquic::http3::runtime_server_response_for_test(document_root.path(), request("GET", "/"));
    EXPECT_EQ(root_get.head.status, 200);
    EXPECT_EQ(root_get.body, bytes_from_text("<h1>home</h1>"));
    expect_header_value(root_get.head, {"content-type", "text/html; charset=utf-8"});

    auto query_get = coquic::http3::runtime_server_response_for_test(
        document_root.path(), request("GET", "/plain.txt?x=1"));
    EXPECT_EQ(query_get.head.status, 200);
    EXPECT_EQ(query_get.body, bytes_from_text("plain"));
    expect_header_value(query_get.head, {"content-type", "text/plain; charset=utf-8"});

    auto head = coquic::http3::runtime_server_response_for_test(document_root.path(),
                                                                request("HEAD", "/payload.json"));
    EXPECT_EQ(head.head.status, 200);
    EXPECT_TRUE(head.body.empty());
    expect_header_value(head.head, {"content-type", "application/json"});

    auto css = coquic::http3::runtime_server_response_for_test(document_root.path(),
                                                               request("GET", "/style.css"));
    EXPECT_EQ(css.head.status, 200);
    expect_header_value(css.head, {"content-type", "text/css; charset=utf-8"});

    auto js = coquic::http3::runtime_server_response_for_test(document_root.path(),
                                                              request("GET", "/app.js"));
    EXPECT_EQ(js.head.status, 200);
    expect_header_value(js.head, {"content-type", "text/javascript; charset=utf-8"});

    auto mjs = coquic::http3::runtime_server_response_for_test(document_root.path(),
                                                               request("GET", "/module.mjs"));
    EXPECT_EQ(mjs.head.status, 200);
    expect_header_value(mjs.head, {"content-type", "text/javascript; charset=utf-8"});

    auto svg = coquic::http3::runtime_server_response_for_test(document_root.path(),
                                                               request("GET", "/vector.svg"));
    EXPECT_EQ(svg.head.status, 200);
    expect_header_value(svg.head, {"content-type", "image/svg+xml"});

    auto bin = coquic::http3::runtime_server_response_for_test(document_root.path(),
                                                               request("GET", "/blob.bin"));
    EXPECT_EQ(bin.head.status, 200);
    expect_header_value(bin.head, {"content-type", "application/octet-stream"});

    auto missing = coquic::http3::runtime_server_response_for_test(document_root.path(),
                                                                   request("GET", "/missing.txt"));
    EXPECT_EQ(missing.head.status, 404);

    auto traversal = coquic::http3::runtime_server_response_for_test(
        document_root.path(), request("GET", "/../secret.txt"));
    EXPECT_EQ(traversal.head.status, 404);

    auto double_slash = coquic::http3::runtime_server_response_for_test(
        document_root.path(), request("GET", "//secret.txt"));
    EXPECT_EQ(double_slash.head.status, 404);

    ScopedForcedFileReadFailure force_read_failure(
        (document_root.path() / "secret.txt").lexically_normal());
    auto unreadable = coquic::http3::runtime_server_response_for_test(
        document_root.path(), request("GET", "/secret.txt"));
    EXPECT_EQ(unreadable.head.status, 500);
}

TEST(QuicHttp3RuntimeTest, RuntimeInspectRouteSupportsPost) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir output_root;
    document_root.write_file("index.html", "<h1>home</h1>");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .enable_bootstrap = false,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    ScopedHttp3Process server_process(server);

    {
        const auto inspect_client = coquic::http3::Http3RuntimeConfig{
            .mode = coquic::http3::Http3RuntimeMode::client,
            .url = "https://localhost:" + std::to_string(port) + "/_coquic/inspect",
            .method = "POST",
            .body_text = "ping",
            .output_path = output_root.path() / "inspect.json",
        };
        EXPECT_EQ(coquic::http3::run_http3_runtime(inspect_client), 0);
        const auto inspect_body =
            coquic::quic::test::read_text_file(output_root.path() / "inspect.json");
        EXPECT_NE(inspect_body.find("\"method\":\"POST\""), std::string::npos);
        EXPECT_NE(inspect_body.find("\"body_bytes\":4"), std::string::npos);
    }

    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds{200}).has_value());
}

TEST(QuicHttp3RuntimeTest, RuntimeServerResponseCoversSpecialRoutes) {
    coquic::quic::test::ScopedTempDir document_root;
    const auto request = [](std::string method, std::string path, std::string_view body = "") {
        return coquic::http3::Http3Request{
            .head =
                {
                    .method = std::move(method),
                    .path = std::move(path),
                },
            .body = bytes_from_text(body),
        };
    };

    const auto echo_get = coquic::http3::runtime_server_response_for_test(
        document_root.path(), request("GET", "/_coquic/echo"));
    EXPECT_EQ(echo_get.head.status, 405);
    expect_header_value(echo_get.head, {"allow", "POST"});

    const auto echo_post = coquic::http3::runtime_server_response_for_test(
        document_root.path(), request("POST", "/_coquic/echo", "ping"));
    EXPECT_EQ(echo_post.head.status, 200);
    EXPECT_EQ(echo_post.body, bytes_from_text("ping"));

    const auto inspect_get = coquic::http3::runtime_server_response_for_test(
        document_root.path(), request("GET", "/_coquic/inspect"));
    EXPECT_EQ(inspect_get.head.status, 405);
    expect_header_value(inspect_get.head, {"allow", "POST"});

    const auto inspect_post = coquic::http3::runtime_server_response_for_test(
        document_root.path(), request("POST", "/_coquic/inspect", "ping"));
    EXPECT_EQ(inspect_post.head.status, 200);
    expect_header_value(inspect_post.head, {"content-type", "application/json"});
    const std::string inspect_body(reinterpret_cast<const char *>(inspect_post.body.data()),
                                   inspect_post.body.size());
    EXPECT_NE(inspect_body.find("\"method\":\"POST\""), std::string::npos);
    EXPECT_NE(inspect_body.find("\"body_bytes\":4"), std::string::npos);
}

} // namespace
