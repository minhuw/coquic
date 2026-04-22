#include <gtest/gtest.h>

#include <chrono>
#include <csignal>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
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
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/http3/http3_bootstrap.h"
#include "tests/support/quic_test_utils.h"

namespace coquic::http3 {
bool bootstrap_scoped_fd_move_constructor_for_test();
bool bootstrap_scoped_fd_move_assignment_for_test();
bool bootstrap_scoped_fd_self_move_assignment_for_test();
bool bootstrap_parse_request_for_test(std::string_view request_text);
bool bootstrap_accept_errno_is_transient_for_test(int accept_errno);
bool bootstrap_path_has_prefix_for_test(const std::filesystem::path &path,
                                        const std::filesystem::path &prefix);
std::optional<std::filesystem::path>
bootstrap_resolve_path_under_root_for_test(const std::filesystem::path &root,
                                           std::string_view request_path);
std::optional<std::string> bootstrap_read_binary_file_for_test(const std::filesystem::path &path);
std::string bootstrap_content_type_for_path_for_test(const std::filesystem::path &path);
void bootstrap_set_forced_file_read_failure_path_for_test(const std::filesystem::path &path);
void bootstrap_clear_forced_file_read_failure_path_for_test();
void bootstrap_set_forced_file_size_failure_path_for_test(const std::filesystem::path &path);
void bootstrap_clear_forced_file_size_failure_path_for_test();
std::string bootstrap_serialize_unknown_status_response_for_test(const Http3BootstrapConfig &config,
                                                                 int status_code);
bool bootstrap_internal_coverage_for_test();
} // namespace coquic::http3

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

coquic::http3::Http3BootstrapConfig
make_bootstrap_config(const std::filesystem::path &document_root, std::uint16_t port) {
    return coquic::http3::Http3BootstrapConfig{
        .host = "127.0.0.1",
        .port = port,
        .h3_port = 4433,
        .alt_svc_max_age = 60,
        .document_root = document_root,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
}

int run_bootstrap_server_guarded(const coquic::http3::Http3BootstrapConfig &config,
                                 const std::atomic<bool> *stop_requested,
                                 std::atomic<bool> *listener_ready) noexcept;

class ScopedBootstrapProcess {
  public:
    explicit ScopedBootstrapProcess(const coquic::http3::Http3BootstrapConfig &config)
        : host_(config.host), port_(config.port), config_(config),
          thread_(&ScopedBootstrapProcess::run_server_thread, this) {
        wait_for_startup(std::chrono::seconds{5});
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
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!completed_.load()) {
            if (std::chrono::steady_clock::now() >= deadline) {
                return std::nullopt;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        if (thread_.joinable()) {
            thread_.join();
        }
        cached_status_ = exit_status_.load();
        return cached_status_;
    }

    void terminate() {
        if (cached_status_.has_value()) {
            if (thread_.joinable()) {
                thread_.join();
            }
            return;
        }
        if (!thread_.joinable()) {
            return;
        }
        stop_requested_.store(true);
        wake();
        thread_.join();
        completed_.store(true);
        cached_status_ = exit_status_.load();
    }

    bool send_signal(int signal_number) {
        return thread_.joinable() && ::pthread_kill(thread_.native_handle(), signal_number) == 0;
    }

    bool started_successfully() const {
        return started_successfully_;
    }

  private:
    static void run_server_thread(ScopedBootstrapProcess *self) noexcept {
        const int status = run_bootstrap_server_guarded(self->config_, &self->stop_requested_,
                                                        &self->listener_ready_);
        self->exit_status_.store(status);
        self->completed_.store(true);
    }

    void wait_for_startup(std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!listener_ready_.load(std::memory_order_acquire) && !completed_.load()) {
            if (std::chrono::steady_clock::now() >= deadline) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }

        started_successfully_ = listener_ready_.load(std::memory_order_acquire);
        if (started_successfully_) {
            return;
        }

        if (!completed_.load()) {
            stop_requested_.store(true);
            wake();
            if (thread_.joinable()) {
                thread_.join();
            }
            completed_.store(true);
        } else if (thread_.joinable()) {
            thread_.join();
        }
        cached_status_ = exit_status_.load();
    }

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
    coquic::http3::Http3BootstrapConfig config_;
    std::atomic<bool> stop_requested_ = false;
    std::atomic<bool> completed_ = false;
    std::atomic<bool> listener_ready_ = false;
    std::atomic<int> exit_status_ = 0;
    std::thread thread_;
    std::optional<int> cached_status_;
    bool started_successfully_ = false;
};

int run_bootstrap_server_guarded(const coquic::http3::Http3BootstrapConfig &config,
                                 const std::atomic<bool> *stop_requested,
                                 std::atomic<bool> *listener_ready) noexcept {
    try {
        return coquic::http3::run_http3_bootstrap_server(config, stop_requested, listener_ready);
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
                                                 std::string_view request_text) {
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

    if (SSL_write(ssl.get(), request_text.data(), static_cast<int>(request_text.size())) <= 0) {
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

std::optional<SimpleHttpsResponse> https_request(std::string_view host, std::uint16_t port,
                                                 std::string_view method, std::string_view target) {
    const std::string request = std::string(method) + " " + std::string(target) +
                                " HTTP/1.1\r\nHost: " + std::string(host) +
                                "\r\nConnection: close\r\n\r\n";
    return https_request(host, port, request);
}

bool https_connect_and_close(std::string_view host, std::uint16_t port) {
    SSL_library_init();
    SSL_load_error_strings();

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_client_method()),
                                                          &SSL_CTX_free);
    if (ctx == nullptr) {
        return false;
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }
    ScopedFd socket_guard(fd);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, std::string(host).c_str(), &address.sin_addr) != 1) {
        return false;
    }
    if (::connect(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        return false;
    }

    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), &SSL_free);
    if (ssl == nullptr) {
        return false;
    }
    SSL_set_fd(ssl.get(), fd);
    SSL_set_tlsext_host_name(ssl.get(), std::string(host).c_str());
    if (SSL_connect(ssl.get()) != 1) {
        return false;
    }
    (void)SSL_shutdown(ssl.get());
    return true;
}

std::string raw_tcp_request(std::string_view host, std::uint16_t port,
                            std::string_view request_text) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return {};
    }
    ScopedFd socket_guard(fd);

    timeval timeout{
        .tv_sec = 1,
        .tv_usec = 0,
    };
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, std::string(host).c_str(), &address.sin_addr) != 1) {
        return {};
    }
    if (::connect(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        return {};
    }
    if (::send(fd, request_text.data(), request_text.size(), 0) < 0) {
        return {};
    }
    (void)::shutdown(fd, SHUT_WR);

    std::string response_text;
    std::array<char, 1024> buffer{};
    while (true) {
        const ssize_t read = ::recv(fd, buffer.data(), buffer.size(), 0);
        if (read <= 0) {
            break;
        }
        response_text.append(buffer.data(), static_cast<std::size_t>(read));
    }

    return response_text;
}

bool wake_bootstrap_listener(std::string_view host, std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }
    ScopedFd socket_guard(fd);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, std::string(host).c_str(), &address.sin_addr) != 1) {
        return false;
    }
    return ::connect(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0;
}

class ScopedSignalHandler {
  public:
    explicit ScopedSignalHandler(int signal_number)
        : signal_number_(signal_number), installed_(false) {
        struct sigaction action{};
        action.sa_handler = &ScopedSignalHandler::handle_signal;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        installed_ = ::sigaction(signal_number_, &action, &previous_) == 0;
    }

    ~ScopedSignalHandler() {
        if (installed_) {
            (void)::sigaction(signal_number_, &previous_, nullptr);
        }
    }

    ScopedSignalHandler(const ScopedSignalHandler &) = delete;
    ScopedSignalHandler &operator=(const ScopedSignalHandler &) = delete;

  private:
    static void handle_signal(int) {
    }

    int signal_number_;
    bool installed_;
    struct sigaction previous_{};
};

class ScopedForcedFileReadFailure {
  public:
    explicit ScopedForcedFileReadFailure(const std::filesystem::path &path) {
        coquic::http3::bootstrap_set_forced_file_read_failure_path_for_test(path);
    }

    ~ScopedForcedFileReadFailure() {
        coquic::http3::bootstrap_clear_forced_file_read_failure_path_for_test();
    }

    ScopedForcedFileReadFailure(const ScopedForcedFileReadFailure &) = delete;
    ScopedForcedFileReadFailure &operator=(const ScopedForcedFileReadFailure &) = delete;
};

class ScopedForcedFileSizeFailure {
  public:
    explicit ScopedForcedFileSizeFailure(const std::filesystem::path &path) {
        coquic::http3::bootstrap_set_forced_file_size_failure_path_for_test(path);
    }

    ~ScopedForcedFileSizeFailure() {
        coquic::http3::bootstrap_clear_forced_file_size_failure_path_for_test();
    }

    ScopedForcedFileSizeFailure(const ScopedForcedFileSizeFailure &) = delete;
    ScopedForcedFileSizeFailure &operator=(const ScopedForcedFileSizeFailure &) = delete;
};

constexpr std::string_view kMismatchedPrivateKeyPem = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCtHe/u9TNfeq+J
lQIG5uv3uD7X6kGo1FvI2NNAMWfhdihmNIuSxWKwXxBy+Z6iZtFXMq4jG0gEXtOH
hr0/9U1mno7FtfRBL89MvvAT62NfgXS7X8hNxZlsJLIVeas14e9kj0IFHFW67yXr
UAlAinDPWs2JIseBy2vQIwdIarliAF1IpyxpqYJDbF3a/W1ZegvffcYHROUp3wIc
x+gyRXBWXwkA/hx323HS4CVESV7qiwQ4tzbfrusiqXZTBcO3qEIXFviiOHxCI+Vw
Qvg5Jyx01jV4m12bL5DN/xlXHlb15+++/h8nDDPEAOOUgEnZWKOqLCseDCxOYkcv
aaKd2bnDAgMBAAECggEAftO47PrMmT2bjpMQ+heBdmmP+MURN2vkll9rXNMVRNM4
w6/pNSzQoV/0ABeqRVZINbbWZrfc6f7Cv75RtaK0AuNUu7oS6RLqr1IPNrizg8um
xoNkjr2eKeE0apFJgl808BoYBwB8OkhsIlnvfU4vWWovvDEzsn5iTQjsk/xENmvT
c2mFHQbVMNCi++0zNy+xrlqivI116RT3g+4E6oCn/zDLqGjbZvDZvRYF/Blw1oEJ
yIoj44Fpo5pPpV1fnAjxE6425P8oknbJ3MXzU/7rO2hRhPvDQR/D9LlGIPy+j8IQ
MOOHMBKVPBDSJhUhPvzuyPKfi/uvCa7D9QOdKTsv0QKBgQDUMdIczFMC89wsCWSJ
BLrWX8NbKzftNNZ2M3oFsZvZg8uvvQmh9ITS+GuMAXFSC7y6UIjpOfZJEVpUF8Km
yAsmTGWEDk7VD3SHSw5GGI0o+O9wHZw8EsIpZ33oUVKKIPMbA4uxlkPHjVacvqih
HsrfrJsQLrft/+4XRQdtCHMK6QKBgQDQ2usBFm5CqDeuVNMgRSQVbWf4TYyuTK9Z
++z5IjiSXwo8ESJOofagfDiOTwqBm2U45+NVrHmhda6kfGbY9SJ1YVQCzgevQwZ9
NLehZsixbge/wV9puNMm5IGy5TlpAWvGaThXjAcwJXbUAh3v3bzqrIqPcw1bFgcL
merDbb2bywKBgQC0uFnCvSJV+Wsi9jzxlV2rBpRTKVPQapfcw6rA/qtFbcIkQlPZ
427cX0b5TqE8x1JNPBneyMbBJE5SIIpfkTAtxhMPjUAGpcsRDxNxD6fppVoHmrBd
WXyT1tic6+XoTne+Ih7veJLxeaayiI8F6jvOlCrcdW2g/b/BgcD5U6DnQQKBgGQH
NV6D+7L5FhHslmFyO+H3UEBgA+zG1YTnX4vClA2mbyRtoFzAvXoHhJ7DxGhmoIgs
p3i07lwiHM6yth9a6HIHd1EQlCWgmE8HHJu0upIf/J4eYzAjUR3jeyrPFjvwbknM
wytK6XZpuwu3J9dl/8D1ejdSByeE2UL5KLMIsDMZAoGAQ+stK23A3ccb9o3SkzcU
ZFctldLN95+eaCcqnR8vILsSECfctiOofyoH1n6YefmbA+Co6ax+vRXHvcF60Tt/
Kau/F5cMXFnQIj6NdsobMoUBKbIb9cg604QFSxkFxqUsYCmNq5xcVYBjQaQIjUxe
HVIEkjmpV5WKd5WM5QI3Mlo=
-----END PRIVATE KEY-----
)";

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

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);

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

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);

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

TEST(QuicHttp3BootstrapTest, HttpsGetResolvesIndexQueryAndContentTypes) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("index.html", "<h1>hello</h1>");
    document_root.write_file("data.json", "{\"ok\":true}");
    document_root.write_file("site.css", "body{}");
    document_root.write_file("app.js", "console.log('js');");
    document_root.write_file("module.mjs", "export default 1;");
    document_root.write_file("image.svg", "<svg/>");
    document_root.write_file("blob.bin", "bin");

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedBootstrapProcess server(config);

    const auto root = https_request("127.0.0.1", bootstrap_port, "GET", "/");
    ASSERT_TRUE(root.has_value());
    if (!root.has_value()) {
        return;
    }
    const auto &root_response = root.value();
    EXPECT_EQ(root_response.status_code, 200);
    EXPECT_EQ(root_response.body, "<h1>hello</h1>");
    EXPECT_EQ(root_response.headers.at("Content-Type"), "text/html; charset=utf-8");

    const auto json = https_request("127.0.0.1", bootstrap_port, "GET", "/data.json?cache=1");
    ASSERT_TRUE(json.has_value());
    if (!json.has_value()) {
        return;
    }
    const auto &json_response = json.value();
    EXPECT_EQ(json_response.status_code, 200);
    EXPECT_EQ(json_response.headers.at("Content-Type"), "application/json");

    const auto css = https_request("127.0.0.1", bootstrap_port, "GET", "/site.css");
    ASSERT_TRUE(css.has_value());
    if (!css.has_value()) {
        return;
    }
    EXPECT_EQ(css.value().headers.at("Content-Type"), "text/css; charset=utf-8");

    const auto js = https_request("127.0.0.1", bootstrap_port, "GET", "/app.js");
    ASSERT_TRUE(js.has_value());
    if (!js.has_value()) {
        return;
    }
    EXPECT_EQ(js.value().headers.at("Content-Type"), "text/javascript; charset=utf-8");

    const auto mjs = https_request("127.0.0.1", bootstrap_port, "GET", "/module.mjs");
    ASSERT_TRUE(mjs.has_value());
    if (!mjs.has_value()) {
        return;
    }
    EXPECT_EQ(mjs.value().headers.at("Content-Type"), "text/javascript; charset=utf-8");

    const auto svg = https_request("127.0.0.1", bootstrap_port, "GET", "/image.svg");
    ASSERT_TRUE(svg.has_value());
    if (!svg.has_value()) {
        return;
    }
    EXPECT_EQ(svg.value().headers.at("Content-Type"), "image/svg+xml");

    const auto bin = https_request("127.0.0.1", bootstrap_port, "GET", "/blob.bin");
    ASSERT_TRUE(bin.has_value());
    if (!bin.has_value()) {
        return;
    }
    EXPECT_EQ(bin.value().headers.at("Content-Type"), "application/octet-stream");
}

TEST(QuicHttp3BootstrapTest, HttpsGetReturnsNotFoundForRejectedOrUnavailableTargets) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-bootstrap");
    ASSERT_TRUE(std::filesystem::create_directory(document_root.path() / "folder"));

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedBootstrapProcess server(config);

    const auto traversal = https_request("127.0.0.1", bootstrap_port, "GET", "/../hello.txt");
    ASSERT_TRUE(traversal.has_value());
    if (!traversal.has_value()) {
        return;
    }
    EXPECT_EQ(traversal.value().status_code, 404);

    const auto absolute_like = https_request("127.0.0.1", bootstrap_port, "GET", "//hello.txt");
    ASSERT_TRUE(absolute_like.has_value());
    if (!absolute_like.has_value()) {
        return;
    }
    EXPECT_EQ(absolute_like.value().status_code, 404);

    const auto missing = https_request("127.0.0.1", bootstrap_port, "GET", "/missing.txt");
    ASSERT_TRUE(missing.has_value());
    if (!missing.has_value()) {
        return;
    }
    EXPECT_EQ(missing.value().status_code, 404);

    const auto directory = https_request("127.0.0.1", bootstrap_port, "GET", "/folder");
    ASSERT_TRUE(directory.has_value());
    if (!directory.has_value()) {
        return;
    }
    EXPECT_EQ(directory.value().status_code, 404);
}

TEST(QuicHttp3BootstrapTest, HttpsGetReturnsInternalServerErrorForForcedFileReadFailure) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("secret.txt", "hidden");
    const auto unreadable_path = document_root.path() / "secret.txt";
    ScopedForcedFileReadFailure forced_failure(unreadable_path);

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedBootstrapProcess server(config);
    const auto response = https_request("127.0.0.1", bootstrap_port, "GET", "/secret.txt");

    ASSERT_TRUE(response.has_value());
    if (!response.has_value()) {
        return;
    }
    EXPECT_EQ(response.value().status_code, 500);
}

TEST(QuicHttp3BootstrapTest, HttpsGetReturnsInternalServerErrorForForcedFileSizeFailure) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("secret.txt", "hidden");
    const auto failing_path = document_root.path() / "secret.txt";
    ScopedForcedFileSizeFailure forced_failure(failing_path);

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedBootstrapProcess server(config);
    const auto response = https_request("127.0.0.1", bootstrap_port, "GET", "/secret.txt");

    ASSERT_TRUE(response.has_value());
    if (!response.has_value()) {
        return;
    }
    EXPECT_EQ(response.value().status_code, 500);
}

TEST(QuicHttp3BootstrapTest, HttpsHeadIgnoresForcedFileSizeFailureForOtherPaths) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("secret.txt", "hidden");
    document_root.write_file("other.txt", "other");
    const auto unrelated_path = document_root.path() / "other.txt";
    ScopedForcedFileSizeFailure forced_failure(unrelated_path);

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedBootstrapProcess server(config);
    const auto response = https_request("127.0.0.1", bootstrap_port, "HEAD", "/secret.txt");

    ASSERT_TRUE(response.has_value());
    if (!response.has_value()) {
        return;
    }
    EXPECT_EQ(response.value().status_code, 200);
    EXPECT_TRUE(response.value().body.empty());
    ASSERT_TRUE(response.value().headers.contains("Content-Length"));
    EXPECT_EQ(response.value().headers.at("Content-Length"), "6");
}

TEST(QuicHttp3BootstrapTest, HttpsPostReturnsMethodNotAllowedAndAllowHeader) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-bootstrap");

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedBootstrapProcess server(config);
    const auto response = https_request("127.0.0.1", bootstrap_port, "POST", "/hello.txt");

    ASSERT_TRUE(response.has_value());
    if (!response.has_value()) {
        return;
    }
    const auto &received = response.value();
    EXPECT_EQ(received.status_code, 405);
    EXPECT_TRUE(received.body.empty());
    ASSERT_TRUE(received.headers.contains("Allow"));
    EXPECT_EQ(received.headers.at("Allow"), "GET, HEAD");
}

TEST(QuicHttp3BootstrapTest, HttpsMalformedRequestsReturnBadRequest) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("index.html", "<h1>hello</h1>");

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedBootstrapProcess server(config);

    const auto merged_request_line_and_header = https_request(
        "127.0.0.1", bootstrap_port, "GET / HTTP/1.1Host: example\r\nConnection: close\r\n\r\n");
    ASSERT_TRUE(merged_request_line_and_header.has_value());
    if (!merged_request_line_and_header.has_value()) {
        return;
    }
    EXPECT_EQ(merged_request_line_and_header.value().status_code, 400);

    const auto missing_method = https_request(
        "127.0.0.1", bootstrap_port, " / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n");
    ASSERT_TRUE(missing_method.has_value());
    if (!missing_method.has_value()) {
        return;
    }
    EXPECT_EQ(missing_method.value().status_code, 400);

    const auto missing_target = https_request(
        "127.0.0.1", bootstrap_port, "GET  HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n");
    ASSERT_TRUE(missing_target.has_value());
    if (!missing_target.has_value()) {
        return;
    }
    EXPECT_EQ(missing_target.value().status_code, 400);

    const auto bad_version =
        https_request("127.0.0.1", bootstrap_port,
                      "GET / HTTP/2.0\r\nHost: example\r\nConnection: close\r\n\r\n");
    ASSERT_TRUE(bad_version.has_value());
    if (!bad_version.has_value()) {
        return;
    }
    EXPECT_EQ(bad_version.value().status_code, 400);
}

TEST(QuicHttp3BootstrapTest, HttpsOversizedRequestWithoutTerminatorReturnsBadRequest) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("index.html", "<h1>hello</h1>");

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedBootstrapProcess server(config);
    ASSERT_TRUE(server.started_successfully());

    std::string oversized_request = "GET / HTTP/1.1\r\nHost: example\r\nX-Fill: ";
    oversized_request.append(static_cast<std::string::size_type>(17u * 1024u), 'a');

    const auto response = https_request("127.0.0.1", bootstrap_port, oversized_request);
    ASSERT_TRUE(response.has_value());
    if (!response.has_value()) {
        return;
    }
    EXPECT_EQ(response.value().status_code, 400);
}

TEST(QuicHttp3BootstrapTest, ScopedBootstrapProcessReportsImmediateStartupFailure) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("index.html", "<h1>hello</h1>");

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const int occupied_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(occupied_fd, 0);
    ScopedFd occupied_socket(occupied_fd);

    const int reuse = 1;
    ASSERT_EQ(::setsockopt(occupied_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)), 0);

    sockaddr_in occupied_address{};
    occupied_address.sin_family = AF_INET;
    occupied_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    occupied_address.sin_port = htons(bootstrap_port);
    ASSERT_EQ(::bind(occupied_fd, reinterpret_cast<const sockaddr *>(&occupied_address),
                     sizeof(occupied_address)),
              0);
    ASSERT_EQ(::listen(occupied_fd, 1), 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedBootstrapProcess server(config);
    EXPECT_FALSE(server.started_successfully());

    const auto exit_status = server.wait_for_exit(std::chrono::milliseconds{0});
    EXPECT_EQ(exit_status, std::optional<int>{1});
}

TEST(QuicHttp3BootstrapTest, RawTcpClientFailsTlsAcceptAndServerKeepsServing) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-bootstrap");

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedBootstrapProcess server(config);

    const auto raw_response =
        raw_tcp_request("127.0.0.1", bootstrap_port,
                        "GET /hello.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    EXPECT_NE(raw_response.rfind("HTTP/1.1 ", 0), 0U);

    const auto response = https_request("127.0.0.1", bootstrap_port, "GET", "/hello.txt");
    ASSERT_TRUE(response.has_value());
    if (!response.has_value()) {
        return;
    }
    EXPECT_EQ(response.value().status_code, 200);
    EXPECT_EQ(response.value().body, "hello-bootstrap");
}

TEST(QuicHttp3BootstrapTest, TlsClientWithoutRequestKeepsServerServing) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-bootstrap");
    ScopedSignalHandler signal_handler(SIGPIPE);

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedBootstrapProcess server(config);
    ASSERT_TRUE(https_connect_and_close("127.0.0.1", bootstrap_port));

    const auto response = https_request("127.0.0.1", bootstrap_port, "GET", "/hello.txt");
    ASSERT_TRUE(response.has_value());
    if (!response.has_value()) {
        return;
    }
    EXPECT_EQ(response.value().status_code, 200);
    EXPECT_EQ(response.value().body, "hello-bootstrap");
}

TEST(QuicHttp3BootstrapTest, EmptyHostUsesPassiveWildcardBinding) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-bootstrap");

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    config.host.clear();

    ScopedBootstrapProcess server(config);
    const auto response = https_request("127.0.0.1", bootstrap_port, "GET", "/hello.txt");

    ASSERT_TRUE(response.has_value());
    if (!response.has_value()) {
        return;
    }
    EXPECT_EQ(response.value().status_code, 200);
    EXPECT_EQ(response.value().body, "hello-bootstrap");
}

TEST(QuicHttp3BootstrapTest, InvalidHostReturnsFailure) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-bootstrap");

    auto config = make_bootstrap_config(document_root.path(), 443);
    config.host = "bad host name";

    EXPECT_EQ(coquic::http3::run_http3_bootstrap_server(config), 1);
}

TEST(QuicHttp3BootstrapTest, TestHooksCoverBootstrapPathReadAndContentTypeColdBranches) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("legacy.htm", "legacy");

    EXPECT_TRUE(coquic::http3::bootstrap_path_has_prefix_for_test(
        document_root.path() / "legacy.htm", document_root.path()));
    EXPECT_FALSE(coquic::http3::bootstrap_path_has_prefix_for_test(
        document_root.path(), document_root.path() / "legacy.htm"));
    EXPECT_FALSE(coquic::http3::bootstrap_path_has_prefix_for_test(document_root.path(),
                                                                   document_root.path() / "other"));
    EXPECT_FALSE(coquic::http3::bootstrap_path_has_prefix_for_test(
        document_root.path() / "legacy.htm", document_root.path() / "other"));
    EXPECT_FALSE(coquic::http3::bootstrap_resolve_path_under_root_for_test(document_root.path(), "")
                     .has_value());
    EXPECT_FALSE(coquic::http3::bootstrap_resolve_path_under_root_for_test(document_root.path(),
                                                                           "legacy.htm")
                     .has_value());
    EXPECT_FALSE(coquic::http3::bootstrap_resolve_path_under_root_for_test(document_root.path(),
                                                                           "/./legacy.htm")
                     .has_value());
    const auto resolved = coquic::http3::bootstrap_resolve_path_under_root_for_test(
        document_root.path(), "/legacy.htm");
    if (!resolved.has_value()) {
        FAIL() << "expected resolved document path";
        return;
    }
    EXPECT_EQ(*resolved, document_root.path() / "legacy.htm");
    EXPECT_FALSE(
        coquic::http3::bootstrap_read_binary_file_for_test(document_root.path() / "missing.txt")
            .has_value());
    EXPECT_EQ(coquic::http3::bootstrap_content_type_for_path_for_test(document_root.path() /
                                                                      "legacy.htm"),
              "text/html; charset=utf-8");
}

TEST(QuicHttp3BootstrapTest, InvalidCertificateChainReturnsFailure) {

    coquic::quic::test::ScopedTempDir document_root;
    const auto config = coquic::http3::Http3BootstrapConfig{
        .document_root = document_root.path(),
        .certificate_chain_path = document_root.path() / "missing-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::http3::run_http3_bootstrap_server(config), 1);
}

TEST(QuicHttp3BootstrapTest, InvalidPrivateKeyReturnsFailure) {
    coquic::quic::test::ScopedTempDir document_root;
    const auto config = coquic::http3::Http3BootstrapConfig{
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = document_root.path() / "missing-key.pem",
    };

    EXPECT_EQ(coquic::http3::run_http3_bootstrap_server(config), 1);
}

TEST(QuicHttp3BootstrapTest, MismatchedPrivateKeyReturnsFailure) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("mismatched-key.pem", std::string(kMismatchedPrivateKeyPem));

    const auto config = coquic::http3::Http3BootstrapConfig{
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = document_root.path() / "mismatched-key.pem",
    };

    EXPECT_EQ(coquic::http3::run_http3_bootstrap_server(config), 1);
}

TEST(QuicHttp3BootstrapTest, StopRequestedWakeupExitsCleanly) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("index.html", "<h1>hello</h1>");

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    std::atomic<bool> stop_requested = false;
    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    auto future = std::async(std::launch::async, run_bootstrap_server_guarded, config,
                             &stop_requested, nullptr);

    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    stop_requested.store(true);
    ASSERT_TRUE(wake_bootstrap_listener("127.0.0.1", bootstrap_port));

    ASSERT_EQ(future.wait_for(std::chrono::seconds{5}), std::future_status::ready);
    EXPECT_EQ(future.get(), 0);
}

TEST(QuicHttp3BootstrapTest, PollEintrKeepsServingRequests) {
    coquic::quic::test::ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello-bootstrap");

    const auto bootstrap_port = allocate_tcp_loopback_port();
    ASSERT_NE(bootstrap_port, 0);

    const auto config = make_bootstrap_config(document_root.path(), bootstrap_port);
    ScopedSignalHandler signal_handler(SIGUSR1);
    ScopedBootstrapProcess server(config);
    ASSERT_TRUE(server.send_signal(SIGUSR1));
    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    const auto response = https_request("127.0.0.1", bootstrap_port, "GET", "/hello.txt");
    ASSERT_TRUE(response.has_value());
    if (!response.has_value()) {
        return;
    }
    EXPECT_EQ(response.value().status_code, 200);
    EXPECT_EQ(response.value().body, "hello-bootstrap");

    server.terminate();
    const auto exit_status = server.wait_for_exit(std::chrono::seconds{5});
    ASSERT_TRUE(exit_status.has_value());
    if (!exit_status.has_value()) {
        return;
    }
    EXPECT_EQ(*exit_status, 0);
}

TEST(QuicHttp3BootstrapTest, TestHookExercisesScopedFdMoveOperations) {
    EXPECT_TRUE(coquic::http3::bootstrap_scoped_fd_move_constructor_for_test());
    EXPECT_TRUE(coquic::http3::bootstrap_scoped_fd_move_assignment_for_test());
    EXPECT_TRUE(coquic::http3::bootstrap_scoped_fd_self_move_assignment_for_test());
}

TEST(QuicHttp3BootstrapTest, TestHookRejectsRequestWithoutRequestLineTerminator) {
    EXPECT_FALSE(coquic::http3::bootstrap_parse_request_for_test("GET / HTTP/1.1"));
}

TEST(QuicHttp3BootstrapTest, AcceptErrnoTransientClassificationMatchesBootstrapRetryRules) {
    EXPECT_TRUE(coquic::http3::bootstrap_accept_errno_is_transient_for_test(EINTR));
    EXPECT_TRUE(coquic::http3::bootstrap_accept_errno_is_transient_for_test(EAGAIN));
    EXPECT_TRUE(coquic::http3::bootstrap_accept_errno_is_transient_for_test(EWOULDBLOCK));
    EXPECT_FALSE(coquic::http3::bootstrap_accept_errno_is_transient_for_test(EMFILE));
}

TEST(QuicHttp3BootstrapTest, TestHooksCoverAdditionalRequestParsingAndFailureBranches) {
    EXPECT_FALSE(coquic::http3::bootstrap_parse_request_for_test("GET/HTTP/1.1\r\n\r\n"));
    EXPECT_FALSE(coquic::http3::bootstrap_parse_request_for_test("GET /\r\n\r\n"));
    EXPECT_TRUE(coquic::http3::bootstrap_parse_request_for_test("GET / HTTP/1.0\r\n\r\n"));
    EXPECT_TRUE(coquic::http3::bootstrap_internal_coverage_for_test());
}

TEST(QuicHttp3BootstrapTest, TestHookSerializesUnknownStatusWithFallbackReasonPhrase) {
    const auto config = coquic::http3::Http3BootstrapConfig{
        .h3_port = 8443,
        .alt_svc_max_age = 120,
    };

    const auto response_text =
        coquic::http3::bootstrap_serialize_unknown_status_response_for_test(config, 599);
    EXPECT_NE(response_text.find("HTTP/1.1 599 Error\r\n"), std::string::npos);
    EXPECT_NE(response_text.find("Alt-Svc: h3=\":8443\"; ma=120\r\n"), std::string::npos);
    EXPECT_NE(response_text.find("Content-Length: 0\r\n"), std::string::npos);
}

} // namespace
