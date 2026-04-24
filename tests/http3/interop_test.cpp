#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <netinet/in.h>
#include <optional>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "src/http3/http3_interop.h"
#include "src/http3/http3_runtime.h"
#include "tests/support/core/connection_test_fixtures.h"
#include "tests/support/quic_test_utils.h"

namespace {

using coquic::quic::test::ScopedTempDir;
using coquic::quic::test_support::optional_ref_or_terminate;
using coquic::quic::test_support::ScopedEnvVar;

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

} // namespace

TEST(QuicHttp3InteropTest, ParsesServerInvocationFromEnvironment) {
    const char *argv[] = {"coquic", "h3-interop-server"};
    ScopedEnvVar testcase("TESTCASE", "http3");
    ScopedEnvVar host("HOST", "0.0.0.0");
    ScopedEnvVar port("PORT", "443");
    ScopedEnvVar document_root("DOCUMENT_ROOT", "/www");
    ScopedEnvVar certificate_chain("CERTIFICATE_CHAIN_PATH", "/certs/cert.pem");
    ScopedEnvVar private_key("PRIVATE_KEY_PATH", "/certs/priv.key");

    const auto parsed = coquic::http3::parse_http3_interop_args(2, const_cast<char **>(argv));

    ASSERT_TRUE(parsed.has_value());
    const auto &config = optional_ref_or_terminate(parsed);
    EXPECT_EQ(config.mode, coquic::http3::Http3InteropMode::server);
    EXPECT_EQ(config.testcase, "http3");
    EXPECT_EQ(config.host, "0.0.0.0");
    EXPECT_EQ(config.port, 443);
    EXPECT_EQ(config.document_root, std::filesystem::path("/www"));
    EXPECT_EQ(config.certificate_chain_path, std::filesystem::path("/certs/cert.pem"));
    EXPECT_EQ(config.private_key_path, std::filesystem::path("/certs/priv.key"));
}

TEST(QuicHttp3InteropTest, UnsupportedTestcaseReturnsRunnerSkipExitCode) {
    const auto config = coquic::http3::Http3InteropConfig{
        .mode = coquic::http3::Http3InteropMode::server,
        .testcase = "transfer",
    };

    EXPECT_EQ(coquic::http3::run_http3_interop(config), 127);
}

TEST(QuicHttp3InteropTest, ParsesClientInvocationWithRequestsFromEnvironment) {
    const char *argv[] = {"coquic", "h3-interop-client"};
    ScopedEnvVar testcase("TESTCASE", "http3");
    ScopedEnvVar host("HOST", "127.0.0.1");
    ScopedEnvVar port("PORT", "443");
    ScopedEnvVar server_name("SERVER_NAME", "localhost");
    ScopedEnvVar download_root("DOWNLOAD_ROOT", "/downloads");
    ScopedEnvVar requests("REQUESTS", "https://server/a.txt https://server/b.txt");

    const auto parsed = coquic::http3::parse_http3_interop_args(2, const_cast<char **>(argv));

    ASSERT_TRUE(parsed.has_value());
    const auto &config = optional_ref_or_terminate(parsed);
    EXPECT_EQ(config.mode, coquic::http3::Http3InteropMode::client);
    EXPECT_EQ(config.testcase, "http3");
    EXPECT_EQ(config.host, "127.0.0.1");
    EXPECT_EQ(config.port, 443);
    EXPECT_EQ(config.server_name, "localhost");
    EXPECT_EQ(config.download_root, std::filesystem::path("/downloads"));
    ASSERT_EQ(config.requests.size(), 2u);
    EXPECT_EQ(config.requests[0], "https://server/a.txt");
    EXPECT_EQ(config.requests[1], "https://server/b.txt");
}

TEST(QuicHttp3InteropTest, RejectsClientInvocationWithoutRequests) {
    const char *argv[] = {"coquic", "h3-interop-client"};
    ScopedEnvVar testcase("TESTCASE", "http3");
    ScopedEnvVar requests("REQUESTS", std::nullopt);

    const auto missing_requests =
        coquic::http3::parse_http3_interop_args(2, const_cast<char **>(argv));
    EXPECT_FALSE(missing_requests.has_value());

    ScopedEnvVar whitespace_requests("REQUESTS", "   ");
    const auto empty_requests =
        coquic::http3::parse_http3_interop_args(2, const_cast<char **>(argv));
    EXPECT_FALSE(empty_requests.has_value());
}

TEST(QuicHttp3InteropTest, ParsesAndRejectsCongestionControlFromEnvironment) {
    const char *argv[] = {"coquic", "h3-interop-client"};
    ScopedEnvVar testcase("TESTCASE", "http3");
    ScopedEnvVar requests("REQUESTS", "https://server/a.txt");

    {
        ScopedEnvVar congestion_control("COQUIC_CONGESTION_CONTROL", "bbr");
        const auto parsed = coquic::http3::parse_http3_interop_args(2, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(optional_ref_or_terminate(parsed).congestion_control,
                  coquic::quic::QuicCongestionControlAlgorithm::bbr);
    }

    {
        ScopedEnvVar congestion_control("COQUIC_CONGESTION_CONTROL", "cubic");
        EXPECT_FALSE(
            coquic::http3::parse_http3_interop_args(2, const_cast<char **>(argv)).has_value());
    }
}

TEST(QuicHttp3InteropTest, RejectsMissingAndUnknownInteropSubcommands) {
    const char *missing_subcommand_argv[] = {"coquic"};
    EXPECT_FALSE(
        coquic::http3::parse_http3_interop_args(1, const_cast<char **>(missing_subcommand_argv))
            .has_value());

    const char *unknown_subcommand_argv[] = {"coquic", "h3-interop-runner"};
    EXPECT_FALSE(
        coquic::http3::parse_http3_interop_args(2, const_cast<char **>(unknown_subcommand_argv))
            .has_value());
}

TEST(QuicHttp3InteropTest, RejectsInvalidPortValuesFromEnvironment) {
    const char *argv[] = {"coquic", "h3-interop-client"};
    ScopedEnvVar requests("REQUESTS", "https://server.example/a.txt");

    for (const char *invalid_port : {"", "abc", "443extra", "0", "65536"}) {
        ScopedEnvVar port("PORT", std::string(invalid_port));
        EXPECT_FALSE(
            coquic::http3::parse_http3_interop_args(2, const_cast<char **>(argv)).has_value())
            << "PORT=" << invalid_port;
    }
}

TEST(QuicHttp3InteropTest, RejectsServerInvocationWhenRequiredEnvironmentIsMissingOrEmpty) {
    const char *argv[] = {"coquic", "h3-interop-server"};
    struct ServerEnvironment {
        std::optional<std::string> testcase;
        std::optional<std::string> host;
        std::optional<std::string> port;
        std::optional<std::string> document_root;
        std::optional<std::string> certificate_chain_path;
        std::optional<std::string> private_key_path;
    };
    const auto parse_server = [&](const ServerEnvironment &environment) {
        ScopedEnvVar testcase_env("TESTCASE", environment.testcase);
        ScopedEnvVar host_env("HOST", environment.host);
        ScopedEnvVar port_env("PORT", environment.port);
        ScopedEnvVar document_root_env("DOCUMENT_ROOT", environment.document_root);
        ScopedEnvVar certificate_chain_env("CERTIFICATE_CHAIN_PATH",
                                           environment.certificate_chain_path);
        ScopedEnvVar private_key_env("PRIVATE_KEY_PATH", environment.private_key_path);
        return coquic::http3::parse_http3_interop_args(2, const_cast<char **>(argv));
    };

    EXPECT_FALSE(parse_server(ServerEnvironment{
                                  .host = "127.0.0.1",
                                  .port = "443",
                                  .document_root = "/www",
                                  .certificate_chain_path = "/certs/cert.pem",
                                  .private_key_path = "/certs/key.pem",
                              })
                     .has_value());
    EXPECT_FALSE(parse_server(ServerEnvironment{
                                  .testcase = "http3",
                                  .port = "443",
                                  .document_root = "/www",
                                  .certificate_chain_path = "/certs/cert.pem",
                                  .private_key_path = "/certs/key.pem",
                              })
                     .has_value());
    EXPECT_FALSE(parse_server(ServerEnvironment{
                                  .testcase = "http3",
                                  .host = "127.0.0.1",
                                  .document_root = "/www",
                                  .certificate_chain_path = "/certs/cert.pem",
                                  .private_key_path = "/certs/key.pem",
                              })
                     .has_value());
    EXPECT_FALSE(parse_server(ServerEnvironment{
                                  .testcase = "http3",
                                  .host = "127.0.0.1",
                                  .port = "443",
                                  .certificate_chain_path = "/certs/cert.pem",
                                  .private_key_path = "/certs/key.pem",
                              })
                     .has_value());
    EXPECT_FALSE(parse_server(ServerEnvironment{
                                  .testcase = "http3",
                                  .host = "127.0.0.1",
                                  .port = "443",
                                  .document_root = "/www",
                                  .private_key_path = "/certs/key.pem",
                              })
                     .has_value());
    EXPECT_FALSE(parse_server(ServerEnvironment{
                                  .testcase = "http3",
                                  .host = "127.0.0.1",
                                  .port = "443",
                                  .document_root = "/www",
                                  .certificate_chain_path = "/certs/cert.pem",
                              })
                     .has_value());
    EXPECT_FALSE(parse_server(ServerEnvironment{
                                  .testcase = "",
                                  .host = "127.0.0.1",
                                  .port = "443",
                                  .document_root = "/www",
                                  .certificate_chain_path = "/certs/cert.pem",
                                  .private_key_path = "/certs/key.pem",
                              })
                     .has_value());
    EXPECT_FALSE(parse_server(ServerEnvironment{
                                  .testcase = "http3",
                                  .host = "",
                                  .port = "443",
                                  .document_root = "/www",
                                  .certificate_chain_path = "/certs/cert.pem",
                                  .private_key_path = "/certs/key.pem",
                              })
                     .has_value());
    EXPECT_FALSE(parse_server(ServerEnvironment{
                                  .testcase = "http3",
                                  .host = "127.0.0.1",
                                  .port = "443",
                                  .document_root = "",
                                  .certificate_chain_path = "/certs/cert.pem",
                                  .private_key_path = "/certs/key.pem",
                              })
                     .has_value());
    EXPECT_FALSE(parse_server(ServerEnvironment{
                                  .testcase = "http3",
                                  .host = "127.0.0.1",
                                  .port = "443",
                                  .document_root = "/www",
                                  .certificate_chain_path = "",
                                  .private_key_path = "/certs/key.pem",
                              })
                     .has_value());
    EXPECT_FALSE(parse_server(ServerEnvironment{
                                  .testcase = "http3",
                                  .host = "127.0.0.1",
                                  .port = "443",
                                  .document_root = "/www",
                                  .certificate_chain_path = "/certs/cert.pem",
                                  .private_key_path = "",
                              })
                     .has_value());
}

TEST(QuicHttp3InteropTest, RejectsClientRequestsThatCannotProduceOutputPaths) {
    const auto base_config = coquic::http3::Http3InteropConfig{
        .mode = coquic::http3::Http3InteropMode::client,
        .testcase = "http3",
        .download_root = "/downloads",
    };

    auto invalid_scheme = base_config;
    invalid_scheme.requests = {"http://server.example/a.txt"};
    EXPECT_EQ(coquic::http3::run_http3_interop(invalid_scheme), 1);

    auto missing_filename = base_config;
    missing_filename.requests = {"https://server.example"};
    EXPECT_EQ(coquic::http3::run_http3_interop(missing_filename), 1);

    auto empty_requests = base_config;
    empty_requests.requests.clear();
    EXPECT_EQ(coquic::http3::run_http3_interop(empty_requests), 1);
}

TEST(QuicHttp3InteropTest, ClientDownloadsMultipleFilesOverLoopback) {
    ScopedTempDir document_root;
    ScopedTempDir download_root;
    document_root.write_file("a.txt", "alpha");
    document_root.write_file("b.txt", "bravo");

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

    const auto config = coquic::http3::Http3InteropConfig{
        .mode = coquic::http3::Http3InteropMode::client,
        .testcase = "http3",
        .download_root = download_root.path(),
        .requests =
            {
                "https://localhost:" + std::to_string(port) + "/a.txt",
                "https://localhost:" + std::to_string(port) + "/b.txt",
            },
    };

    EXPECT_EQ(coquic::http3::run_http3_interop(config), 0);
    EXPECT_EQ(coquic::quic::test::read_text_file(download_root.path() / "a.txt"), "alpha");
    EXPECT_EQ(coquic::quic::test::read_text_file(download_root.path() / "b.txt"), "bravo");
}

TEST(QuicHttp3InteropTest, ClientDownloadsFilesWithQueryAndFragmentSuffixes) {
    ScopedTempDir document_root;
    ScopedTempDir download_root;
    document_root.write_file("a.txt", "alpha");
    document_root.write_file("b.txt", "bravo");

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

    const auto config = coquic::http3::Http3InteropConfig{
        .mode = coquic::http3::Http3InteropMode::client,
        .testcase = "http3",
        .download_root = download_root.path(),
        .requests =
            {
                "https://localhost:" + std::to_string(port) + "/a.txt?cache=1",
                "https://localhost:" + std::to_string(port) + "/b.txt#fragment",
            },
    };

    EXPECT_EQ(coquic::http3::run_http3_interop(config), 0);
    EXPECT_EQ(coquic::quic::test::read_text_file(download_root.path() / "a.txt"), "alpha");
    EXPECT_EQ(coquic::quic::test::read_text_file(download_root.path() / "b.txt"), "bravo");
}

TEST(QuicHttp3InteropTest, ServerModeStartsHttp3Runtime) {
    ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello http3");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto interop_config = coquic::http3::Http3InteropConfig{
        .mode = coquic::http3::Http3InteropMode::server,
        .testcase = "http3",
        .host = "127.0.0.1",
        .port = port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto runtime_config = coquic::http3::Http3RuntimeConfig{
        .mode = coquic::http3::Http3RuntimeMode::server,
        .host = interop_config.host,
        .port = interop_config.port,
        .enable_bootstrap = false,
        .document_root = interop_config.document_root,
        .certificate_chain_path = interop_config.certificate_chain_path,
        .private_key_path = interop_config.private_key_path,
    };

    pid_t child_pid = ::fork();
    ASSERT_GE(child_pid, 0);
    if (child_pid == 0) {
        _exit(coquic::http3::run_http3_interop(interop_config));
    }

    const auto terminate_child = [&]() {
        if (child_pid <= 0) {
            return;
        }
        ::kill(child_pid, SIGTERM);
        int status = 0;
        ::waitpid(child_pid, &status, 0);
        child_pid = -1;
    };

    if (!wait_for_http3_server_ready(child_pid, runtime_config)) {
        terminate_child();
        FAIL() << "timed out waiting for h3 interop server to bind loopback listeners";
    }

    EXPECT_TRUE(udp_port_is_bound(port));
    terminate_child();
}

TEST(QuicHttp3InteropTest, ServerModeReturnsFailureWhenRuntimeCannotLoadIdentity) {
    ScopedTempDir document_root;
    document_root.write_file("hello.txt", "hello http3");

    const auto config = coquic::http3::Http3InteropConfig{
        .mode = coquic::http3::Http3InteropMode::server,
        .testcase = "http3",
        .host = "127.0.0.1",
        .port = 443,
        .document_root = document_root.path(),
        .certificate_chain_path = document_root.path() / "missing-cert.pem",
        .private_key_path = document_root.path() / "missing-key.pem",
    };

    EXPECT_EQ(coquic::http3::run_http3_interop(config), 1);
}
