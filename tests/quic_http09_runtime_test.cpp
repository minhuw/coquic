#include <algorithm>
#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "src/quic/http09_runtime.h"
#include "tests/quic_test_utils.h"

namespace {

class ScopedEnvVar {
  public:
    ScopedEnvVar(std::string name, std::optional<std::string> value) : name_(std::move(name)) {
        const char *existing = std::getenv(name_.c_str());
        if (existing != nullptr) {
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

std::string read_file_bytes(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

bool first_header_is_retry_packet(std::span<const std::byte> datagram) {
    if (datagram.empty()) {
        return false;
    }

    const auto first = std::to_integer<std::uint8_t>(datagram.front());
    const bool is_long_header = (first & 0x80u) != 0;
    if (!is_long_header) {
        return false;
    }

    const std::uint8_t packet_type = (first >> 4) & 0x03u;
    return packet_type == 0x03u;
}

bool has_long_header(std::span<const std::byte> datagram) {
    if (datagram.empty()) {
        return false;
    }
    return (std::to_integer<std::uint8_t>(datagram.front()) & 0x80u) != 0;
}

coquic::quic::QuicCoreTimePoint runtime_now() {
    return coquic::quic::QuicCoreClock::now();
}

struct ObservingServerResult {
    int exit_code = 1;
    std::size_t handshake_ready_events = 0;
    std::vector<std::uint64_t> request_stream_ids;
};

ObservingServerResult run_observing_http09_server(const coquic::quic::Http09RuntimeConfig &config) {
    ObservingServerResult observed;

    const int socket_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        return observed;
    }
    ScopedFd socket_guard(socket_fd);

    sockaddr_in bind_address{};
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons(config.port);
    if (::inet_pton(AF_INET, config.host.c_str(), &bind_address.sin_addr) != 1) {
        return observed;
    }
    if (::bind(socket_fd, reinterpret_cast<const sockaddr *>(&bind_address),
               sizeof(bind_address)) != 0) {
        return observed;
    }

    coquic::quic::QuicHttp09ServerEndpoint endpoint(
        coquic::quic::QuicHttp09ServerConfig{.document_root = config.document_root});
    coquic::quic::QuicCore core(coquic::quic::make_http09_server_core_config(config));

    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    bool have_peer = false;
    bool saw_peer_activity = false;
    std::optional<coquic::quic::QuicCoreTimePoint> next_wakeup;

    std::function<bool(coquic::quic::QuicCoreResult)> drive =
        [&](coquic::quic::QuicCoreResult result) -> bool {
        for (;;) {
            next_wakeup = result.next_wakeup;
            if (result.local_error.has_value()) {
                return false;
            }

            for (const auto &effect : result.effects) {
                if (const auto *event = std::get_if<coquic::quic::QuicCoreStateEvent>(&effect)) {
                    if (event->change == coquic::quic::QuicCoreStateChange::handshake_ready) {
                        ++observed.handshake_ready_events;
                    }
                    continue;
                }

                if (const auto *received =
                        std::get_if<coquic::quic::QuicCoreReceiveStreamData>(&effect)) {
                    observed.request_stream_ids.push_back(received->stream_id);
                    continue;
                }

                const auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect);
                if (send == nullptr) {
                    continue;
                }
                if (!have_peer) {
                    return false;
                }

                const auto *buffer = send->bytes.empty()
                                         ? nullptr
                                         : reinterpret_cast<const void *>(send->bytes.data());
                if (::sendto(socket_fd, buffer, send->bytes.size(), 0,
                             reinterpret_cast<const sockaddr *>(&peer), peer_len) < 0) {
                    return false;
                }
            }

            auto update = endpoint.on_core_result(result, runtime_now());
            if (update.terminal_failure) {
                return false;
            }

            while (true) {
                if (!update.core_inputs.empty()) {
                    result = coquic::quic::test::advance_core_with_inputs(core, update.core_inputs,
                                                                          runtime_now());
                    break;
                }

                if (!update.has_pending_work) {
                    return true;
                }

                update = endpoint.poll(runtime_now());
                if (update.terminal_failure) {
                    return false;
                }
            }
        }
    };

    if (!drive(core.advance(coquic::quic::QuicCoreStart{}, runtime_now()))) {
        return observed;
    }

    for (;;) {
        int timeout_ms = 1000;
        if (next_wakeup.has_value()) {
            const auto current = runtime_now();
            if (*next_wakeup <= current) {
                if (!drive(core.advance(coquic::quic::QuicCoreTimerExpired{}, current))) {
                    return observed;
                }
                continue;
            }

            const auto remaining = *next_wakeup - current;
            timeout_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              remaining + std::chrono::milliseconds(1))
                                              .count());
            if (timeout_ms < 1) {
                timeout_ms = 1;
            }
        }

        pollfd descriptor{};
        descriptor.fd = socket_fd;
        descriptor.events = POLLIN;

        int poll_result = 0;
        do {
            poll_result = ::poll(&descriptor, 1, timeout_ms);
        } while (poll_result < 0 && errno == EINTR);

        if (poll_result < 0) {
            return observed;
        }
        if (poll_result == 0) {
            if (next_wakeup.has_value()) {
                if (!drive(core.advance(coquic::quic::QuicCoreTimerExpired{}, runtime_now()))) {
                    return observed;
                }
                continue;
            }

            observed.exit_code = saw_peer_activity ? 0 : 1;
            return observed;
        }
        if ((descriptor.revents & POLLIN) == 0) {
            return observed;
        }

        std::vector<std::byte> inbound(65535);
        sockaddr_storage source{};
        socklen_t source_len = sizeof(source);
        ssize_t bytes_read = 0;
        do {
            bytes_read = ::recvfrom(socket_fd, inbound.data(), inbound.size(), 0,
                                    reinterpret_cast<sockaddr *>(&source), &source_len);
        } while (bytes_read < 0 && errno == EINTR);

        if (bytes_read < 0) {
            return observed;
        }

        inbound.resize(static_cast<std::size_t>(bytes_read));
        peer = source;
        peer_len = source_len;
        have_peer = true;
        saw_peer_activity = true;

        if (!drive(core.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = std::move(inbound)},
                                runtime_now()))) {
            return observed;
        }
    }
}

TEST(QuicHttp09RuntimeTest, ClientAndServerTransferSingleFileOverUdpSockets) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-over-udp");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/hello.txt",
    };

    auto server_future = std::async(
        std::launch::async, [&server]() { return coquic::quic::run_http09_runtime(server); });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    ASSERT_EQ(server_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_EQ(server_future.get(), 0);
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello-over-udp");
}

TEST(QuicHttp09RuntimeTest, TransferCaseUsesSingleConnectionAndMultipleStreams) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("alpha.txt", "alpha-bytes");
    document_root.write_file("beta.txt", "beta-bytes");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/alpha.txt https://localhost/beta.txt",
    };

    auto server_future =
        std::async(std::launch::async, [&server]() { return run_observing_http09_server(server); });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    ASSERT_EQ(server_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto server_result = server_future.get();
    EXPECT_EQ(server_result.exit_code, 0);
    EXPECT_EQ(read_file_bytes(download_root.path() / "alpha.txt"), "alpha-bytes");
    EXPECT_EQ(read_file_bytes(download_root.path() / "beta.txt"), "beta-bytes");

    std::sort(server_result.request_stream_ids.begin(), server_result.request_stream_ids.end());
    server_result.request_stream_ids.erase(std::unique(server_result.request_stream_ids.begin(),
                                                       server_result.request_stream_ids.end()),
                                           server_result.request_stream_ids.end());
    EXPECT_EQ(server_result.handshake_ready_events, 1u);
    EXPECT_EQ(server_result.request_stream_ids, (std::vector<std::uint64_t>{0u, 4u}));
}

TEST(QuicHttp09RuntimeTest, RuntimeBuildsCoreConfigWithInteropAlpnAndRunnerDefaults) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "transfer");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt https://localhost/b.txt");
    ScopedEnvVar host("HOST", std::nullopt);
    ScopedEnvVar port("PORT", std::nullopt);
    ScopedEnvVar document_root("DOCUMENT_ROOT", std::nullopt);
    ScopedEnvVar download_root("DOWNLOAD_ROOT", std::nullopt);
    ScopedEnvVar certificate("CERTIFICATE_CHAIN_PATH", std::nullopt);
    ScopedEnvVar private_key("PRIVATE_KEY_PATH", std::nullopt);

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    if (!parsed.has_value()) {
        FAIL() << "expected runtime config";
    }
    const auto &runtime = *parsed;
    EXPECT_EQ(runtime.mode, coquic::quic::Http09RuntimeMode::client);
    EXPECT_EQ(runtime.application_protocol, "hq-interop");
    EXPECT_EQ(runtime.document_root, std::filesystem::path("/www"));
    EXPECT_EQ(runtime.download_root, std::filesystem::path("/downloads"));
    EXPECT_EQ(runtime.certificate_chain_path, std::filesystem::path("/certs/cert.pem"));
    EXPECT_EQ(runtime.private_key_path, std::filesystem::path("/certs/priv.key"));

    auto overridden_runtime = runtime;
    overridden_runtime.application_protocol = "not-hq-interop";

    const auto client_core = coquic::quic::make_http09_client_core_config(overridden_runtime);
    EXPECT_EQ(client_core.application_protocol, "hq-interop");
    EXPECT_EQ(client_core.transport.initial_max_data, 64u * 1024u);
    EXPECT_EQ(client_core.transport.initial_max_stream_data_bidi_local, 16u * 1024u);
    EXPECT_EQ(client_core.transport.initial_max_stream_data_bidi_remote, 256u * 1024u);

    auto server_runtime = overridden_runtime;
    server_runtime.mode = coquic::quic::Http09RuntimeMode::server;
    server_runtime.certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    server_runtime.private_key_path = "tests/fixtures/quic-server-key.pem";
    const auto server_core = coquic::quic::make_http09_server_core_config(server_runtime);
    EXPECT_EQ(server_core.application_protocol, "hq-interop");
    if (!server_core.identity.has_value()) {
        FAIL() << "expected server identity";
    }
    const auto &identity = *server_core.identity;
    EXPECT_EQ(identity.certificate_pem,
              coquic::quic::test::read_text_file("tests/fixtures/quic-server-cert.pem"));
    EXPECT_EQ(identity.private_key_pem,
              coquic::quic::test::read_text_file("tests/fixtures/quic-server-key.pem"));
}

TEST(QuicHttp09RuntimeTest, HandshakeCaseNeverEmitsRetryPackets) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    auto server_future = std::async(
        std::launch::async, [&]() { return coquic::quic::run_http09_runtime(server_runtime); });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int client_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(client_fd, 0);
    ScopedFd client_socket_guard(client_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    auto client_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
        .requests_env = "https://localhost/hello.txt",
    };
    coquic::quic::QuicCore client(coquic::quic::make_http09_client_core_config(client_runtime));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto client_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(client_datagrams.empty());
    for (const auto &datagram : client_datagrams) {
        ASSERT_GE(::sendto(client_fd, datagram.data(), datagram.size(), 0,
                           reinterpret_cast<const sockaddr *>(&server_address),
                           sizeof(server_address)),
                  0);
    }

    std::vector<std::vector<std::byte>> server_datagrams;
    for (int i = 0; i < 32; ++i) {
        pollfd descriptor{};
        descriptor.fd = client_fd;
        descriptor.events = POLLIN;
        const int poll_result = ::poll(&descriptor, 1, 250);
        ASSERT_GE(poll_result, 0);
        if (poll_result == 0) {
            if (client.is_handshake_complete()) {
                break;
            }
            continue;
        }
        ASSERT_NE((descriptor.revents & POLLIN), 0);

        std::vector<std::byte> buffer(65535);
        const auto bytes_read =
            ::recvfrom(client_fd, buffer.data(), buffer.size(), 0, nullptr, nullptr);
        ASSERT_GT(bytes_read, 0);
        buffer.resize(static_cast<std::size_t>(bytes_read));
        server_datagrams.push_back(std::move(buffer));

        auto step =
            client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = server_datagrams.back()},
                           coquic::quic::test::test_time(i + 1));
        const auto response_datagrams = coquic::quic::test::send_datagrams_from(step);
        for (const auto &datagram : response_datagrams) {
            ASSERT_GE(::sendto(client_fd, datagram.data(), datagram.size(), 0,
                               reinterpret_cast<const sockaddr *>(&server_address),
                               sizeof(server_address)),
                      0);
        }
    }

    std::vector<std::vector<std::byte>> long_header_datagrams;
    for (const auto &datagram : server_datagrams) {
        if (!has_long_header(datagram)) {
            continue;
        }
        long_header_datagrams.push_back(datagram);
    }

    ASSERT_FALSE(long_header_datagrams.empty());
    for (const auto &datagram : long_header_datagrams) {
        EXPECT_FALSE(first_header_is_retry_packet(datagram));
    }

    ASSERT_EQ(server_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_EQ(server_future.get(), 0);
}

} // namespace
