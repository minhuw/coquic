#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

TEST(QuicHttp09RuntimeTest, ZeroRttRuntimeTransfersWarmupAndFinalRequestsAcrossResumedConnection) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("seed.txt", "seed-body");
    document_root.write_file("final.txt", "final-body");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    coquic::quic::Http09RuntimeConfig server;
    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "server");
        ScopedEnvVar testcase("TESTCASE", "zerortt");
        ScopedEnvVar host("HOST", "127.0.0.1");
        ScopedEnvVar port_env("PORT", std::to_string(port));
        ScopedEnvVar document_root_env("DOCUMENT_ROOT", document_root.path().string());
        ScopedEnvVar certificate("CERTIFICATE_CHAIN_PATH", "tests/fixtures/quic-server-cert.pem");
        ScopedEnvVar private_key("PRIVATE_KEY_PATH", "tests/fixtures/quic-server-key.pem");

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        server = optional_value_or_terminate(parsed);
    }

    coquic::quic::Http09RuntimeConfig client;
    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar testcase("TESTCASE", "zerortt");
        ScopedEnvVar host("HOST", "127.0.0.1");
        ScopedEnvVar port_env("PORT", std::to_string(port));
        ScopedEnvVar download_root_env("DOWNLOAD_ROOT", download_root.path().string());
        ScopedEnvVar requests("REQUESTS", "https://localhost/seed.txt https://localhost/final.txt");

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        client = optional_value_or_terminate(parsed);
    }

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_EQ(read_file_bytes(download_root.path() / "final.txt"), "final-body");
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksCoverRetryAndZeroRttBranches) {
    EXPECT_TRUE(coquic::quic::test::resumed_client_warmup_failure_exits_early_for_tests());
    EXPECT_TRUE(coquic::quic::test::zero_rtt_request_allowance_for_tests());
}

TEST(QuicHttp09RuntimeTest, HandshakeCaseNeverEmitsRetryPackets) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::http09::QuicHttp09Testcase::handshake,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    auto server_process = launch_runtime_server_process(server_runtime);
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
        .testcase = coquic::http09::QuicHttp09Testcase::handshake,
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

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
}

TEST(QuicHttp09RuntimeTest, RetryEnabledServerSendsRetryBeforeCreatingSession) {
    EXPECT_TRUE(run_retry_enabled_server_retry_smoke());
}

TEST(QuicHttp09RuntimeTest, RetryEnabledServerCompletesHandshakeAfterRetriedInitial) {
    EXPECT_EQ(run_retry_enabled_runtime_handshake(), 0);
}

TEST(QuicHttp09RuntimeTest, V2CaseStartsInQuicV1AndNegotiatesQuicV2LongHeaders) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::http09::QuicHttp09Testcase::v2,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    auto server_process = launch_runtime_server_process(server_runtime);
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
        .testcase = coquic::http09::QuicHttp09Testcase::v2,
        .requests_env = "https://localhost/hello.txt",
    };
    coquic::quic::QuicCore client(coquic::quic::make_http09_client_core_config(client_runtime));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto client_start_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(client_start_datagrams.empty());
    EXPECT_TRUE(std::ranges::all_of(client_start_datagrams, [](const auto &datagram) {
        return has_long_header(datagram) && read_u32_be_at(datagram, 1) == kQuicVersion1;
    }));
    for (const auto &datagram : client_start_datagrams) {
        ASSERT_GE(::sendto(client_fd, datagram.data(), datagram.size(), 0,
                           reinterpret_cast<const sockaddr *>(&server_address),
                           sizeof(server_address)),
                  0);
    }

    std::vector<std::vector<std::byte>> server_datagrams;
    std::vector<std::vector<std::byte>> client_followup_datagrams;
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
        client_followup_datagrams.insert(client_followup_datagrams.end(),
                                         response_datagrams.begin(), response_datagrams.end());
        for (const auto &datagram : response_datagrams) {
            ASSERT_GE(::sendto(client_fd, datagram.data(), datagram.size(), 0,
                               reinterpret_cast<const sockaddr *>(&server_address),
                               sizeof(server_address)),
                      0);
        }
    }

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(std::ranges::any_of(server_datagrams, [](const auto &datagram) {
        return has_long_header(datagram) && read_u32_be_at(datagram, 1) == kQuicVersion2;
    }));
    EXPECT_TRUE(std::ranges::any_of(client_followup_datagrams, [](const auto &datagram) {
        return has_long_header(datagram) && read_u32_be_at(datagram, 1) == kQuicVersion2;
    }));
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
}

} // namespace
