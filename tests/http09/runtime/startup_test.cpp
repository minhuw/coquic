#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

TEST(QuicHttp09RuntimeTest, ServerDoesNotExitAfterMalformedTraffic) {
    ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int client_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(client_fd, 0);
    ScopedFd client_socket(client_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    const std::array<std::byte, 4> garbage = {
        std::byte{0xde},
        std::byte{0xad},
        std::byte{0xbe},
        std::byte{0xef},
    };
    ASSERT_GE(::sendto(client_socket.get(), garbage.data(), garbage.size(), 0,
                       reinterpret_cast<const sockaddr *>(&server_address), sizeof(server_address)),
              0);

    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(1500)).has_value());
}

TEST(QuicHttp09RuntimeTest, ServerFailsFastWhenTlsFilesMissing) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "/no/such/cert.pem",
        .private_key_path = "/no/such/key.pem",
    };

    auto server_process = launch_runtime_server_process(server);
    const auto status = server_process.wait_for_exit(std::chrono::milliseconds(250));
    if (!status.has_value()) {
        FAIL() << "expected child process to exit quickly";
    }
    const auto process_status = *status;
    ASSERT_TRUE(WIFEXITED(process_status));
    EXPECT_EQ(WEXITSTATUS(process_status), 1);
}

TEST(QuicHttp09RuntimeTest, ServerFailsFastWhenPrivateKeyFileMissing) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "/no/such/key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
}

TEST(QuicHttp09RuntimeTest, ServerFailsWhenSocketCreationFails) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {.socket_fn = &fail_socket},
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
}

TEST(QuicHttp09RuntimeTest, ServerFailsWhenSocketBindFails) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {.bind_fn = &fail_bind},
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
}

TEST(QuicHttp09RuntimeTest, ServerFailsWhenConfiguredHostIsNotIpv4) {
    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "not-an-ipv4-address",
        .port = 443,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
}

TEST(QuicHttp09RuntimeTest, ServerUsesIpv6SocketFamilyForIpv6Host) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {.socket_fn = &record_socket_family_then_fail},
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "::1",
        .port = 443,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
    EXPECT_EQ(g_last_socket_family, AF_INET6);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenPeerResolutionFails) {
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {.getaddrinfo_fn = &fail_getaddrinfo},
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .requests_env = "https://localhost/hello.txt",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenResolutionSucceedsWithoutAnyAddrinfoResults) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &missing_results_getaddrinfo,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "localhost",
        .port = 443,
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_last_getaddrinfo_family, AF_UNSPEC);
    EXPECT_EQ(g_last_socket_family, AF_UNSPEC);
}

TEST(QuicHttp09RuntimeTest, ServerResolutionPassesNullNodeForWildcardHost) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &wildcard_ipv4_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "",
        .port = 443,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
    EXPECT_EQ(g_last_getaddrinfo_family, AF_UNSPEC);
    EXPECT_EQ(g_last_socket_family, AF_INET);
}

TEST(QuicHttp09RuntimeTest, RuntimeHealthCheckSucceedsWhenDependenciesAreAvailable) {
    const auto runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::health_check,
    };
    EXPECT_EQ(coquic::quic::run_http09_runtime(runtime), 0);
}

TEST(QuicHttp09RuntimeTest, RuntimeReturnsFailureForUnknownMode) {
    const auto runtime = coquic::quic::Http09RuntimeConfig{
        .mode = invalid_runtime_mode(),
    };

    EXPECT_EXIT(std::exit(coquic::quic::run_http09_runtime(runtime)), ::testing::ExitedWithCode(1),
                "");
}

TEST(QuicHttp09RuntimeTest, ServerRespondsToUnsupportedVersionProbeAndStillTransfersFile) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-after-version-negotiation");

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

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int probe_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(probe_fd, 0);
    ScopedFd probe_socket(probe_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    const auto probe = make_unsupported_version_probe();
    ASSERT_GE(::sendto(probe_socket.get(), probe.data(), probe.size(), 0,
                       reinterpret_cast<const sockaddr *>(&server_address), sizeof(server_address)),
              0);

    pollfd descriptor{};
    descriptor.fd = probe_socket.get();
    descriptor.events = POLLIN;
    ASSERT_EQ(::poll(&descriptor, 1, 1000), 1);
    ASSERT_NE((descriptor.revents & POLLIN), 0);

    std::vector<std::byte> response(65535);
    const auto response_size =
        ::recvfrom(probe_socket.get(), response.data(), response.size(), 0, nullptr, nullptr);
    ASSERT_GT(response_size, 0);
    response.resize(static_cast<std::size_t>(response_size));

    const auto decoded = coquic::quic::deserialize_packet(response, {});
    ASSERT_TRUE(decoded.has_value());
    ASSERT_NE(std::get_if<coquic::quic::VersionNegotiationPacket>(&decoded.value().packet),
              nullptr);
    const auto &version_negotiation =
        std::get<coquic::quic::VersionNegotiationPacket>(decoded.value().packet);
    EXPECT_EQ(version_negotiation.destination_connection_id, (coquic::quic::ConnectionId{
                                                                 std::byte{0xc1},
                                                                 std::byte{0x01},
                                                                 std::byte{0x12},
                                                                 std::byte{0x23},
                                                                 std::byte{0x34},
                                                                 std::byte{0x45},
                                                                 std::byte{0x56},
                                                                 std::byte{0x67},
                                                             }));
    EXPECT_EQ(version_negotiation.source_connection_id, (coquic::quic::ConnectionId{
                                                            std::byte{0x83},
                                                            std::byte{0x94},
                                                            std::byte{0xc8},
                                                            std::byte{0xf0},
                                                            std::byte{0x3e},
                                                            std::byte{0x51},
                                                            std::byte{0x57},
                                                            std::byte{0x08},
                                                        }));
    EXPECT_NE(std::find(version_negotiation.supported_versions.begin(),
                        version_negotiation.supported_versions.end(), 1u),
              version_negotiation.supported_versions.end());
    EXPECT_NE(std::find(version_negotiation.supported_versions.begin(),
                        version_negotiation.supported_versions.end(), 0x6b3343cfu),
              version_negotiation.supported_versions.end());

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"),
              "hello-after-version-negotiation");
}

TEST(QuicHttp09RuntimeTest, ServerIgnoresUnsupportedVersionProbeBelowMinimumInitialSize) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int probe_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(probe_fd, 0);
    ScopedFd probe_socket(probe_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    auto probe = make_unsupported_version_probe();
    probe.resize(64);
    ASSERT_GE(::sendto(probe_socket.get(), probe.data(), probe.size(), 0,
                       reinterpret_cast<const sockaddr *>(&server_address), sizeof(server_address)),
              0);

    pollfd descriptor{};
    descriptor.fd = probe_socket.get();
    descriptor.events = POLLIN;
    EXPECT_EQ(::poll(&descriptor, 1, 200), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
}

TEST(QuicHttp09RuntimeTest, ServerIgnoresSupportedLongHeaderWithoutSession) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int probe_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(probe_fd, 0);
    ScopedFd probe_socket(probe_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    auto datagram = make_unsupported_version_probe();
    datagram[1] = std::byte{0x00};
    datagram[2] = std::byte{0x00};
    datagram[3] = std::byte{0x00};
    datagram[4] = std::byte{0x01};
    datagram[0] = std::byte{0xd0};
    ASSERT_GE(::sendto(probe_socket.get(), datagram.data(), datagram.size(), 0,
                       reinterpret_cast<const sockaddr *>(&server_address), sizeof(server_address)),
              0);

    pollfd descriptor{};
    descriptor.fd = probe_socket.get();
    descriptor.events = POLLIN;
    EXPECT_EQ(::poll(&descriptor, 1, 200), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
}

TEST(QuicHttp09RuntimeTest, ServerFailsWhenVersionNegotiationSendFails) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const ScopedFailSendtoAfterReset sendto_reset;
    g_fail_sendto_after_calls.store(1);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    auto server_process =
        launch_runtime_server_process(server, {
                                                  .sendto_fn = &fail_sendto_after_n_calls,
                                              });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int probe_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(probe_fd, 0);
    ScopedFd probe_socket(probe_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    const auto probe = make_unsupported_version_probe();
    ASSERT_GE(::sendto(probe_socket.get(), probe.data(), probe.size(), 0,
                       reinterpret_cast<const sockaddr *>(&server_address), sizeof(server_address)),
              0);

    const auto status = server_process.wait_for_exit(std::chrono::milliseconds(1000));
    ASSERT_TRUE(status.has_value());
    const auto exit_status = optional_value_or_terminate(status);
    ASSERT_TRUE(WIFEXITED(exit_status));
    EXPECT_EQ(WEXITSTATUS(exit_status), 1);
}

TEST(QuicHttp09RuntimeTest, TraceEnabledServerDropsMalformedSupportedInitialAndStillTransfersFile) {
    ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-after-malformed-initial");

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

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int client_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(client_fd, 0);
    ScopedFd client_socket(client_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    auto malformed_initial = make_unsupported_version_probe();
    malformed_initial[1] = std::byte{0x00};
    malformed_initial[2] = std::byte{0x00};
    malformed_initial[3] = std::byte{0x00};
    malformed_initial[4] = std::byte{0x01};
    ASSERT_GE(::sendto(client_socket.get(), malformed_initial.data(), malformed_initial.size(), 0,
                       reinterpret_cast<const sockaddr *>(&server_address), sizeof(server_address)),
              0);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(100)).has_value());

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello-after-malformed-initial");
}

} // namespace
