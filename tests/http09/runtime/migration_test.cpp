#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::http09::test_support;

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerBindsPreferredSocketAndPollsBothSockets) {
    auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const ScopedServerSocketPollTraceReset trace_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .socket_fn = &record_server_socket_then_succeed,
            .bind_fn = &record_server_bind_then_succeed,
            .poll_fn = &record_poll_descriptor_count_then_cancel,
            .setsockopt_fn = [](int, int, int, const void *, socklen_t) { return 0; },
            .recvfrom_fn = &would_block_recvfrom,
        },
    };

    auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .enable_client_preferred_address_migration = true,
        .enable_server_preferred_address = true,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::http09::run_http09_runtime(server), 1);
    ASSERT_EQ(g_server_socket_poll_trace.opened_sockets.size(), 2u);
    ASSERT_EQ(g_server_socket_poll_trace.bound_ports.size(), 2u);
    EXPECT_EQ(g_server_socket_poll_trace.bound_ports[0], port);
    EXPECT_EQ(g_server_socket_poll_trace.bound_ports[1], port + 1);
    ASSERT_FALSE(g_server_socket_poll_trace.poll_descriptor_counts.empty());
    EXPECT_EQ(g_server_socket_poll_trace.poll_descriptor_counts.front(), 2u);
}

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerConfigAdvertisesPreferredAddress) {
    EXPECT_TRUE(coquic::http09::test::server_preferred_address_config_for_tests());
}

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerConfigIncludesPreferredAddressResetToken) {
    auto core = coquic::http09::make_http09_server_core_config(coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 443,
        .enable_client_preferred_address_migration = true,
        .enable_server_preferred_address = true,
    });

    ASSERT_TRUE(core.transport.preferred_address.has_value());
    auto preferred_address =
        core.transport.preferred_address.value_or(coquic::quic::PreferredAddress{});
    EXPECT_FALSE(std::all_of(preferred_address.stateless_reset_token.begin(),
                             preferred_address.stateless_reset_token.end(),
                             [](std::byte byte) { return byte == std::byte{0x00}; }));
}

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerConfigUsesConcreteAddressForWildcardHost) {
    ScopedEnvVar hostname("HOSTNAME", "interop-server-host");
    ScopedFreeaddrinfoCounterReset freeaddrinfo_counter;
    ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops(
        coquic::io::test::SocketIoBackendOpsOverride{
            .getaddrinfo_fn = hostname_ipv6_getaddrinfo,
            .freeaddrinfo_fn = counting_freeaddrinfo,
        });

    auto core = coquic::http09::make_http09_server_core_config(coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "::",
        .port = 443,
        .enable_client_preferred_address_migration = true,
        .enable_server_preferred_address = true,
    });

    ASSERT_TRUE(core.transport.preferred_address.has_value());
    auto preferred_address =
        core.transport.preferred_address.value_or(coquic::quic::PreferredAddress{});
    EXPECT_EQ(g_last_getaddrinfo_family, AF_INET6);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
    EXPECT_EQ(preferred_address.ipv4_port, 0);
    EXPECT_EQ(preferred_address.ipv6_port, 444);
    EXPECT_EQ(preferred_address.ipv6_address, (std::array<std::byte, 16>{
                                                  std::byte{0x20},
                                                  std::byte{0x01},
                                                  std::byte{0x0d},
                                                  std::byte{0xb8},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x09},
                                              }));
}

TEST(QuicHttp09RuntimeTest, ConnectionMigrationWildcardServerConfigAdvertisesBothFamilies) {
    ScopedEnvVar hostname("HOSTNAME", "interop-server-host");
    ScopedFreeaddrinfoCounterReset freeaddrinfo_counter;
    ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops(
        coquic::io::test::SocketIoBackendOpsOverride{
            .getaddrinfo_fn = hostname_dual_stack_getaddrinfo,
            .freeaddrinfo_fn = counting_freeaddrinfo,
        });

    auto core = coquic::http09::make_http09_server_core_config(coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "::",
        .port = 443,
        .enable_client_preferred_address_migration = true,
        .enable_server_preferred_address = true,
    });

    ASSERT_TRUE(core.transport.preferred_address.has_value());
    auto preferred_address =
        core.transport.preferred_address.value_or(coquic::quic::PreferredAddress{});
    EXPECT_EQ(g_freeaddrinfo_calls, 2);
    EXPECT_EQ(preferred_address.ipv4_port, 444);
    EXPECT_EQ(preferred_address.ipv4_address, (std::array<std::byte, 4>{
                                                  std::byte{192},
                                                  std::byte{0},
                                                  std::byte{2},
                                                  std::byte{9},
                                              }));
    EXPECT_EQ(preferred_address.ipv6_port, 444);
    EXPECT_EQ(preferred_address.ipv6_address, (std::array<std::byte, 16>{
                                                  std::byte{0x20},
                                                  std::byte{0x01},
                                                  std::byte{0x0d},
                                                  std::byte{0xb8},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x00},
                                                  std::byte{0x09},
                                              }));
}

} // namespace
