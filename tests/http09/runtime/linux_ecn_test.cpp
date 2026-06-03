#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::http09::test_support;

TEST(QuicHttp09RuntimeTest, ClientPrefersIpv4AddrinfoWhenHostnameIsNonNumeric) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &prefer_ipv4_mixed_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "localhost",
        .port = 443,
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::http09::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_last_getaddrinfo_family, AF_UNSPEC);
    EXPECT_EQ(g_last_socket_family, AF_INET);
}

TEST(QuicHttp09RuntimeTest, ClientConnectionUsesIpv6ResolutionAndSocketFamilyForIpv6Remote) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &ipv6_only_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    const std::vector<coquic::http09::QuicHttp09Request> requests = {
        {.url = "https://[::1]:9443/a.txt",
         .authority = "[::1]:9443",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };

    EXPECT_EQ(coquic::http09::test::run_http09_client_connection_for_tests(client, requests, 1), 1);
    EXPECT_EQ(g_last_getaddrinfo_family, AF_INET6);
    EXPECT_EQ(g_last_socket_family, AF_INET6);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

TEST(QuicHttp09RuntimeTest, ClientFallsBackToEarlierValidAddrinfoWhenPreferredResultIsInvalid) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &fallback_to_earlier_valid_result_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "localhost",
        .port = 443,
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::http09::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_last_socket_family, AF_INET6);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenAllResolvedAddrinfoEntriesAreInvalid) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &no_valid_result_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "localhost",
        .port = 443,
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::http09::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_last_getaddrinfo_family, AF_UNSPEC);
    EXPECT_EQ(g_last_socket_family, AF_UNSPEC);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenAddrinfoFamilyIsUnsupported) {
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .getaddrinfo_fn = &unsupported_family_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "localhost",
        .port = 443,
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::http09::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

TEST(QuicHttp09RuntimeTest, ClientUsesRealIpv6SocketSetupBeforeInitialSend) {
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .sendto_fn = &fail_sendto,
            .getaddrinfo_fn = &ipv6_only_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    const std::vector<coquic::http09::QuicHttp09Request> requests = {
        {.url = "https://[::1]:9443/a.txt",
         .authority = "[::1]:9443",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };

    EXPECT_EQ(coquic::http09::test::run_http09_client_connection_for_tests(client, requests, 1), 1);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

} // namespace
