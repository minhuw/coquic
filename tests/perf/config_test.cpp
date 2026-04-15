#include <gtest/gtest.h>

#include "src/perf/perf_runtime.h"

namespace {
using coquic::io::QuicIoBackendKind;
using namespace coquic::perf;

TEST(QuicPerfConfigTest, ParsesClientRrInvocation) {
    const char *argv[] = {
        "coquic-perf",
        "client",
        "--host",
        "127.0.0.1",
        "--port",
        "9443",
        "--mode",
        "rr",
        "--request-bytes",
        "64",
        "--response-bytes",
        "96",
        "--requests",
        "1000",
        "--requests-in-flight",
        "4",
        "--json-out",
        "results.json",
    };

    const auto config =
        parse_perf_runtime_args(static_cast<int>(std::size(argv)), const_cast<char **>(argv));

    ASSERT_TRUE(config.has_value());
    const auto parsed = config.value_or(QuicPerfConfig{});
    EXPECT_EQ(parsed.role, QuicPerfRole::client);
    EXPECT_EQ(parsed.mode, QuicPerfMode::rr);
    EXPECT_EQ(parsed.io_backend, QuicIoBackendKind::socket);
    EXPECT_EQ(parsed.host, "127.0.0.1");
    EXPECT_EQ(parsed.port, 9443);
    EXPECT_EQ(parsed.request_bytes, 64u);
    EXPECT_EQ(parsed.response_bytes, 96u);
    EXPECT_EQ(parsed.requests, std::optional<std::size_t>{1000u});
    EXPECT_EQ(parsed.requests_in_flight, 4u);
    EXPECT_EQ(parsed.json_out.value_or(std::filesystem::path{}).string(), "results.json");
}

TEST(QuicPerfConfigTest, DefaultsToSocketSingleFlow) {
    const char *argv[] = {
        "coquic-perf", "client",      "--host",   "127.0.0.1",     "--mode",
        "bulk",        "--direction", "download", "--total-bytes", "65536",
    };

    const auto config =
        parse_perf_runtime_args(static_cast<int>(std::size(argv)), const_cast<char **>(argv));

    ASSERT_TRUE(config.has_value());
    const auto parsed = config.value_or(QuicPerfConfig{});
    EXPECT_EQ(parsed.io_backend, QuicIoBackendKind::socket);
    EXPECT_EQ(parsed.streams, 1u);
    EXPECT_EQ(parsed.connections, 1u);
    EXPECT_EQ(parsed.requests_in_flight, 1u);
    EXPECT_EQ(parsed.duration, std::chrono::milliseconds{5000});
}

TEST(QuicPerfConfigTest, RejectsBulkOnlyFlagsInRrMode) {
    const char *argv[] = {
        "coquic-perf", "client",   "--host",          "127.0.0.1", "--mode",           "rr",
        "--direction", "download", "--request-bytes", "32",        "--response-bytes", "32",
    };

    EXPECT_FALSE(
        parse_perf_runtime_args(static_cast<int>(std::size(argv)), const_cast<char **>(argv))
            .has_value());
}

TEST(QuicPerfConfigTest, ParsesServerIoUringInvocation) {
    const char *argv[] = {
        "coquic-perf",
        "server",
        "--host",
        "0.0.0.0",
        "--port",
        "9443",
        "--io-backend",
        "io_uring",
        "--certificate-chain",
        "tests/fixtures/quic-server-cert.pem",
        "--private-key",
        "tests/fixtures/quic-server-key.pem",
    };

    const auto config =
        parse_perf_runtime_args(static_cast<int>(std::size(argv)), const_cast<char **>(argv));

    ASSERT_TRUE(config.has_value());
    const auto parsed = config.value_or(QuicPerfConfig{});
    EXPECT_EQ(parsed.role, QuicPerfRole::server);
    EXPECT_EQ(parsed.io_backend, QuicIoBackendKind::io_uring);
    EXPECT_EQ(parsed.certificate_chain_path,
              std::filesystem::path{"tests/fixtures/quic-server-cert.pem"});
    EXPECT_EQ(parsed.private_key_path, std::filesystem::path{"tests/fixtures/quic-server-key.pem"});
}

TEST(QuicPerfConfigTest, EndpointConfigUsesPerfOutboundDatagramSize) {
    constexpr std::size_t kExpectedPerfDatagramSize = std::size_t{16} * 1024u;

    const auto client =
        make_perf_client_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::client});
    const auto server =
        make_perf_server_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::server});

    EXPECT_EQ(client.max_outbound_datagram_size, kExpectedPerfDatagramSize);
    EXPECT_EQ(server.max_outbound_datagram_size, kExpectedPerfDatagramSize);
}
} // namespace
