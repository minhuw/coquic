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

TEST(QuicPerfConfigTest, ParsesAndPropagatesCongestionControlSelection) {
    const char *argv[] = {
        "coquic-perf",
        "client",
        "--host",
        "127.0.0.1",
        "--mode",
        "bulk",
        "--direction",
        "download",
        "--total-bytes",
        "65536",
        "--congestion-control",
        "copa",
    };

    const auto config =
        parse_perf_runtime_args(static_cast<int>(std::size(argv)), const_cast<char **>(argv));

    ASSERT_TRUE(config.has_value());
    const auto parsed = config.value_or(QuicPerfConfig{});
    EXPECT_EQ(parsed.congestion_control, coquic::quic::QuicCongestionControlAlgorithm::copa);

    const auto client = make_perf_client_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::client,
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::copa,
    });
    EXPECT_EQ(client.transport.congestion_control,
              coquic::quic::QuicCongestionControlAlgorithm::copa);

    const auto server = make_perf_server_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::server,
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::bbr,
    });
    EXPECT_EQ(server.transport.congestion_control,
              coquic::quic::QuicCongestionControlAlgorithm::bbr);
}

TEST(QuicPerfConfigTest, EndpointConfigUsesPerfOutboundDatagramSize) {
    constexpr std::size_t kExpectedPerfDatagramSize = std::size_t{60} * 1024u;

    const auto client =
        make_perf_client_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::client});
    const auto server =
        make_perf_server_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::server});

    EXPECT_EQ(client.max_outbound_datagram_size, kExpectedPerfDatagramSize);
    EXPECT_EQ(server.max_outbound_datagram_size, kExpectedPerfDatagramSize);
}

TEST(QuicPerfConfigTest, EndpointConfigKeepsPmtudEnabledForContainerBenchmarks) {
    const auto client =
        make_perf_client_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::client});
    const auto server =
        make_perf_server_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::server});

    EXPECT_TRUE(client.transport.pmtud_enabled);
    EXPECT_TRUE(server.transport.pmtud_enabled);
}

TEST(QuicPerfConfigTest, EndpointConfigUsesTransferSizedReceiveWindows) {
    constexpr std::uint64_t kExpectedConnectionWindow = 32ull * 1024ull * 1024ull;
    constexpr std::uint64_t kExpectedStreamWindow = 16ull * 1024ull * 1024ull;

    const auto client =
        make_perf_client_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::client});
    const auto server =
        make_perf_server_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::server});

    EXPECT_EQ(client.transport.initial_max_data, kExpectedConnectionWindow);
    EXPECT_EQ(client.transport.initial_max_stream_data_bidi_local, kExpectedStreamWindow);
    EXPECT_EQ(server.transport.initial_max_data, kExpectedConnectionWindow);
    EXPECT_EQ(server.transport.initial_max_stream_data_bidi_remote, kExpectedStreamWindow);
}

TEST(QuicPerfConfigTest, EndpointConfigUsesPerfAckElicitingThreshold) {
    constexpr std::uint64_t kExpectedAckElicitingThreshold = 2;
    constexpr std::uint64_t kExpectedCopaBulkAckElicitingThreshold = 1;
    constexpr std::uint64_t kExpectedCopaInteractiveAckElicitingThreshold = 8;

    const auto bulk_client =
        make_perf_client_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::client});
    const auto bulk_server =
        make_perf_server_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::server});
    const auto rr_client = make_perf_client_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::rr,
    });
    const auto crr_server = make_perf_server_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::server,
        .mode = QuicPerfMode::crr,
    });
    const auto copa_client = make_perf_client_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::bulk,
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::copa,
    });
    const auto copa_server = make_perf_server_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::server,
        .mode = QuicPerfMode::bulk,
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::copa,
    });
    const auto copa_rr_client = make_perf_client_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::rr,
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::copa,
    });
    const auto copa_crr_server = make_perf_server_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::server,
        .mode = QuicPerfMode::crr,
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::copa,
    });

    EXPECT_EQ(bulk_client.transport.ack_eliciting_threshold, kExpectedAckElicitingThreshold);
    EXPECT_EQ(bulk_server.transport.ack_eliciting_threshold, kExpectedAckElicitingThreshold);
    EXPECT_EQ(rr_client.transport.ack_eliciting_threshold, kExpectedAckElicitingThreshold);
    EXPECT_EQ(crr_server.transport.ack_eliciting_threshold, kExpectedAckElicitingThreshold);
    EXPECT_EQ(copa_client.transport.ack_eliciting_threshold,
              kExpectedCopaBulkAckElicitingThreshold);
    EXPECT_EQ(copa_server.transport.ack_eliciting_threshold,
              kExpectedCopaBulkAckElicitingThreshold);
    EXPECT_EQ(copa_rr_client.transport.ack_eliciting_threshold,
              kExpectedCopaInteractiveAckElicitingThreshold);
    EXPECT_EQ(copa_crr_server.transport.ack_eliciting_threshold,
              kExpectedCopaInteractiveAckElicitingThreshold);
}

TEST(QuicPerfConfigTest, EndpointConfigDisablesHyStartPlusPlusOnlyForBulkLossBasedControllers) {
    const auto default_config = coquic::quic::QuicCoreEndpointConfig{};
    EXPECT_TRUE(default_config.transport.enable_hystart_plus_plus);

    const auto bulk_newreno_client =
        make_perf_client_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::client});
    const auto bulk_newreno_server =
        make_perf_server_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::server});
    const auto bulk_cubic_client = make_perf_client_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::client,
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::cubic,
    });
    const auto bulk_cubic_server = make_perf_server_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::server,
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::cubic,
    });
    const auto rr_newreno_client = make_perf_client_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::rr,
    });
    const auto crr_cubic_server = make_perf_server_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::server,
        .mode = QuicPerfMode::crr,
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::cubic,
    });
    const auto bulk_bbr_client = make_perf_client_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::client,
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::bbr,
    });
    const auto bulk_copa_server = make_perf_server_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::server,
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::copa,
    });

    EXPECT_FALSE(bulk_newreno_client.transport.enable_hystart_plus_plus);
    EXPECT_FALSE(bulk_newreno_server.transport.enable_hystart_plus_plus);
    EXPECT_FALSE(bulk_cubic_client.transport.enable_hystart_plus_plus);
    EXPECT_FALSE(bulk_cubic_server.transport.enable_hystart_plus_plus);
    EXPECT_TRUE(rr_newreno_client.transport.enable_hystart_plus_plus);
    EXPECT_TRUE(crr_cubic_server.transport.enable_hystart_plus_plus);
    EXPECT_TRUE(bulk_bbr_client.transport.enable_hystart_plus_plus);
    EXPECT_TRUE(bulk_copa_server.transport.enable_hystart_plus_plus);
}

TEST(QuicPerfConfigTest, EndpointConfigUsesUnfairStreamSchedulingOnlyForBulk) {
    const auto default_config = coquic::quic::QuicCoreEndpointConfig{};
    EXPECT_TRUE(default_config.transport.send_stream_fairness);

    const auto bulk_client =
        make_perf_client_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::client});
    const auto bulk_server =
        make_perf_server_endpoint_config(QuicPerfConfig{.role = QuicPerfRole::server});
    const auto rr_client = make_perf_client_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::rr,
    });
    const auto crr_server = make_perf_server_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::server,
        .mode = QuicPerfMode::crr,
    });

    EXPECT_FALSE(bulk_client.transport.send_stream_fairness);
    EXPECT_FALSE(bulk_server.transport.send_stream_fairness);
    EXPECT_TRUE(rr_client.transport.send_stream_fairness);
    EXPECT_TRUE(crr_server.transport.send_stream_fairness);
}

} // namespace
