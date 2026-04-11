#include <filesystem>

#include <gtest/gtest.h>

#include "tests/support/perf/perf_test_fixtures.h"

namespace {
using namespace coquic::perf;
using namespace coquic::perf::test_support;

TEST(QuicPerfRrTest, EstablishedConnectionReportsLatencyAndRequestRate) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const QuicPerfConfig server{
        .role = QuicPerfRole::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    ScopedPerfProcess server_process(server);

    const auto json_path = std::filesystem::temp_directory_path() / "coquic-perf-rr.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::rr,
        .host = "127.0.0.1",
        .port = port,
        .request_bytes = 32,
        .response_bytes = 48,
        .requests = 32,
        .requests_in_flight = 4,
        .duration = std::chrono::milliseconds{500},
        .json_out = json_path,
    };

    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto json = read_result_text(json_path);
    EXPECT_NE(json.find("\"mode\":\"rr\""), std::string::npos);
    EXPECT_NE(json.find("\"requests_completed\":32"), std::string::npos);
    EXPECT_NE(json.find("\"latency\":{"), std::string::npos);
}

TEST(QuicPerfRrTest, HonorsRequestsInFlightLimit) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const QuicPerfConfig server{
        .role = QuicPerfRole::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    ScopedPerfProcess server_process(server);

    const auto json_path = std::filesystem::temp_directory_path() / "coquic-perf-rr-inflight.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::rr,
        .host = "127.0.0.1",
        .port = port,
        .request_bytes = 16,
        .response_bytes = 16,
        .requests = 12,
        .requests_in_flight = 2,
        .duration = std::chrono::milliseconds{500},
        .json_out = json_path,
    };

    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto json = read_result_text(json_path);
    EXPECT_NE(json.find("\"requests_in_flight\":2"), std::string::npos);
}
} // namespace
