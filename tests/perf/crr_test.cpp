#include <filesystem>

#include <gtest/gtest.h>

#include "tests/support/perf/perf_test_fixtures.h"

namespace {
using namespace coquic::perf;
using namespace coquic::perf::test_support;

TEST(QuicPerfCrrTest, FreshConnectionPerRequestReportsLatency) {
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

    const auto json_path = std::filesystem::temp_directory_path() / "coquic-perf-crr.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::crr,
        .host = "127.0.0.1",
        .port = port,
        .json_out = json_path,
        .request_bytes = 24,
        .response_bytes = 24,
        .connections = 2,
        .requests_in_flight = 1,
        .requests = 8,
        .duration = std::chrono::milliseconds{500},
    };

    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto json = read_result_text(json_path);
    EXPECT_NE(json.find("\"mode\":\"crr\""), std::string::npos);
    EXPECT_NE(json.find("\"requests_completed\":8"), std::string::npos);
    EXPECT_NE(json.find("\"connections\":2"), std::string::npos);
}

TEST(QuicPerfCrrTest, HonorsParallelConnectionLimit) {
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

    const auto json_path = std::filesystem::temp_directory_path() / "coquic-perf-crr-parallel.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::crr,
        .host = "127.0.0.1",
        .port = port,
        .json_out = json_path,
        .request_bytes = 8,
        .response_bytes = 8,
        .connections = 3,
        .requests_in_flight = 1,
        .requests = 6,
        .duration = std::chrono::milliseconds{500},
    };

    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto json = read_result_text(json_path);
    EXPECT_NE(json.find("\"connections\":3"), std::string::npos);
}
} // namespace
