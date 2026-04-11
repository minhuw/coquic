#include <filesystem>

#include <gtest/gtest.h>

#include "tests/support/perf/perf_test_fixtures.h"

namespace {
using namespace coquic::perf;
using namespace coquic::perf::test_support;

TEST(QuicPerfBulkTest, DownloadRunWritesJsonSummary) {
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

    const auto json_path =
        std::filesystem::temp_directory_path() / "coquic-perf-bulk-download.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::bulk,
        .direction = QuicPerfDirection::download,
        .host = "127.0.0.1",
        .port = port,
        .request_bytes = 0,
        .response_bytes = 0,
        .streams = 2,
        .connections = 1,
        .requests_in_flight = 1,
        .total_bytes = 65536,
        .duration = std::chrono::milliseconds{500},
        .json_out = json_path,
    };

    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto json = read_result_text(json_path);
    EXPECT_NE(json.find("\"mode\":\"bulk\""), std::string::npos);
    EXPECT_NE(json.find("\"direction\":\"download\""), std::string::npos);
    EXPECT_NE(json.find("\"bytes_received\":"), std::string::npos);
}

TEST(QuicPerfBulkTest, UploadRunReportsServerReceivedByteCount) {
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

    const auto json_path = std::filesystem::temp_directory_path() / "coquic-perf-bulk-upload.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::bulk,
        .direction = QuicPerfDirection::upload,
        .host = "127.0.0.1",
        .port = port,
        .streams = 1,
        .connections = 1,
        .requests_in_flight = 1,
        .total_bytes = 32768,
        .duration = std::chrono::milliseconds{500},
        .json_out = json_path,
    };

    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto json = read_result_text(json_path);
    EXPECT_NE(json.find("\"direction\":\"upload\""), std::string::npos);
    EXPECT_NE(json.find("\"bytes_sent\":32768"), std::string::npos);
    EXPECT_NE(json.find("\"bytes_received\":0"), std::string::npos);
}
} // namespace
