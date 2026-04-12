#include <charconv>
#include <filesystem>

#include <gtest/gtest.h>

#include "tests/support/perf/perf_test_fixtures.h"

namespace {
using namespace coquic::perf;
using namespace coquic::perf::test_support;

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::optional<std::uint64_t> json_first_u64_field(std::string_view json, std::string_view key) {
    const std::string needle = std::string{"\""} + std::string{key} + "\":";
    const auto pos = json.find(needle);
    if (pos == std::string_view::npos) {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    const auto start = pos + needle.size();
    const auto *begin = json.data() + start;
    const auto *end = json.data() + json.size();
    const auto result = std::from_chars(begin, end, value);
    if (result.ec != std::errc{}) {
        return std::nullopt;
    }
    return value;
}

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

TEST(QuicPerfBulkTest, TimedDownloadUsesMeasurementWindow) {
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

    const auto json_path = std::filesystem::temp_directory_path() / "coquic-perf-bulk-timed.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::bulk,
        .direction = QuicPerfDirection::download,
        .host = "127.0.0.1",
        .port = port,
        .request_bytes = 0,
        .response_bytes = 4096,
        .streams = 2,
        .connections = 1,
        .requests_in_flight = 1,
        .warmup = std::chrono::milliseconds{100},
        .duration = std::chrono::milliseconds{150},
        .json_out = json_path,
    };

    const auto started_at = std::chrono::steady_clock::now();
    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto wall_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at);

    const auto json = read_result_text(json_path);
    const auto warmup_ms = json_u64_field(json, "warmup_ms");
    const auto elapsed_ms = json_u64_field(json, "elapsed_ms");
    const auto measured_bytes_received = json_first_u64_field(json, "bytes_received");
    const auto streams = json_u64_field(json, "streams");

    ASSERT_TRUE(warmup_ms.has_value());
    ASSERT_TRUE(elapsed_ms.has_value());
    ASSERT_TRUE(measured_bytes_received.has_value());
    ASSERT_TRUE(streams.has_value());
    const auto warmup_ms_value = warmup_ms.value_or(0);
    const auto elapsed_ms_value = elapsed_ms.value_or(0);
    const auto measured_bytes_received_value = measured_bytes_received.value_or(0);
    const auto streams_value = streams.value_or(0);
    EXPECT_EQ(warmup_ms_value, 100u);
    EXPECT_EQ(streams_value, 2u);
    EXPECT_GE(elapsed_ms_value, 120u);
    EXPECT_LE(elapsed_ms_value, 260u);
    EXPECT_GT(measured_bytes_received_value,
              static_cast<std::uint64_t>(client.response_bytes * client.streams));
    EXPECT_LT(wall_elapsed.count(), 900);
}

TEST(QuicPerfBulkTest, TimedDownloadDurationScalesMeasuredBytes) {
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

    const auto short_json_path =
        std::filesystem::temp_directory_path() / "coquic-perf-bulk-timed-short.json";
    const auto long_json_path =
        std::filesystem::temp_directory_path() / "coquic-perf-bulk-timed-long.json";
    std::filesystem::remove(short_json_path);
    std::filesystem::remove(long_json_path);

    const auto run_timed_client =
        [&](std::chrono::milliseconds duration,
            const std::filesystem::path &json_path) -> std::optional<std::uint64_t> {
        const QuicPerfConfig client{
            .role = QuicPerfRole::client,
            .mode = QuicPerfMode::bulk,
            .direction = QuicPerfDirection::download,
            .host = "127.0.0.1",
            .port = port,
            .request_bytes = 0,
            .response_bytes = 4096,
            .streams = 2,
            .connections = 1,
            .requests_in_flight = 1,
            .warmup = std::chrono::milliseconds{100},
            .duration = duration,
            .json_out = json_path,
        };

        if (run_perf_runtime(client) != 0) {
            return std::nullopt;
        }
        const auto json = read_result_text(json_path);
        return json_first_u64_field(json, "bytes_received");
    };

    const auto short_bytes = run_timed_client(std::chrono::milliseconds{60}, short_json_path);
    const auto long_bytes = run_timed_client(std::chrono::milliseconds{240}, long_json_path);
    ASSERT_TRUE(short_bytes.has_value());
    ASSERT_TRUE(long_bytes.has_value());
    const auto short_bytes_value = short_bytes.value_or(0);
    const auto long_bytes_value = long_bytes.value_or(0);
    EXPECT_GT(long_bytes_value, short_bytes_value + 8192u);
}
} // namespace
