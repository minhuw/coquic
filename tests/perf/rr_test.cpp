#include <array>
#include <filesystem>

#include <gtest/gtest.h>

#include "src/perf/perf_client.h"
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

TEST(QuicPerfRrTest, HighRequestsInFlightReservesCapacityForControlStream) {
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
        std::filesystem::temp_directory_path() / "coquic-perf-rr-control-stream-budget.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::rr,
        .host = "127.0.0.1",
        .port = port,
        .request_bytes = 32,
        .response_bytes = 32,
        .requests = 16,
        .requests_in_flight = 16,
        .duration = std::chrono::milliseconds{500},
        .json_out = json_path,
    };

    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto json = read_result_text(json_path);
    EXPECT_NE(json.find("\"requests_completed\":16"), std::string::npos);
}

TEST(QuicPerfRrTest, FixedRequestCompletesWithMultipleConfiguredConnections) {
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
        std::filesystem::temp_directory_path() / "coquic-perf-rr-fixed-multi-conn.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::rr,
        .host = "127.0.0.1",
        .port = port,
        .request_bytes = 16,
        .response_bytes = 16,
        .connections = 4,
        .requests = 8,
        .requests_in_flight = 2,
        .duration = std::chrono::milliseconds{500},
        .json_out = json_path,
    };

    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto json = read_result_text(json_path);
    EXPECT_NE(json.find("\"requests_completed\":8"), std::string::npos);
}

TEST(QuicPerfRrTest, TimedWindowUsesMeasurementOnly) {
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

    const auto json_path = std::filesystem::temp_directory_path() / "coquic-perf-rr-timed.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::rr,
        .host = "127.0.0.1",
        .port = port,
        .request_bytes = 32,
        .response_bytes = 32,
        .connections = 4,
        .requests_in_flight = 2,
        .warmup = std::chrono::milliseconds{100},
        .duration = std::chrono::milliseconds{150},
        .json_out = json_path,
    };

    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto json = read_result_text(json_path);
    const auto warmup_ms = json_u64_field(json, "warmup_ms");
    const auto elapsed_ms = json_u64_field(json, "elapsed_ms");
    const auto connections = json_u64_field(json, "connections");
    const auto requests_completed = json_u64_field(json, "requests_completed");
    const auto server_bytes_sent = json_u64_field_in_object(json, "server_counters", "bytes_sent");
    const auto server_bytes_received =
        json_u64_field_in_object(json, "server_counters", "bytes_received");
    const auto server_requests_completed =
        json_u64_field_in_object(json, "server_counters", "requests_completed");

    ASSERT_TRUE(warmup_ms.has_value());
    ASSERT_TRUE(elapsed_ms.has_value());
    ASSERT_TRUE(connections.has_value());
    ASSERT_TRUE(requests_completed.has_value());
    ASSERT_TRUE(server_bytes_sent.has_value());
    ASSERT_TRUE(server_bytes_received.has_value());
    ASSERT_TRUE(server_requests_completed.has_value());

    const std::uint64_t warmup_ms_value = warmup_ms.value_or(0);
    const std::uint64_t elapsed_ms_value = elapsed_ms.value_or(0);
    const std::uint64_t connections_value = connections.value_or(0);
    const std::uint64_t requests_completed_value = requests_completed.value_or(0);
    const std::uint64_t server_bytes_sent_value = server_bytes_sent.value_or(0);
    const std::uint64_t server_bytes_received_value = server_bytes_received.value_or(0);
    const std::uint64_t server_requests_completed_value = server_requests_completed.value_or(0);

    EXPECT_EQ(warmup_ms_value, 100u);
    EXPECT_EQ(connections_value, 4u);
    EXPECT_GE(elapsed_ms_value, 100u);
    EXPECT_LE(elapsed_ms_value, 350u);
    EXPECT_GT(requests_completed_value, 0u);
    EXPECT_GT(server_bytes_sent_value, 0u);
    EXPECT_GT(server_bytes_received_value, 0u);
    EXPECT_EQ(server_requests_completed_value, requests_completed_value);
}

TEST(QuicPerfRrTest, TimedDrainCompletesAfterCloseRequestsDrainOutstandingResponses) {
    std::array<QuicPerfDrainStateSnapshot, 2> connections{{
        QuicPerfDrainStateSnapshot{
            .control_complete = false,
            .close_requested = true,
            .outstanding_requests = 0,
        },
        QuicPerfDrainStateSnapshot{
            .control_complete = true,
            .close_requested = true,
            .outstanding_requests = 0,
        },
    }};

    EXPECT_TRUE(timed_rr_drain_complete_for_test(connections));

    connections[1].outstanding_requests = 1;
    EXPECT_FALSE(timed_rr_drain_complete_for_test(connections));
}

TEST(QuicPerfRrTest, TimedModeUsesConfiguredInitialConnectionFanout) {
    QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::rr,
        .connections = 4,
    };

    EXPECT_EQ(initial_connection_target_for_test(client), 4u);
}

TEST(QuicPerfRrTest, PrintsHumanReadableSummaryToStdout) {
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
        std::filesystem::temp_directory_path() / "coquic-perf-rr-stdout-summary.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::rr,
        .host = "127.0.0.1",
        .port = port,
        .request_bytes = 24,
        .response_bytes = 24,
        .requests = 8,
        .requests_in_flight = 2,
        .duration = std::chrono::milliseconds{500},
        .json_out = json_path,
    };

    testing::internal::CaptureStdout();
    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto stdout_output = testing::internal::GetCapturedStdout();

    EXPECT_NE(stdout_output.find("status=ok"), std::string::npos);
    EXPECT_NE(stdout_output.find("mode=rr"), std::string::npos);
    EXPECT_NE(stdout_output.find("requests/s="), std::string::npos);
    EXPECT_FALSE(read_result_text(json_path).empty());
}

} // namespace
