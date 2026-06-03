#include <array>
#include <cstdint>
#include <filesystem>
#include <initializer_list>
#include <string_view>

#include "../support/gtest_compat.h"

#include "src/perf/perf_client.h"
#include "tests/support/perf/perf_test_fixtures.h"

namespace {
using namespace coquic::perf;
using namespace coquic::perf::test_support;

bool contains_all(std::string_view text, std::initializer_list<std::string_view> needles) {
    for (const std::string_view needle : needles) {
        if (text.find(needle) == std::string_view::npos) {
            return false;
        }
    }
    return true;
}

bool rr_result_contains(const std::filesystem::path &json_path,
                        std::initializer_list<std::string_view> needles) {
    return contains_all(read_result_text(json_path), needles);
}

bool stdout_summary_contains_rr_metrics(std::string_view stdout_output) {
    return contains_all(stdout_output, {"status=ok", "mode=rr", "requests/s="});
}

testing::AssertionResult
timed_rr_result_uses_measurement_only(const std::filesystem::path &json_path) {
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

    if (!warmup_ms.has_value() || !elapsed_ms.has_value() || !connections.has_value() ||
        !requests_completed.has_value() || !server_bytes_sent.has_value() ||
        !server_bytes_received.has_value() || !server_requests_completed.has_value()) {
        return testing::AssertionFailure() << "timed rr JSON omitted required counters";
    }

    const std::uint64_t elapsed_ms_value = elapsed_ms.value_or(0);
    const std::uint64_t requests_completed_value = requests_completed.value_or(0);
    if (warmup_ms.value_or(0) != 100u) {
        return testing::AssertionFailure() << "warmup_ms was " << warmup_ms.value_or(0);
    }
    if (connections.value_or(0) != 4u) {
        return testing::AssertionFailure() << "connections was " << connections.value_or(0);
    }
    if (elapsed_ms_value < 100u || elapsed_ms_value > 350u) {
        return testing::AssertionFailure() << "elapsed_ms was " << elapsed_ms_value;
    }
    if (requests_completed_value == 0u) {
        return testing::AssertionFailure() << "requests_completed was zero";
    }
    if (server_bytes_sent.value_or(0) == 0u) {
        return testing::AssertionFailure() << "server bytes_sent was zero";
    }
    if (server_bytes_received.value_or(0) == 0u) {
        return testing::AssertionFailure() << "server bytes_received was zero";
    }
    if (server_requests_completed.value_or(0) != requests_completed_value) {
        return testing::AssertionFailure()
               << "server requests_completed was " << server_requests_completed.value_or(0)
               << ", client requests_completed was " << requests_completed_value;
    }
    return testing::AssertionSuccess();
}

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
    EXPECT_TRUE(rr_result_contains(
        json_path, {"\"mode\":\"rr\"", "\"requests_completed\":32", "\"latency\":{"}));
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
    EXPECT_TRUE(rr_result_contains(json_path, {"\"requests_in_flight\":2"}));
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
    EXPECT_TRUE(rr_result_contains(json_path, {"\"requests_completed\":16"}));
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
    EXPECT_TRUE(rr_result_contains(json_path, {"\"requests_completed\":8"}));
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
    EXPECT_TRUE(timed_rr_result_uses_measurement_only(json_path));
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
    EXPECT_TRUE(timed_rr_drain_complete_for_test(connections));
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
    EXPECT_TRUE(stdout_summary_contains_rr_metrics(testing::internal::GetCapturedStdout()));
    EXPECT_FALSE(read_result_text(json_path).empty());
}

} // namespace
