#include <array>
#include <filesystem>

#include <gtest/gtest.h>

#include "src/perf/perf_client.h"
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

TEST(QuicPerfCrrTest, ClientOpenConfigUsesDistinctConnectionIdsBeyond256Connections) {
    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::crr,
    };

    const auto first = make_client_open_config_for_test(client, 0);
    const auto wrapped = make_client_open_config_for_test(client, 256);

    EXPECT_NE(first.source_connection_id, wrapped.source_connection_id);
    EXPECT_NE(first.initial_destination_connection_id, wrapped.initial_destination_connection_id);
}

TEST(QuicPerfCrrTest, TimedDrainCompletesAfterCloseRequestsDrainOutstandingResponses) {
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

    EXPECT_TRUE(timed_crr_drain_complete_for_test(connections));

    connections[0].outstanding_requests = 1;
    EXPECT_FALSE(timed_crr_drain_complete_for_test(connections));
}

TEST(QuicPerfCrrTest, TimedWindowUsesMeasurementOnly) {
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

    const auto json_path = std::filesystem::temp_directory_path() / "coquic-perf-crr-timed.json";
    std::filesystem::remove(json_path);

    const QuicPerfConfig client{
        .role = QuicPerfRole::client,
        .mode = QuicPerfMode::crr,
        .host = "127.0.0.1",
        .port = port,
        .request_bytes = 32,
        .response_bytes = 32,
        .connections = 6,
        .requests_in_flight = 1,
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
    EXPECT_EQ(connections_value, 6u);
    EXPECT_GE(elapsed_ms_value, 100u);
    EXPECT_LE(elapsed_ms_value, 350u);
    EXPECT_GT(requests_completed_value, 0u);
    EXPECT_GT(server_bytes_sent_value, 0u);
    EXPECT_GT(server_bytes_received_value, 0u);
    EXPECT_EQ(server_requests_completed_value, requests_completed_value);
}
} // namespace
