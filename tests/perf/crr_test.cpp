#include <array>
#include <filesystem>

#include <gtest/gtest.h>

#include "bench/coquic-perf/perf_client.h"
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
    const auto result_json = read_result_text(json_path);
    if (result_json.find("\"mode\":\"crr\"") == std::string::npos) {
        ADD_FAILURE() << "CRR result did not report CRR mode";
    }
    if (result_json.find("\"requests_completed\":8") == std::string::npos) {
        ADD_FAILURE() << "CRR result did not report completed requests";
    }
    if (result_json.find("\"connections\":2") == std::string::npos) {
        ADD_FAILURE() << "CRR result did not report connection count";
    }
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
    const auto result_json = read_result_text(json_path);
    if (result_json.find("\"connections\":3") == std::string::npos) {
        ADD_FAILURE() << "CRR result did not report connection limit";
    }
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
    EXPECT_TRUE(timed_crr_drain_complete_for_test(connections));
}

TEST(QuicPerfCrrTest, CloseRequestedConnectionsDoNotConsumeActiveSlots) {
    std::array<QuicPerfDrainStateSnapshot, 4> connections{{
        QuicPerfDrainStateSnapshot{.close_requested = false},
        QuicPerfDrainStateSnapshot{.close_requested = true},
        QuicPerfDrainStateSnapshot{.close_requested = false},
        QuicPerfDrainStateSnapshot{.close_requested = true},
    }};

    EXPECT_EQ(active_crr_connections_for_test(connections), 2u);
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
        .duration = std::chrono::milliseconds{1000},
        .json_out = json_path,
    };

    EXPECT_EQ(run_perf_runtime(client), 0);
    const auto result_json = read_result_text(json_path);
    const auto warmup_ms = json_u64_field(result_json, "warmup_ms");
    const auto elapsed_ms = json_u64_field(result_json, "elapsed_ms");
    const auto connections = json_u64_field(result_json, "connections");
    const auto requests_completed = json_u64_field(result_json, "requests_completed");
    const auto server_bytes_sent =
        json_u64_field_in_object(result_json, "server_counters", "bytes_sent");
    const auto server_bytes_received =
        json_u64_field_in_object(result_json, "server_counters", "bytes_received");
    const auto server_requests_completed =
        json_u64_field_in_object(result_json, "server_counters", "requests_completed");

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

    if (warmup_ms_value != 100u) {
        ADD_FAILURE() << "unexpected CRR warmup duration";
    }
    if (connections_value != 6u) {
        ADD_FAILURE() << "unexpected CRR connection count";
    }
    if (elapsed_ms_value < 900u) {
        ADD_FAILURE() << "CRR measurement ended too early";
    }
    if (elapsed_ms_value > 1250u) {
        ADD_FAILURE() << "CRR measurement ran too long";
    }
    if (requests_completed_value == 0u) {
        ADD_FAILURE() << "CRR did not complete requests";
    }
    if (server_bytes_sent_value == 0u) {
        ADD_FAILURE() << "CRR server did not send bytes";
    }
    if (server_bytes_received_value == 0u) {
        ADD_FAILURE() << "CRR server did not receive bytes";
    }
    if (server_requests_completed_value != requests_completed_value) {
        ADD_FAILURE() << "server request count did not match client result";
    }
}
} // namespace
