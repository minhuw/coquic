#include <gtest/gtest.h>

#include "src/perf/perf_metrics.h"

namespace {
using namespace coquic::perf;

TEST(QuicPerfMetricsTest, SummarizesLatencyAndRendersJson) {
    QuicPerfRunSummary summary{
        .schema_version = 1,
        .status = "ok",
        .mode = QuicPerfMode::rr,
        .direction = QuicPerfDirection::download,
        .backend = "socket",
        .remote_host = "127.0.0.1",
        .remote_port = 9443,
        .alpn = "coquic-perf/1",
        .elapsed = std::chrono::milliseconds{1000},
        .warmup = std::chrono::milliseconds{250},
        .bytes_sent = 64000,
        .bytes_received = 96000,
        .server_bytes_received = 64000,
        .server_requests_completed = 1000,
        .requests_completed = 1000,
        .streams = 1,
        .connections = 1,
        .requests_in_flight = 4,
        .request_bytes = 64,
        .response_bytes = 96,
        .latency_samples =
            {
                std::chrono::microseconds{100},
                std::chrono::microseconds{200},
                std::chrono::microseconds{300},
                std::chrono::microseconds{400},
                std::chrono::microseconds{500},
            },
    };

    finalize_perf_run_summary(summary);

    EXPECT_EQ(summary.latency.min_us, 100u);
    EXPECT_EQ(summary.latency.p50_us, 300u);
    EXPECT_EQ(summary.latency.p90_us, 500u);
    EXPECT_EQ(summary.latency.max_us, 500u);
    EXPECT_NE(render_perf_summary(summary).find("requests/s"), std::string::npos);
    EXPECT_NE(render_perf_json(summary).find("\"schema_version\":1"), std::string::npos);
    EXPECT_NE(render_perf_json(summary).find("\"status\":\"ok\""), std::string::npos);
    EXPECT_NE(render_perf_json(summary).find("\"mode\":\"rr\""), std::string::npos);
    EXPECT_NE(render_perf_json(summary).find("\"server_counters\":{"), std::string::npos);
    EXPECT_NE(render_perf_json(summary).find("\"requests_completed\":1000"), std::string::npos);
}
} // namespace
