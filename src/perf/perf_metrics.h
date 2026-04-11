#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "src/perf/perf_runtime.h"

namespace coquic::perf {

struct QuicPerfLatencySummary {
    std::uint64_t min_us = 0;
    std::uint64_t avg_us = 0;
    std::uint64_t p50_us = 0;
    std::uint64_t p90_us = 0;
    std::uint64_t p99_us = 0;
    std::uint64_t max_us = 0;
};

struct QuicPerfRunSummary {
    std::uint32_t schema_version = 1;
    std::string status = "ok";
    std::optional<std::string> failure_reason;
    QuicPerfMode mode = QuicPerfMode::bulk;
    QuicPerfDirection direction = QuicPerfDirection::download;
    std::string backend = "socket";
    std::string remote_host = "127.0.0.1";
    std::uint16_t remote_port = 0;
    std::string alpn = "coquic-perf/1";
    std::chrono::milliseconds elapsed{0};
    std::chrono::milliseconds warmup{0};
    std::uint64_t bytes_sent = 0;
    std::uint64_t bytes_received = 0;
    std::uint64_t server_bytes_sent = 0;
    std::uint64_t server_bytes_received = 0;
    std::uint64_t server_requests_completed = 0;
    std::uint64_t requests_completed = 0;
    std::size_t streams = 1;
    std::size_t connections = 1;
    std::size_t requests_in_flight = 1;
    std::size_t request_bytes = 0;
    std::size_t response_bytes = 0;
    std::vector<std::chrono::nanoseconds> latency_samples;
    QuicPerfLatencySummary latency;
    double throughput_mib_per_s = 0.0;
    double throughput_gbit_per_s = 0.0;
    double requests_per_s = 0.0;
};

void finalize_perf_run_summary(QuicPerfRunSummary &summary);
QuicPerfLatencySummary summarize_latency_samples(
    std::vector<std::chrono::nanoseconds> samples); // NOLINT(performance-unnecessary-value-param)
std::string render_perf_summary(const QuicPerfRunSummary &summary);
std::string render_perf_json(const QuicPerfRunSummary &summary);

} // namespace coquic::perf
