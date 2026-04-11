#include "src/perf/perf_metrics.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <string_view>

namespace coquic::perf {
namespace {

std::uint64_t percentile_value(const std::vector<std::uint64_t> &sorted, double percentile) {
    if (sorted.empty()) {
        return 0;
    }
    const auto rank = static_cast<std::size_t>(
        std::ceil((percentile / 100.0) * static_cast<double>(sorted.size())));
    const auto index = rank == 0 ? 0 : std::min(rank - 1, sorted.size() - 1);
    return sorted[index];
}

std::string mode_name(QuicPerfMode mode) {
    switch (mode) {
    case QuicPerfMode::bulk:
        return "bulk";
    case QuicPerfMode::rr:
        return "rr";
    case QuicPerfMode::crr:
        return "crr";
    }
    return "unknown";
}

std::string direction_name(QuicPerfDirection direction) {
    switch (direction) {
    case QuicPerfDirection::upload:
        return "upload";
    case QuicPerfDirection::download:
        return "download";
    }
    return "unknown";
}

std::string json_escape(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        switch (ch) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out += ch;
            break;
        }
    }
    return out;
}

} // namespace

void finalize_perf_run_summary(QuicPerfRunSummary &summary) {
    summary.latency = summarize_latency_samples(summary.latency_samples);
    const auto seconds = std::max(static_cast<double>(summary.elapsed.count()) / 1000.0, 0.001);
    summary.throughput_mib_per_s =
        static_cast<double>(summary.bytes_received + summary.bytes_sent) / (1024.0 * 1024.0) /
        seconds;
    summary.throughput_gbit_per_s =
        static_cast<double>((summary.bytes_received + summary.bytes_sent) * 8) / 1'000'000'000.0 /
        seconds;
    summary.requests_per_s = static_cast<double>(summary.requests_completed) / seconds;
}

QuicPerfLatencySummary summarize_latency_samples(
    std::vector<std::chrono::nanoseconds> samples) { // NOLINT(performance-unnecessary-value-param)
    if (samples.empty()) {
        return {};
    }

    std::vector<std::uint64_t> micros;
    micros.reserve(samples.size());
    for (const auto sample : samples) {
        micros.push_back(static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(sample).count()));
    }
    std::sort(micros.begin(), micros.end());

    const auto total = std::accumulate(micros.begin(), micros.end(), std::uint64_t{0});
    QuicPerfLatencySummary summary;
    summary.min_us = micros.front();
    summary.avg_us = total / micros.size();
    summary.p50_us = percentile_value(micros, 50.0);
    summary.p90_us = percentile_value(micros, 90.0);
    summary.p99_us = percentile_value(micros, 99.0);
    summary.max_us = micros.back();
    return summary;
}

std::string render_perf_summary(const QuicPerfRunSummary &summary) {
    std::ostringstream out;
    out << "status=" << summary.status << " mode=" << mode_name(summary.mode)
        << " direction=" << direction_name(summary.direction) << " throughput_mib/s=" << std::fixed
        << std::setprecision(3) << summary.throughput_mib_per_s
        << " throughput_gbit/s=" << std::fixed << std::setprecision(3)
        << summary.throughput_gbit_per_s << " requests/s=" << std::fixed << std::setprecision(3)
        << summary.requests_per_s;
    return out.str();
}

std::string render_perf_json(const QuicPerfRunSummary &summary) {
    std::ostringstream json;
    json << '{' << "\"schema_version\":" << summary.schema_version << ',' << "\"status\":\""
         << json_escape(summary.status) << "\","
         << "\"mode\":\"" << mode_name(summary.mode) << "\","
         << "\"direction\":\"" << direction_name(summary.direction) << "\","
         << "\"backend\":\"" << json_escape(summary.backend) << "\","
         << "\"remote_host\":\"" << json_escape(summary.remote_host) << "\","
         << "\"remote_port\":" << summary.remote_port << ',' << "\"alpn\":\""
         << json_escape(summary.alpn) << "\","
         << "\"elapsed_ms\":" << summary.elapsed.count() << ','
         << "\"warmup_ms\":" << summary.warmup.count() << ','
         << "\"bytes_sent\":" << summary.bytes_sent << ','
         << "\"bytes_received\":" << summary.bytes_received << ',' << "\"server_counters\":{"
         << "\"bytes_sent\":" << summary.server_bytes_sent << ','
         << "\"bytes_received\":" << summary.server_bytes_received << ','
         << "\"requests_completed\":" << summary.server_requests_completed << "},"
         << "\"requests_completed\":" << summary.requests_completed << ','
         << "\"streams\":" << summary.streams << ',' << "\"connections\":" << summary.connections
         << ',' << "\"requests_in_flight\":" << summary.requests_in_flight << ','
         << "\"request_bytes\":" << summary.request_bytes << ','
         << "\"response_bytes\":" << summary.response_bytes << ','
         << "\"throughput_mib_per_s\":" << std::fixed << std::setprecision(3)
         << summary.throughput_mib_per_s << ',' << "\"throughput_gbit_per_s\":" << std::fixed
         << std::setprecision(3) << summary.throughput_gbit_per_s << ','
         << "\"requests_per_s\":" << std::fixed << std::setprecision(3) << summary.requests_per_s
         << ',' << "\"latency\":{";
    json << "\"min_us\":" << summary.latency.min_us << ','
         << "\"avg_us\":" << summary.latency.avg_us << ','
         << "\"p50_us\":" << summary.latency.p50_us << ','
         << "\"p90_us\":" << summary.latency.p90_us << ','
         << "\"p99_us\":" << summary.latency.p99_us << ','
         << "\"max_us\":" << summary.latency.max_us << '}';
    if (summary.failure_reason.has_value()) {
        json << ",\"failure_reason\":\"" << json_escape(*summary.failure_reason) << "\"";
    }
    json << '}';
    return json.str();
}

} // namespace coquic::perf
