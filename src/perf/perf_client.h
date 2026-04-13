#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "src/io/io_backend_factory.h"
#include "src/perf/perf_loop.h"
#include "src/perf/perf_metrics.h"
#include "src/perf/perf_protocol.h"
#include "src/perf/perf_runtime.h"

namespace coquic::perf {

int run_perf_client(const QuicPerfConfig &config);
std::size_t initial_connection_target_for_test(const QuicPerfConfig &config);
quic::QuicCoreClientConnectionConfig make_client_open_config_for_test(const QuicPerfConfig &config,
                                                                      std::uint64_t index);

struct QuicPerfDrainStateSnapshot {
    bool control_complete = false;
    bool close_requested = false;
    std::size_t outstanding_requests = 0;
    std::size_t active_bulk_streams = 0;
};

bool timed_bulk_download_drain_complete_for_test(
    std::span<const QuicPerfDrainStateSnapshot> connections);
bool timed_rr_drain_complete_for_test(std::span<const QuicPerfDrainStateSnapshot> connections);
bool timed_crr_drain_complete_for_test(std::span<const QuicPerfDrainStateSnapshot> connections);

class QuicPerfClient {
  public:
    explicit QuicPerfClient(const QuicPerfConfig &config);
    int run();

  private:
    enum class BenchmarkPhase : std::uint8_t {
        warmup,
        measure,
        drain,
    };

    struct OutstandingRequest {
        quic::QuicCoreTimePoint started_at{};
        std::size_t received_bytes = 0;
        bool counts_toward_measurement = false;
    };

    struct ConnectionState {
        quic::QuicConnectionHandle handle = 0;
        quic::QuicRouteHandle route_handle = 0;
        bool session_ready = false;
        bool control_complete = false;
        bool close_requested = false;
        std::vector<std::byte> control_bytes;
        std::unordered_map<std::uint64_t, OutstandingRequest> outstanding_requests;
        std::unordered_map<std::uint64_t, bool> active_bulk_streams;
        std::uint64_t next_stream_id = kQuicPerfFirstDataStreamId;
        std::uint64_t bytes_sent = 0;
        std::uint64_t bytes_received = 0;
    };

    bool open_initial_connection(quic::QuicCoreTimePoint now);
    void advance_benchmark_phase(quic::QuicCoreTimePoint now);
    void enter_measure_phase(quic::QuicCoreTimePoint now);
    void enter_drain_phase(quic::QuicCoreTimePoint now);
    bool timed_rr_mode() const;
    bool timed_crr_mode() const;
    bool timed_bulk_download_mode() const;
    bool open_bulk_stream(ConnectionState &connection, quic::QuicCoreTimePoint now,
                          bool counts_toward_measurement);
    bool maybe_close_bulk_connection(ConnectionState &connection, quic::QuicCoreTimePoint now);
    bool benchmark_accepts_new_work() const;
    bool handle_result(const quic::QuicCoreResult &result, quic::QuicCoreTimePoint now);
    bool handle_stream_data(ConnectionState &connection,
                            const quic::QuicCoreReceiveStreamData &received,
                            quic::QuicCoreTimePoint now);
    bool run_complete() const;
    bool maybe_start_bulk_streams(ConnectionState &connection, quic::QuicCoreTimePoint now);
    bool maybe_issue_rr_requests(ConnectionState &connection, quic::QuicCoreTimePoint now);
    bool maybe_issue_crr_request(ConnectionState &connection, quic::QuicCoreTimePoint now);
    bool maybe_close_rr_connection(ConnectionState &connection, quic::QuicCoreTimePoint now);
    bool maybe_close_crr_connection(ConnectionState &connection, quic::QuicCoreTimePoint now);
    std::chrono::milliseconds result_elapsed(quic::QuicCoreTimePoint now) const;
    quic::QuicCoreClientConnectionConfig make_client_open_config(std::uint64_t index) const;
    bool maybe_open_crr_connections(quic::QuicCoreTimePoint now);
    bool flush_json_result() const;

    QuicPerfConfig config_;
    quic::QuicCore core_;
    std::unique_ptr<io::QuicIoBackend> backend_;
    quic::QuicRouteHandle primary_route_handle_ = 0;
    std::unordered_map<quic::QuicConnectionHandle, ConnectionState> connections_;
    std::unordered_set<quic::QuicConnectionHandle> closing_connections_;
    std::size_t requests_started_ = 0;
    std::size_t crr_requests_opened_ = 0;
    std::uint64_t next_connection_index_ = 0;
    BenchmarkPhase phase_ = BenchmarkPhase::warmup;
    quic::QuicCoreTimePoint run_started_at_{};
    quic::QuicCoreTimePoint measure_started_at_{};
    quic::QuicCoreTimePoint measure_deadline_{};
    QuicPerfRunSummary summary_;
};

} // namespace coquic::perf
