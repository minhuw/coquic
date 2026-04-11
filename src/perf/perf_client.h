#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "src/io/io_backend_factory.h"
#include "src/perf/perf_loop.h"
#include "src/perf/perf_metrics.h"
#include "src/perf/perf_protocol.h"
#include "src/perf/perf_runtime.h"

namespace coquic::perf {

int run_perf_client(const QuicPerfConfig &config);

class QuicPerfClient {
  public:
    explicit QuicPerfClient(const QuicPerfConfig &config);
    int run();

  private:
    struct ConnectionState {
        quic::QuicConnectionHandle handle = 0;
        quic::QuicRouteHandle route_handle = 0;
        bool session_ready = false;
        bool control_complete = false;
        std::vector<std::byte> control_bytes;
        std::uint64_t next_stream_id = kQuicPerfFirstDataStreamId;
        std::uint64_t bytes_sent = 0;
        std::uint64_t bytes_received = 0;
    };

    bool open_initial_connection(quic::QuicCoreTimePoint now);
    bool handle_result(const quic::QuicCoreResult &result, quic::QuicCoreTimePoint now);
    bool handle_stream_data(ConnectionState &connection,
                            const quic::QuicCoreReceiveStreamData &received,
                            quic::QuicCoreTimePoint now);
    void maybe_start_bulk_streams(ConnectionState &connection, quic::QuicCoreTimePoint now);
    quic::QuicCoreClientConnectionConfig make_client_open_config(std::uint64_t index) const;
    void maybe_open_crr_connections(quic::QuicCoreTimePoint now);
    bool flush_json_result() const;

    QuicPerfConfig config_;
    quic::QuicCore core_;
    std::unique_ptr<io::QuicIoBackend> backend_;
    quic::QuicRouteHandle primary_route_handle_ = 0;
    std::unordered_map<quic::QuicConnectionHandle, ConnectionState> connections_;
    QuicPerfRunSummary summary_;
};

} // namespace coquic::perf
