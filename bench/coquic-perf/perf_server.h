#pragma once

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "src/io/io_backend_factory.h"
#include "bench/coquic-perf/perf_loop.h"
#include "bench/coquic-perf/perf_protocol.h"
#include "bench/coquic-perf/perf_runtime.h"
#include "src/quic/crypto/crypto_stream.h"

namespace coquic::perf {

std::optional<std::string> validate_perf_session_start(const QuicPerfSessionStart &start);
int run_perf_server(const QuicPerfConfig &config);

class QuicPerfServer {
  public:
    QuicPerfServer(const QuicPerfConfig &config, std::unique_ptr<io::QuicIoBackend> backend);
    int run();

  private:
    struct Session {
        quic::QuicConnectionHandle connection = 0;
        std::vector<std::byte> control_bytes;
        std::optional<QuicPerfSessionStart> start;
        bool ready_sent = false;
        bool complete_sent = false;
        std::uint64_t bytes_sent = 0;
        std::uint64_t bytes_received = 0;
        std::uint64_t requests_completed = 0;
        quic::SharedBytes fixed_response_payload;
    };

    quic::QuicCoreResult advance_endpoint(quic::QuicCoreEndpointInput input,
                                          quic::QuicCoreTimePoint now);
    bool handle_result(quic::QuicCoreResult result, quic::QuicCoreTimePoint now);
    bool drain_pending_backend_events();
    bool flush_pending_sends();
    bool handle_stream_data(Session &session, const quic::QuicCoreReceiveStreamData &received,
                            quic::QuicCoreTimePoint now);
    bool should_exit_on_idle_empty() const;
    bool should_exit_on_session_complete() const;
    bool completed_sessions_drained_for_exit() const;
    const quic::SharedBytes &cached_download_payload(std::size_t bytes);
    bool send_control(Session &session, const QuicPerfControlMessage &message);

    QuicPerfConfig config_;
    quic::QuicCore core_;
    std::unique_ptr<io::QuicIoBackend> backend_;
    std::unordered_map<std::size_t, quic::SharedBytes> download_payload_cache_;
    std::unordered_map<quic::QuicConnectionHandle, Session> sessions_;
    PerfSendBuffer send_buffer_;
    bool accepted_session_ = false;
    bool completed_session_seen_ = false;
};

} // namespace coquic::perf
