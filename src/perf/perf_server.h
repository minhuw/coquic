#pragma once

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "src/io/io_backend_factory.h"
#include "src/perf/perf_loop.h"
#include "src/perf/perf_protocol.h"
#include "src/perf/perf_runtime.h"
#include "src/quic/crypto_stream.h"

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
        std::uint64_t bytes_sent = 0;
        std::uint64_t bytes_received = 0;
        std::uint64_t requests_completed = 0;
    };

    static constexpr std::size_t kMaxDownloadPayloadCacheEntries = 8;

    bool handle_result(const quic::QuicCoreResult &result, quic::QuicCoreTimePoint now);
    bool handle_stream_data(Session &session, const quic::QuicCoreReceiveStreamData &received,
                            quic::QuicCoreTimePoint now);
    quic::SharedBytes cached_download_payload(std::size_t bytes);
    bool send_control(Session &session, const QuicPerfControlMessage &message);

    QuicPerfConfig config_;
    quic::QuicCore core_;
    std::unique_ptr<io::QuicIoBackend> backend_;
    std::unordered_map<std::size_t, quic::SharedBytes> download_payload_cache_;
    std::vector<std::size_t> download_payload_cache_lru_;
    std::unordered_map<quic::QuicConnectionHandle, Session> sessions_;
};

} // namespace coquic::perf
