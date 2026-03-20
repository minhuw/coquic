#pragma once

#include <cstdint>
#include <deque>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include "src/quic/http09.h"

namespace coquic::quic {

struct QuicHttp09ClientConfig {
    std::vector<QuicHttp09Request> requests;
    std::filesystem::path download_root;
};

class QuicHttp09ClientEndpoint {
  public:
    explicit QuicHttp09ClientEndpoint(QuicHttp09ClientConfig config);

    QuicHttp09EndpointUpdate on_core_result(const QuicCoreResult &result, QuicCoreTimePoint now);
    QuicHttp09EndpointUpdate poll(QuicCoreTimePoint now);

    bool is_complete() const;
    bool has_failed() const;

  private:
    struct RequestState {
        std::string request_target;
        bool complete = false;
    };

    QuicHttp09EndpointUpdate make_failure_update() const;
    QuicHttp09EndpointUpdate fail_endpoint();
    QuicHttp09EndpointUpdate drain_pending_inputs();
    bool process_receive_stream_data(const QuicCoreReceiveStreamData &received);
    bool all_streams_complete() const;
    void clear_state();

    QuicHttp09ClientConfig config_;
    bool handshake_ready_ = false;
    bool requests_issued_ = false;
    bool complete_ = false;
    bool failed_ = false;
    std::unordered_map<std::uint64_t, RequestState> request_streams_;
    std::deque<QuicCoreInput> pending_core_inputs_;
};

} // namespace coquic::quic
