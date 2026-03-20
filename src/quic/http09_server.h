#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <unordered_map>
#include <vector>

#include "src/quic/http09.h"

namespace coquic::quic {

struct QuicHttp09ServerConfig {
    std::filesystem::path document_root;
};

class QuicHttp09ServerEndpoint {
  public:
    explicit QuicHttp09ServerEndpoint(QuicHttp09ServerConfig config);

    QuicHttp09EndpointUpdate on_core_result(const QuicCoreResult &result, QuicCoreTimePoint now);
    QuicHttp09EndpointUpdate poll(QuicCoreTimePoint now);

    bool has_failed() const;

  private:
    struct PendingRequest {
        std::vector<std::byte> request_bytes;
    };

    QuicHttp09EndpointUpdate make_failure_update() const;
    QuicHttp09EndpointUpdate drain_pending_inputs();
    bool process_receive_stream_data(const QuicCoreReceiveStreamData &received);

    QuicHttp09ServerConfig config_;
    bool failed_ = false;
    std::unordered_map<std::uint64_t, PendingRequest> pending_requests_;
    std::deque<QuicCoreInput> pending_core_inputs_;
};

} // namespace coquic::quic
