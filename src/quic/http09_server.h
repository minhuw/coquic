#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <vector>

#include "src/quic/http09.h"

namespace coquic::quic {

namespace test {
struct QuicHttp09ServerEndpointTestPeer;
}

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

    struct PendingResponse {
        std::ifstream file;
    };

    QuicHttp09EndpointUpdate make_failure_update() const;
    QuicHttp09EndpointUpdate drain_pending_inputs();
    void pump_response_chunks(std::size_t max_chunks);
    bool process_receive_stream_data(const QuicCoreReceiveStreamData &received);
    void clear_state();

    QuicHttp09ServerConfig config_;
    bool failed_ = false;
    std::unordered_map<std::uint64_t, PendingRequest> pending_requests_;
    std::unordered_map<std::uint64_t, PendingResponse> pending_responses_;
    std::deque<QuicCoreInput> pending_core_inputs_;

    friend struct test::QuicHttp09ServerEndpointTestPeer;
};

} // namespace coquic::quic
