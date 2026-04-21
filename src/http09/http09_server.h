#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "src/http09/http09.h"

namespace coquic::http09 {

namespace test {
struct QuicHttp09ServerEndpointTestPeer;
void server_set_forced_file_open_failure_path_for_tests(const std::filesystem::path &path);
void server_clear_forced_file_open_failure_path_for_tests();
} // namespace test

struct QuicHttp09ServerConfig {
    std::filesystem::path document_root;
};

class QuicHttp09ServerEndpoint {
  public:
    explicit QuicHttp09ServerEndpoint(QuicHttp09ServerConfig config);

    QuicHttp09EndpointUpdate on_core_result(const quic::QuicCoreResult &result,
                                            quic::QuicCoreTimePoint now);
    QuicHttp09EndpointUpdate poll(quic::QuicCoreTimePoint now);

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
    bool queue_response_chunk(std::uint64_t stream_id, PendingResponse &response);
    bool process_receive_stream_data(const quic::QuicCoreReceiveStreamData &received);
    void clear_state();

    QuicHttp09ServerConfig config_;
    bool failed_ = false;
    std::unordered_map<std::uint64_t, PendingRequest> pending_requests_;
    std::unordered_map<std::uint64_t, PendingResponse> pending_responses_;
    std::unordered_set<std::uint64_t> closed_streams_;
    std::deque<quic::QuicCoreInput> pending_core_inputs_;

    friend struct test::QuicHttp09ServerEndpointTestPeer;
};

} // namespace coquic::http09
