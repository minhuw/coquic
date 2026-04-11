#pragma once

#include <cstdint>
#include <deque>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "src/http09/http09.h"

namespace coquic::http09 {

struct QuicHttp09ClientConfig {
    std::vector<QuicHttp09Request> requests;
    std::filesystem::path download_root;
    bool allow_requests_before_handshake_ready = false;
    bool request_key_update = false;
};

class QuicHttp09ClientEndpoint {
  public:
    explicit QuicHttp09ClientEndpoint(QuicHttp09ClientConfig config);

    QuicHttp09EndpointUpdate on_core_result(const quic::QuicCoreResult &result,
                                            quic::QuicCoreTimePoint now);
    QuicHttp09EndpointUpdate poll(quic::QuicCoreTimePoint now);

    bool is_complete() const;
    bool has_failed() const;

  private:
    struct RequestState {
        std::string request_target;
        bool complete = false;
    };

    struct PendingOpenRequest {
        std::size_t request_index = 0;
        std::uint64_t stream_id = 0;
    };

    QuicHttp09EndpointUpdate make_failure_update() const;
    QuicHttp09EndpointUpdate fail_endpoint();
    QuicHttp09EndpointUpdate drain_pending_inputs();
    bool handle_local_error(const quic::QuicCoreLocalError &error);
    void activate_pending_request();
    bool has_unissued_requests() const;
    bool requests_may_be_issued() const;
    bool can_issue_next_request() const;
    std::size_t active_request_count() const;
    std::size_t in_flight_request_count() const;
    std::optional<PendingOpenRequest> take_next_request_to_issue();
    void queue_request_send(const PendingOpenRequest &request);
    bool process_receive_stream_data(const quic::QuicCoreReceiveStreamData &received);
    bool all_streams_complete() const;
    void clear_state();

    QuicHttp09ClientConfig config_;
    bool handshake_ready_ = false;
    bool complete_ = false;
    bool failed_ = false;
    bool key_update_requested_ = false;
    bool blocked_on_stream_limit_ = false;
    std::size_t next_request_index_ = 0;
    std::optional<std::size_t> max_concurrent_requests_;
    std::deque<PendingOpenRequest> pending_open_requests_;
    std::deque<PendingOpenRequest> retry_open_requests_;
    std::unordered_map<std::uint64_t, RequestState> request_streams_;
    std::deque<quic::QuicCoreInput> pending_core_inputs_;
};

} // namespace coquic::http09
