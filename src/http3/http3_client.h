#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "src/http3/http3_connection.h"

namespace coquic::http3 {

struct Http3ClientConfig {
    Http3SettingsSnapshot local_settings;
};

struct Http3ClientResponseEvent {
    std::uint64_t stream_id = 0;
    Http3Request request;
    Http3Response response;
};

struct Http3ClientEndpointUpdate {
    std::vector<quic::QuicCoreInput> core_inputs;
    std::vector<Http3ClientResponseEvent> events;
    bool has_pending_work = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};

class Http3ClientEndpoint {
  public:
    explicit Http3ClientEndpoint(Http3ClientConfig config = {});

    Http3Result<std::uint64_t> submit_request(Http3Request request);
    Http3ClientEndpointUpdate on_core_result(const quic::QuicCoreResult &result,
                                             quic::QuicCoreTimePoint now);
    Http3ClientEndpointUpdate poll(quic::QuicCoreTimePoint now);

    bool has_failed() const;

  private:
    struct PendingRequest {
        std::uint64_t stream_id = 0;
        Http3Request request;
    };

    struct PendingResponse {
        std::vector<Http3ResponseHead> interim_heads;
        std::optional<Http3ResponseHead> head;
        std::vector<std::byte> body;
        Http3Headers trailers;
    };

    Http3ClientConfig config_;
    Http3Connection connection_;
    bool failed_ = false;
    std::uint64_t next_request_stream_id_ = 0;
    std::deque<PendingRequest> pending_requests_;
    std::unordered_map<std::uint64_t, Http3Request> active_requests_;
    std::unordered_map<std::uint64_t, PendingResponse> pending_responses_;

    bool handle_connection_events(Http3ClientEndpointUpdate &update,
                                  std::span<const Http3EndpointEvent> events);
};

} // namespace coquic::http3
