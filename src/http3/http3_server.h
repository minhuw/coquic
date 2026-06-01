#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <unordered_map>
#include <vector>

#include "src/http3/http3_connection.h"

namespace coquic::http3 {

struct Http3ServerEndpointTestAccess;

struct Http3ServerConfig {
    Http3SettingsSnapshot local_settings;
    std::function<std::optional<Http3Response>(const Http3RequestHead &)> request_head_handler;
    std::function<Http3Response(const Http3Request &)> request_handler;
    std::function<Http3Response(const Http3Request &)> fallback_request_handler;
    std::function<bool(std::uint64_t, Http3Request)> deferred_request_handler;
    std::function<std::optional<Http3Response>(std::uint64_t)> deferred_response_handler;
    std::function<std::optional<Http3ResponsePart>(std::uint64_t)> deferred_response_part_handler;
    std::function<void(std::uint64_t)> deferred_request_cancel_handler;
};

struct Http3ServerRequestCancelledEvent {
    std::uint64_t stream_id = 0;
    std::optional<Http3RequestHead> head;
    std::vector<std::byte> body;
    Http3Headers trailers;
    std::uint64_t application_error_code = 0;
};

struct Http3ServerEndpointUpdate {
    std::vector<quic::QuicCoreInput> core_inputs;
    std::vector<Http3ServerRequestCancelledEvent> request_cancelled_events;
    bool has_pending_work = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};

class Http3ServerEndpoint {
  public:
    explicit Http3ServerEndpoint(Http3ServerConfig config = {});

    Http3ServerEndpointUpdate on_core_result(const quic::QuicCoreResult &result,
                                             quic::QuicCoreTimePoint now);
    Http3ServerEndpointUpdate poll(quic::QuicCoreTimePoint now);

    bool has_failed() const;
    bool has_pending_deferred_responses() const;
    void cancel_pending_deferred_responses();

  private:
    friend struct Http3ServerEndpointTestAccess;

    struct PendingRequest {
        std::optional<Http3RequestHead> head;
        std::vector<std::byte> body;
        Http3Headers trailers;
        bool early_response_committed = false;
    };

    struct PendingDeferredResponse {
        Http3RequestHead head;
        bool final_head_sent = false;
        bool finished = false;
    };

    bool cancel_pending_deferred_response(std::uint64_t stream_id);
    void cancel_deferred_responses_interrupted_by_peer(const quic::QuicCoreResult &result);

    Http3ServerConfig config_;
    Http3Connection connection_;
    bool failed_ = false;
    std::unordered_map<std::uint64_t, PendingRequest> pending_requests_;
    std::unordered_map<std::uint64_t, PendingDeferredResponse> pending_deferred_responses_;
};

} // namespace coquic::http3
