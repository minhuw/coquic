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

  private:
    friend struct Http3ServerEndpointTestAccess;

    struct PendingRequest {
        std::optional<Http3RequestHead> head;
        std::vector<std::byte> body;
        Http3Headers trailers;
        bool early_response_committed = false;
    };

    Http3ServerConfig config_;
    Http3Connection connection_;
    bool failed_ = false;
    std::unordered_map<std::uint64_t, PendingRequest> pending_requests_;
};

} // namespace coquic::http3
