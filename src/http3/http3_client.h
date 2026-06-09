#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "src/http3/http3_connection.h"

namespace coquic::http3 {

struct Http3ClientEndpointTestAccess;

struct Http3ClientConfig {
    Http3SettingsSnapshot local_settings;
    std::optional<Http3SettingsSnapshot> remembered_peer_settings;
};

struct Http3ClientResponseEvent {
    std::uint64_t stream_id = 0;
    Http3Request request;
    Http3Response response;
};

struct Http3ClientRequestErrorEvent {
    std::uint64_t stream_id = 0;
    Http3Request request;
    std::uint64_t application_error_code = 0;
};

struct Http3ClientPushResponseEvent {
    std::uint64_t request_stream_id = 0;
    std::uint64_t push_id = 0;
    Http3RequestHead request;
    Http3Response response;
};

struct Http3ClientPushErrorEvent {
    std::uint64_t push_id = 0;
    std::optional<Http3RequestHead> request;
    std::uint64_t application_error_code = 0;
};

struct Http3ClientEndpointUpdate {
    std::vector<quic::QuicCoreInput> core_inputs;
    std::vector<Http3ClientResponseEvent> events;
    std::vector<Http3ClientRequestErrorEvent> request_error_events;
    std::vector<Http3ClientPushResponseEvent> push_events;
    std::vector<Http3ClientPushErrorEvent> push_error_events;
    std::vector<Http3PriorityUpdateEvent> priority_update_events;
    std::vector<Http3DatagramEvent> datagram_events;
    bool has_pending_work = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};

class Http3ClientEndpoint {
  public:
    explicit Http3ClientEndpoint(Http3ClientConfig config = {});

    Http3Result<std::uint64_t> submit_request(Http3Request request);
    Http3Result<bool> submit_max_push_id(std::uint64_t push_id);
    Http3Result<bool> cancel_push(std::uint64_t push_id);
    Http3Result<bool> submit_priority_update_for_request(std::uint64_t stream_id,
                                                         std::string priority_field_value);
    Http3Result<bool> submit_priority_update_for_push(std::uint64_t push_id,
                                                      std::string priority_field_value);
    Http3Result<bool> submit_datagram(std::uint64_t stream_id, std::span<const std::byte> payload);
    Http3Result<bool> abort_connect_stream(std::uint64_t stream_id);
    Http3ClientEndpointUpdate on_core_result(const quic::QuicCoreResult &result,
                                             quic::QuicCoreTimePoint now);
    Http3ClientEndpointUpdate poll(quic::QuicCoreTimePoint now);

    bool has_failed() const;

  private:
    friend struct Http3ClientEndpointTestAccess;

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

    struct PendingPushResponse {
        std::optional<std::uint64_t> request_stream_id;
        std::optional<Http3RequestHead> request;
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
    std::unordered_map<std::uint64_t, PendingPushResponse> pending_push_responses_;

    bool handle_connection_events(Http3ClientEndpointUpdate &update,
                                  std::span<const Http3EndpointEvent> events);
};

} // namespace coquic::http3
