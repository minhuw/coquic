#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "coquic/core.h"

namespace coquic::http3 {

using StreamId = core::StreamId;
using TimePoint = core::TimePoint;

inline constexpr std::string_view kApplicationProtocol = "h3";

enum class ErrorCode : std::uint16_t {
    no_error = 0x0100,
    general_protocol_error = 0x0101,
    internal_error = 0x0102,
    stream_creation_error = 0x0103,
    closed_critical_stream = 0x0104,
    frame_unexpected = 0x0105,
    frame_error = 0x0106,
    excessive_load = 0x0107,
    id_error = 0x0108,
    settings_error = 0x0109,
    missing_settings = 0x010a,
    request_rejected = 0x010b,
    request_cancelled = 0x010c,
    request_incomplete = 0x010d,
    message_error = 0x010e,
    version_fallback = 0x0110,
    qpack_decompression_failed = 0x0200,
    qpack_encoder_stream_error = 0x0201,
    qpack_decoder_stream_error = 0x0202,
};

struct Error {
    ErrorCode code = ErrorCode::general_protocol_error;
    std::string detail;
    std::optional<StreamId> stream_id;
};

template <typename T> class Result {
  public:
    Result(T value) : storage_(std::move(value)) {
    }

    Result(Error error) : storage_(std::move(error)) {
    }

    bool has_value() const {
        return std::holds_alternative<T>(storage_);
    }

    T &value() {
        return std::get<T>(storage_);
    }

    const T &value() const {
        return std::get<T>(storage_);
    }

    Error &error() {
        return std::get<Error>(storage_);
    }

    const Error &error() const {
        return std::get<Error>(storage_);
    }

  private:
    std::variant<T, Error> storage_;
};

struct Field {
    std::string name;
    std::string value;
};

using Headers = std::vector<Field>;

struct Settings {
    std::uint64_t qpack_max_table_capacity = 4096;
    std::uint64_t qpack_blocked_streams = 16;
    std::optional<std::uint64_t> max_field_section_size = 64 * 1024;
};

struct RequestHead {
    std::string method;
    std::string scheme;
    std::string authority;
    std::string path;
    std::optional<std::uint64_t> content_length;
    Headers headers;
};

struct ResponseHead {
    std::uint16_t status = 200;
    std::optional<std::uint64_t> content_length;
    Headers headers;
};

struct Request {
    RequestHead head;
    std::vector<std::byte> body;
    Headers trailers;
};

struct Response {
    std::vector<ResponseHead> interim_heads;
    ResponseHead head;
    std::vector<std::byte> body;
    Headers trailers;
};

struct ClientConfig {
    Settings local_settings;
};

struct ClientResponseEvent {
    StreamId stream_id = 0;
    Request request;
    Response response;
};

struct ClientRequestErrorEvent {
    StreamId stream_id = 0;
    Request request;
    std::uint64_t application_error_code = 0;
};

struct ClientUpdate {
    std::vector<core::ConnectionInput> quic_inputs;
    std::vector<ClientResponseEvent> responses;
    std::vector<ClientRequestErrorEvent> request_errors;
    bool has_pending_work = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};

class Client {
  public:
    explicit Client(const ClientConfig &config = {});
    ~Client();

    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;
    Client(Client &&) noexcept;
    Client &operator=(Client &&) noexcept;

    Result<StreamId> submit_request(const Request &request);
    ClientUpdate on_quic_result(const core::Result &result, TimePoint now);
    ClientUpdate poll(TimePoint now);
    bool has_failed() const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

struct ServerConfig {
    Settings local_settings;
    std::function<std::optional<Response>(const RequestHead &)> request_head_handler;
    std::function<Response(const Request &)> request_handler;
    std::function<Response(const Request &)> fallback_request_handler;
};

struct ServerRequestCancelledEvent {
    StreamId stream_id = 0;
    std::optional<RequestHead> head;
    std::vector<std::byte> body;
    Headers trailers;
    std::uint64_t application_error_code = 0;
};

struct ServerUpdate {
    std::vector<core::ConnectionInput> quic_inputs;
    std::vector<ServerRequestCancelledEvent> request_cancelled;
    bool has_pending_work = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};

class Server {
  public:
    explicit Server(ServerConfig config = {});
    ~Server();

    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;
    Server(Server &&) noexcept;
    Server &operator=(Server &&) noexcept;

    ServerUpdate on_quic_result(const core::Result &result, TimePoint now);
    ServerUpdate poll(TimePoint now);
    bool has_failed() const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

core::EndpointConfig client_endpoint_config(core::EndpointConfig config = {});
core::EndpointConfig server_endpoint_config(core::EndpointConfig config = {});

} // namespace coquic::http3
