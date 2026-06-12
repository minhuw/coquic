#include "coquic/http3.h"

#include <algorithm>
#include <iterator>
#include <ranges>
#include <type_traits>
#include <utility>

#include "src/http3/http3_client.h"
#include "src/http3/http3_server.h"

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

namespace coquic::http3 {

namespace {

::coquic::http3::Http3SettingsSnapshot to_internal(const Settings &settings) {
    return ::coquic::http3::Http3SettingsSnapshot{
        .qpack_max_table_capacity = settings.qpack_max_table_capacity,
        .qpack_blocked_streams = settings.qpack_blocked_streams,
        .max_field_section_size = settings.max_field_section_size,
        .enable_connect_protocol = settings.enable_connect_protocol,
        .h3_datagram = settings.h3_datagram,
    };
}

Settings from_internal(const ::coquic::http3::Http3SettingsSnapshot &settings) {
    return Settings{
        .qpack_max_table_capacity = settings.qpack_max_table_capacity,
        .qpack_blocked_streams = settings.qpack_blocked_streams,
        .max_field_section_size = settings.max_field_section_size,
        .enable_connect_protocol = settings.enable_connect_protocol,
        .h3_datagram = settings.h3_datagram,
    };
}

::coquic::http3::Http3Field to_internal(const Field &field) {
    return ::coquic::http3::Http3Field{
        .name = field.name,
        .value = field.value,
    };
}

Field from_internal(const ::coquic::http3::Http3Field &field) {
    return Field{
        .name = field.name,
        .value = field.value,
    };
}

::coquic::http3::Http3Headers to_internal(const Headers &headers) {
    ::coquic::http3::Http3Headers out;
    out.reserve(headers.size());
    std::ranges::transform(headers, std::back_inserter(out),
                           [](const auto &field) { return to_internal(field); });
    return out;
}

Headers from_internal(const ::coquic::http3::Http3Headers &headers) {
    Headers out;
    out.reserve(headers.size());
    std::ranges::transform(headers, std::back_inserter(out),
                           [](const auto &field) { return from_internal(field); });
    return out;
}

::coquic::http3::Http3RequestHead to_internal(const RequestHead &head) {
    return ::coquic::http3::Http3RequestHead{
        .method = head.method,
        .scheme = head.scheme,
        .authority = head.authority,
        .path = head.path,
        .protocol = head.protocol,
        .content_length = head.content_length,
        .headers = to_internal(head.headers),
    };
}

RequestHead from_internal(const ::coquic::http3::Http3RequestHead &head) {
    return RequestHead{
        .method = head.method,
        .scheme = head.scheme,
        .authority = head.authority,
        .path = head.path,
        .protocol = head.protocol,
        .content_length = head.content_length,
        .headers = from_internal(head.headers),
    };
}

::coquic::http3::Http3ResponseHead to_internal(const ResponseHead &head) {
    return ::coquic::http3::Http3ResponseHead{
        .status = head.status,
        .content_length = head.content_length,
        .headers = to_internal(head.headers),
    };
}

ResponseHead from_internal(const ::coquic::http3::Http3ResponseHead &head) {
    return ResponseHead{
        .status = head.status,
        .content_length = head.content_length,
        .headers = from_internal(head.headers),
    };
}

::coquic::http3::Http3Request to_internal(const Request &request) {
    return ::coquic::http3::Http3Request{
        .head = to_internal(request.head),
        .body = request.body,
        .trailers = to_internal(request.trailers),
    };
}

Request from_internal(const ::coquic::http3::Http3Request &request) {
    return Request{
        .head = from_internal(request.head),
        .body = request.body,
        .trailers = from_internal(request.trailers),
    };
}

Response from_internal(const ::coquic::http3::Http3Response &response) {
    Response out{
        .body = response.body,
        .trailers = from_internal(response.trailers),
    };
    out.interim_heads.reserve(response.interim_heads.size());
    std::ranges::transform(response.interim_heads, std::back_inserter(out.interim_heads),
                           [](const auto &head) { return from_internal(head); });
    out.head = from_internal(response.head);
    return out;
}

::coquic::http3::Http3Response to_internal(const Response &response) {
    ::coquic::http3::Http3Response out{
        .head = to_internal(response.head),
        .body = response.body,
        .trailers = to_internal(response.trailers),
    };
    out.interim_heads.reserve(response.interim_heads.size());
    std::ranges::transform(response.interim_heads, std::back_inserter(out.interim_heads),
                           [](const auto &head) { return to_internal(head); });
    return out;
}

ErrorCode from_internal(::coquic::http3::Http3ErrorCode code) {
    return static_cast<ErrorCode>(static_cast<std::uint16_t>(code));
}

Error from_internal(const ::coquic::http3::Http3Error &error) {
    return Error{
        .code = from_internal(error.code),
        .detail = error.detail,
        .stream_id = error.stream_id,
    };
}

PriorityUpdateEvent from_internal(const ::coquic::http3::Http3PriorityUpdateEvent &event) {
    return PriorityUpdateEvent{
        .id = event.id,
        .push = event.push,
        .priority_field_value = event.priority_field_value,
    };
}

DatagramEvent from_internal(const ::coquic::http3::Http3DatagramEvent &event) {
    return DatagramEvent{
        .stream_id = event.stream_id,
        .payload = event.payload,
    };
}

core::ConnectionInput from_internal(::coquic::quic::QuicCoreInput input) {
    return std::visit(
        [](auto &&value) -> core::ConnectionInput {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, ::coquic::quic::QuicCoreSendStreamData>) {
                return core::SendStreamData{
                    .stream_id = value.stream_id,
                    .bytes = std::move(value.bytes),
                    .fin = value.fin,
                    .priority = value.priority,
                };
            } else if constexpr (std::is_same_v<T, ::coquic::quic::QuicCoreSendDatagramData>) {
                return core::SendDatagramData{
                    .bytes = std::move(value.bytes),
                    .priority = value.priority,
                };
            } else if constexpr (std::is_same_v<T, ::coquic::quic::QuicCoreResetStream>) {
                return core::ResetStream{
                    .stream_id = value.stream_id,
                    .application_error_code = value.application_error_code,
                };
            } else if constexpr (std::is_same_v<T, ::coquic::quic::QuicCoreStopSending>) {
                return core::StopSending{
                    .stream_id = value.stream_id,
                    .application_error_code = value.application_error_code,
                };
            } else if constexpr (std::is_same_v<T, ::coquic::quic::QuicCoreCloseConnection>) {
                return core::CloseConnection{
                    .application_error_code = value.application_error_code,
                    .reason_phrase = std::move(value.reason_phrase),
                };
            } else if constexpr (std::is_same_v<T, ::coquic::quic::QuicCoreRequestKeyUpdate>) {
                return core::RequestKeyUpdate{};
            } else if constexpr (std::is_same_v<
                                     T, ::coquic::quic::QuicCoreRequestConnectionMigration>) {
                return core::RequestConnectionMigration{
                    .route_handle = value.route_handle,
                    .reason = value.reason ==
                                      ::coquic::quic::QuicMigrationRequestReason::preferred_address
                                  ? core::MigrationReason::preferred_address
                                  : core::MigrationReason::active,
                    .address_validation_identity = std::move(value.address_validation_identity),
                };
            } else {
                return core::CloseConnection{
                    .application_error_code = static_cast<std::uint64_t>(ErrorCode::internal_error),
                    .reason_phrase = "unsupported HTTP/3 endpoint-level command",
                };
            }
        },
        std::move(input));
}

std::vector<core::ConnectionInput>
connection_inputs_from(std::vector<::coquic::quic::QuicCoreInput> inputs) {
    std::vector<core::ConnectionInput> out;
    out.reserve(inputs.size());
    for (auto &input : inputs) {
        out.push_back(from_internal(std::move(input)));
    }
    return out;
}

::coquic::quic::QuicCoreEffect to_internal(const core::Effect &effect) {
    return std::visit(
        [](const auto &value) -> ::coquic::quic::QuicCoreEffect {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, core::ReceiveStreamData>) {
                return ::coquic::quic::QuicCoreReceiveStreamData{
                    .connection = value.connection,
                    .stream_id = value.stream_id,
                    .offset = value.offset,
                    .bytes = value.bytes,
                    .fin = value.fin,
                    .final_size = value.final_size,
                };
            } else if constexpr (std::is_same_v<T, core::ReceiveDatagramData>) {
                return ::coquic::quic::QuicCoreReceiveDatagramData{
                    .connection = value.connection,
                    .bytes = value.bytes,
                };
            } else if constexpr (std::is_same_v<T, core::PeerResetStream>) {
                return ::coquic::quic::QuicCorePeerResetStream{
                    .connection = value.connection,
                    .stream_id = value.stream_id,
                    .application_error_code = value.application_error_code,
                    .final_size = value.final_size,
                };
            } else if constexpr (std::is_same_v<T, core::PeerStopSending>) {
                return ::coquic::quic::QuicCorePeerStopSending{
                    .connection = value.connection,
                    .stream_id = value.stream_id,
                    .application_error_code = value.application_error_code,
                };
            } else if constexpr (std::is_same_v<T, core::StateEvent>) {
                ::coquic::quic::QuicCoreStateChange change =
                    ::coquic::quic::QuicCoreStateChange::failed;
                if (value.change == core::StateChange::handshake_ready) {
                    change = ::coquic::quic::QuicCoreStateChange::handshake_ready;
                } else if (value.change == core::StateChange::handshake_confirmed) {
                    change = ::coquic::quic::QuicCoreStateChange::handshake_confirmed;
                }
                return ::coquic::quic::QuicCoreStateEvent{
                    .connection = value.connection,
                    .change = change,
                };
            } else if constexpr (std::is_same_v<T, core::ZeroRttStatusEvent>) {
                ::coquic::quic::QuicZeroRttStatus status =
                    ::coquic::quic::QuicZeroRttStatus::not_attempted;
                if (value.status == core::ZeroRttStatus::unavailable) {
                    status = ::coquic::quic::QuicZeroRttStatus::unavailable;
                } else if (value.status == core::ZeroRttStatus::attempted) {
                    status = ::coquic::quic::QuicZeroRttStatus::attempted;
                } else if (value.status == core::ZeroRttStatus::accepted) {
                    status = ::coquic::quic::QuicZeroRttStatus::accepted;
                } else if (value.status == core::ZeroRttStatus::rejected) {
                    status = ::coquic::quic::QuicZeroRttStatus::rejected;
                }
                return ::coquic::quic::QuicCoreZeroRttStatusEvent{
                    .connection = value.connection,
                    .status = status,
                };
            } else {
                return ::coquic::quic::QuicCoreConnectionLifecycleEvent{
                    .connection = 0,
                    .event = ::coquic::quic::QuicCoreConnectionLifecycle::created,
                };
            }
        },
        effect);
}

::coquic::quic::QuicCoreResult to_internal(const core::Result &result) {
    ::coquic::quic::QuicCoreResult out;
    out.effects.reserve(result.effects.size());
    for (const auto &effect : result.effects) {
        out.effects.push_back(to_internal(effect));
    }
    out.next_wakeup = result.next_wakeup;
    out.send_continuation_pending = result.send_continuation_pending;
    if (result.local_error.has_value()) {
        out.local_error = ::coquic::quic::QuicCoreLocalError{
            .connection = result.local_error->connection,
            .code = ::coquic::quic::QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = result.local_error->stream_id,
        };
    }
    return out;
}

::coquic::http3::Http3ServerConfig to_internal(ServerConfig config) {
    ::coquic::http3::Http3ServerConfig out{
        .local_settings = to_internal(config.local_settings),
    };
    if (config.request_head_handler) {
        auto handler = std::move(config.request_head_handler);
        out.request_head_handler =
            [handler = std::move(handler)](const ::coquic::http3::Http3RequestHead &head)
            -> std::optional<::coquic::http3::Http3Response> {
            const auto response = handler(from_internal(head));
            if (!response.has_value()) {
                return std::nullopt;
            }
            return to_internal(*response);
        };
    }
    if (config.request_handler) {
        auto handler = std::move(config.request_handler);
        out.request_handler =
            [handler = std::move(handler)](
                const ::coquic::http3::Http3Request &request) -> ::coquic::http3::Http3Response {
            return to_internal(handler(from_internal(request)));
        };
    }
    if (config.fallback_request_handler) {
        auto handler = std::move(config.fallback_request_handler);
        out.fallback_request_handler =
            [handler = std::move(handler)](
                const ::coquic::http3::Http3Request &request) -> ::coquic::http3::Http3Response {
            return to_internal(handler(from_internal(request)));
        };
    }
    return out;
}

ClientUpdate from_internal(::coquic::http3::Http3ClientEndpointUpdate update) {
    ClientUpdate out{
        .quic_inputs = connection_inputs_from(std::move(update.core_inputs)),
        .has_pending_work = update.has_pending_work,
        .terminal_failure = update.terminal_failure,
        .handled_local_error = update.handled_local_error,
    };
    out.responses.reserve(update.events.size());
    for (const auto &event : update.events) {
        out.responses.push_back(ClientResponseEvent{
            .stream_id = event.stream_id,
            .request = from_internal(event.request),
            .response = from_internal(event.response),
        });
    }
    out.request_errors.reserve(update.request_error_events.size());
    for (const auto &event : update.request_error_events) {
        out.request_errors.push_back(ClientRequestErrorEvent{
            .stream_id = event.stream_id,
            .request = from_internal(event.request),
            .application_error_code = event.application_error_code,
        });
    }
    out.pushed_responses.reserve(update.push_events.size());
    for (const auto &event : update.push_events) {
        out.pushed_responses.push_back(ClientPushResponseEvent{
            .request_stream_id = event.request_stream_id,
            .push_id = event.push_id,
            .request = from_internal(event.request),
            .response = from_internal(event.response),
        });
    }
    out.push_errors.reserve(update.push_error_events.size());
    for (const auto &event : update.push_error_events) {
        out.push_errors.push_back(ClientPushErrorEvent{
            .push_id = event.push_id,
            .request = event.request.has_value()
                           ? std::optional<RequestHead>(from_internal(*event.request))
                           : std::nullopt,
            .application_error_code = event.application_error_code,
        });
    }
    out.priority_updates.reserve(update.priority_update_events.size());
    for (const auto &event : update.priority_update_events) {
        out.priority_updates.push_back(from_internal(event));
    }
    out.datagrams.reserve(update.datagram_events.size());
    for (const auto &event : update.datagram_events) {
        out.datagrams.push_back(from_internal(event));
    }
    return out;
}

ServerUpdate from_internal(::coquic::http3::Http3ServerEndpointUpdate update) {
    ServerUpdate out{
        .quic_inputs = connection_inputs_from(std::move(update.core_inputs)),
        .has_pending_work = update.has_pending_work,
        .terminal_failure = update.terminal_failure,
        .handled_local_error = update.handled_local_error,
    };
    out.request_cancelled.reserve(update.request_cancelled_events.size());
    for (const auto &event : update.request_cancelled_events) {
        out.request_cancelled.push_back(ServerRequestCancelledEvent{
            .stream_id = event.stream_id,
            .head = event.head.has_value() ? std::optional<RequestHead>(from_internal(*event.head))
                                           : std::nullopt,
            .body = event.body,
            .trailers = from_internal(event.trailers),
            .application_error_code = event.application_error_code,
        });
    }
    out.priority_updates.reserve(update.priority_update_events.size());
    for (const auto &event : update.priority_update_events) {
        out.priority_updates.push_back(from_internal(event));
    }
    out.datagrams.reserve(update.datagram_events.size());
    for (const auto &event : update.datagram_events) {
        out.datagrams.push_back(from_internal(event));
    }
    return out;
}

} // namespace

namespace test {} // namespace test

class Client::Impl {
  public:
    explicit Impl(const ClientConfig &config)
        : client(::coquic::http3::Http3ClientConfig{
              .local_settings = to_internal(config.local_settings),
              .remembered_peer_settings =
                  config.remembered_peer_settings.has_value()
                      ? std::optional<::coquic::http3::Http3SettingsSnapshot>(
                            to_internal(*config.remembered_peer_settings))
                      : std::nullopt,
          }) {
    }

    ::coquic::http3::Http3ClientEndpoint client;
};

Client::Client(const ClientConfig &config) : impl_(std::make_unique<Impl>(config)) {
}

Client::~Client() = default;

Client::Client(Client &&) noexcept = default;

Client &Client::operator=(Client &&) noexcept = default;

Result<StreamId> Client::submit_request(const Request &request) {
    auto submitted = impl_->client.submit_request(to_internal(request));
    if (!submitted.has_value()) {
        return Result<StreamId>(from_internal(submitted.error()));
    }
    return Result<StreamId>(submitted.value());
}

Result<bool> Client::submit_max_push_id(std::uint64_t push_id) {
    auto submitted = impl_->client.submit_max_push_id(push_id);
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Client::cancel_push(std::uint64_t push_id) {
    auto submitted = impl_->client.cancel_push(push_id);
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Client::submit_priority_update_for_request(StreamId stream_id,
                                                        std::string priority_field_value) {
    auto submitted = impl_->client.submit_priority_update_for_request(
        stream_id, std::move(priority_field_value));
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Client::submit_priority_update_for_push(std::uint64_t push_id,
                                                     std::string priority_field_value) {
    auto submitted =
        impl_->client.submit_priority_update_for_push(push_id, std::move(priority_field_value));
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Client::submit_datagram(StreamId stream_id, std::span<const std::byte> payload) {
    auto submitted = impl_->client.submit_datagram(stream_id, payload);
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Client::abort_connect_stream(StreamId stream_id) {
    auto submitted = impl_->client.abort_connect_stream(stream_id);
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

ClientUpdate Client::on_quic_result(const core::Result &result, TimePoint now) {
    return from_internal(impl_->client.on_core_result(to_internal(result), now));
}

ClientUpdate Client::poll(TimePoint now) {
    return from_internal(impl_->client.poll(now));
}

bool Client::has_failed() const {
    return impl_->client.has_failed();
}

class Server::Impl {
  public:
    explicit Impl(ServerConfig config) : server(to_internal(std::move(config))) {
    }

    ::coquic::http3::Http3ServerEndpoint server;
};

Server::Server(ServerConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {
}

Server::~Server() = default;

Server::Server(Server &&) noexcept = default;

Server &Server::operator=(Server &&) noexcept = default;

ServerUpdate Server::on_quic_result(const core::Result &result, TimePoint now) {
    return from_internal(impl_->server.on_core_result(to_internal(result), now));
}

ServerUpdate Server::poll(TimePoint now) {
    return from_internal(impl_->server.poll(now));
}

Result<std::uint64_t> Server::submit_push_promise(StreamId request_stream_id,
                                                  const RequestHead &head) {
    auto submitted = impl_->server.submit_push_promise(request_stream_id, to_internal(head));
    if (!submitted.has_value()) {
        return Result<std::uint64_t>(from_internal(submitted.error()));
    }
    return Result<std::uint64_t>(submitted.value());
}

Result<bool> Server::submit_push_response_head(std::uint64_t push_id, const ResponseHead &head) {
    auto submitted = impl_->server.submit_push_response_head(push_id, to_internal(head));
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Server::submit_push_response_body(std::uint64_t push_id,
                                               std::span<const std::byte> body, bool fin) {
    auto submitted = impl_->server.submit_push_response_body(push_id, body, fin);
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Server::submit_push_response_trailers(std::uint64_t push_id,
                                                   std::span<const Field> trailers, bool fin) {
    auto internal_trailers = std::vector<::coquic::http3::Http3Field>{};
    internal_trailers.reserve(trailers.size());
    std::ranges::transform(trailers, std::back_inserter(internal_trailers),
                           [](const auto &field) { return to_internal(field); });
    auto submitted = impl_->server.submit_push_response_trailers(push_id, internal_trailers, fin);
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Server::finish_push_response(std::uint64_t push_id, bool enforce_content_length) {
    auto submitted = impl_->server.finish_push_response(push_id, enforce_content_length);
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Server::cancel_push(std::uint64_t push_id) {
    auto submitted = impl_->server.cancel_push(push_id);
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Server::submit_priority_update_for_request(StreamId stream_id,
                                                        std::string priority_field_value) {
    auto submitted = impl_->server.submit_priority_update_for_request(
        stream_id, std::move(priority_field_value));
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Server::submit_priority_update_for_push(std::uint64_t push_id,
                                                     std::string priority_field_value) {
    auto submitted =
        impl_->server.submit_priority_update_for_push(push_id, std::move(priority_field_value));
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Server::submit_datagram(StreamId stream_id, std::span<const std::byte> payload) {
    auto submitted = impl_->server.submit_datagram(stream_id, payload);
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

Result<bool> Server::abort_connect_stream(StreamId stream_id) {
    auto submitted = impl_->server.abort_connect_stream(stream_id);
    if (!submitted.has_value()) {
        return Result<bool>(from_internal(submitted.error()));
    }
    return Result<bool>(submitted.value());
}

bool Server::has_failed() const {
    return impl_->server.has_failed();
}

core::EndpointConfig client_endpoint_config(core::EndpointConfig config) {
    config.role = core::Role::client;
    config.application_protocol = std::string(kApplicationProtocol);
    return config;
}

core::EndpointConfig server_endpoint_config(core::EndpointConfig config) {
    config.role = core::Role::server;
    config.verify_peer = false;
    config.application_protocol = std::string(kApplicationProtocol);
    return config;
}

} // namespace coquic::http3
