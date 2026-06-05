#include "coquic/http3.h"

#include <algorithm>
#include <iterator>
#include <ranges>
#include <type_traits>
#include <utility>

#include "src/http3/http3_client.h"
#include "src/http3/http3_server.h"

#if defined(COQUIC_COVERAGE_BUILD)
#define COQUIC_NO_PROFILE
#elif defined(__clang__)
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
    };
}

Settings from_internal(const ::coquic::http3::Http3SettingsSnapshot &settings) {
    return Settings{
        .qpack_max_table_capacity = settings.qpack_max_table_capacity,
        .qpack_blocked_streams = settings.qpack_blocked_streams,
        .max_field_section_size = settings.max_field_section_size,
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

core::ConnectionInput from_internal(::coquic::quic::QuicCoreInput input) {
    return std::visit(
        [](auto &&value) -> core::ConnectionInput {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, ::coquic::quic::QuicCoreSendStreamData>) {
                return core::SendStreamData{
                    .stream_id = value.stream_id,
                    .bytes = std::move(value.bytes),
                    .fin = value.fin,
                };
            } else if constexpr (std::is_same_v<T, ::coquic::quic::QuicCoreSendDatagramData>) {
                return core::SendDatagramData{
                    .bytes = std::move(value.bytes),
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
                    .bytes = value.bytes,
                    .fin = value.fin,
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
    return out;
}

} // namespace

namespace test {

COQUIC_NO_PROFILE bool http3_wrapper_conversion_coverage_for_tests() {
    auto ok = true;
    const auto record = [&ok](bool condition) {
        ok = static_cast<bool>(static_cast<unsigned>(ok) & static_cast<unsigned>(condition));
    };

    Settings settings = from_internal(::coquic::http3::Http3SettingsSnapshot{
        .qpack_max_table_capacity = 8,
        .qpack_blocked_streams = 4,
        .max_field_section_size = 1024,
    });
    record(settings.qpack_max_table_capacity == 8);
    record(settings.qpack_blocked_streams == 4);

    std::vector<::coquic::quic::QuicCoreInput> inputs;
    inputs.push_back(::coquic::quic::QuicCoreSendDatagramData{
        .bytes = {std::byte{0x01}},
    });
    inputs.push_back(::coquic::quic::QuicCoreResetStream{
        .stream_id = 4,
        .application_error_code = 5,
    });
    inputs.push_back(::coquic::quic::QuicCoreStopSending{
        .stream_id = 8,
        .application_error_code = 9,
    });
    inputs.push_back(::coquic::quic::QuicCoreCloseConnection{
        .application_error_code = 10,
        .reason_phrase = "done",
    });
    inputs.push_back(::coquic::quic::QuicCoreRequestKeyUpdate{});
    inputs.push_back(::coquic::quic::QuicCoreRequestConnectionMigration{
        .route_handle = 11,
        .reason = ::coquic::quic::QuicMigrationRequestReason::preferred_address,
        .address_validation_identity = {std::byte{0x02}},
    });
    inputs.push_back(::coquic::quic::QuicCoreRequestConnectionMigration{
        .route_handle = 12,
        .reason = ::coquic::quic::QuicMigrationRequestReason::active,
        .address_validation_identity = {std::byte{0x03}},
    });
    inputs.push_back(::coquic::quic::QuicCoreStart{});
    inputs.push_back(::coquic::quic::QuicCoreInboundDatagram{});
    inputs.push_back(::coquic::quic::QuicCorePathMtuUpdate{});
    inputs.push_back(::coquic::quic::QuicCoreTimerExpired{});
    const auto converted_inputs = connection_inputs_from(std::move(inputs));
    record(converted_inputs.size() == 11);
    record(std::holds_alternative<core::SendDatagramData>(converted_inputs.at(0)));
    record(std::holds_alternative<core::ResetStream>(converted_inputs.at(1)));
    record(std::holds_alternative<core::StopSending>(converted_inputs.at(2)));
    record(std::holds_alternative<core::CloseConnection>(converted_inputs.at(3)));
    record(std::holds_alternative<core::RequestKeyUpdate>(converted_inputs.at(4)));
    record(std::get<core::RequestConnectionMigration>(converted_inputs.at(5)).reason ==
           core::MigrationReason::preferred_address);
    record(std::get<core::RequestConnectionMigration>(converted_inputs.at(6)).reason ==
           core::MigrationReason::active);
    record(std::holds_alternative<core::CloseConnection>(converted_inputs.at(7)));
    record(std::holds_alternative<core::CloseConnection>(converted_inputs.at(8)));
    record(std::holds_alternative<core::CloseConnection>(converted_inputs.at(9)));
    record(std::holds_alternative<core::CloseConnection>(converted_inputs.at(10)));

    core::Result result;
    result.effects = {
        core::ReceiveStreamData{.connection = 1, .stream_id = 0, .bytes = {std::byte{0x03}}},
        core::PeerStopSending{.connection = 1, .stream_id = 0, .application_error_code = 12},
        core::StateEvent{.connection = 1, .change = core::StateChange::handshake_confirmed},
        core::StateEvent{.connection = 1, .change = core::StateChange::failed},
        core::NewTokenAvailable{.connection = 1, .token = {std::byte{0x04}}},
    };
    result.local_error = core::LocalError{
        .connection = 1,
        .code = core::LocalErrorCode::datagram_too_large,
        .stream_id = 0,
    };
    const auto internal_result = to_internal(result);
    record(internal_result.effects.size() == 5);
    record(internal_result.local_error.has_value());
    record(std::holds_alternative<::coquic::quic::QuicCoreReceiveStreamData>(
        internal_result.effects.at(0)));
    record(std::holds_alternative<::coquic::quic::QuicCorePeerStopSending>(
        internal_result.effects.at(1)));
    record(std::get<::coquic::quic::QuicCoreStateEvent>(internal_result.effects.at(2)).change ==
           ::coquic::quic::QuicCoreStateChange::handshake_confirmed);
    record(std::get<::coquic::quic::QuicCoreStateEvent>(internal_result.effects.at(3)).change ==
           ::coquic::quic::QuicCoreStateChange::failed);
    record(std::holds_alternative<::coquic::quic::QuicCoreConnectionLifecycleEvent>(
        internal_result.effects.at(4)));

    auto server_config = to_internal(ServerConfig{
        .request_head_handler = [](const RequestHead &head) -> std::optional<Response> {
            if (head.path == "/defer") {
                return std::nullopt;
            }
            return Response{
                .interim_heads = {{.status = 103, .headers = {{"link", "</x>"}}}},
                .head = {.status = 201, .content_length = 1, .headers = {{"x", "y"}}},
                .body = {std::byte{0x05}},
                .trailers = {{"done", "1"}},
            };
        },
        .request_handler =
            [](const Request &request) {
                return Response{
                    .head = {.status = static_cast<std::uint16_t>(202 + request.body.size())},
                    .body = request.body,
                };
            },
        .fallback_request_handler =
            [](const Request &request) {
                return Response{
                    .head = {.status = static_cast<std::uint16_t>(204 + request.trailers.size())},
                };
            },
    });
    record(static_cast<bool>(server_config.request_head_handler));
    record(static_cast<bool>(server_config.request_handler));
    record(static_cast<bool>(server_config.fallback_request_handler));

    const auto no_head_response =
        server_config.request_head_handler(::coquic::http3::Http3RequestHead{.path = "/defer"});
    const auto head_response =
        server_config.request_head_handler(::coquic::http3::Http3RequestHead{.path = "/now"});
    const auto full_response = server_config.request_handler(::coquic::http3::Http3Request{
        .body = {std::byte{0x06}},
    });
    const auto fallback_response = server_config.fallback_request_handler(
        ::coquic::http3::Http3Request{.trailers = {{"t", "v"}}});

    record(!no_head_response.has_value());
    record(head_response.has_value());
    record(head_response->head.status == 201);
    record(!head_response->interim_heads.empty());
    record(full_response.head.status == 203);
    record(fallback_response.head.status == 205);

    auto
        client_update =
            from_internal(
                ::coquic::http3::Http3ClientEndpointUpdate{
                    .core_inputs =
                        {
                            ::coquic::quic::QuicCoreSendStreamData{
                                .stream_id = 0,
                                .bytes = {std::byte{0x07}},
                                .fin = true,
                            },
                        },
                    .events =
                        {
                            ::coquic::http3::Http3ClientResponseEvent{
                                .stream_id = 0,
                                .request = {.head = {.path = "/ok"}},
                                .response =
                                    {
                                        .interim_heads = {{.status = 103}},
                                        .head = {.status = 204},
                                        .body = {std::byte{0x08}},
                                    },
                            },
                        },
                    .request_error_events =
                        {
                            ::coquic::http3::Http3ClientRequestErrorEvent{
                                .stream_id = 4,
                                .request = {.head = {.path = "/cancelled"}},
                                .application_error_code = 99,
                            },
                        },
                    .has_pending_work = true,
                    .terminal_failure = true,
                    .handled_local_error = true,
                });
    record(client_update.quic_inputs.size() == 1);
    record(std::holds_alternative<core::SendStreamData>(client_update.quic_inputs.front()));
    record(client_update.responses.size() == 1);
    record(client_update.responses.front().stream_id == 0);
    record(client_update.responses.front().response.head.status == 204);
    record(client_update.request_errors.size() == 1);
    record(client_update.request_errors.front().application_error_code == 99);
    record(client_update.has_pending_work);
    record(client_update.terminal_failure);
    record(client_update.handled_local_error);

    auto server_update = from_internal(::coquic::http3::Http3ServerEndpointUpdate{
        .core_inputs =
            {
                ::coquic::quic::QuicCoreRequestKeyUpdate{},
            },
        .request_cancelled_events =
            {
                ::coquic::http3::Http3ServerRequestCancelledEvent{
                    .stream_id = 8,
                    .head = ::coquic::http3::Http3RequestHead{.path = "/head"},
                    .body = {std::byte{0x09}},
                    .trailers = {{"done", "1"}},
                    .application_error_code = 123,
                },
                ::coquic::http3::Http3ServerRequestCancelledEvent{
                    .stream_id = 12,
                    .head = std::nullopt,
                    .application_error_code = 124,
                },
            },
        .has_pending_work = true,
        .terminal_failure = true,
        .handled_local_error = true,
    });
    record(server_update.quic_inputs.size() == 1);
    record(std::holds_alternative<core::RequestKeyUpdate>(server_update.quic_inputs.front()));
    record(server_update.request_cancelled.size() == 2);
    record(server_update.request_cancelled.front().head.has_value());
    record(server_update.request_cancelled.front().head->path == "/head");
    record(!server_update.request_cancelled.back().head.has_value());
    record(server_update.has_pending_work);
    record(server_update.terminal_failure);
    record(server_update.handled_local_error);
    return ok;
}

} // namespace test

class Client::Impl {
  public:
    explicit Impl(const ClientConfig &config)
        : client(::coquic::http3::Http3ClientConfig{
              .local_settings = to_internal(config.local_settings),
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
    config.application_protocol = std::string(kApplicationProtocol);
    return config;
}

} // namespace coquic::http3
