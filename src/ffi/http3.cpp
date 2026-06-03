#include "coquic/ffi/http3.h"

#include "coquic/http3.h"
#include "src/ffi/core_internal.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <new>
#include <optional>
#include <ranges>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

struct coquic_http3_client {
    explicit coquic_http3_client(const coquic::http3::ClientConfig &config) : client(config) {
    }

    coquic::http3::Client client;
};

struct coquic_http3_server {
    explicit coquic_http3_server(coquic::http3::ServerConfig config) : server(std::move(config)) {
    }

    coquic::http3::Server server;
};

namespace {

using TimePoint = coquic::core::TimePoint;

constexpr std::size_t kHttp3SettingsSizeV1 =
    offsetof(coquic_http3_settings_t, max_field_section_size) +
    sizeof(coquic_http3_settings_t::max_field_section_size);
constexpr std::size_t kHttp3ClientConfigSizeV1 =
    offsetof(coquic_http3_client_config_t, local_settings) +
    sizeof(coquic_http3_client_config_t::local_settings);
constexpr std::size_t kHttp3ServerConfigSizeV1 =
    offsetof(coquic_http3_server_config_t, local_settings) +
    sizeof(coquic_http3_server_config_t::local_settings);
constexpr std::size_t kHttp3RequestHeadSizeV1 =
    offsetof(coquic_http3_request_head_t, headers_count) +
    sizeof(coquic_http3_request_head_t::headers_count);
constexpr std::size_t kHttp3RequestSizeV1 = offsetof(coquic_http3_request_t, trailers_count) +
                                            sizeof(coquic_http3_request_t::trailers_count);

template <typename F> coquic_status_t ffi_guard(F &&function) noexcept {
    try {
        function();
        return COQUIC_STATUS_OK;
    } catch (const std::bad_alloc &) {
        return COQUIC_STATUS_OUT_OF_MEMORY;
    } catch (...) {
        return COQUIC_STATUS_INTERNAL_ERROR;
    }
}

TimePoint to_time_point(coquic_time_us_t now) {
    return TimePoint{std::chrono::microseconds{static_cast<std::int64_t>(now)}};
}

std::string to_string(const char *data, std::size_t length) {
    if (data == nullptr || length == 0) {
        return {};
    }
    return std::string(data, length);
}

std::vector<std::byte> to_vector(coquic_bytes_t bytes) {
    if (bytes.data == nullptr || bytes.length == 0) {
        return {};
    }
    const auto *begin = reinterpret_cast<const std::byte *>(bytes.data);
    return std::vector<std::byte>(begin, begin + bytes.length);
}

coquic_bytes_view_t bytes_view(const std::string &bytes) {
    return coquic_bytes_view_t{
        .data = reinterpret_cast<const std::uint8_t *>(bytes.data()),
        .length = bytes.size(),
    };
}

coquic_bytes_view_t bytes_view(const std::vector<std::byte> &bytes) {
    return coquic_bytes_view_t{
        .data = reinterpret_cast<const std::uint8_t *>(bytes.data()),
        .length = bytes.size(),
    };
}

coquic_bytes_t bytes_input(const std::vector<std::byte> &bytes) {
    return coquic_bytes_t{
        .data = reinterpret_cast<const std::uint8_t *>(bytes.data()),
        .length = bytes.size(),
    };
}

std::optional<std::uint64_t> to_optional(coquic_http3_optional_u64_t value) {
    if (value.has_value == 0) {
        return std::nullopt;
    }
    return value.value;
}

coquic_http3_optional_u64_t from_optional(std::optional<std::uint64_t> value) {
    if (!value.has_value()) {
        return {.has_value = 0, .value = 0};
    }
    return {.has_value = 1, .value = *value};
}

coquic_optional_stream_id_t from_optional_stream_id(std::optional<coquic::core::StreamId> value) {
    if (!value.has_value()) {
        return {.has_value = 0, .value = 0};
    }
    return {.has_value = 1, .value = *value};
}

coquic_http3_error_code_t from_cpp(coquic::http3::ErrorCode code) {
    return static_cast<coquic_http3_error_code_t>(code);
}

coquic_http3_field_view_t field_view(const coquic::http3::Field &field) {
    return coquic_http3_field_view_t{
        .name = bytes_view(field.name),
        .value = bytes_view(field.value),
    };
}

std::vector<coquic_http3_field_view_t> field_views(const coquic::http3::Headers &headers) {
    std::vector<coquic_http3_field_view_t> out;
    out.reserve(headers.size());
    std::ranges::transform(headers, std::back_inserter(out),
                           [](const auto &field) { return field_view(field); });
    return out;
}

coquic_http3_request_head_view_t head_view(const coquic::http3::RequestHead &head,
                                           const std::vector<coquic_http3_field_view_t> &headers) {
    return coquic_http3_request_head_view_t{
        .method = bytes_view(head.method),
        .scheme = bytes_view(head.scheme),
        .authority = bytes_view(head.authority),
        .path = bytes_view(head.path),
        .content_length = from_optional(head.content_length),
        .headers = headers.data(),
        .headers_count = headers.size(),
    };
}

coquic_http3_response_head_view_t head_view(const coquic::http3::ResponseHead &head,
                                            const std::vector<coquic_http3_field_view_t> &headers) {
    return coquic_http3_response_head_view_t{
        .status = head.status,
        .content_length = from_optional(head.content_length),
        .headers = headers.data(),
        .headers_count = headers.size(),
    };
}

struct StoredRequestHeadView {
    std::vector<coquic_http3_field_view_t> headers;
    coquic_http3_request_head_view_t view{};

    explicit StoredRequestHeadView(const coquic::http3::RequestHead &head)
        : headers(field_views(head.headers)), view(head_view(head, headers)) {
    }
};

struct StoredResponseHeadView {
    std::vector<coquic_http3_field_view_t> headers;
    coquic_http3_response_head_view_t view{};

    explicit StoredResponseHeadView(const coquic::http3::ResponseHead &head)
        : headers(field_views(head.headers)), view(head_view(head, headers)) {
    }
};

struct StoredRequestView {
    StoredRequestHeadView head;
    std::vector<coquic_http3_field_view_t> trailers;
    coquic_http3_request_view_t view{};

    explicit StoredRequestView(const coquic::http3::Request &request)
        : head(request.head), trailers(field_views(request.trailers)),
          view{
              .head = head.view,
              .body = bytes_view(request.body),
              .trailers = trailers.data(),
              .trailers_count = trailers.size(),
          } {
    }
};

struct StoredResponseView {
    std::vector<StoredResponseHeadView> interim_head_storage;
    std::vector<coquic_http3_response_head_view_t> interim_heads;
    StoredResponseHeadView head;
    std::vector<coquic_http3_field_view_t> trailers;
    coquic_http3_response_view_t view{};

    explicit StoredResponseView(const coquic::http3::Response &response)
        : head(response.head), trailers(field_views(response.trailers)) {
        interim_head_storage.reserve(response.interim_heads.size());
        for (const auto &interim : response.interim_heads) {
            interim_head_storage.emplace_back(interim);
        }
        interim_heads.reserve(interim_head_storage.size());
        std::ranges::transform(interim_head_storage, std::back_inserter(interim_heads),
                               [](const auto &stored) { return stored.view; });
        view = coquic_http3_response_view_t{
            .interim_heads = interim_heads.data(),
            .interim_head_count = interim_heads.size(),
            .head = head.view,
            .body = bytes_view(response.body),
            .trailers = trailers.data(),
            .trailers_count = trailers.size(),
        };
    }
};

struct StoredClientResponseEvent {
    StoredRequestView request;
    StoredResponseView response;
    coquic_http3_client_response_event_t view{};

    explicit StoredClientResponseEvent(const coquic::http3::ClientResponseEvent &event)
        : request(event.request), response(event.response), view{
                                                                .stream_id = event.stream_id,
                                                                .request = request.view,
                                                                .response = response.view,
                                                            } {
    }
};

struct StoredClientRequestErrorEvent {
    StoredRequestView request;
    coquic_http3_client_request_error_event_t view{};

    explicit StoredClientRequestErrorEvent(const coquic::http3::ClientRequestErrorEvent &event)
        : request(event.request), view{
                                      .stream_id = event.stream_id,
                                      .request = request.view,
                                      .application_error_code = event.application_error_code,
                                  } {
    }
};

struct StoredServerRequestCancelledEvent {
    std::optional<StoredRequestHeadView> head;
    std::vector<coquic_http3_field_view_t> trailers;
    coquic_http3_server_request_cancelled_event_t view{};

    explicit StoredServerRequestCancelledEvent(
        const coquic::http3::ServerRequestCancelledEvent &event)
        : trailers(field_views(event.trailers)) {
        if (event.head.has_value()) {
            head.emplace(*event.head);
        }
        view = coquic_http3_server_request_cancelled_event_t{
            .stream_id = event.stream_id,
            .has_head = static_cast<std::uint8_t>(head.has_value() ? 1 : 0),
            .head = head.has_value() ? head->view : coquic_http3_request_head_view_t{},
            .body = bytes_view(event.body),
            .trailers = trailers.data(),
            .trailers_count = trailers.size(),
            .application_error_code = event.application_error_code,
        };
    }
};

coquic::http3::Settings to_cpp(coquic_http3_settings_t settings) {
    return coquic::http3::Settings{
        .qpack_max_table_capacity = settings.qpack_max_table_capacity,
        .qpack_blocked_streams = settings.qpack_blocked_streams,
        .max_field_section_size = to_optional(settings.max_field_section_size),
    };
}

coquic::http3::Headers to_headers(const coquic_http3_field_t *fields, std::size_t count) {
    coquic::http3::Headers out;
    if (fields == nullptr || count == 0) {
        return out;
    }
    out.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        out.push_back(coquic::http3::Field{
            .name = to_string(fields[index].name, fields[index].name_length),
            .value = to_string(fields[index].value, fields[index].value_length),
        });
    }
    return out;
}

coquic::http3::RequestHead to_cpp(const coquic_http3_request_head_t &head) {
    return coquic::http3::RequestHead{
        .method = to_string(head.method, head.method_length),
        .scheme = to_string(head.scheme, head.scheme_length),
        .authority = to_string(head.authority, head.authority_length),
        .path = to_string(head.path, head.path_length),
        .content_length = to_optional(head.content_length),
        .headers = to_headers(head.headers, head.headers_count),
    };
}

coquic::http3::Request to_cpp(const coquic_http3_request_t &request) {
    return coquic::http3::Request{
        .head = to_cpp(request.head),
        .body = to_vector(request.body),
        .trailers = to_headers(request.trailers, request.trailers_count),
    };
}

bool valid_settings(const coquic_http3_settings_t &settings) {
    return settings.size >= kHttp3SettingsSizeV1;
}

bool valid_request(const coquic_http3_request_t &request) {
    return request.size >= kHttp3RequestSizeV1 && request.head.size >= kHttp3RequestHeadSizeV1;
}

coquic_connection_input_t from_cpp(const coquic::core::ConnectionInput &input) {
    return std::visit(
        [](const auto &value) -> coquic_connection_input_t {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, coquic::core::SendStreamData>) {
                return coquic_connection_input_t{
                    .kind = COQUIC_CONNECTION_INPUT_SEND_STREAM,
                    .as =
                        {
                            .send_stream =
                                {
                                    .size = sizeof(coquic_send_stream_data_t),
                                    .stream_id = value.stream_id,
                                    .bytes = bytes_input(value.bytes),
                                    .fin = static_cast<std::uint8_t>(value.fin ? 1 : 0),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::SendDatagramData>) {
                return coquic_connection_input_t{
                    .kind = COQUIC_CONNECTION_INPUT_SEND_DATAGRAM,
                    .as =
                        {
                            .send_datagram =
                                {
                                    .size = sizeof(coquic_send_datagram_data_t),
                                    .bytes = bytes_input(value.bytes),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::ResetStream>) {
                return coquic_connection_input_t{
                    .kind = COQUIC_CONNECTION_INPUT_RESET_STREAM,
                    .as =
                        {
                            .reset_stream =
                                {
                                    .size = sizeof(coquic_reset_stream_t),
                                    .stream_id = value.stream_id,
                                    .application_error_code = value.application_error_code,
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::StopSending>) {
                return coquic_connection_input_t{
                    .kind = COQUIC_CONNECTION_INPUT_STOP_SENDING,
                    .as =
                        {
                            .stop_sending =
                                {
                                    .size = sizeof(coquic_stop_sending_t),
                                    .stream_id = value.stream_id,
                                    .application_error_code = value.application_error_code,
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::CloseConnection>) {
                return coquic_connection_input_t{
                    .kind = COQUIC_CONNECTION_INPUT_CLOSE,
                    .as =
                        {
                            .close =
                                {
                                    .size = sizeof(coquic_close_connection_t),
                                    .application_error_code = value.application_error_code,
                                    .reason_phrase = value.reason_phrase.data(),
                                    .reason_phrase_length = value.reason_phrase.size(),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::RequestKeyUpdate>) {
                return coquic_connection_input_t{
                    .kind = COQUIC_CONNECTION_INPUT_REQUEST_KEY_UPDATE,
                    .as = {},
                };
            } else if constexpr (std::is_same_v<T, coquic::core::RequestConnectionMigration>) {
                return coquic_connection_input_t{
                    .kind = COQUIC_CONNECTION_INPUT_REQUEST_MIGRATION,
                    .as =
                        {
                            .request_migration =
                                {
                                    .size = sizeof(coquic_request_connection_migration_t),
                                    .route_handle = value.route_handle,
                                    .reason = static_cast<coquic_migration_reason_t>(
                                        value.reason ==
                                                coquic::core::MigrationReason::preferred_address
                                            ? COQUIC_MIGRATION_REASON_PREFERRED_ADDRESS
                                            : COQUIC_MIGRATION_REASON_ACTIVE),
                                    .address_validation_identity =
                                        bytes_input(value.address_validation_identity),
                                },
                        },
                };
            }
        },
        input);
}

void clear_error(coquic_http3_error_t *error) {
    if (error == nullptr) {
        return;
    }
    auto *detail_buffer = error->detail_buffer;
    const auto detail_buffer_capacity = error->detail_buffer_capacity;
    *error = coquic_http3_error_t{
        .code = COQUIC_HTTP3_ERROR_NO_ERROR,
        .stream_id = {},
        .detail_buffer = detail_buffer,
        .detail_buffer_capacity = detail_buffer_capacity,
        .detail_length = 0,
        .detail_truncated = 0,
    };
    if (detail_buffer != nullptr && detail_buffer_capacity != 0) {
        detail_buffer[0] = '\0';
    }
}

void write_error(const coquic::http3::Error &src, coquic_http3_error_t *dst) {
    if (dst == nullptr) {
        return;
    }

    auto *detail_buffer = dst->detail_buffer;
    const auto detail_buffer_capacity = dst->detail_buffer_capacity;
    *dst = coquic_http3_error_t{
        .code = from_cpp(src.code),
        .stream_id = from_optional_stream_id(src.stream_id),
        .detail_buffer = detail_buffer,
        .detail_buffer_capacity = detail_buffer_capacity,
        .detail_length = src.detail.size(),
        .detail_truncated = 0,
    };

    if (detail_buffer == nullptr || detail_buffer_capacity == 0) {
        dst->detail_truncated = static_cast<std::uint8_t>(src.detail.empty() ? 0 : 1);
        return;
    }

    const auto copy_length = std::min(src.detail.size(), detail_buffer_capacity);
    if (copy_length != 0) {
        std::memcpy(detail_buffer, src.detail.data(), copy_length);
    }
    if (copy_length < src.detail.size()) {
        dst->detail_truncated = 1;
    } else if (copy_length < detail_buffer_capacity) {
        detail_buffer[copy_length] = '\0';
    }
}

template <typename Update>
std::vector<coquic_connection_input_t> input_views(const Update &update) {
    std::vector<coquic_connection_input_t> out;
    out.reserve(update.quic_inputs.size());
    std::ranges::transform(update.quic_inputs, std::back_inserter(out),
                           [](const auto &input) { return from_cpp(input); });
    return out;
}

} // namespace

struct coquic_http3_client_update {
    explicit coquic_http3_client_update(coquic::http3::ClientUpdate value)
        : update(std::move(value)), inputs(input_views(update)) {
        responses.reserve(update.responses.size());
        for (const auto &event : update.responses) {
            responses.emplace_back(event);
        }
        request_errors.reserve(update.request_errors.size());
        for (const auto &event : update.request_errors) {
            request_errors.emplace_back(event);
        }
    }

    coquic::http3::ClientUpdate update;
    std::vector<coquic_connection_input_t> inputs;
    std::vector<StoredClientResponseEvent> responses;
    std::vector<StoredClientRequestErrorEvent> request_errors;
};

struct coquic_http3_server_update {
    explicit coquic_http3_server_update(coquic::http3::ServerUpdate value)
        : update(std::move(value)), inputs(input_views(update)) {
        request_cancelled.reserve(update.request_cancelled.size());
        for (const auto &event : update.request_cancelled) {
            request_cancelled.emplace_back(event);
        }
    }

    coquic::http3::ServerUpdate update;
    std::vector<coquic_connection_input_t> inputs;
    std::vector<StoredServerRequestCancelledEvent> request_cancelled;
};

extern "C" {

void coquic_http3_settings_init(coquic_http3_settings_t *settings) {
    if (settings == nullptr) {
        return;
    }
    const coquic::http3::Settings defaults;
    *settings = coquic_http3_settings_t{
        .size = sizeof(coquic_http3_settings_t),
        .qpack_max_table_capacity = defaults.qpack_max_table_capacity,
        .qpack_blocked_streams = defaults.qpack_blocked_streams,
        .max_field_section_size = from_optional(defaults.max_field_section_size),
    };
}

void coquic_http3_client_config_init(coquic_http3_client_config_t *config) {
    if (config == nullptr) {
        return;
    }
    coquic_http3_settings_t settings{};
    coquic_http3_settings_init(&settings);
    *config = coquic_http3_client_config_t{
        .size = sizeof(coquic_http3_client_config_t),
        .local_settings = settings,
    };
}

void coquic_http3_server_config_init(coquic_http3_server_config_t *config) {
    if (config == nullptr) {
        return;
    }
    coquic_http3_settings_t settings{};
    coquic_http3_settings_init(&settings);
    *config = coquic_http3_server_config_t{
        .size = sizeof(coquic_http3_server_config_t),
        .local_settings = settings,
    };
}

void coquic_http3_client_endpoint_config_init(coquic_endpoint_config_t *config) {
    coquic_endpoint_config_init(config);
    if (config == nullptr) {
        return;
    }
    config->role = COQUIC_ROLE_CLIENT;
    config->application_protocol = "h3";
    config->application_protocol_length = 2;
}

void coquic_http3_server_endpoint_config_init(coquic_endpoint_config_t *config) {
    coquic_endpoint_config_init(config);
    if (config == nullptr) {
        return;
    }
    config->role = COQUIC_ROLE_SERVER;
    config->application_protocol = "h3";
    config->application_protocol_length = 2;
}

coquic_status_t coquic_http3_client_create(const coquic_http3_client_config_t *config,
                                           coquic_http3_client_t **out_client) {
    if (out_client != nullptr) {
        *out_client = nullptr;
    }
    if (config == nullptr || out_client == nullptr || config->size < kHttp3ClientConfigSizeV1 ||
        !valid_settings(config->local_settings)) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] {
        *out_client = new coquic_http3_client(coquic::http3::ClientConfig{
            .local_settings = to_cpp(config->local_settings),
        });
    });
}

void coquic_http3_client_destroy(coquic_http3_client_t *client) {
    delete client;
}

coquic_status_t coquic_http3_client_submit_request(coquic_http3_client_t *client,
                                                   const coquic_http3_request_t *request,
                                                   coquic_stream_id_t *out_stream_id,
                                                   coquic_http3_error_t *out_error) {
    if (out_stream_id != nullptr) {
        *out_stream_id = 0;
    }
    clear_error(out_error);
    if (client == nullptr || request == nullptr || !valid_request(*request) ||
        out_stream_id == nullptr) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] {
        auto submitted = client->client.submit_request(to_cpp(*request));
        if (submitted.has_value()) {
            *out_stream_id = submitted.value();
        } else {
            write_error(submitted.error(), out_error);
        }
    });
}

coquic_status_t coquic_http3_client_on_quic_result(coquic_http3_client_t *client,
                                                   const coquic_result_t *result,
                                                   coquic_time_us_t now,
                                                   coquic_http3_client_update_t **out_update) {
    if (out_update != nullptr) {
        *out_update = nullptr;
    }
    if (client == nullptr || result == nullptr || out_update == nullptr) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] {
        *out_update = new coquic_http3_client_update(
            client->client.on_quic_result(result->result, to_time_point(now)));
    });
}

coquic_status_t coquic_http3_client_poll(coquic_http3_client_t *client, coquic_time_us_t now,
                                         coquic_http3_client_update_t **out_update) {
    if (out_update != nullptr) {
        *out_update = nullptr;
    }
    if (client == nullptr || out_update == nullptr) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] {
        *out_update = new coquic_http3_client_update(client->client.poll(to_time_point(now)));
    });
}

uint8_t coquic_http3_client_has_failed(const coquic_http3_client_t *client) {
    if (client == nullptr) {
        return 0;
    }
    return static_cast<std::uint8_t>(client->client.has_failed() ? 1 : 0);
}

void coquic_http3_client_update_destroy(coquic_http3_client_update_t *update) {
    delete update;
}

size_t
coquic_http3_client_update_connection_input_count(const coquic_http3_client_update_t *update) {
    return update == nullptr ? 0 : update->inputs.size();
}

coquic_status_t
coquic_http3_client_update_connection_input_at(const coquic_http3_client_update_t *update,
                                               size_t index, coquic_connection_input_t *out_input) {
    if (update == nullptr || out_input == nullptr || index >= update->inputs.size()) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_input = update->inputs[index];
    return COQUIC_STATUS_OK;
}

size_t coquic_http3_client_update_response_count(const coquic_http3_client_update_t *update) {
    return update == nullptr ? 0 : update->responses.size();
}

coquic_status_t
coquic_http3_client_update_response_at(const coquic_http3_client_update_t *update, size_t index,
                                       coquic_http3_client_response_event_t *out_event) {
    if (update == nullptr || out_event == nullptr || index >= update->responses.size()) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_event = update->responses[index].view;
    return COQUIC_STATUS_OK;
}

size_t coquic_http3_client_update_request_error_count(const coquic_http3_client_update_t *update) {
    return update == nullptr ? 0 : update->request_errors.size();
}

coquic_status_t
coquic_http3_client_update_request_error_at(const coquic_http3_client_update_t *update,
                                            size_t index,
                                            coquic_http3_client_request_error_event_t *out_event) {
    if (update == nullptr || out_event == nullptr || index >= update->request_errors.size()) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_event = update->request_errors[index].view;
    return COQUIC_STATUS_OK;
}

uint8_t coquic_http3_client_update_has_pending_work(const coquic_http3_client_update_t *update) {
    return update != nullptr && update->update.has_pending_work ? 1 : 0;
}

uint8_t coquic_http3_client_update_terminal_failure(const coquic_http3_client_update_t *update) {
    return update != nullptr && update->update.terminal_failure ? 1 : 0;
}

uint8_t coquic_http3_client_update_handled_local_error(const coquic_http3_client_update_t *update) {
    return update != nullptr && update->update.handled_local_error ? 1 : 0;
}

coquic_status_t coquic_http3_server_create(const coquic_http3_server_config_t *config,
                                           coquic_http3_server_t **out_server) {
    if (out_server != nullptr) {
        *out_server = nullptr;
    }
    if (config == nullptr || out_server == nullptr || config->size < kHttp3ServerConfigSizeV1 ||
        !valid_settings(config->local_settings)) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] {
        *out_server = new coquic_http3_server(coquic::http3::ServerConfig{
            .local_settings = to_cpp(config->local_settings),
        });
    });
}

void coquic_http3_server_destroy(coquic_http3_server_t *server) {
    delete server;
}

coquic_status_t coquic_http3_server_on_quic_result(coquic_http3_server_t *server,
                                                   const coquic_result_t *result,
                                                   coquic_time_us_t now,
                                                   coquic_http3_server_update_t **out_update) {
    if (out_update != nullptr) {
        *out_update = nullptr;
    }
    if (server == nullptr || result == nullptr || out_update == nullptr) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] {
        *out_update = new coquic_http3_server_update(
            server->server.on_quic_result(result->result, to_time_point(now)));
    });
}

coquic_status_t coquic_http3_server_poll(coquic_http3_server_t *server, coquic_time_us_t now,
                                         coquic_http3_server_update_t **out_update) {
    if (out_update != nullptr) {
        *out_update = nullptr;
    }
    if (server == nullptr || out_update == nullptr) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] {
        *out_update = new coquic_http3_server_update(server->server.poll(to_time_point(now)));
    });
}

uint8_t coquic_http3_server_has_failed(const coquic_http3_server_t *server) {
    if (server == nullptr) {
        return 0;
    }
    return static_cast<std::uint8_t>(server->server.has_failed() ? 1 : 0);
}

void coquic_http3_server_update_destroy(coquic_http3_server_update_t *update) {
    delete update;
}

size_t
coquic_http3_server_update_connection_input_count(const coquic_http3_server_update_t *update) {
    return update == nullptr ? 0 : update->inputs.size();
}

coquic_status_t
coquic_http3_server_update_connection_input_at(const coquic_http3_server_update_t *update,
                                               size_t index, coquic_connection_input_t *out_input) {
    if (update == nullptr || out_input == nullptr || index >= update->inputs.size()) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_input = update->inputs[index];
    return COQUIC_STATUS_OK;
}

size_t
coquic_http3_server_update_request_cancelled_count(const coquic_http3_server_update_t *update) {
    return update == nullptr ? 0 : update->request_cancelled.size();
}

coquic_status_t coquic_http3_server_update_request_cancelled_at(
    const coquic_http3_server_update_t *update, size_t index,
    coquic_http3_server_request_cancelled_event_t *out_event) {
    if (update == nullptr || out_event == nullptr || index >= update->request_cancelled.size()) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_event = update->request_cancelled[index].view;
    return COQUIC_STATUS_OK;
}

uint8_t coquic_http3_server_update_has_pending_work(const coquic_http3_server_update_t *update) {
    return update != nullptr && update->update.has_pending_work ? 1 : 0;
}

uint8_t coquic_http3_server_update_terminal_failure(const coquic_http3_server_update_t *update) {
    return update != nullptr && update->update.terminal_failure ? 1 : 0;
}

uint8_t coquic_http3_server_update_handled_local_error(const coquic_http3_server_update_t *update) {
    return update != nullptr && update->update.handled_local_error ? 1 : 0;
}

coquic_status_t coquic_http3_request_view_header_at(const coquic_http3_request_view_t *request,
                                                    size_t index,
                                                    coquic_http3_field_view_t *out_field) {
    if (request == nullptr || out_field == nullptr || index >= request->head.headers_count) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_field = request->head.headers[index];
    return COQUIC_STATUS_OK;
}

coquic_status_t coquic_http3_request_view_trailer_at(const coquic_http3_request_view_t *request,
                                                     size_t index,
                                                     coquic_http3_field_view_t *out_field) {
    if (request == nullptr || out_field == nullptr || index >= request->trailers_count) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_field = request->trailers[index];
    return COQUIC_STATUS_OK;
}

coquic_status_t
coquic_http3_request_head_view_header_at(const coquic_http3_request_head_view_t *head, size_t index,
                                         coquic_http3_field_view_t *out_field) {
    if (head == nullptr || out_field == nullptr || index >= head->headers_count) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_field = head->headers[index];
    return COQUIC_STATUS_OK;
}

coquic_status_t
coquic_http3_response_view_interim_head_at(const coquic_http3_response_view_t *response,
                                           size_t index,
                                           coquic_http3_response_head_view_t *out_head) {
    if (response == nullptr || out_head == nullptr || index >= response->interim_head_count) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_head = response->interim_heads[index];
    return COQUIC_STATUS_OK;
}

coquic_status_t coquic_http3_response_view_header_at(const coquic_http3_response_view_t *response,
                                                     size_t index,
                                                     coquic_http3_field_view_t *out_field) {
    if (response == nullptr || out_field == nullptr || index >= response->head.headers_count) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_field = response->head.headers[index];
    return COQUIC_STATUS_OK;
}

coquic_status_t coquic_http3_response_view_trailer_at(const coquic_http3_response_view_t *response,
                                                      size_t index,
                                                      coquic_http3_field_view_t *out_field) {
    if (response == nullptr || out_field == nullptr || index >= response->trailers_count) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_field = response->trailers[index];
    return COQUIC_STATUS_OK;
}

coquic_status_t
coquic_http3_response_head_view_header_at(const coquic_http3_response_head_view_t *head,
                                          size_t index, coquic_http3_field_view_t *out_field) {
    if (head == nullptr || out_field == nullptr || index >= head->headers_count) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_field = head->headers[index];
    return COQUIC_STATUS_OK;
}

coquic_status_t coquic_http3_server_request_cancelled_view_trailer_at(
    const coquic_http3_server_request_cancelled_event_t *event, size_t index,
    coquic_http3_field_view_t *out_field) {
    if (event == nullptr || out_field == nullptr || index >= event->trailers_count) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_field = event->trailers[index];
    return COQUIC_STATUS_OK;
}

} // extern "C"
