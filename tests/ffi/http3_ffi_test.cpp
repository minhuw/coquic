#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "coquic/ffi/http3.h"
#include "src/ffi/core_internal.h"
#include "src/http3/http3_protocol.h"
#include "src/http3/http3_qpack.h"

namespace {

coquic_bytes_t bytes_view(const std::vector<std::uint8_t> &bytes) {
    return coquic_bytes_t{
        .data = bytes.data(),
        .length = bytes.size(),
    };
}

coquic_http3_request_t make_get_request() {
    return coquic_http3_request_t{
        .size = sizeof(coquic_http3_request_t),
        .head =
            {
                .size = sizeof(coquic_http3_request_head_t),
                .method = "GET",
                .method_length = 3,
                .scheme = "https",
                .scheme_length = 5,
                .authority = "example.test",
                .authority_length = 12,
                .path = "/",
                .path_length = 1,
                .content_length = {},
                .headers = nullptr,
                .headers_count = 0,
            },
        .body = {},
        .trailers = nullptr,
        .trailers_count = 0,
    };
}

std::string_view view_string(coquic_bytes_view_t bytes) {
    return std::string_view(reinterpret_cast<const char *>(bytes.data), bytes.length);
}

std::vector<std::byte> bytes_from_text(std::string_view text) {
    const auto *begin = reinterpret_cast<const std::byte *>(text.data());
    return std::vector<std::byte>(begin, begin + text.size());
}

std::vector<std::uint8_t> u8_from_text(std::string_view text) {
    const auto *begin = reinterpret_cast<const std::uint8_t *>(text.data());
    return std::vector<std::uint8_t>(begin, begin + text.size());
}

coquic_result make_ffi_result(coquic::core::Result result) {
    return coquic_result(std::move(result));
}

coquic_result handshake_ready_result() {
    coquic::core::Result result;
    result.effects.push_back(coquic::core::StateEvent{
        .connection = 1,
        .change = coquic::core::StateChange::handshake_ready,
    });
    return make_ffi_result(std::move(result));
}

coquic_result receive_stream_result(std::uint64_t stream_id, std::vector<std::byte> bytes,
                                    bool fin) {
    coquic::core::Result result;
    result.effects.push_back(coquic::core::ReceiveStreamData{
        .connection = 1,
        .stream_id = stream_id,
        .bytes = std::move(bytes),
        .fin = fin,
    });
    return make_ffi_result(std::move(result));
}

coquic_result receive_datagram_result(std::vector<std::byte> bytes) {
    coquic::core::Result result;
    result.effects.push_back(coquic::core::ReceiveDatagramData{
        .connection = 1,
        .bytes = std::move(bytes),
    });
    return make_ffi_result(std::move(result));
}

coquic_result peer_reset_result(std::uint64_t stream_id, std::uint64_t error_code) {
    coquic::core::Result result;
    result.effects.push_back(coquic::core::PeerResetStream{
        .connection = 1,
        .stream_id = stream_id,
        .application_error_code = error_code,
    });
    return make_ffi_result(std::move(result));
}

std::vector<std::byte> headers_frame_bytes(coquic::http3::Http3QpackEncoderContext &encoder,
                                           std::uint64_t stream_id,
                                           std::span<const coquic::http3::Http3Field> fields) {
    const auto encoded = coquic::http3::encode_http3_field_section(encoder, stream_id, fields);
    EXPECT_TRUE(encoded.has_value());
    if (!encoded.has_value()) {
        return {};
    }

    auto field_section = encoded.value().prefix;
    field_section.insert(field_section.end(), encoded.value().payload.begin(),
                         encoded.value().payload.end());
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3HeadersFrame{
            .field_section = std::move(field_section),
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

std::vector<std::byte> data_frame_bytes(std::string_view payload) {
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3DataFrame{
            .payload = bytes_from_text(payload),
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

std::vector<std::byte> max_push_id_frame_bytes(std::uint64_t push_id) {
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3MaxPushIdFrame{
            .push_id = push_id,
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

std::vector<std::byte>
settings_control_stream_bytes(std::span<const coquic::http3::Http3Setting> settings = {}) {
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3SettingsFrame{
            .settings = std::vector<coquic::http3::Http3Setting>(settings.begin(), settings.end()),
        },
    });
    EXPECT_TRUE(frame.has_value());
    auto out = std::vector<std::byte>{std::byte{0x00}};
    if (frame.has_value()) {
        out.insert(out.end(), frame.value().begin(), frame.value().end());
    }
    return out;
}

std::vector<std::byte> push_stream_bytes(std::uint64_t push_id,
                                         std::span<const std::byte> payload = {}) {
    auto bytes =
        coquic::http3::serialize_http3_uni_stream_prefix(coquic::http3::Http3UniStreamType::push)
            .value();
    const auto encoded_push_id = coquic::quic::encode_varint(push_id).value();
    bytes.insert(bytes.end(), encoded_push_id.begin(), encoded_push_id.end());
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters)
std::vector<std::byte> push_promise_frame_bytes(coquic::http3::Http3QpackEncoderContext &encoder,
                                                std::uint64_t stream_id, std::uint64_t push_id,
                                                std::span<const coquic::http3::Http3Field> fields) {
    // NOLINTEND(bugprone-easily-swappable-parameters)
    const auto encoded = coquic::http3::encode_http3_field_section(encoder, stream_id, fields);
    EXPECT_TRUE(encoded.has_value());
    if (!encoded.has_value()) {
        return {};
    }

    auto field_section = encoded.value().prefix;
    field_section.insert(field_section.end(), encoded.value().payload.begin(),
                         encoded.value().payload.end());
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3PushPromiseFrame{
            .push_id = push_id,
            .field_section = std::move(field_section),
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

void append(std::vector<std::byte> &target, std::vector<std::byte> bytes) {
    target.insert(target.end(), bytes.begin(), bytes.end());
}

void expect_field(coquic_http3_field_view_t field, std::string_view name, std::string_view value) {
    EXPECT_EQ(view_string(field.name), name);
    EXPECT_EQ(view_string(field.value), value);
}

} // namespace

TEST(CoquicHttp3FfiTest, ClientSubmitRequestEmitsPendingWorkAndQuicInputsAfterHandshakeReady) {
    coquic_http3_client_config_t config{};
    coquic_http3_client_config_init(&config);

    coquic_http3_client_t *client = nullptr;
    ASSERT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_OK);
    ASSERT_NE(client, nullptr);

    auto request = make_get_request();
    coquic_stream_id_t stream_id = 999;
    coquic_http3_error_t error{};
    ASSERT_EQ(coquic_http3_client_submit_request(client, &request, &stream_id, &error),
              COQUIC_STATUS_OK);
    EXPECT_EQ(stream_id, 0u);

    coquic_http3_client_update_t *poll_update = nullptr;
    ASSERT_EQ(coquic_http3_client_poll(client, 0, &poll_update), COQUIC_STATUS_OK);
    ASSERT_NE(poll_update, nullptr);
    EXPECT_EQ(coquic_http3_client_update_has_pending_work(poll_update), 1);
    EXPECT_EQ(coquic_http3_client_update_connection_input_count(poll_update), 0u);
    coquic_http3_client_update_destroy(poll_update);

    coquic_endpoint_config_t endpoint_config{};
    coquic_http3_client_endpoint_config_init(&endpoint_config);
    EXPECT_EQ(endpoint_config.role, COQUIC_ROLE_CLIENT);
    EXPECT_EQ(std::string_view(endpoint_config.application_protocol,
                               endpoint_config.application_protocol_length),
              "h3");

    coquic_http3_client_destroy(client);
}

TEST(CoquicHttp3FfiTest, ServerConsumesHandshakeReadyAndEmitsStartupInputs) {
    coquic_http3_server_config_t config{};
    coquic_http3_server_config_init(&config);

    coquic_http3_server_t *server = nullptr;
    ASSERT_EQ(coquic_http3_server_create(&config, &server), COQUIC_STATUS_OK);
    ASSERT_NE(server, nullptr);

    coquic_endpoint_config_t endpoint_config{};
    coquic_http3_server_endpoint_config_init(&endpoint_config);
    EXPECT_EQ(endpoint_config.role, COQUIC_ROLE_SERVER);
    EXPECT_EQ(std::string_view(endpoint_config.application_protocol,
                               endpoint_config.application_protocol_length),
              "h3");

    coquic_http3_server_update_t *update = nullptr;
    ASSERT_EQ(coquic_http3_server_poll(server, 0, &update), COQUIC_STATUS_OK);
    ASSERT_NE(update, nullptr);
    EXPECT_EQ(coquic_http3_server_update_terminal_failure(update), 0);
    EXPECT_EQ(coquic_http3_server_update_connection_input_count(update), 0u);

    coquic_http3_server_update_destroy(update);
    coquic_http3_server_destroy(server);
}

TEST(CoquicHttp3FfiTest, SettingsRequestProtocolAndRememberedSettingsUseV2Fields) {
    coquic_http3_settings_t settings{};
    coquic_http3_settings_init(&settings);
    EXPECT_EQ(settings.size, sizeof(coquic_http3_settings_t));
    EXPECT_EQ(settings.enable_connect_protocol, 0);
    EXPECT_EQ(settings.h3_datagram, 0);

    coquic_http3_client_config_t config{};
    coquic_http3_client_config_init(&config);
    EXPECT_EQ(config.size, sizeof(coquic_http3_client_config_t));
    EXPECT_EQ(config.has_remembered_peer_settings, 0);
    EXPECT_EQ(config.remembered_peer_settings.size, sizeof(coquic_http3_settings_t));

    config.has_remembered_peer_settings = 1;
    config.remembered_peer_settings.enable_connect_protocol = 1;
    config.remembered_peer_settings.h3_datagram = 1;
    coquic_http3_client_t *client = nullptr;
    ASSERT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_OK);
    ASSERT_NE(client, nullptr);
    coquic_http3_client_destroy(client);

    config.remembered_peer_settings.size = 0;
    EXPECT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_INVALID_ARGUMENT);

    coquic_http3_server_config_t server_config{};
    coquic_http3_server_config_init(&server_config);
    server_config.local_settings.enable_connect_protocol = 1;

    coquic_http3_server_t *server = nullptr;
    ASSERT_EQ(coquic_http3_server_create(&server_config, &server), COQUIC_STATUS_OK);
    ASSERT_NE(server, nullptr);
    auto ready = handshake_ready_result();
    coquic_http3_server_update_t *ready_update = nullptr;
    ASSERT_EQ(coquic_http3_server_on_quic_result(server, &ready, 0, &ready_update),
              COQUIC_STATUS_OK);
    coquic_http3_server_update_destroy(ready_update);

    auto request = make_get_request();
    request.head.method = "CONNECT";
    request.head.method_length = 7;
    request.head.path = "/chat";
    request.head.path_length = 5;
    request.head.has_protocol = 1;
    request.head.protocol = "websocket";
    request.head.protocol_length = 9;

    coquic::http3::Http3QpackEncoderContext encoder;
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "CONNECT"},
        coquic::http3::Http3Field{":protocol", "websocket"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/chat"},
    };
    auto request_bytes = headers_frame_bytes(encoder, 0, request_fields);
    auto request_result = receive_stream_result(0, std::move(request_bytes), true);
    coquic_http3_server_update_t *update = nullptr;
    ASSERT_EQ(coquic_http3_server_on_quic_result(server, &request_result, 0, &update),
              COQUIC_STATUS_OK);
    ASSERT_NE(update, nullptr);
    EXPECT_EQ(coquic_http3_server_update_terminal_failure(update), 0);

    coquic_http3_server_update_destroy(update);
    coquic_http3_server_destroy(server);
}

TEST(CoquicHttp3FfiTest, RejectsInvalidArguments) {
    coquic_http3_settings_init(nullptr);
    coquic_http3_client_config_init(nullptr);
    coquic_http3_server_config_init(nullptr);
    coquic_http3_client_endpoint_config_init(nullptr);
    coquic_http3_server_endpoint_config_init(nullptr);
    coquic_http3_client_destroy(nullptr);
    coquic_http3_server_destroy(nullptr);
    coquic_http3_client_update_destroy(nullptr);
    coquic_http3_server_update_destroy(nullptr);

    coquic_http3_settings_t settings{};
    coquic_http3_settings_init(&settings);
    EXPECT_EQ(settings.size, sizeof(coquic_http3_settings_t));
    ASSERT_EQ(settings.max_field_section_size.has_value, 1);
    EXPECT_EQ(settings.max_field_section_size.value, 64u * 1024u);

    coquic_http3_client_t *client = nullptr;
    EXPECT_EQ(coquic_http3_client_create(nullptr, &client), COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(client, nullptr);

    coquic_http3_client_config_t config{};
    coquic_http3_client_config_init(&config);
    config.size = 0;
    EXPECT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_INVALID_ARGUMENT);

    coquic_http3_client_config_init(&config);
    config.local_settings.size = 0;
    EXPECT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_INVALID_ARGUMENT);

    coquic_http3_client_config_init(&config);
    config.local_settings.max_field_section_size = {.has_value = 0, .value = 0};
    ASSERT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_OK);
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(coquic_http3_client_has_failed(nullptr), 0);
    EXPECT_EQ(coquic_http3_client_has_failed(client), 0);

    auto request = make_get_request();
    coquic_stream_id_t stream_id = 0;
    char detail[] = "unchanged";
    coquic_http3_error_t error{
        .code = COQUIC_HTTP3_ERROR_INTERNAL_ERROR,
        .stream_id = {.has_value = 1, .value = 77},
        .detail_buffer = detail,
        .detail_buffer_capacity = sizeof(detail),
        .detail_length = 99,
        .detail_truncated = 1,
    };
    EXPECT_EQ(coquic_http3_client_submit_request(nullptr, &request, &stream_id, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);

    request.size = 0;
    stream_id = 99;
    EXPECT_EQ(coquic_http3_client_submit_request(client, &request, &stream_id, &error),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(stream_id, 0u);
    EXPECT_EQ(error.code, COQUIC_HTTP3_ERROR_NO_ERROR);
    EXPECT_EQ(detail[0], '\0');
    request = make_get_request();
    request.head.size = 0;
    EXPECT_EQ(coquic_http3_client_submit_request(client, &request, &stream_id, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    request = make_get_request();
    EXPECT_EQ(coquic_http3_client_submit_request(client, &request, nullptr, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_submit_max_push_id(nullptr, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_cancel_push(nullptr, 0, nullptr), COQUIC_STATUS_INVALID_ARGUMENT);

    coquic_http3_client_update_t *update = reinterpret_cast<coquic_http3_client_update_t *>(0x1);
    EXPECT_EQ(coquic_http3_client_poll(nullptr, 0, &update), COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(update, nullptr);
    EXPECT_EQ(coquic_http3_client_poll(client, 0, nullptr), COQUIC_STATUS_INVALID_ARGUMENT);

    const auto ready = handshake_ready_result();
    EXPECT_EQ(coquic_http3_client_on_quic_result(nullptr, &ready, 0, &update),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(update, nullptr);
    EXPECT_EQ(coquic_http3_client_on_quic_result(client, nullptr, 0, &update),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_on_quic_result(client, &ready, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);

    EXPECT_EQ(coquic_http3_client_update_connection_input_count(nullptr), 0u);
    EXPECT_EQ(coquic_http3_client_update_response_count(nullptr), 0u);
    EXPECT_EQ(coquic_http3_client_update_request_error_count(nullptr), 0u);
    EXPECT_EQ(coquic_http3_client_update_push_response_count(nullptr), 0u);
    EXPECT_EQ(coquic_http3_client_update_push_error_count(nullptr), 0u);
    EXPECT_EQ(coquic_http3_client_update_priority_update_count(nullptr), 0u);
    EXPECT_EQ(coquic_http3_client_update_datagram_count(nullptr), 0u);
    EXPECT_EQ(coquic_http3_client_update_has_pending_work(nullptr), 0);
    EXPECT_EQ(coquic_http3_client_update_terminal_failure(nullptr), 0);
    EXPECT_EQ(coquic_http3_client_update_handled_local_error(nullptr), 0);
    coquic_connection_input_t input{};
    EXPECT_EQ(coquic_http3_client_update_connection_input_at(nullptr, 0, &input),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_client_response_event_t response_event{};
    EXPECT_EQ(coquic_http3_client_update_response_at(nullptr, 0, &response_event),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_client_request_error_event_t request_error{};
    EXPECT_EQ(coquic_http3_client_update_request_error_at(nullptr, 0, &request_error),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_client_push_response_event_t push_response{};
    EXPECT_EQ(coquic_http3_client_update_push_response_at(nullptr, 0, &push_response),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_client_push_error_event_t push_error{};
    EXPECT_EQ(coquic_http3_client_update_push_error_at(nullptr, 0, &push_error),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_priority_update_event_t priority_update{};
    EXPECT_EQ(coquic_http3_client_update_priority_update_at(nullptr, 0, &priority_update),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_datagram_event_t datagram{};
    EXPECT_EQ(coquic_http3_client_update_datagram_at(nullptr, 0, &datagram),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_submit_priority_update_for_request(nullptr, 0, "u=3", 3, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_submit_priority_update_for_push(nullptr, 0, "u=3", 3, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_submit_datagram(nullptr, 0, {}, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_abort_connect_stream(nullptr, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);

    coquic_http3_client_destroy(client);

    coquic_http3_server_t *server = nullptr;
    EXPECT_EQ(coquic_http3_server_create(nullptr, &server), COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_server_config_t server_config{};
    coquic_http3_server_config_init(&server_config);
    server_config.size = 0;
    EXPECT_EQ(coquic_http3_server_create(&server_config, &server), COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_server_config_init(&server_config);
    server_config.local_settings.size = 0;
    EXPECT_EQ(coquic_http3_server_create(&server_config, &server), COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_server_config_init(&server_config);
    ASSERT_EQ(coquic_http3_server_create(&server_config, &server), COQUIC_STATUS_OK);
    ASSERT_NE(server, nullptr);
    EXPECT_EQ(coquic_http3_server_has_failed(nullptr), 0);
    EXPECT_EQ(coquic_http3_server_has_failed(server), 0);

    coquic_http3_server_update_t *server_update =
        reinterpret_cast<coquic_http3_server_update_t *>(0x1);
    EXPECT_EQ(coquic_http3_server_poll(nullptr, 0, &server_update), COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(server_update, nullptr);
    EXPECT_EQ(coquic_http3_server_poll(server, 0, nullptr), COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_on_quic_result(nullptr, &ready, 0, &server_update),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(server_update, nullptr);
    EXPECT_EQ(coquic_http3_server_on_quic_result(server, nullptr, 0, &server_update),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_on_quic_result(server, &ready, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);

    EXPECT_EQ(coquic_http3_server_update_connection_input_count(nullptr), 0u);
    EXPECT_EQ(coquic_http3_server_update_request_cancelled_count(nullptr), 0u);
    EXPECT_EQ(coquic_http3_server_update_priority_update_count(nullptr), 0u);
    EXPECT_EQ(coquic_http3_server_update_datagram_count(nullptr), 0u);
    EXPECT_EQ(coquic_http3_server_update_has_pending_work(nullptr), 0);
    EXPECT_EQ(coquic_http3_server_update_terminal_failure(nullptr), 0);
    EXPECT_EQ(coquic_http3_server_update_handled_local_error(nullptr), 0);
    EXPECT_EQ(coquic_http3_server_update_connection_input_at(nullptr, 0, &input),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_server_request_cancelled_event_t cancelled{};
    EXPECT_EQ(coquic_http3_server_update_request_cancelled_at(nullptr, 0, &cancelled),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_update_priority_update_at(nullptr, 0, &priority_update),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_update_datagram_at(nullptr, 0, &datagram),
              COQUIC_STATUS_INVALID_ARGUMENT);
    uint64_t push_id = 77;
    coquic_http3_request_head_t request_head = make_get_request().head;
    coquic_http3_response_head_t response_head_input{
        .size = sizeof(coquic_http3_response_head_t),
        .status = 200,
        .content_length = {},
        .headers = nullptr,
        .headers_count = 0,
    };
    EXPECT_EQ(coquic_http3_server_submit_push_promise(nullptr, 0, &request_head, &push_id, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(
        coquic_http3_server_submit_push_response_head(nullptr, 0, &response_head_input, nullptr),
        COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_submit_push_response_body(nullptr, 0, {}, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_submit_push_response_trailers(nullptr, 0, nullptr, 0, 1, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_finish_push_response(nullptr, 0, 1, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_cancel_push(nullptr, 0, nullptr), COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_submit_priority_update_for_request(nullptr, 0, "u=3", 3, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_submit_priority_update_for_push(nullptr, 0, "u=3", 3, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_submit_datagram(nullptr, 0, {}, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_abort_connect_stream(nullptr, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);

    coquic_http3_field_view_t field{};
    coquic_http3_request_view_t request_view{};
    EXPECT_EQ(coquic_http3_request_view_header_at(nullptr, 0, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_request_view_header_at(&request_view, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_request_view_header_at(&request_view, 0, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_request_view_trailer_at(nullptr, 0, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_request_head_view_header_at(nullptr, 0, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_response_view_t response_view{};
    coquic_http3_response_head_view_t response_head_view{};
    EXPECT_EQ(coquic_http3_response_view_interim_head_at(nullptr, 0, &response_head_view),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_response_view_header_at(nullptr, 0, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_response_view_trailer_at(nullptr, 0, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_response_head_view_header_at(nullptr, 0, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_response_view_interim_head_at(&response_view, 0, &response_head_view),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_request_cancelled_view_trailer_at(nullptr, 0, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_request_cancelled_view_trailer_at(&cancelled, 0, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);

    coquic_http3_server_destroy(server);
}

TEST(CoquicHttp3FfiTest, ClientPriorityDatagramAndConnectAbortWrappersExposeOutputs) {
    coquic_http3_client_config_t config{};
    coquic_http3_client_config_init(&config);
    config.local_settings.h3_datagram = 1;
    config.has_remembered_peer_settings = 1;
    config.remembered_peer_settings.h3_datagram = 1;

    coquic_http3_client_t *client = nullptr;
    ASSERT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_OK);
    ASSERT_NE(client, nullptr);

    auto ready = handshake_ready_result();
    coquic_http3_client_update_t *ready_update = nullptr;
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, &ready, 0, &ready_update),
              COQUIC_STATUS_OK);
    ASSERT_NE(ready_update, nullptr);
    coquic_http3_client_update_destroy(ready_update);

    auto settings_result = receive_stream_result(3, settings_control_stream_bytes(), false);
    coquic_http3_client_update_t *settings_update = nullptr;
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, &settings_result, 0, &settings_update),
              COQUIC_STATUS_OK);
    ASSERT_NE(settings_update, nullptr);
    coquic_http3_client_update_destroy(settings_update);

    coquic_http3_error_t error{};
    ASSERT_EQ(coquic_http3_client_submit_priority_update_for_request(client, 0, "u=2", 3, &error),
              COQUIC_STATUS_OK);
    ASSERT_EQ(coquic_http3_client_submit_priority_update_for_push(client, 0, "i", 1, &error),
              COQUIC_STATUS_OK);

    const auto datagram_payload = u8_from_text("hello");
    ASSERT_EQ(coquic_http3_client_submit_datagram(client, 0, bytes_view(datagram_payload), &error),
              COQUIC_STATUS_OK);
    ASSERT_EQ(coquic_http3_client_abort_connect_stream(client, 0, &error), COQUIC_STATUS_OK);

    coquic_http3_client_update_t *update = nullptr;
    ASSERT_EQ(coquic_http3_client_poll(client, 0, &update), COQUIC_STATUS_OK);
    ASSERT_NE(update, nullptr);
    ASSERT_EQ(coquic_http3_client_update_connection_input_count(update), 5u);

    coquic_connection_input_t input{};
    ASSERT_EQ(coquic_http3_client_update_connection_input_at(update, 0, &input), COQUIC_STATUS_OK);
    EXPECT_EQ(input.kind, COQUIC_CONNECTION_INPUT_SEND_STREAM);
    EXPECT_EQ(input.as.send_stream.stream_id, 2u);
    EXPECT_GT(input.as.send_stream.bytes.length, 0u);
    ASSERT_EQ(coquic_http3_client_update_connection_input_at(update, 1, &input), COQUIC_STATUS_OK);
    EXPECT_EQ(input.kind, COQUIC_CONNECTION_INPUT_SEND_STREAM);
    EXPECT_EQ(input.as.send_stream.stream_id, 2u);
    EXPECT_GT(input.as.send_stream.bytes.length, 0u);

    ASSERT_EQ(coquic_http3_client_update_connection_input_at(update, 2, &input), COQUIC_STATUS_OK);
    EXPECT_EQ(input.kind, COQUIC_CONNECTION_INPUT_SEND_DATAGRAM);
    auto parsed_datagram = coquic::http3::parse_http3_datagram(std::span<const std::byte>(
        reinterpret_cast<const std::byte *>(input.as.send_datagram.bytes.data),
        input.as.send_datagram.bytes.length));
    ASSERT_TRUE(parsed_datagram.has_value());
    EXPECT_EQ(parsed_datagram.value().stream_id, 0u);
    EXPECT_EQ(parsed_datagram.value().payload, bytes_from_text("hello"));

    ASSERT_EQ(coquic_http3_client_update_connection_input_at(update, 3, &input), COQUIC_STATUS_OK);
    EXPECT_EQ(input.kind, COQUIC_CONNECTION_INPUT_RESET_STREAM);
    EXPECT_EQ(input.as.reset_stream.stream_id, 0u);
    EXPECT_EQ(input.as.reset_stream.application_error_code, COQUIC_HTTP3_ERROR_CONNECT_ERROR);
    ASSERT_EQ(coquic_http3_client_update_connection_input_at(update, 4, &input), COQUIC_STATUS_OK);
    EXPECT_EQ(input.kind, COQUIC_CONNECTION_INPUT_STOP_SENDING);
    EXPECT_EQ(input.as.stop_sending.stream_id, 0u);
    EXPECT_EQ(input.as.stop_sending.application_error_code, COQUIC_HTTP3_ERROR_CONNECT_ERROR);

    coquic_http3_client_update_destroy(update);

    auto datagram_bytes = coquic::http3::serialize_http3_datagram(0, bytes_from_text("peer"));
    ASSERT_TRUE(datagram_bytes.has_value());
    auto datagram_result = receive_datagram_result(datagram_bytes.value());
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, &datagram_result, 0, &update),
              COQUIC_STATUS_OK);
    ASSERT_NE(update, nullptr);
    ASSERT_EQ(coquic_http3_client_update_datagram_count(update), 1u);
    coquic_http3_datagram_event_t datagram_event{};
    ASSERT_EQ(coquic_http3_client_update_datagram_at(update, 0, &datagram_event), COQUIC_STATUS_OK);
    EXPECT_EQ(datagram_event.stream_id, 0u);
    EXPECT_EQ(view_string(datagram_event.payload), "peer");
    EXPECT_EQ(coquic_http3_client_update_datagram_at(update, 1, &datagram_event),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_client_update_destroy(update);

    coquic_http3_client_destroy(client);
}

TEST(CoquicHttp3FfiTest, ServerPushPriorityDatagramAndAbortWrappersExposeOutputs) {
    coquic_http3_server_config_t config{};
    coquic_http3_server_config_init(&config);
    config.local_settings.h3_datagram = 1;

    coquic_http3_server_t *server = nullptr;
    ASSERT_EQ(coquic_http3_server_create(&config, &server), COQUIC_STATUS_OK);
    ASSERT_NE(server, nullptr);

    auto ready = handshake_ready_result();
    coquic_http3_server_update_t *ready_update = nullptr;
    ASSERT_EQ(coquic_http3_server_on_quic_result(server, &ready, 0, &ready_update),
              COQUIC_STATUS_OK);
    coquic_http3_server_update_destroy(ready_update);

    const std::array peer_settings{
        coquic::http3::Http3Setting{
            .id = coquic::http3::kHttp3SettingsH3Datagram,
            .value = 1,
        },
    };
    auto settings_result =
        receive_stream_result(2, settings_control_stream_bytes(peer_settings), false);
    coquic_http3_server_update_t *settings_update = nullptr;
    ASSERT_EQ(coquic_http3_server_on_quic_result(server, &settings_result, 0, &settings_update),
              COQUIC_STATUS_OK);
    coquic_http3_server_update_destroy(settings_update);

    const auto max_push_frame = max_push_id_frame_bytes(0);
    auto max_push_result = receive_stream_result(2, max_push_frame, false);
    coquic_http3_server_update_t *max_push_update = nullptr;
    ASSERT_EQ(coquic_http3_server_on_quic_result(server, &max_push_result, 0, &max_push_update),
              COQUIC_STATUS_OK);
    coquic_http3_server_update_destroy(max_push_update);

    coquic::http3::Http3QpackEncoderContext encoder;
    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    auto request_bytes = headers_frame_bytes(encoder, 0, request_fields);
    auto request_result = receive_stream_result(0, std::move(request_bytes), true);
    coquic_http3_server_update_t *request_update = nullptr;
    ASSERT_EQ(coquic_http3_server_on_quic_result(server, &request_result, 0, &request_update),
              COQUIC_STATUS_OK);
    coquic_http3_server_update_destroy(request_update);

    auto promised_head = make_get_request().head;
    promised_head.path = "/pushed";
    promised_head.path_length = 7;
    uint64_t push_id = 77;
    coquic_http3_error_t error{};
    ASSERT_EQ(coquic_http3_server_submit_push_promise(server, 0, &promised_head, &push_id, &error),
              COQUIC_STATUS_OK);
    EXPECT_EQ(push_id, 0u);

    coquic_http3_response_head_t response_head{
        .size = sizeof(coquic_http3_response_head_t),
        .status = 200,
        .content_length = {.has_value = 1, .value = 4},
        .headers = nullptr,
        .headers_count = 0,
    };
    ASSERT_EQ(
        coquic_http3_server_submit_push_response_head(server, push_id, &response_head, &error),
        COQUIC_STATUS_OK);
    const auto body = u8_from_text("body");
    ASSERT_EQ(
        coquic_http3_server_submit_push_response_body(server, push_id, bytes_view(body), 0, &error),
        COQUIC_STATUS_OK);
    const coquic_http3_field_t trailers[] = {
        {.name = "etag", .name_length = 4, .value = "done", .value_length = 4},
    };
    ASSERT_EQ(
        coquic_http3_server_submit_push_response_trailers(server, push_id, trailers, 1, 1, &error),
        COQUIC_STATUS_OK);
    ASSERT_EQ(coquic_http3_server_submit_priority_update_for_request(server, 0, "u=1", 3, &error),
              COQUIC_STATUS_OK);
    ASSERT_EQ(coquic_http3_server_submit_priority_update_for_push(server, push_id, "i", 1, &error),
              COQUIC_STATUS_OK);
    const auto datagram_payload = u8_from_text("server");
    ASSERT_EQ(coquic_http3_server_submit_datagram(server, 0, bytes_view(datagram_payload), &error),
              COQUIC_STATUS_OK);
    ASSERT_EQ(coquic_http3_server_abort_connect_stream(server, 0, &error), COQUIC_STATUS_OK);

    coquic_http3_server_update_t *update = nullptr;
    ASSERT_EQ(coquic_http3_server_poll(server, 0, &update), COQUIC_STATUS_OK);
    ASSERT_NE(update, nullptr);
    ASSERT_GT(coquic_http3_server_update_connection_input_count(update), 0u);
    coquic_connection_input_t input{};
    bool saw_control_send = false;
    bool saw_datagram = false;
    bool saw_reset = false;
    bool saw_stop_sending = false;
    for (std::size_t index = 0; index < coquic_http3_server_update_connection_input_count(update);
         ++index) {
        ASSERT_EQ(coquic_http3_server_update_connection_input_at(update, index, &input),
                  COQUIC_STATUS_OK);
        if (input.kind == COQUIC_CONNECTION_INPUT_SEND_STREAM &&
            input.as.send_stream.stream_id == 3u) {
            saw_control_send = true;
        } else if (input.kind == COQUIC_CONNECTION_INPUT_SEND_DATAGRAM) {
            auto parsed_datagram = coquic::http3::parse_http3_datagram(std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(input.as.send_datagram.bytes.data),
                input.as.send_datagram.bytes.length));
            ASSERT_TRUE(parsed_datagram.has_value());
            EXPECT_EQ(parsed_datagram.value().payload, bytes_from_text("server"));
            saw_datagram = true;
        } else if (input.kind == COQUIC_CONNECTION_INPUT_RESET_STREAM &&
                   input.as.reset_stream.application_error_code ==
                       COQUIC_HTTP3_ERROR_CONNECT_ERROR) {
            saw_reset = true;
        } else if (input.kind == COQUIC_CONNECTION_INPUT_STOP_SENDING &&
                   input.as.stop_sending.application_error_code ==
                       COQUIC_HTTP3_ERROR_CONNECT_ERROR) {
            saw_stop_sending = true;
        }
    }
    EXPECT_TRUE(saw_control_send);
    EXPECT_TRUE(saw_datagram);
    EXPECT_TRUE(saw_reset);
    EXPECT_TRUE(saw_stop_sending);
    coquic_http3_server_update_destroy(update);

    auto priority_bytes = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3PriorityUpdateFrame{
            .frame_type = coquic::http3::kHttp3FrameTypePriorityUpdateRequestStream,
            .prioritized_element_id = 0,
            .priority_field_value = "u=0",
        },
    });
    ASSERT_TRUE(priority_bytes.has_value());
    auto priority_result = receive_stream_result(2, priority_bytes.value(), false);
    ASSERT_EQ(coquic_http3_server_on_quic_result(server, &priority_result, 0, &update),
              COQUIC_STATUS_OK);
    ASSERT_NE(update, nullptr);
    ASSERT_EQ(coquic_http3_server_update_priority_update_count(update), 1u);
    coquic_http3_priority_update_event_t priority_event{};
    ASSERT_EQ(coquic_http3_server_update_priority_update_at(update, 0, &priority_event),
              COQUIC_STATUS_OK);
    EXPECT_EQ(priority_event.id, 0u);
    EXPECT_EQ(priority_event.push, 0);
    EXPECT_EQ(view_string(priority_event.priority_field_value), "u=0");
    EXPECT_EQ(coquic_http3_server_update_priority_update_at(update, 1, &priority_event),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_server_update_destroy(update);

    auto datagram_bytes = coquic::http3::serialize_http3_datagram(0, bytes_from_text("client"));
    ASSERT_TRUE(datagram_bytes.has_value());
    auto datagram_result = receive_datagram_result(datagram_bytes.value());
    ASSERT_EQ(coquic_http3_server_on_quic_result(server, &datagram_result, 0, &update),
              COQUIC_STATUS_OK);
    ASSERT_NE(update, nullptr);
    ASSERT_EQ(coquic_http3_server_update_datagram_count(update), 1u);
    coquic_http3_datagram_event_t datagram_event{};
    ASSERT_EQ(coquic_http3_server_update_datagram_at(update, 0, &datagram_event), COQUIC_STATUS_OK);
    EXPECT_EQ(datagram_event.stream_id, 0u);
    EXPECT_EQ(view_string(datagram_event.payload), "client");
    EXPECT_EQ(coquic_http3_server_update_datagram_at(update, 1, &datagram_event),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_server_update_destroy(update);

    coquic_http3_server_destroy(server);
}

TEST(CoquicHttp3FfiTest, SubmitRequestReportsOwnedErrorDetailAfterClientFailure) {
    coquic_http3_client_config_t config{};
    coquic_http3_client_config_init(&config);

    coquic_http3_client_t *client = nullptr;
    ASSERT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_OK);
    ASSERT_NE(client, nullptr);

    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.role = COQUIC_ROLE_CLIENT;
    endpoint_config.verify_peer = 0;

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);

    coquic_send_stream_data_t send{
        .size = sizeof(coquic_send_stream_data_t),
        .stream_id = 0,
        .bytes = {},
        .fin = 1,
    };

    coquic_result_t *result = nullptr;
    ASSERT_EQ(coquic_connection_send_stream(endpoint, 99, &send, 0, &result), COQUIC_STATUS_OK);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(coquic_result_has_local_error(result), 1);

    coquic_http3_client_update_t *update = nullptr;
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, result, 0, &update), COQUIC_STATUS_OK);
    ASSERT_NE(update, nullptr);
    EXPECT_EQ(coquic_http3_client_update_terminal_failure(update), 1);
    EXPECT_EQ(coquic_http3_client_update_handled_local_error(update), 1);
    coquic_http3_client_update_destroy(update);
    coquic_result_destroy(result);
    coquic_endpoint_destroy(endpoint);

    char detail[8] = {};
    coquic_http3_error_t error{
        .detail_buffer = detail,
        .detail_buffer_capacity = sizeof(detail),
    };
    auto request = make_get_request();
    coquic_stream_id_t stream_id = 77;
    ASSERT_EQ(coquic_http3_client_submit_request(client, &request, &stream_id, &error),
              COQUIC_STATUS_OK);
    EXPECT_EQ(stream_id, 0u);
    EXPECT_EQ(error.code, COQUIC_HTTP3_ERROR_GENERAL_PROTOCOL_ERROR);
    EXPECT_EQ(error.stream_id.has_value, 0);
    EXPECT_GT(error.detail_length, sizeof(detail));
    EXPECT_EQ(error.detail_truncated, 1);
    EXPECT_EQ(std::string_view(detail, sizeof(detail)), "client e");

    coquic_http3_client_destroy(client);
}

TEST(CoquicHttp3FfiTest, ClientResponseAndRequestErrorViewsExposeBorrowedFields) {
    coquic_http3_client_config_t config{};
    coquic_http3_client_config_init(&config);

    coquic_http3_client_t *client = nullptr;
    ASSERT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_OK);
    ASSERT_NE(client, nullptr);

    auto ready = handshake_ready_result();
    coquic_http3_client_update_t *ready_update = nullptr;
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, &ready, 0, &ready_update),
              COQUIC_STATUS_OK);
    ASSERT_NE(ready_update, nullptr);
    ASSERT_GT(coquic_http3_client_update_connection_input_count(ready_update), 0u);
    coquic_connection_input_t input{};
    EXPECT_EQ(coquic_http3_client_update_connection_input_at(ready_update, 0, &input),
              COQUIC_STATUS_OK);
    EXPECT_EQ(coquic_http3_client_update_connection_input_at(ready_update, 999, &input),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_update_connection_input_at(ready_update, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_client_update_destroy(ready_update);

    const auto request_body = u8_from_text("ping");
    const coquic_http3_field_t request_headers[] = {
        {.name = "x-client", .name_length = 8, .value = "yes", .value_length = 3},
    };
    const coquic_http3_field_t request_trailers[] = {
        {.name = "x-request-trailer", .name_length = 17, .value = "done", .value_length = 4},
    };
    auto request = make_get_request();
    request.head.method = "POST";
    request.head.method_length = 4;
    request.head.path = "/ffi-response";
    request.head.path_length = 13;
    request.head.content_length = {.has_value = 1, .value = request_body.size()};
    request.head.headers = request_headers;
    request.head.headers_count = 1;
    request.body = bytes_view(request_body);
    request.trailers = request_trailers;
    request.trailers_count = 1;

    coquic_stream_id_t stream_id = 77;
    ASSERT_EQ(coquic_http3_client_submit_request(client, &request, &stream_id, nullptr),
              COQUIC_STATUS_OK);
    EXPECT_EQ(stream_id, 0u);
    coquic_http3_client_update_t *request_update = nullptr;
    ASSERT_EQ(coquic_http3_client_poll(client, 0, &request_update), COQUIC_STATUS_OK);
    ASSERT_NE(request_update, nullptr);
    ASSERT_GT(coquic_http3_client_update_connection_input_count(request_update), 0u);
    coquic_http3_client_update_destroy(request_update);

    coquic::http3::Http3QpackEncoderContext encoder;
    const std::array interim_headers{
        coquic::http3::Http3Field{":status", "103"},
        coquic::http3::Http3Field{"x-hint", "warm"},
    };
    const std::array response_headers{
        coquic::http3::Http3Field{":status", "200"},
        coquic::http3::Http3Field{"content-length", "4"},
        coquic::http3::Http3Field{"x-answer", "yes"},
    };
    const std::array response_trailers{
        coquic::http3::Http3Field{"etag", "done"},
    };
    auto response_bytes = headers_frame_bytes(encoder, 0, interim_headers);
    append(response_bytes, headers_frame_bytes(encoder, 0, response_headers));
    append(response_bytes, data_frame_bytes("pong"));
    append(response_bytes, headers_frame_bytes(encoder, 0, response_trailers));

    auto response_result = receive_stream_result(0, std::move(response_bytes), true);
    coquic_http3_client_update_t *response_update = nullptr;
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, &response_result, 0, &response_update),
              COQUIC_STATUS_OK);
    ASSERT_NE(response_update, nullptr);
    ASSERT_EQ(coquic_http3_client_update_response_count(response_update), 1u);
    EXPECT_EQ(coquic_http3_client_update_request_error_count(response_update), 0u);

    coquic_http3_client_response_event_t event{};
    ASSERT_EQ(coquic_http3_client_update_response_at(response_update, 0, &event), COQUIC_STATUS_OK);
    EXPECT_EQ(event.stream_id, 0u);
    EXPECT_EQ(view_string(event.request.head.path), "/ffi-response");
    EXPECT_EQ(view_string(event.request.body), "ping");
    EXPECT_EQ(event.request.head.content_length.has_value, 1);
    EXPECT_EQ(event.request.head.content_length.value, request_body.size());
    EXPECT_EQ(event.response.interim_head_count, 1u);
    EXPECT_EQ(event.response.head.status, 200u);
    EXPECT_EQ(event.response.head.content_length.has_value, 1);
    EXPECT_EQ(event.response.head.content_length.value, 4u);
    EXPECT_EQ(view_string(event.response.body), "pong");

    coquic_http3_field_view_t field{};
    ASSERT_EQ(coquic_http3_request_view_header_at(&event.request, 0, &field), COQUIC_STATUS_OK);
    expect_field(field, "x-client", "yes");
    ASSERT_EQ(coquic_http3_request_head_view_header_at(&event.request.head, 0, &field),
              COQUIC_STATUS_OK);
    expect_field(field, "x-client", "yes");
    ASSERT_EQ(coquic_http3_request_view_trailer_at(&event.request, 0, &field), COQUIC_STATUS_OK);
    expect_field(field, "x-request-trailer", "done");
    EXPECT_EQ(coquic_http3_request_view_trailer_at(&event.request, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_request_view_trailer_at(&event.request, 1, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_response_head_view_t interim{};
    ASSERT_EQ(coquic_http3_response_view_interim_head_at(&event.response, 0, &interim),
              COQUIC_STATUS_OK);
    EXPECT_EQ(interim.status, 103u);
    EXPECT_EQ(coquic_http3_response_view_interim_head_at(&event.response, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_response_view_interim_head_at(&event.response, 1, &interim),
              COQUIC_STATUS_INVALID_ARGUMENT);
    ASSERT_EQ(coquic_http3_response_head_view_header_at(&interim, 0, &field), COQUIC_STATUS_OK);
    expect_field(field, "x-hint", "warm");
    EXPECT_EQ(coquic_http3_response_head_view_header_at(&interim, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_response_head_view_header_at(&interim, 1, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    ASSERT_EQ(coquic_http3_response_view_header_at(&event.response, 1, &field), COQUIC_STATUS_OK);
    expect_field(field, "x-answer", "yes");
    EXPECT_EQ(coquic_http3_response_view_header_at(&event.response, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_response_view_header_at(&event.response, 2, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    ASSERT_EQ(coquic_http3_response_view_trailer_at(&event.response, 0, &field), COQUIC_STATUS_OK);
    expect_field(field, "etag", "done");
    EXPECT_EQ(coquic_http3_response_view_trailer_at(&event.response, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_response_view_trailer_at(&event.response, 1, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_update_response_at(response_update, 1, &event),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_update_response_at(response_update, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_client_update_destroy(response_update);
    coquic_http3_client_destroy(client);

    ASSERT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_OK);
    ready = handshake_ready_result();
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, &ready, 0, &ready_update),
              COQUIC_STATUS_OK);
    coquic_http3_client_update_destroy(ready_update);
    auto reject = make_get_request();
    reject.head.path = "/reject";
    reject.head.path_length = 7;
    ASSERT_EQ(coquic_http3_client_submit_request(client, &reject, &stream_id, nullptr),
              COQUIC_STATUS_OK);
    ASSERT_EQ(coquic_http3_client_poll(client, 0, &request_update), COQUIC_STATUS_OK);
    coquic_http3_client_update_destroy(request_update);
    auto reset = peer_reset_result(0, COQUIC_HTTP3_ERROR_REQUEST_REJECTED);
    coquic_http3_client_update_t *reset_update = nullptr;
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, &reset, 0, &reset_update),
              COQUIC_STATUS_OK);
    ASSERT_NE(reset_update, nullptr);
    ASSERT_EQ(coquic_http3_client_update_request_error_count(reset_update), 1u);
    coquic_http3_client_request_error_event_t error_event{};
    ASSERT_EQ(coquic_http3_client_update_request_error_at(reset_update, 0, &error_event),
              COQUIC_STATUS_OK);
    EXPECT_EQ(error_event.stream_id, 0u);
    EXPECT_EQ(view_string(error_event.request.head.path), "/reject");
    EXPECT_EQ(error_event.application_error_code, COQUIC_HTTP3_ERROR_REQUEST_REJECTED);
    EXPECT_EQ(coquic_http3_client_update_request_error_at(reset_update, 1, &error_event),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_update_request_error_at(reset_update, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_client_update_destroy(reset_update);
    coquic_http3_client_destroy(client);
}

TEST(CoquicHttp3FfiTest, ClientPushResponseViewsExposeBorrowedFields) {
    coquic_http3_client_config_t config{};
    coquic_http3_client_config_init(&config);

    coquic_http3_client_t *client = nullptr;
    ASSERT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_OK);
    ASSERT_NE(client, nullptr);

    auto ready = handshake_ready_result();
    coquic_http3_client_update_t *ready_update = nullptr;
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, &ready, 0, &ready_update),
              COQUIC_STATUS_OK);
    ASSERT_NE(ready_update, nullptr);
    coquic_http3_client_update_destroy(ready_update);

    auto server_settings = receive_stream_result(3, std::vector<std::byte>{std::byte{0x00}}, false);
    coquic_http3_client_update_t *settings_update = nullptr;
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, &server_settings, 0, &settings_update),
              COQUIC_STATUS_OK);
    ASSERT_NE(settings_update, nullptr);
    EXPECT_EQ(coquic_http3_client_update_terminal_failure(settings_update), 0);
    coquic_http3_client_update_destroy(settings_update);

    coquic_http3_error_t error{};
    ASSERT_EQ(coquic_http3_client_submit_max_push_id(client, 0, &error), COQUIC_STATUS_OK);
    coquic_http3_client_update_t *max_update = nullptr;
    ASSERT_EQ(coquic_http3_client_poll(client, 0, &max_update), COQUIC_STATUS_OK);
    ASSERT_NE(max_update, nullptr);
    coquic_http3_client_update_destroy(max_update);

    auto request = make_get_request();
    coquic_stream_id_t request_stream_id = 99;
    ASSERT_EQ(coquic_http3_client_submit_request(client, &request, &request_stream_id, nullptr),
              COQUIC_STATUS_OK);
    EXPECT_EQ(request_stream_id, 0u);
    coquic_http3_client_update_t *request_update = nullptr;
    ASSERT_EQ(coquic_http3_client_poll(client, 0, &request_update), COQUIC_STATUS_OK);
    ASSERT_NE(request_update, nullptr);
    coquic_http3_client_update_destroy(request_update);

    coquic::http3::Http3QpackEncoderContext encoder;
    const std::array promised_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":path", "/pushed.css"},
        coquic::http3::Http3Field{"x-promise", "yes"},
    };
    auto promise_bytes = push_promise_frame_bytes(encoder, 0, 0, promised_fields);
    auto promise_result = receive_stream_result(0, std::move(promise_bytes), false);
    coquic_http3_client_update_t *promise_update = nullptr;
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, &promise_result, 0, &promise_update),
              COQUIC_STATUS_OK);
    ASSERT_NE(promise_update, nullptr);
    EXPECT_EQ(coquic_http3_client_update_terminal_failure(promise_update), 0);
    coquic_http3_client_update_destroy(promise_update);

    const std::array response_fields{
        coquic::http3::Http3Field{":status", "200"},
        coquic::http3::Http3Field{"content-length", "4"},
        coquic::http3::Http3Field{"x-push", "ok"},
    };
    const std::array response_trailers{
        coquic::http3::Http3Field{"etag", "push"},
    };
    auto push_payload = headers_frame_bytes(encoder, 15, response_fields);
    append(push_payload, data_frame_bytes("body"));
    append(push_payload, headers_frame_bytes(encoder, 15, response_trailers));
    auto push_bytes = push_stream_bytes(0, push_payload);
    auto push_result = receive_stream_result(15, std::move(push_bytes), true);
    coquic_http3_client_update_t *push_update = nullptr;
    ASSERT_EQ(coquic_http3_client_on_quic_result(client, &push_result, 0, &push_update),
              COQUIC_STATUS_OK);
    ASSERT_NE(push_update, nullptr);
    ASSERT_EQ(coquic_http3_client_update_push_response_count(push_update), 1u);
    EXPECT_EQ(coquic_http3_client_update_push_error_count(push_update), 0u);

    coquic_http3_client_push_response_event_t event{};
    ASSERT_EQ(coquic_http3_client_update_push_response_at(push_update, 0, &event),
              COQUIC_STATUS_OK);
    EXPECT_EQ(event.request_stream_id, 0u);
    EXPECT_EQ(event.push_id, 0u);
    EXPECT_EQ(view_string(event.request.path), "/pushed.css");
    EXPECT_EQ(event.response.head.status, 200u);
    EXPECT_EQ(view_string(event.response.body), "body");

    coquic_http3_field_view_t field{};
    ASSERT_EQ(coquic_http3_request_head_view_header_at(&event.request, 0, &field),
              COQUIC_STATUS_OK);
    expect_field(field, "x-promise", "yes");
    ASSERT_EQ(coquic_http3_response_view_header_at(&event.response, 1, &field), COQUIC_STATUS_OK);
    expect_field(field, "x-push", "ok");
    ASSERT_EQ(coquic_http3_response_view_trailer_at(&event.response, 0, &field), COQUIC_STATUS_OK);
    expect_field(field, "etag", "push");
    EXPECT_EQ(coquic_http3_client_update_push_response_at(push_update, 1, &event),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_client_update_push_response_at(push_update, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);

    coquic_http3_client_update_destroy(push_update);
    coquic_http3_client_destroy(client);
}

TEST(CoquicHttp3FfiTest, ServerRequestCancelledViewExposesHeadBodyAndTrailers) {
    coquic_http3_server_config_t config{};
    coquic_http3_server_config_init(&config);

    coquic_http3_server_t *server = nullptr;
    ASSERT_EQ(coquic_http3_server_create(&config, &server), COQUIC_STATUS_OK);
    ASSERT_NE(server, nullptr);

    auto ready = handshake_ready_result();
    coquic_http3_server_update_t *ready_update = nullptr;
    ASSERT_EQ(coquic_http3_server_on_quic_result(server, &ready, 0, &ready_update),
              COQUIC_STATUS_OK);
    ASSERT_NE(ready_update, nullptr);
    ASSERT_GT(coquic_http3_server_update_connection_input_count(ready_update), 0u);
    coquic_connection_input_t input{};
    EXPECT_EQ(coquic_http3_server_update_connection_input_at(ready_update, 0, &input),
              COQUIC_STATUS_OK);
    EXPECT_EQ(coquic_http3_server_update_connection_input_at(ready_update, 999, &input),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_update_connection_input_at(ready_update, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_http3_server_update_destroy(ready_update);

    coquic::http3::Http3QpackEncoderContext encoder;
    const std::array request_headers{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/cancel"},
        coquic::http3::Http3Field{"content-length", "4"},
        coquic::http3::Http3Field{"x-client", "yes"},
    };
    const std::array request_trailers{
        coquic::http3::Http3Field{"etag", "gone"},
    };
    auto request_bytes = headers_frame_bytes(encoder, 0, request_headers);
    append(request_bytes, data_frame_bytes("ping"));
    append(request_bytes, headers_frame_bytes(encoder, 0, request_trailers));

    coquic::core::Result core_result;
    core_result.effects.push_back(coquic::core::ReceiveStreamData{
        .connection = 1,
        .stream_id = 0,
        .bytes = std::move(request_bytes),
        .fin = false,
    });
    core_result.effects.push_back(coquic::core::PeerResetStream{
        .connection = 1,
        .stream_id = 0,
        .application_error_code = COQUIC_HTTP3_ERROR_REQUEST_CANCELLED,
    });
    auto ffi_result = make_ffi_result(std::move(core_result));

    coquic_http3_server_update_t *update = nullptr;
    ASSERT_EQ(coquic_http3_server_on_quic_result(server, &ffi_result, 0, &update),
              COQUIC_STATUS_OK);
    ASSERT_NE(update, nullptr);
    ASSERT_EQ(coquic_http3_server_update_request_cancelled_count(update), 1u);

    coquic_http3_server_request_cancelled_event_t event{};
    ASSERT_EQ(coquic_http3_server_update_request_cancelled_at(update, 0, &event), COQUIC_STATUS_OK);
    EXPECT_EQ(event.stream_id, 0u);
    EXPECT_EQ(event.has_head, 1);
    EXPECT_EQ(view_string(event.head.method), "POST");
    EXPECT_EQ(view_string(event.head.path), "/cancel");
    EXPECT_EQ(view_string(event.body), "ping");
    EXPECT_EQ(event.application_error_code, COQUIC_HTTP3_ERROR_REQUEST_CANCELLED);

    coquic_http3_field_view_t field{};
    ASSERT_EQ(coquic_http3_request_head_view_header_at(&event.head, 1, &field), COQUIC_STATUS_OK);
    expect_field(field, "x-client", "yes");
    EXPECT_EQ(coquic_http3_request_head_view_header_at(&event.head, 1, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_request_head_view_header_at(&event.head, 2, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);
    ASSERT_EQ(coquic_http3_server_request_cancelled_view_trailer_at(&event, 0, &field),
              COQUIC_STATUS_OK);
    expect_field(field, "etag", "gone");
    EXPECT_EQ(coquic_http3_server_update_request_cancelled_at(update, 1, &event),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_update_request_cancelled_at(update, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_request_cancelled_view_trailer_at(&event, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_http3_server_request_cancelled_view_trailer_at(&event, 1, &field),
              COQUIC_STATUS_INVALID_ARGUMENT);

    coquic_http3_server_update_destroy(update);
    coquic_http3_server_destroy(server);
}
