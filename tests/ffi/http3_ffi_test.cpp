#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

#include "../support/gtest_compat.h"

#include "coquic/ffi/http3.h"

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

TEST(CoquicHttp3FfiTest, RejectsInvalidArguments) {
    coquic_http3_client_t *client = nullptr;
    EXPECT_EQ(coquic_http3_client_create(nullptr, &client), COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(client, nullptr);

    coquic_http3_client_config_t config{};
    coquic_http3_client_config_init(&config);
    config.size = 0;
    EXPECT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_INVALID_ARGUMENT);

    coquic_http3_client_config_init(&config);
    ASSERT_EQ(coquic_http3_client_create(&config, &client), COQUIC_STATUS_OK);
    ASSERT_NE(client, nullptr);

    auto request = make_get_request();
    coquic_stream_id_t stream_id = 0;
    EXPECT_EQ(coquic_http3_client_submit_request(nullptr, &request, &stream_id, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);

    request.size = 0;
    EXPECT_EQ(coquic_http3_client_submit_request(client, &request, &stream_id, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);

    coquic_http3_client_update_t *update = reinterpret_cast<coquic_http3_client_update_t *>(0x1);
    EXPECT_EQ(coquic_http3_client_poll(nullptr, 0, &update), COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(update, nullptr);

    coquic_http3_client_destroy(client);
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
