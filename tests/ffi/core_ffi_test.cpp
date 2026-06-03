#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "coquic/ffi/core.h"

namespace {

coquic_bytes_t bytes_view(const std::vector<std::uint8_t> &bytes) {
    return coquic_bytes_t{
        .data = bytes.data(),
        .length = bytes.size(),
    };
}

struct ExpectedLocalError {
    coquic_connection_handle_t connection = 0;
    coquic_local_error_code_t code = COQUIC_LOCAL_ERROR_UNSUPPORTED_OPERATION;
    coquic_optional_stream_id_t stream_id = {};
};

void expect_local_error(const coquic_result_t *ffi_result, ExpectedLocalError expected) {
    ASSERT_NE(ffi_result, nullptr);
    ASSERT_EQ(coquic_result_has_local_error(ffi_result), 1);

    coquic_local_error_t local_error{};
    ASSERT_EQ(coquic_result_local_error(ffi_result, &local_error), COQUIC_STATUS_OK);
    ASSERT_EQ(local_error.connection.has_value, 1);
    EXPECT_EQ(local_error.connection.value, expected.connection);
    EXPECT_EQ(local_error.code, expected.code);
    EXPECT_EQ(local_error.stream_id.has_value, expected.stream_id.has_value);
    if (expected.stream_id.has_value != 0) {
        EXPECT_EQ(local_error.stream_id.value, expected.stream_id.value);
    }
}

} // namespace

TEST(CoquicCoreFfiTest, OpensClientConnectionAndExposesEffects) {
    EXPECT_EQ(coquic_ffi_abi_version(), COQUIC_FFI_ABI_VERSION);

    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.role = COQUIC_ROLE_CLIENT;
    endpoint_config.verify_peer = 0;

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);

    coquic_client_connection_config_t connection_config{};
    coquic_client_connection_config_init(&connection_config);
    const std::vector<std::uint8_t> source_connection_id{0xc1, 0x01};
    const std::vector<std::uint8_t> destination_connection_id{0x83, 0x41};
    connection_config.source_connection_id = bytes_view(source_connection_id);
    connection_config.initial_destination_connection_id = bytes_view(destination_connection_id);

    coquic_open_connection_t open{
        .size = sizeof(coquic_open_connection_t),
        .connection = connection_config,
        .initial_route_handle = 7,
        .address_validation_identity = {},
    };

    coquic_result_t *result = nullptr;
    ASSERT_EQ(coquic_endpoint_open_connection(endpoint, &open, 0, &result), COQUIC_STATUS_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(coquic_endpoint_connection_count(endpoint), 1u);
    EXPECT_EQ(coquic_result_has_local_error(result), 0);

    bool saw_created = false;
    bool saw_send_datagram = false;
    const auto effect_count = coquic_result_effect_count(result);
    ASSERT_GT(effect_count, 0u);
    for (std::size_t index = 0; index < effect_count; ++index) {
        coquic_effect_t effect{};
        ASSERT_EQ(coquic_result_effect_at(result, index, &effect), COQUIC_STATUS_OK);
        if (effect.kind == COQUIC_EFFECT_CONNECTION_LIFECYCLE_EVENT) {
            const auto lifecycle = effect.as.connection_lifecycle_event;
            if (lifecycle.connection == 1 && lifecycle.event == COQUIC_LIFECYCLE_CREATED) {
                saw_created = true;
            }
        }
        if (effect.kind == COQUIC_EFFECT_SEND_DATAGRAM) {
            const auto send = effect.as.send_datagram;
            if (send.connection == 1 && send.route_handle.has_value != 0 &&
                send.route_handle.value == 7 && send.bytes.length > 0) {
                saw_send_datagram = true;
            }
        }
    }

    EXPECT_TRUE(saw_created);
    EXPECT_TRUE(saw_send_datagram);
    coquic_result_destroy(result);
    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, ReportsLocalErrorForInvalidConnectionCommand) {
    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.role = COQUIC_ROLE_CLIENT;
    endpoint_config.verify_peer = 0;

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);

    const std::vector<std::uint8_t> payload{0x68, 0x69};
    coquic_send_stream_data_t send{
        .size = sizeof(coquic_send_stream_data_t),
        .stream_id = 0,
        .bytes = bytes_view(payload),
        .fin = 1,
    };

    coquic_result_t *result = nullptr;
    ASSERT_EQ(coquic_connection_send_stream(endpoint, 99, &send, 0, &result), COQUIC_STATUS_OK);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(coquic_result_has_local_error(result), 1);

    coquic_local_error_t error{};
    ASSERT_EQ(coquic_result_local_error(result, &error), COQUIC_STATUS_OK);
    ASSERT_EQ(error.connection.has_value, 1);
    EXPECT_EQ(error.connection.value, 99u);
    EXPECT_EQ(error.code, COQUIC_LOCAL_ERROR_UNSUPPORTED_OPERATION);

    coquic_result_destroy(result);
    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, QuicFacadeConnectReturnsConnectionHandleAndSharesEffects) {
    EXPECT_EQ(coquic_ffi_abi_version(), COQUIC_FFI_ABI_VERSION);

    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.role = COQUIC_ROLE_CLIENT;
    endpoint_config.verify_peer = 0;

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);

    coquic_client_connection_config_t connection_config{};
    coquic_client_connection_config_init(&connection_config);
    const std::vector<std::uint8_t> source_connection_id{0xc1, 0x02};
    const std::vector<std::uint8_t> destination_connection_id{0x83, 0x42};
    connection_config.source_connection_id = bytes_view(source_connection_id);
    connection_config.initial_destination_connection_id = bytes_view(destination_connection_id);

    coquic_open_connection_t open{
        .size = sizeof(coquic_open_connection_t),
        .connection = connection_config,
        .initial_route_handle = 9,
        .address_validation_identity = {},
    };

    coquic_connection_handle_t connection = 0;
    coquic_result_t *result = nullptr;
    ASSERT_EQ(coquic_quic_connect(endpoint, &open, 0, &connection, &result), COQUIC_STATUS_OK);
    ASSERT_EQ(connection, 1u);
    ASSERT_NE(result, nullptr);

    bool saw_created = false;
    bool saw_send_datagram = false;
    for (std::size_t index = 0; index < coquic_result_effect_count(result); ++index) {
        coquic_effect_t effect{};
        ASSERT_EQ(coquic_result_effect_at(result, index, &effect), COQUIC_STATUS_OK);
        if (effect.kind == COQUIC_EFFECT_CONNECTION_LIFECYCLE_EVENT &&
            effect.as.connection_lifecycle_event.connection == connection &&
            effect.as.connection_lifecycle_event.event == COQUIC_LIFECYCLE_CREATED) {
            saw_created = true;
        }
        if (effect.kind == COQUIC_EFFECT_SEND_DATAGRAM &&
            effect.as.send_datagram.connection == connection &&
            effect.as.send_datagram.route_handle.has_value != 0 &&
            effect.as.send_datagram.route_handle.value == 9) {
            saw_send_datagram = true;
        }
    }
    EXPECT_TRUE(saw_created);
    EXPECT_TRUE(saw_send_datagram);
    coquic_result_destroy(result);

    const std::vector<std::uint8_t> payload{0x68, 0x69};
    result = nullptr;
    ASSERT_EQ(coquic_quic_stream_send(endpoint, connection, 0, bytes_view(payload), 1, 1, &result),
              COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = connection,
                                .code = COQUIC_LOCAL_ERROR_INVALID_STREAM_ID,
                                .stream_id = {.has_value = 1, .value = 0}});
    coquic_result_destroy(result);

    result = nullptr;
    ASSERT_EQ(coquic_quic_stream_finish(endpoint, connection, 4, 2, &result), COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = connection,
                                .code = COQUIC_LOCAL_ERROR_INVALID_STREAM_ID,
                                .stream_id = {.has_value = 1, .value = 4}});
    coquic_result_destroy(result);

    result = nullptr;
    ASSERT_EQ(coquic_quic_stream_reset(endpoint, connection, 8, 42, 3, &result), COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = connection,
                                .code = COQUIC_LOCAL_ERROR_INVALID_STREAM_ID,
                                .stream_id = {.has_value = 1, .value = 8}});
    coquic_result_destroy(result);

    result = nullptr;
    ASSERT_EQ(coquic_quic_stream_stop_sending(endpoint, connection, 12, 43, 4, &result),
              COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = connection,
                                .code = COQUIC_LOCAL_ERROR_INVALID_STREAM_ID,
                                .stream_id = {.has_value = 1, .value = 12}});
    coquic_result_destroy(result);

    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, RejectsInvalidArguments) {
    coquic_endpoint_t *endpoint = nullptr;
    EXPECT_EQ(coquic_endpoint_create(nullptr, &endpoint), COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(endpoint, nullptr);

    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.size = 0;
    EXPECT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(endpoint, nullptr);

    coquic_endpoint_config_init(&endpoint_config);
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);

    coquic_connection_handle_t connection = 123;
    coquic_result_t *result = reinterpret_cast<coquic_result_t *>(0x1);
    EXPECT_EQ(coquic_quic_connect(endpoint, nullptr, 0, &connection, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(connection, 0u);
    EXPECT_EQ(result, nullptr);
    EXPECT_EQ(coquic_quic_connect(endpoint, nullptr, 0, nullptr, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);

    coquic_endpoint_destroy(endpoint);
}
