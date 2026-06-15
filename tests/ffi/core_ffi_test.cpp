#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

#include "coquic/ffi/core.h"
#include "src/ffi/core_internal.h"

namespace {

coquic_bytes_t bytes_view(const std::vector<std::uint8_t> &bytes) {
    return coquic_bytes_t{
        .data = bytes.data(),
        .length = bytes.size(),
    };
}

std::vector<std::byte> core_bytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (const auto value : values) {
        out.push_back(static_cast<std::byte>(value));
    }
    return out;
}

template <std::size_t N>
std::array<std::byte, N> byte_array(std::initializer_list<std::uint8_t> values) {
    std::array<std::byte, N> out{};
    std::size_t index = 0;
    for (const auto value : values) {
        if (index >= N) {
            break;
        }
        out[index++] = static_cast<std::byte>(value);
    }
    return out;
}

template <typename Enum>
Enum enum_value_from_underlying_for_tests(std::underlying_type_t<Enum> value) {
    return std::bit_cast<Enum>(value);
}

void expect_bytes(coquic_bytes_view_t actual, std::initializer_list<std::uint8_t> expected) {
    ASSERT_EQ(actual.length, expected.size());
    if (expected.size() == 0) {
        return;
    }
    ASSERT_NE(actual.data, nullptr);
    std::size_t index = 0;
    for (const auto value : expected) {
        EXPECT_EQ(actual.data[index++], value);
    }
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
    EXPECT_EQ(coquic_endpoint_has_send_continuation_pending(endpoint), 0);
    EXPECT_EQ(coquic_endpoint_has_pending_stream_send(endpoint), 0);
    const auto endpoint_wakeup = coquic_endpoint_next_wakeup(endpoint);
    ASSERT_EQ(endpoint_wakeup.has_value, 1);
    EXPECT_NE(endpoint_wakeup.value, 0u);
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
    EXPECT_EQ(coquic_endpoint_open_connection(nullptr, nullptr, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    EXPECT_EQ(coquic_endpoint_open_connection(endpoint, nullptr, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);

    result = reinterpret_cast<coquic_result_t *>(0x1);
    coquic_open_connection_t open{};
    EXPECT_EQ(coquic_endpoint_open_connection(endpoint, nullptr, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    EXPECT_EQ(coquic_endpoint_open_connection(endpoint, &open, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    open.size = sizeof(coquic_open_connection_t);
    EXPECT_EQ(coquic_endpoint_open_connection(endpoint, &open, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);

    EXPECT_EQ(coquic_quic_connect(endpoint, nullptr, 0, &connection, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(connection, 0u);
    EXPECT_EQ(result, nullptr);
    open.connection.size = sizeof(coquic_client_connection_config_t);
    connection = 123;
    result = reinterpret_cast<coquic_result_t *>(0x1);
    EXPECT_EQ(coquic_quic_connect(nullptr, &open, 0, &connection, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(connection, 0u);
    EXPECT_EQ(result, nullptr);
    result = reinterpret_cast<coquic_result_t *>(0x1);
    EXPECT_EQ(coquic_quic_connect(endpoint, &open, 0, nullptr, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);

    result = reinterpret_cast<coquic_result_t *>(0x1);
    EXPECT_EQ(coquic_quic_connect(endpoint, nullptr, 0, nullptr, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);

    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, InitializersAndNullQueriesAreStable) {
    EXPECT_EQ(COQUIC_STATUS_OUT_OF_MEMORY, 2u);
    EXPECT_EQ(COQUIC_STATUS_INTERNAL_ERROR, 3u);

    coquic_transport_config_init(nullptr);
    coquic_endpoint_config_init(nullptr);
    coquic_client_connection_config_init(nullptr);
    coquic_endpoint_destroy(nullptr);
    coquic_result_destroy(nullptr);

    coquic_transport_config_t transport{};
    coquic_transport_config_init(&transport);
    EXPECT_EQ(static_cast<unsigned>(transport.congestion_control),
              static_cast<unsigned>(COQUIC_CONGESTION_CONTROL_NEWRENO));
    EXPECT_NE(transport.max_udp_payload_size, 0u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.3
    // # Endpoints SHOULD set the initial value of BASE_PLPMTU (Section 5.1 of
    // # [DPLPMTUD]) to be consistent with QUIC's smallest allowed maximum
    // # datagram size.
    EXPECT_EQ(transport.pmtud_base_datagram_size, 1200u);

    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    EXPECT_EQ(endpoint_config.size, sizeof(coquic_endpoint_config_t));
    EXPECT_EQ(static_cast<unsigned>(endpoint_config.role),
              static_cast<unsigned>(COQUIC_ROLE_CLIENT));
    EXPECT_EQ(endpoint_config.application_protocol_length, 6u);
    EXPECT_EQ(static_cast<unsigned>(endpoint_config.transport.congestion_control),
              static_cast<unsigned>(COQUIC_CONGESTION_CONTROL_NEWRENO));
    EXPECT_EQ(endpoint_config.enable_out_of_order_receive, 0);
    EXPECT_EQ(endpoint_config.orphan_zero_rtt_buffer.max_packets, 0u);
    EXPECT_EQ(endpoint_config.orphan_zero_rtt_buffer.max_bytes, 0u);
    EXPECT_EQ(endpoint_config.orphan_zero_rtt_buffer.max_age_us, 0u);
    EXPECT_EQ(endpoint_config.enable_reserved_version_probe, 0);

    coquic_client_connection_config_t connection_config{};
    coquic_client_connection_config_init(&connection_config);
    EXPECT_EQ(connection_config.size, sizeof(coquic_client_connection_config_t));
    EXPECT_EQ(connection_config.original_version, 1u);
    EXPECT_EQ(connection_config.server_name_length, 9u);

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ(coquic_endpoint_connection_count(endpoint), 0u);
    EXPECT_EQ(coquic_endpoint_has_send_continuation_pending(endpoint), 0u);
    EXPECT_EQ(coquic_endpoint_has_pending_stream_send(endpoint), 0u);
    EXPECT_EQ(coquic_endpoint_next_wakeup(endpoint).has_value, 0);
    coquic_endpoint_destroy(endpoint);

    EXPECT_EQ(coquic_endpoint_connection_count(nullptr), 0u);
    EXPECT_EQ(coquic_endpoint_has_send_continuation_pending(nullptr), 0u);
    EXPECT_EQ(coquic_endpoint_has_pending_stream_send(nullptr), 0u);
    EXPECT_EQ(coquic_endpoint_next_wakeup(nullptr).has_value, 0);
    EXPECT_EQ(coquic_result_effect_count(nullptr), 0u);
    EXPECT_EQ(coquic_result_next_wakeup(nullptr).has_value, 0);
    EXPECT_EQ(coquic_result_has_local_error(nullptr), 0);
    EXPECT_EQ(coquic_result_send_continuation_pending(nullptr), 0);

    coquic_effect_t effect{};
    EXPECT_EQ(coquic_result_effect_at(nullptr, 0, &effect), COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_local_error_t error{};
    EXPECT_EQ(coquic_result_local_error(nullptr, &error), COQUIC_STATUS_INVALID_ARGUMENT);
}

TEST(CoquicCoreFfiTest, EndpointConfigSizeGatesOutOfOrderReceiveOption) {
    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.enable_out_of_order_receive = 1;
    endpoint_config.size = offsetof(coquic_endpoint_config_t, enable_out_of_order_receive);

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);
    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, EndpointConfigSizeGatesOrphanZeroRttBufferOption) {
    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.orphan_zero_rtt_buffer = coquic_orphan_zero_rtt_buffer_config_t{
        .max_packets = 2,
        .max_bytes = 4096,
        .max_age_us = 1000,
    };
    endpoint_config.size = offsetof(coquic_endpoint_config_t, orphan_zero_rtt_buffer);

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);
    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, EndpointConfigSizeGatesReservedVersionProbeOption) {
    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.enable_reserved_version_probe = 1;
    endpoint_config.size = offsetof(coquic_endpoint_config_t, enable_reserved_version_probe);

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);
    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, EndpointConfigCoversServerOptionsAndEnumConversions) {
    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    const std::uint32_t versions[] = {1, 0x6b3343cfu};
    const char alpn[] = "h3";
    const char cert[] = "not a certificate";
    const char key[] = "not a key";
    coquic_tls_identity_t identity{
        .certificate_pem = cert,
        .certificate_pem_length = sizeof(cert) - 1,
        .private_key_pem = key,
        .private_key_pem_length = sizeof(key) - 1,
    };
    const std::vector<std::uint8_t> context{0x01, 0x02};
    endpoint_config.role = COQUIC_ROLE_SERVER;
    endpoint_config.supported_versions = versions;
    endpoint_config.supported_versions_count = 2;
    endpoint_config.verify_peer = 1;
    endpoint_config.retry_enabled = 1;
    endpoint_config.application_protocol = alpn;
    endpoint_config.application_protocol_length = sizeof(alpn) - 1;
    endpoint_config.identity = &identity;
    endpoint_config.transport.congestion_control = COQUIC_CONGESTION_CONTROL_CUBIC;
    endpoint_config.transport.enable_latency_spin_bit = 1;
    endpoint_config.zero_rtt = coquic_zero_rtt_config_t{
        .attempt = 1,
        .allow = 1,
        .application_context = bytes_view(context),
    };
    endpoint_config.emit_shared_receive_stream_data = 1;
    endpoint_config.enable_out_of_order_receive = 1;
    endpoint_config.enable_packet_inspection = 1;
    endpoint_config.allow_peer_address_change = 0;
    endpoint_config.max_server_connections = 8;
    endpoint_config.orphan_zero_rtt_buffer = coquic_orphan_zero_rtt_buffer_config_t{
        .max_packets = 2,
        .max_bytes = 8192,
        .max_age_us = 250000,
    };
    endpoint_config.enable_reserved_version_probe = 1;

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);
    EXPECT_EQ(coquic_endpoint_connection_count(endpoint), 0u);
    coquic_endpoint_destroy(endpoint);

    endpoint_config.role = 99;
    endpoint_config.transport.congestion_control = COQUIC_CONGESTION_CONTROL_BBR;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);
    coquic_endpoint_destroy(endpoint);

    endpoint_config.transport.congestion_control = COQUIC_CONGESTION_CONTROL_COPA;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);
    coquic_endpoint_destroy(endpoint);

    endpoint_config.transport.congestion_control = COQUIC_CONGESTION_CONTROL_PCC;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);
    coquic_endpoint_destroy(endpoint);

    endpoint_config.transport.congestion_control = COQUIC_CONGESTION_CONTROL_PCC_VIVACE;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);
    coquic_endpoint_destroy(endpoint);

    endpoint_config.transport.congestion_control = 99;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);
    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, OpenConnectionCoversRetryAndResumptionFields) {
    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.role = COQUIC_ROLE_CLIENT;
    endpoint_config.verify_peer = 0;

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);

    coquic_client_connection_config_t connection_config{};
    coquic_client_connection_config_init(&connection_config);
    const std::vector<std::uint8_t> source_connection_id{0xc1, 0x21};
    const std::vector<std::uint8_t> destination_connection_id{0x83, 0x61};
    const std::vector<std::uint8_t> original_destination_connection_id{0x83, 0x62};
    const std::vector<std::uint8_t> retry_source_connection_id{0x44, 0x63};
    const std::vector<std::uint8_t> retry_token{0xaa, 0xbb};
    const std::vector<std::uint8_t> resumption{0x01, 0x02, 0x03};
    const std::vector<std::uint8_t> zero_rtt_context{0x09};
    const std::vector<std::uint8_t> address_identity{0x77};
    const char server_name[] = "example.test";
    coquic_resumption_state_t resumption_state{.serialized = bytes_view(resumption)};
    connection_config.source_connection_id = bytes_view(source_connection_id);
    connection_config.initial_destination_connection_id = bytes_view(destination_connection_id);
    connection_config.original_destination_connection_id =
        bytes_view(original_destination_connection_id);
    connection_config.has_original_destination_connection_id = 1;
    connection_config.retry_source_connection_id = bytes_view(retry_source_connection_id);
    connection_config.has_retry_source_connection_id = 1;
    connection_config.retry_token = bytes_view(retry_token);
    connection_config.reacted_to_version_negotiation = 1;
    connection_config.server_name = server_name;
    connection_config.server_name_length = sizeof(server_name) - 1;
    connection_config.resumption_state = &resumption_state;
    connection_config.zero_rtt = {
        .attempt = 1,
        .allow = 0,
        .application_context = bytes_view(zero_rtt_context),
    };

    coquic_open_connection_t open{
        .size = sizeof(coquic_open_connection_t),
        .connection = connection_config,
        .initial_route_handle = 91,
        .address_validation_identity = bytes_view(address_identity),
    };

    coquic_result_t *result = nullptr;
    ASSERT_EQ(coquic_endpoint_open_connection(endpoint, &open, 123, &result), COQUIC_STATUS_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(coquic_result_has_local_error(result), 0);
    EXPECT_GT(coquic_result_effect_count(result), 0u);
    coquic_result_destroy(result);
    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, EndpointCallsValidateInputsAndForwardFacadeAliases) {
    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.role = COQUIC_ROLE_CLIENT;
    endpoint_config.verify_peer = 0;

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);

    coquic_result_t *result = reinterpret_cast<coquic_result_t *>(0x1);
    EXPECT_EQ(coquic_endpoint_timer_expired(nullptr, 1, &result), COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    EXPECT_EQ(coquic_endpoint_timer_expired(endpoint, 1, nullptr), COQUIC_STATUS_INVALID_ARGUMENT);

    ASSERT_EQ(coquic_endpoint_timer_expired(endpoint, 2, &result), COQUIC_STATUS_OK);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(coquic_result_effect_count(result), 0u);
    EXPECT_EQ(coquic_result_effect_at(result, 0, nullptr), COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_effect_t effect{};
    EXPECT_EQ(coquic_result_effect_at(result, 0, &effect), COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(coquic_result_local_error(result, nullptr), COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_local_error_t missing_error{};
    EXPECT_EQ(coquic_result_local_error(result, &missing_error), COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_result_destroy(result);

    coquic_inbound_datagram_t datagram{
        .size = sizeof(coquic_inbound_datagram_t),
        .bytes = {},
        .route_handle = {.has_value = 0, .value = 0},
        .address_validation_identity = {},
        .ecn = COQUIC_ECN_UNAVAILABLE,
    };
    result = reinterpret_cast<coquic_result_t *>(0x1);
    EXPECT_EQ(coquic_endpoint_input_datagram(nullptr, &datagram, 3, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    result = reinterpret_cast<coquic_result_t *>(0x1);
    EXPECT_EQ(coquic_endpoint_input_datagram(endpoint, nullptr, 3, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    datagram.size = 0;
    EXPECT_EQ(coquic_endpoint_input_datagram(endpoint, &datagram, 3, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    datagram.size = sizeof(coquic_inbound_datagram_t);
    for (const auto ecn : {static_cast<coquic_ecn_codepoint_t>(COQUIC_ECN_UNAVAILABLE),
                           static_cast<coquic_ecn_codepoint_t>(COQUIC_ECN_NOT_ECT),
                           static_cast<coquic_ecn_codepoint_t>(COQUIC_ECN_ECT0),
                           static_cast<coquic_ecn_codepoint_t>(COQUIC_ECN_ECT1),
                           static_cast<coquic_ecn_codepoint_t>(COQUIC_ECN_CE),
                           static_cast<coquic_ecn_codepoint_t>(99)}) {
        datagram.ecn = ecn;
        datagram.route_handle = {
            .has_value = static_cast<std::uint8_t>(ecn != COQUIC_ECN_UNAVAILABLE), .value = 77};
        ASSERT_EQ(coquic_quic_receive_datagram(endpoint, &datagram, 4, &result), COQUIC_STATUS_OK);
        ASSERT_NE(result, nullptr);
        coquic_result_destroy(result);
    }

    coquic_path_mtu_update_t mtu{
        .size = sizeof(coquic_path_mtu_update_t),
        .route_handle = {.has_value = 1, .value = 77},
        .max_udp_payload_size = 1200,
    };
    result = reinterpret_cast<coquic_result_t *>(0x1);
    EXPECT_EQ(coquic_endpoint_update_path_mtu(nullptr, &mtu, 5, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    result = reinterpret_cast<coquic_result_t *>(0x1);
    EXPECT_EQ(coquic_endpoint_update_path_mtu(endpoint, nullptr, 5, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    mtu.size = 0;
    EXPECT_EQ(coquic_endpoint_update_path_mtu(endpoint, &mtu, 5, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    mtu.size = sizeof(coquic_path_mtu_update_t);
    ASSERT_EQ(coquic_quic_update_path_mtu(endpoint, &mtu, 5, &result), COQUIC_STATUS_OK);
    ASSERT_NE(result, nullptr);
    coquic_result_destroy(result);

    ASSERT_EQ(coquic_quic_timer_expired(endpoint, 6, &result), COQUIC_STATUS_OK);
    ASSERT_NE(result, nullptr);
    coquic_result_destroy(result);
    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, ConnectionCommandValidationCoversAllKinds) {
    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.role = COQUIC_ROLE_CLIENT;
    endpoint_config.verify_peer = 0;

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);

    const std::vector<std::uint8_t> payload{0x68, 0x69};
    coquic_result_t *result = reinterpret_cast<coquic_result_t *>(0x1);

    auto expect_invalid = [&](coquic_status_t status) {
        EXPECT_EQ(status, COQUIC_STATUS_INVALID_ARGUMENT);
        EXPECT_EQ(result, nullptr);
        result = reinterpret_cast<coquic_result_t *>(0x1);
    };

    expect_invalid(coquic_connection_send_stream(endpoint, 1, nullptr, 0, &result));
    EXPECT_EQ(coquic_connection_send_stream(endpoint, 1, nullptr, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_send_stream_data_t send_stream{
        .size = 0, .stream_id = 0, .bytes = bytes_view(payload), .fin = 1};
    expect_invalid(coquic_connection_send_stream(endpoint, 1, &send_stream, 0, &result));
    send_stream.size = sizeof(coquic_send_stream_data_t);
    EXPECT_EQ(coquic_connection_send_stream(nullptr, 99, &send_stream, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    result = reinterpret_cast<coquic_result_t *>(0x1);
    ASSERT_EQ(coquic_quic_connection_send_stream(endpoint, 99, &send_stream, 0, &result),
              COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = 99});
    coquic_result_destroy(result);
    result = reinterpret_cast<coquic_result_t *>(0x1);

    expect_invalid(coquic_connection_send_datagram(endpoint, 1, nullptr, 0, &result));
    EXPECT_EQ(coquic_connection_send_datagram(endpoint, 1, nullptr, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_send_datagram_data_t send_datagram{.size = 0, .bytes = bytes_view(payload)};
    expect_invalid(coquic_connection_send_datagram(endpoint, 1, &send_datagram, 0, &result));
    send_datagram.size = sizeof(coquic_send_datagram_data_t);
    EXPECT_EQ(coquic_connection_send_datagram(nullptr, 99, &send_datagram, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    result = reinterpret_cast<coquic_result_t *>(0x1);
    ASSERT_EQ(coquic_quic_connection_send_datagram(endpoint, 99, &send_datagram, 0, &result),
              COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = 99});
    coquic_result_destroy(result);
    result = reinterpret_cast<coquic_result_t *>(0x1);

    expect_invalid(coquic_connection_reset_stream(endpoint, 1, nullptr, 0, &result));
    EXPECT_EQ(coquic_connection_reset_stream(endpoint, 1, nullptr, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_reset_stream_t reset{.size = 0, .stream_id = 4, .application_error_code = 42};
    expect_invalid(coquic_connection_reset_stream(endpoint, 1, &reset, 0, &result));
    reset.size = sizeof(coquic_reset_stream_t);
    EXPECT_EQ(coquic_connection_reset_stream(nullptr, 99, &reset, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    result = reinterpret_cast<coquic_result_t *>(0x1);
    ASSERT_EQ(coquic_quic_connection_reset_stream(endpoint, 99, &reset, 0, &result),
              COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = 99});
    coquic_result_destroy(result);
    result = reinterpret_cast<coquic_result_t *>(0x1);

    expect_invalid(coquic_connection_stop_sending(endpoint, 1, nullptr, 0, &result));
    EXPECT_EQ(coquic_connection_stop_sending(endpoint, 1, nullptr, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_stop_sending_t stop{.size = 0, .stream_id = 4, .application_error_code = 43};
    expect_invalid(coquic_connection_stop_sending(endpoint, 1, &stop, 0, &result));
    stop.size = sizeof(coquic_stop_sending_t);
    EXPECT_EQ(coquic_connection_stop_sending(nullptr, 99, &stop, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    result = reinterpret_cast<coquic_result_t *>(0x1);
    ASSERT_EQ(coquic_quic_connection_stop_sending(endpoint, 99, &stop, 0, &result),
              COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = 99});
    coquic_result_destroy(result);
    result = reinterpret_cast<coquic_result_t *>(0x1);

    expect_invalid(coquic_connection_close(endpoint, 1, nullptr, 0, &result));
    EXPECT_EQ(coquic_connection_close(endpoint, 1, nullptr, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    const char reason[] = "done";
    coquic_close_connection_t close{.size = 0,
                                    .application_error_code = 44,
                                    .reason_phrase = reason,
                                    .reason_phrase_length = sizeof(reason) - 1};
    expect_invalid(coquic_connection_close(endpoint, 1, &close, 0, &result));
    close.size = sizeof(coquic_close_connection_t);
    EXPECT_EQ(coquic_connection_close(nullptr, 99, &close, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    result = reinterpret_cast<coquic_result_t *>(0x1);
    ASSERT_EQ(coquic_quic_connection_close(endpoint, 99, &close, 0, &result), COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = 99});
    coquic_result_destroy(result);
    result = reinterpret_cast<coquic_result_t *>(0x1);

    expect_invalid(coquic_connection_request_migration(endpoint, 1, nullptr, 0, &result));
    EXPECT_EQ(coquic_connection_request_migration(endpoint, 1, nullptr, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);
    coquic_request_connection_migration_t migration{
        .size = 0,
        .route_handle = 101,
        .reason = COQUIC_MIGRATION_REASON_PREFERRED_ADDRESS,
        .address_validation_identity = bytes_view(payload),
    };
    expect_invalid(coquic_connection_request_migration(endpoint, 1, &migration, 0, &result));
    migration.size = sizeof(coquic_request_connection_migration_t);
    EXPECT_EQ(coquic_connection_request_migration(nullptr, 99, &migration, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    result = reinterpret_cast<coquic_result_t *>(0x1);
    ASSERT_EQ(coquic_connection_request_migration(endpoint, 99, &migration, 0, &result),
              COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = 99});
    coquic_result_destroy(result);
    result = reinterpret_cast<coquic_result_t *>(0x1);
    migration.reason = static_cast<coquic_migration_reason_t>(99);
    ASSERT_EQ(coquic_connection_request_migration(endpoint, 99, &migration, 0, &result),
              COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = 99});
    coquic_result_destroy(result);
    result = reinterpret_cast<coquic_result_t *>(0x1);

    ASSERT_EQ(coquic_quic_connection_request_key_update(endpoint, 99, 0, &result),
              COQUIC_STATUS_OK);
    expect_local_error(result, {.connection = 99});
    coquic_result_destroy(result);

    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, ConnectionAdvanceValidationCoversAllKinds) {
    coquic_endpoint_config_t endpoint_config{};
    coquic_endpoint_config_init(&endpoint_config);
    endpoint_config.role = COQUIC_ROLE_CLIENT;
    endpoint_config.verify_peer = 0;

    coquic_endpoint_t *endpoint = nullptr;
    ASSERT_EQ(coquic_endpoint_create(&endpoint_config, &endpoint), COQUIC_STATUS_OK);
    ASSERT_NE(endpoint, nullptr);

    const std::vector<std::uint8_t> payload{0x01, 0x02};
    coquic_result_t *result = reinterpret_cast<coquic_result_t *>(0x1);
    EXPECT_EQ(coquic_connection_advance(endpoint, 99, nullptr, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);
    EXPECT_EQ(coquic_connection_advance(endpoint, 99, nullptr, 0, nullptr),
              COQUIC_STATUS_INVALID_ARGUMENT);

    auto expect_advance_error = [&](coquic_connection_input_t input) {
        result = nullptr;
        ASSERT_EQ(coquic_quic_connection_advance(endpoint, 99, &input, 0, &result),
                  COQUIC_STATUS_OK);
        expect_local_error(result, {.connection = 99});
        coquic_result_destroy(result);
    };

    coquic_connection_input_t input{};
    input.kind = COQUIC_CONNECTION_INPUT_SEND_STREAM;
    input.as.send_stream = {.size = sizeof(coquic_send_stream_data_t),
                            .stream_id = 0,
                            .bytes = bytes_view(payload),
                            .fin = 1};
    expect_advance_error(input);

    input = {};
    input.kind = COQUIC_CONNECTION_INPUT_SEND_DATAGRAM;
    input.as.send_datagram = {.size = sizeof(coquic_send_datagram_data_t),
                              .bytes = bytes_view(payload)};
    expect_advance_error(input);

    input = {};
    input.kind = COQUIC_CONNECTION_INPUT_RESET_STREAM;
    input.as.reset_stream = {
        .size = sizeof(coquic_reset_stream_t), .stream_id = 4, .application_error_code = 42};
    expect_advance_error(input);

    input = {};
    input.kind = COQUIC_CONNECTION_INPUT_STOP_SENDING;
    input.as.stop_sending = {
        .size = sizeof(coquic_stop_sending_t), .stream_id = 8, .application_error_code = 43};
    expect_advance_error(input);

    input = {};
    input.kind = COQUIC_CONNECTION_INPUT_CLOSE;
    input.as.close = {.size = sizeof(coquic_close_connection_t),
                      .application_error_code = 44,
                      .reason_phrase = nullptr,
                      .reason_phrase_length = 7};
    expect_advance_error(input);

    input = {};
    input.kind = COQUIC_CONNECTION_INPUT_REQUEST_KEY_UPDATE;
    expect_advance_error(input);

    input = {};
    input.kind = COQUIC_CONNECTION_INPUT_REQUEST_MIGRATION;
    input.as.request_migration = {.size = sizeof(coquic_request_connection_migration_t),
                                  .route_handle = 7,
                                  .reason = COQUIC_MIGRATION_REASON_ACTIVE,
                                  .address_validation_identity = bytes_view(payload)};
    expect_advance_error(input);

    for (auto invalid : {
             coquic_connection_input_t{.kind = COQUIC_CONNECTION_INPUT_SEND_STREAM,
                                       .as = {.send_stream = {.size = 0}}},
             coquic_connection_input_t{.kind = COQUIC_CONNECTION_INPUT_SEND_DATAGRAM,
                                       .as = {.send_datagram = {.size = 0}}},
             coquic_connection_input_t{.kind = COQUIC_CONNECTION_INPUT_RESET_STREAM,
                                       .as = {.reset_stream = {.size = 0}}},
             coquic_connection_input_t{.kind = COQUIC_CONNECTION_INPUT_STOP_SENDING,
                                       .as = {.stop_sending = {.size = 0}}},
             coquic_connection_input_t{.kind = COQUIC_CONNECTION_INPUT_CLOSE,
                                       .as = {.close = {.size = 0}}},
             coquic_connection_input_t{.kind = COQUIC_CONNECTION_INPUT_REQUEST_MIGRATION,
                                       .as = {.request_migration = {.size = 0}}},
             coquic_connection_input_t{.kind = static_cast<coquic_connection_input_kind_t>(99)},
         }) {
        result = reinterpret_cast<coquic_result_t *>(0x1);
        EXPECT_EQ(coquic_connection_advance(endpoint, 99, &invalid, 0, &result),
                  COQUIC_STATUS_INVALID_ARGUMENT);
        EXPECT_EQ(result, nullptr);
    }

    input = {};
    input.kind = COQUIC_CONNECTION_INPUT_REQUEST_KEY_UPDATE;
    result = reinterpret_cast<coquic_result_t *>(0x1);
    EXPECT_EQ(coquic_connection_advance(nullptr, 99, &input, 0, &result),
              COQUIC_STATUS_INVALID_ARGUMENT);
    EXPECT_EQ(result, nullptr);

    coquic_endpoint_destroy(endpoint);
}

TEST(CoquicCoreFfiTest, ResultAccessorsExposeAllEffectVariants) {
    coquic::core::Result core_result;
    core_result.next_wakeup = coquic::core::TimePoint{std::chrono::microseconds{12345}};
    core_result.send_continuation_pending = true;
    core_result.effects = {
        coquic::core::SendDatagram{
            .connection = 1,
            .route_handle = 41,
            .bytes = core_bytes({0x01, 0x02}),
            .ecn = coquic::core::EcnCodepoint::ce,
            .is_pmtu_probe = true,
        },
        coquic::core::ReceiveStreamData{
            .connection = 2,
            .stream_id = 8,
            .offset = 13,
            .bytes = core_bytes({0x03, 0x04, 0x05}),
            .fin = true,
            .final_size = 16,
        },
        coquic::core::ReceiveDatagramData{
            .connection = 3,
            .bytes = core_bytes({0x06}),
        },
        coquic::core::PeerResetStream{
            .connection = 4,
            .stream_id = 12,
            .application_error_code = 77,
            .final_size = 99,
        },
        coquic::core::PeerStopSending{
            .connection = 5,
            .stream_id = 16,
            .application_error_code = 78,
        },
        coquic::core::StateEvent{
            .connection = 6,
            .change = coquic::core::StateChange::handshake_confirmed,
        },
        coquic::core::ConnectionLifecycleEvent{
            .connection = 7,
            .event = coquic::core::Lifecycle::accepted,
        },
        coquic::core::PeerPreferredAddressAvailable{
            .connection = 8,
            .preferred_address =
                {
                    .ipv4_address = byte_array<4>({192, 0, 2, 1}),
                    .ipv4_port = 4433,
                    .ipv6_address = byte_array<16>(
                        {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
                    .ipv6_port = 4434,
                    .connection_id = core_bytes({0xaa, 0xbb}),
                    .stateless_reset_token =
                        byte_array<16>({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}),
                },
        },
        coquic::core::ResumptionStateAvailable{
            .connection = 9,
            .state = {.serialized = core_bytes({0x10, 0x11})},
        },
        coquic::core::ZeroRttStatusEvent{
            .connection = 10,
            .status = coquic::core::ZeroRttStatus::accepted,
        },
        coquic::core::PacketInspection{
            .connection = 11,
            .direction = coquic::core::PacketInspectionDirection::inbound,
            .packet_type = coquic::core::PacketInspectionPacketType::handshake,
            .datagram_id = 100,
            .datagram_length = 1200,
            .datagram_offset = 32,
            .packet_length = 900,
            .version = 1,
            .destination_connection_id = core_bytes({0x21}),
            .source_connection_id = core_bytes({0x22}),
            .token = core_bytes({0x23, 0x24}),
            .spin_bit = true,
            .key_phase = true,
            .packet_number_length = 4,
            .packet_number = 55,
            .encrypted_packet = core_bytes({0x25, 0x26}),
            .plaintext_payload = core_bytes({0x27}),
        },
        coquic::core::NewTokenAvailable{
            .connection = 12,
            .token = core_bytes({0x31, 0x32, 0x33}),
        },
    };

    coquic_result result(std::move(core_result));
    ASSERT_EQ(coquic_result_effect_count(&result), 12u);
    EXPECT_EQ(coquic_result_send_continuation_pending(&result), 1);
    const auto next_wakeup = coquic_result_next_wakeup(&result);
    ASSERT_EQ(next_wakeup.has_value, 1);
    EXPECT_EQ(next_wakeup.value, 12345u);

    coquic_effect_t effect{};
    ASSERT_EQ(coquic_result_effect_at(&result, 0, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_SEND_DATAGRAM);
    EXPECT_EQ(effect.as.send_datagram.connection, 1u);
    ASSERT_EQ(effect.as.send_datagram.route_handle.has_value, 1);
    EXPECT_EQ(effect.as.send_datagram.route_handle.value, 41u);
    expect_bytes(effect.as.send_datagram.bytes, {0x01, 0x02});
    EXPECT_EQ(effect.as.send_datagram.ecn, COQUIC_ECN_CE);
    EXPECT_EQ(effect.as.send_datagram.is_pmtu_probe, 1);

    ASSERT_EQ(coquic_result_effect_at(&result, 1, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_RECEIVE_STREAM_DATA);
    EXPECT_EQ(effect.as.receive_stream_data.connection, 2u);
    EXPECT_EQ(effect.as.receive_stream_data.stream_id, 8u);
    EXPECT_EQ(effect.as.receive_stream_data.offset, 13u);
    expect_bytes(effect.as.receive_stream_data.bytes, {0x03, 0x04, 0x05});
    EXPECT_EQ(effect.as.receive_stream_data.fin, 1);
    ASSERT_EQ(effect.as.receive_stream_data.final_size.has_value, 1);
    EXPECT_EQ(effect.as.receive_stream_data.final_size.value, 16u);

    ASSERT_EQ(coquic_result_effect_at(&result, 2, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_RECEIVE_DATAGRAM_DATA);
    EXPECT_EQ(effect.as.receive_datagram_data.connection, 3u);
    expect_bytes(effect.as.receive_datagram_data.bytes, {0x06});

    ASSERT_EQ(coquic_result_effect_at(&result, 3, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_PEER_RESET_STREAM);
    EXPECT_EQ(effect.as.peer_reset_stream.connection, 4u);
    EXPECT_EQ(effect.as.peer_reset_stream.stream_id, 12u);
    EXPECT_EQ(effect.as.peer_reset_stream.application_error_code, 77u);
    EXPECT_EQ(effect.as.peer_reset_stream.final_size, 99u);

    ASSERT_EQ(coquic_result_effect_at(&result, 4, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_PEER_STOP_SENDING);
    EXPECT_EQ(effect.as.peer_stop_sending.connection, 5u);
    EXPECT_EQ(effect.as.peer_stop_sending.stream_id, 16u);
    EXPECT_EQ(effect.as.peer_stop_sending.application_error_code, 78u);

    ASSERT_EQ(coquic_result_effect_at(&result, 5, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_STATE_EVENT);
    EXPECT_EQ(effect.as.state_event.connection, 6u);
    EXPECT_EQ(effect.as.state_event.change, COQUIC_STATE_CHANGE_HANDSHAKE_CONFIRMED);

    ASSERT_EQ(coquic_result_effect_at(&result, 6, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_CONNECTION_LIFECYCLE_EVENT);
    EXPECT_EQ(effect.as.connection_lifecycle_event.connection, 7u);
    EXPECT_EQ(effect.as.connection_lifecycle_event.event, COQUIC_LIFECYCLE_ACCEPTED);

    ASSERT_EQ(coquic_result_effect_at(&result, 7, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_PEER_PREFERRED_ADDRESS_AVAILABLE);
    EXPECT_EQ(effect.as.peer_preferred_address_available.connection, 8u);
    const auto &address = effect.as.peer_preferred_address_available.preferred_address;
    EXPECT_EQ(address.ipv4_address[0], 192u);
    EXPECT_EQ(address.ipv4_address[3], 1u);
    EXPECT_EQ(address.ipv4_port, 4433u);
    EXPECT_EQ(address.ipv6_address[0], 0x20u);
    EXPECT_EQ(address.ipv6_address[15], 1u);
    EXPECT_EQ(address.ipv6_port, 4434u);
    expect_bytes(address.connection_id, {0xaa, 0xbb});
    EXPECT_EQ(address.stateless_reset_token[0], 0u);
    EXPECT_EQ(address.stateless_reset_token[15], 15u);

    ASSERT_EQ(coquic_result_effect_at(&result, 8, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_RESUMPTION_STATE_AVAILABLE);
    EXPECT_EQ(effect.as.resumption_state_available.connection, 9u);
    expect_bytes(effect.as.resumption_state_available.serialized, {0x10, 0x11});

    ASSERT_EQ(coquic_result_effect_at(&result, 9, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_ZERO_RTT_STATUS_EVENT);
    EXPECT_EQ(effect.as.zero_rtt_status_event.connection, 10u);
    EXPECT_EQ(effect.as.zero_rtt_status_event.status, COQUIC_ZERO_RTT_ACCEPTED);

    ASSERT_EQ(coquic_result_effect_at(&result, 10, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_PACKET_INSPECTION);
    EXPECT_EQ(effect.as.packet_inspection.connection, 11u);
    EXPECT_EQ(effect.as.packet_inspection.direction, COQUIC_PACKET_INSPECTION_INBOUND);
    EXPECT_EQ(effect.as.packet_inspection.packet_type, COQUIC_PACKET_INSPECTION_HANDSHAKE);
    EXPECT_EQ(effect.as.packet_inspection.datagram_id, 100u);
    EXPECT_EQ(effect.as.packet_inspection.datagram_length, 1200u);
    EXPECT_EQ(effect.as.packet_inspection.datagram_offset, 32u);
    EXPECT_EQ(effect.as.packet_inspection.packet_length, 900u);
    EXPECT_EQ(effect.as.packet_inspection.version, 1u);
    expect_bytes(effect.as.packet_inspection.destination_connection_id, {0x21});
    expect_bytes(effect.as.packet_inspection.source_connection_id, {0x22});
    expect_bytes(effect.as.packet_inspection.token, {0x23, 0x24});
    EXPECT_EQ(effect.as.packet_inspection.spin_bit, 1);
    EXPECT_EQ(effect.as.packet_inspection.key_phase, 1);
    EXPECT_EQ(effect.as.packet_inspection.packet_number_length, 4u);
    EXPECT_EQ(effect.as.packet_inspection.packet_number, 55u);
    expect_bytes(effect.as.packet_inspection.encrypted_packet, {0x25, 0x26});
    expect_bytes(effect.as.packet_inspection.plaintext_payload, {0x27});

    ASSERT_EQ(coquic_result_effect_at(&result, 11, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.kind, COQUIC_EFFECT_NEW_TOKEN_AVAILABLE);
    EXPECT_EQ(effect.as.new_token_available.connection, 12u);
    expect_bytes(effect.as.new_token_available.token, {0x31, 0x32, 0x33});
}

TEST(CoquicCoreFfiTest, ResultAccessorsExposeRemainingEnumVariants) {
    coquic::core::Result core_result;
    core_result.effects = {
        coquic::core::SendDatagram{
            .connection = 1,
            .route_handle = std::nullopt,
            .bytes = {},
            .ecn = coquic::core::EcnCodepoint::unavailable,
            .is_pmtu_probe = false,
        },
        coquic::core::SendDatagram{
            .connection = 2,
            .route_handle = std::nullopt,
            .bytes = {},
            .ecn = coquic::core::EcnCodepoint::ect0,
            .is_pmtu_probe = false,
        },
        coquic::core::SendDatagram{
            .connection = 3,
            .route_handle = std::nullopt,
            .bytes = {},
            .ecn = coquic::core::EcnCodepoint::ect1,
            .is_pmtu_probe = false,
        },
        coquic::core::SendDatagram{
            .connection = 14,
            .route_handle = std::nullopt,
            .bytes = {},
            .ecn = enum_value_from_underlying_for_tests<coquic::core::EcnCodepoint>(99),
            .is_pmtu_probe = false,
        },
        coquic::core::StateEvent{
            .connection = 4,
            .change = coquic::core::StateChange::handshake_ready,
        },
        coquic::core::StateEvent{
            .connection = 15,
            .change = enum_value_from_underlying_for_tests<coquic::core::StateChange>(99),
        },
        coquic::core::StateEvent{
            .connection = 5,
            .change = coquic::core::StateChange::failed,
        },
        coquic::core::ConnectionLifecycleEvent{
            .connection = 6,
            .event = coquic::core::Lifecycle::closed,
        },
        coquic::core::ConnectionLifecycleEvent{
            .connection = 16,
            .event = enum_value_from_underlying_for_tests<coquic::core::Lifecycle>(99),
        },
        coquic::core::ZeroRttStatusEvent{
            .connection = 7,
            .status = coquic::core::ZeroRttStatus::unavailable,
        },
        coquic::core::ZeroRttStatusEvent{
            .connection = 8,
            .status = coquic::core::ZeroRttStatus::not_attempted,
        },
        coquic::core::ZeroRttStatusEvent{
            .connection = 9,
            .status = coquic::core::ZeroRttStatus::attempted,
        },
        coquic::core::ZeroRttStatusEvent{
            .connection = 10,
            .status = coquic::core::ZeroRttStatus::rejected,
        },
        coquic::core::ZeroRttStatusEvent{
            .connection = 17,
            .status = enum_value_from_underlying_for_tests<coquic::core::ZeroRttStatus>(99),
        },
        coquic::core::PacketInspection{
            .connection = 11,
            .direction = coquic::core::PacketInspectionDirection::outbound,
            .packet_type = coquic::core::PacketInspectionPacketType::initial,
        },
        coquic::core::PacketInspection{
            .connection = 18,
            .direction =
                enum_value_from_underlying_for_tests<coquic::core::PacketInspectionDirection>(99),
            .packet_type = coquic::core::PacketInspectionPacketType::initial,
        },
        coquic::core::PacketInspection{
            .connection = 12,
            .direction = coquic::core::PacketInspectionDirection::outbound,
            .packet_type = coquic::core::PacketInspectionPacketType::zero_rtt,
        },
        coquic::core::PacketInspection{
            .connection = 13,
            .direction = coquic::core::PacketInspectionDirection::outbound,
            .packet_type = coquic::core::PacketInspectionPacketType::one_rtt,
        },
        coquic::core::PacketInspection{
            .connection = 19,
            .direction = coquic::core::PacketInspectionDirection::outbound,
            .packet_type =
                enum_value_from_underlying_for_tests<coquic::core::PacketInspectionPacketType>(99),
        },
    };

    coquic_result result(std::move(core_result));
    coquic_effect_t effect{};

    ASSERT_EQ(coquic_result_effect_at(&result, 0, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.send_datagram.ecn, COQUIC_ECN_UNAVAILABLE);
    EXPECT_EQ(effect.as.send_datagram.route_handle.has_value, 0);
    EXPECT_EQ(effect.as.send_datagram.bytes.length, 0u);
    ASSERT_EQ(coquic_result_effect_at(&result, 1, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.send_datagram.ecn, COQUIC_ECN_ECT0);
    ASSERT_EQ(coquic_result_effect_at(&result, 2, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.send_datagram.ecn, COQUIC_ECN_ECT1);
    ASSERT_EQ(coquic_result_effect_at(&result, 3, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.send_datagram.ecn, COQUIC_ECN_UNAVAILABLE);

    ASSERT_EQ(coquic_result_effect_at(&result, 4, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.state_event.change, COQUIC_STATE_CHANGE_HANDSHAKE_READY);
    ASSERT_EQ(coquic_result_effect_at(&result, 5, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.state_event.change, COQUIC_STATE_CHANGE_FAILED);
    ASSERT_EQ(coquic_result_effect_at(&result, 6, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.state_event.change, COQUIC_STATE_CHANGE_FAILED);
    ASSERT_EQ(coquic_result_effect_at(&result, 7, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.connection_lifecycle_event.event, COQUIC_LIFECYCLE_CLOSED);
    ASSERT_EQ(coquic_result_effect_at(&result, 8, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.connection_lifecycle_event.event, COQUIC_LIFECYCLE_CLOSED);

    ASSERT_EQ(coquic_result_effect_at(&result, 9, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.zero_rtt_status_event.status, COQUIC_ZERO_RTT_UNAVAILABLE);
    ASSERT_EQ(coquic_result_effect_at(&result, 10, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.zero_rtt_status_event.status, COQUIC_ZERO_RTT_NOT_ATTEMPTED);
    ASSERT_EQ(coquic_result_effect_at(&result, 11, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.zero_rtt_status_event.status, COQUIC_ZERO_RTT_ATTEMPTED);
    ASSERT_EQ(coquic_result_effect_at(&result, 12, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.zero_rtt_status_event.status, COQUIC_ZERO_RTT_REJECTED);
    ASSERT_EQ(coquic_result_effect_at(&result, 13, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.zero_rtt_status_event.status, COQUIC_ZERO_RTT_UNAVAILABLE);

    ASSERT_EQ(coquic_result_effect_at(&result, 14, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.packet_inspection.direction, COQUIC_PACKET_INSPECTION_OUTBOUND);
    EXPECT_EQ(effect.as.packet_inspection.packet_type, COQUIC_PACKET_INSPECTION_INITIAL);
    ASSERT_EQ(coquic_result_effect_at(&result, 15, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.packet_inspection.direction, COQUIC_PACKET_INSPECTION_OUTBOUND);
    ASSERT_EQ(coquic_result_effect_at(&result, 16, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.packet_inspection.packet_type, COQUIC_PACKET_INSPECTION_ZERO_RTT);
    ASSERT_EQ(coquic_result_effect_at(&result, 17, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.packet_inspection.packet_type, COQUIC_PACKET_INSPECTION_ONE_RTT);
    ASSERT_EQ(coquic_result_effect_at(&result, 18, &effect), COQUIC_STATUS_OK);
    EXPECT_EQ(effect.as.packet_inspection.packet_type, COQUIC_PACKET_INSPECTION_INITIAL);
}

TEST(CoquicCoreFfiTest, ResultLocalErrorsExposeAllCodesAndOptionalFields) {
    const std::vector<coquic::core::LocalErrorCode> codes{
        coquic::core::LocalErrorCode::unsupported_operation,
        coquic::core::LocalErrorCode::invalid_stream_id,
        coquic::core::LocalErrorCode::invalid_stream_direction,
        coquic::core::LocalErrorCode::send_side_closed,
        coquic::core::LocalErrorCode::receive_side_closed,
        coquic::core::LocalErrorCode::final_size_conflict,
        coquic::core::LocalErrorCode::datagram_not_supported,
        coquic::core::LocalErrorCode::datagram_too_large,
        coquic::core::LocalErrorCode::flow_control_violation,
    };
    const std::vector<coquic_local_error_code_t> ffi_codes{
        COQUIC_LOCAL_ERROR_UNSUPPORTED_OPERATION,    COQUIC_LOCAL_ERROR_INVALID_STREAM_ID,
        COQUIC_LOCAL_ERROR_INVALID_STREAM_DIRECTION, COQUIC_LOCAL_ERROR_SEND_SIDE_CLOSED,
        COQUIC_LOCAL_ERROR_RECEIVE_SIDE_CLOSED,      COQUIC_LOCAL_ERROR_FINAL_SIZE_CONFLICT,
        COQUIC_LOCAL_ERROR_DATAGRAM_NOT_SUPPORTED,   COQUIC_LOCAL_ERROR_DATAGRAM_TOO_LARGE,
        COQUIC_LOCAL_ERROR_FLOW_CONTROL_VIOLATION,
    };

    for (std::size_t index = 0; index < codes.size(); ++index) {
        coquic::core::Result core_result;
        core_result.local_error = coquic::core::LocalError{
            .connection = index % 2 == 0
                              ? std::optional<coquic::core::ConnectionHandle>{100 + index}
                              : std::nullopt,
            .code = codes[index],
            .stream_id =
                index % 3 == 0 ? std::optional<coquic::core::StreamId>{200 + index} : std::nullopt,
        };
        coquic_result result(std::move(core_result));

        ASSERT_EQ(coquic_result_has_local_error(&result), 1);
        coquic_local_error_t error{};
        ASSERT_EQ(coquic_result_local_error(&result, &error), COQUIC_STATUS_OK);
        EXPECT_EQ(error.code, ffi_codes[index]);
        EXPECT_EQ(error.connection.has_value, index % 2 == 0 ? 1 : 0);
        if (error.connection.has_value != 0) {
            EXPECT_EQ(error.connection.value, 100u + index);
        }
        EXPECT_EQ(error.stream_id.has_value, index % 3 == 0 ? 1 : 0);
        if (error.stream_id.has_value != 0) {
            EXPECT_EQ(error.stream_id.value, 200u + index);
        }
    }
}
