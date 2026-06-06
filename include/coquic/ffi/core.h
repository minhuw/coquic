#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef COQUIC_FFI_API
#if defined(_WIN32)
#if defined(COQUIC_FFI_BUILD)
#define COQUIC_FFI_API __declspec(dllexport)
#elif defined(COQUIC_FFI_USE_SHARED)
#define COQUIC_FFI_API __declspec(dllimport)
#else
#define COQUIC_FFI_API
#endif
#elif defined(COQUIC_FFI_BUILD)
#define COQUIC_FFI_API __attribute__((visibility("default")))
#else
#define COQUIC_FFI_API
#endif
#endif

#define COQUIC_FFI_ABI_VERSION 1u

typedef struct coquic_endpoint coquic_endpoint_t;
typedef struct coquic_result coquic_result_t;

typedef uint64_t coquic_connection_handle_t;
typedef uint64_t coquic_route_handle_t;
typedef uint64_t coquic_stream_id_t;
typedef uint64_t coquic_time_us_t;

typedef uint8_t coquic_status_t;
#define COQUIC_STATUS_OK 0u
#define COQUIC_STATUS_INVALID_ARGUMENT 1u
#define COQUIC_STATUS_OUT_OF_MEMORY 2u
#define COQUIC_STATUS_INTERNAL_ERROR 3u

typedef uint8_t coquic_role_t;
#define COQUIC_ROLE_CLIENT 0u
#define COQUIC_ROLE_SERVER 1u

typedef uint8_t coquic_congestion_control_t;
#define COQUIC_CONGESTION_CONTROL_NEWRENO 0u
#define COQUIC_CONGESTION_CONTROL_CUBIC 1u
#define COQUIC_CONGESTION_CONTROL_BBR 2u
#define COQUIC_CONGESTION_CONTROL_COPA 3u

typedef uint8_t coquic_ecn_codepoint_t;
#define COQUIC_ECN_UNAVAILABLE 0u
#define COQUIC_ECN_NOT_ECT 1u
#define COQUIC_ECN_ECT0 2u
#define COQUIC_ECN_ECT1 3u
#define COQUIC_ECN_CE 4u

typedef uint8_t coquic_state_change_t;
#define COQUIC_STATE_CHANGE_HANDSHAKE_READY 0u
#define COQUIC_STATE_CHANGE_HANDSHAKE_CONFIRMED 1u
#define COQUIC_STATE_CHANGE_FAILED 2u

typedef uint8_t coquic_local_error_code_t;
#define COQUIC_LOCAL_ERROR_UNSUPPORTED_OPERATION 0u
#define COQUIC_LOCAL_ERROR_INVALID_STREAM_ID 1u
#define COQUIC_LOCAL_ERROR_INVALID_STREAM_DIRECTION 2u
#define COQUIC_LOCAL_ERROR_SEND_SIDE_CLOSED 3u
#define COQUIC_LOCAL_ERROR_RECEIVE_SIDE_CLOSED 4u
#define COQUIC_LOCAL_ERROR_FINAL_SIZE_CONFLICT 5u
#define COQUIC_LOCAL_ERROR_DATAGRAM_NOT_SUPPORTED 6u
#define COQUIC_LOCAL_ERROR_DATAGRAM_TOO_LARGE 7u

typedef uint8_t coquic_lifecycle_t;
#define COQUIC_LIFECYCLE_CREATED 0u
#define COQUIC_LIFECYCLE_ACCEPTED 1u
#define COQUIC_LIFECYCLE_CLOSED 2u

typedef uint8_t coquic_migration_reason_t;
#define COQUIC_MIGRATION_REASON_ACTIVE 0u
#define COQUIC_MIGRATION_REASON_PREFERRED_ADDRESS 1u

typedef uint8_t coquic_zero_rtt_status_t;
#define COQUIC_ZERO_RTT_UNAVAILABLE 0u
#define COQUIC_ZERO_RTT_NOT_ATTEMPTED 1u
#define COQUIC_ZERO_RTT_ATTEMPTED 2u
#define COQUIC_ZERO_RTT_ACCEPTED 3u
#define COQUIC_ZERO_RTT_REJECTED 4u

typedef uint8_t coquic_packet_inspection_direction_t;
#define COQUIC_PACKET_INSPECTION_OUTBOUND 0u
#define COQUIC_PACKET_INSPECTION_INBOUND 1u

typedef uint8_t coquic_packet_inspection_packet_type_t;
#define COQUIC_PACKET_INSPECTION_INITIAL 0u
#define COQUIC_PACKET_INSPECTION_ZERO_RTT 1u
#define COQUIC_PACKET_INSPECTION_HANDSHAKE 2u
#define COQUIC_PACKET_INSPECTION_ONE_RTT 3u

typedef uint8_t coquic_connection_input_kind_t;
#define COQUIC_CONNECTION_INPUT_SEND_STREAM 0u
#define COQUIC_CONNECTION_INPUT_SEND_DATAGRAM 1u
#define COQUIC_CONNECTION_INPUT_RESET_STREAM 2u
#define COQUIC_CONNECTION_INPUT_STOP_SENDING 3u
#define COQUIC_CONNECTION_INPUT_CLOSE 4u
#define COQUIC_CONNECTION_INPUT_REQUEST_KEY_UPDATE 5u
#define COQUIC_CONNECTION_INPUT_REQUEST_MIGRATION 6u

typedef uint8_t coquic_effect_kind_t;
#define COQUIC_EFFECT_SEND_DATAGRAM 0u
#define COQUIC_EFFECT_RECEIVE_STREAM_DATA 1u
#define COQUIC_EFFECT_RECEIVE_DATAGRAM_DATA 2u
#define COQUIC_EFFECT_PEER_RESET_STREAM 3u
#define COQUIC_EFFECT_PEER_STOP_SENDING 4u
#define COQUIC_EFFECT_STATE_EVENT 5u
#define COQUIC_EFFECT_CONNECTION_LIFECYCLE_EVENT 6u
#define COQUIC_EFFECT_PEER_PREFERRED_ADDRESS_AVAILABLE 7u
#define COQUIC_EFFECT_RESUMPTION_STATE_AVAILABLE 8u
#define COQUIC_EFFECT_ZERO_RTT_STATUS_EVENT 9u
#define COQUIC_EFFECT_PACKET_INSPECTION 10u
#define COQUIC_EFFECT_NEW_TOKEN_AVAILABLE 11u

typedef struct coquic_bytes_view {
    const uint8_t *data;
    size_t length;
} coquic_bytes_view_t;

typedef struct coquic_bytes {
    const uint8_t *data;
    size_t length;
} coquic_bytes_t;

typedef struct coquic_optional_route_handle {
    uint8_t has_value;
    coquic_route_handle_t value;
} coquic_optional_route_handle_t;

typedef struct coquic_optional_connection_handle {
    uint8_t has_value;
    coquic_connection_handle_t value;
} coquic_optional_connection_handle_t;

typedef struct coquic_optional_stream_id {
    uint8_t has_value;
    coquic_stream_id_t value;
} coquic_optional_stream_id_t;

typedef struct coquic_optional_time_us {
    uint8_t has_value;
    coquic_time_us_t value;
} coquic_optional_time_us_t;

typedef struct coquic_tls_identity {
    const char *certificate_pem;
    size_t certificate_pem_length;
    const char *private_key_pem;
    size_t private_key_pem_length;
} coquic_tls_identity_t;

typedef struct coquic_zero_rtt_config {
    uint8_t attempt;
    uint8_t allow;
    coquic_bytes_t application_context;
} coquic_zero_rtt_config_t;

typedef struct coquic_transport_config {
    uint64_t max_idle_timeout;
    uint64_t max_udp_payload_size;
    uint8_t pmtud_enabled;
    size_t pmtud_base_datagram_size;
    size_t pmtud_max_datagram_size;
    uint64_t active_connection_id_limit;
    uint8_t disable_active_migration;
    uint64_t ack_delay_exponent;
    uint64_t max_ack_delay;
    uint64_t ack_eliciting_threshold;
    uint64_t initial_max_data;
    uint64_t initial_max_stream_data_bidi_local;
    uint64_t initial_max_stream_data_bidi_remote;
    uint64_t initial_max_stream_data_uni;
    uint64_t initial_max_streams_bidi;
    uint64_t initial_max_streams_uni;
    uint64_t max_datagram_frame_size;
    coquic_congestion_control_t congestion_control;
    uint8_t enable_hystart_plus_plus;
    uint8_t send_stream_fairness;
    uint8_t enable_latency_spin_bit;
    uint8_t grease_reserved_versions;
    uint8_t grease_quic_bit;
    uint8_t enable_optimistic_ack_mitigation;
} coquic_transport_config_t;

typedef struct coquic_endpoint_config {
    size_t size;
    coquic_role_t role;
    const uint32_t *supported_versions;
    size_t supported_versions_count;
    uint8_t verify_peer;
    uint8_t retry_enabled;
    const char *application_protocol;
    size_t application_protocol_length;
    const coquic_tls_identity_t *identity;
    coquic_transport_config_t transport;
    size_t max_outbound_datagram_size;
    coquic_zero_rtt_config_t zero_rtt;
    uint8_t emit_shared_receive_stream_data;
    uint8_t enable_packet_inspection;
    uint8_t allow_peer_address_change;
} coquic_endpoint_config_t;

typedef struct coquic_resumption_state {
    coquic_bytes_t serialized;
} coquic_resumption_state_t;

typedef struct coquic_client_connection_config {
    size_t size;
    coquic_bytes_t source_connection_id;
    coquic_bytes_t initial_destination_connection_id;
    coquic_bytes_t original_destination_connection_id;
    uint8_t has_original_destination_connection_id;
    coquic_bytes_t retry_source_connection_id;
    uint8_t has_retry_source_connection_id;
    coquic_bytes_t retry_token;
    uint32_t original_version;
    uint32_t initial_version;
    uint8_t reacted_to_version_negotiation;
    const char *server_name;
    size_t server_name_length;
    const coquic_resumption_state_t *resumption_state;
    coquic_zero_rtt_config_t zero_rtt;
} coquic_client_connection_config_t;

typedef struct coquic_open_connection {
    size_t size;
    coquic_client_connection_config_t connection;
    coquic_route_handle_t initial_route_handle;
    coquic_bytes_t address_validation_identity;
} coquic_open_connection_t;

typedef struct coquic_inbound_datagram {
    size_t size;
    coquic_bytes_t bytes;
    coquic_optional_route_handle_t route_handle;
    coquic_bytes_t address_validation_identity;
    coquic_ecn_codepoint_t ecn;
} coquic_inbound_datagram_t;

typedef struct coquic_path_mtu_update {
    size_t size;
    coquic_optional_route_handle_t route_handle;
    size_t max_udp_payload_size;
} coquic_path_mtu_update_t;

typedef struct coquic_send_stream_data {
    size_t size;
    coquic_stream_id_t stream_id;
    coquic_bytes_t bytes;
    uint8_t fin;
    int32_t priority;
} coquic_send_stream_data_t;

typedef struct coquic_send_datagram_data {
    size_t size;
    coquic_bytes_t bytes;
    int32_t priority;
} coquic_send_datagram_data_t;

typedef struct coquic_reset_stream {
    size_t size;
    coquic_stream_id_t stream_id;
    uint64_t application_error_code;
} coquic_reset_stream_t;

typedef struct coquic_stop_sending {
    size_t size;
    coquic_stream_id_t stream_id;
    uint64_t application_error_code;
} coquic_stop_sending_t;

typedef struct coquic_close_connection {
    size_t size;
    uint64_t application_error_code;
    const char *reason_phrase;
    size_t reason_phrase_length;
} coquic_close_connection_t;

typedef struct coquic_request_connection_migration {
    size_t size;
    coquic_route_handle_t route_handle;
    coquic_migration_reason_t reason;
    coquic_bytes_t address_validation_identity;
} coquic_request_connection_migration_t;

typedef struct coquic_connection_input {
    coquic_connection_input_kind_t kind;
    union {
        coquic_send_stream_data_t send_stream;
        coquic_send_datagram_data_t send_datagram;
        coquic_reset_stream_t reset_stream;
        coquic_stop_sending_t stop_sending;
        coquic_close_connection_t close;
        coquic_request_connection_migration_t request_migration;
    } as;
} coquic_connection_input_t;

typedef struct coquic_local_error {
    coquic_optional_connection_handle_t connection;
    coquic_local_error_code_t code;
    coquic_optional_stream_id_t stream_id;
} coquic_local_error_t;

typedef struct coquic_send_datagram_effect {
    coquic_connection_handle_t connection;
    coquic_optional_route_handle_t route_handle;
    coquic_bytes_view_t bytes;
    coquic_ecn_codepoint_t ecn;
    uint8_t is_pmtu_probe;
} coquic_send_datagram_effect_t;

typedef struct coquic_receive_stream_data_effect {
    coquic_connection_handle_t connection;
    coquic_stream_id_t stream_id;
    coquic_bytes_view_t bytes;
    uint8_t fin;
} coquic_receive_stream_data_effect_t;

typedef struct coquic_receive_datagram_data_effect {
    coquic_connection_handle_t connection;
    coquic_bytes_view_t bytes;
} coquic_receive_datagram_data_effect_t;

typedef struct coquic_peer_reset_stream_effect {
    coquic_connection_handle_t connection;
    coquic_stream_id_t stream_id;
    uint64_t application_error_code;
    uint64_t final_size;
} coquic_peer_reset_stream_effect_t;

typedef struct coquic_peer_stop_sending_effect {
    coquic_connection_handle_t connection;
    coquic_stream_id_t stream_id;
    uint64_t application_error_code;
} coquic_peer_stop_sending_effect_t;

typedef struct coquic_state_event_effect {
    coquic_connection_handle_t connection;
    coquic_state_change_t change;
} coquic_state_event_effect_t;

typedef struct coquic_connection_lifecycle_event_effect {
    coquic_connection_handle_t connection;
    coquic_lifecycle_t event;
} coquic_connection_lifecycle_event_effect_t;

typedef struct coquic_preferred_address {
    uint8_t ipv4_address[4];
    uint16_t ipv4_port;
    uint8_t ipv6_address[16];
    uint16_t ipv6_port;
    coquic_bytes_view_t connection_id;
    uint8_t stateless_reset_token[16];
} coquic_preferred_address_t;

typedef struct coquic_peer_preferred_address_available_effect {
    coquic_connection_handle_t connection;
    coquic_preferred_address_t preferred_address;
} coquic_peer_preferred_address_available_effect_t;

typedef struct coquic_resumption_state_available_effect {
    coquic_connection_handle_t connection;
    coquic_bytes_view_t serialized;
} coquic_resumption_state_available_effect_t;

typedef struct coquic_zero_rtt_status_event_effect {
    coquic_connection_handle_t connection;
    coquic_zero_rtt_status_t status;
} coquic_zero_rtt_status_event_effect_t;

typedef struct coquic_packet_inspection_effect {
    coquic_connection_handle_t connection;
    coquic_packet_inspection_direction_t direction;
    coquic_packet_inspection_packet_type_t packet_type;
    uint64_t datagram_id;
    size_t datagram_length;
    size_t datagram_offset;
    size_t packet_length;
    uint32_t version;
    coquic_bytes_view_t destination_connection_id;
    coquic_bytes_view_t source_connection_id;
    coquic_bytes_view_t token;
    uint8_t spin_bit;
    uint8_t key_phase;
    uint8_t packet_number_length;
    uint64_t packet_number;
    coquic_bytes_view_t encrypted_packet;
    coquic_bytes_view_t plaintext_payload;
} coquic_packet_inspection_effect_t;

typedef struct coquic_new_token_available_effect {
    coquic_connection_handle_t connection;
    coquic_bytes_view_t token;
} coquic_new_token_available_effect_t;

typedef struct coquic_effect {
    coquic_effect_kind_t kind;
    union {
        coquic_send_datagram_effect_t send_datagram;
        coquic_receive_stream_data_effect_t receive_stream_data;
        coquic_receive_datagram_data_effect_t receive_datagram_data;
        coquic_peer_reset_stream_effect_t peer_reset_stream;
        coquic_peer_stop_sending_effect_t peer_stop_sending;
        coquic_state_event_effect_t state_event;
        coquic_connection_lifecycle_event_effect_t connection_lifecycle_event;
        coquic_peer_preferred_address_available_effect_t peer_preferred_address_available;
        coquic_resumption_state_available_effect_t resumption_state_available;
        coquic_zero_rtt_status_event_effect_t zero_rtt_status_event;
        coquic_packet_inspection_effect_t packet_inspection;
        coquic_new_token_available_effect_t new_token_available;
    } as;
} coquic_effect_t;

COQUIC_FFI_API uint32_t coquic_ffi_abi_version(void);
COQUIC_FFI_API void coquic_transport_config_init(coquic_transport_config_t *config);
COQUIC_FFI_API void coquic_endpoint_config_init(coquic_endpoint_config_t *config);
COQUIC_FFI_API void coquic_client_connection_config_init(coquic_client_connection_config_t *config);

COQUIC_FFI_API coquic_status_t coquic_endpoint_create(const coquic_endpoint_config_t *config,
                                                      coquic_endpoint_t **out_endpoint);
COQUIC_FFI_API void coquic_endpoint_destroy(coquic_endpoint_t *endpoint);

COQUIC_FFI_API coquic_status_t
coquic_endpoint_open_connection(coquic_endpoint_t *endpoint, const coquic_open_connection_t *input,
                                coquic_time_us_t now, coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t
coquic_endpoint_input_datagram(coquic_endpoint_t *endpoint, const coquic_inbound_datagram_t *input,
                               coquic_time_us_t now, coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t
coquic_endpoint_update_path_mtu(coquic_endpoint_t *endpoint, const coquic_path_mtu_update_t *input,
                                coquic_time_us_t now, coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_endpoint_timer_expired(coquic_endpoint_t *endpoint,
                                                             coquic_time_us_t now,
                                                             coquic_result_t **out_result);

COQUIC_FFI_API coquic_status_t coquic_connection_send_stream(coquic_endpoint_t *endpoint,
                                                             coquic_connection_handle_t connection,
                                                             const coquic_send_stream_data_t *input,
                                                             coquic_time_us_t now,
                                                             coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_connection_send_datagram(
    coquic_endpoint_t *endpoint, coquic_connection_handle_t connection,
    const coquic_send_datagram_data_t *input, coquic_time_us_t now, coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_connection_reset_stream(coquic_endpoint_t *endpoint,
                                                              coquic_connection_handle_t connection,
                                                              const coquic_reset_stream_t *input,
                                                              coquic_time_us_t now,
                                                              coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_connection_stop_sending(coquic_endpoint_t *endpoint,
                                                              coquic_connection_handle_t connection,
                                                              const coquic_stop_sending_t *input,
                                                              coquic_time_us_t now,
                                                              coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_connection_close(coquic_endpoint_t *endpoint,
                                                       coquic_connection_handle_t connection,
                                                       const coquic_close_connection_t *input,
                                                       coquic_time_us_t now,
                                                       coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_connection_request_key_update(
    coquic_endpoint_t *endpoint, coquic_connection_handle_t connection, coquic_time_us_t now,
    coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_connection_request_migration(
    coquic_endpoint_t *endpoint, coquic_connection_handle_t connection,
    const coquic_request_connection_migration_t *input, coquic_time_us_t now,
    coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_connection_advance(coquic_endpoint_t *endpoint,
                                                         coquic_connection_handle_t connection,
                                                         const coquic_connection_input_t *input,
                                                         coquic_time_us_t now,
                                                         coquic_result_t **out_result);

COQUIC_FFI_API coquic_status_t coquic_quic_connect(coquic_endpoint_t *endpoint,
                                                   const coquic_open_connection_t *input,
                                                   coquic_time_us_t now,
                                                   coquic_connection_handle_t *out_connection,
                                                   coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_quic_receive_datagram(coquic_endpoint_t *endpoint,
                                                            const coquic_inbound_datagram_t *input,
                                                            coquic_time_us_t now,
                                                            coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_quic_update_path_mtu(coquic_endpoint_t *endpoint,
                                                           const coquic_path_mtu_update_t *input,
                                                           coquic_time_us_t now,
                                                           coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_quic_timer_expired(coquic_endpoint_t *endpoint,
                                                         coquic_time_us_t now,
                                                         coquic_result_t **out_result);

COQUIC_FFI_API coquic_status_t coquic_quic_connection_send_stream(
    coquic_endpoint_t *endpoint, coquic_connection_handle_t connection,
    const coquic_send_stream_data_t *input, coquic_time_us_t now, coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_quic_connection_send_datagram(
    coquic_endpoint_t *endpoint, coquic_connection_handle_t connection,
    const coquic_send_datagram_data_t *input, coquic_time_us_t now, coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_quic_connection_reset_stream(
    coquic_endpoint_t *endpoint, coquic_connection_handle_t connection,
    const coquic_reset_stream_t *input, coquic_time_us_t now, coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_quic_connection_stop_sending(
    coquic_endpoint_t *endpoint, coquic_connection_handle_t connection,
    const coquic_stop_sending_t *input, coquic_time_us_t now, coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_quic_connection_close(coquic_endpoint_t *endpoint,
                                                            coquic_connection_handle_t connection,
                                                            const coquic_close_connection_t *input,
                                                            coquic_time_us_t now,
                                                            coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_quic_connection_request_key_update(
    coquic_endpoint_t *endpoint, coquic_connection_handle_t connection, coquic_time_us_t now,
    coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_quic_connection_advance(
    coquic_endpoint_t *endpoint, coquic_connection_handle_t connection,
    const coquic_connection_input_t *input, coquic_time_us_t now, coquic_result_t **out_result);

COQUIC_FFI_API coquic_status_t coquic_quic_stream_send(coquic_endpoint_t *endpoint,
                                                       coquic_connection_handle_t connection,
                                                       coquic_stream_id_t stream_id,
                                                       coquic_bytes_t bytes, uint8_t fin,
                                                       coquic_time_us_t now,
                                                       coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_quic_stream_finish(coquic_endpoint_t *endpoint,
                                                         coquic_connection_handle_t connection,
                                                         coquic_stream_id_t stream_id,
                                                         coquic_time_us_t now,
                                                         coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t coquic_quic_stream_reset(coquic_endpoint_t *endpoint,
                                                        coquic_connection_handle_t connection,
                                                        coquic_stream_id_t stream_id,
                                                        uint64_t application_error_code,
                                                        coquic_time_us_t now,
                                                        coquic_result_t **out_result);
COQUIC_FFI_API coquic_status_t
coquic_quic_stream_stop_sending(coquic_endpoint_t *endpoint, coquic_connection_handle_t connection,
                                coquic_stream_id_t stream_id, uint64_t application_error_code,
                                coquic_time_us_t now, coquic_result_t **out_result);

COQUIC_FFI_API size_t coquic_endpoint_connection_count(const coquic_endpoint_t *endpoint);
COQUIC_FFI_API uint8_t
coquic_endpoint_has_send_continuation_pending(const coquic_endpoint_t *endpoint);
COQUIC_FFI_API uint8_t coquic_endpoint_has_pending_stream_send(const coquic_endpoint_t *endpoint);
COQUIC_FFI_API coquic_optional_time_us_t
coquic_endpoint_next_wakeup(const coquic_endpoint_t *endpoint);

COQUIC_FFI_API void coquic_result_destroy(coquic_result_t *result);
COQUIC_FFI_API size_t coquic_result_effect_count(const coquic_result_t *result);
COQUIC_FFI_API coquic_status_t coquic_result_effect_at(const coquic_result_t *result, size_t index,
                                                       coquic_effect_t *out_effect);
COQUIC_FFI_API coquic_optional_time_us_t coquic_result_next_wakeup(const coquic_result_t *result);
COQUIC_FFI_API uint8_t coquic_result_has_local_error(const coquic_result_t *result);
COQUIC_FFI_API coquic_status_t coquic_result_local_error(const coquic_result_t *result,
                                                         coquic_local_error_t *out_error);
COQUIC_FFI_API uint8_t coquic_result_send_continuation_pending(const coquic_result_t *result);

#ifdef __cplusplus
}
#endif
