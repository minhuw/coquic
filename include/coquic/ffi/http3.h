#pragma once

#include "coquic/ffi/core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct coquic_http3_client coquic_http3_client_t;
typedef struct coquic_http3_server coquic_http3_server_t;
typedef struct coquic_http3_client_update coquic_http3_client_update_t;
typedef struct coquic_http3_server_update coquic_http3_server_update_t;

typedef uint16_t coquic_http3_error_code_t;
#define COQUIC_HTTP3_ERROR_NO_ERROR 0x0100u
#define COQUIC_HTTP3_ERROR_GENERAL_PROTOCOL_ERROR 0x0101u
#define COQUIC_HTTP3_ERROR_INTERNAL_ERROR 0x0102u
#define COQUIC_HTTP3_ERROR_STREAM_CREATION_ERROR 0x0103u
#define COQUIC_HTTP3_ERROR_CLOSED_CRITICAL_STREAM 0x0104u
#define COQUIC_HTTP3_ERROR_FRAME_UNEXPECTED 0x0105u
#define COQUIC_HTTP3_ERROR_FRAME_ERROR 0x0106u
#define COQUIC_HTTP3_ERROR_EXCESSIVE_LOAD 0x0107u
#define COQUIC_HTTP3_ERROR_ID_ERROR 0x0108u
#define COQUIC_HTTP3_ERROR_SETTINGS_ERROR 0x0109u
#define COQUIC_HTTP3_ERROR_MISSING_SETTINGS 0x010au
#define COQUIC_HTTP3_ERROR_REQUEST_REJECTED 0x010bu
#define COQUIC_HTTP3_ERROR_REQUEST_CANCELLED 0x010cu
#define COQUIC_HTTP3_ERROR_REQUEST_INCOMPLETE 0x010du
#define COQUIC_HTTP3_ERROR_MESSAGE_ERROR 0x010eu
#define COQUIC_HTTP3_ERROR_VERSION_FALLBACK 0x0110u
#define COQUIC_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED 0x0200u
#define COQUIC_HTTP3_ERROR_QPACK_ENCODER_STREAM_ERROR 0x0201u
#define COQUIC_HTTP3_ERROR_QPACK_DECODER_STREAM_ERROR 0x0202u

typedef struct coquic_http3_optional_u64 {
    uint8_t has_value;
    uint64_t value;
} coquic_http3_optional_u64_t;

typedef struct coquic_http3_settings {
    size_t size;
    uint64_t qpack_max_table_capacity;
    uint64_t qpack_blocked_streams;
    coquic_http3_optional_u64_t max_field_section_size;
} coquic_http3_settings_t;

typedef struct coquic_http3_client_config {
    size_t size;
    coquic_http3_settings_t local_settings;
} coquic_http3_client_config_t;

typedef struct coquic_http3_server_config {
    size_t size;
    coquic_http3_settings_t local_settings;
} coquic_http3_server_config_t;

typedef struct coquic_http3_field {
    const char *name;
    size_t name_length;
    const char *value;
    size_t value_length;
} coquic_http3_field_t;

typedef struct coquic_http3_field_view {
    coquic_bytes_view_t name;
    coquic_bytes_view_t value;
} coquic_http3_field_view_t;

typedef struct coquic_http3_request_head {
    size_t size;
    const char *method;
    size_t method_length;
    const char *scheme;
    size_t scheme_length;
    const char *authority;
    size_t authority_length;
    const char *path;
    size_t path_length;
    coquic_http3_optional_u64_t content_length;
    const coquic_http3_field_t *headers;
    size_t headers_count;
} coquic_http3_request_head_t;

typedef struct coquic_http3_response_head {
    size_t size;
    uint16_t status;
    coquic_http3_optional_u64_t content_length;
    const coquic_http3_field_t *headers;
    size_t headers_count;
} coquic_http3_response_head_t;

typedef struct coquic_http3_request {
    size_t size;
    coquic_http3_request_head_t head;
    coquic_bytes_t body;
    const coquic_http3_field_t *trailers;
    size_t trailers_count;
} coquic_http3_request_t;

typedef struct coquic_http3_request_head_view {
    coquic_bytes_view_t method;
    coquic_bytes_view_t scheme;
    coquic_bytes_view_t authority;
    coquic_bytes_view_t path;
    coquic_http3_optional_u64_t content_length;
    const coquic_http3_field_view_t *headers;
    size_t headers_count;
} coquic_http3_request_head_view_t;

typedef struct coquic_http3_response_head_view {
    uint16_t status;
    coquic_http3_optional_u64_t content_length;
    const coquic_http3_field_view_t *headers;
    size_t headers_count;
} coquic_http3_response_head_view_t;

typedef struct coquic_http3_request_view {
    coquic_http3_request_head_view_t head;
    coquic_bytes_view_t body;
    const coquic_http3_field_view_t *trailers;
    size_t trailers_count;
} coquic_http3_request_view_t;

typedef struct coquic_http3_response_view {
    const coquic_http3_response_head_view_t *interim_heads;
    size_t interim_head_count;
    coquic_http3_response_head_view_t head;
    coquic_bytes_view_t body;
    const coquic_http3_field_view_t *trailers;
    size_t trailers_count;
} coquic_http3_response_view_t;

typedef struct coquic_http3_client_response_event {
    coquic_stream_id_t stream_id;
    coquic_http3_request_view_t request;
    coquic_http3_response_view_t response;
} coquic_http3_client_response_event_t;

typedef struct coquic_http3_client_request_error_event {
    coquic_stream_id_t stream_id;
    coquic_http3_request_view_t request;
    uint64_t application_error_code;
} coquic_http3_client_request_error_event_t;

typedef struct coquic_http3_server_request_cancelled_event {
    coquic_stream_id_t stream_id;
    uint8_t has_head;
    coquic_http3_request_head_view_t head;
    coquic_bytes_view_t body;
    const coquic_http3_field_view_t *trailers;
    size_t trailers_count;
    uint64_t application_error_code;
} coquic_http3_server_request_cancelled_event_t;

typedef struct coquic_http3_error {
    coquic_http3_error_code_t code;
    coquic_optional_stream_id_t stream_id;
    char *detail_buffer;
    size_t detail_buffer_capacity;
    size_t detail_length;
    uint8_t detail_truncated;
} coquic_http3_error_t;

COQUIC_FFI_API void coquic_http3_settings_init(coquic_http3_settings_t *settings);
COQUIC_FFI_API void coquic_http3_client_config_init(coquic_http3_client_config_t *config);
COQUIC_FFI_API void coquic_http3_server_config_init(coquic_http3_server_config_t *config);
COQUIC_FFI_API void coquic_http3_client_endpoint_config_init(coquic_endpoint_config_t *config);
COQUIC_FFI_API void coquic_http3_server_endpoint_config_init(coquic_endpoint_config_t *config);

COQUIC_FFI_API coquic_status_t coquic_http3_client_create(
    const coquic_http3_client_config_t *config, coquic_http3_client_t **out_client);
COQUIC_FFI_API void coquic_http3_client_destroy(coquic_http3_client_t *client);
COQUIC_FFI_API coquic_status_t coquic_http3_client_submit_request(
    coquic_http3_client_t *client, const coquic_http3_request_t *request,
    coquic_stream_id_t *out_stream_id, coquic_http3_error_t *out_error);
COQUIC_FFI_API coquic_status_t
coquic_http3_client_on_quic_result(coquic_http3_client_t *client, const coquic_result_t *result,
                                   coquic_time_us_t now, coquic_http3_client_update_t **out_update);
COQUIC_FFI_API coquic_status_t coquic_http3_client_poll(coquic_http3_client_t *client,
                                                        coquic_time_us_t now,
                                                        coquic_http3_client_update_t **out_update);
COQUIC_FFI_API uint8_t coquic_http3_client_has_failed(const coquic_http3_client_t *client);

COQUIC_FFI_API void coquic_http3_client_update_destroy(coquic_http3_client_update_t *update);
COQUIC_FFI_API size_t
coquic_http3_client_update_connection_input_count(const coquic_http3_client_update_t *update);
COQUIC_FFI_API coquic_status_t coquic_http3_client_update_connection_input_at(
    const coquic_http3_client_update_t *update, size_t index, coquic_connection_input_t *out_input);
COQUIC_FFI_API size_t
coquic_http3_client_update_response_count(const coquic_http3_client_update_t *update);
COQUIC_FFI_API coquic_status_t
coquic_http3_client_update_response_at(const coquic_http3_client_update_t *update, size_t index,
                                       coquic_http3_client_response_event_t *out_event);
COQUIC_FFI_API size_t
coquic_http3_client_update_request_error_count(const coquic_http3_client_update_t *update);
COQUIC_FFI_API coquic_status_t coquic_http3_client_update_request_error_at(
    const coquic_http3_client_update_t *update, size_t index,
    coquic_http3_client_request_error_event_t *out_event);
COQUIC_FFI_API uint8_t
coquic_http3_client_update_has_pending_work(const coquic_http3_client_update_t *update);
COQUIC_FFI_API uint8_t
coquic_http3_client_update_terminal_failure(const coquic_http3_client_update_t *update);
COQUIC_FFI_API uint8_t
coquic_http3_client_update_handled_local_error(const coquic_http3_client_update_t *update);

COQUIC_FFI_API coquic_status_t coquic_http3_server_create(
    const coquic_http3_server_config_t *config, coquic_http3_server_t **out_server);
COQUIC_FFI_API void coquic_http3_server_destroy(coquic_http3_server_t *server);
COQUIC_FFI_API coquic_status_t
coquic_http3_server_on_quic_result(coquic_http3_server_t *server, const coquic_result_t *result,
                                   coquic_time_us_t now, coquic_http3_server_update_t **out_update);
COQUIC_FFI_API coquic_status_t coquic_http3_server_poll(coquic_http3_server_t *server,
                                                        coquic_time_us_t now,
                                                        coquic_http3_server_update_t **out_update);
COQUIC_FFI_API uint8_t coquic_http3_server_has_failed(const coquic_http3_server_t *server);

COQUIC_FFI_API void coquic_http3_server_update_destroy(coquic_http3_server_update_t *update);
COQUIC_FFI_API size_t
coquic_http3_server_update_connection_input_count(const coquic_http3_server_update_t *update);
COQUIC_FFI_API coquic_status_t coquic_http3_server_update_connection_input_at(
    const coquic_http3_server_update_t *update, size_t index, coquic_connection_input_t *out_input);
COQUIC_FFI_API size_t
coquic_http3_server_update_request_cancelled_count(const coquic_http3_server_update_t *update);
COQUIC_FFI_API coquic_status_t coquic_http3_server_update_request_cancelled_at(
    const coquic_http3_server_update_t *update, size_t index,
    coquic_http3_server_request_cancelled_event_t *out_event);
COQUIC_FFI_API uint8_t
coquic_http3_server_update_has_pending_work(const coquic_http3_server_update_t *update);
COQUIC_FFI_API uint8_t
coquic_http3_server_update_terminal_failure(const coquic_http3_server_update_t *update);
COQUIC_FFI_API uint8_t
coquic_http3_server_update_handled_local_error(const coquic_http3_server_update_t *update);

COQUIC_FFI_API coquic_status_t coquic_http3_request_view_header_at(
    const coquic_http3_request_view_t *request, size_t index, coquic_http3_field_view_t *out_field);
COQUIC_FFI_API coquic_status_t coquic_http3_request_view_trailer_at(
    const coquic_http3_request_view_t *request, size_t index, coquic_http3_field_view_t *out_field);
COQUIC_FFI_API coquic_status_t
coquic_http3_request_head_view_header_at(const coquic_http3_request_head_view_t *head, size_t index,
                                         coquic_http3_field_view_t *out_field);
COQUIC_FFI_API coquic_status_t coquic_http3_response_view_interim_head_at(
    const coquic_http3_response_view_t *response, size_t index,
    coquic_http3_response_head_view_t *out_head);
COQUIC_FFI_API coquic_status_t
coquic_http3_response_view_header_at(const coquic_http3_response_view_t *response, size_t index,
                                     coquic_http3_field_view_t *out_field);
COQUIC_FFI_API coquic_status_t
coquic_http3_response_view_trailer_at(const coquic_http3_response_view_t *response, size_t index,
                                      coquic_http3_field_view_t *out_field);
COQUIC_FFI_API coquic_status_t
coquic_http3_response_head_view_header_at(const coquic_http3_response_head_view_t *head,
                                          size_t index, coquic_http3_field_view_t *out_field);
COQUIC_FFI_API coquic_status_t coquic_http3_server_request_cancelled_view_trailer_at(
    const coquic_http3_server_request_cancelled_event_t *event, size_t index,
    coquic_http3_field_view_t *out_field);

#ifdef __cplusplus
}
#endif
