# C FFI Reference

`core.h` and `http3.h` File Reference

```c
#include <coquic/ffi/core.h>
#include <coquic/ffi/http3.h>
```

This page documents the public C functions exported by the CoQUIC C FFI. The
headers remain the exact signature source.

## Detailed Description

The C FFI is a sans-I/O ABI for native bindings. It does not own sockets,
timers, address routing, files, or threads. Endpoint and connection calls
consume caller-provided inputs and return `coquic_result_t` objects containing
effects.

The API has three layers:

- Core endpoint and connection functions, matching the low-level C++ Core API.
- QUIC facade functions, which reuse the same handles and results but expose
  transport-oriented helper names.
- HTTP/3 functions, which maintain per-connection HTTP/3 state and emit QUIC
  connection inputs.

## Function Documentation

### coquic_ffi_abi_version()

```c
uint32_t coquic_ffi_abi_version(void);
```

Return the runtime C FFI ABI version.

Parameters:

- None.

Returns:

- The ABI version compiled into the loaded library.

Notes:

- Compare with `COQUIC_FFI_ABI_VERSION` before using a dynamically loaded
  library.

### coquic_transport_config_init()

```c
void coquic_transport_config_init(coquic_transport_config_t *config);
```

Initialize transport configuration defaults.

Parameters:

- `config`: output transport config. May be `NULL`.

Returns:

- Nothing.

Notes:

- `NULL` is a no-op.
- The initialized values mirror CoQUIC's C++ transport defaults.

### coquic_endpoint_config_init()

```c
void coquic_endpoint_config_init(coquic_endpoint_config_t *config);
```

Initialize endpoint configuration defaults.

Parameters:

- `config`: output endpoint config. May be `NULL`.

Returns:

- Nothing.

Notes:

- Sets `config->size` to `sizeof(coquic_endpoint_config_t)`.
- Also initializes the embedded `coquic_transport_config_t`.
- `NULL` is a no-op.

### coquic_client_connection_config_init()

```c
void coquic_client_connection_config_init(coquic_client_connection_config_t *config);
```

Initialize client connection configuration defaults.

Parameters:

- `config`: output client connection config. May be `NULL`.

Returns:

- Nothing.

Notes:

- Sets `config->size` to `sizeof(coquic_client_connection_config_t)`.
- Callers normally override connection IDs, versions, server name, resumption
  state, and 0-RTT config after initialization.

### coquic_endpoint_create()

```c
coquic_status_t coquic_endpoint_create(
    const coquic_endpoint_config_t *config,
    coquic_endpoint_t **out_endpoint);
```

Create a QUIC endpoint.

Parameters:

- `config`: initialized endpoint config.
- `out_endpoint`: receives the allocated endpoint handle.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` if `config`, `out_endpoint`, or
  `config->size` is invalid.
- `COQUIC_STATUS_OUT_OF_MEMORY` or `COQUIC_STATUS_INTERNAL_ERROR` on failure.

Notes:

- On failure, `*out_endpoint` is set to `NULL` when possible.
- Destroy successful outputs with `coquic_endpoint_destroy()`.

### coquic_endpoint_destroy()

```c
void coquic_endpoint_destroy(coquic_endpoint_t *endpoint);
```

Destroy a QUIC endpoint.

Parameters:

- `endpoint`: endpoint handle to release. May be `NULL`.

Returns:

- Nothing.

Notes:

- Invalidates all connection handles owned by the endpoint.
- `NULL` is allowed.

### coquic_endpoint_open_connection()

```c
coquic_status_t coquic_endpoint_open_connection(
    coquic_endpoint_t *endpoint,
    const coquic_open_connection_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Open a client connection through the Core endpoint API.

Parameters:

- `endpoint`: endpoint handle.
- `input`: initialized open-connection input.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` if required pointers or size fields are
  invalid.

Notes:

- `input->size` and `input->connection.size` must cover v1 fields.
- Process returned effects and destroy `*out_result` with
  `coquic_result_destroy()`.

### coquic_endpoint_input_datagram()

```c
coquic_status_t coquic_endpoint_input_datagram(
    coquic_endpoint_t *endpoint,
    const coquic_inbound_datagram_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Feed one received UDP datagram into the endpoint.

Parameters:

- `endpoint`: endpoint handle.
- `input`: datagram bytes, optional route handle, address-validation identity,
  and ECN codepoint.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers or `input->size`.

Notes:

- Input bytes are copied during the call.
- Preserve route-handle identity so send effects can be routed to the same path.

### coquic_endpoint_update_path_mtu()

```c
coquic_status_t coquic_endpoint_update_path_mtu(
    coquic_endpoint_t *endpoint,
    const coquic_path_mtu_update_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Notify the endpoint about a path MTU update.

Parameters:

- `endpoint`: endpoint handle.
- `input`: optional route handle and maximum UDP payload size.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers or `input->size`.

Notes:

- Use the same route-handle namespace used for datagram input and output.

### coquic_endpoint_timer_expired()

```c
coquic_status_t coquic_endpoint_timer_expired(
    coquic_endpoint_t *endpoint,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Advance endpoint timers.

Parameters:

- `endpoint`: endpoint handle.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers.

Notes:

- Call when the deadline returned by `coquic_result_next_wakeup()` or
  `coquic_endpoint_next_wakeup()` fires.

### coquic_connection_send_stream()

```c
coquic_status_t coquic_connection_send_stream(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_send_stream_data_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Send stream data on a connection.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `input`: stream ID, bytes, and FIN flag.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers or `input->size`.

Notes:

- Invalid connection or stream state is reported as a local error in the result.
- Input bytes are copied during the call.

### coquic_connection_send_datagram()

```c
coquic_status_t coquic_connection_send_datagram(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_send_datagram_data_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Send a QUIC DATAGRAM on a connection.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `input`: datagram payload.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers or `input->size`.

Notes:

- DATAGRAM support and size failures are reported as local errors in the
  result.

### coquic_connection_reset_stream()

```c
coquic_status_t coquic_connection_reset_stream(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_reset_stream_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Request RESET_STREAM.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `input`: stream ID and application error code.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers or `input->size`.

Notes:

- Stream-state failures are reported as local errors in the result.

### coquic_connection_stop_sending()

```c
coquic_status_t coquic_connection_stop_sending(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_stop_sending_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Request STOP_SENDING.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `input`: stream ID and application error code.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers or `input->size`.

Notes:

- Stream-state failures are reported as local errors in the result.

### coquic_connection_close()

```c
coquic_status_t coquic_connection_close(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_close_connection_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Request application close.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `input`: application error code and reason phrase.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers or `input->size`.

Notes:

- The reason phrase is copied during the call.

### coquic_connection_request_key_update()

```c
coquic_status_t coquic_connection_request_key_update(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Request a QUIC key update.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers.

Notes:

- Unsupported connection state is reported as a local error in the result.

### coquic_connection_request_migration()

```c
coquic_status_t coquic_connection_request_migration(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_request_connection_migration_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Request active connection migration.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `input`: route handle, migration reason, and address-validation identity.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers or `input->size`.

Notes:

- Address-validation identity bytes are copied during the call.

### coquic_connection_advance()

```c
coquic_status_t coquic_connection_advance(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_connection_input_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Dispatch a tagged connection input.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `input`: tagged `coquic_connection_input_t`.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers or unsupported tags.

Notes:

- This is the preferred entry point for commands emitted by HTTP/3 updates.

### coquic_quic_connect()

```c
coquic_status_t coquic_quic_connect(
    coquic_endpoint_t *endpoint,
    const coquic_open_connection_t *input,
    coquic_time_us_t now,
    coquic_connection_handle_t *out_connection,
    coquic_result_t **out_result);
```

Open a client connection through the QUIC facade.

Parameters:

- `endpoint`: endpoint handle.
- `input`: initialized open-connection input.
- `now`: monotonic timestamp in microseconds.
- `out_connection`: receives the created connection handle when present.
- `out_result`: receives the result object.

Returns:

- `COQUIC_STATUS_OK` on ABI-level success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid required pointers or size
  fields.

Notes:

- `out_connection` is set to `0` before validation.
- Effects still must be processed from `out_result`.

### coquic_quic_receive_datagram()

```c
coquic_status_t coquic_quic_receive_datagram(
    coquic_endpoint_t *endpoint,
    const coquic_inbound_datagram_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Facade alias for receiving a datagram.

Parameters:

- Same as `coquic_endpoint_input_datagram()`.

Returns:

- Same as `coquic_endpoint_input_datagram()`.

Notes:

- This function shares semantics with the Core endpoint datagram API.

### coquic_quic_update_path_mtu()

```c
coquic_status_t coquic_quic_update_path_mtu(
    coquic_endpoint_t *endpoint,
    const coquic_path_mtu_update_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Facade alias for path MTU updates.

Parameters:

- Same as `coquic_endpoint_update_path_mtu()`.

Returns:

- Same as `coquic_endpoint_update_path_mtu()`.

Notes:

- This function exists for facade naming consistency.

### coquic_quic_timer_expired()

```c
coquic_status_t coquic_quic_timer_expired(
    coquic_endpoint_t *endpoint,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Facade alias for timer expiry.

Parameters:

- Same as `coquic_endpoint_timer_expired()`.

Returns:

- Same as `coquic_endpoint_timer_expired()`.

Notes:

- This function exists for facade naming consistency.

### coquic_quic_connection_send_stream()

```c
coquic_status_t coquic_quic_connection_send_stream(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_send_stream_data_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Facade alias for stream send.

Parameters:

- Same as `coquic_connection_send_stream()`.

Returns:

- Same as `coquic_connection_send_stream()`.

Notes:

- Uses the same result and local-error behavior as the Core function.

### coquic_quic_connection_send_datagram()

```c
coquic_status_t coquic_quic_connection_send_datagram(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_send_datagram_data_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Facade alias for DATAGRAM send.

Parameters:

- Same as `coquic_connection_send_datagram()`.

Returns:

- Same as `coquic_connection_send_datagram()`.

Notes:

- Uses the same result and local-error behavior as the Core function.

### coquic_quic_connection_reset_stream()

```c
coquic_status_t coquic_quic_connection_reset_stream(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_reset_stream_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Facade alias for RESET_STREAM.

Parameters:

- Same as `coquic_connection_reset_stream()`.

Returns:

- Same as `coquic_connection_reset_stream()`.

Notes:

- Uses the same result and local-error behavior as the Core function.

### coquic_quic_connection_stop_sending()

```c
coquic_status_t coquic_quic_connection_stop_sending(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_stop_sending_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Facade alias for STOP_SENDING.

Parameters:

- Same as `coquic_connection_stop_sending()`.

Returns:

- Same as `coquic_connection_stop_sending()`.

Notes:

- Uses the same result and local-error behavior as the Core function.

### coquic_quic_connection_close()

```c
coquic_status_t coquic_quic_connection_close(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_close_connection_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Facade alias for application close.

Parameters:

- Same as `coquic_connection_close()`.

Returns:

- Same as `coquic_connection_close()`.

Notes:

- Uses the same result and local-error behavior as the Core function.

### coquic_quic_connection_request_key_update()

```c
coquic_status_t coquic_quic_connection_request_key_update(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Facade alias for key update.

Parameters:

- Same as `coquic_connection_request_key_update()`.

Returns:

- Same as `coquic_connection_request_key_update()`.

Notes:

- Uses the same result and local-error behavior as the Core function.

### coquic_quic_connection_advance()

```c
coquic_status_t coquic_quic_connection_advance(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    const coquic_connection_input_t *input,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Facade alias for tagged connection input.

Parameters:

- Same as `coquic_connection_advance()`.

Returns:

- Same as `coquic_connection_advance()`.

Notes:

- Uses the same invalid-tag validation as the Core function.

### coquic_quic_stream_send()

```c
coquic_status_t coquic_quic_stream_send(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    coquic_stream_id_t stream_id,
    coquic_bytes_t bytes,
    uint8_t fin,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Send stream data with facade-style parameters.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `stream_id`: target stream ID.
- `bytes`: stream payload.
- `fin`: non-zero to mark FIN.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- Same status behavior as `coquic_connection_send_stream()`.

Notes:

- Internally builds `coquic_send_stream_data_t`.

### coquic_quic_stream_finish()

```c
coquic_status_t coquic_quic_stream_finish(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    coquic_stream_id_t stream_id,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Send an empty FIN on a stream.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `stream_id`: target stream ID.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- Same status behavior as `coquic_quic_stream_send()`.

Notes:

- Equivalent to stream send with empty bytes and `fin = 1`.

### coquic_quic_stream_reset()

```c
coquic_status_t coquic_quic_stream_reset(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    coquic_stream_id_t stream_id,
    uint64_t application_error_code,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Reset a stream with facade-style parameters.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `stream_id`: target stream ID.
- `application_error_code`: application error code.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- Same status behavior as `coquic_connection_reset_stream()`.

Notes:

- Internally builds `coquic_reset_stream_t`.

### coquic_quic_stream_stop_sending()

```c
coquic_status_t coquic_quic_stream_stop_sending(
    coquic_endpoint_t *endpoint,
    coquic_connection_handle_t connection,
    coquic_stream_id_t stream_id,
    uint64_t application_error_code,
    coquic_time_us_t now,
    coquic_result_t **out_result);
```

Request STOP_SENDING with facade-style parameters.

Parameters:

- `endpoint`: endpoint handle.
- `connection`: target connection handle.
- `stream_id`: target stream ID.
- `application_error_code`: application error code.
- `now`: monotonic timestamp in microseconds.
- `out_result`: receives the result object.

Returns:

- Same status behavior as `coquic_connection_stop_sending()`.

Notes:

- Internally builds `coquic_stop_sending_t`.

### coquic_endpoint_connection_count()

```c
size_t coquic_endpoint_connection_count(const coquic_endpoint_t *endpoint);
```

Return the number of endpoint-owned connections.

Parameters:

- `endpoint`: endpoint handle or `NULL`.

Returns:

- The connection count, or `0` for `NULL`.

Notes:

- This is a query only; it does not advance protocol state.

### coquic_endpoint_has_send_continuation_pending()

```c
uint8_t coquic_endpoint_has_send_continuation_pending(
    const coquic_endpoint_t *endpoint);
```

Report whether endpoint send continuation work is pending.

Parameters:

- `endpoint`: endpoint handle or `NULL`.

Returns:

- Non-zero when send continuation work should continue.
- `0` for `NULL`.

Notes:

- If non-zero, call back into the endpoint without blocking.

### coquic_endpoint_next_wakeup()

```c
coquic_optional_time_us_t coquic_endpoint_next_wakeup(
    const coquic_endpoint_t *endpoint);
```

Return the endpoint's current timer deadline.

Parameters:

- `endpoint`: endpoint handle or `NULL`.

Returns:

- Optional wakeup timestamp in microseconds.

Notes:

- Returns no value for `NULL`.

### coquic_result_destroy()

```c
void coquic_result_destroy(coquic_result_t *result);
```

Destroy a result object.

Parameters:

- `result`: result handle or `NULL`.

Returns:

- Nothing.

Notes:

- Invalidates all borrowed byte views read from result effects.

### coquic_result_effect_count()

```c
size_t coquic_result_effect_count(const coquic_result_t *result);
```

Return the number of effects in a result.

Parameters:

- `result`: result handle or `NULL`.

Returns:

- Effect count, or `0` for `NULL`.

Notes:

- Use `coquic_result_effect_at()` for indices `[0, count)`.

### coquic_result_effect_at()

```c
coquic_status_t coquic_result_effect_at(
    const coquic_result_t *result,
    size_t index,
    coquic_effect_t *out_effect);
```

Read one effect from a result.

Parameters:

- `result`: result handle.
- `index`: effect index.
- `out_effect`: output effect pointer.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` if the result, output pointer, or index is
  invalid.

Notes:

- Byte views inside `out_effect` are borrowed from `result`.

### coquic_result_next_wakeup()

```c
coquic_optional_time_us_t coquic_result_next_wakeup(
    const coquic_result_t *result);
```

Return the timer deadline from a result.

Parameters:

- `result`: result handle or `NULL`.

Returns:

- Optional wakeup timestamp in microseconds.

Notes:

- Prefer this immediately after processing a result.

### coquic_result_has_local_error()

```c
uint8_t coquic_result_has_local_error(const coquic_result_t *result);
```

Report whether a result carries a local transport error.

Parameters:

- `result`: result handle or `NULL`.

Returns:

- Non-zero when a local error is present.
- `0` for `NULL`.

Notes:

- Read the error with `coquic_result_local_error()`.

### coquic_result_local_error()

```c
coquic_status_t coquic_result_local_error(
    const coquic_result_t *result,
    coquic_local_error_t *out_error);
```

Read a local transport error.

Parameters:

- `result`: result handle.
- `out_error`: output local error pointer.

Returns:

- `COQUIC_STATUS_OK` when an error was copied.
- `COQUIC_STATUS_INVALID_ARGUMENT` if no error is present or arguments are
  invalid.

Notes:

- Local errors are application signals; process any valid effects in the same
  result as usual.

### coquic_result_send_continuation_pending()

```c
uint8_t coquic_result_send_continuation_pending(
    const coquic_result_t *result);
```

Report send continuation state from a result.

Parameters:

- `result`: result handle or `NULL`.

Returns:

- Non-zero when send continuation work remains.
- `0` for `NULL`.

Notes:

- If non-zero, call back into the endpoint without blocking.

### coquic_http3_settings_init()

```c
void coquic_http3_settings_init(coquic_http3_settings_t *settings);
```

Initialize HTTP/3 settings.

Parameters:

- `settings`: output settings pointer or `NULL`.

Returns:

- Nothing.

Notes:

- Sets `settings->size` to `sizeof(coquic_http3_settings_t)`.
- `NULL` is a no-op.

### coquic_http3_client_config_init()

```c
void coquic_http3_client_config_init(coquic_http3_client_config_t *config);
```

Initialize HTTP/3 client config.

Parameters:

- `config`: output client config pointer or `NULL`.

Returns:

- Nothing.

Notes:

- Initializes embedded local HTTP/3 settings.

### coquic_http3_server_config_init()

```c
void coquic_http3_server_config_init(coquic_http3_server_config_t *config);
```

Initialize HTTP/3 server config.

Parameters:

- `config`: output server config pointer or `NULL`.

Returns:

- Nothing.

Notes:

- Initializes embedded local HTTP/3 settings.

### coquic_http3_client_endpoint_config_init()

```c
void coquic_http3_client_endpoint_config_init(coquic_endpoint_config_t *config);
```

Initialize a QUIC endpoint config for HTTP/3 client use.

Parameters:

- `config`: output endpoint config pointer or `NULL`.

Returns:

- Nothing.

Notes:

- Sets role to `COQUIC_ROLE_CLIENT` and ALPN to `h3`.
- Calls `coquic_endpoint_config_init()` first.

### coquic_http3_server_endpoint_config_init()

```c
void coquic_http3_server_endpoint_config_init(coquic_endpoint_config_t *config);
```

Initialize a QUIC endpoint config for HTTP/3 server use.

Parameters:

- `config`: output endpoint config pointer or `NULL`.

Returns:

- Nothing.

Notes:

- Sets role to `COQUIC_ROLE_SERVER` and ALPN to `h3`.
- Server TLS identity remains caller-configured.

### coquic_http3_client_create()

```c
coquic_status_t coquic_http3_client_create(
    const coquic_http3_client_config_t *config,
    coquic_http3_client_t **out_client);
```

Create HTTP/3 client state.

Parameters:

- `config`: initialized client config.
- `out_client`: receives the client handle.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers or size fields.

Notes:

- The client object is per QUIC connection.
- Destroy with `coquic_http3_client_destroy()`.

### coquic_http3_client_destroy()

```c
void coquic_http3_client_destroy(coquic_http3_client_t *client);
```

Destroy HTTP/3 client state.

Parameters:

- `client`: client handle or `NULL`.

Returns:

- Nothing.

Notes:

- Does not destroy the QUIC endpoint.

### coquic_http3_client_submit_request()

```c
coquic_status_t coquic_http3_client_submit_request(
    coquic_http3_client_t *client,
    const coquic_http3_request_t *request,
    coquic_stream_id_t *out_stream_id,
    coquic_http3_error_t *out_error);
```

Queue an HTTP/3 request.

Parameters:

- `client`: client handle.
- `request`: initialized request object.
- `out_stream_id`: receives the request stream ID.
- `out_error`: optional protocol error output.

Returns:

- `COQUIC_STATUS_OK` when the C call completed.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid required pointers or size
  fields.

Notes:

- An HTTP/3 rejection can be reported through `out_error` while returning
  `COQUIC_STATUS_OK`.
- `out_error->detail_buffer` is caller-owned and preserved across the call.

### coquic_http3_client_on_quic_result()

```c
coquic_status_t coquic_http3_client_on_quic_result(
    coquic_http3_client_t *client,
    const coquic_result_t *result,
    coquic_time_us_t now,
    coquic_http3_client_update_t **out_update);
```

Feed a QUIC result into HTTP/3 client state.

Parameters:

- `client`: client handle.
- `result`: borrowed QUIC result.
- `now`: monotonic timestamp in microseconds.
- `out_update`: receives the client update.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid required pointers.

Notes:

- The caller still owns `result`.
- Destroy the update with `coquic_http3_client_update_destroy()`.

### coquic_http3_client_poll()

```c
coquic_status_t coquic_http3_client_poll(
    coquic_http3_client_t *client,
    coquic_time_us_t now,
    coquic_http3_client_update_t **out_update);
```

Poll pending HTTP/3 client work.

Parameters:

- `client`: client handle.
- `now`: monotonic timestamp in microseconds.
- `out_update`: receives the client update.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid required pointers.

Notes:

- Poll again while `coquic_http3_client_update_has_pending_work()` is non-zero.

### coquic_http3_client_has_failed()

```c
uint8_t coquic_http3_client_has_failed(const coquic_http3_client_t *client);
```

Report terminal client failure.

Parameters:

- `client`: client handle or `NULL`.

Returns:

- Non-zero after terminal HTTP/3 client failure.
- `0` for `NULL`.

Notes:

- Terminal failure is HTTP/3-layer state, not endpoint ownership state.

### coquic_http3_client_update_destroy()

```c
void coquic_http3_client_update_destroy(
    coquic_http3_client_update_t *update);
```

Destroy a client update.

Parameters:

- `update`: update handle or `NULL`.

Returns:

- Nothing.

Notes:

- Invalidates all response views and emitted connection-input byte pointers
  borrowed from the update.

### coquic_http3_client_update_connection_input_count()

```c
size_t coquic_http3_client_update_connection_input_count(
    const coquic_http3_client_update_t *update);
```

Return the number of emitted QUIC connection inputs.

Parameters:

- `update`: client update or `NULL`.

Returns:

- Input count, or `0` for `NULL`.

Notes:

- Feed each input to the matching QUIC connection.

### coquic_http3_client_update_connection_input_at()

```c
coquic_status_t coquic_http3_client_update_connection_input_at(
    const coquic_http3_client_update_t *update,
    size_t index,
    coquic_connection_input_t *out_input);
```

Read one emitted QUIC connection input.

Parameters:

- `update`: client update.
- `index`: input index.
- `out_input`: output connection input.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Byte pointers inside `out_input` are borrowed from `update`.

### coquic_http3_client_update_response_count()

```c
size_t coquic_http3_client_update_response_count(
    const coquic_http3_client_update_t *update);
```

Return the number of completed response events.

Parameters:

- `update`: client update or `NULL`.

Returns:

- Response event count, or `0` for `NULL`.

Notes:

- Read events with `coquic_http3_client_update_response_at()`.

### coquic_http3_client_update_response_at()

```c
coquic_status_t coquic_http3_client_update_response_at(
    const coquic_http3_client_update_t *update,
    size_t index,
    coquic_http3_client_response_event_t *out_event);
```

Read one completed response event.

Parameters:

- `update`: client update.
- `index`: response event index.
- `out_event`: output event pointer.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Request and response views inside `out_event` are borrowed from `update`.

### coquic_http3_client_update_request_error_count()

```c
size_t coquic_http3_client_update_request_error_count(
    const coquic_http3_client_update_t *update);
```

Return the number of request error events.

Parameters:

- `update`: client update or `NULL`.

Returns:

- Request error count, or `0` for `NULL`.

Notes:

- Read events with `coquic_http3_client_update_request_error_at()`.

### coquic_http3_client_update_request_error_at()

```c
coquic_status_t coquic_http3_client_update_request_error_at(
    const coquic_http3_client_update_t *update,
    size_t index,
    coquic_http3_client_request_error_event_t *out_event);
```

Read one request error event.

Parameters:

- `update`: client update.
- `index`: request error event index.
- `out_event`: output event pointer.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Request views inside `out_event` are borrowed from `update`.

### coquic_http3_client_update_has_pending_work()

```c
uint8_t coquic_http3_client_update_has_pending_work(
    const coquic_http3_client_update_t *update);
```

Report whether the client has immediate pending work.

Parameters:

- `update`: client update or `NULL`.

Returns:

- Non-zero when the caller should poll again immediately.
- `0` for `NULL`.

Notes:

- Do not wait for network input before polling again when this is non-zero.

### coquic_http3_client_update_terminal_failure()

```c
uint8_t coquic_http3_client_update_terminal_failure(
    const coquic_http3_client_update_t *update);
```

Report terminal client failure in an update.

Parameters:

- `update`: client update or `NULL`.

Returns:

- Non-zero when this update reports terminal HTTP/3 client failure.
- `0` for `NULL`.

Notes:

- This mirrors update state; `coquic_http3_client_has_failed()` queries the
  client object.

### coquic_http3_client_update_handled_local_error()

```c
uint8_t coquic_http3_client_update_handled_local_error(
    const coquic_http3_client_update_t *update);
```

Report whether a QUIC local error was consumed by HTTP/3 client state.

Parameters:

- `update`: client update or `NULL`.

Returns:

- Non-zero when a QUIC local error was handled.
- `0` for `NULL`.

Notes:

- This is useful for bindings that separately log QUIC local errors.

### coquic_http3_server_create()

```c
coquic_status_t coquic_http3_server_create(
    const coquic_http3_server_config_t *config,
    coquic_http3_server_t **out_server);
```

Create HTTP/3 server state.

Parameters:

- `config`: initialized server config.
- `out_server`: receives the server handle.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid pointers or size fields.

Notes:

- The server object is per QUIC connection.
- Destroy with `coquic_http3_server_destroy()`.

### coquic_http3_server_destroy()

```c
void coquic_http3_server_destroy(coquic_http3_server_t *server);
```

Destroy HTTP/3 server state.

Parameters:

- `server`: server handle or `NULL`.

Returns:

- Nothing.

Notes:

- Does not destroy the QUIC endpoint.

### coquic_http3_server_on_quic_result()

```c
coquic_status_t coquic_http3_server_on_quic_result(
    coquic_http3_server_t *server,
    const coquic_result_t *result,
    coquic_time_us_t now,
    coquic_http3_server_update_t **out_update);
```

Feed a QUIC result into HTTP/3 server state.

Parameters:

- `server`: server handle.
- `result`: borrowed QUIC result.
- `now`: monotonic timestamp in microseconds.
- `out_update`: receives the server update.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid required pointers.

Notes:

- The caller still owns `result`.
- Destroy the update with `coquic_http3_server_update_destroy()`.

### coquic_http3_server_poll()

```c
coquic_status_t coquic_http3_server_poll(
    coquic_http3_server_t *server,
    coquic_time_us_t now,
    coquic_http3_server_update_t **out_update);
```

Poll pending HTTP/3 server work.

Parameters:

- `server`: server handle.
- `now`: monotonic timestamp in microseconds.
- `out_update`: receives the server update.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid required pointers.

Notes:

- Poll again while `coquic_http3_server_update_has_pending_work()` is non-zero.

### coquic_http3_server_has_failed()

```c
uint8_t coquic_http3_server_has_failed(const coquic_http3_server_t *server);
```

Report terminal server failure.

Parameters:

- `server`: server handle or `NULL`.

Returns:

- Non-zero after terminal HTTP/3 server failure.
- `0` for `NULL`.

Notes:

- Terminal failure is HTTP/3-layer state, not endpoint ownership state.

### coquic_http3_server_update_destroy()

```c
void coquic_http3_server_update_destroy(
    coquic_http3_server_update_t *update);
```

Destroy a server update.

Parameters:

- `update`: update handle or `NULL`.

Returns:

- Nothing.

Notes:

- Invalidates all request views and emitted connection-input byte pointers
  borrowed from the update.

### coquic_http3_server_update_connection_input_count()

```c
size_t coquic_http3_server_update_connection_input_count(
    const coquic_http3_server_update_t *update);
```

Return the number of emitted QUIC connection inputs.

Parameters:

- `update`: server update or `NULL`.

Returns:

- Input count, or `0` for `NULL`.

Notes:

- Feed each input to the matching QUIC connection.

### coquic_http3_server_update_connection_input_at()

```c
coquic_status_t coquic_http3_server_update_connection_input_at(
    const coquic_http3_server_update_t *update,
    size_t index,
    coquic_connection_input_t *out_input);
```

Read one emitted QUIC connection input.

Parameters:

- `update`: server update.
- `index`: input index.
- `out_input`: output connection input.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Byte pointers inside `out_input` are borrowed from `update`.

### coquic_http3_server_update_request_cancelled_count()

```c
size_t coquic_http3_server_update_request_cancelled_count(
    const coquic_http3_server_update_t *update);
```

Return the number of request cancellation events.

Parameters:

- `update`: server update or `NULL`.

Returns:

- Cancellation event count, or `0` for `NULL`.

Notes:

- Read events with `coquic_http3_server_update_request_cancelled_at()`.

### coquic_http3_server_update_request_cancelled_at()

```c
coquic_status_t coquic_http3_server_update_request_cancelled_at(
    const coquic_http3_server_update_t *update,
    size_t index,
    coquic_http3_server_request_cancelled_event_t *out_event);
```

Read one server request cancellation event.

Parameters:

- `update`: server update.
- `index`: cancellation event index.
- `out_event`: output event pointer.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Views inside `out_event` are borrowed from `update`.

### coquic_http3_server_update_has_pending_work()

```c
uint8_t coquic_http3_server_update_has_pending_work(
    const coquic_http3_server_update_t *update);
```

Report whether the server has immediate pending work.

Parameters:

- `update`: server update or `NULL`.

Returns:

- Non-zero when the caller should poll again immediately.
- `0` for `NULL`.

Notes:

- Do not wait for network input before polling again when this is non-zero.

### coquic_http3_server_update_terminal_failure()

```c
uint8_t coquic_http3_server_update_terminal_failure(
    const coquic_http3_server_update_t *update);
```

Report terminal server failure in an update.

Parameters:

- `update`: server update or `NULL`.

Returns:

- Non-zero when this update reports terminal HTTP/3 server failure.
- `0` for `NULL`.

Notes:

- This mirrors update state; `coquic_http3_server_has_failed()` queries the
  server object.

### coquic_http3_server_update_handled_local_error()

```c
uint8_t coquic_http3_server_update_handled_local_error(
    const coquic_http3_server_update_t *update);
```

Report whether a QUIC local error was consumed by HTTP/3 server state.

Parameters:

- `update`: server update or `NULL`.

Returns:

- Non-zero when a QUIC local error was handled.
- `0` for `NULL`.

Notes:

- This is useful for bindings that separately log QUIC local errors.

### coquic_http3_request_view_header_at()

```c
coquic_status_t coquic_http3_request_view_header_at(
    const coquic_http3_request_view_t *request,
    size_t index,
    coquic_http3_field_view_t *out_field);
```

Read a request header view.

Parameters:

- `request`: borrowed request view.
- `index`: header index.
- `out_field`: receives the field view.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Returned name and value views are borrowed from the owning HTTP/3 update.

### coquic_http3_request_view_trailer_at()

```c
coquic_status_t coquic_http3_request_view_trailer_at(
    const coquic_http3_request_view_t *request,
    size_t index,
    coquic_http3_field_view_t *out_field);
```

Read a request trailer view.

Parameters:

- `request`: borrowed request view.
- `index`: trailer index.
- `out_field`: receives the field view.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Returned name and value views are borrowed from the owning HTTP/3 update.

### coquic_http3_request_head_view_header_at()

```c
coquic_status_t coquic_http3_request_head_view_header_at(
    const coquic_http3_request_head_view_t *head,
    size_t index,
    coquic_http3_field_view_t *out_field);
```

Read a request-head header view.

Parameters:

- `head`: borrowed request head view.
- `index`: header index.
- `out_field`: receives the field view.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Returned name and value views are borrowed from the owning HTTP/3 update.

### coquic_http3_response_view_interim_head_at()

```c
coquic_status_t coquic_http3_response_view_interim_head_at(
    const coquic_http3_response_view_t *response,
    size_t index,
    coquic_http3_response_head_view_t *out_head);
```

Read an interim response head.

Parameters:

- `response`: borrowed response view.
- `index`: interim head index.
- `out_head`: receives the response head view.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Header arrays inside `out_head` are borrowed from the owning HTTP/3 update.

### coquic_http3_response_view_header_at()

```c
coquic_status_t coquic_http3_response_view_header_at(
    const coquic_http3_response_view_t *response,
    size_t index,
    coquic_http3_field_view_t *out_field);
```

Read a final response header view.

Parameters:

- `response`: borrowed response view.
- `index`: header index.
- `out_field`: receives the field view.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Returned name and value views are borrowed from the owning HTTP/3 update.

### coquic_http3_response_view_trailer_at()

```c
coquic_status_t coquic_http3_response_view_trailer_at(
    const coquic_http3_response_view_t *response,
    size_t index,
    coquic_http3_field_view_t *out_field);
```

Read a response trailer view.

Parameters:

- `response`: borrowed response view.
- `index`: trailer index.
- `out_field`: receives the field view.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Returned name and value views are borrowed from the owning HTTP/3 update.

### coquic_http3_response_head_view_header_at()

```c
coquic_status_t coquic_http3_response_head_view_header_at(
    const coquic_http3_response_head_view_t *head,
    size_t index,
    coquic_http3_field_view_t *out_field);
```

Read a response-head header view.

Parameters:

- `head`: borrowed response head view.
- `index`: header index.
- `out_field`: receives the field view.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Returned name and value views are borrowed from the owning HTTP/3 update.

### coquic_http3_server_request_cancelled_view_trailer_at()

```c
coquic_status_t coquic_http3_server_request_cancelled_view_trailer_at(
    const coquic_http3_server_request_cancelled_event_t *event,
    size_t index,
    coquic_http3_field_view_t *out_field);
```

Read a trailer from a server request cancellation event.

Parameters:

- `event`: borrowed cancellation event.
- `index`: trailer index.
- `out_field`: receives the field view.

Returns:

- `COQUIC_STATUS_OK` on success.
- `COQUIC_STATUS_INVALID_ARGUMENT` for invalid arguments or index.

Notes:

- Returned name and value views are borrowed from the owning HTTP/3 update.
