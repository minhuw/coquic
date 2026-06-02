# C FFI API

The C FFI API is the public C ABI boundary for CoQUIC. It exposes the same
sans-I/O endpoint model as `coquic::core`, but uses opaque handles, fixed-width
integer types, tagged effect structs, and explicit result destruction so it can
be consumed from C and native language bindings.

The public header is:

```c
#include <coquic/ffi/core.h>
```

The implementation is packaged by TLS backend:

- CMake packages: `coquic-boringssl` and `coquic-quictls`
- CMake shared targets: `CoQUIC::coquic_boringssl` and
  `CoQUIC::coquic_quictls`
- CMake static targets: `CoQUIC::coquic_boringssl_static` and
  `CoQUIC::coquic_quictls_static`
- pkg-config packages: `coquic-boringssl` and `coquic-quictls`
- static pkg-config packages: `coquic-boringssl-static` and
  `coquic-quictls-static`

Do not link both backend packages into one process. They intentionally export
the same `coquic_*` C symbols.

## ABI Version

`COQUIC_FFI_ABI_VERSION` is the compile-time ABI version. Call
`coquic_ffi_abi_version()` at runtime when a binding needs to verify that the
loaded library matches the headers it was built against.

The current ABI version is `1`.

## Object Model

`coquic_endpoint_t` owns QUIC endpoint state. Create it with
`coquic_endpoint_create()` and release it with `coquic_endpoint_destroy()`.

`coquic_result_t` owns the effects returned by an endpoint operation. Every
successful endpoint or connection operation writes a result pointer to the
caller-provided `coquic_result_t **`. Release each non-null result with
`coquic_result_destroy()` after reading its effects.

Passing `NULL` to a destroy function is allowed.

## Configuration

Initialize configuration structs before use:

```c
coquic_endpoint_config_t endpoint_config;
coquic_endpoint_config_init(&endpoint_config);

coquic_client_connection_config_t connection_config;
coquic_client_connection_config_init(&connection_config);
```

Structs that cross the ABI boundary include a `size` field when they are used
as API inputs. Keep that field at `sizeof(the_struct)` after initialization.
This lets future versions append fields while still accepting older callers
whose struct size covers the required v1 fields.

## Time

`coquic_time_us_t` is an unsigned microsecond timestamp. Use one monotonic
runtime clock consistently for all calls on an endpoint. CoQUIC compares these
values to drive timers; it does not read the system clock through the C API.

Use `coquic_endpoint_next_wakeup()` or `coquic_result_next_wakeup()` to arm the
runtime timer. When the timer fires, call `coquic_endpoint_timer_expired()`.

## Buffer Ownership

Input buffers use `coquic_bytes_t`. CoQUIC copies input bytes during the API
call, so the caller only needs those buffers to remain valid until the function
returns.

Output buffers use `coquic_bytes_view_t`. These are borrowed views into the
owning `coquic_result_t`. They remain valid only until that result is destroyed.
Copy any effect bytes, resumption state, NEW_TOKEN token, or packet-inspection
data that must outlive the result.

Do not free `coquic_bytes_view_t.data`; it is not caller-owned.

## Event Loop

The C FFI is still sans-I/O. The caller owns sockets, routing, timers, files,
threading, and application scheduling.

The usual loop is:

1. Create one endpoint with `coquic_endpoint_create()`.
2. For a client, call `coquic_endpoint_open_connection()`.
3. Feed inbound UDP datagrams with `coquic_endpoint_input_datagram()`.
4. Feed timer expiry with `coquic_endpoint_timer_expired()`.
5. Feed application work with connection functions such as
   `coquic_connection_send_stream()` and `coquic_connection_close()`.
6. Iterate returned effects with `coquic_result_effect_count()` and
   `coquic_result_effect_at()`.
7. Send every `COQUIC_EFFECT_SEND_DATAGRAM` effect through the runtime socket.
8. Deliver stream, DATAGRAM, lifecycle, 0-RTT, token, and diagnostic effects to
   the application.
9. Destroy the result.
10. Re-arm the runtime timer from the endpoint or result wakeup.

`coquic_route_handle_t` is runtime-defined. CoQUIC returns route handles on send
effects so the caller can send the datagram on the matching socket or path.

## Status And Errors

Most functions return `coquic_status_t`:

- `COQUIC_STATUS_OK`: the C call succeeded.
- `COQUIC_STATUS_INVALID_ARGUMENT`: a required pointer, size field, or index was
  invalid.
- `COQUIC_STATUS_OUT_OF_MEMORY`: allocation failed.
- `COQUIC_STATUS_INTERNAL_ERROR`: an unexpected implementation exception was
  caught before it crossed the C ABI.

Transport-level local errors are reported in `coquic_result_t`. Use
`coquic_result_has_local_error()` and `coquic_result_local_error()` after a
successful API call.

## Minimal Smoke Test

```c
#include <coquic/ffi/core.h>

int main(void) {
    return coquic_ffi_abi_version() == COQUIC_FFI_ABI_VERSION ? 0 : 1;
}
```

With pkg-config:

```sh
cc smoke.c -o smoke $(pkg-config --cflags --libs coquic-boringssl)
```

For a static link, use the explicit static package:

```sh
cc smoke.c -o smoke $(pkg-config --cflags --libs coquic-boringssl-static)
```

With CMake:

```cmake
find_package(coquic-boringssl CONFIG REQUIRED)
target_link_libraries(app PRIVATE CoQUIC::coquic_boringssl)
```

Use `CoQUIC::coquic_boringssl_static` when a static link is required.

## Stability

The C FFI API is intended to become the stable native binding surface. For now,
treat the ABI version, exported `coquic_*` functions, enum values, and public
struct layouts in `include/coquic/ffi/core.h` as the compatibility boundary.
Implementation files under `src/` remain private.
