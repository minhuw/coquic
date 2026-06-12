# C FFI API

The C FFI API is the public C ABI boundary for CoQUIC. It exposes the sans-I/O
Core, QUIC facade, and HTTP/3 APIs through opaque handles, fixed-width integer
types, tagged structs, and explicit ownership.

Use these headers:

```c
#include <coquic/ffi/core.h>
#include <coquic/ffi/http3.h>
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

## Common Rules

`COQUIC_FFI_ABI_VERSION` is the compile-time ABI version. Call
`coquic_ffi_abi_version()` at runtime when a binding needs to verify that the
loaded library matches the headers it was built against. The current ABI version
is `2`.

All API input structs with a `size` member must be initialized before use. Keep
`size` at `sizeof(the_struct)` after initialization so future ABI versions can
append fields while still accepting v1 callers.

Input buffers use `coquic_bytes_t`. CoQUIC copies input bytes during the call,
so those buffers only need to live until the function returns.

Output buffers use `coquic_bytes_view_t`. These views are borrowed from the
owning `coquic_result_t` or HTTP/3 update object. Copy data that must outlive
that owner.

`coquic_time_us_t` is a monotonic microsecond timestamp supplied by the caller.
Use one runtime clock consistently for all calls on an endpoint.

## Ownership

`coquic_endpoint_t` owns QUIC endpoint state. Create it with
`coquic_endpoint_create()` and release it with `coquic_endpoint_destroy()`.

`coquic_result_t` owns endpoint and connection effects. Every successful
endpoint, Core connection, or QUIC facade operation writes a result pointer to
`coquic_result_t **out_result`. Release each non-null result with
`coquic_result_destroy()` after reading its effects.

`coquic_http3_client_t` and `coquic_http3_server_t` own HTTP/3 protocol state
for one QUIC connection. HTTP/3 update objects own emitted QUIC inputs and HTTP
events; release them with the matching update destroy function.

Passing `NULL` to destroy functions is allowed.

## Status And Errors

Most mutating calls return `coquic_status_t`:

- `COQUIC_STATUS_OK`: the C call succeeded.
- `COQUIC_STATUS_INVALID_ARGUMENT`: a required pointer, struct size, enum tag,
  or index was invalid.
- `COQUIC_STATUS_OUT_OF_MEMORY`: allocation failed.
- `COQUIC_STATUS_INTERNAL_ERROR`: an unexpected implementation exception was
  caught before crossing the C ABI.

`COQUIC_STATUS_OK` does not mean the QUIC or HTTP/3 operation completed
successfully at the protocol layer. Transport-level local errors are reported
inside `coquic_result_t`; use `coquic_result_has_local_error()` and
`coquic_result_local_error()`.

HTTP/3 submit errors are reported with `coquic_http3_error_t`. Set
`detail_buffer` and `detail_buffer_capacity` before the call when a binding
wants a copied diagnostic string.

## Event Loop

The C FFI remains sans-I/O. The caller owns sockets, timers, routing, files,
threads, and scheduling.

The usual loop is:

1. Create an endpoint with `coquic_endpoint_create()`.
2. Open a client connection with `coquic_endpoint_open_connection()` or
   `coquic_quic_connect()`.
3. Feed inbound UDP datagrams with `coquic_endpoint_input_datagram()` or
   `coquic_quic_receive_datagram()`.
4. Feed timer expiry with `coquic_endpoint_timer_expired()` or
   `coquic_quic_timer_expired()`.
5. Feed application work with Core connection functions, QUIC facade functions,
   or HTTP/3-produced `coquic_connection_input_t` values.
6. Iterate result effects with `coquic_result_effect_count()` and
   `coquic_result_effect_at()`.
7. Send every `COQUIC_EFFECT_SEND_DATAGRAM` effect through the runtime socket.
8. Deliver stream, DATAGRAM, lifecycle, 0-RTT, token, and diagnostic effects to
   the application.
9. Destroy the result.
10. Re-arm the runtime timer from `coquic_result_next_wakeup()` or
    `coquic_endpoint_next_wakeup()`.

If `coquic_result_send_continuation_pending()` or
`coquic_endpoint_has_send_continuation_pending()` returns non-zero, call back
into the endpoint without blocking so queued send work can continue.

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

## API Reference

The usage guide intentionally keeps signatures and per-function behavior out of
the main flow. See the [C FFI Reference](c-ffi-reference.md) for the public
function list with inputs, outputs, semantics, and important notices.

## Stability

The C FFI API is intended to become the stable native binding surface. For now,
treat the ABI version, exported `coquic_*` functions, enum values, and public
struct layouts in `include/coquic/ffi/core.h` and `include/coquic/ffi/http3.h`
as the compatibility boundary. Implementation files under `src/` remain
private.
