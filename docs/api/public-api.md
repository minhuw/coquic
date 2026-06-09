# Public API

CoQUIC exposes its public C++ API from `include/coquic/`. Code outside the
library should include those headers instead of reaching into `src/`.

```cpp
#include "coquic/coquic.h" // core + quic + http3
```

Use narrower headers when a caller only needs one layer:

```cpp
#include "coquic/core.h"
#include "coquic/quic.h"
#include "coquic/http3.h"
```

The public API is the compatibility boundary, not a fourth runtime layer. Within
that boundary, CoQUIC exposes three API layers:

- [`coquic::core`](core.md): sans-I/O QUIC endpoint API for runtimes, tests,
  interop harnesses, and bindings.
- [`coquic::quic`](quic.md): a convenience transport facade over `core` with
  endpoint, connection, and stream objects.
- [`coquic::http3`](http3.md): HTTP/3 request and response API that translates
  HTTP/3 work into QUIC connection inputs.

The headers under `include/coquic/` are the intended compatibility surface.
Types and helpers under `src/` remain implementation details.

The C ABI wrapper is documented separately as the [C FFI API](c-ffi.md). It is a
public ABI surface for native bindings, but it is not one of the C++ API layers.
Use it for C consumers and native language bindings that need opaque handles,
explicit result ownership, and pkg-config or CMake package metadata.

The in-tree language wrappers build on that C FFI. [Rust](rust-wrapper.md)
provides `coquic-sys` plus an ergonomic `coquic-rs` facade; the
[JavaScript](javascript-wrapper.md), [Python](python-wrapper.md), and
[Go](go-wrapper.md) wrappers expose similar sans-I/O QUIC surfaces for their
runtime ecosystems.

## Layer Map

```text
include/coquic/ public API
+-- coquic/core.h
|   coquic::core: lowest sans-I/O QUIC endpoint.
+-- coquic/quic.h
|   coquic::quic: optional facade that wraps core endpoint commands.
`-- coquic/http3.h
   coquic::http3: HTTP/3 state machine that emits QUIC connection inputs.
```

At runtime the data flow is:

```text
HTTP/3 API
  emits core::ConnectionInput values
        v
QUIC Facade API, optional
  forwards connection work to core
        v
Core API
  consumes endpoint inputs and returns effects
        v
Caller runtime
  owns sockets, timers, routing, files, and threads
```

The facade layer is optional. A runtime can call `core` directly, or use `quic`
to reduce manual construction of connection commands. HTTP/3 remains separate
protocol state and feeds work into the selected QUIC connection.

## Layer Selection

Choose `core` when the integration needs complete control over routing, timers,
connection handles, packet effects, and event-loop behavior.

Choose `quic` when the integration wants a small transport facade for
connections and streams while still processing `core::Result` effects.

Choose `http3` when the integration wants request/response state that emits QUIC
connection inputs. HTTP/3 does not own UDP sockets or a QUIC endpoint.

## Event-Loop Model

The caller owns the runtime: sockets, timers, address routing, file I/O, and
threading. CoQUIC consumes inputs and returns effects.

The usual loop is:

1. Pass inbound UDP bytes to an endpoint with `InboundDatagram`.
2. Pass timer expiry with `timer_expired`.
3. Pass application writes with `ConnectionCommand` or the `quic::Connection`
   helpers.
4. Send every returned `SendDatagram` effect through the runtime socket.
5. Deliver received stream data, DATAGRAM data, lifecycle, state, and diagnostic
   effects to the application.
6. Arm the runtime timer from `Result::next_wakeup` or `Endpoint::next_wakeup`.

Every endpoint method takes a `coquic::core::TimePoint`. Use one runtime clock
consistently for all calls on an endpoint.

## Compatibility Boundary

Stable surface:

- Headers in `include/coquic/`.
- Namespaces `coquic::core`, `coquic::quic`, and `coquic::http3`.
- Public value types, enums, endpoint facades, and result/effect types declared
  by those headers.

Internal surface:

- Anything under `src/`.
- Test hooks and support headers.
- Generated demo artifacts and benchmark result JSON.

## Build Notes

Inside this repository, `zig build` adds `include/` to the project library,
executables, and tests. Public API smoke tests live in
`tests/api/public_api_test.cpp`.

```bash
nix develop -c zig build test
```

Packaging and installation of exported headers for external consumers is still
separate from the in-repo build.
