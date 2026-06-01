# CoQUIC Public API

CoQUIC exposes its public C++ API from `include/coquic/`. Code outside the
library should include those headers instead of reaching into `src/`.

```cpp
#include "coquic/coquic.h" // core + quic + http3
```

Use the narrower headers when a caller only needs one layer:

```cpp
#include "coquic/core.h"
#include "coquic/quic.h"
#include "coquic/http3.h"
```

The public API is split into three layers:

- `coquic::core`: sans-I/O QUIC endpoint API for runtimes, tests, interop
  harnesses, and bindings.
- `coquic::quic`: a convenience transport facade over `core` with endpoint,
  connection, and stream objects.
- `coquic::http3`: HTTP/3 request and response API that translates HTTP/3 work
  into QUIC connection inputs.

The headers under `include/coquic/` are the intended compatibility surface.
Types and helpers under `src/` remain implementation details.

## Event Loop Model

The caller owns the runtime: sockets, timers, address routing, file I/O, and
threading. CoQUIC consumes inputs and returns effects.

The usual loop is:

1. Pass inbound UDP bytes to an endpoint with `InboundDatagram`.
2. Pass timer expiry with `timer_expired`.
3. Pass application writes with `ConnectionCommand` or the `quic::Connection`
   helpers.
4. Send every returned `SendDatagram` effect through the runtime socket.
5. Deliver `ReceiveStreamData`, `ReceiveDatagramData`, lifecycle, state, and
   diagnostic effects to the application.
6. Arm the runtime timer from `Result::next_wakeup` or `Endpoint::next_wakeup`.

Every endpoint method takes a `coquic::core::TimePoint`. Use one runtime clock
consistently for all calls on an endpoint.

## `coquic::core`

`core` is the lowest stable API. It is useful when the caller needs full control
over routing, timers, effects, connection handles, and integration with a
custom event loop.

```cpp
#include "coquic/core.h"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <vector>

std::vector<std::byte> bytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (auto value : values) {
        out.push_back(static_cast<std::byte>(value));
    }
    return out;
}

void open_client_connection() {
    coquic::core::Endpoint endpoint({
        .role = coquic::core::Role::client,
        .verify_peer = false,
        .application_protocol = "coquic",
    });

    const auto now = coquic::core::Clock::now();
    auto result = endpoint.open_connection(
        coquic::core::OpenConnection{
            .connection =
                {
                    .source_connection_id = bytes({0xc1, 0x01}),
                    .initial_destination_connection_id = bytes({0x83, 0x41}),
                    .server_name = "localhost",
                },
            .initial_route_handle = 7,
        },
        now);

    for (const auto &datagram : coquic::core::send_datagrams(result)) {
        // Send datagram.bytes on the UDP route identified by datagram.route_handle.
    }
}
```

Important core types:

- `EndpointConfig`: endpoint role, QUIC versions, TLS policy, ALPN, transport
  limits, qlog, 0-RTT, packet inspection, and migration policy.
- `EndpointInput`: a variant of `OpenConnection`, `InboundDatagram`,
  `PathMtuUpdate`, `ConnectionCommand`, and `TimerExpired`.
- `ConnectionInput`: a variant for application actions on a connection:
  stream data, DATAGRAM data, reset, stop-sending, close, key update, and
  migration.
- `Result`: effects, next wakeup, local error, and send-continuation state.
- `Effect`: outbound datagrams, received stream or datagram data, peer stream
  state, connection state, lifecycle, resumption, 0-RTT, qlog inspection, and
  token events.

Use the extractor helpers when only one effect class matters:

```cpp
auto datagrams = coquic::core::send_datagrams(result);
auto states = coquic::core::state_events(result);
auto streams = coquic::core::receive_stream_events(result);
```

## `coquic::quic`

`quic` keeps the same event-loop ownership model, but wraps connection handles
in small facade objects. It is the right layer for callers that want a stable
QUIC transport API without manually constructing every `ConnectionCommand`.

```cpp
#include "coquic/quic.h"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <vector>

std::vector<std::byte> bytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (auto value : values) {
        out.push_back(static_cast<std::byte>(value));
    }
    return out;
}

void send_on_stream() {
    coquic::quic::Endpoint endpoint({
        .core =
            {
                .role = coquic::core::Role::client,
                .verify_peer = false,
                .application_protocol = "coquic",
            },
    });

    auto connected = endpoint.connect(
        coquic::quic::ClientConfig{
            .core =
                {
                    .source_connection_id = bytes({0xc1, 0x01}),
                    .initial_destination_connection_id = bytes({0x83, 0x41}),
                    .server_name = "localhost",
                },
            .initial_route_handle = 7,
        },
        coquic::core::Clock::now());

    for (const auto &datagram : coquic::core::send_datagrams(connected.result)) {
        // Send datagram.bytes through the runtime socket.
    }

    auto stream = connected.connection.stream(0);
    const auto payload = bytes({0x68, 0x65, 0x6c, 0x6c, 0x6f});
    auto write_result = stream.send(payload, true, coquic::core::Clock::now());
    for (const auto &datagram : coquic::core::send_datagrams(write_result)) {
        // Send datagram.bytes through the runtime socket.
    }
}
```

Important facade types:

- `quic::Endpoint`: owns the underlying QUIC endpoint and accepts datagrams,
  timers, PMTU updates, and generic core inputs.
- `quic::Connection`: sends stream data, DATAGRAM frames, resets, stop-sending,
  application close, and key-update requests.
- `quic::Stream`: convenience handle for stream send, finish, reset, and
  stop-sending.
- `quic::ConnectResult`: returns both the new connection facade and the first
  core `Result`.

The `quic` facade still returns `core::Result`; the caller still sends returned
datagrams and processes returned effects.

## `coquic::http3`

`http3` exposes request and response objects and emits QUIC connection inputs.
It does not own UDP sockets or a QUIC endpoint. The caller drives a QUIC
endpoint, passes QUIC results into HTTP/3, then feeds HTTP/3 `quic_inputs` back
to the matching QUIC connection.

Use `client_endpoint_config` and `server_endpoint_config` to set the endpoint
role and ALPN to `h3`.

```cpp
#include "coquic/http3.h"

void submit_http3_request(coquic::http3::Client &client) {
    auto submitted = client.submit_request(coquic::http3::Request{
        .head =
            {
                .method = "GET",
                .scheme = "https",
                .authority = "example.test",
                .path = "/",
            },
    });

    if (!submitted.has_value()) {
        // Inspect submitted.error().
        return;
    }

    coquic::core::Result ready;
    ready.effects.push_back(coquic::core::StateEvent{
        .connection = 1,
        .change = coquic::core::StateChange::handshake_ready,
    });

    auto update = client.on_quic_result(ready, coquic::core::Clock::now());
    for (auto &input : update.quic_inputs) {
        // Feed input to the QUIC connection with core::ConnectionCommand or
        // quic::Connection::advance.
    }
}
```

Server handlers can answer after the full request is received, or send an early
response once the request head is available.

```cpp
#include "coquic/http3.h"

#include <optional>

coquic::http3::Server make_server() {
    return coquic::http3::Server({
        .request_head_handler =
            [](const coquic::http3::RequestHead &head)
                -> std::optional<coquic::http3::Response> {
                if (head.path == "/healthz") {
                    return coquic::http3::Response{
                        .head = {.status = 204, .content_length = 0},
                    };
                }
                return std::nullopt;
            },
        .request_handler =
            [](const coquic::http3::Request &request) {
                return coquic::http3::Response{
                    .head =
                        {
                            .status = 200,
                            .content_length = request.body.size(),
                        },
                    .body = request.body,
                };
            },
    });
}
```

Important HTTP/3 types:

- `RequestHead`, `Request`, `ResponseHead`, `Response`, `Field`, and `Headers`.
- `Client::submit_request`, `Client::on_quic_result`, and `Client::poll`.
- `Server::on_quic_result` and `Server::poll`.
- `ClientUpdate` and `ServerUpdate`, which carry `quic_inputs`, completed
  responses, cancellation events, pending-work state, and terminal failure
  state.
- `ServerConfig::request_head_handler` for early responses,
  `request_handler` for complete requests, and `fallback_request_handler` for
  callers that want an explicit fallback path.

## Integration Checklist

- Include headers from `include/coquic/`; do not include internal headers from
  `src/`.
- Keep one monotonic clock source per endpoint.
- Send all `SendDatagram` effects before waiting for the next socket or timer
  event.
- Re-arm the timer from the most recent `next_wakeup`.
- Feed HTTP/3 `quic_inputs` to the QUIC connection that produced the
  corresponding HTTP/3 events.
- Treat `local_error`, `terminal_failure`, and `has_failed()` as application
  signals; they do not send UDP bytes by themselves.

## Build Notes

Inside this repository, `zig build` adds `include/` to the project library,
executables, and tests. The current public API smoke tests live in
`tests/api/public_api_test.cpp` and are run by:

```bash
nix develop -c zig build test
```

Packaging and installation of exported headers for external consumers is still
separate from the in-repo build.
