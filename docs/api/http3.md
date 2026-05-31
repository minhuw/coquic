# HTTP/3 API

The `coquic::http3` layer translates HTTP/3 requests and responses into QUIC
connection inputs. It does not own a UDP socket or a QUIC endpoint.

Use it as application protocol state above the QUIC transport. It can be paired
with the low-level `coquic::core` API or with the `coquic::quic` facade.

```cpp
#include "coquic/http3.h"
```

Use this layer together with `coquic::core` or `coquic::quic`:

1. Drive the QUIC endpoint from the runtime.
2. Pass QUIC results into `http3::Client` or `http3::Server`.
3. Feed returned `quic_inputs` back to the matching QUIC connection.

Use `client_endpoint_config()` and `server_endpoint_config()` to set endpoint
role and ALPN to `h3`.

## Data Types

HTTP messages use simple value types:

- `Field`: one header field.
- `Headers`: vector of fields.
- `RequestHead`: method, scheme, authority, path, content length, headers.
- `ResponseHead`: status, content length, headers.
- `Request`: head, body, trailers.
- `Response`: interim heads, final head, body, trailers.
- `Settings`: local HTTP/3 and QPACK settings.

Errors use `http3::ErrorCode` and `http3::Error`. API calls that can fail use
`http3::Result<T>`.

## Client

`http3::Client` exposes:

- `submit_request(Request)`: enqueue a request and return its stream ID.
- `on_quic_result(core::Result, TimePoint)`: consume QUIC events and emit HTTP/3
  work.
- `poll(TimePoint)`: produce pending HTTP/3 work without new QUIC input.
- `has_failed()`: terminal client failure state.

`ClientUpdate` contains:

- `quic_inputs`: inputs to feed to the matching QUIC connection.
- `responses`: completed response events.
- `request_errors`: request cancellation/error events.
- `has_pending_work`: poll again without waiting for network input.
- `terminal_failure`: HTTP/3 layer failure.
- `handled_local_error`: whether a QUIC local error was consumed.

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

## Server

`http3::Server` exposes:

- `on_quic_result(core::Result, TimePoint)`: consume QUIC events and emit HTTP/3
  work.
- `poll(TimePoint)`: produce pending HTTP/3 work.
- `has_failed()`: terminal server failure state.

`ServerConfig` provides request handlers:

- `request_head_handler`: optional early response after the request head.
- `request_handler`: response after the full request is available.
- `fallback_request_handler`: explicit fallback path.

`ServerUpdate` contains QUIC inputs, cancelled request events, pending-work
state, terminal failure state, and local-error handling state.

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

## Integration Notes

HTTP/3 objects are per-connection protocol state. They do not route QUIC
connection handles by themselves. Feed each `quic_inputs` item to the QUIC
connection that produced the corresponding HTTP/3 event stream.
