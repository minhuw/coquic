# QUIC Facade API

The `coquic::quic` layer wraps the core endpoint with endpoint, connection, and
stream facade objects. It keeps the same caller-owned event-loop model while
reducing manual construction of `core::ConnectionCommand` values.

Use it as an ergonomic transport layer above `coquic::core`; it does not replace
the core result/effect model.

```cpp
#include "coquic/quic.h"
```

Use this layer when the caller wants a transport API for connection and stream
operations but still wants to process `core::Result` effects directly.

## Endpoint

`quic::Endpoint` owns a `core::Endpoint` internally. It exposes:

- `connect(ClientConfig, TimePoint)`: open a client connection.
- `connection(ConnectionHandle)`: create a connection facade for a handle.
- `receive_datagram(InboundDatagram, TimePoint)`: deliver UDP input.
- `update_path_mtu(PathMtuUpdate, TimePoint)`: deliver PMTU updates.
- `timer_expired(TimePoint)`: deliver timer expiry.
- `advance(EndpointInput, TimePoint)`: pass through generic core input.
- `next_wakeup()`: current timer deadline.
- `connection_count()` and `connection_diagnostics()`: endpoint state.

## Connection

`quic::Connection` is a lightweight handle back into an endpoint. It exposes:

- `stream(StreamId)`: create a stream facade.
- `advance(ConnectionInput, TimePoint)`: pass through generic connection input.
- `send_stream(StreamId, bytes, fin, TimePoint)`.
- `send_datagram(bytes, TimePoint)`.
- `reset_stream(StreamId, error_code, TimePoint)`.
- `stop_sending(StreamId, error_code, TimePoint)`.
- `close(error_code, reason_phrase, TimePoint)`.
- `request_key_update(TimePoint)`.

Each method returns `core::Result`. The caller must still send returned
datagrams and process returned effects.

## Stream

`quic::Stream` is a convenience handle for a single stream ID:

- `send(bytes, fin, TimePoint)`
- `finish(TimePoint)`
- `reset(error_code, TimePoint)`
- `stop_sending(error_code, TimePoint)`

## Example

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

## Ownership Rules

Facade objects do not own sockets and do not send network bytes by themselves.
They are handles into the endpoint. Keep the endpoint alive while using
connections or streams created from it.
