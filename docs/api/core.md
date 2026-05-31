# Core API

The `coquic::core` layer is the lowest public API. It is a sans-I/O endpoint:
the caller owns UDP sockets, address routing, timers, file I/O, and threading.
CoQUIC consumes typed inputs and returns typed effects.

This is the foundation used directly by low-level integrations and indirectly by
the `coquic::quic` facade. HTTP/3 work ultimately returns to this layer as QUIC
connection inputs.

```cpp
#include "coquic/core.h"
```

Use `core` when the integration needs direct control over connection handles,
route handles, timers, packets, and application effects.

## Endpoint Configuration

`core::EndpointConfig` configures one endpoint:

- `role`: client or server.
- `supported_versions`: QUIC versions, defaulting to version 1.
- `verify_peer`: peer certificate verification policy.
- `retry_enabled`: server retry policy.
- `application_protocol`: ALPN value.
- `identity`: server certificate and key material.
- `transport`: flow-control, PMTU, DATAGRAM, ACK, migration, grease, and
  congestion-control settings.
- `zero_rtt`: 0-RTT attempt/allow policy and application context.
- `qlog`: optional qlog output directory.
- `tls_keylog_path`: optional TLS key log output.
- `emit_shared_receive_stream_data`: receive-data ownership mode.
- `enable_packet_inspection`: packet inspection effect emission.
- `allow_peer_address_change`: peer address migration policy.

`core::TransportConfig` contains the transport-level defaults. Important
settings include idle timeout, UDP payload size, PMTU probing limits,
connection ID limit, stream and connection flow-control windows, DATAGRAM frame
size, and congestion-control algorithm.

## Inputs

`core::EndpointInput` is a variant of:

- `OpenConnection`: client connection creation.
- `InboundDatagram`: UDP payload received from the runtime.
- `PathMtuUpdate`: runtime PMTU observation.
- `ConnectionCommand`: application action for an existing connection.
- `TimerExpired`: runtime timer expiry.

Connection commands carry `core::ConnectionInput`, a variant of:

- `SendStreamData`
- `SendDatagramData`
- `ResetStream`
- `StopSending`
- `CloseConnection`
- `RequestKeyUpdate`
- `RequestConnectionMigration`

## Effects

Every endpoint method returns `core::Result`. A result contains:

- `effects`: typed actions and events.
- `next_wakeup`: next timer deadline.
- `local_error`: synchronous local API error, if any.
- `send_continuation_pending`: more send work can be produced without waiting
  for network input.

`core::Effect` is a variant of:

- `SendDatagram`: bytes the runtime must send on a UDP route.
- `ReceiveStreamData`: stream bytes delivered to the application.
- `ReceiveDatagramData`: DATAGRAM frame payload delivered to the application.
- `PeerResetStream` and `PeerStopSending`: peer stream-control signals.
- `StateEvent`: handshake-ready, handshake-confirmed, or failed state changes.
- `ConnectionLifecycleEvent`: connection created, accepted, or closed.
- `PeerPreferredAddressAvailable`: server preferred address advertisement.
- `ResumptionStateAvailable`: TLS resumption state for persistence.
- `ZeroRttStatusEvent`: 0-RTT attempt result.
- `PacketInspection`: optional decoded packet metadata and payload snapshots.
- `NewTokenAvailable`: address-validation token from the peer.

Use helper extractors when only one effect class matters:

```cpp
auto datagrams = coquic::core::send_datagrams(result);
auto states = coquic::core::state_events(result);
auto streams = coquic::core::receive_stream_events(result);
auto datagram_events = coquic::core::receive_datagram_events(result);
```

## Example

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

## Diagnostics

`Endpoint::connection_diagnostics()` returns lightweight connection state for
debug views and tests. It includes handshake status, current version, active
paths, active streams, and retired streams. Diagnostics are observability data,
not protocol commands.
