# Socket I/O Backend Design

## Goal

Extract the current UDP socket implementation out of `src/quic/http09_runtime.cpp` into a
separate backend module, and define a stable interface between real I/O, `QuicCore`, and the
HTTP/0.9 runtime.

The extracted boundary must support future backends such as `epoll`, `io_uring`, `DPDK`, and
`AF_XDP` without moving transport logic into those backends.

## Design Summary

The system is split into three layers:

1. `QuicCore`
   Pure transport state machine. It consumes endpoint inputs and produces transport effects.
2. `QuicIoBackend`
   Owns real I/O. It opens listeners/connectors, waits for events, receives datagrams, and sends
   outbound datagrams. It does not know HTTP/0.9 or QUIC stream semantics.
3. HTTP/0.9 runtime
   Orchestrates `QuicIoBackend`, `QuicCore`, and HTTP/0.9 endpoint logic. It owns app policy and
   terminal-success/failure behavior.

The external/backend boundary uses only `QuicRouteHandle`. `QuicPathId` remains internal to
`QuicCore`.

## Requirements

- `QuicCore` must remain free of real I/O and backend-specific wait/send APIs.
- The socket implementation must move out of `http09_runtime.cpp`.
- The backend must own stable route-handle assignment for inbound peers and for client-created
  remote routes.
- The runtime must treat `QuicRouteHandle` as an opaque token.
- `QuicPathId` must not cross the `QuicCore` boundary.
- The current endpoint-scoped multi-connection core design must remain intact.

## Non-Goals

- This change does not add a new I/O backend beyond the extracted socket backend.
- This change does not redesign HTTP/0.9 application behavior.
- This change does not move endpoint app logic into `QuicIoBackend`.
- This change does not add a connector layer between `QuicCore` and `QuicConnection`.

## Public Interface

The extracted backend interface is active: the backend owns wait/recv/send behavior.

```cpp
struct QuicIoRemote {
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    int family = AF_UNSPEC;
};

struct QuicIoRxDatagram {
    QuicRouteHandle route_handle;
    std::vector<std::byte> bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
};

struct QuicIoTxDatagram {
    QuicRouteHandle route_handle;
    std::vector<std::byte> bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
};

struct QuicIoEvent {
    enum class Kind : std::uint8_t {
        rx_datagram,
        timer_expired,
        idle_timeout,
        shutdown,
    };

    Kind kind;
    QuicCoreTimePoint now;
    std::optional<QuicIoRxDatagram> datagram;
};

class QuicIoBackend {
  public:
    virtual ~QuicIoBackend() = default;

    virtual std::optional<QuicRouteHandle> ensure_route(const QuicIoRemote &remote) = 0;
    virtual std::optional<QuicIoEvent>
    wait(std::optional<QuicCoreTimePoint> next_wakeup) = 0;
    virtual bool send(const QuicIoTxDatagram &datagram) = 0;
};
```

The abstract interface operates on resolved remotes. Host/port resolution is intentionally not part
of the generic `QuicIoBackend` contract. The concrete socket backend may provide backend-specific
startup helpers or factories that resolve runtime config into `QuicIoRemote` values before
`ensure_route(...)` is used.

### Why `ensure_route(...)` exists

`wait(...)` and `send(...)` alone are not enough for the client path. Before the first inbound
packet arrives, the runtime must be able to ask the backend for an initial outbound route so it can
open a client connection in `QuicCore` with a stable `QuicRouteHandle`.

## `QuicCore` Boundary Changes

The `QuicCore` boundary should be simplified to route-handle-only transport routing.

### `QuicCoreInboundDatagram`

Current state:
- carries `path_id`
- may also carry `route_handle`

Target state:

```cpp
struct QuicCoreInboundDatagram {
    std::vector<std::byte> bytes;
    std::optional<QuicRouteHandle> route_handle;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
};
```

### `QuicCoreSendDatagram`

Current state:
- may carry `path_id`
- may carry `route_handle`

Target state:

```cpp
struct QuicCoreSendDatagram {
    QuicConnectionHandle connection = 0;
    std::optional<QuicRouteHandle> route_handle;
    std::vector<std::byte> bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
};
```

### `QuicCoreRequestConnectionMigration`

Current state:
- public API takes `path_id`

Target state:

```cpp
struct QuicCoreRequestConnectionMigration {
    QuicRouteHandle route_handle = 0;
    QuicMigrationRequestReason reason = QuicMigrationRequestReason::active;
};
```

### Internal `QuicCore` responsibility

Inside `QuicCore`, each connection entry continues to maintain route-to-path bookkeeping:

- `route_handle -> path_id`
- `path_id -> route_handle`

When an inbound datagram arrives, `QuicCore` creates or looks up the internal `path_id` from the
route handle. When an outbound datagram is emitted, `QuicCore` resolves the correct route handle
for the selected internal path. Migration commands likewise select or create the path from a route
handle, not from a runtime-assigned path id.

## File Decomposition

### New files

- `src/quic/io_backend.h`
  Declares `QuicIoRemote`, `QuicIoEvent`, `QuicIoRxDatagram`, `QuicIoTxDatagram`, and
  `QuicIoBackend`.
- `src/quic/socket_io_backend.h`
  Declares the UDP socket backend and its constructor/config types.
- `src/quic/socket_io_backend.cpp`
  Implements socket open/bind/close, wait/poll, recvmsg/sendmsg, ECN handling, address resolution,
  and route-handle management.
- `src/quic/io_backend_test_hooks.h`
  Declares backend-level syscall override seams currently misnamed as HTTP/0.9 runtime hooks.

### Existing files to shrink or adjust

- `src/quic/http09_runtime.cpp`
  Becomes orchestration only.
- `src/quic/http09_runtime_test_hooks.h`
  Keeps HTTP/0.9 runtime-specific helpers only; backend syscall hooks move out.
- `src/quic/core.h`
  Public transport API changes: remove public `path_id` routing usage and update migration command.
- `src/quic/core.cpp`
  Internalize route-handle to path-id translation completely.

## Ownership Boundaries

### `QuicIoBackend` owns

- Socket lifecycle
- Listener/client route creation
- Stable route-handle assignment
- `route_handle -> actual outbound destination`
- Polling/waiting and receive loops
- ECN send/receive socket behavior

### `QuicCore` owns

- QUIC packet processing
- Retry/version-negotiation/connection lifecycle
- Internal path state and path validation
- Route-handle to internal path-id mapping

### HTTP/0.9 runtime owns

- Runtime config and CLI parsing
- App endpoint creation
- App policy such as preferred-address migration triggering
- Loop control, terminal success/failure behavior
- Translating backend events into `QuicCoreEndpointInput`
- Translating app-generated endpoint commands back into `QuicCore`

## Data Flow

### Client

1. Runtime obtains a resolved remote, using socket-backend-owned startup resolution or a
   backend-specific helper.
2. Runtime calls `backend.ensure_route(remote)` and gets an initial `QuicRouteHandle`.
3. Runtime opens a client connection in `QuicCore` using that route handle.
4. Backend `wait(...)` returns inbound datagrams tagged with route handles.
5. Runtime converts backend events to `QuicCoreEndpointInput`.
6. `QuicCore` emits send effects with route handles.
7. Runtime forwards outbound datagrams to `backend.send(...)`.

### Client preferred-address migration

1. `QuicCore` emits `QuicCorePeerPreferredAddressAvailable`.
2. Runtime converts the preferred address into `QuicIoRemote`.
3. Runtime calls `backend.ensure_route(preferred_remote)`.
4. Runtime sends `QuicCoreRequestConnectionMigration{ .route_handle = ... }`.
5. `QuicCore` chooses or creates the internal path for that route handle.

### Server

1. Backend owns listener socket(s).
2. Each inbound peer tuple is assigned a stable `QuicRouteHandle` by the backend.
3. Runtime passes inbound datagrams and route handles into `QuicCore`.
4. `QuicCore` handles VN, Retry, accepted connections, and 1-RTT traffic.
5. Outbound datagrams are emitted with route handles and sent by the backend.

## Migration Strategy

### Slice 1: Extract socket backend without behavior change

- Add `io_backend.h` and `socket_io_backend.h/.cpp`.
- Move socket open/bind/close, wait, recvmsg/sendmsg, ECN setup, and address resolution there.
- Update `http09_runtime.cpp` to use the socket backend while preserving current runtime behavior.

### Slice 2: Move test seams to the backend layer

- Move `Http09RuntimeOpsOverride` and its scoped override helper into `io_backend_test_hooks.h`.
- Retain runtime test hooks in `http09_runtime_test_hooks.h` only for runtime-specific behavior.
- Add focused backend tests for route stability, send/recv behavior, ECN handling, and bind/open
  failure paths.

### Slice 3: Internalize `QuicPathId`

- Remove public `path_id` use from `QuicCoreInboundDatagram`.
- Remove public `path_id` use from `QuicCoreSendDatagram`.
- Change `QuicCoreRequestConnectionMigration` to use only `route_handle`.
- Keep route-to-path bookkeeping internal to `QuicCore`.

### Slice 4: Shrink `http09_runtime.cpp` to orchestration only

- Remove raw socket fd sets from runtime.
- Remove runtime-owned send route tables.
- Remove direct recv/send/poll logic from runtime.
- Keep only orchestration, app policy, and event pumping.

## Verification Plan

### Backend tests

- Stable route-handle assignment per `(socket_fd, peer tuple)`
- Correct send route lookup by route handle
- ECN socket option configuration
- `recvmsg` ECN extraction
- `sendmsg` ECN marking
- Open/bind/wait error behavior

### `QuicCore` endpoint tests

- Accepted server connections preserve route-handle-based reply routing
- Retry and version-negotiation replies are emitted on the correct route
- Migration by route handle updates internal path selection correctly
- No public API path-id dependency remains

### HTTP/0.9 runtime tests

- Shared-core server transfer still works
- Multiconnect still works
- Retry and zero-rtt cases still work
- Preferred-address migration still works
- Runtime loops terminate correctly on success/failure with backend events

## Risks And Mitigations

### Risk: moving socket code just relocates the mess

Mitigation:
- Keep backend limited to I/O and route ownership
- Keep app policy in runtime
- Keep QUIC transport semantics in `QuicCore`

### Risk: route creation semantics drift between client and server

Mitigation:
- Backend owns both client-created and server-learned route handles
- Runtime treats route handles as opaque

### Risk: `path_id` leaks back into the runtime over time

Mitigation:
- Remove it from the public `QuicCore` boundary completely
- Keep route-to-path translation private to `QuicCore`

## Success Criteria

- `src/quic/http09_runtime.cpp` no longer contains raw socket I/O implementation details
- `QuicIoBackend` becomes the only real-I/O boundary
- `QuicCore` public API uses route handles, not path ids, for external routing
- Existing runtime and endpoint behavior remains intact under tests
- The extracted socket backend is a viable template for future non-socket backends
