# io_uring Backend Design

Date: 2026-04-11
Repo: `coquic`
Status: Approved

## Summary

Add an explicit HTTP/0.9 runtime I/O backend selector and implement a second real
Linux backend using `io_uring`, with full behavioral parity against the current
socket backend.

The existing `QuicIoBackend` boundary is good enough to keep as the runtime-facing
contract. The design extends the `src/io/` layer underneath that boundary with a
shared UDP backend core plus a narrower internal `io_engine` interface. This lets
`socket` and `io_uring` share route, socket, resolution, and ECN semantics while
changing only the event/completion engine.

The design also keeps the door open for separately compiled engine libraries and
future plugin work, but it does not claim a stable third-party plugin ABI in v1.

## Problem

The repository currently has only one real I/O backend:

- `SocketIoBackend` in `src/io/socket_io_backend.cpp`

That means the current abstraction has only been validated by one implementation.
The HTTP/0.9 runtime also still hard-codes `SocketIoBackend` construction in
`src/http09/http09_runtime.cpp`, so runtime selection is not explicit.

Adding a second backend by copying `SocketIoBackend` would prove very little. The
copied code would duplicate the same UDP socket setup, route-handle bookkeeping,
address resolution, migration socket management, and ECN logic that should stay
consistent across backends.

## Goals

- Add explicit runtime backend selection with `socket` as the default.
- Implement a Linux `io_uring` backend with full parity:
  - client and server support
  - stable route handles per peer tuple
  - migration and cross-family extra sockets
  - ECN send and receive behavior
  - unchanged `QuicIoBackend` semantics
- Keep `QuicCore` and the current runtime/backend transport boundary intact.
- Introduce a narrow internal `io_engine` interface so multiple event engines can
  share one UDP/backend core.
- Allow in-tree engines to be compiled as separate libraries if desired, without
  freezing a public plugin ABI.
- Fail fast when the user explicitly selects `io_uring` but the platform or
  runtime cannot support it.
- Add `liburing` to the Linux development and build environment.

## Non-Goals

- No stable third-party plugin ABI in this change.
- No dynamic engine loading in this change.
- No redesign of `QuicIoBackend`.
- No changes to `QuicCore` transport semantics.
- No non-Linux async engines such as `kqueue`, IOCP, DPDK, or AF_XDP.
- No silent fallback from explicit `io_uring` selection to `socket`.

## Chosen Architecture

### Runtime-Facing Boundary

`QuicIoBackend` remains the public runtime-facing interface:

```cpp
class QuicIoBackend {
  public:
    virtual ~QuicIoBackend() = default;

    virtual std::optional<QuicRouteHandle> ensure_route(const QuicIoRemote &remote) = 0;
    virtual std::optional<QuicIoEvent> wait(std::optional<QuicCoreTimePoint> next_wakeup) = 0;
    virtual bool send(const QuicIoTxDatagram &datagram) = 0;
};
```

The runtime keeps talking only to `QuicIoBackend`. `QuicCore` remains unaware of
backend choice, engine details, `poll`, and `io_uring`.

### Explicit Runtime Selection

`Http09RuntimeConfig` gains an explicit backend selector:

```cpp
enum class Http09IoBackendKind : std::uint8_t {
    socket,
    io_uring,
};

struct Http09RuntimeConfig {
    Http09RuntimeMode mode = Http09RuntimeMode::health_check;
    Http09IoBackendKind io_backend = Http09IoBackendKind::socket;
    // existing fields...
};
```

CLI parsing accepts:

- `--io-backend=socket`
- `--io-backend=io_uring`

The default remains `socket`.

### Backend Composition

The concrete runtime-facing backends are composed from two internal pieces:

1. Shared UDP backend core
2. Pluggable I/O engine

The intended composition is:

```text
SocketIoBackend   = SharedUdpBackendCore + PollIoEngine
IoUringBackend    = SharedUdpBackendCore + IoUringIoEngine
```

This keeps backend semantics in one place while allowing multiple event engines.

### Shared UDP Backend Core

The shared backend core owns the logic that must stay identical across backends:

- remote address resolution
- listener bind policy
- UDP socket open/bind/close
- route-handle allocation and peer-tuple stability
- route-handle to outbound socket/peer mapping
- extra route sockets for migration and cross-family routing
- ECN send ancillary generation
- ECN receive ancillary parsing
- translation between engine completions and `QuicIoEvent`

This layer does not know HTTP/0.9 application semantics and does not know QUIC
stream behavior. It only owns UDP/backend mechanics.

### Internal `io_engine` Layer

Add a narrower in-tree engine interface under `src/io/` that is used by the
shared backend core but is not exposed as a stable public runtime ABI.

Conceptually, the engine is responsible only for:

- registering active sockets or descriptors
- arming receive operations
- submitting send operations
- waiting for completions or timer expiry
- reporting shutdown or I/O errors back to the backend core

The engine does not own:

- route handles
- peer-tuple routing policy
- address resolution
- migration policy
- HTTP/0.9 runtime behavior
- `QuicCore`

The engine interface should stay small enough that:

- `PollIoEngine` is a straightforward synchronous reference implementation
- `IoUringIoEngine` replaces the event/completion mechanism only
- future in-tree engines can be built as separate library targets if desired

This interface is intentionally an internal C++ contract, not a frozen plugin ABI.

### Separate Compilation And Future Plugins

The design should allow engine implementations to be compiled as independent
library artifacts, including shared libraries if that becomes useful for local
build composition or downstream packaging.

However, v1 does not promise:

- runtime `dlopen`-style discovery
- cross-toolchain ABI stability
- a third-party extension ABI

If third-party runtime-loaded engines are needed later, that must be a separate
design that introduces an explicit versioned C ABI on top of this internal engine
layer.

## Backend Factory And Bootstrap

Move backend selection and startup wiring out of `src/http09/http09_runtime.cpp`
into a small factory/bootstrap layer under `src/io/`.

The factory layer is responsible for:

- choosing `SocketIoBackend` or `IoUringBackend`
- returning clear startup failure when explicit `io_uring` selection is unsupported
- client bootstrap:
  - create backend
  - resolve remote
  - create initial outbound route
- server bootstrap:
  - create backend
  - open primary listener
  - open additional listener when the testcase requires it

This removes direct `SocketIoBackend` construction from the runtime while keeping
runtime orchestration logic simple.

## Client And Server Flow

### Client

1. Runtime parses config and selects an I/O backend kind.
2. Factory creates the chosen backend.
3. Backend resolves the configured remote and allocates the initial route handle.
4. Runtime opens the QUIC client connection in `QuicCore` with that route handle.
5. Backend `wait(...)` returns `QuicIoEvent` values tagged with route handles.
6. Runtime feeds those events into `QuicCore`.
7. Runtime forwards `QuicCore` send effects to `backend.send(...)`.

### Server

1. Runtime parses config and selects an I/O backend kind.
2. Factory creates the chosen backend and opens the configured listener socket set.
3. Backend assigns stable route handles to inbound peer tuples.
4. Runtime passes inbound datagrams and route handles into `QuicCore`.
5. `QuicCore` emits outbound datagrams tagged with route handles.
6. Runtime forwards those sends to `backend.send(...)`.

### Preferred Address And Migration

The backend core continues to own route creation for new peers and new outbound
socket families. When preferred-address migration or rebinding requires a new
route, the runtime still asks the backend for a route handle and then submits the
transport migration command to `QuicCore`.

`io_uring` must preserve the same route and migration behavior as `socket`.

## Send And Wait Semantics

`send(...)` must remain synchronous at the `QuicIoBackend` boundary.

For `PollIoEngine`, this is naturally synchronous.

For `IoUringIoEngine`, the implementation may submit asynchronous send operations
internally, but `QuicIoBackend::send(...)` must not report success until the send
completion is known. This preserves current runtime behavior and existing test
assumptions.

`wait(...)` must continue to expose the same high-level event model:

- `rx_datagram`
- `timer_expired`
- `idle_timeout`
- `shutdown`

The runtime should not need different logic for `socket` versus `io_uring`.

## Failure Semantics

If the user explicitly selects `io_uring`, the runtime must fail fast with a clear
error and exit code `1` when any of the following occur:

- build or runtime is not Linux-capable for `io_uring`
- `liburing` initialization fails
- ring setup fails
- engine registration of a listener or route socket fails
- required receive arming fails
- engine completion reports a fatal receive or send failure

The runtime must not silently fall back to `socket` when `io_uring` was explicitly
requested.

If the user does not specify a backend, the default remains `socket`.

## File Decomposition

### New Files

- `src/io/io_engine.h`
  - internal engine contract used by shared backend core
- `src/io/poll_io_engine.h`
- `src/io/poll_io_engine.cpp`
  - poll-based engine extracted from current socket backend wait mechanics
- `src/io/io_uring_io_engine.h`
- `src/io/io_uring_io_engine.cpp`
  - `liburing`-based engine implementation
- `src/io/shared_udp_backend_core.h`
- `src/io/shared_udp_backend_core.cpp`
  - shared UDP sockets, routing, resolution, and ECN logic
- `src/io/io_backend_factory.h`
- `src/io/io_backend_factory.cpp`
  - explicit backend selection and runtime bootstrap
- `tests/http09/runtime/io_uring_backend_test.cpp`
  - `io_uring`-specific tests

### Existing Files To Modify

- `src/http09/http09_runtime.h`
  - add `Http09IoBackendKind` and config field
- `src/http09/http09_runtime.cpp`
  - parse backend selection and use factory/bootstrap instead of direct
    `SocketIoBackend` construction
- `src/io/socket_io_backend.h`
- `src/io/socket_io_backend.cpp`
  - delegate common backend mechanics to shared UDP backend core and
    `PollIoEngine`
- `src/io/io_backend_test_hooks.h`
  - split or extend test seams so backend-neutral helpers stay generic and
    `io_uring`-specific hooks are separate
- `tests/http09/runtime/config_test.cpp`
  - cover CLI parsing and default selection
- `tests/http09/runtime/socket_io_backend_test.cpp`
  - keep or reshape socket-backend coverage around the refactored core
- `build.zig`
  - compile new source files and link `liburing` on supported builds
- `flake.nix`
  - add `liburing` to the Linux development/build environment

## Testing Strategy

### Backend-Neutral Contract Coverage

The existing backend behavior should be tested through a backend-neutral contract
surface where practical:

- stable route handles per peer tuple
- send path uses the selected route handle
- multiple active sockets can deliver inbound datagrams
- explicit runtime backend selection reaches the requested implementation

These tests prove that both concrete backends honor the same semantics.

### `io_uring`-Specific Coverage

Add focused `io_uring` tests for behavior that is specific to the engine:

- ring initialization failure
- unsupported-platform rejection
- completion error translation
- receive re-arming after completion
- listener or route socket registration failure

### Runtime Coverage

Add runtime parsing and startup tests for:

- default backend remains `socket`
- `--io-backend=socket` parses
- `--io-backend=io_uring` parses
- invalid backend name is rejected
- explicit `io_uring` startup failure produces deterministic runtime failure

## Build And Environment Changes

The Linux development environment must provide `liburing`.

The build graph must:

- compile the new engine and shared backend core sources
- link `liburing` when building Linux targets that include the `io_uring` engine
- keep the default build usable without changing runtime behavior when
  `socket` remains selected

Because this repository is currently Linux-focused, the initial implementation
may guard `io_uring` compilation and tests with Linux checks rather than trying
to emulate support on other platforms.

## Why This Design

This design proves the generality of the existing backend boundary without
overreacting and turning the project into a plugin platform too early.

It keeps the runtime-facing transport contract small, factors shared UDP policy
into one place, and introduces a narrow engine seam that can support both the
existing poll-driven backend and a real `io_uring` backend.

That gives the repository:

- a real second backend
- less duplication than a copy-and-fork implementation
- explicit runtime selection
- a credible path toward more engines later

without committing to a public ABI that the project is not ready to support.
