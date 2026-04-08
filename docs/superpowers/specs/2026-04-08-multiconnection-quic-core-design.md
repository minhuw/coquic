# Multi-Connection QUIC Core Redesign

Date: 2026-04-08
Repo: `coquic`
Status: Approved

## Summary

Redesign `QuicCore` from a single-connection adapter into a multi-connection,
I/O-agnostic transport endpoint that owns many `QuicConnection` instances.

Under the new model:

- `QuicCore` manages endpoint-scoped transport concerns
- `QuicConnection` remains the single-connection transport state machine
- real I/O remains outside transport code
- HTTP/0.9 and future HTTP/3 sit above `QuicCore` and track per-connection
  application state using stable connection handles

This redesign fixes the current boundary problem where generic QUIC endpoint
logic is mixed into the HTTP/0.9 runtime.

## Problem

The current repository has three different kinds of logic interleaved in the
HTTP/0.9 runtime:

- HTTP/0.9 application behavior
- generic QUIC endpoint behavior
- real process and socket I/O behavior

The generic QUIC endpoint behavior includes:

- CID-based routing to the right connection
- server-side Retry and version-negotiation prerouting
- timer aggregation across connections
- path bookkeeping that maps inbound peers to `QuicPathId`
- tracking active local connection IDs for server session routing

Those responsibilities do not belong to HTTP/0.9. They also do not belong to
the current single-connection `QuicConnection` state machine.

At the same time, the current public `QuicCore` type is named too broadly for
what it actually is: a single-connection wrapper around one `QuicConnection`.

## Goals

- Make `QuicCore` the true endpoint-scoped QUIC transport manager.
- Keep `QuicConnection` as the single-connection transport state machine.
- Move generic QUIC endpoint logic out of the HTTP/0.9 runtime.
- Keep transport code I/O-agnostic so different backends can be used later
  (`epoll`, `io_uring`, DPDK, AF_XDP, test backends).
- Preserve a clean boundary between transport and application layers.
- Prepare the repository for both HTTP/0.9 and HTTP/3 on top of the same
  transport endpoint.

## Non-Goals

- Do not make `QuicCore` own sockets, polling, binds, address resolution, or
  any other real I/O backend behavior.
- Do not introduce an intermediate connector layer between `QuicCore` and
  `QuicConnection`.
- Do not merge HTTP/0.9 or HTTP/3 application semantics into transport code.
- Do not optimize for compatibility with the current single-connection
  `QuicCore` API; temporary breakage during migration is acceptable.

## Core Model

### `QuicCore`

`QuicCore` becomes the multi-connection transport endpoint.

It owns:

- the live connection table
- connection-handle allocation and lifecycle
- CID-based routing for inbound datagrams
- server-side Retry and version-negotiation prerouting
- dispatch of transport commands to the correct `QuicConnection`
- timer scheduling and aggregation across connections
- path-route bookkeeping for each live connection
- draining outbound datagrams and transport events from all live connections

It does not own:

- sockets
- polling
- address resolution
- filesystem access
- HTTP/0.9 or HTTP/3 behavior

### `QuicConnection`

`QuicConnection` remains the single-connection transport state machine.

It keeps responsibility for:

- handshake and TLS state
- packet parsing and generation
- stream state
- recovery and congestion control
- ECN state
- migration and path validation state
- local and peer connection ID state
- connection-scoped transport effects

## Two-Level Transport Abstraction

The transport model is intentionally only two levels:

- `QuicCore`
- `QuicConnection`

No intermediate `QuicConnectionConnector` or similar layer is introduced.

If transport-to-application adaptation is needed, that adaptation belongs in
application code or runtime code above `QuicCore`, not between `QuicCore` and
`QuicConnection`.

## Application Boundary

Applications no longer own one transport core per connection.

Instead:

- `QuicCore` owns all transport connections
- applications own per-connection application state keyed by a stable
  connection handle
- applications react to `QuicCore` events and submit connection-scoped commands
  back into `QuicCore`

This keeps application logic independent from:

- wire CIDs
- socket routing
- Retry and version-negotiation handling
- endpoint-wide timer driving

## Connection Identity

The redesign must distinguish three identities:

1. Connection handle
   - stable internal identity used by application layers and runtimes
   - not transmitted on the wire

2. Wire connection IDs
   - transport-visible CIDs used for packet routing and migration

3. Path identity
   - transport-visible `QuicPathId` used within a single connection

These identities must not be conflated.

Applications should work in terms of connection handles, not wire CIDs.

## Input And Effect Direction

The current single-connection `QuicCore` API cannot be preserved because it
implicitly assumes exactly one connection.

The new endpoint-scoped direction should be:

### Inputs to `QuicCore`

- inbound datagram from some peer identity
- app command for a specific connection handle
- timer-driving input
- explicit client-open input for locally initiated connections

### Effects from `QuicCore`

- outbound datagram with enough metadata for an external I/O layer to send it
- connection lifecycle effects
  - created
  - accepted
  - handshake ready
  - handshake confirmed
  - failed
  - closed
- connection-scoped transport effects
  - stream data
  - peer reset
  - peer stop-sending
  - preferred address available
  - resumption state available
  - zero-RTT status

All connection-scoped effects must carry a stable connection handle.

## Retry And Version Negotiation

### Client Side

Client-side Retry and version-negotiation handling currently performed in the
single-connection `QuicCore` should move into the connection-management logic of
the new multi-connection `QuicCore`.

### Server Side

Server-side Retry and version-negotiation prerouting currently stranded in the
HTTP/0.9 runtime should move into the new multi-connection `QuicCore`.

This keeps all QUIC transport endpoint routing and handshake pre-processing in
one place.

## Path And CID Routing

The new `QuicCore` owns endpoint-scoped routing logic:

- map inbound datagrams to the right live connection using CID routing
- maintain routing updates when active local connection IDs change
- maintain path-route state for each connection
- map inbound peer identity to stable `QuicPathId` values per connection
- map outbound `QuicPathId` back to abstract route metadata in effects

This routing is transport logic, not application logic.

## I/O Boundary

Real I/O remains outside `QuicCore`.

External runtime or backend code is responsible for:

- sockets
- bind/listen/connect setup
- polling and wakeups
- address resolution
- OS-specific send and receive APIs
- backend-specific batching strategies

That external layer converts:

- real inbound datagrams into `QuicCore` inputs
- `QuicCore` outbound datagram effects into real sends
- `QuicCore` wakeup needs into backend timer registration

This preserves the ability to support multiple I/O backends later.

## Source Tree Layout

The long-term source layout should reflect the new boundaries:

- `src/quic/`
  - transport only
  - `core.*`
  - `connection.*`
  - packets, streams, recovery, transport parameters, qlog, crypto
- `src/apps/http09/`
  - HTTP/0.9 application behavior
  - request parsing
  - file serving
  - zero-RTT application context
  - per-connection app state management above `QuicCore`
- `src/apps/http3/`
  - future HTTP/3 application behavior
- `src/runtime/`
  - CLI wiring
  - environment and argument parsing
  - socket integration
  - backend adapters

The redesign should not begin with file moves. Physical file reorganization
should follow once the semantic boundaries are implemented.

## Migration Strategy

Temporary breakage during the refactor is acceptable. The preferred migration
order is semantic first:

1. Redefine `QuicCore` as a multi-connection transport endpoint.
2. Move endpoint-scoped routing responsibilities into it:
   - CID routing
   - Retry prerouting
   - version-negotiation prerouting
   - timer aggregation
   - path bookkeeping
3. Change transport inputs and effects to be endpoint-scoped and
   connection-handle-tagged.
4. Rewrite HTTP/0.9 to consume the new `QuicCore` API and manage app state
   keyed by connection handle.
5. Split runtime and application files into new directories after the semantic
   model is stable.

Do not start by shuffling files before the transport model is corrected.

## Testing Strategy

Testing should align with the new boundaries:

### `src/quic/` transport tests

- CID routing across multiple live connections
- Retry and version-negotiation prerouting
- connection creation and teardown
- timer aggregation
- path assignment and route stability
- active local connection ID route updates

### `QuicConnection` tests

- single-connection transport behavior
- streams
- recovery
- migration
- ECN
- transport parameters

### application tests

- HTTP/0.9 behavior above connection handles
- later HTTP/3 behavior above connection handles

### runtime/backend tests

- socket and polling integration
- CLI/env parsing
- backend-specific behavior

Tests that require real socket state, filesystem-heavy runtime behavior, or
interop harness behavior should not be the primary way `src/quic/` transport is
validated.

## Main Risk

The main risk is moving too much runtime responsibility into transport and
recreating the same boundary problem under a different name.

The design avoids that by keeping `QuicCore`:

- multi-connection
- transport-only
- I/O-agnostic
- application-agnostic

## Acceptance Criteria

- `QuicCore` manages multiple live `QuicConnection` instances.
- endpoint-scoped CID routing is owned by `QuicCore`.
- server-side Retry and version-negotiation prerouting are owned by `QuicCore`.
- `QuicCore` remains I/O-agnostic.
- `QuicConnection` remains the single-connection transport state machine.
- application layers interact with transport through stable connection handles.
- HTTP/0.9 no longer owns generic QUIC endpoint routing logic.
- source layout can be reorganized cleanly along transport, application, and
  runtime boundaries after the semantic redesign lands.
