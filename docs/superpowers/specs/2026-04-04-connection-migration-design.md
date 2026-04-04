# QUIC Connection Migration Design

## Status

Approved in conversation on 2026-04-04.

## Goal

Implement RFC-aligned QUIC connection migration in `coquic`, add the official
`rebind-port`, `rebind-addr`, and `connectionmigration` testcase names to the
repo-local interop surface, and extend the picoquic GitHub interop job to run
those cases.

The desired outcome is:

- the picoquic workflow job includes `rebind-port`, `rebind-addr`, and
  `connectionmigration`
- the repo-local interop wrapper accepts those testcase names
- `QuicCore` and `QuicConnection` own migration behavior rather than the
  HTTP/0.9 runtime
- the transport implements path validation with `PATH_CHALLENGE` and
  `PATH_RESPONSE`
- the transport implements peer and local connection ID lifecycle for
  migration, including `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID`
- the transport models `disable_active_migration` and `preferred_address`
- runtime/client behavior is sufficient to pass the picoquic official runner
  for `rebind-port`, `rebind-addr`, and `connectionmigration`

## Protocol Grounding

This design is grounded in RFC 9000:

- Section 5.1 and Section 5.1.1: connection IDs are the mechanism that makes
  migration and NAT rebinding possible, and `NEW_CONNECTION_ID` /
  `RETIRE_CONNECTION_ID` define the peer-visible connection ID lifecycle
- Section 8.2: path validation uses `PATH_CHALLENGE` and `PATH_RESPONSE`
- Section 9.3: on receipt of a non-probing packet from a new address, the peer
  treats that as apparent migration or rebinding, switches to the new path if
  allowed, and validates it
- Section 9.3.1 and Section 9.3.2: new paths must be anti-amplification-limited
  until validated and failed validation reverts to the last validated path
- Section 9.5: endpoints need spare connection IDs in order to support
  migration
- Section 9.6: the server `preferred_address` transport parameter is the
  standard mechanism for post-handshake client migration to a new server
  address
- Section 18.2: `disable_active_migration`, `preferred_address`, and
  `active_connection_id_limit` are transport parameters that affect migration
- Section 19.15, Section 19.16, Section 19.17, and Section 19.18 define
  `NEW_CONNECTION_ID`, `RETIRE_CONNECTION_ID`, `PATH_CHALLENGE`, and
  `PATH_RESPONSE`

## Runner Grounding

The checked-in official runner wrapper in
[run-official.sh](/home/minhu/projects/coquic/interop/run-official.sh) pins
the runner ref `97319f8c0be2bc0be67b025522a64c9231018d37`.

At this integration boundary:

- the official runner exposes testcase names `rebind-port`, `rebind-addr`, and
  `connectionmigration`
- this repo currently does not accept those names in
  [entrypoint.sh](/home/minhu/projects/coquic/interop/entrypoint.sh)
- the user-approved scope targets only the picoquic workflow job for these new
  cases

## Context

The repo already has a few migration-adjacent pieces:

- `src/quic/frame.h` and `src/quic/frame.cpp` already define and codec
  `NEW_CONNECTION_ID`, `RETIRE_CONNECTION_ID`, `PATH_CHALLENGE`, and
  `PATH_RESPONSE`
- `src/quic/transport_parameters.h` and
  `src/quic/transport_parameters.cpp` already support
  `active_connection_id_limit`
- `src/quic/connection.cpp` already has handshake-time peer address validation
  state for anti-amplification
- `src/quic/http09_runtime.cpp` already routes server packets by destination
  connection ID and updates the session peer address opportunistically

However, the current implementation is not connection migration:

- the transport parameter model does not include `disable_active_migration` or
  `preferred_address`
- `QuicConnection::process_inbound_application(...)` accepts
  `NewConnectionIdFrame` but ignores it, and it does not implement
  `PATH_CHALLENGE` or `PATH_RESPONSE`
- `QuicConnection` stores only a single peer connection ID and a single
  handshake validation boolean, not a path state machine or connection ID pool
- `QuicCore` moves only raw datagram bytes across the runtime boundary and has
  no notion of source path identity or outbound target path selection
- the client runtime assumes one resolved peer address for the lifetime of the
  connection

## Scope

This design covers:

- [.github/workflows/interop.yml](/home/minhu/projects/coquic/.github/workflows/interop.yml)
- [interop/entrypoint.sh](/home/minhu/projects/coquic/interop/entrypoint.sh)
- [interop/README.md](/home/minhu/projects/coquic/interop/README.md)
- [src/quic/transport_parameters.h](/home/minhu/projects/coquic/src/quic/transport_parameters.h)
- [src/quic/transport_parameters.cpp](/home/minhu/projects/coquic/src/quic/transport_parameters.cpp)
- [src/quic/core.h](/home/minhu/projects/coquic/src/quic/core.h)
- [src/quic/core.cpp](/home/minhu/projects/coquic/src/quic/core.cpp)
- [src/quic/connection.h](/home/minhu/projects/coquic/src/quic/connection.h)
- [src/quic/connection.cpp](/home/minhu/projects/coquic/src/quic/connection.cpp)
- [src/quic/http09_runtime.h](/home/minhu/projects/coquic/src/quic/http09_runtime.h)
- [src/quic/http09_runtime.cpp](/home/minhu/projects/coquic/src/quic/http09_runtime.cpp)
- [tests/quic_transport_parameters_test.cpp](/home/minhu/projects/coquic/tests/quic_transport_parameters_test.cpp)
- [tests/quic_core_test.cpp](/home/minhu/projects/coquic/tests/quic_core_test.cpp)
- [tests/quic_http09_runtime_test.cpp](/home/minhu/projects/coquic/tests/quic_http09_runtime_test.cpp)

## Non-Goals

- adding these migration testcases to the quic-go workflow job
- implementing multipath QUIC
- implementing arbitrary server-initiated active migration beyond
  `preferred_address`
- introducing peer-specific wrapper forks for picoquic
- changing the pinned official runner ref as part of this slice
- adding qlog, packet capture, or new external observability surfaces as part
  of the first migration implementation

## Approaches Considered

### 1. Testcase-Driven Minimum

Implement only the behavior needed to satisfy the three runner cases and stop
as soon as the picoquic matrix is green.

Pros:

- smallest code change
- fastest path to local interop verification

Cons:

- likely leaves the transport in a partially RFC-shaped state
- encourages runner-specific logic in the runtime
- would create rework when adding `preferred_address` and
  `disable_active_migration` semantics more generally

### 2. Core-Centric RFC Implementation

Implement migration as a transport feature owned by `QuicConnection`, with
`QuicCore` carrying path identity across the runtime boundary and
`http09_runtime` remaining a socket adapter plus testcase policy layer.

Pros:

- matches the user-approved architecture
- keeps protocol rules in the transport instead of in the runtime
- gives a coherent base for both the official runner cases and future migration
  coverage

Cons:

- larger first slice than a testcase-only patch
- requires widening the `QuicCore` I/O surface

### 3. Runtime-Owned Migration Shim

Keep `QuicConnection` mostly unchanged and implement path tracking, path
switching, and most migration logic in `http09_runtime.cpp`.

Pros:

- fewer changes in the transport immediately

Cons:

- wrong ownership boundary for the feature
- makes it much harder to unit-test protocol behavior without the runtime
- duplicates transport semantics outside the transport

## Decision

Use approach 2.

Connection migration is a transport feature and will be implemented as such.
`QuicConnection` owns path validation, migration state, and connection ID
lifecycle. `QuicCore` carries enough path metadata to let the runtime supply
source addresses and honor the transport-selected destination path.

## Decisions

### 1. Extend Only The Picoquic Workflow Job

Add `rebind-port`, `rebind-addr`, and `connectionmigration` only to the
picoquic job in
[interop.yml](/home/minhu/projects/coquic/.github/workflows/interop.yml).

The quic-go job remains unchanged.

Rationale:

- this matches the approved scope exactly
- it avoids binding this slice to a peer with different current support
  characteristics

### 2. Accept The New Testcase Names End-To-End Locally

Add `rebind-port`, `rebind-addr`, and `connectionmigration` to:

- [interop/entrypoint.sh](/home/minhu/projects/coquic/interop/entrypoint.sh)
- the HTTP/0.9 runtime testcase parser in
  [http09_runtime.cpp](/home/minhu/projects/coquic/src/quic/http09_runtime.cpp)
- the interop README documentation in
  [README.md](/home/minhu/projects/coquic/interop/README.md)

Rationale:

- direct local runs should accept the same names as the official runner
- testcase naming should not be hidden only inside CI configuration

### 3. Introduce Opaque Path Identity Into `QuicCore`

Add an opaque runtime-supplied path identifier to inbound datagrams and an
opaque transport-selected path identifier to outbound datagrams.

Concretely:

- `QuicCoreInboundDatagram` gains a `path_id` field
- `QuicCoreSendDatagram` gains an optional `path_id` field
- the runtime is responsible for mapping `sockaddr_storage` tuples to stable
  opaque path IDs for the lifetime of a connection or server session
- the transport compares path IDs only for identity and never interprets their
  binary contents

Rationale:

- `QuicConnection` needs a stable concept of "same path" versus "new path"
  without learning about socket structures
- this keeps socket details out of the transport while still giving the core
  ownership of migration semantics

### 4. Model Migration-Relevant Transport Parameters Explicitly

Extend `TransportParameters` with:

- `disable_active_migration`
- `preferred_address`

`preferred_address` will include:

- IPv4 address and port
- IPv6 address and port
- connection ID
- stateless reset token

Validation and serialization will follow RFC 9000 Section 18.2 rules,
including:

- server-only semantics for `preferred_address`
- zero-length value semantics for `disable_active_migration`
- non-zero connection ID requirements for `preferred_address`

Rationale:

- a transport cannot implement full migration semantics without these
  parameters
- picoquic `connectionmigration` requires the preferred-address path

### 5. Add Core-Owned Path State

`QuicConnection` will track:

- current send path
- last validated peer path
- active candidate path under validation
- the previously active path being revalidated after apparent migration
- queued `PATH_RESPONSE` frames scoped to the path where the challenge was
  received
- locally outstanding `PATH_CHALLENGE` data scoped to the path being validated

Each tracked path stores only transport-facing facts:

- opaque path ID
- validation state
- anti-amplification counters
- whether it is the current send path
- retry / timeout state for path validation

Rationale:

- migration needs more than one boolean
- the transport must be able to revert to the last validated path when
  validation of a new path fails

### 6. Add Peer And Local Connection ID Inventories

`QuicConnection` will replace the current single peer CID field with:

- peer destination CID inventory keyed by sequence number
- active peer CID selection for outbound packets
- locally issued source CID inventory keyed by sequence number
- retirement tracking for locally issued CIDs
- local replacement issuance to maintain a usable spare CID pool

Rules:

- `NEW_CONNECTION_ID` stores new peer CIDs, validates sequence ordering, and
  retires entries below `retire_prior_to`
- `RETIRE_CONNECTION_ID` retires locally issued CIDs and triggers replacement
  issuance whenever retirement would otherwise leave the peer without a spare
  usable CID below its advertised active limit
- the server issues spare CIDs after handshake so the peer can migrate
- the client uses a fresh peer CID when migrating to a preferred address or an
  actively migrated path

Rationale:

- rebinding can work without CID rotation in some deployments, but full
  connection migration cannot
- runner cases and RFC 9000 both expect CID support, not just tuple switching

### 7. Implement Inbound Migration Rules In The Transport

Inbound packet handling changes:

- same-path packets process normally
- a packet from a new path with only probing frames does not by itself switch
  the connection to that path
- a packet from a new path with any non-probing frame is treated as apparent
  rebinding or migration
- if migration is permitted, the transport switches the current send path to
  the new path, initiates path validation if necessary, and anti-amplification
  limits sends on that path until validation succeeds
- the previously active path is also probed after apparent migration to defend
  against spurious migration
- if the new-path validation fails, the transport reverts to the last
  validated path

Rationale:

- this matches RFC 9000 Sections 9.3, 9.3.1, 9.3.2, and 9.3.3

### 8. Implement `PATH_CHALLENGE` And `PATH_RESPONSE` Fully

`QuicConnection` will:

- respond immediately to `PATH_CHALLENGE` on the same path with a matching
  `PATH_RESPONSE`
- generate unpredictable challenge payloads for locally initiated validation
- associate outstanding challenge bytes with the exact path being validated
- mark a path validated only when a matching `PATH_RESPONSE` arrives for a
  locally issued challenge
- pad validation datagrams when RFC 9000 requires it

Rationale:

- frame codecs already exist, but full path validation logic is currently
  missing

### 9. Respect `disable_active_migration` As Policy, Not As A Codec Detail

The peer's `disable_active_migration` transport parameter will change transport
policy:

- the endpoint must not initiate active migration away from the handshake path
- passive reaction to the peer's apparent migration or NAT rebinding still
  occurs where RFC 9000 allows it
- `preferred_address` migration remains allowed as defined by RFC 9000 even if
  `disable_active_migration` is present on the handshake path

Rationale:

- this is the behavior RFC 9000 requires
- it keeps migration permission checks concentrated in the transport

### 10. Preferred-Address Migration Is Client-Driven And Testcase-Scoped In Runtime

The runtime will not implement generic path policy. It only supplies testcase
intent:

- for the `connectionmigration` testcase, the server runtime configures a
  preferred address
- once the client transport reports handshake readiness and the preferred
  address is available, the client runtime requests active migration through
  the core

The transport still decides when the migration is legal and how it proceeds.

Rationale:

- `preferred_address` is transport state, but choosing to exercise it for a
  specific interop testcase is runtime policy
- this keeps unrelated testcases unchanged

### 11. Runtime Remains A Socket Adapter With Stable Session Routing

`http09_runtime.cpp` changes are limited to:

- mapping inbound `sockaddr_storage` tuples to stable opaque path IDs
- preserving multiple known peer tuples for one server session
- sending outbound datagrams to the path selected by `QuicCoreSendDatagram`
  instead of always reusing the last observed tuple
- exposing testcase-driven preferred-address configuration for the server

Rationale:

- server session lookup still uses connection IDs first
- runtime should route packets; transport should decide where the connection
  wants to send

## Architecture

### Transport Parameter Layer

The transport parameter codec becomes the single source of truth for migration
policy inputs:

- parse and serialize `disable_active_migration`
- parse, serialize, and validate `preferred_address`
- preserve existing `active_connection_id_limit` handling

### Core I/O Layer

`QuicCore` becomes path-aware but not socket-aware:

- inbound datagrams carry bytes plus opaque path identity
- outbound datagrams carry bytes plus the chosen path identity
- higher-level stream and timer APIs remain unchanged

### Connection Layer

`QuicConnection` owns:

- peer and local CID state
- current and validated path state
- migration permission checks
- path validation frame production and consumption
- migration-triggered path switching and revert-on-failure behavior

### Runtime Layer

The runtime owns:

- socket address resolution
- session maps
- path-ID-to-`sockaddr_storage` mapping
- testcase-specific preferred-address configuration

It does not own:

- CID policy
- migration legality rules
- path validation logic

## Error Handling

Transport errors should fail fast on invalid migration semantics, including:

- malformed or invalid `preferred_address`
- invalid `NEW_CONNECTION_ID` sequence or retirement semantics
- duplicate or contradictory peer CID inventory updates
- path validation state corruption

Validation failure of a new path is not itself a fatal error when a last
validated path exists; the transport reverts to the last validated path instead.

If no validated path remains when a migration attempt fails, the transport may
need to fail the connection or discard state according to the path and packet
context.

## Testing

### Unit Tests

Add transport parameter tests for:

- `disable_active_migration` round-trip and validation
- `preferred_address` round-trip and validation

Add `QuicConnection` tests for:

- `NEW_CONNECTION_ID` storage and retirement behavior
- `RETIRE_CONNECTION_ID` processing and replacement issuance
- sending `PATH_RESPONSE` on receipt of `PATH_CHALLENGE`
- path validation success on matching `PATH_RESPONSE`
- rebinding detection from new-path non-probing packets
- anti-amplification limits on unvalidated migrated paths
- revert-to-last-validated-path behavior when validation fails
- active migration blocked by `disable_active_migration`
- preferred-address migration flow

Add runtime tests for:

- server session continuity across peer tuple changes
- runtime honoring transport-selected outbound path IDs
- testcase parsing for `rebind-port`, `rebind-addr`, and `connectionmigration`
- preferred-address testcase configuration

### Interop Verification

After the transport and runtime tests pass:

- extend the picoquic workflow testcase list
- run targeted local official-runner verification against picoquic for:
  - `rebind-port`
  - `rebind-addr`
  - `connectionmigration`
- keep the quic-go official-runner coverage unchanged

### Regression Verification

After migration stabilizes:

- run `nix develop -c zig build test`
- run `nix develop -c zig build coverage`
- run the targeted picoquic interop subset locally

## Risks

### 1. Path Identity Can Leak Runtime Concerns Into The Transport

This is mitigated by using opaque path IDs instead of exposing socket structs
to the core.

### 2. CID Rotation And Path Switching Can Break Existing Non-Migration Flows

This is mitigated by:

- keeping new testcase activation runtime-driven
- building unit tests before each production slice
- preserving quic-go workflow behavior untouched

### 3. Preferred Address Adds A Wider Surface Than The Runner Cases Alone

This is intentional. The user approved full RFC-surface migration support
instead of a testcase-only patch. The implementation still remains bounded to
single-path migration, not multipath.
