# QUIC 0-RTT First-Class API Design

## Status

Approved in conversation on 2026-03-28.

## Context

`coquic` currently supports:

- QUIC v1 and QUIC v2 handshakes
- HTTP/0.9 interop runtime paths for handshake, transfer, multiconnect,
  chacha20, retry, and v2
- transport-parameter validation and compatible version negotiation
- parsing and serialization of the QUIC `NEW_TOKEN` frame

`coquic` does not currently support:

- interop `resumption` or `zerortt` testcases
- TLS session ticket capture and reuse
- client PSK resumption attempts
- QUIC 0-RTT packet protection and transmission
- server-side 0-RTT accept/reject policy
- an application-facing API for resumption or early data

The current interop failure for `resumption` is immediate and local:

- [interop/entrypoint.sh](/home/minhu/projects/coquic/interop/entrypoint.sh)
  rejects `TESTCASE=resumption`
- [src/quic/http09.h](/home/minhu/projects/coquic/src/quic/http09.h) has no
  `resumption` testcase enum
- [src/quic/http09_runtime.cpp](/home/minhu/projects/coquic/src/quic/http09_runtime.cpp)
  has no testcase parser or runtime behavior for resumption

The user wants broader reusable support as a first-class API, not only a narrow
interop patch.

Relevant protocol requirements:

- RFC 9001 Section 4.6 defines QUIC 0-RTT and requires remembered state from a
  previous connection
- RFC 9001 Section 4.6.1 defines the QUIC use of TLS session tickets and the
  early-data sentinel value in `NewSessionTicket`
- RFC 9001 Section 4.6.3 requires QUIC and the application to validate current
  configuration before accepting 0-RTT
- RFC 9002 Section 6.4 requires endpoints to discard recovery state for all
  rejected 0-RTT packets
- RFC 9369 Section 5 requires session tickets and tokens to be scoped to the
  negotiated QUIC version

## Goal

Implement reusable first-class 0-RTT support so that:

- applications can persist opaque resumption artifacts produced by `coquic`
- applications can supply stored resumption artifacts on later client
  connections
- applications can attempt client early data through the public QUIC API
- servers can make explicit accept/reject decisions for 0-RTT based on QUIC and
  application compatibility
- rejected 0-RTT cleanly falls back to 1-RTT without corrupting connection
  state
- the HTTP/0.9 runtime can consume the same public API to unlock interop
  `resumption` and later `zerortt`

## Non-Goals

- exposing raw `SSL_SESSION *` or other TLS-backend-native handles in the public
  API
- building a server-managed built-in session cache as the primary API
- introducing durable storage format guarantees beyond opaque application-owned
  persistence
- implementing retry-token persistence as part of this slice
- defining replay protection for arbitrary application semantics beyond making
  the 0-RTT replay risk explicit and application-controlled
- shipping a fully generic ticket key rotation and distributed stateless ticket
  service in the first pass

## Decisions

### 1. Make 0-RTT A QUIC-Owned API, Not A TLS-Owned API

The public API will be shaped around QUIC concepts:

- opaque `ResumptionState`
- client-side 0-RTT attempt configuration
- server-side 0-RTT accept/reject policy
- explicit outcome reporting

TLS adapters remain responsible for backend-specific session ticket, PSK, and
early-data mechanics, but those details remain internal.

### 2. Build The Minimum Resumption Substrate Needed To Support 0-RTT First

QUIC 0-RTT cannot exist without a prior ticket-based resumption path. However,
the first product surface is 0-RTT, not "generic TLS resumption" as an
independent feature.

This slice therefore includes:

- ticket capture
- ticket restore for client PSK attempts
- remembered QUIC/application compatibility state
- 0-RTT acceptance and rejection handling

This slice does not need a separate user-facing 1-RTT-only resumption mode.

### 3. Application Owns Persistence

Applications receive opaque serialized resumption artifacts and are responsible
for storing and reloading them.

This keeps:

- storage lifetime policy outside the transport stack
- file/database choice outside `coquic`
- future runtime and library users on the same API surface

It also avoids prematurely baking in an internal cache that would later be hard
to remove.

### 4. QUIC Owns Compatibility Validation

The QUIC stack, not only TLS, must decide whether 0-RTT can be accepted.

Remembered validation state must include at least:

- QUIC version scope
- application protocol identity
- transport parameters that constrain 0-RTT behavior
- application-provided compatibility state blob

If TLS would otherwise resume but QUIC or the application rejects compatibility,
the handshake can continue while 0-RTT is rejected.

### 5. 0-RTT Outcome Must Be Explicit

Applications need to distinguish:

- resumption unavailable
- resumption attempted but 0-RTT not attempted
- 0-RTT attempted and accepted
- 0-RTT attempted and rejected

This is necessary for correct replay-sensitive application behavior and for
clean retransmission semantics.

### 6. Rejected 0-RTT Must Be Retransmitted As 1-RTT Data

Client-side early writes that are encoded into 0-RTT packets remain logically
pending until acceptance is known. If 0-RTT is rejected:

- 0-RTT packet recovery state is discarded
- affected application writes are requeued
- retransmission occurs only in 1-RTT packets

This follows RFC 9002 Section 6.4 and avoids exposing silent data loss to the
application.

### 7. First Runtime Consumer Uses Safe HTTP/0.9 GET Semantics

The first consumer of the public API in the HTTP/0.9 runtime should restrict
itself to replay-tolerant client GET-style requests.

That restriction belongs to the runtime consumer, not the generic core API. The
generic API still supports application-owned policy and data submission.

## Architecture

### Public API Layer

Extend [src/quic/core.h](/home/minhu/projects/coquic/src/quic/core.h) with
first-class types such as:

- `QuicResumptionState`
- `QuicZeroRttConfig`
- `QuicZeroRttStatus`
- `QuicCoreStateChange` additions for resumption/0-RTT outcomes

`QuicCoreConfig` gains optional fields for:

- previously stored resumption state on the client
- application compatibility blob
- server-side policy for whether 0-RTT is allowed

The application submits early data through the same `QuicCore` surface rather
than by reaching into TLS internals.

### TLS Adapter Backend Layer

Extend [src/quic/tls_adapter.h](/home/minhu/projects/coquic/src/quic/tls_adapter.h)
with QUIC-shaped methods for:

- installing an opaque prior resumption artifact on the client
- exporting newly issued resumption artifacts after handshake completion
- indicating whether early data was attempted
- indicating whether early data was accepted or rejected

The concrete quictls and BoringSSL implementations translate these operations
to:

- session ticket capture
- PSK resumption setup
- TLS early-data negotiation state

### QUIC Resumption Validation Layer

`QuicConnection` stores remembered validation state from a completed connection
and validates it on a future connection before 0-RTT is accepted.

This layer compares current connection config with remembered state:

- version compatibility
- application protocol
- transport parameters relevant to 0-RTT
- application compatibility blob

If validation fails, the connection rejects 0-RTT and proceeds without early
data when possible.

### 0-RTT Packet/Data Handling Layer

Client-side:

- early writes are tracked separately from fully committed 1-RTT writes
- eligible early writes are encoded into 0-RTT protected packets once early
  keys are available
- rejection returns those writes to the normal send path

Server-side:

- received 0-RTT stream data is held behind policy/acceptance state
- accepted early data is surfaced to the application
- rejected early data is discarded and not surfaced

### Runtime And Interop Consumer Layer

The HTTP/0.9 runtime consumes the public API in a narrow way:

- first connection captures resumption state
- next connection reuses it
- runtime attempts early GET requests only
- rejection transparently falls back to normal 1-RTT transfer

Interop testcase enablement is a follow-on consumer change after the library API
and core behavior are correct.

## Components

### 1. Resumption State Model

Introduce an opaque serialized resumption artifact that contains enough
information for `coquic` to restore:

- TLS resumption identity
- negotiated QUIC version scope
- remembered transport/application compatibility state

The serialized format is internal to `coquic`. Applications treat it as opaque
bytes.

### 2. 0-RTT Policy Model

Introduce explicit policy knobs:

- client: whether to attempt 0-RTT when resumption state is present
- server: whether 0-RTT is allowed for this endpoint
- application: compatibility blob and replay-sensitive acceptance policy

These knobs must be available without forcing users through the HTTP/0.9
runtime.

### 3. TLS Ticket Capture And Restore

Add backend-private TLS logic for:

- capturing newly issued session tickets after handshake completion
- restoring a prior ticket/session before a client handshake
- querying early-data negotiation status

This is required in both TLS adapter backends to keep feature parity.

### 4. Connection-Level Early Data Tracking

Add connection state for:

- pending early writes
- whether 0-RTT was attempted
- whether 0-RTT was accepted or rejected
- whether early writes need retransmission as 1-RTT

This state must remain isolated from normal stream send bookkeeping so rejection
does not corrupt ordinary retransmission logic.

### 5. Runtime Consumer Support

Add a runtime testcase and helper path that exercises:

- first connection state capture
- second connection early GET attempt
- clean fallback on rejection

This provides a concrete end-to-end consumer without becoming the primary API
shape.

## Data Flow

### Client Path

1. A normal connection completes.
2. TLS emits session ticket material.
3. QUIC combines that with version, transport, and application compatibility
   state into an opaque `QuicResumptionState`.
4. The application persists that state.
5. A later client connection is configured with the stored state and optional
   early writes.
6. TLS attempts PSK resumption and exposes early-data capability.
7. QUIC sends eligible writes in 0-RTT packets.
8. If 0-RTT is accepted, the writes stand.
9. If 0-RTT is rejected, QUIC discards 0-RTT recovery state and retransmits the
   logical writes as 1-RTT data.

### Server Path

1. Server receives a `ClientHello` with resumption and early-data intent.
2. TLS validates the ticket/session cryptographically.
3. QUIC validates remembered version/transport/application compatibility.
4. Server policy decides whether early data is allowed for this endpoint.
5. If all checks pass, 0-RTT is accepted and buffered early data is surfaced.
6. If any QUIC/application check fails, 0-RTT is rejected while the handshake
   can continue.
7. If ticket validation fails completely, the connection falls back to a full
   handshake.

### Ownership Boundaries

- application owns persistence and replay-sensitive usage decisions
- QUIC owns compatibility validation and retransmission semantics
- TLS backend owns raw ticket/session primitives
- runtime is only one consumer of the public API

## Error Handling

- malformed or stale resumption state on the client is non-fatal and falls back
  to a normal handshake
- version-scoped ticket mismatch rejects 0-RTT and resumption for that attempt
- server-side compatibility rejection rejects only early data when possible
- rejected 0-RTT data is never surfaced as committed application input
- loss recovery discards rejected 0-RTT packet state
- applications receive explicit outcome signals so replay-sensitive code can act
  safely

## Testing

### Unit Tests

- TLS adapter tests for ticket export/import
- TLS adapter tests for early-data attempted, accepted, and rejected states
- QUIC connection tests for resumption artifact issuance
- QUIC connection tests for client 0-RTT packet emission
- QUIC connection tests for server 0-RTT accept path
- QUIC connection tests for server 0-RTT reject path
- QUIC connection tests for version mismatch rejection
- QUIC connection tests for transport/application incompatibility rejection
- QUIC connection tests for retransmission of rejected early writes as 1-RTT

### Runtime Tests

- two-connection runtime flow that stores state then attempts early GETs
- fallback path where 0-RTT is rejected but transfer still succeeds

### Interop Verification

After the library and runtime slices land:

- official `resumption` interop should pass
- official `zerortt` interop should be evaluated and enabled if supported by the
  pinned peers

## Risks And Tradeoffs

- 0-RTT replay semantics are application-sensitive; the API must make that risk
  visible instead of hiding it
- exposing too much TLS detail would make backend parity harder to maintain
- storing too little remembered compatibility state would create silent 0-RTT
  acceptance bugs
- storing too much policy in the core would make the API harder to use and
  harder to keep stable

The chosen design accepts slightly more upfront plumbing in exchange for a
cleaner long-term API boundary.
