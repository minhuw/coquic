# HTTP/3 Minimal Support Design

Date: 2026-04-06
Repo: `coquic`
Status: Approved

## Summary

Add a parallel HTTP/3 implementation to `coquic` that supports both client and
server operation, while preserving the existing HTTP/0.9 interop harness.

The first milestone targets a real but narrow HTTP/3 subset that is sufficient
for browser-playable experimentation and direct tool testing:

- `h3` ALPN over QUIC
- client and server HTTP/3 control streams
- HTTP/3 `SETTINGS`
- request/response streams using `HEADERS`, `DATA`, and trailing `HEADERS`
- basic `GOAWAY` support
- strict HTTP/3 message validation
- QPACK with a zero-dynamic-table profile

The initial implementation explicitly excludes server push, CONNECT, extended
CONNECT, priority signaling, WebTransport, H3 DATAGRAM, and dynamic QPACK table
insertion.

## Goals

- Support both HTTP/3 client and HTTP/3 server behavior in this repository.
- Keep `http09` intact for QUIC interop and existing CI coverage.
- Reach a protocol-correct HTTP/3 baseline that can interoperate with browsers
  and tools once certificate trust and discovery are configured.
- Keep the HTTP/3 protocol core separate from runtime/socket glue and separate
  from the existing HTTP/0.9 logic.

## Non-Goals

- Do not replace or heavily refactor `http09` as part of phase 1.
- Do not implement server push, CONNECT, priority extensions, WebTransport, or
  H3 DATAGRAM in phase 1.
- Do not make dynamic QPACK compression a milestone-1 requirement.
- Do not make TCP bootstrap or Alt-Svc advertisement part of the first protocol
  implementation.

## Why A Parallel HTTP/3 Stack

The current repository only contains `http09` application layers and runtimes:

- `src/quic/http09.*`
- `src/quic/http09_client.*`
- `src/quic/http09_server.*`
- `src/quic/http09_runtime.*`

That stack is intentionally narrow and interop-runner-focused. HTTP/3 is not a
small extension of HTTP/0.9; it requires its own stream taxonomy, frame model,
message validation, `SETTINGS`, control streams, and QPACK. Trying to evolve
`http09` into HTTP/3 would couple test harness logic to protocol semantics and
would make both paths harder to reason about.

The recommended direction is therefore:

- keep `http09` unchanged for interop use
- add a parallel `http3` implementation
- extract shared helpers only after the HTTP/3 path is stable

## Protocol Grounding

The design follows the local RFC corpus in `docs/rfc/`, especially:

- RFC 9114 Section 3.2: HTTP/3 support is negotiated using ALPN token `h3`
- RFC 9114 Section 6.1: client-initiated bidirectional streams are request
  streams
- RFC 9114 Section 6.2 and Section 6.2.1: each side needs the HTTP control
  stream and enough unidirectional stream capacity for mandatory streams
- RFC 9114 Section 7.2.4: `SETTINGS` must be the first frame on each control
  stream and must not appear elsewhere
- RFC 9114 Section 4.1: request/response stream framing rules
- RFC 9114 Section 4.1.2, Section 4.2, Section 4.3, Section 4.3.1, and Section
  4.3.2: malformed-message handling, field rules, and pseudo-header rules
- RFC 9204 Section 4.2: QPACK encoder and decoder streams
- RFC 9204 Section 5: QPACK settings

Browser discovery is distinct from the HTTP/3 wire protocol:

- RFC 9114 Section 3.1 and Section 3.1.1 describe discovering an HTTP/3
  endpoint and advertising it via `Alt-Svc`

## Scope Of Milestone 1

### In Scope

- QUIC + TLS with ALPN `h3`
- HTTP/3 client and server runtimes
- one control stream per side
- one QPACK encoder stream per side
- one QPACK decoder stream per side
- request/response transaction handling on request streams
- `HEADERS`, `DATA`, and trailing `HEADERS`
- `SETTINGS`
- `GOAWAY`
- strict message and frame validation
- static-file HTTP/3 server behavior
- direct HTTP/3 client behavior for repository-side testing
- qlog compatibility at the QUIC layer, with optional later HTTP/3 qlog work

### Out Of Scope

- server push
- `PUSH_PROMISE`, `MAX_PUSH_ID`, `CANCEL_PUSH`
- CONNECT and extended CONNECT
- prioritization
- WebTransport
- H3 DATAGRAM
- dynamic QPACK table insertion
- HTTP/3 0-RTT request replay support
- in-repo TCP Alt-Svc bootstrap server in milestone 1

## Proposed Module Layout

Add a parallel HTTP/3 stack under `src/quic/`:

- `http3.h`
- `http3_protocol.h` / `http3_protocol.cpp`
- `http3_qpack.h` / `http3_qpack.cpp`
- `http3_client.h` / `http3_client.cpp`
- `http3_server.h` / `http3_server.cpp`
- `http3_runtime.h` / `http3_runtime.cpp`
- `http3_runtime_test_hooks.h`

Expected responsibilities:

- `http3_protocol.*`
  - HTTP/3 stream types
  - frame parsing and serialization
  - `SETTINGS`, `GOAWAY`, error mapping
  - connection-scoped protocol state
- `http3_qpack.*`
  - field section encoding and decoding
  - static-table-only milestone-1 profile
  - QPACK encoder/decoder stream instruction handling
- `http3_client.*`
  - request issuance
  - response collection and validation
  - client-side transaction state machines
- `http3_server.*`
  - request parsing and validation
  - static-file serving behavior
  - server-side transaction state machines
- `http3_runtime.*`
  - CLI/runtime parsing
  - socket loop integration
  - environment/config wiring

## Connection Model

Introduce an HTTP/3 connection context above `QuicCore`, conceptually:

- local settings
- remote settings
- local control stream ID
- remote control stream ID
- local QPACK encoder stream ID
- local QPACK decoder stream ID
- remote QPACK encoder stream ID
- remote QPACK decoder stream ID
- GOAWAY state
- request stream state map

This should remain connection-scoped and separate from runtime-specific socket
details.

## Mandatory Streams And Startup Behavior

At the start of an HTTP/3 connection, each endpoint should create:

- one unidirectional control stream with type `0x00`
- one unidirectional QPACK encoder stream with type `0x02`
- one unidirectional QPACK decoder stream with type `0x03`

The first frame on the control stream must be `SETTINGS`. Violations are
connection errors, such as:

- `H3_MISSING_SETTINGS`
- `H3_STREAM_CREATION_ERROR`
- `H3_CLOSED_CRITICAL_STREAM`
- `H3_FRAME_UNEXPECTED`

Transport configuration for HTTP/3 should allow peers to open at least the
mandatory unidirectional streams without backpressure.

## QPACK Strategy For Phase 1

Milestone 1 uses a zero-dynamic-table profile:

- advertise `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`
- advertise `SETTINGS_QPACK_BLOCKED_STREAMS = 0`
- do not insert dynamic entries
- encode field sections using static-table references and literals only

This preserves protocol correctness while avoiding the hardest parts of QPACK
state synchronization in the first milestone.

Even with the dynamic table disabled, the implementation still keeps the QPACK
layer explicit and still creates the required encoder and decoder streams so
later dynamic-table support can be added without changing the upper API.

## Request/Response Model

All client-initiated bidirectional streams are treated as request streams.

A request stream carries:

1. one initial `HEADERS` frame containing the request header section
2. zero or more `DATA` frames containing content
3. optionally one trailing `HEADERS` frame containing trailers

Response handling follows the same framing model, except a server may send zero
or more interim responses before one final response.

Invalid frame ordering is treated strictly. Examples:

- `DATA` before initial `HEADERS`
- `HEADERS` after trailing `HEADERS`
- extra response after a final response

These are treated as protocol errors according to RFC 9114 Section 4.1.

## HTTP Message Validation Rules

Milestone 1 should be strict rather than permissive.

### Request Pseudo-Headers

Require the standard request pseudo-headers for non-CONNECT requests:

- `:method`
- `:scheme`
- `:path`

For schemes with mandatory authority, require `:authority` or `Host`, and if
both are present they must match.

### Response Pseudo-Headers

Require exactly one:

- `:status`

### General Header Rules

- pseudo-headers must precede regular headers
- pseudo-headers must not appear in trailers
- uppercase field names are malformed
- connection-specific headers are malformed
- `TE`, if present on requests, must be `trailers`
- `content-length` must match the sum of received `DATA` lengths when content
  is defined

Malformed requests and responses should map to `H3_MESSAGE_ERROR` where
appropriate.

## Application-Facing API

The HTTP/3 application layer should be message-oriented, not frame-oriented.

Suggested shared types:

- `Http3Field`
- `Http3Headers`
- `Http3RequestHead`
- `Http3ResponseHead`
- `Http3BodyChunk`

Suggested protocol-to-endpoint events:

- request head received
- request body chunk received
- request completed
- response head received
- response body chunk received
- response completed

This keeps QPACK and frame parsing internal to the protocol layer.

## Server Behavior

Milestone-1 server behavior is intentionally simple:

- static file serving from a document root
- produce real HTTP status codes and headers
- support common content types
- support `GET` first
- allow extension to request bodies later without redesign

The server should not reuse raw HTTP/0.9 semantics. It should emit proper
HTTP/3 response headers and body framing.

## Client Behavior

Milestone-1 client behavior should support:

- direct HTTP/3 requests from CLI/runtime
- certificate validation and SNI
- response header parsing
- response body streaming to files or stdout-like sinks later

The client API should be structured, even if the CLI initially accepts simple
inputs like `GET https://host/path`.

## Runtime And CLI Design

Do not keep `src/main.cpp` hard-wired to the HTTP/0.9 runtime.

Instead:

- preserve existing `interop-server` and `interop-client` behavior
- add new subcommands:
  - `h3-server`
  - `h3-client`
- route those subcommands through separate runtime config parsing and dispatch

This keeps the existing interop tooling stable while allowing a clean HTTP/3
runtime surface.

### `h3-server`

Should support:

- host/port
- certificate chain and private key
- qlog directory
- document root
- application protocol fixed to `h3`
- browser-appropriate transport defaults

### `h3-client`

Should support:

- HTTPS target URI
- certificate verification and SNI
- output destination for response body
- optional request headers
- later extension to request bodies

## Browser Story

There are two separate requirements for using browsers:

1. Protocol correctness
   - QUIC + TLS 1.3
   - ALPN `h3`
   - correct certificate for the target origin
   - correct authority/SNI behavior

2. Discovery
   - browsers often learn about HTTP/3 through `Alt-Svc`

Therefore, milestone 1 should make the HTTP/3 server correct and usable with:

- repo-native HTTP/3 client
- `curl --http3`
- direct browser experiments in setups that already know how to reach the H3
  endpoint

But milestone 1 should not require an in-repo Alt-Svc bootstrap server. That
can be a later helper or be handled by an external reverse proxy/front-end.

## Testing Strategy

### Unit Tests

- HTTP/3 frame parse/serialize
- stream type parse/serialize
- `SETTINGS` validation
- `GOAWAY` parsing and state changes
- malformed-message validation
- field ordering and pseudo-header validation

### QPACK Tests

- static-table encoding
- literal field handling
- zero-dynamic-table settings behavior
- malformed field-section decode failures
- encoder/decoder stream validation

### Endpoint Tests

- in-memory client/server request-response exchanges
- static file serving with correct status and headers
- interim responses and final responses
- trailers
- GOAWAY behavior

### Runtime Tests

- `h3-server` and `h3-client` CLI parsing
- direct UDP end-to-end transfer
- certificate failures
- SNI mismatches
- ALPN mismatch handling

### External Verification

- `curl --http3`
- browser tests after certificates and discovery are configured

## Recommended Rollout Order

1. HTTP/3 frame and stream-type primitives
2. zero-dynamic-table QPACK implementation
3. server-side request parsing and static responses
4. client-side request issuance and response parsing
5. CLI/runtime integration
6. browser bootstrap story via documentation or helper
7. optional later work:
   - dynamic QPACK table
   - CONNECT
   - richer routing
   - HTTP/3 qlog events

## Risks And Trade-Offs

### Main Risk

The greatest risk is implementing a handshake-successful but semantically loose
HTTP/3 stack that browsers or tools refuse to use reliably. Strict validation
and narrow scope reduce this risk.

### Chosen Trade-Off

The design accepts some duplication with `http09` in exchange for:

- lower implementation risk
- cleaner module boundaries
- easier reasoning and testing
- safer future refactoring once HTTP/3 is stable

## Acceptance Criteria For Milestone 1

- repository contains parallel HTTP/3 client and server stacks
- existing `http09` runtime and tests remain intact
- `h3-server` can serve static content correctly over QUIC with ALPN `h3`
- `h3-client` can fetch from the HTTP/3 server
- HTTP/3 mandatory streams, `SETTINGS`, request stream semantics, and QPACK
  zero-dynamic-table mode are implemented
- malformed messages and invalid stream/frame sequences are rejected correctly
- direct tool-based verification works with an external HTTP/3-capable client
