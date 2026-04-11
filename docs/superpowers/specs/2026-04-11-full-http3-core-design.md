# Full HTTP/3 Core Design

Date: 2026-04-11
Repo: `coquic`
Status: Approved

## Summary

Add a standards-conformant core HTTP/3 stack under `src/http3/` with both a
first-class client and a first-class server, full dynamic-table QPACK, and an
in-repo browser discovery path.

This milestone targets a usable HTTP/3 implementation rather than a protocol
primitive library. It should:

- negotiate ALPN `h3`
- create and manage the mandatory HTTP/3 and QPACK unidirectional streams
- exchange `SETTINGS`, `HEADERS`, `DATA`, and `GOAWAY` correctly
- support `GET`, `HEAD`, and `POST`
- support request bodies, response bodies, interim responses, and trailers
- implement dynamic-table QPACK with correct encoder and decoder stream behavior
- expose first-class `h3-server` and `h3-client` runtime modes
- provide a repo-owned HTTPS bootstrap origin that advertises `Alt-Svc` for
  mainstream browser discovery

For this repo, "mainstream browser" verification means Chromium-based browsers
and Firefox in the documented local certificate-trust setup on supported
developer platforms.

## Problem

`src/http3/` currently contains only a small protocol primitive layer:

- frame parsing and serialization
- minimal request and response pseudo-header validation
- a reduced QPACK implementation with a tiny static table

That is not enough to behave as a real HTTP/3 endpoint. There is currently no:

- connection-scoped HTTP/3 controller above `QuicCore`
- first-class HTTP/3 client or server endpoint
- dynamic-table QPACK implementation
- runtime integration
- browser discovery path

The earlier minimal design intentionally stopped at a narrow milestone. This new
design replaces that narrow target with a complete core stack that can be used
by:

- the repo-native HTTP/3 client
- the repo-native HTTP/3 server
- `curl --http3`
- Chromium-based browsers and Firefox, via an in-repo HTTPS bootstrap origin

## Standards-Conformant Core Definition

For this milestone, "standards-conformant core HTTP/3" means:

- RFC 9114 core connection establishment and ALPN `h3`
- RFC 9114 control stream, request stream, `SETTINGS`, `HEADERS`, `DATA`, and
  `GOAWAY` behavior
- RFC 9114 malformed-message handling for the supported request and response
  model
- RFC 9204 QPACK static-table and dynamic-table support, including encoder and
  decoder streams and blocked-stream accounting
- browser discovery using the `Alt-Svc` HTTP response header field from an
  HTTPS bootstrap origin, as described in RFC 9114 Section 3.1.1

This milestone does not aim to implement every HTTP/3 extension or optional
feature. It focuses on the interoperable core needed for client, server, curl,
and browser use.

## Goals

- Add a complete HTTP/3 application layer under `src/http3/`.
- Deliver both a repo-native HTTP/3 client and server as first-class features.
- Keep `src/quic/` transport-only and application-agnostic.
- Implement dynamic-table QPACK, not a zero-dynamic-table profile.
- Support request and response bodies plus trailers for at least:
  - `GET`
  - `HEAD`
  - `POST`
- Provide graceful shutdown with `GOAWAY`.
- Provide a repo-owned browser discovery path with HTTPS bootstrap plus
  `Alt-Svc`.
- Interoperate with:
  - repo-native HTTP/3 client and server
  - `curl --http3`
  - Chromium-based browsers
  - Firefox
- Keep advanced HTTP/3 features explicitly deferred.

## Non-Goals

- No server push or push stream support in this milestone.
- No CONNECT, extended CONNECT, or proxy-tunneling behavior.
- No HTTP/3 DATAGRAM, WebTransport, or MASQUE features.
- No priority signaling or prioritization extensions.
- No HTTP/3-specific qlog events in this milestone.
- No H3 application-layer 0-RTT request replay support in this milestone.
- No Safari or mobile-browser verification target in this milestone.
- No attempt to turn the bootstrap HTTPS origin into a general-purpose HTTP/1.1
  or HTTP/2 framework.

To make the no-push decision explicit:

- the repo-native client should advertise a no-push policy by sending
  `MAX_PUSH_ID = 0`
- the repo-native server must never emit push-related frames or create push
  streams

## Chosen Architecture

### Layering

`src/quic/` remains transport-only. All HTTP/3 semantics live above it in
`src/http3/`.

The HTTP/3 layer owns:

- HTTP/3 frame and stream semantics
- connection-scoped HTTP/3 state
- request and response transaction state
- QPACK compression state
- HTTP/3 runtime wiring
- the runtime-only HTTPS bootstrap origin used for browser discovery

The QUIC layer must not absorb HTTP/3 message validation, request tracking, or
QPACK logic.

### Module Layout

The recommended `src/http3/` layout is:

- `http3.h`
  - shared HTTP/3 types
  - config structs
  - request, response, and trailer models
  - error codes and result types
- `http3_protocol.h` / `http3_protocol.cpp`
  - frame parsing and serialization
  - stream type parsing and validation
  - frame placement rules
  - `SETTINGS` and `GOAWAY` validation helpers
  - HTTP message validation helpers
- `http3_qpack.h` / `http3_qpack.cpp`
  - QPACK field-section encoding and decoding
  - static-table support
  - dynamic-table management
  - encoder instruction parsing and emission
  - decoder instruction parsing and emission
  - blocked-stream tracking
- `http3_connection.h` / `http3_connection.cpp`
  - HTTP/3 connection-scoped state above `QuicCore`
  - mandatory local unidirectional stream creation
  - remote stream-type registration
  - local and remote settings
  - GOAWAY state
  - QPACK session wiring
  - mapping QUIC transport events to HTTP/3 actions or errors
- `http3_client.h` / `http3_client.cpp`
  - client transaction state machines
  - request issuance
  - request-body upload flow
  - response, interim-response, and trailer collection
  - GOAWAY-aware retry or rejection of not-yet-processed requests
- `http3_server.h` / `http3_server.cpp`
  - server transaction state machines
  - request parsing and validation
  - request-body consumption
  - response and trailer emission
  - static file behavior plus a minimal programmable handler surface
- `http3_runtime.h` / `http3_runtime.cpp`
  - CLI parsing
  - runtime wiring
  - socket/backend integration for QUIC
  - HTTPS bootstrap origin wiring
  - certificate and SNI setup
- `http3_runtime_test_hooks.h`
  - runtime-specific test seams

### Shared Connection Engine

The core protocol logic should not be duplicated between client and server.

Instead, `http3_connection.*` acts as a shared connection engine that owns the
behavior common to both roles:

- startup sequencing for mandatory streams
- local and remote stream registry
- frame dispatch by stream role
- connection-level settings and GOAWAY handling
- QPACK stream and field-section coordination
- translation from protocol violations into HTTP/3 application close codes

`http3_client.*` and `http3_server.*` remain role-specific thin layers on top of
that shared engine.

### Application Surface

The server-side application surface must be concrete enough to exercise HTTP/3
request and response semantics without turning this milestone into a full web
framework.

The chosen shape is:

- a shared request and response model in `http3.h`
- a small handler interface for server-side request processing
- runtime-provided handlers that cover:
  - static file serving for `GET` and `HEAD`
  - exact reserved `POST` endpoints for request-body and trailer verification

The runtime-owned reserved routes for this milestone are:

- `POST /_coquic/echo`
  - returns `200`
  - echoes the request body byte-for-byte in the response body
  - is used to verify request-body upload and response-body download semantics
- `POST /_coquic/inspect`
  - returns `200`
  - emits a small deterministic JSON response describing:
    - request method
    - declared content length, if any
    - total body bytes received
    - normalized request trailer fields
  - is used to verify trailer handling and content-length accounting

The important design constraint is that runtime tests, repo-native client tests,
and curl-based checks all use the same deterministic routes.

### Runtime Shape

The root `coquic` binary should gain first-class subcommands:

- `h3-server`
- `h3-client`

`h3-server` starts:

- a QUIC HTTP/3 server on UDP
- an HTTPS bootstrap origin on TCP/TLS

The HTTPS bootstrap origin exists only to provide browser discovery and aligned
content. It is runtime-only code and must not leak into `src/quic/`.

`h3-client` is a real HTTP/3 client. It must:

- open an HTTP/3 connection
- manage mandatory streams and settings
- send `GET`, `HEAD`, and `POST`
- stream request bodies
- collect interim responses, final responses, and trailers
- write response bodies to stdout or files

The bootstrap HTTPS origin should be a minimal HTTP/1.1-over-TLS server rather
than a full HTTP/2 implementation. `Alt-Svc` works as an HTTP response header
field, so HTTP/1.1 is sufficient and keeps scope under control.

## Protocol Model

### Connection Establishment

HTTP/3 support is negotiated using ALPN `h3` during the TLS handshake, as
described in RFC 9114 Section 3.2.

The runtime must require:

- TLS 1.3 via QUIC transport setup
- SNI for named hosts
- certificate material valid for the advertised origin

This milestone targets HTTPS origins. Direct cleartext `http` origin support is
out of scope.

### Mandatory Streams

Each HTTP/3 endpoint maintains one connection-scoped controller above `QuicCore`.
At connection startup it should create, as soon as transport is ready:

- one local control stream of type `0x00`
- one local QPACK encoder stream of type `0x02`
- one local QPACK decoder stream of type `0x03`

This is aligned with RFC 9114 Section 6.2.1 and RFC 9204 Section 4.2.

The controller must track:

- local control stream ID
- remote control stream ID
- local QPACK encoder stream ID
- local QPACK decoder stream ID
- remote QPACK encoder stream ID
- remote QPACK decoder stream ID
- local settings
- remote settings
- GOAWAY state
- active request stream state

The first frame on each peer control stream must be `SETTINGS`. Violations map
to the RFC 9114 connection errors:

- `H3_MISSING_SETTINGS`
- `H3_STREAM_CREATION_ERROR`
- `H3_CLOSED_CRITICAL_STREAM`
- `H3_FRAME_UNEXPECTED`

Endpoints must use default peer-setting values until the peer `SETTINGS` frame
arrives and must not deadlock waiting for peer settings before sending their own
mandatory streams or valid early requests.

The implementation should reserve enough QUIC flow-control credit and stream
budget so control and QPACK streams do not deadlock behind request data. The
default transport configuration should permit at least 100 concurrent request
streams unless the user explicitly configures a lower limit.

### Request Streams

All client-initiated bidirectional QUIC streams are treated as request streams.

For a supported non-CONNECT request, the request stream model is:

1. one initial request `HEADERS` frame
2. zero or more request `DATA` frames
3. optionally one trailing request `HEADERS` frame
4. zero or more interim response header sections
5. exactly one final response header section
6. zero or more response `DATA` frames
7. optionally one trailing response `HEADERS` frame

This follows RFC 9114 Section 4.1.

The implementation must reject invalid ordering, including:

- `DATA` before initial `HEADERS`
- request or response `HEADERS` after trailing `HEADERS`
- an additional final response after a final response already completed
- `HEADERS` on streams that are not request or push streams
- `GOAWAY` or `SETTINGS` on streams other than the control stream

Unknown frame types should be tolerated where RFC 9114 allows them. Unknown
settings must be ignored. Reserved HTTP/2-derived HTTP/3 setting identifiers
must be rejected with `H3_SETTINGS_ERROR`.

Unknown unidirectional stream types should be drained and ignored rather than
treated as connection errors.

### HTTP Message Validation

The implementation should be strict about malformed messages.

The validation rules for this milestone include:

- request pseudo-headers:
  - exactly one `:method`
  - exactly one `:scheme`
  - exactly one `:path`, except CONNECT is out of scope here
  - `:authority` or `Host` required for schemes with mandatory authority
  - if both `:authority` and `Host` are present, they must match
- response pseudo-headers:
  - exactly one `:status`
- general rules:
  - pseudo-headers must precede regular fields
  - pseudo-headers are forbidden in trailers
  - undefined or role-invalid pseudo-headers are malformed
  - uppercase field names are malformed
  - connection-specific HTTP fields are malformed
  - `Transfer-Encoding` is forbidden
  - `TE`, if present on requests, must equal `trailers`
  - `content-length`, if present, must match the sum of body bytes actually
    transferred

Malformed messages should map to `H3_MESSAGE_ERROR` where appropriate.

`HEAD` responses must preserve header semantics while suppressing response body
transmission.

### Requests, Cancellation, And Shutdown

This milestone supports:

- `GET`
- `HEAD`
- `POST`

It does not support CONNECT-family semantics.

The server may produce a complete response before fully consuming the request
body when permitted by the request semantics. If it does so, it should terminate
the client send side cleanly using the appropriate QUIC-side signal while still
preserving the valid HTTP response, consistent with RFC 9114 Section 4.1.

Client- and server-side request cancellation should map to the appropriate
HTTP/3 application error codes when a full HTTP response is not used instead.

Graceful shutdown must use `GOAWAY`, following RFC 9114 Section 5.2 and Section
7.2.6. A server-side GOAWAY carries a client-initiated bidirectional stream ID.
The implementation must reject invalid GOAWAY identifiers with `H3_ID_ERROR`.

The client must stop issuing new requests after peer GOAWAY and mark or retry
not-yet-processed requests according to the stream identifier boundary conveyed
by GOAWAY.

## QPACK Design

### Full Dynamic-Table Scope

Dynamic-table QPACK is in scope for this milestone.

Both endpoints must:

- advertise and honor `SETTINGS_QPACK_MAX_TABLE_CAPACITY`
- advertise and honor `SETTINGS_QPACK_BLOCKED_STREAMS`
- create and manage encoder and decoder streams
- process valid peer instructions
- maintain synchronized dynamic table state
- account for blocked streams correctly

This follows RFC 9204 Section 4.2 and Section 5.

### Decoder Requirements

The decoder must:

- decode valid field sections referencing the static table and dynamic table
- block only within the peer-advertised limit
- resume blocked field sections when required inserts arrive
- track insert count and known received count correctly
- surface `QPACK_DECOMPRESSION_FAILED` for invalid encoded field sections on
  request streams

### Encoder Requirements

The encoder must:

- send encoder stream instructions that never exceed the peer-advertised dynamic
  table capacity
- emit Set Dynamic Table Capacity and insertion instructions correctly
- process decoder stream acknowledgments and cancellation signals
- avoid violating the peer-advertised blocked-stream limit

Invalid encoder-stream processing by the peer maps to
`QPACK_ENCODER_STREAM_ERROR`. Invalid decoder-stream processing maps to
`QPACK_DECODER_STREAM_ERROR`.

### Encoder Policy

The wire format must be fully conformant even if the compression policy is
conservative.

The default encoder policy for this milestone should be:

- prefer exact static-table references when available
- never index sensitive headers such as:
  - `authorization`
  - `cookie`
  - `set-cookie`
- prefer literal-with-name-reference or literal-without-indexing for one-off
  fields
- insert dynamic entries for repeated, non-sensitive fields once reuse on the
  same connection is likely and peer capacity permits

This gives useful dynamic-table coverage for interoperability while avoiding an
aggressive policy that is hard to reason about.

### QPACK And Request Semantics

The implementation must respect the dependency between field-section decoding and
QPACK stream processing. A request or response header section cannot be consumed
before the required QPACK inserts are known. This affects:

- request dispatch timing on the server
- response availability timing on the client
- blocked-stream accounting
- flow-control behavior on QPACK streams

## Runtime And Browser Discovery

### `h3-server`

`coquic h3-server` should accept configuration for:

- host
- UDP port for HTTP/3
- TCP port for HTTPS bootstrap
- certificate chain and private key
- document root
- server name
- optional qlog directory
- optional keylog path
- optional `Alt-Svc` max-age
- optional QPACK settings

The H3 origin and HTTPS bootstrap origin must share:

- the same certificate identity
- the same routing or content configuration
- enough response metadata that browser-visible behavior is coherent

### HTTPS Bootstrap Origin

The runtime must include a small HTTPS bootstrap origin that:

- serves the same static content roots as the H3 server for `GET` and `HEAD`
- emits `Alt-Svc` advertising the H3 endpoint on bootstrap responses
- uses the same hostname and certificate identity as the H3 server

The bootstrap listener is runtime-only code. It should not become a dependency
of `src/quic/`.

The advertised `Alt-Svc` value should be configurable and should default to the
same host with the configured H3 UDP port, for example:

- `Alt-Svc: h3=":4433"; ma=60`

The runtime should document the local trust and browser setup needed for
Chromium-based browsers and Firefox to accept the certificate and discover the
HTTP/3 endpoint.

### `h3-client`

`coquic h3-client` should support:

- URL input
- explicit method selection
- request headers
- request body from a file or stdin
- response body to stdout or file
- optional trailer output
- certificate verification controls
- server name override

The client should reuse an HTTP/3 connection across requests to the same origin
when practical, while remaining correct in the presence of GOAWAY and other
connection-level errors.

### Runtime-Provided Test Surfaces

To keep request-body and trailer behavior testable, the runtime should expose
the standard reserved routes defined above:

- `POST /_coquic/echo`
- `POST /_coquic/inspect`

These routes are not intended as public product features. They exist to make
body upload, trailer handling, and malformed-request coverage easy to verify in
automated tests.

## Testing Strategy

### Unit Tests

Add or extend unit tests for:

- frame parsing and serialization
- stream type parsing
- frame placement rules
- control stream rules
- settings parsing and reserved-setting rejection
- GOAWAY validation
- request and response pseudo-header validation
- trailer validation
- malformed message detection
- `content-length` accounting

### QPACK Tests

Add or extend QPACK tests for:

- static-table references
- dynamic-table insertion and eviction
- Set Dynamic Table Capacity handling
- blocked-stream accounting
- decoder acknowledgments
- stream cancellation instructions
- malformed field sections
- malformed encoder stream instructions
- malformed decoder stream instructions

### Endpoint Tests

Add in-memory endpoint tests for:

- connection startup and mandatory stream creation
- request-response exchanges over one connection
- parallel requests on multiple streams
- request bodies and upload handling
- interim responses
- response bodies and trailers
- GOAWAY handling
- early server response before request-body completion
- client and server cancellation
- error mapping to application close codes

### Runtime Tests

Add runtime tests for:

- CLI parsing for `h3-server` and `h3-client`
- TLS certificate loading and failure cases
- SNI mismatch handling
- ALPN mismatch handling
- HTTPS bootstrap origin responses
- `Alt-Svc` emission
- end-to-end H3 data transfer over the real runtime path

### External Verification

External verification for this milestone should include:

- repo-native client against repo-native server
- `curl --http3` against repo-native server
- Chromium-based browser against HTTPS bootstrap plus H3 server
- Firefox against HTTPS bootstrap plus H3 server

Browser verification should use the documented local trust setup rather than an
external reverse proxy.

## Risks And Mitigations

### Dynamic QPACK Complexity

Dynamic-table QPACK is the largest protocol risk. It introduces cross-stream
dependencies, blocked-stream accounting, and more failure modes than the earlier
minimal design.

Mitigation:

- keep QPACK state isolated in `http3_qpack.*`
- give it an explicit instruction parser and serializer
- test encoder, decoder, and blocked-stream behavior independently from runtime

### Runtime Scope Creep

The HTTPS bootstrap origin is necessary for browser discovery, but it can easily
turn into a separate web-server project.

Mitigation:

- keep the bootstrap origin minimal
- limit it to the same content and reserved routes needed by the H3 runtime
- keep it runtime-only and separate from transport abstractions

### Client And Server Drift

Independent client and server logic can diverge if they each carry their own
copy of connection-scoped rules.

Mitigation:

- centralize shared protocol behavior in `http3_connection.*`
- keep role-specific logic in thin client and server layers

## Recommended Rollout Order

1. Expand `http3_protocol.*` from primitive helpers to full frame-placement and
   message-validation coverage.
2. Replace the current reduced QPACK implementation with a full dynamic-table
   implementation.
3. Add `http3_connection.*` as the shared connection-scoped engine.
4. Add `http3_server.*` with request parsing, static serving, and reserved POST
   handler support.
5. Add `http3_client.*` with request issuance, body upload, and response
   collection.
6. Add `http3_runtime.*` plus `h3-server` and `h3-client` CLI wiring.
7. Add the HTTPS bootstrap origin and browser discovery path.
8. Complete runtime and external verification with curl and browsers.

## Acceptance Criteria

- `src/http3/` contains first-class client, server, connection, QPACK, and
  runtime modules in addition to the base protocol types.
- Both endpoints create and manage the mandatory control and QPACK streams.
- `SETTINGS`, request-stream framing, message validation, and `GOAWAY` behavior
  conform to the supported RFC 9114 core.
- Dynamic-table QPACK is implemented and interoperable in the supported profile.
- The server supports `GET`, `HEAD`, and `POST`, including request bodies,
  response bodies, and trailers.
- The repo-native client can fetch from the repo-native server and handle
  interim responses, final responses, and trailers.
- `coquic h3-server` provides an in-repo HTTPS bootstrap origin that emits
  `Alt-Svc` for the H3 endpoint.
- `curl --http3` works against the repo-native server in the documented setup.
- Chromium-based browsers and Firefox can discover and use the repo-native H3
  server through the in-repo bootstrap origin in the documented setup.
- Malformed frames, stream misuse, settings violations, malformed messages, and
  QPACK failures are rejected with the correct HTTP/3 or QPACK error behavior.
- The deferred advanced features remain unimplemented and explicitly out of
  scope:
  - server push
  - CONNECT-family methods
  - HTTP/3 DATAGRAM
  - WebTransport
  - priorities
  - HTTP/3-specific qlog events
  - H3 0-RTT request replay
