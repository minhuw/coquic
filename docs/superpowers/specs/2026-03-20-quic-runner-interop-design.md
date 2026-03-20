# QUIC Runner Interop Design

## Status

Approved in conversation on 2026-03-20.

## Context

`coquic` currently has:

- a transport-facing `QuicCore` with a poll/result API
- a real QUIC + TLS handshake
- multi-stream transport support
- flow control, ACK processing, loss recovery, PTO, and NewReno congestion
  control
- a socket-backed local demo in `src/main.cpp`
- a `QuicDemoChannel` wrapper that exposes a private one-stream message demo

That current demo is not suitable as an interop target:

- it hard-wires application traffic to stream `0`
- it uses a private 4-byte length-prefixed framing protocol
- it does not model HTTP/0.9 request / response semantics
- it is intentionally local-demo oriented, not runner oriented

The official QUIC interop runner expects a different application contract:

- the server serves files from `/www`
- the client stores downloaded files under `/downloads`
- request URLs are passed in the `REQUESTS` environment variable
- the server listens on UDP port `443`
- test cases use HTTP/0.9 unless noted otherwise
- the `handshake` test establishes one connection and downloads one or more
  small files
- the `transfer` test establishes one connection and concurrently downloads
  multiple files on multiple streams
- the `transfer` client must advertise small initial stream-level and
  connection-level flow-control windows, forcing `MAX_DATA` and
  `MAX_STREAM_DATA` updates during transfer
- servers must not send Retry packets in the `handshake` test case

Reference implementations for runner HTTP/0.9 mode also use ALPN
`"hq-interop"` instead of this repo's current `"coquic"` demo default.

The user wants the fastest path to official-runner reuse for both client and
server endpoints, starting with `handshake` and ideal-network `transfer`.

## Goal

Add a runner-compatible application layer above `QuicCore` that:

- supports both client and server roles
- speaks minimal HTTP/0.9 over QUIC using ALPN `"hq-interop"`
- passes the official runner's `handshake` test case
- passes the official runner's ideal-case `transfer` test case
- keeps the transport engine I/O independent
- preserves `QuicCore` as the transport layer rather than turning it into an
  HTTP application layer
- provides a clear migration path away from `QuicDemoChannel`

## Non-Goals

- HTTP/3, QPACK, or HTTP header support
- Retry, resumption, 0-RTT, key update, migration, or version negotiation
- non-ideal-network runner scenarios in this slice
- redesigning `QuicCore` into a high-level application API
- general-purpose web-server behavior beyond what the runner needs
- preserving `QuicDemoChannel` as a long-term public abstraction

## Decisions

### 1. Add A New HTTP/0.9 Endpoint Layer Above `QuicCore`

Do not rewrite `QuicDemoChannel` into a runner protocol.

Instead, introduce a separate application layer above `QuicCore` that owns:

- HTTP/0.9 request / response parsing and formatting
- file-system mapping for `/www` and `/downloads`
- request-to-stream assignment
- runner-specific startup configuration

`QuicCore` remains transport-only. It continues to expose raw stream-aware QUIC
effects and inputs.

### 2. Support Both Client And Server Endpoints In The First Slice

The first interop slice includes:

- a client endpoint that consumes `REQUESTS`, opens one connection, and
  downloads all requested files concurrently
- a server endpoint that serves files from a configured document root on the
  inbound request streams

This is intentionally broader than a server-only spike because the user wants
official-runner reuse quickly, and the runner exercises both sides through a
single shared contract.

### 3. Keep The Existing Demo Temporarily, Then Remove It

`QuicDemoChannel` remains only as migration scaffolding while the new endpoint
path is built and tested.

After:

- the local runtime is switched to the new endpoint path, and
- endpoint-level tests cover the same smoke behavior that `QuicDemoChannel`
  currently justifies,

`QuicDemoChannel` should be deleted rather than maintained in parallel.

### 4. Use Minimal HTTP/0.9, Not A Private Runner Wire Protocol

The new application layer is runner-compatible but should not be named or
structured as a runner-only hack. It should model HTTP/0.9 over QUIC directly.

For this slice:

- requests are `GET <path>\r\n`
- responses are body-only byte streams
- each request uses one bidirectional QUIC stream
- the client half-closes its send side after writing the request
- the server replies on the same stream and finishes with `FIN`

The parser should accept `\r\n` and bare `\n` line endings to be liberal in
what it accepts, but the client should emit `\r\n`.

### 5. Use Runner-Compatible Defaults

Interop mode uses these defaults:

- ALPN: `"hq-interop"`
- server UDP port: `443`
- server certificate chain: `/certs/cert.pem`
- server private key: `/certs/priv.key`
- client download root: `/downloads`
- server document root: `/www`

The current `QuicCoreConfig::application_protocol` default of `"coquic"` stays
unchanged for local non-interop use. Interop code must override it explicitly.

### 6. Make Testcase Behavior Explicit In Configuration

Interop runtime behavior depends on the runner testcase:

- `handshake`
  - one connection
  - download all requested small files
  - no Retry support or Retry generation in this slice
- `transfer`
  - one connection
  - one bidirectional stream per requested file
  - concurrent downloads
  - client transport parameters must use small initial flow-control windows so
    the transfer exercises `MAX_DATA` and `MAX_STREAM_DATA`

This testcase-dependent behavior should be represented explicitly in endpoint or
runtime configuration rather than hidden in ad hoc branching throughout the UDP
loop.

## Architecture

### Layering

The interop stack becomes:

1. UDP I/O loop
2. `QuicCore`
3. HTTP/0.9 endpoint layer
4. runner-facing CLI / environment adapter

Responsibilities:

- UDP loop
  - owns sockets and polling
  - feeds datagrams and timer expirations into `QuicCore`
  - sends datagrams produced by `QuicCore`
- `QuicCore`
  - owns QUIC transport state
  - exposes stream receive events, stream control events, and outbound datagrams
- HTTP/0.9 endpoint layer
  - translates between stream events and HTTP/0.9 file-transfer behavior
  - owns request parsing, transfer state, and file I/O
- runner adapter
  - parses env vars and CLI inputs
  - chooses client or server mode
  - builds endpoint configuration for `handshake` vs `transfer`

### Endpoint Types

Introduce two endpoint objects above `QuicCore`:

- `QuicHttp09ClientEndpoint`
- `QuicHttp09ServerEndpoint`

The exact filenames are implementation detail, but the responsibilities are
fixed.

#### Client Endpoint Responsibilities

- parse `REQUESTS` into ordered transfer intents
- maintain one QUIC connection
- allocate client-initiated bidirectional stream IDs for requests
- send one HTTP/0.9 `GET` request per transfer
- receive response bytes on the matching stream
- write the body to `/downloads` plus the requested URL path
- mark each transfer complete only when the response stream finishes with `FIN`
- expose terminal success only when all requested downloads complete

The client writes files to `/downloads` preserving the URL path, for example
`https://server.example/a/b.bin` maps to `/downloads/a/b.bin`. Parent
directories are created as needed.

#### Server Endpoint Responsibilities

- track per-stream request parsing state
- accept only peer-opened bidirectional streams
- buffer request bytes until a complete request line is available
- validate and normalize the request path
- map the path into the configured document root
- read and send the file bytes on the same stream
- finish the response with `FIN`

### Stream Model

The stream contract for this slice is:

- one request per bidirectional stream
- one response body per bidirectional stream
- the client opens streams
- the server never initiates application streams
- stream reuse is not allowed
- stream-local failure should fail the transfer on that stream deterministically

The server should start sending the response as soon as the request line is
parsed; it does not need to wait for full connection idle states or any
application-level acknowledgment.

### Request Parsing And Path Handling

For this slice, the server accepts only:

- method `GET`
- absolute paths beginning with `/`
- no request body

The server rejects:

- unsupported methods
- empty or relative paths
- query or fragment components
- path traversal outside the configured document root

It is acceptable in this slice to reject percent-encoded or otherwise unusual
paths that are not needed by the runner-generated test corpus.

### Transfer Scheduling

The client should issue all `transfer` testcase requests without artificial
serialization. `QuicCore` transport scheduling, flow control, and congestion
control decide how bytes are actually sent.

The application layer should not invent another fairness or pacing scheme in
this slice.

### Runtime Shape

The local socket runtime in `src/main.cpp` should be reworked around the new
endpoint layer instead of around `QuicDemoChannel`.

Runtime inputs include:

- role: client or server
- host / bind address
- port
- testcase
- request list
- document root
- download root
- certificate / key paths
- optional TLS verification mode

For official runner compatibility, the runtime must read the environment
variables and mount conventions that the runner provides. A thin shell wrapper
or entrypoint script may still be used, but application behavior must live in
the C++ runtime rather than in shell-only logic.

## Error Handling

### Transport Errors

Transport failures remain owned by `QuicCore`. If `QuicCore` reports a failure
or local error, the endpoint run fails.

### Application Errors

Application-layer failures include:

- malformed request line
- unsupported HTTP method
- invalid request path
- file not found
- file read failure
- file write failure
- unexpected stream direction or stream role
- response stream terminated without a clean completed transfer

For this slice, these failures should be deterministic and explicit. Do not add
fallback behavior or partial compatibility heuristics.

Where the transport makes it practical, request-local failures may abort the
affected stream. If the implementation cannot represent a clean stream-local
application error yet, failing the endpoint run is acceptable in this slice.

## Testing

### Endpoint-Level Tests

Add integration tests above `QuicCore` that cover:

- client/server handshake plus single-file download
- multiple concurrent downloads on one connection
- server-side request parsing and file serving
- client-side file creation and byte-exact download output
- invalid path rejection
- malformed request rejection
- transfer completion only on `FIN`
- testcase-specific client flow-control profile for `transfer`

These tests should run in-process first, using the existing style of idealized
datagram relay, because they are fast and deterministic.

### Runtime Smoke Tests

Add socket-backed smoke coverage for:

- local server runtime serving a real file
- local client runtime downloading a real file
- end-to-end HTTP/0.9 transfer over UDP sockets on localhost

### Runner Readiness

The deliverable for this design is not complete until the repo has a documented
path to run the official runner or network simulator against the new endpoint
mode.

This slice targets only:

- `handshake`
- ideal-case `transfer`

All other official runner cases remain out of scope until a later design.

## Rollout

The migration sequence is:

1. add the new HTTP/0.9 endpoint layer above `QuicCore`
2. rework the local runtime to use that endpoint layer
3. add endpoint-level and socket-backed tests
4. add runner-facing runtime and entrypoint glue
5. remove `QuicDemoChannel` and its now-obsolete tests and demo-only helpers

This ordering keeps interop compatibility on the critical path while making the
eventual demo-channel removal explicit and low risk.
