# QUIC Perf Benchmark Framework Design

Date: 2026-04-11
Repo: `coquic`
Status: Approved

## Summary

Add a dedicated `coquic-perf` binary plus a repo-owned benchmark harness for
measuring `coquic` transport performance without the HTTP/0.9 interop runtime in
the hot path.

The first version targets three benchmark classes:

- bulk data transfer throughput
- request-response throughput and latency for small payloads on an established
  connection
- connection-request-response throughput and latency for small payloads where
  each exchange pays for a fresh QUIC connection

The benchmark binary should support both `socket` and `io_uring` backends,
produce both human-readable and machine-readable JSON output, and run in a
repeatable two-container setup that uses host networking and explicit CPU pinning
to minimize Docker overhead.

## Problem

The repository currently has no dedicated benchmark framework.

Existing HTTP/0.9 runtime tests and interop flows are useful for correctness, but
they are not appropriate for transport-focused performance measurement because
they include extra noise from:

- HTTP/0.9 request parsing
- document-root and download-root filesystem work
- interop-oriented wrapper behavior
- testcase-specific runtime branches unrelated to pure throughput or latency

That makes it hard to answer simple transport questions such as:

- how much bulk stream throughput `coquic` reaches on loopback
- how `socket` compares with `io_uring` under the same workload
- what latency and request rate look like for small request-response traffic
- what the full connection-plus-request cost is for short-lived exchanges

## Goals

- Add a separate `coquic-perf` executable for QUIC benchmark workloads.
- Keep the benchmark transport path independent from the HTTP/0.9 runtime.
- Support the existing runtime I/O backend selector:
  - `socket`
  - `io_uring`
- Measure three benchmark modes:
  - `bulk`
  - `rr`
  - `crr`
- Support common v1 tuning knobs:
  - `streams`
  - `connections`
  - `requests_in_flight`
  - payload sizes
  - time-based and count-based run limits where applicable
- Emit both:
  - human-readable terminal summary
  - structured JSON output suitable for archival and comparison
- Provide a repo-owned two-container harness using:
  - host networking
  - CPU pinning
  - persisted result files
- Make the benchmark protocol and CLI stable enough for repeatable local use and
  later CI integration.

## Non-Goals

- No reuse of HTTP/0.9 application protocol or file-serving logic.
- No attempt to benchmark Docker bridge networking.
- No non-container orchestration framework in v1 beyond a repo-owned local
  harness.
- No automatic trend dashboards or historical database in v1.
- No cross-machine distributed benchmark controller.
- No promise that benchmark numbers are comparable across different hosts without
  external environment control.
- No HTTP/3 benchmark surface in this change.

## Chosen Architecture

### Separate Binary

Add a new executable:

- `coquic-perf`

This binary reuses the existing QUIC core, TLS, and I/O backend layers, but it
does not share the HTTP/0.9 runtime entrypoints or interop ALPN. The benchmark
application gets its own minimal runtime and its own dedicated ALPN:

- `coquic-perf/1`

This keeps transport measurement focused and prevents benchmark behavior from
being shaped by HTTP/0.9 interop-specific logic.

### Runtime Roles

`coquic-perf` supports two roles:

- `server`
- `client`

The server is benchmark-generic. It validates session parameters and performs the
requested send/receive pattern. The client owns the run lifecycle and all final
metrics.

### Modes

The client supports three benchmark modes:

- `bulk`
- `rr`
- `crr`

#### `bulk`

Long-lived payload transfer over QUIC streams for throughput measurement.

- `download`: server sends, client receives and measures
- `upload`: client sends, server receives and reports counters back

This mode supports `--streams` and may use one or more parallel streams on one or
more connections.

#### `rr`

Small request-response exchanges on already-established QUIC connection(s).

Each request-response pair is carried on a stream. The connection remains alive
for many operations so the benchmark isolates steady-state request rate and
latency after handshake.

#### `crr`

Small request-response exchanges where each exchange uses a fresh QUIC
connection.

This mode measures the cost of:

- connection establishment
- request send
- response receive
- connection completion

That makes it the transport-native analogue of short-lived RPC or connect-fetch
workloads.

## Protocol Design

### Control Stream

Each QUIC connection uses one bidirectional control stream. The client opens the
stream first and sends a `session_start` message. The server replies with either:

- `session_ready`
- `session_error`

The control stream is also used for final counters and orderly shutdown.

### Message Model

The protocol should stay intentionally small and versioned. Messages are framed as
length-prefixed binary records rather than ad-hoc text so the wire format is
stable and cheap to parse.

The initial `session_start` payload includes:

- protocol version
- benchmark mode
- direction for `bulk`
- request payload size
- response payload size
- total byte target when applicable
- total request target when applicable
- measurement duration when applicable
- warmup duration
- number of streams
- number of connections requested by the client side controller
- number of requests in flight

The server validates the requested mode and parameters. Unsupported combinations
return `session_error` with a compact reason string and no benchmark data.

### Data Path

#### `bulk`

Data flows only as payload bytes on benchmark streams.

- `download`: server emits stream payload until the target is met or the duration
  expires
- `upload`: client emits stream payload and the server sends final receive
  counters on the control stream

#### `rr`

Each operation sends a small request payload and expects a small response payload.

- one stream per request-response exchange
- multiple in-flight exchanges allowed
- connection stays established across many operations

#### `crr`

Each operation uses a fresh connection and one control/data exchange.

- client opens a new QUIC connection
- client sends one request
- server sends one response
- client records full end-to-end latency for that connection-scoped exchange

## Metrics

### Client-Authoritative Timing

The client is the source of truth for:

- elapsed benchmark time
- request rate
- throughput
- latency statistics

The server contributes counters only for sanity checking and data-integrity
reporting.

### Human Summary

Every successful run should print a concise terminal summary that includes:

- mode
- backend
- remote host and port
- run duration and warmup duration
- streams
- connections
- requests in flight
- request size
- response size
- bytes sent and received
- requests completed
- throughput in MiB/s
- throughput in Gbit/s
- requests per second where applicable
- latency:
  - min
  - avg
  - p50
  - p90
  - p99
  - max

Modes that do not have a meaningful latency distribution may omit the latency
section.

### JSON Output

Each run should also emit JSON containing:

- schema version
- timestamp
- client host metadata when available
- server host metadata when available
- exact CLI-derived configuration
- negotiated backend and ALPN
- measurement start and stop timestamps
- elapsed durations
- throughput metrics
- request metrics
- latency summary
- optional raw histogram bucket or sample-summary data
- server counters
- exit status
- failure reason when the run aborts

The JSON format must be stable enough that a later aggregate script can compare
multiple runs without scraping human text.

## CLI Shape

### Top-Level Commands

The binary exposes:

- `coquic-perf server`
- `coquic-perf client`

### Common Options

Common relevant flags include:

- `--host`
- `--port`
- `--io-backend socket|io_uring`

### Server Options

The server also accepts:

- `--certificate-chain`
- `--private-key`

The server should remain simple and should not grow client-only measurement
options.

### Client Options

The client accepts:

- `--server-name`
- `--verify-peer`
- `--mode bulk|rr|crr`
- `--direction upload|download`
- `--request-bytes`
- `--response-bytes`
- `--streams`
- `--connections`
- `--requests-in-flight`
- `--warmup`
- `--duration`
- `--requests`
- `--total-bytes`
- `--json-out <path>`

The CLI should reject invalid combinations explicitly. Examples:

- `--direction` with `rr`
- `--total-bytes` with `crr`
- zero request size in `rr` when the protocol requires a request body

## Container Harness

### Deployment Model

The benchmark harness should reuse the existing repo packaging model and produce a
container image that includes `coquic-perf`.

The v1 harness uses two containers:

- pinned server container
- pinned client container

Both containers use:

- `--network host`
- explicit `--cpuset-cpus`

This intentionally avoids Docker bridge overhead and keeps the benchmark closer
to host loopback transport behavior.

### Harness Responsibilities

The repo-owned harness script is separate from interop and is responsible for:

- building or loading the benchmark-capable image
- creating results directories
- starting the server container with fixed CPU affinity
- starting the client container with fixed CPU affinity
- waiting for completion
- collecting JSON and text results
- writing an aggregate manifest over all completed runs

The harness should support small preset matrices over:

- backend
- mode
- payload size
- streams
- connections
- requests in flight

## Code Organization

The benchmark code should live outside `src/http09/`.

A reasonable layout is:

- `src/perf/` for benchmark runtime, protocol, and reporting
- `src/main_perf.cpp` or equivalent benchmark entrypoint source
- `tests/perf/` for benchmark protocol and runtime tests

The benchmark layer should depend on:

- `src/quic/`
- `src/io/`

It should not depend on HTTP/0.9 protocol logic.

## Failure Handling

Failure behavior should be explicit and machine-readable.

Examples:

- invalid CLI combinations fail before network startup
- unsupported backend selection fails during bootstrap
- handshake failure produces a failed run record
- protocol-version mismatch produces `session_error`
- server-side parameter rejection produces `session_error`
- partial runs emit JSON with failure metadata instead of silently disappearing

If a benchmark aborts after some work has completed, the JSON should still include
the partial counters that were observed before failure.

## Testing Strategy

### Unit And Integration Tests

Add tests that cover:

- CLI parsing and validation
- protocol encode/decode
- server parameter validation
- JSON result serialization
- human summary formatting for representative modes
- benchmark runtime bookkeeping for throughput and latency aggregation

### End-To-End Local Tests

Add focused integration tests that run `coquic-perf` client and server locally
with small payloads and low durations to verify:

- `bulk` upload and download complete successfully
- `rr` completes multiple operations on one connection
- `crr` completes repeated short-lived exchanges
- both `socket` and `io_uring` selection paths stay wired correctly

These tests are correctness checks, not performance assertions.

### Harness Verification

The harness script should also have lightweight verification covering:

- expected result-file naming
- aggregate manifest creation
- matrix expansion semantics

## Trade-Offs

- A dedicated benchmark protocol adds new code, but it produces cleaner transport
  measurements than reusing HTTP/0.9.
- Host networking improves fidelity for local loopback measurements, but it means
  the harness is intentionally not a benchmark of Docker virtual networking.
- Client-authoritative metrics keep the reporting model simple, but they require
  clear server counters to catch data mismatches in upload cases.
- A separate benchmark binary keeps layering clean, but it adds build, packaging,
  and documentation surface.

## Open Follow-Ups

This design intentionally leaves room for later work, but not in v1:

- CI trend tracking over stored JSON results
- richer latency histograms
- benchmark comparison tools and regression thresholds
- HTTP/3 benchmark workloads
- multi-host benchmark orchestration
