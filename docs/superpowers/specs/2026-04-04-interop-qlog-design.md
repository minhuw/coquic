# Interop QLOG Enablement Design

## Status

Approved in conversation on 2026-04-04.

## Goal

Enable `coquic` to emit real core-QUIC qlog traces during official interop
runs, using the standard `QLOGDIR` environment contract so the generated
`.sqlog` files land in the existing interop log artifacts.

## Context

Core qlog support already exists in this branch:

- `QuicCoreConfig` can carry an optional `QuicQlogConfig`
- each `QuicConnection` can open one `.sqlog` file per connection
- qlog write failures are observational and must not break transport behavior

The remaining gap is not inside the core serializer or event emission logic.
The gap is that the HTTP/0.9 interop runtime does not currently read any qlog
configuration from its environment and therefore never populates
`QuicCoreConfig.qlog`.

## Runner Grounding

The pinned `quic-interop-runner` revision already does the two things this
design needs:

- it sets `QLOGDIR=/logs/qlog/` for both the client and server containers
- it copies `/logs` out of the containers into the testcase log tree

That means enabling qlog in GitHub Actions does not require a new artifact
pipeline or a new workflow variable. Once `coquic` honors `QLOGDIR`, qlogs
should appear automatically in the existing uploaded `.interop-logs/official`
artifacts.

## Scope

This design covers only the `coquic` side of interop qlog emission:

- read `QLOGDIR` in the HTTP/0.9 runtime
- store the parsed path in runtime configuration
- propagate that path into `QuicCoreConfig.qlog` for both client and server
- verify that interop artifacts can contain `.sqlog` files without changing
  connection behavior

## Non-Goals

- collecting or normalizing peer implementation qlogs
- adding HTTP/3 or HTTP harness qlog events
- changing qlog file naming, schema selection, or event content
- adding a bespoke CI artifact upload path for qlogs
- making qlog mandatory for interop success

## Approaches Considered

### 1. Honor Standard `QLOGDIR` In The Runtime

Teach the HTTP/0.9 runtime to read `QLOGDIR` from the environment and, when
present, pass it through to `QuicCoreConfig.qlog`.

Pros:

- matches official interop runner conventions
- aligns with other QUIC implementations
- requires the smallest code change
- keeps the qlog concern at the runtime boundary where environment parsing
  already happens

Cons:

- local non-interop users must know the `QLOGDIR` convention unless a future
  CLI flag is added

### 2. Add A Coquic-Specific Environment Variable

Teach the runtime to read something like `COQUIC_QLOG_DIR` and ignore
`QLOGDIR`.

Pros:

- explicit and repo-specific

Cons:

- diverges from interop conventions
- requires wrapper-script plumbing even though the official runner already
  supplies `QLOGDIR`
- makes local and CI behavior less predictable for users familiar with qlog

### 3. Add A New CLI Flag Only

Add `--qlog-dir PATH` and require wrappers or manual invocation to pass it.

Pros:

- clear explicit local interface

Cons:

- does not solve official runner integration by itself
- still needs wrapper changes or env-to-CLI translation
- adds more surface area than the first slice needs

## Decision

Use approach 1 now: honor standard `QLOGDIR` in the runtime, leave workflow
logic unchanged, and defer any explicit CLI flag until there is a separate
local-debugging need.

## Decisions

### 1. Add Optional Qlog Directory To `Http09RuntimeConfig`

Extend `Http09RuntimeConfig` with an optional filesystem path field for qlog
output. Unset means qlog is disabled for that runtime instance.

This keeps environment parsing separated from core config construction and gives
tests a stable configuration surface.

### 2. Read `QLOGDIR` From The Environment Only In This Slice

The runtime parser should treat:

- unset `QLOGDIR` as disabled
- empty `QLOGDIR` as disabled
- non-empty `QLOGDIR` as an enabled qlog root directory

This mirrors how interop containers are configured today without adding a new
flag parsing branch.

### 3. Wire Runtime Qlog Into Both Client And Server Core Factories

`make_http09_client_core_config()` and
`make_http09_server_core_config_with_identity()` should both copy the runtime
qlog directory into `QuicCoreConfig.qlog` when present.

That ensures qlog works regardless of whether `coquic` is the client or the
server in the official runner matrix.

### 4. Keep Failure Semantics Observational

If the qlog sink cannot create directories or open files, the connection must
still proceed without transport failure.

This preserves the existing core-qlog contract and avoids turning a debugging
surface into a protocol dependency.

### 5. Leave Workflow YAML Unchanged Unless Documentation Value Justifies A Comment

Because the uploaded artifact path already includes the runner log tree and the
runner already sets `QLOGDIR`, no functional workflow change is required to
start collecting qlogs.

At most, `interop/run-official.sh` may gain a small comment documenting that
qlog now works automatically via the official runner environment.

## Data Flow

1. GitHub Actions runs `interop/run-official.sh`.
2. The pinned official runner launches `coquic` containers with
   `QLOGDIR=/logs/qlog/`.
3. `parse_http09_runtime_args()` reads `QLOGDIR` and stores it in
   `Http09RuntimeConfig`.
4. The HTTP/0.9 runtime factories copy that path into `QuicCoreConfig.qlog`.
5. `QuicConnection` opens a per-connection `.sqlog` file under that directory.
6. The official runner copies `/logs` out of the container into the testcase
   artifact tree already uploaded by the workflow.

## Error Handling

- The runtime does not perform path validation beyond empty versus non-empty
  input; unset or empty disables qlog, and any non-empty path is forwarded to
  the core.
- Filesystem failures while opening or writing qlogs remain non-fatal.
- Interop test success remains driven by testcase results, not by qlog
  presence.

## Testing

Add focused runtime tests that cover:

- `QLOGDIR` unset leaves runtime qlog disabled
- `QLOGDIR` empty leaves runtime qlog disabled
- `QLOGDIR` set populates the runtime qlog directory field
- client core config inherits runtime qlog configuration
- server core config inherits runtime qlog configuration

No new end-to-end qlog content tests are required for this slice because core
qlog serialization and event emission are already covered elsewhere in the
branch.

## Risks

### 1. Runtime-Only Wiring Could Be Mistaken For A Full User-Facing Qlog Interface

This slice intentionally optimizes for interop and CI. Local ergonomics may
still justify a later `--qlog-dir` flag.

### 2. Artifact Layout Is Owned By The Official Runner

The exact log directory nesting in uploaded artifacts is determined by the
runner. This design depends on the current documented `/logs` copy behavior.

### 3. Qlog Volume Can Grow In Large Interop Runs

Because one `.sqlog` is emitted per connection and some testcases create
multiple connections, artifact size will increase. This is acceptable for the
current scope because qlog remains optional and only activates when `QLOGDIR`
is present.
