# 100 Percent Coverage Design

## Status

Approved in conversation on 2026-03-24.

## Goal

Raise the current LLVM source-based coverage report for the repo's unit-test
coverage run to:

- `100.00%` line coverage
- `100.00%` region coverage
- `100.00%` branch coverage

while preserving runtime behavior apart from narrowly-scoped testability seams
and tiny cleanups for genuinely unreachable defensive control flow.

## Context

A fresh coverage run on `main` at `a347792` produced:

- line coverage: `86.40%` (`9712/11241`)
- region coverage: `87.96%` (`4859/5524`)
- branch coverage: `83.84%` (`3238/3862`)
- functions executed: `94.23%` (`604/641`)

The largest remaining gaps are concentrated in a small set of files:

- `src/quic/http09_runtime.cpp`
- `src/quic/connection.cpp`
- `src/quic/protected_codec.cpp`
- `src/quic/packet_crypto_quictls.cpp`
- `src/quic/http09.cpp`
- `src/quic/http09_client.cpp`
- `src/quic/http09_server.cpp`
- `src/quic/crypto_stream.cpp`
- `src/quic/crypto_stream.h`
- `src/quic/tls_adapter_quictls.cpp`
- `src/quic/streams.cpp`

The dominant blocker is `src/quic/http09_runtime.cpp`, which currently carries
the majority of the missing lines, regions, and branches.

The user explicitly approved pursuing literal `100.00%` coverage, including
small behavior-preserving test hooks or helper extraction where a real branch is
otherwise unreachable through existing public interfaces.

## Scope

This design covers:

- shared runtime and HTTP/0.9 behavior under `src/quic/http09*.{cpp,h}`
- connection state-machine coverage in `src/quic/connection.cpp`
- protected packet codec coverage in `src/quic/protected_codec.cpp`
- quictls packet-crypto and TLS-adapter fault/error coverage
- targeted unit-test and white-box helper updates in `tests/*.cpp` and
  `tests/quic_test_utils.h`
- fresh verification with `zig build test`, `zig build coverage`, and
  `llvm-cov report`

## Non-Goals

- excluding lines or files from the coverage report
- massaging coverage output to appear complete without real execution
- broad architecture changes unrelated to the uncovered branches
- changing externally observable runtime semantics just to manufacture coverage
- adding new product features unrelated to closing the current misses

## Decisions

### 1. Use Tests First, Seams Second

Prefer targeted tests whenever the uncovered branch reflects normal behavior.

When a branch depends on external I/O, TLS library failures, or exact internal
state that is not deterministically reachable today, add the smallest possible
testability seam instead of forcing brittle integration setups.

Allowed seam types:

- tiny helper extraction from anonymous-namespace runtime logic
- deterministic syscall/file/TLS failure hooks at existing module boundaries
- white-box access through the repo's established test-helper style

Disallowed seam types:

- broad dependency-injection frameworks
- test-only runtime flags or public API surface with no production value
- fake success paths that bypass real production logic

### 2. Close The HTTP/0.9 Runtime Layer First

`src/quic/http09_runtime.cpp` is the primary blocker and should be handled
before the smaller residual files.

The work should cover:

- argument parsing and defaulting branches
- authority, host, port, and testcase derivation
- top-level role dispatch and usage/error branches
- file-loading failure cases
- DNS/address parsing branches
- socket creation, bind/connect, send, receive, and poll failures
- runtime orchestration branches that normal happy-path integration tests do not
  exercise

Implementation guidance:

- add focused tests in `tests/quic_http09_runtime_test.cpp`
- extract only narrow, local helpers when a branch is trapped behind OS calls
- keep production behavior unchanged when the seam is inactive

### 3. Finish The Adjacent HTTP/0.9 Modules With Focused Tests

Close the remaining misses in:

- `src/quic/http09.cpp`
- `src/quic/http09_client.cpp`
- `src/quic/http09_server.cpp`

Expected coverage themes:

- URL and authority parsing edge cases
- invalid path and document-root resolution
- duplicate or out-of-order stream events
- zero-request and already-complete request handling
- missing file, file-open, file-read, and post-write failure paths
- server chunk-drain and pending-work accounting edges

These files should mostly move through tests rather than production changes once
the runtime fixtures exist.

### 4. Drive Connection State Edges Through Deterministic White-Box Tests

`src/quic/connection.cpp` remains a large file with a smaller but still
material tail of missed branches.

The implementation should extend `tests/quic_core_test.cpp` and
`tests/quic_test_utils.h` to cover:

- ACK and loss-processing edge cases
- PTO and deadline-selection branches
- packet-space transitions and cleanup
- version-negotiation, retry, and unsupported-packet branches
- flow-control refresh conditions
- stream scheduling and sendability corner cases
- terminal and partially-initialized state transitions

Prefer existing test patterns and white-box helpers over widening the
production-facing API.

### 5. Reuse Existing Fault-Injection Patterns For Codec And TLS Coverage

For the remaining misses in:

- `src/quic/protected_codec.cpp`
- `src/quic/packet_crypto_quictls.cpp`
- `src/quic/tls_adapter_quictls.cpp`
- `src/quic/crypto_stream.cpp`
- `src/quic/crypto_stream.h`
- `src/quic/streams.cpp`

the preferred strategy is:

- add one test per uncovered branch family
- extend existing fault-injection or test-hook patterns where available
- keep seams local to the codec/TLS boundary
- avoid new generic abstraction layers

For TLS and packet crypto specifically, fault hooks should target:

- setup and initialization failures
- library call failures on encrypt/decrypt/open/seal paths
- cleanup/error-return branches after partial setup
- callback wiring and missing-context defensive branches

### 6. Remove Only Truly Dead Fallback Control Flow

If the final uncovered branches reduce to impossible fallback returns after an
exhaustive enum or invariant-guarded path, removing that dead code is
acceptable.

That cleanup is allowed only when:

- the path is structurally unreachable under the actual design
- the removal simplifies the code
- no observable behavior changes for real callers

Coverage must not be raised by weakening validation or skipping real error
handling.

## Architecture

The work is organized into four implementation lanes:

### Lane 1: HTTP/0.9 Runtime And CLI Coverage

Primary files:

- `src/quic/http09_runtime.cpp`
- `tests/quic_http09_runtime_test.cpp`

This lane introduces the minimal runtime seams needed to exercise
configuration-, filesystem-, network-, and orchestration-only branches
deterministically.

### Lane 2: HTTP/0.9 Endpoint And Parser Coverage

Primary files:

- `src/quic/http09.cpp`
- `src/quic/http09_client.cpp`
- `src/quic/http09_server.cpp`
- corresponding `tests/quic_http09*_test.cpp`

This lane closes parser, request/response, path-resolution, and stream-lifecycle
branches using focused unit tests and small deterministic filesystem fixtures.

### Lane 3: Connection State-Machine Coverage

Primary files:

- `src/quic/connection.cpp`
- `tests/quic_core_test.cpp`
- `tests/quic_test_utils.h`

This lane expands targeted packet/state tests to hit the remaining logic tails
without changing the runtime architecture.

### Lane 4: Codec, Crypto, And TLS Tail Coverage

Primary files:

- `src/quic/protected_codec.cpp`
- `src/quic/packet_crypto_quictls.cpp`
- `src/quic/tls_adapter_quictls.cpp`
- `src/quic/crypto_stream.cpp`
- `src/quic/crypto_stream.h`
- `src/quic/streams.cpp`
- related test files and test-hook headers

This lane relies on existing fault-injection patterns and narrow additions where
needed to deterministically cover external-library and error-only branches.

## Test Design

### Test Layout

Prefer extending the existing suites:

- `tests/quic_http09_test.cpp`
- `tests/quic_http09_client_test.cpp`
- `tests/quic_http09_server_test.cpp`
- `tests/quic_http09_runtime_test.cpp`
- `tests/quic_core_test.cpp`
- `tests/quic_packet_crypto_test.cpp`
- `tests/quic_protected_codec_test.cpp`
- `tests/quic_crypto_stream_test.cpp`
- `tests/quic_streams_test.cpp`
- `tests/quic_tls_adapter_contract_test.cpp`
- `tests/quic_test_utils.h`

### Test Style

- Follow TDD for each branch family or cleanup.
- Keep each test narrowly named and behavior-focused.
- Prefer direct deterministic setup over large end-to-end scaffolding.
- Use white-box access only where the public surface makes a branch
  nondeterministic or impractical.
- When a fault hook is needed, keep each test mapped to one concrete failure
  mode.

## Verification

Every success claim must be backed by a fresh full run:

```bash
nix develop -c zig build test
nix develop -c zig build coverage
nix develop -c bash -lc '"$LLVM_COV" report \
  .zig-cache/o/<coverage-test-artifact>/coquic-coverage-tests \
  --instr-profile=coverage/coquic.profdata \
  --ignore-filename-regex="(^/nix/store/|/tests/|/\.zig-cache/)" \
  --show-branch-summary'
```

Success means:

- `zig build test` exits `0`
- `zig build coverage` exits `0`
- every owned source file in the report shows `100.00%` line, region, and
  branch coverage
- the `TOTAL` row shows `100.00%` line, region, and branch coverage

## File Shape

Likely production files to modify:

- `src/quic/http09_runtime.cpp`
- `src/quic/http09.cpp`
- `src/quic/http09_client.cpp`
- `src/quic/http09_server.cpp`
- `src/quic/connection.cpp`
- `src/quic/protected_codec.cpp`
- `src/quic/packet_crypto_quictls.cpp`
- `src/quic/tls_adapter_quictls.cpp`
- `src/quic/crypto_stream.cpp`
- `src/quic/crypto_stream.h`
- `src/quic/streams.cpp`
- existing test-hook headers near codec or TLS boundaries, if needed

Likely test files to modify:

- `tests/quic_http09_test.cpp`
- `tests/quic_http09_client_test.cpp`
- `tests/quic_http09_server_test.cpp`
- `tests/quic_http09_runtime_test.cpp`
- `tests/quic_core_test.cpp`
- `tests/quic_packet_crypto_test.cpp`
- `tests/quic_protected_codec_test.cpp`
- `tests/quic_crypto_stream_test.cpp`
- `tests/quic_streams_test.cpp`
- `tests/quic_tls_adapter_contract_test.cpp`
- `tests/quic_test_utils.h`

## Risks

- `100.00%` branch coverage is sensitive to defensive code around OS and TLS
  boundaries; the seam scope must stay narrow to avoid brittle tests.
- The runtime file can attract over-engineering if its helper extraction grows
  beyond local, single-purpose functions.
- White-box tests can become coupled to implementation detail if they are not
  targeted to specific branch families.
- The final few uncovered branches may be cleaner to delete than to simulate if
  they are provably dead fallback paths.

## Recommended Execution Order

1. Close `src/quic/http09_runtime.cpp`.
2. Finish the smaller HTTP/0.9 files.
3. Close the remaining `src/quic/connection.cpp` branches.
4. Finish codec, crypto, TLS, and header-only tails.
5. Re-run full coverage after each batch and chase the remaining misses to
   zero.
