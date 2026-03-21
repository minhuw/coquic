# 100 Percent Coverage Design

## Status

Approved in conversation on 2026-03-21.

## Context

The current LLVM coverage reports show that the codebase is no longer blocked by
the TLS adapter work. Both adapters are already fully covered, but the repo is
still short of 100% overall coverage on both supported TLS backends.

Current totals from fresh coverage runs on 2026-03-21:

- `quictls`
  - function coverage: `98.86%` (`522/528`)
  - line coverage: `94.57%` (`8235/8708`)
  - region coverage: `94.19%` (`4212/4472`)
  - branch coverage: `91.94%` (`2830/3078`)
- `boringssl`
  - function coverage: `98.88%` (`531/537`)
  - line coverage: `94.57%` (`8235/8708`)
  - region coverage: `94.23%` (`4248/4508`)
  - branch coverage: `92.02%` (`2858/3106`)

The remaining gaps are concentrated in:

- shared files
  - `src/quic/http09_runtime.cpp`
  - `src/quic/http09.cpp`
  - `src/quic/http09_client.cpp`
  - `src/quic/http09_server.cpp`
  - a small tail in `src/quic/connection.cpp`
- backend-specific files
  - `src/quic/packet_crypto_quictls.cpp`
  - `src/quic/packet_crypto_boringssl.cpp`

Files already at or effectively closed to the goal include:

- `src/quic/tls_adapter_quictls.cpp`
- `src/quic/tls_adapter_boringssl.cpp`
- `src/quic/transport_parameters.cpp`
- `src/quic/core.cpp`
- `src/quic/crypto_stream.cpp`

The user approved small behavior-preserving cleanups where a branch is truly
unreachable or exists only as defensive fallback.

## Goal

Raise LLVM source-based coverage to:

- `100.00%` line coverage
- `100.00%` region coverage
- `100.00%` branch coverage

for both `quictls` and `boringssl`, while preserving intended behavior.

## Non-Goals

- adding unrelated product functionality
- broad refactors outside the current coverage blockers
- weakening validation or error handling just to satisfy coverage
- introducing test-only production behavior
- changing external semantics except for tiny cleanups to remove unreachable
  fallback control flow

## Decisions

### Coverage Strategy

- Use a hybrid approach:
  - prefer targeted tests for real behavior
  - allow very small production cleanups for unreachable fallback paths
- Keep the work split into:
  - a shared coverage lane for the HTTP/0.9 and connection code
  - a backend-specific lane for packet crypto
- Reuse existing testing style and existing fault-injection seams instead of
  introducing broad new abstractions.

### Shared Coverage Lane

#### `src/quic/http09.cpp`

Close the remaining parser and path-resolution branches with tests in
`tests/quic_http09_test.cpp`.

The added cases should cover:

- invalid absolute URL scheme
- empty remainder after `https://`
- empty authority
- authority without a path, which should normalize to `/`
- invalid request-target forms that fail lexical validation
- request-path resolution edge cases that currently leave raw-absolute and
  lexical-prefix rejection branches uncovered

This file should reach 100% through tests alone.

#### `src/quic/http09_client.cpp`

Close the client endpoint gaps with focused tests in
`tests/quic_http09_client_test.cpp`.

The added cases should cover:

- `on_core_result(...)` failing on `local_error`
- `on_core_result(...)` failing on explicit failed-state events
- unknown stream IDs
- duplicate receive events after a stream is already complete
- zero-request behavior, including immediate completion after handshake
- invalid path resolution under the configured download root
- file-open and post-write failure paths
- `all_streams_complete()` when requests have not yet been issued

Prefer tests over production changes. If file-write failures are otherwise
difficult to induce portably, use small deterministic filesystem setups rather
than broad seams.

#### `src/quic/http09_server.cpp`

Close the server endpoint gaps with focused tests in
`tests/quic_http09_server_test.cpp`.

The added cases should cover:

- repeated receive data on a stream that already has a pending response
- invalid stream classes beyond the already-covered server-initiated case
- chunk pumping edge cases, including empty file responses
- file-read failure handling during chunk emission
- `poll()` and `drain_pending_inputs()` branches that report pending work
  correctly across queued responses

Prefer tests over code changes. If a fallback branch in chunk pumping is
provably unreachable under standard library semantics, a tiny cleanup is
acceptable.

#### `src/quic/http09_runtime.cpp`

This is the largest remaining blocker and should be closed with a mix of tests
and narrow helper extraction.

The current misses are concentrated in:

- argument parsing and defaulting
- authority, host, port, and testcase derivation
- health-check and top-level dispatch branches
- runtime socket/poll/send/receive error handling
- server and client orchestration paths that normal end-to-end tests do not hit

The implementation should:

- add tests in `tests/quic_http09_runtime_test.cpp` for the branches already
  reachable through:
  - `parse_http09_runtime_args(...)`
  - `make_http09_client_core_config(...)`
  - `make_http09_server_core_config(...)`
  - `run_http09_runtime(...)`
- extract only tiny pure or dependency-light helpers from anonymous-namespace
  logic when a branch is otherwise trapped behind `poll`, `recvfrom`,
  `getaddrinfo`, `getenv`, or process exit timing
- avoid a broad I/O abstraction or test-only dependency injection layer

The helper extractions should stay local to the runtime module and exist only to
make existing behavior directly testable.

#### `src/quic/connection.cpp`

The remaining connection gaps are now small. Finish them with white-box tests in
`tests/quic_core_test.cpp` and helper surface in `tests/quic_test_utils.h`.

Use production cleanup only if the last misses are truly unreachable fallback
returns or non-exhaustive control-flow scaffolding.

### Backend-Specific Coverage Lane

#### Packet Crypto

Use the existing fault injector in `src/quic/packet_crypto_test_hooks.h` and
extend `tests/quic_packet_crypto_test.cpp` to close the remaining misses in:

- `src/quic/packet_crypto_quictls.cpp`
- `src/quic/packet_crypto_boringssl.cpp`

The preferred approach is:

- cover each backend's remaining setup and failure branches with explicit fault
  cases
- keep the production implementations unchanged unless a backend-specific
  fallback is genuinely unreachable
- extend the existing fault enum only if a remaining branch cannot be reached by
  the current hook surface

No new broad packet-crypto seam should be introduced.

### Small Cleanups

Allowed cleanups are limited to:

- removing unreachable fallback returns after an exhaustive switch or enum path
- extracting a tiny helper from runtime code to make existing logic testable
- replacing structurally dead control flow with clearer exhaustive logic

Disallowed cleanups include:

- changing public semantics to manufacture coverage
- introducing runtime flags, environment variables, or test knobs solely for
  coverage
- restructuring unrelated code while touching the coverage areas

## Test Design

### Test Layout

Prefer extending the existing suites:

- `tests/quic_http09_test.cpp`
- `tests/quic_http09_client_test.cpp`
- `tests/quic_http09_server_test.cpp`
- `tests/quic_http09_runtime_test.cpp`
- `tests/quic_packet_crypto_test.cpp`
- `tests/quic_core_test.cpp`
- `tests/quic_test_utils.h`

Possible source changes:

- `src/quic/http09.cpp`
- `src/quic/http09_client.cpp`
- `src/quic/http09_server.cpp`
- `src/quic/http09_runtime.cpp`
- `src/quic/connection.cpp`
- `src/quic/packet_crypto_test_hooks.h`

### Test Style

- Follow TDD for each added behavior or cleanup.
- Keep tests narrowly named and behavior-focused.
- Prefer direct deterministic inputs over large end-to-end scaffolding.
- Use white-box access only where public behavior is impractical for the final
  uncovered branch.
- Keep runtime helper extraction minimal and local; test the helper directly
  rather than simulating the entire runtime loop when that is not necessary.

## Verification

The completed implementation must prove the claim with fresh verification for
both backends and repo checks:

```bash
nix develop -c zig build -Dtls_backend=quictls test
nix develop -c zig build -Dtls_backend=quictls coverage
nix develop -c zig build -Dtls_backend=boringssl test
nix develop -c zig build -Dtls_backend=boringssl coverage
pre-commit run clang-format --all-files --show-diff-on-failure
pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
```

Success means:

- both backend test runs exit `0`
- both backend coverage runs exit `0`
- each backend reports `100.00%` for line, region, and branch totals
- format and lint checks pass

## Risks And Constraints

- `http09_runtime.cpp` is large enough that unstructured test additions would
  become brittle; helper extraction must stay disciplined and local.
- literal 100% branch coverage is sensitive to defensive fallback code; cleanup
  must distinguish between truly unreachable paths and real error handling.
- backend-specific packet-crypto coverage can diverge slightly because the
  OpenSSL and BoringSSL implementations are not identical; tests must verify the
  correct backend behavior without assuming the same internal structure.

## Recommended Execution Order

1. Close `http09.cpp`, `http09_client.cpp`, and `http09_server.cpp`.
2. Close the backend-specific packet-crypto gaps with the existing fault seam.
3. Finish the small remaining `connection.cpp` tail.
4. Extract minimal runtime helpers and close `http09_runtime.cpp`.
5. Run verification on both backends, inspect any residual misses, and make a
   final cleanup pass only where justified.
