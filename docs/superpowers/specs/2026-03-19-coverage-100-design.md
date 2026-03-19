# 100 Percent Coverage Design

## Status

Approved in conversation on 2026-03-19.

## Context

The current repo-level LLVM coverage report is strong overall but not complete:

- line coverage: 91.37% (`3770/4126`)
- branch coverage: 87.37% (`1218/1394`)
- region coverage: 92.63% (`1987/2145`)

The largest gaps are concentrated in a small number of files:

- `src/quic/connection.cpp`
- `src/quic/tls_adapter_quictls.cpp`
- `src/quic/transport_parameters.cpp`
- smaller gaps in `src/quic/core.cpp`, `src/quic/crypto_stream.cpp`, and
  `src/quic/demo_channel.cpp`

The user wants all three reported totals to reach 100%. They also explicitly
approved small cleanup refactors and removal of genuinely unreachable code when
that is cleaner than manufacturing artificial tests.

## Goal

Raise LLVM source-based coverage for the current codebase to:

- 100% line coverage
- 100% branch coverage
- 100% region coverage

while preserving production behavior except for narrowly-scoped cleanups that
remove dead or unreachable paths.

## Non-Goals

- adding new product functionality unrelated to coverage
- broad architecture changes across the QUIC stack
- weakening error handling just to satisfy coverage
- introducing test-only behavior into production builds
- changing runtime semantics unless the current path is unreachable or
  needlessly untestable

## Decisions

### Coverage Strategy

- Prefer tests over code changes whenever a branch reflects real behavior.
- Use small production refactors only when they make existing behavior
  observable or remove unreachable fallback code.
- Treat enum fallthrough fallbacks and impossible default returns as dead code
  candidates rather than mandatory test targets.
- Drive coverage from the public API where feasible, then use the repo's
  established white-box testing style for hard-to-reach state transitions.
- Add deterministic test seams only for code that cannot be reliably exercised
  through public behavior, especially `quictls` adapter failure branches.

### Connection Coverage

`src/quic/connection.cpp` has many untested parser and failure branches plus a
few fallback returns that look unreachable.

The implementation should:

- add focused tests for:
  - malformed initial packet headers
  - truncated connection ID and length fields
  - unsupported long-header packet types and versions
  - invalid token and payload length declarations
  - failed receive behavior after terminal state
  - failed `process_inbound_packet(...)` and `sync_tls_state()` paths
  - transport-parameter validation failures after peer parameters become ready
  - outbound datagram failure paths when required secrets or serialization fail
- continue using white-box access patterns already present in
  `tests/quic_test_utils.h`
- remove unreachable fallback returns such as impossible enum fallthroughs when
  they only exist to satisfy control-flow completeness and do not represent real
  runtime behavior

### Transport Parameter Coverage

`src/quic/transport_parameters.cpp` is mostly pure logic and should reach 100%
through tests alone.

The implementation should add coverage for:

- optional parameter serialization, including retry source connection ID
- unknown parameter preservation behavior during parse
- malformed parameter headers and truncated bodies
- invalid encoded integer payloads
- all validation failure branches:
  - missing initial source connection ID
  - wrong initial source connection ID
  - too-small UDP payload size
  - forbidden client-only and server-only parameter combinations
  - missing or mismatched original destination connection ID
  - expected retry source connection ID missing or mismatched
  - unexpected retry source connection ID

No production refactor should be necessary beyond tiny cleanup if a dead
fallback exists.

### TLS Adapter Coverage

`src/quic/tls_adapter_quictls.cpp` contains the hardest branches because many
depend on OpenSSL/quictls internals or callback wiring failures that normal
handshake tests do not trigger.

The implementation should add a narrow internal test seam modeled on existing
fault-injection patterns in:

- `src/quic/packet_crypto_test_hooks.h`
- `src/quic/protected_codec_test_hooks.h`

The seam should support deterministic coverage of:

- sticky-error early returns
- null `ssl_` handling
- post-handshake application processing failure
- callback entrypoints with missing app data
- unsupported cipher-suite handling
- `on_add_handshake_data(...)` early-data rejection
- `on_send_alert(...)`
- initialization failures for identity loading and SSL setup when they cannot be
  induced portably through public configuration alone

The seam must remain:

- thread-local
- opt-in
- test-only in spirit
- behavior-preserving when inactive

It should be scoped no wider than needed to cover current unreachable branches.

### Small-Gap Files

The remaining files should be closed with straightforward tests or tiny
cleanups:

- `src/quic/core.cpp`
  - cover move constructor and move assignment with a simple ownership-transfer
    test
- `src/quic/crypto_stream.cpp`
  - cover empty send buffer, zero-size frame budget, empty receive push,
    overflow rejection, and duplicate/overlap handling
- `src/quic/demo_channel.cpp`
  - cover direct send on ready channels, pre-handshake queued flush path, the
    `outbound.empty()` retry path after handshake completion, and partial-frame
    buffering behavior

## Test Design

### Test Layout

Prefer extending existing test files:

- `tests/quic_core_test.cpp`
- `tests/quic_crypto_stream_test.cpp`
- `tests/quic_demo_channel_test.cpp`
- `tests/quic_transport_parameters_test.cpp`

Add a dedicated TLS adapter test file if needed:

- `tests/quic_tls_adapter_test.cpp`

Reuse `tests/quic_test_utils.h` for shared helpers and add only minimal helper
surface needed to keep new tests readable.

### Test Style

- Keep tests behavior-focused and narrowly named.
- For white-box tests, touch private state only when public API would make the
  target branch impractical or nondeterministic.
- Prefer direct construction of malformed byte buffers over overly indirect test
  setup.
- For TLS fault coverage, one test should target one injected failure mode.

### Verification

The completed implementation must prove the claim with fresh commands:

```bash
nix develop -c zig build test
nix develop -c zig build coverage
```

Success means:

- `zig build test` exits 0
- `coverage/html/index.html` reports 100.00% for line, region, and branch
  totals

## File Shape

- Modify: `src/quic/connection.cpp`
- Modify: `src/quic/tls_adapter_quictls.cpp`
- Possibly modify: `src/quic/connection.h`
- Possibly modify: `src/quic/tls_adapter.h`
- Create or modify test hooks adjacent to the TLS adapter as needed
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_crypto_stream_test.cpp`
- Modify: `tests/quic_demo_channel_test.cpp`
- Modify: `tests/quic_transport_parameters_test.cpp`
- Possibly create: `tests/quic_tls_adapter_test.cpp`
- Possibly modify: `tests/quic_test_utils.h`

## Risks And Constraints

- 100% branch coverage is sensitive to callback glue and defensive fallback code;
  some code deletion may be cleaner than trying to synthesize impossible states.
- TLS adapter coverage can become brittle if the test seam is too broad; keep it
  as narrow and explicit as the existing fault injectors.
- White-box tests must not lock the design into poor boundaries; if a tiny
  helper extraction improves testability without changing semantics, that is
  acceptable.

## Recommended Execution Order

1. Close the pure-logic transport parameter and crypto stream gaps.
2. Close the demo channel and core gaps.
3. Add targeted connection parser/state tests and remove dead fallback branches.
4. Add the TLS adapter fault seam and tests.
5. Run full coverage, inspect remaining misses, and do a final cleanup pass.
