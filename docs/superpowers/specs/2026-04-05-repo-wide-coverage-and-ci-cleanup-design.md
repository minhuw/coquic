# Repo-Wide 100% Coverage And CI Cleanup Design

## Goal

Raise the current CI target to literal repo-wide `100%` line, branch, and region
coverage while preserving existing behavior and keeping `.github/workflows/ci.yml`
clean without weakening lint or coverage enforcement.

## Scope

In scope:

- The exact CI path in [.github/workflows/ci.yml](/home/minhu/projects/coquic/.github/workflows/ci.yml):
  `clang-format`, `coquic-clang-tidy`, `zig build`, and `zig build coverage`
- All source currently counted by the LLVM coverage run
- Small production seams only where a remaining branch is not deterministically
  reachable from an existing public API

Out of scope:

- Coverage exclusions or report filtering changes
- New `NOLINT` suppressions added just to silence CI
- Unrelated refactoring outside the uncovered or lint-sensitive surfaces

## Current Gaps

Fresh coverage on `main` at `a124fe2` shows the remaining non-100% files are:

- `src/quic/connection.cpp`
- `src/quic/connection.h`
- `src/quic/qlog/json.cpp`
- `src/quic/qlog/session.cpp`
- `src/quic/qlog/sink.cpp`
- `src/quic/tls_adapter_quictls.cpp`

Fresh local CI checks show:

- `clang-format` already passes
- `coquic-clang-tidy` already passes

That means the work is primarily about closing the residual coverage gaps while
keeping the current lint state intact.

## Design Principles

1. Keep behavior unchanged unless a test seam requires a tiny internal API.
2. Put tests in the file that already owns the behavior instead of building a new
   harness.
3. Prefer direct unit coverage over broad integration tests when the remaining
   branches are pure formatting, guard, or state-transition logic.
4. Add no config changes that reduce CI strictness.

## Architecture

### QLOG Serialization

`src/quic/qlog/json.cpp` remains a pure serialization unit. The missing coverage
comes from unvisited frame variants and optional-field combinations, not from
architectural defects. The right fix is broader direct unit coverage in
`tests/quic_qlog_test.cpp`.

Coverage additions will target:

- Every remaining `Frame` variant serialized by `serialize_packet_snapshot`
- Non-printable ALPN values that omit `string_value`
- ALPN payload combinations where only local, only peer, only chosen, or mixed
  values are present
- `PacketSnapshot` and `RecoveryMetricsSnapshot` combinations that currently miss
  optional-field branches

No production refactor is expected here.

### QLOG Session

`src/quic/qlog/session.cpp` is mostly covered except for:

- Preamble write failure during `Session::try_open`
- First-call vs repeated-call paths for the `mark_*_emitted()` flags

The repeated flag paths can be covered directly with unit tests if session
construction is available to tests. The preamble write failure is difficult to
exercise deterministically through the filesystem alone.

Design choice:

- Add a narrow internal seam that allows tests to construct a `Session` with a
  controlled sink or to route `try_open` through an injectable sink creator
- Keep the public `Session::try_open(...)` production API unchanged
- Keep the seam internal to qlog/session ownership and reuse it only from
  `tests/quic_qlog_test.cpp`

### QLOG Sink

`src/quic/qlog/sink.cpp` only misses:

- Writing after the sink has already become unhealthy
- The trivial `path()` accessor

These should be covered directly in `tests/quic_qlog_test.cpp` without production
changes.

### Connection Flow Control And QLOG Guards

`src/quic/connection.cpp` and `src/quic/connection.h` only have a few residual
branches left relative to the size of the file. The remaining gaps are in
focused state-machine behavior, especially `ConnectionFlowControlState`.

Design choice:

- Extend the existing `ConnectionFlowControlState` tests in
  `tests/quic_core_test.cpp`
- Keep tests local to the current owner file instead of adding another
  connection-specific test suite
- Use existing test peers and direct state setup for remaining qlog guard paths
  if any survive after the qlog unit coverage is expanded

No broad connection refactor is planned.

### QUIC-TLS Adapter

`src/quic/tls_adapter_quictls.cpp` already has deep test coverage through
`tests/quic_tls_adapter_contract_test.cpp` and the test-hook surface in
`src/quic/tls_adapter_quictls_test_hooks.h`.

Design choice:

- Close the remaining branches through the existing contract tests and fault
  injector
- Only add a tiny helper in the existing test-hook surface if one final branch
  still cannot be reached cleanly
- Avoid introducing a second TLS harness or changing runtime TLS behavior

## File Ownership

Expected files to modify:

- `docs/superpowers/specs/2026-04-05-repo-wide-coverage-and-ci-cleanup-design.md`
- `tests/quic_qlog_test.cpp`
- `tests/quic_core_test.cpp`
- `tests/quic_tls_adapter_contract_test.cpp`
- `src/quic/qlog/session.h`
- `src/quic/qlog/session.cpp`

Additional files that may be touched only if verification shows one remaining
branch cannot be covered cleanly with the existing hooks:

- `src/quic/qlog/sink.h`
- `src/quic/tls_adapter_quictls_test_hooks.h`
- `src/quic/tls_adapter_quictls.cpp`

## Testing Strategy

### QLOG Tests

`tests/quic_qlog_test.cpp` should become the exhaustive owner for qlog helper
behavior:

- Serializer branch coverage for all qlog-supported frames
- ALPN formatting edge cases
- Packet snapshot optional-field coverage
- Recovery metrics optional-field coverage
- Session repeated-mark idempotence
- Session write failure on preamble
- Sink disabled-write and `path()` access

### Core QUIC Tests

`tests/quic_core_test.cpp` should add narrow state-machine tests rather than new
integration scenarios:

- Remaining `ConnectionFlowControlState` pending/sent/acknowledged/lost paths
- Any residual qlog emission guards that still count toward `connection.cpp`

### TLS Contract Tests

`tests/quic_tls_adapter_contract_test.cpp` should close the remaining
`tls_adapter_quictls.cpp` branches using:

- Existing fault injection
- Existing static callback entry points
- Existing test-peer helpers

## Verification

Each change follows TDD:

1. Add one failing test for one uncovered behavior.
2. Run the narrowest target that proves the failure.
3. Implement the smallest required code change.
4. Rerun the narrow target until it passes.
5. Move to the next uncovered behavior.

Final acceptance requires all of:

- `nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure`
- `nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure`
- `nix develop -c zig build`
- `nix develop -c zig build coverage`

Success is only when the refreshed coverage totals report `100.00%` for line,
branch, and region coverage repo-wide.

## Risks And Controls

Risk: tests become brittle by targeting incidental control flow.

Control:

- Prefer pure unit tests for pure serializers and state machines.
- Add seams only where branch reachability is otherwise nondeterministic.

Risk: production seams expand beyond their narrow purpose.

Control:

- Keep seams private or internal.
- Preserve existing production entry points and behavior.

Risk: chasing 100% creates unrelated cleanup churn.

Control:

- Limit file edits to the listed uncovered surfaces.
- Treat current passing lint as a regression boundary, not an invitation to
  refactor broadly.

## Implementation Readiness

This design is scoped to a single implementation plan. The work is concentrated
in three existing test files plus, at most, one or two tiny internal seams.
