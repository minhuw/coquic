# 2026-04-08 Repo-Wide Test Hierarchy Redesign

## Goal

Reorganize the repository test suite into a domain-oriented hierarchy with smaller
translation units and a small number of area-specific GoogleTest executables.
The primary goal is maintainability and clearer ownership boundaries. Reduced
`clang-tidy` wall time is an intended side effect, especially for the current
`tests/quic_core_test.cpp` bottleneck.

## Current Problems

- The `tests/` directory is flat, mixing unrelated domains.
- `tests/quic_core_test.cpp` is a single large translation unit and currently
  dominates `clang-tidy` wall clock.
- `tests/quic_http09_runtime_test.cpp` is also large and covers many unrelated
  runtime concerns in one file.
- The build graph in `build.zig` has one explicit flat test file list and one
  main test binary, which does not reflect domain boundaries in the codebase.
- Shared helpers exist, but the overall test structure does not make their scope
  obvious.

## Non-Goals

- No protocol or runtime behavior changes.
- No weakening of `.clang-tidy` checks.
- No one-binary-per-file explosion.
- No broad refactoring of production code unless required to preserve test build
  correctness after moving helpers.

## Recommended Architecture

### Directory Layout

The test tree will be reorganized under `tests/` by domain:

```text
tests/
  support/
    quic_test_utils.h
    core/
      connection_fixtures.h
      packet_fixtures.h
    http09/
      runtime_fixtures.h

  smoke/
    smoke_test.cpp

  core/
    connection/
      handshake_test.cpp
      stream_test.cpp
      flow_control_test.cpp
      ack_test.cpp
      migration_test.cpp
      path_validation_test.cpp
      retry_version_test.cpp
      key_update_test.cpp
      zero_rtt_test.cpp
      connection_id_test.cpp
    recovery/
      recovery_test.cpp
      congestion_test.cpp
    packets/
      packet_test.cpp
      packet_number_test.cpp
      plaintext_codec_test.cpp
      protected_codec_test.cpp
      frame_test.cpp
      transport_parameters_test.cpp
      varint_test.cpp
    streams/
      streams_test.cpp
      crypto_stream_test.cpp

  tls/
    packet_crypto_test.cpp
    tls_adapter_contract_test.cpp

  http09/
    protocol/
      http09_test.cpp
      server_test.cpp
      client_test.cpp
    runtime/
      startup_test.cpp
      config_test.cpp
      io_test.cpp
      routing_test.cpp
      migration_test.cpp
      preferred_address_test.cpp
      retry_zero_rtt_test.cpp
      interop_alias_test.cpp
      linux_ecn_test.cpp

  http3/
    protocol_test.cpp
    qpack_test.cpp

  qlog/
    qlog_test.cpp
```

This layout is intentionally domain-first. File names should represent stable
behavior clusters, not arbitrary slices like `part1.cpp` or `misc_test.cpp`.

### Test Executables

The repository will move from one main GoogleTest binary to a small set of
area-specific binaries:

- `coquic-tests-smoke`
- `coquic-tests-core`
- `coquic-tests-http09`
- `coquic-tests-http3`
- `coquic-tests-qlog`
- `coquic-tests-tls`

This keeps the number of binaries manageable while reflecting real subsystem
boundaries.

### Build System Shape

`build.zig` will:

- keep a shared helper for constructing a GoogleTest executable from a file list
- replace the flat monolithic test source list with per-area file lists
- make `zig build test` an aggregate step that builds and runs all area binaries
- preserve coverage generation across all test binaries

## Migration Rules

### Shared Helpers

- Shared test support stays under `tests/support/`.
- Existing helper APIs should remain stable where practical to limit churn.
- New helper headers are allowed only when they represent a real shared fixture
  boundary.
- Avoid a single giant replacement for `quic_core_test.cpp` in header form;
  that would only move the problem.

### Splitting Strategy

- Start by splitting `tests/quic_core_test.cpp` into behavior-oriented files.
- Split `tests/quic_http09_runtime_test.cpp` next by runtime concern.
- Move already-small tests into their target directories with minimal content
  changes.
- Prefer moving tests as-is first, then performing only small cleanup needed for
  helper visibility or naming consistency.

### Naming Rules

- Directory names describe the subsystem.
- File names describe the behavior cluster.
- Use `*_test.cpp` consistently.
- Avoid catch-all names such as `misc`, `more`, `extra`, or `partN`.

## Expected Benefits

- Clearer ownership and easier navigation.
- Smaller translation units, especially for core transport tests.
- Better parallelism for `clang-tidy` because more work can complete without one
  giant tail-dominating file.
- More targeted local test execution by domain.
- A build graph that matches repository architecture instead of historical file
  accumulation.

## Risks And Constraints

- Moving tests can break include paths or implicit helper visibility.
- Splitting one large file may expose helper duplication that was previously
  hidden by file-local scope.
- Coverage aggregation must continue to work after introducing multiple test
  executables.
- `zig build test` must remain a single reliable entry point for CI and local
  development.

## Verification Requirements

The implementation will not be considered complete until all of the following
are verified:

- `zig build test` still passes through the aggregate test entry point
- coverage generation still succeeds
- `pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure` still
  passes
- the measured clang-tidy wall time is compared before and after the reorg
- no test behavior regresses during the file moves and executable split

## Implementation Ordering

1. Create the target directory hierarchy.
2. Move shared support into `tests/support/`.
3. Split `quic_core_test.cpp` into domain files under `tests/core/`.
4. Split `quic_http09_runtime_test.cpp` into domain files under
   `tests/http09/runtime/`.
5. Move the remaining smaller tests into the new hierarchy.
6. Update `build.zig` to define the per-area test executables and aggregate test
   step.
7. Run aggregate tests, coverage, and all-files clang-tidy.
8. Measure and report lint timing before and after.

## Scope Boundary

This redesign is one repository-wide test structure project, but it remains
focused: it reorganizes tests and the corresponding build wiring only. If major
production-code refactors become necessary to make the hierarchy work, those
must be treated as narrow compatibility edits, not as an excuse for unrelated
cleanup.
