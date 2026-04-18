# Http3 Coverage Phase 1 Design

## Status

Approved in conversation on 2026-04-18.

## Goal

Raise every `src/http3/*` file currently counted by the repo coverage target to
literal `100.00%` line, region, and branch coverage, while preserving runtime
behavior and avoiding coverage exclusions or report filtering changes.

This is phase 1 of the broader repo-wide `100%` coverage effort. Later phases
will cover `http09`/`io` and the remaining `quic` surfaces.

## Current Coverage Snapshot

A fresh `nix develop -c zig build coverage` run on 2026-04-18 produced these
repo-wide totals:

- line coverage: `86.27%` (`28674/33238`)
- region coverage: `87.73%` (`14119/16093`)
- branch coverage: `81.23%` (`9078/11176`)
- function coverage: `93.73%` (`1750/1867`)

The `http3` subsystem is a dominant source of the remaining misses:

- `src/http3/http3_runtime.cpp`: `43.69%` line, `50.11%` region,
  `37.69%` branch
- `src/http3/http3_bootstrap.cpp`: `63.10%` line, `65.40%` region,
  `48.19%` branch
- `src/http3/http3_connection.cpp`: `65.87%` line, `76.74%` region,
  `61.54%` branch
- `src/http3/http3_qpack.cpp`: `63.88%` line, `68.07%` region,
  `56.22%` branch
- `src/http3/http3_server.cpp`: `59.32%` line, `73.03%` region,
  `64.29%` branch
- `src/http3/http3_client.cpp`: `65.85%` line, `81.82%` region,
  `71.25%` branch
- `src/http3/http3_interop.cpp`: `80.46%` line, `88.62%` region,
  `71.43%` branch
- `src/http3/http3_protocol.cpp`: `92.49%` line, `94.71%` region,
  `84.58%` branch

These numbers make `http3` the right first subsystem for the
subsystem-by-subsystem plan.

## Scope

In scope for this phase:

- `src/http3/http3_runtime.cpp`
- `src/http3/http3_bootstrap.cpp`
- `src/http3/http3_client.cpp`
- `src/http3/http3_server.cpp`
- `src/http3/http3_connection.cpp`
- `src/http3/http3_qpack.cpp`
- `src/http3/http3_protocol.cpp`
- `src/http3/http3_interop.cpp`
- existing `tests/http3/*` suites that already own these behaviors
- tiny internal seams only where a branch cannot be reached deterministically
  through the current testable surface

Out of scope for this phase:

- `http09`, `io`, or non-`http3` `quic` coverage work
- coverage exclusions or LLVM report filtering changes
- broad refactors that are not required to make a remaining branch testable
- behavior changes made only to manufacture coverage

## Design Principles

1. Keep changes local to the existing `http3` module and its current tests.
2. Prefer direct unit or loopback tests over wider integration harnesses.
3. Use tests first and add seams second.
4. If a seam is necessary, keep it internal, narrow, and reusable only by the
   existing test owner for that file.
5. Finish the whole `http3` subsystem before moving to the next subsystem.

## File Ownership

The existing `tests/http3/*` layout already matches the production ownership and
should remain the primary test surface.

### Runtime And Bootstrap Ownership

- `tests/http3/runtime_test.cpp` owns:
  - `src/http3/http3_runtime.cpp`
  - runtime-facing branches inside `src/http3/http3_bootstrap.cpp`
- `tests/http3/bootstrap_test.cpp` owns:
  - pure bootstrap and Alt-Svc behavior in `src/http3/http3_bootstrap.cpp`

Coverage themes:

- CLI parsing and invalid invocation branches
- server/client/standalone dispatch
- bootstrap enabled/disabled behavior
- loopback process setup and failure paths
- document-root and output-path failures
- direct bootstrap response behaviors for GET, HEAD, missing files, and
  malformed targets

### Connection And QPACK Ownership

- `tests/http3/connection_test.cpp` owns:
  - `src/http3/http3_connection.cpp`
- `tests/http3/qpack_test.cpp` and `tests/http3/qpack_dynamic_test.cpp` own:
  - `src/http3/http3_qpack.cpp`

Coverage themes:

- request and response stream lifecycle edges
- blocked and unblocked field-section transitions
- malformed peer stream ordering
- reset and stop-sending cleanup paths
- GOAWAY boundaries and interim/final sequencing
- malformed encoder and decoder instructions
- dynamic-table capacity, eviction, and feedback paths

### Wrapper And Protocol Ownership

- `tests/http3/client_test.cpp` owns `src/http3/http3_client.cpp`
- `tests/http3/server_test.cpp` owns `src/http3/http3_server.cpp`
- `tests/http3/protocol_test.cpp` owns `src/http3/http3_protocol.cpp`
- `tests/http3/interop_test.cpp` owns `src/http3/http3_interop.cpp`

Coverage themes:

- wrapper dispatch guards
- unsupported or invalid call sequences
- residual protocol validation branches
- unsupported testcase handling
- remaining loopback download or request-shaping tails

## Batch Plan

Phase 1 should be executed in three internal batches.

### Batch 1: Runtime And Bootstrap

Target files:

- `src/http3/http3_runtime.cpp`
- `src/http3/http3_bootstrap.cpp`

Why first:

- They currently have the worst percentages in the subsystem.
- Their behavior is externally visible and easier to verify with existing
  loopback and parser tests.
- Closing them first removes a large chunk of the subsystem-wide misses.

Expected work:

- extend `tests/http3/runtime_test.cpp`
- extend `tests/http3/bootstrap_test.cpp`
- add tiny internal seams only if process-orchestration or bootstrap helper
  branches are otherwise nondeterministic

### Batch 2: Connection And QPACK

Target files:

- `src/http3/http3_connection.cpp`
- `src/http3/http3_qpack.cpp`

Why second:

- They are large and still materially uncovered, but mostly deterministic once
  the right direct tests exist.
- They should move substantially through test additions alone.

Expected work:

- extend `tests/http3/connection_test.cpp`
- extend `tests/http3/qpack_test.cpp`
- extend `tests/http3/qpack_dynamic_test.cpp`
- avoid production changes unless one branch family is truly unreachable

### Batch 3: Wrapper Tails

Target files:

- `src/http3/http3_client.cpp`
- `src/http3/http3_server.cpp`
- `src/http3/http3_protocol.cpp`
- `src/http3/http3_interop.cpp`

Why last:

- These should shrink quickly after the lower runtime, connection, and QPACK
  layers are fully exercised.
- Leaving them last keeps the early batches focused on the biggest gaps.

Expected work:

- extend `tests/http3/client_test.cpp`
- extend `tests/http3/server_test.cpp`
- extend `tests/http3/protocol_test.cpp`
- extend `tests/http3/interop_test.cpp`

## Seam Policy

Default rule: do not modify production code until a failing test proves the
current surface cannot reach the branch.

Allowed seams:

- tiny helper extraction from anonymous-namespace or file-local logic
- narrow internal test hooks beside the file they support
- deterministic failure injection for runtime/bootstrap paths that depend on
  OS or process behavior

Disallowed seams:

- new public APIs whose only purpose is tests
- generic dependency-injection frameworks
- coverage-only flags that bypass real production logic
- cross-subsystem abstractions introduced solely to make tests easier

## Testing Strategy

Each uncovered behavior should follow TDD:

1. Add one failing test in the file that already owns the behavior.
2. Run the narrowest possible target to confirm the failure.
3. Implement the smallest behavior-preserving change required.
4. Re-run the narrow target until it passes.
5. Periodically rerun `zig build coverage` to measure subsystem progress.

Verification focus during the phase:

- narrow `tests/http3/*` reruns during development
- repeated `zig build coverage` checkpoints after each batch
- no subsystem transition until all `http3` files are at `100.00%`

## Success Criteria

Phase 1 is complete only when:

- every `http3/*` file in the generated coverage report shows `100.00%` line
  coverage
- every `http3/*` file in the generated coverage report shows `100.00%` region
  coverage
- every `http3/*` file in the generated coverage report shows `100.00%` branch
  coverage
- the repo coverage pipeline still runs through the normal `zig build coverage`
  path
- no coverage exclusions or report-filter changes were introduced

## Risks And Controls

Risk: runtime and bootstrap tests become flaky because they rely on timing.

Control:

- prefer deterministic file and parser tests first
- use loopback process tests only where the branch is specifically in runtime
  orchestration
- keep readiness/failure checks explicit and bounded

Risk: connection and QPACK tests become brittle by asserting incidental state.

Control:

- assert externally meaningful events and state transitions
- keep tests narrow and scenario-based
- avoid overfitting to private implementation layout unless a white-box seam is
  already the established repo pattern

Risk: seam growth turns into subsystem refactoring.

Control:

- add seams only after a failing test proves the current surface is inadequate
- keep seam ownership inside the same module and its existing test file
- reject any seam that broadens the public API without runtime value

## Implementation Readiness

This phase is scoped tightly enough for a single implementation plan. It has a
clear batch order, a stable file-ownership model, and an explicit seam policy.
The next step should be a concrete implementation plan for the `http3`
coverage campaign only.
