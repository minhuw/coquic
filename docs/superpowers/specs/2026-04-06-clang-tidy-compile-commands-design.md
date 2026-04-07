# Clang-Tidy Compile Commands And Parallelization Design

## Goal

Reduce local and CI lint latency without weakening the current `clang-tidy`
check set by fixing two structural issues:

- missing `compile_commands.json`
- serial `clang-tidy` execution

The resulting workflow should keep the current checks intact while making the
lint step use real build commands and parallel execution.

## Current Problems

The repository currently runs `clang-tidy` through
`scripts/run-clang-tidy.sh`, which manually fabricates a partial compile
command and invokes `clang-tidy` once per file in a shell loop.

That has three direct costs:

- `clang-tidy` does not see the real compile command that Zig uses for each
  translation unit.
- the hook runs files serially even though `clang-tidy` has a parallel runner
  designed for compilation databases
- large translation units such as `tests/quic_core_test.cpp` dominate commit and
  CI latency because they are analyzed alone and from scratch

The expensive `clang-analyzer-*` and `performance-*` checks are not themselves a
design bug here; they are part of the intended policy and must remain enabled.

## Constraints

- Do not weaken or remove any configured `clang-tidy` checks.
- Keep the existing `pre-commit` hook id, so developer workflow and CI naming
  stay stable.
- Preserve the Zig-based build as the source of truth for compile flags.
- Avoid hand-maintaining a synthetic compile database.
- Keep the solution workable in the Nix dev shell and GitHub Actions CI.

## Recommended Approach

Generate `compile_commands.json` from Zig's real C/C++ compiler invocations by
parsing `zig build compdb --verbose-cc`, then feed that database into parallel
`clang-tidy` execution from the repository wrapper.

### Why This Approach

- `zig build --verbose-cc` exposes the real C/C++ compile commands that Zig
  executes for this project.
- a small repo-local parser can turn that output into a deterministic
  `compile_commands.json` without trying to intercept Zig internals.
- parallel `clang-tidy` execution can be achieved directly from the wrapper once
  each file is analyzed with `-p .`.
- This fixes both the correctness problem and the serial-execution problem with
  relatively small repository changes.

## Proposed Repository Changes

### 1. Add A Compile Database Refresh Pipeline

Create two repository scripts:

- `scripts/refresh-compile-commands.sh`
- `scripts/compile-commands-from-verbose-cc.py`

The refresh script should:

- runs from the repository root
- checks whether `compile_commands.json` is missing or stale
- refreshes it by running `zig build compdb --verbose-cc`
- sends the emitted compile commands into the parser script
- removes any previous stale output before regenerating

The parser script should:

- read verbose `zig clang` lines from standard input
- extract only real compile commands for project source and test files
- serialize a valid `compile_commands.json`
- write one entry per translation unit with the repo root as `directory`

The staleness check should be simple and deterministic. It should refresh when
`compile_commands.json` is missing or older than inputs that can materially
change compile commands, including:

- `build.zig`
- `flake.nix`
- `flake.lock`
- `.clang-tidy`
- `scripts/compile-commands-from-verbose-cc.py`
- `scripts/run-clang-tidy.sh`

This should optimize for correctness rather than cleverness.

### 2. Add A Build-Only Compile Database Step

Update `build.zig` to add a `compdb` step that compiles the main executable and
the GoogleTest binary without running either artifact.

This keeps compile-database generation aligned with the real build graph while
covering both ordinary project sources such as `src/main.cpp` and the GoogleTest
suite while still avoiding the unnecessary cost of executing either program just
to collect compiler arguments.

### 3. Replace The Serial Wrapper With A Database-Backed Parallel Wrapper

Update `scripts/run-clang-tidy.sh` so it no longer fabricates per-file compiler
arguments.

Instead it should:

- ensure it is running from the repo root
- exit early when no filenames are supplied
- call `scripts/refresh-compile-commands.sh`
- invoke `clang-tidy -p "${repo_root}"` for the requested files
- run those `clang-tidy` invocations in parallel using the local machine's CPU
  count rather than a serial shell loop

The wrapper should keep using the repo-local `.clang-tidy` configuration rather
than embedding check configuration in the script.

### 4. Add Tooling To The Nix Shell

Update `flake.nix` so the default dev shell includes the tools needed by the
new refresh and parallel-lint flow. In practice this means:

- Python remains available for the compile-command parser
- the shell should prefer Nix-provided clang tooling over any incompatible
  host-installed alternatives

No host-installed `bear` dependency should remain in the lint path.

### 5. Update CI To Warm The Database Before Lint

Update `.github/workflows/ci.yml` so the lint job refreshes
`compile_commands.json` before invoking the `pre-commit` lint hook.

That makes CI behavior deterministic and avoids relying on hook-internal
database generation as the first step of the lint stage.

The CI lint command itself should remain the existing:

`nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure`

## Expected Behavior

After this change:

- local pre-commit lint uses real compile commands instead of synthetic flags
- `clang-tidy` runs in parallel across translation units
- CI uses the same database-backed workflow
- the current analyzer and performance checks remain enabled

The lint step may still be expensive on very large translation units, but the
major avoidable overhead from missing compile commands and serial execution is
removed.

## Non-Goals

- changing the configured `clang-tidy` checks
- excluding large files from lint
- splitting local and CI lint policies
- introducing a custom compile database generator inside `build.zig`
- weakening repo-wide lint coverage

## Risks And Mitigations

### Build-Backed Database Generation Is Not Free

Refreshing `compile_commands.json` requires a real build invocation, which has a
cost. This is acceptable because:

- the current lint path is already dominated by expensive analysis
- the generated database can be reused until relevant build inputs change
- correctness of compile commands is more important than avoiding a one-time
  setup cost

To keep the verbose-cc output complete, the refresh script should use a
dedicated throwaway Zig cache directory for database generation. That ensures
compile commands are emitted even when the normal build cache is warm.

### Compile Command Parsing Must Be Conservative

The parser should only emit translation units that belong to the repository's
project sources and tests. It should ignore unrelated toolchain output.

### Pre-Commit File Selection Must Stay Narrow

The wrapper should still only analyze the files requested by pre-commit. It
should therefore parallelize only the incoming filenames rather than falling
back to repo-wide analysis for every local commit.

### Captured Commands Must Match The Default Profile

The compile database should be generated using the same default `nix develop`
profile that the existing hook and CI use today. This keeps behavior aligned
with the repo's primary development path.

## Verification

The change is complete when the following are true:

- `compile_commands.json` is generated successfully from the dev shell
- `pre-commit run coquic-clang-tidy --files ...` succeeds using the generated
  database
- `pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure`
  succeeds
- CI is updated to refresh the compile database before lint
- formatting and the existing test suite still pass
