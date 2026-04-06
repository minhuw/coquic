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

Use `bear` to generate `compile_commands.json` from an actual `zig build test`
invocation, then feed that database into LLVM's parallel `run-clang-tidy`.

### Why This Approach

- `bear` captures the real compile commands emitted during the build instead of
  forcing the repository to duplicate Zig's flags manually.
- `run-clang-tidy` is the supported parallel runner for `clang-tidy` when a
  compilation database exists.
- This fixes both the correctness problem and the serial-execution problem with
  relatively small repository changes.

## Proposed Repository Changes

### 1. Add A Compile Database Refresh Script

Create a repository script, `scripts/refresh-compile-commands.sh`, that:

- runs from the repository root
- checks whether `compile_commands.json` is missing or stale
- refreshes it with `bear -- zig build test`
- removes any previous stale output before regenerating

The staleness check should be simple and deterministic. It should refresh when
`compile_commands.json` is missing or older than inputs that can materially
change compile commands, including:

- `build.zig`
- `flake.nix`
- `flake.lock`
- `.clang-tidy`
- `scripts/run-clang-tidy.sh`

This should optimize for correctness rather than cleverness.

### 2. Replace The Serial Wrapper With A Database-Backed Parallel Wrapper

Update `scripts/run-clang-tidy.sh` so it no longer fabricates per-file compiler
arguments.

Instead it should:

- ensure it is running from the repo root
- exit early when no filenames are supplied
- call `scripts/refresh-compile-commands.sh`
- invoke `run-clang-tidy` against the repository's `compile_commands.json`
- limit analysis to the requested files using a file-regex filter built from the
  incoming pre-commit filenames

The wrapper should keep using the repo-local `.clang-tidy` configuration rather
than embedding check configuration in the script.

### 3. Add Tooling To The Nix Shell

Update `flake.nix` so the default dev shell includes `bear` alongside the
existing clang tooling. This makes compile database generation available both
locally and in CI without depending on host-installed tools.

If `run-clang-tidy` is already provided by the existing clang package, reuse it.
If not, the shell package selection should be adjusted so the LLVM parallel
runner is available from Nix.

### 4. Update CI To Warm The Database Before Lint

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

### Pre-Commit Filename Filtering Must Be Exact

`run-clang-tidy` should still only analyze the files requested by pre-commit.
The wrapper should therefore build a conservative regex from the incoming file
list and pass it to the runner, rather than falling back to repo-wide analysis
for every local commit.

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
