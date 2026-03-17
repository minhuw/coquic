# GoogleTest + LLVM Coverage Design

## Status

Approved on 2026-03-17.

## Context

`coquic` currently has Nix-backed formatting, clang-based linting, a Zig C++20
build, and a smoke-test executable. It does not yet have a real C++ unit test
framework or a coverage reporting pipeline, so the CI `Test` step only proves
that a trivial executable runs.

## Goal

Add a real C++ unit test framework with GoogleTest and generate LLVM
source-based coverage reports locally and in GitHub Actions without breaking the
existing Nix + Zig developer workflow.

## Decisions

### Test Framework

- Use GoogleTest from Nix instead of a header-only test library.
- Link tests against `gtest_main`.
- Replace the current smoke test with a real GoogleTest binary in `tests/`.

### Build Structure

- Extract project code under test into a small reusable library target.
- Link that library into both the main `coquic` executable and the GoogleTest
  test runner.
- Keep `zig build` as the single build entry point.

### Nix Environment

- Add `gtest` and LLVM tools to `flake.nix`.
- Export the required include, library, and coverage tool paths from the Nix
  dev shell so `build.zig` can consume them deterministically in local
  development and CI.
- Keep pre-commit, lint, and formatting behavior unchanged.

### Coverage

- Use LLVM source-based coverage with:
  - `-fprofile-instr-generate`
  - `-fcoverage-mapping`
  - `llvm-profdata`
  - `llvm-cov`
- Add a `zig build coverage` target that:
  1. builds the GoogleTest runner with coverage instrumentation,
  2. runs the tests,
  3. merges raw profile data,
  4. writes an LCOV report,
  5. writes an HTML coverage report.
- Scope the coverage report to project sources under `src/` and exclude Nix
  store paths, test files, and Zig cache paths.

### CI

- Keep the four validation checks visible in GitHub Actions:
  - `Format Check`
  - `Lint`
  - `Build`
  - `Test`
- Make the `Test` step run the coverage target so the coverage artifacts are
  always generated when tests pass.
- Upload the generated HTML and LCOV outputs as workflow artifacts instead of
  introducing an external reporting service.

## First Tested Unit

The framework needs at least one project-owned unit to validate the plumbing.
The initial unit will be a tiny library function that returns the project name.
This keeps the behavior minimal while proving that:

- the application code is linkable as a reusable library,
- GoogleTest assertions run correctly,
- the coverage report includes project source lines.

## Verification

The completed setup must pass:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build
nix develop -c zig build test
nix develop -c zig build coverage
```

The GitHub Actions workflow should also upload:

- `coverage/html/`
- `coverage/lcov.info`
