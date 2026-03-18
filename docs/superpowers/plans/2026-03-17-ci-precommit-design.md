# CI + Pre-Commit Design

## Status

Approved on 2026-03-17.

## Context

`coquic` already builds a minimal C++20 executable and smoke test through `build.zig`, and `flake.nix` defines the local development shell. The next setup task is to make formatting, linting, building, and testing reproducible in both local development and GitHub Actions without duplicating tool definitions outside Nix.

## Goal

Add a Nix-backed GitHub Actions workflow and Nix-managed pre-commit hooks so contributors can use the same format, lint, build, and test flow locally and in CI.

## Decisions

### CI Runtime

- Use GitHub Actions as the CI system.
- Run CI on `ubuntu-latest`.
- Install Nix with `DeterminateSystems/nix-installer-action`.
- Enable binary cache support with `DeterminateSystems/magic-nix-cache-action`.
- Use one CI job with four ordered steps: format check, lint, build, and test.

### CI Commands

- Run all project commands through `nix develop` for parity with the local shell.
- Use pre-commit for the format and lint checks so CI reuses the same hook definitions as local development.
- Keep build and test as separate CI steps for clearer failure reporting.

### Pre-Commit Integration

- Manage pre-commit through Nix with `cachix/git-hooks.nix`.
- Extend `flake.nix` so entering `nix develop` installs the generated hooks automatically.
- Avoid committing a handwritten `.pre-commit-config.yaml`; let Nix generate it.

### Formatting And Linting

- Add `.clang-format` as the canonical formatting policy for C++ sources.
- Add `.clang-tidy` as the canonical lint policy.
- Use `clang-format` for formatting.
- Use `clang-tidy` for linting.
- Expose the lint hook through a repository-specific pre-commit hook id, `coquic-clang-tidy`, while keeping the underlying tool as `clang-tidy`.
- Provide a small repository script that invokes `clang-tidy` with the C++20 flags needed by the current Zig-based build, so linting works without depending on a generated `compile_commands.json`.

### Documentation

- Update `README.md` with the local workflow:
  - enter the shell with `nix develop`
  - rely on automatic hook installation
  - run format/lint through `pre-commit`
  - run build/test through Zig

## Verification

The implementation is complete when these commands pass locally:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build
nix develop -c zig build test
```

The GitHub Actions workflow must run the same four checks successfully on pushes and pull requests.

## Non-Goals

- No migration away from `build.zig`
- No attempt to generate or maintain a full `compile_commands.json` pipeline yet
- No expansion beyond the current Linux CI target

## Rationale

This design keeps Nix as the source of truth for tools and hook definitions while preserving the current Zig-based build flow. It minimizes duplicated configuration, keeps local and CI behavior aligned, and gives a small repository a clear linear CI signal: format, lint, build, then test.

## References

- https://github.com/DeterminateSystems/nix-installer-action
- https://github.com/DeterminateSystems/magic-nix-cache
- https://github.com/cachix/git-hooks.nix
- https://docs.github.com/actions/reference/workflows-and-actions/workflow-syntax
