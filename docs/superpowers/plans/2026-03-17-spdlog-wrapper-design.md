# spdlog Wrapper Spike Design

## Status

Approved on 2026-03-17.

## Context

`coquic` already uses Nix-managed external dependencies for the build and has a
small OpenSSL spike that proves we can wire third-party C++ libraries through
the Zig build. The next dependency we want is a logging library, but we do not
want `spdlog` calls to spread directly through the codebase yet.

We want a tiny project-owned wrapper that proves the dependency works and keeps
future logging design changes localized.

## Goal

Add `spdlog` as a Nix-managed dependency and expose it through a tiny project
wrapper so the starter executable and tests can prove the logging dependency is
wired correctly.

## Decisions

### Dependency Management

- Add `spdlog` to `flake.nix`.
- Also expose the `dev`-output include and pkg-config metadata from the shell,
  because `spdlog.pc` lives under `spdlog.dev`.
- Export the `fmt` include and pkg-config paths too, because the packaged
  `spdlog` build depends on external `fmt`.
- Keep Zig link resolution driven by pkg-config, consistent with the OpenSSL
  spike.

### Build Integration

- Compile project code against exported include paths for:
  - `spdlog`
  - `fmt`
- Use Zig's `linkSystemLibrary2` with pkg-config enabled for `spdlog`.
- Let pkg-config pull in the transitive `fmt` link dependency.

### Wrapper Shape

- Add a tiny project-owned logging facade in `src/coquic.h` and
  `src/coquic.cpp`.
- Keep the API intentionally small:
  - `void init_logging();`
  - `bool logging_ready();`
- `init_logging()` only needs to configure the default logger and mark the
  wrapper ready.
- No structured logging, file sinks, async logging, or config system yet.

### Validation

- Touch the wrapper once from `src/main.cpp`.
- Add one GoogleTest that verifies:
  - logging is not ready before initialization
  - logging is ready after initialization
- This proves the wrapper and dependency both work without introducing real
  application behavior.

## Verification

The spike must pass:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build
nix develop -c zig build test
nix develop -c zig build coverage
```
