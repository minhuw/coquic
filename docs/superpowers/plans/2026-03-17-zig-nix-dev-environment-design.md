# Zig + Nix Dev Environment Design

## Status

Approved on 2026-03-17.

## Context

`coquic` is a new repository with only a README. The first project task is to establish a reproducible development environment for a C++20 codebase while intentionally exploring Zig as the build system instead of CMake.

## Goal

Create a minimal, repeatable development environment that lets contributors enter a Nix shell and build a starter C++20 target through Zig's `build.zig`.

## Decisions

### Build System

- Use `build.zig` as the only project build entrypoint.
- Build C++ sources with Zig and set the language standard explicitly to C++20.
- Do not add `cmake` or `ninja`.

### Development Environment

- Use `flake.nix` to define `devShells.default`.
- Include `zig`, `clang-tools`, `lldb`, and `pkg-config` in the shell.
- Keep the initial toolchain narrow and avoid protocol-specific or crypto dependencies.

### Project Files

- Add `build.zig` for the executable target and an initial test step.
- Add `.gitignore` entries for `.zig-cache`, `zig-out`, and other local build artifacts.
- Add minimal starter C++ source files needed to verify the toolchain end to end.

### Editor Support

- Optimize for VS Code via the Nix shell plus `clangd`.
- Do not design around CMake-specific VS Code integrations.

## Verification

The first environment verification commands are:

```bash
nix develop -c zig version
nix develop -c zig build
nix develop -c zig build test
```

If any of these fail, fix the environment layer before adding protocol code.

## Non-Goals

- No QUIC implementation details yet
- No crypto libraries yet
- No CI integration yet
- No dependency manager beyond Nix and Zig

## Rationale

This setup keeps the experiment focused on two controlled variables: a C++20 implementation language and Zig as the build system, while Nix provides a reproducible shell. It accepts some editor and ecosystem friction in exchange for a smaller, more intentional starting point.
