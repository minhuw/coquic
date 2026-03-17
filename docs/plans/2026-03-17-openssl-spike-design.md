# OpenSSL Dependency Spike Design

## Status

Approved on 2026-03-17.

## Context

`coquic` currently has a reproducible Nix development shell, Zig-based C++20
build, GoogleTest-based unit tests, and LLVM coverage reporting. The codebase
does not yet link any external crypto or TLS library, but later QUIC work will
need a TLS and crypto backend.

Before designing the real QUIC crypto layer, we want a tiny dependency spike
that proves we can introduce OpenSSL cleanly through Nix and Zig without adding
any meaningful protocol behavior.

## Goal

Add OpenSSL as a managed dependency in the Nix shell and Zig build, then call a
harmless OpenSSL API from the current starter code so the project proves the
dependency is wired correctly.

## Decisions

### Dependency Management

- Add `openssl` to `flake.nix`.
- Keep `pkg-config` in the shell and let Zig resolve OpenSSL link flags through
  `pkg-config`.
- Export the OpenSSL include directory from the Nix shell so the reusable
  project library can compile sources that include OpenSSL headers.

### Build Integration

- Compile the reusable project library against OpenSSL headers.
- Link the main executable and test binaries against OpenSSL with Zig's
  `linkSystemLibrary2` and pkg-config enabled for `openssl`.
- Keep the rest of the build structure unchanged.

### OpenSSL Usage

- Add one tiny wrapper in `src/coquic.cpp` and `src/coquic.h`.
- Call a benign API such as `OpenSSL_version_num()` and surface the result as a
  small helper function.
- Touch that helper from `src/main.cpp`.
- Add a minimal GoogleTest assertion so the OpenSSL path is also exercised by
  `zig build test`.

### Scope

- This is only a dependency spike.
- No TLS handshake logic.
- No QUIC crypto logic.
- No OpenSSL abstraction layer yet beyond the tiny helper needed to prove the
  dependency.

## Verification

The completed spike must pass:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build
nix develop -c zig build test
nix develop -c zig build coverage
```
