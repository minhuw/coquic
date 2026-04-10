# 2026-04-10 Remove Root Coquic Facade

## Goal

Delete `src/coquic.cpp` and `src/coquic.h`, inline their tiny helper behavior
at the real usage sites, and stop using a root-level umbrella header as a
cross-layer dependency shortcut.

## Current Problems

- `src/coquic.h` is a root-level umbrella include that re-exports unrelated
  QUIC and HTTP/0.9 headers.
- `src/coquic.cpp` contains four tiny helpers that are not reusable domain
  abstractions:
  - `project_name()`
  - `openssl_available()`
  - `init_logging()`
  - `logging_ready()`
- Those helpers are only used by the HTTP/0.9 runtime health check and the
  smoke test, so keeping them as a shared facade adds indirection without
  architectural value.
- The just-completed layered hierarchy work established explicit domain
  boundaries, but the root umbrella header still makes it easy for tests and
  runtime code to depend on multiple layers implicitly.

## Decision Summary

The root facade will be removed entirely.

- Delete `src/coquic.cpp`.
- Delete `src/coquic.h`.
- Inline logging initialization and OpenSSL availability checks directly into
  `src/http09/http09_runtime.cpp`.
- Replace every `#include "src/coquic.h"` with the exact domain headers each
  file needs.
- Keep no compatibility header, alias API, or replacement facade under a new
  path.

## Alternatives Considered

### Recommended: Delete And Inline

This keeps the architecture honest. Runtime bootstrap logic stays in the
runtime, and tests depend only on the specific QUIC or HTTP headers they
exercise.

### Not Chosen: Move The Helpers To Another Shared Header

This would preserve a small shared API under a better path, but it would still
keep a faux abstraction alive even though the logic is runtime-local and trivial.

### Not Chosen: Keep The Umbrella Header Only For Tests

That would reduce production coupling but still preserve the same layering leak
for tests, which are supposed to validate the real public and internal
boundaries directly.

## Target Architecture

### Runtime Ownership

`src/http09/http09_runtime.cpp` will own the runtime-only bootstrap behavior:

- initialize spdlog before runtime dispatch
- track whether logging was configured successfully
- query OpenSSL availability directly for health-check mode
- use a local `"coquic"` project-name constant where needed

This logic stays file-local in an anonymous namespace unless a real reusable
runtime abstraction emerges later.

### Header Ownership

Each caller includes only the headers it actually uses:

- HTTP/0.9 runtime sources include HTTP/0.9, QUIC, and third-party headers
  directly.
- packet codec tests include `src/quic/core.h`,
  `src/quic/plaintext_codec.h`, and `src/quic/protected_codec.h` directly as
  needed.
- smoke tests include the concrete headers needed to exercise logging and
  OpenSSL behavior rather than depending on a deleted facade API.

## Build And Test Changes

- Remove `src/coquic.cpp` from `build.zig`.
- Leave `src/main.cpp` unchanged unless an include cleanup is needed.
- Update smoke coverage so it still validates:
  - logging initialization state transition
  - OpenSSL availability
  - the runtime health-check success path
- Keep packet codec tests focused on their direct QUIC dependencies only.

## Error Handling

- Logging initialization remains best-effort and preserves the current
  observable behavior: the runtime health check fails if logging was not marked
  ready.
- OpenSSL availability remains a direct runtime probe using
  `OpenSSL_version_num() != 0`.
- No new fallbacks, retries, or configuration branches are introduced.

## Verification

The implementation plan and verification should confirm:

- no source file still includes `src/coquic.h`
- `build.zig` no longer references `src/coquic.cpp`
- the main test suite passes
- coverage remains at 100%
- formatting and clang-tidy stay clean
