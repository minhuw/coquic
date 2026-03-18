# QUIC Codec Full Coverage Design

## Status

Approved on 2026-03-18.

## Context

`coquic` already has full line and function coverage for the current QUIC codec
implementation, but the LLVM report still shows uncovered regions and branches in
`src/quic/frame.cpp`, `src/quic/packet.cpp`, and `src/quic/varint.cpp`.

## Goal

Raise LLVM source-based coverage for the current codebase to 100% for both
region coverage and branch coverage without changing the public behavior of the
codec.

## Decisions

### Test-First Coverage Work

- Use targeted GoogleTest additions to exercise uncovered success and failure
  paths before touching production code.
- Keep tests close to the existing suites in:
  - `tests/quic_frame_test.cpp`
  - `tests/quic_packet_test.cpp`
  - `tests/quic_varint_test.cpp`

### Production Code Cleanups

- Prefer tests over refactors for any real runtime path.
- Allow small production cleanups only when a remaining uncovered branch is
  defensive, duplicated, or structurally unreachable with meaningful inputs.
- Preserve existing APIs, wire formats, and error codes.

### Coverage Focus

- `src/quic/frame.cpp`: exercise currently unvisited decoder and serializer
  branches across ACK, stream, flow-control, connection-close, and
  connection-id frame families.
- `src/quic/packet.cpp`: cover remaining packet-type validation, connection-id
  handling, packet-number validation, and long/short header decode branches.
- `src/quic/varint.cpp`: cover the final prefix-selection branch for 8-byte
  encodings.

### Verification

The change is complete only when all of the following pass in the worktree:

```bash
nix develop -c zig build test
nix develop -c zig build coverage
```

And the generated report at `coverage/html/index.html` shows:

- region coverage: `100.00%`
- branch coverage: `100.00%`
