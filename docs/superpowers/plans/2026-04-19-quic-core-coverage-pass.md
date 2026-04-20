# QUIC Core Coverage Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Increase `src/quic/core.cpp` line, branch, region, and function coverage by exercising its remaining endpoint-helper and routing cold paths.

**Architecture:** Add focused endpoint-internal tests that call `QuicCore` private helpers through the existing `#define private public` test fixtures, then add a small set of behavior-level endpoint tests for the remaining runtime branches. Keep changes test-only unless a branch proves structurally unreachable and warrants follow-up cleanup in a later pass.

**Tech Stack:** C++, GoogleTest, Zig build, Nix dev shell

---

### Task 1: Cover Core Helper Cold Paths

**Files:**
- Create: `tests/core/endpoint/internal_test.cpp`
- Check: `src/quic/core.cpp`
- Check: `src/quic/core.h`
- Reuse: `tests/support/core/endpoint_test_fixtures.h`

- [ ] **Step 1: Write helper-focused tests**

Add tests for:
- `LegacyConnectionView` null / missing-entry behavior
- `ensure_legacy_entry()` returning null when `legacy_config_` is absent
- `set_legacy_connection(nullptr)` erase path and auto-handle allocation
- `parse_endpoint_datagram()` malformed short-header and long-header cases
- `take_retry_context()` mismatch path
- `make_version_negotiation_packet_bytes()` and `make_retry_packet_bytes()` missing-source / integrity-failure cases
- `refresh_server_connection_routes()`, `remember_inbound_path()`, and `seed_legacy_route_handle_path_for_tests()` collision and displacement paths
- `QuicCore` self move-assignment fast return

- [ ] **Step 2: Run the targeted endpoint test binary**

Run: `nix develop -c sh -lc 'cd /home/minhu/projects/coquic/.worktrees/http3-coverage-phase1 && zig build test --summary all'`
Expected: New endpoint tests compile and any failures identify uncovered assumptions to correct.

### Task 2: Cover Core Endpoint Runtime Branches

**Files:**
- Modify: `tests/core/endpoint/open_test.cpp`
- Modify: `tests/core/endpoint/multiplex_test.cpp`
- Modify: `tests/core/endpoint/server_routing_test.cpp`
- Check: `src/quic/core.cpp`

- [ ] **Step 1: Add behavior-level tests for remaining runtime misses**

Add tests for:
- dropping unmatched inbound datagrams on client endpoints
- retry-enabled server dropping non-empty unknown retry tokens
- migration / reset / stop-sending command error branches
- timer-expired cleanup erasing closed or failed connections
- unsupported endpoint input fallback where applicable

- [ ] **Step 2: Run focused tests and keep them green**

Run: `nix develop -c sh -lc 'cd /home/minhu/projects/coquic/.worktrees/http3-coverage-phase1 && zig build coverage'`
Expected: Coverage completes successfully and `src/quic/core.cpp` coverage improves materially.
