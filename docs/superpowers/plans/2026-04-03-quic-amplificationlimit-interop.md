# QUIC Amplification Limit Interop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable the official `amplificationlimit` interop testcase locally and implement server-side anti-amplification accounting in the QUIC core so the testcase can pass.

**Architecture:** First widen testcase parsing so local entrypoints accept `amplificationlimit` without changing application semantics. Then add minimal server-side pre-validation byte accounting inside `QuicConnection`, with tests that prove blocking, unblocking, and Retry-validated bypass behavior. Finish by running focused local interop verification against the pinned official runner.

**Tech Stack:** Zig build system, C++20, GoogleTest, Bash, Nix, official `quic-interop-runner`

---

### Task 1: Accept `amplificationlimit` in local interop testcase parsing

**Files:**
- Modify: `interop/entrypoint.sh`
- Modify: `src/quic/http09_runtime.cpp`
- Test: `tests/quic_http09_runtime_test.cpp`

- [ ] **Step 1: Write failing runtime tests for testcase parsing**

Add tests that:

- set `TESTCASE=amplificationlimit` and verify `parse_http09_runtime_args(...)`
  succeeds
- verify the parsed testcase uses the same runtime mode as `transfer`
- keep `unknown-case` rejection intact

- [ ] **Step 2: Run the targeted runtime tests to verify the new case fails correctly**

Run: `nix develop -c zig build test -- --gtest_filter=QuicHttp09RuntimeTest.*Amplification*`
Expected: FAIL because `amplificationlimit` is not parsed yet.

- [ ] **Step 3: Add the testcase alias in the entrypoint and runtime parser**

Update:

- `supports_testcase()` in `interop/entrypoint.sh`
- `parse_testcase(...)` or equivalent testcase-name handling in
  `src/quic/http09_runtime.cpp`

Map `amplificationlimit` to the existing transfer-style runtime behavior.

- [ ] **Step 4: Re-run the targeted runtime tests and confirm they pass**

Run: `nix develop -c zig build test -- --gtest_filter=QuicHttp09RuntimeTest.*Amplification*`
Expected: PASS.

### Task 2: Add failing core tests for anti-amplification accounting

**Files:**
- Modify: `tests/quic_core_test.cpp`
- Modify: `tests/quic_test_utils.h` (only if a tiny white-box helper is needed)

- [ ] **Step 1: Write focused failing tests for pre-validation server budget behavior**

Add tests that prove:

- a server with an unvalidated client address cannot emit a datagram whose size
  would exceed `3 * bytes_received`
- receiving another client datagram increases budget and allows sending to
  resume
- a client connection is not subject to the server anti-amplification budget
- a Retry-validated server path bypasses the limit

- [ ] **Step 2: Run the targeted core tests and verify they fail for the right reason**

Run: `nix develop -c zig build test -- --gtest_filter=QuicCoreTest.*Amplification*`
Expected: FAIL because the core does not account for anti-amplification credit
yet.

### Task 3: Implement server-side anti-amplification accounting in `QuicConnection`

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`
- Test: `tests/quic_core_test.cpp`

- [ ] **Step 1: Add minimal connection state for pre-validation byte accounting**

Introduce narrowly scoped server-side state for:

- whether anti-amplification applies
- bytes received before validation
- bytes sent before validation

Prefer explicit names tied to address validation rather than generic counters.

- [ ] **Step 2: Account for received bytes before outbound work is generated**

Update inbound datagram processing so server connections accrue payload-byte
credit from peer datagrams before attempting to emit more handshake or recovery
traffic.

- [ ] **Step 3: Gate outbound datagram emission on remaining budget**

In outbound datagram construction:

- compute remaining budget as `3 * received - sent`
- if the next server datagram would exceed budget, emit nothing and preserve
  pending transport work
- when a datagram is allowed, increment sent-byte accounting after the datagram
  is committed

- [ ] **Step 4: Mark the path validated when existing Retry or server handshake state proves the peer address**

Use the current connection state model to stop applying the limit once the
server has validated the address. Retry-derived validation should be explicit.

- [ ] **Step 5: Re-run the targeted core tests and confirm they pass**

Run: `nix develop -c zig build test -- --gtest_filter=QuicCoreTest.*Amplification*`
Expected: PASS.

### Task 4: Verify no regressions in runtime and core behavior

**Files:**
- Modify: `tests/quic_http09_runtime_test.cpp`
- Modify: `tests/quic_core_test.cpp`

- [ ] **Step 1: Run the full runtime test suite**

Run: `nix develop -c zig build test -- --gtest_filter=QuicHttp09RuntimeTest.*`
Expected: PASS.

- [ ] **Step 2: Run the full core test suite**

Run: `nix develop -c zig build test -- --gtest_filter=QuicCoreTest.*`
Expected: PASS.

### Task 5: Run focused official-runner verification for `amplificationlimit`

**Files:**
- Modify: `.github/workflows/interop.yml` (only if testcase enablement is proven and requested later)
- Use: `interop/run-official.sh`

- [ ] **Step 1: Run a local official-runner attempt against one pinned peer**

Run:

```bash
INTEROP_TESTCASES=amplificationlimit \
INTEROP_PEER_IMPL=quic-go \
INTEROP_PEER_IMAGE=martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424 \
nix develop -c bash interop/run-official.sh
```

Expected: The runner completes and reports whether `amplificationlimit`
actually succeeds against the pinned peer.

- [ ] **Step 2: If the first peer passes, repeat against picoquic**

Run:

```bash
INTEROP_TESTCASES=amplificationlimit \
INTEROP_PEER_IMPL=picoquic \
INTEROP_PEER_IMAGE=privateoctopus/picoquic@sha256:7e4110e3260cd9d4f815ad63ca1d93e020e94d3a8d3cb6cb9cc5c59d97999b05 \
nix develop -c bash interop/run-official.sh
```

Expected: Confirm whether the current implementation also passes the testcase
against the second pinned peer.

- [ ] **Step 3: Only after verification, decide whether to extend CI testcase selection**

Do not add `amplificationlimit` to `.github/workflows/interop.yml` until the
local official-runner verification is green for the intended peer coverage.
