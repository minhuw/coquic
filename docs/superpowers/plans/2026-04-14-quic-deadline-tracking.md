# QUIC Deadline Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace repeated deadline scans with incremental packet-space anchors while preserving loss/PTO behavior.

**Architecture:** Add cache fields to `PacketSpaceState` for the latest in-flight ACK-eliciting send and the earliest loss-deadline candidate. Update them at packet tracking mutation points and derive deadlines from those anchors using current RTT state. Fall back to packet-space-local rescans only when an anchor is invalidated.

**Tech Stack:** C++, GoogleTest, Zig build/test harness

---

### Task 1: Add the failing cache-invalidation test

**Files:**
- Modify: `tests/core/connection/ack_test.cpp`

- [ ] **Step 1: Write the failing test**

```cpp
TEST(QuicCoreTest, DeadlineTrackingCacheRefreshesAfterTrackedPacketsAreRemoved) {
    // Verify cached anchors move to the next eligible packet after ACK/loss.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop -c zig build test -- --gtest_filter=QuicCoreTest.DeadlineTrackingCacheRefreshesAfterTrackedPacketsAreRemoved`
Expected: FAIL because the new cache fields and refresh logic do not exist yet.

- [ ] **Step 3: Write minimal implementation**

```cpp
// Add packet-space cache fields and refresh helpers used by the deadline code.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop -c zig build test -- --gtest_filter=QuicCoreTest.DeadlineTrackingCacheRefreshesAfterTrackedPacketsAreRemoved`
Expected: PASS

### Task 2: Replace deadline scans with cached anchors

**Files:**
- Modify: `src/quic/connection.h`
- Modify: `src/quic/connection.cpp`

- [ ] **Step 1: Add packet-space cache fields and refresh helpers**

```cpp
struct PacketSpaceState {
    // cached loss/PTO anchors
};
```

- [ ] **Step 2: Update mutation points**

Run through `track_sent_packet`, `retire_acked_packet`, `mark_lost_packet`, `process_inbound_ack`, `rebuild_recovery`, and discard helpers so the cache stays synchronized with `sent_packets`.

- [ ] **Step 3: Convert deadline readers**

Make `loss_deadline()`, `pto_deadline()`, and `has_in_flight_ack_eliciting_packet()` read from the cached anchors instead of rescanning `sent_packets`.

- [ ] **Step 4: Run focused tests**

Run: `nix develop -c zig build test -- --gtest_filter=QuicCoreTest.Deadline*`
Expected: PASS

### Task 3: Verify broader connection behavior

**Files:**
- Modify: `tests/core/connection/ack_test.cpp` if needed for follow-up coverage

- [ ] **Step 1: Run broader ACK/recovery coverage**

Run: `nix develop -c zig build test -- --gtest_filter=QuicCoreTest.*Ack*`
Expected: PASS

- [ ] **Step 2: Run the perf benchmark again**

Run the real bulk benchmark used in local perf work and compare throughput plus `perf` hotspot mix.

- [ ] **Step 3: Record outcome**

Summarize whether deadline computation dropped out of the top hotspots and whether throughput improved enough to keep the change.
