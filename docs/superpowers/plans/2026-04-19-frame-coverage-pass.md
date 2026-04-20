# QUIC Frame Coverage Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce the remaining uncovered lines and branches in `src/quic/frame.cpp` without changing externally visible QUIC frame behavior.

**Architecture:** Add a single targeted internal-coverage hook in `frame.cpp` for anonymous helper branches that public APIs cannot reach, then cover it from `frame_test.cpp` and verify the full coverage build. Keep changes narrowly scoped to tests and non-behavioral test-only entry points.

**Tech Stack:** C++, GoogleTest, Zig build, Nix dev shell

---

### Task 1: Add Failing Frame Coverage Test

**Files:**
- Modify: `tests/core/packets/frame_test.cpp`
- Check: `src/quic/frame.cpp`

- [ ] **Step 1: Write a failing test**
- [ ] **Step 2: Run the core packet test target and confirm the new symbol is missing**

### Task 2: Add Minimal Internal Coverage Hook

**Files:**
- Modify: `src/quic/frame.cpp`
- Modify: `tests/core/packets/frame_test.cpp`

- [ ] **Step 1: Implement one test-only hook inside `frame.cpp` that exercises remaining anonymous-helper cold paths**
- [ ] **Step 2: Run the focused frame tests until green**
- [ ] **Step 3: Run `zig build coverage` and inspect the next remaining subsystem gap**
