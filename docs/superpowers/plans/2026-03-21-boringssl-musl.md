# BoringSSL Musl Prototype Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `coquic-boringssl-musl` Nix package and matching shell/image path that proves whether we can produce a static musl-linked binary suitable for a thin interop endpoint image.

**Architecture:** Extend the existing profile-first flake layout with a third backend profile for `boringssl` on musl/static dependencies. Keep the C++/TLS logic changes minimal by making the `spdlog` shared/static compile flags profile-driven instead of globally hardcoded shared mode. Verify using a focused shell test that builds the package and rejects dynamic binaries.

**Tech Stack:** Nix flakes, Zig build, BoringSSL, musl, spdlog, fmt, shell verification

---

### Task 1: Add the failing musl verification

**Files:**
- Create: `tests/nix/boringssl_musl_static_test.sh`

- [x] **Step 1: Write the failing test**

Add a shell verification script that:
- runs `nix build .#coquic-boringssl-musl`
- resolves the resulting `coquic` binary
- fails unless `ldd` reports a static executable

- [x] **Step 2: Run test to verify it fails**

Run: `bash tests/nix/boringssl_musl_static_test.sh`
Expected: FAIL because `coquic-boringssl-musl` does not exist yet

### Task 2: Add the boringssl-musl profile

**Files:**
- Modify: `flake.nix`

- [ ] **Step 1: Add a musl/static dependency profile**

Define a `boringssl-musl` profile alongside existing `quictls` and `boringssl`, using static/musl package variants where available.

- [ ] **Step 2: Expose package and shell outputs**

Add:
- `packages.x86_64-linux.coquic-boringssl-musl`
- `devShells.x86_64-linux.boringssl-musl`

- [ ] **Step 3: Add the image path if the package builds**

Expose:
- `packages.x86_64-linux.interop-image-boringssl-musl`

### Task 3: Make build flags profile-driven

**Files:**
- Modify: `build.zig`

- [ ] **Step 1: Add a build option for shared vs static spdlog**

Replace the unconditional shared-`spdlog` compile flags with a toggle so static musl builds do not claim `SPDLOG_SHARED_LIB`.

- [ ] **Step 2: Thread the new option through flake builds**

Pass the correct `zig build` option for each profile:
- `quictls`: shared `spdlog`
- `boringssl`: static `spdlog`
- `boringssl-musl`: static `spdlog`

### Task 4: Verify the musl package shape

**Files:**
- Test: `tests/nix/boringssl_musl_static_test.sh`

- [ ] **Step 1: Run the focused verification**

Run: `bash tests/nix/boringssl_musl_static_test.sh`
Expected: PASS and print `ldd` output showing a static executable

- [ ] **Step 2: Run focused flake verification**

Run: `nix --option eval-cache false flake show`
Expected: includes `coquic-boringssl-musl`, `boringssl-musl`, and `interop-image-boringssl-musl` if the image path is implemented
