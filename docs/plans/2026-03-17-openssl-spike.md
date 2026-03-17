# OpenSSL Dependency Spike Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prove that `coquic` can consume OpenSSL from the Nix shell and Zig build by linking the library and calling one harmless OpenSSL API from project code.

**Architecture:** `flake.nix` adds OpenSSL to the dev shell, `build.zig` links the reusable project library against OpenSSL via pkg-config, and the project exposes one tiny helper that returns whether OpenSSL reports a non-zero version number. The helper is called from both `main` and a GoogleTest so the dependency is exercised in build and test flows.

**Tech Stack:** Nix flakes, Zig build system, C++20, OpenSSL, pkg-config, GoogleTest

---

### Task 1: Add OpenSSL To The Reproducible Development Shell

**Files:**
- Modify: `flake.nix`

**Step 1: Add the package**

Update `flake.nix` so `devShells.default.packages` includes:

```nix
openssl
```

alongside the existing toolchain packages.

**Step 2: Verify the package is visible in the shell**

Run: `nix develop -c bash -lc 'pkg-config --modversion openssl && pkg-config --cflags --libs openssl'`
Expected: PASS and print an OpenSSL version plus linker flags.

**Step 3: Commit**

```bash
git add flake.nix
git commit -m "build: add openssl dev dependency"
```

### Task 2: Write The Failing OpenSSL Test First

**Files:**
- Modify: `src/coquic.h`
- Modify: `tests/smoke.cpp`

**Step 1: Add the declaration**

Extend `src/coquic.h` with:

```cpp
bool openssl_available();
```

inside `namespace coquic`.

**Step 2: Write the failing test**

Add this test to `tests/smoke.cpp`:

```cpp
TEST(OpenSSLTest, ReportsAvailableVersion) {
    EXPECT_TRUE(coquic::openssl_available());
}
```

Do not implement the function yet.

**Step 3: Run the test to verify it fails**

Run: `nix develop -c zig build test`
Expected: FAIL at link time because `coquic::openssl_available()` is declared but undefined.

**Step 4: Commit**

```bash
git add src/coquic.h tests/smoke.cpp
git commit -m "test: add failing openssl spike test"
```

### Task 3: Implement The Minimal OpenSSL Linkage

**Files:**
- Modify: `build.zig`
- Modify: `src/coquic.cpp`
- Modify: `src/main.cpp`

**Step 1: Link OpenSSL in Zig**

Update the reusable project library in `build.zig` to link OpenSSL through
pkg-config using Zig's system-library integration.

**Step 2: Implement the helper**

Add this minimal implementation to `src/coquic.cpp`:

```cpp
#include <openssl/crypto.h>

bool coquic::openssl_available() {
    return OpenSSL_version_num() != 0;
}
```

Keep the existing `project_name()` helper intact.

**Step 3: Touch the helper from `main`**

Update `src/main.cpp` so the executable references `coquic::openssl_available()`
without adding meaningful runtime logic.

**Step 4: Run the test to verify it passes**

Run: `nix develop -c zig build test`
Expected: PASS.

**Step 5: Run the build to verify the executable links**

Run: `nix develop -c zig build`
Expected: PASS.

**Step 6: Commit**

```bash
git add build.zig src/coquic.cpp src/main.cpp
git commit -m "build: link openssl in starter target"
```

### Task 4: Re-Run Full Verification

**Files:**
- Modify: none

**Step 1: Run formatting**

Run: `nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure`
Expected: PASS.

**Step 2: Run lint**

Run: `nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure`
Expected: PASS.

**Step 3: Run build, test, and coverage**

Run: `nix develop -c zig build`
Expected: PASS.

Run: `nix develop -c zig build test`
Expected: PASS.

Run: `nix develop -c zig build coverage`
Expected: PASS.

**Step 4: Confirm the branch is clean**

Run: `git status --short`
Expected: clean working tree after commits.
