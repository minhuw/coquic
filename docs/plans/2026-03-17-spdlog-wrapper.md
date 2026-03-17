# spdlog Wrapper Spike Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `spdlog` as a Nix-managed dependency and expose it through a tiny project-owned wrapper so the codebase proves logging can be integrated without leaking third-party APIs everywhere.

**Architecture:** `flake.nix` adds the `spdlog` runtime package plus the include and pkg-config paths from `spdlog.dev` and `fmt.dev`, `build.zig` compiles the project library against those headers and links final binaries against `spdlog` through pkg-config, and `src/coquic.cpp` exposes a minimal `init_logging` / `logging_ready` wrapper that `main` and the test suite both exercise.

**Tech Stack:** Nix flakes, Zig build system, C++20, spdlog, fmt, pkg-config, GoogleTest

---

### Task 1: Add spdlog To The Development Shell

**Files:**
- Modify: `flake.nix`

**Step 1: Add the dependency packages**

Update `flake.nix` so `devShells.default.packages` includes:

```nix
spdlog
```

and the shell hook exports:

```sh
SPDLOG_INCLUDE_DIR
FMT_INCLUDE_DIR
PKG_CONFIG_PATH
```

so the shell can find `spdlog.pc` and `fmt.pc`.

**Step 2: Verify pkg-config sees spdlog**

Run: `nix develop -c bash -lc 'pkg-config --modversion spdlog && pkg-config --cflags --libs spdlog'`
Expected: PASS and print the spdlog version plus cflags/libs.

**Step 3: Commit**

```bash
git add flake.nix
git commit -m "build: add spdlog dev dependency"
```

### Task 2: Write The Failing Logging Wrapper Test First

**Files:**
- Modify: `src/coquic.h`
- Modify: `tests/smoke.cpp`

**Step 1: Add the declarations**

Extend `src/coquic.h` with:

```cpp
void init_logging();
bool logging_ready();
```

inside `namespace coquic`.

**Step 2: Write the failing test**

Add this test to `tests/smoke.cpp`:

```cpp
TEST(LoggingTest, InitializesProjectLogger) {
    EXPECT_FALSE(coquic::logging_ready());
    coquic::init_logging();
    EXPECT_TRUE(coquic::logging_ready());
}
```

Do not implement the functions yet.

**Step 3: Run the test to verify it fails**

Run: `nix develop -c zig build test`
Expected: FAIL at link time because the new wrapper functions are declared but
undefined.

**Step 4: Commit**

```bash
git add src/coquic.h tests/smoke.cpp
git commit -m "test: add failing spdlog wrapper test"
```

### Task 3: Implement The Minimal spdlog Wrapper

**Files:**
- Modify: `build.zig`
- Modify: `src/coquic.cpp`
- Modify: `src/main.cpp`

**Step 1: Wire the build**

Update `build.zig` so the reusable project library:
- compiles against `SPDLOG_INCLUDE_DIR` and `FMT_INCLUDE_DIR`
- uses the compile definitions required by the packaged shared-library build

Then link the final executable and test binaries against `spdlog` through
pkg-config.

**Step 2: Implement the wrapper**

Add the smallest possible implementation in `src/coquic.cpp`:
- a static ready flag
- `init_logging()` that configures the default logger through `spdlog`
- `logging_ready()` that returns the flag

**Step 3: Touch the wrapper from `main`**

Update `src/main.cpp` so it initializes logging and incorporates
`logging_ready()` into the existing starter return path.

**Step 4: Run the red-green checks**

Run: `nix develop -c zig build test`
Expected: PASS.

Run: `nix develop -c zig build`
Expected: PASS.

**Step 5: Commit**

```bash
git add build.zig src/coquic.cpp src/main.cpp
git commit -m "build: wire spdlog wrapper spike"
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
