# GoogleTest + LLVM Coverage Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add GoogleTest-based C++ unit tests and LLVM source-based coverage reporting while preserving the existing Nix-backed Zig workflow and four-step CI structure.

**Architecture:** Nix provides GoogleTest and LLVM coverage tools to the shell, `build.zig` builds a reusable project library plus a GoogleTest runner, and a dedicated `coverage` build step runs instrumented tests and exports HTML and LCOV reports under `coverage/`. GitHub Actions keeps separate Format, Lint, Build, and Test checks, with the Test step generating coverage artifacts.

**Tech Stack:** Nix flakes, Zig build system, C++20, GoogleTest, LLVM `llvm-cov`/`llvm-profdata`, GitHub Actions

---

### Task 1: Add Nix Inputs And Ignore Rules For GoogleTest And Coverage

**Files:**
- Modify: `flake.nix`
- Modify: `.gitignore`

**Step 1: Record the missing coverage output rule**

Run: `rg -n "^coverage/$" .gitignore`
Expected: FAIL because the repository does not ignore generated coverage output yet.

**Step 2: Add the shell dependencies and exported paths**

Update `flake.nix` to:
- add `gtest`
- add `llvmPackages_20.llvm`
- export:
  - `GTEST_INCLUDE_DIR`
  - `GTEST_LIB_DIR`
  - `LLVM_COV`
  - `LLVM_PROFDATA`

Update `.gitignore` to add:

```gitignore
coverage/
```

**Step 3: Verify the shell exposes the expected paths**

Run: `nix develop -c bash -lc 'printf "%s\n%s\n%s\n%s\n" "$GTEST_INCLUDE_DIR" "$GTEST_LIB_DIR" "$LLVM_COV" "$LLVM_PROFDATA"'`
Expected: PASS and print non-empty paths.

**Step 4: Commit**

```bash
git add flake.nix .gitignore
git commit -m "build: add gtest and llvm coverage tools"
```

### Task 2: Replace The Smoke Test With A Failing GoogleTest

**Files:**
- Create: `src/coquic.h`
- Modify: `src/main.cpp`
- Modify: `tests/smoke.cpp`
- Modify: `build.zig`

**Step 1: Write the failing GoogleTest first**

Replace `tests/smoke.cpp` with:

```cpp
#include <gtest/gtest.h>

#include "src/coquic.h"

TEST(ProjectNameTest, ReturnsRepositoryName) {
    EXPECT_EQ(coquic::project_name(), "coquic");
}
```

Create `src/coquic.h` with only the declaration:

```cpp
#pragma once

#include <string_view>

namespace coquic {
std::string_view project_name();
}
```

Update `build.zig` so the `test` step builds a GoogleTest runner linked against
`gtest_main`, but do not add `src/coquic.cpp` yet.

**Step 2: Run the test step and verify it fails for the missing implementation**

Run: `nix develop -c zig build test`
Expected: FAIL at link time because `coquic::project_name()` is declared but not defined.

**Step 3: Commit**

```bash
git add tests/smoke.cpp src/coquic.h build.zig src/main.cpp
git commit -m "test: add failing gtest harness"
```

### Task 3: Implement The Minimal Library And Coverage Target

**Files:**
- Create: `src/coquic.cpp`
- Modify: `src/main.cpp`
- Modify: `build.zig`
- Create: `scripts/run-coverage.sh`

**Step 1: Add the minimal implementation**

Create `src/coquic.cpp`:

```cpp
#include "src/coquic.h"

namespace coquic {
std::string_view project_name() {
    return "coquic";
}
}
```

Update `src/main.cpp` to call `coquic::project_name()` so the executable also
links through the shared project library.

**Step 2: Add a dedicated coverage script and build step**

Create `scripts/run-coverage.sh` to:
- remove any previous `coverage/` directory
- run the test binary with `LLVM_PROFILE_FILE=coverage/coquic-%p.profraw`
- merge raw profiles with `llvm-profdata merge -sparse`
- export `coverage/lcov.info`
- generate HTML coverage under `coverage/html/`

Update `build.zig` to:
- build a reusable project library from `src/coquic.cpp`
- link that library into both the main executable and test runner
- compile a coverage-instrumented test binary
- add `zig build coverage` that invokes `scripts/run-coverage.sh`

**Step 3: Run the red-green verification**

Run: `nix develop -c zig build test`
Expected: PASS.

Run: `nix develop -c zig build coverage`
Expected: PASS and create `coverage/lcov.info` plus files under `coverage/html/`.

**Step 4: Commit**

```bash
git add src/coquic.cpp src/main.cpp build.zig scripts/run-coverage.sh coverage
git reset coverage
git commit -m "test: add gtest library target and coverage reports"
```

### Task 4: Wire Coverage Into CI And Document The Workflow

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`

**Step 1: Update the CI Test step**

Change the workflow so:
- `Build` still runs `nix develop -c zig build`
- `Test` runs `nix develop -c zig build coverage`
- a later artifact upload step publishes:
  - `coverage/html/`
  - `coverage/lcov.info`

**Step 2: Document the new local commands**

Update `README.md` so the development section explains:
- GoogleTest is the unit test framework
- `zig build test` runs the test suite
- `zig build coverage` creates local HTML and LCOV reports

**Step 3: Verify the full project workflow**

Run:

```bash
nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure
nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
nix develop -c zig build
nix develop -c zig build test
nix develop -c zig build coverage
```

Expected: PASS, with coverage artifacts written locally.

**Step 4: Commit**

```bash
git add .github/workflows/ci.yml README.md
git commit -m "ci: publish llvm coverage artifacts"
```
