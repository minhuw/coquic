# Zig + Nix Dev Environment Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a reproducible Nix development shell and a Zig-based C++20 build so `coquic` can compile and verify a minimal starter target.

**Architecture:** Nix owns the developer shell and tool availability, while `build.zig` is the single build entrypoint for the project. A tiny starter executable and smoke test keep verification focused on the toolchain rather than protocol logic.

**Tech Stack:** Nix flakes, Zig build system, C++20, clangd/clang-format, lldb

---

### Task 1: Add Build Artifact Ignore Rules

**Files:**
- Create: `.gitignore`

**Step 1: Confirm the repo currently tracks no build artifacts**

Run: `git status --short`
Expected: No `.zig-cache`, `zig-out`, or local build directories are present.

**Step 2: Add ignore rules for Zig and local build outputs**

Add `.gitignore` entries for:

```gitignore
.zig-cache/
zig-out/
build/
out/
```

**Step 3: Verify the ignore file content**

Run: `sed -n '1,40p' .gitignore`
Expected: The four ignore entries appear exactly once.

**Step 4: Commit**

```bash
git add .gitignore
git commit -m "build: ignore zig artifacts"
```

### Task 2: Add Minimal C++ Sources For Toolchain Verification

**Files:**
- Create: `src/main.cpp`
- Create: `tests/smoke.cpp`

**Step 1: Add the starter executable source**

Create `src/main.cpp`:

```cpp
int main() {
    return 0;
}
```

**Step 2: Add the starter smoke test source**

Create `tests/smoke.cpp`:

```cpp
int main() {
    return 0;
}
```

**Step 3: Verify the files exist**

Run: `rg --files src tests`
Expected: `src/main.cpp` and `tests/smoke.cpp` are listed.

**Step 4: Commit**

```bash
git add src/main.cpp tests/smoke.cpp
git commit -m "build: add starter c++ sources"
```

### Task 3: Add Zig Build Configuration

**Files:**
- Create: `build.zig`
- Modify: `src/main.cpp`
- Modify: `tests/smoke.cpp`

**Step 1: Run the build command before adding the build script**

Run: `zig build`
Expected: FAIL because `build.zig` does not exist yet or no default build is defined.

**Step 2: Create `build.zig` with a C++20 executable target**

Create `build.zig` with:
- a default executable target named `coquic`
- `target` and `optimize` options from Zig's standard helpers
- `src/main.cpp` compiled with `-std=c++20`
- `linkLibCpp()`
- `b.installArtifact(exe)`
- a `run` step
- a `test` step backed by a second executable built from `tests/smoke.cpp`

**Step 3: Verify the Zig build works outside Nix if Zig is already available**

Run: `zig build`
Expected: Either PASS if Zig is installed locally, or shell-level failure such as `zig: command not found`. Do not treat missing local Zig as a project bug.

**Step 4: Commit**

```bash
git add build.zig src/main.cpp tests/smoke.cpp
git commit -m "build: add zig c++20 build"
```

### Task 4: Add The Nix Flake

**Files:**
- Create: `flake.nix`

**Step 1: Run the Nix shell command before adding the flake**

Run: `nix develop -c zig version`
Expected: FAIL because `flake.nix` does not exist yet.

**Step 2: Create `flake.nix`**

Create a flake that:
- uses `nixpkgs`
- supports at least `x86_64-linux`
- defines `devShells.default`
- includes `zig`, `clang-tools`, `lldb`, and `pkg-config`
- sets a short shell banner reminding users to run `zig build`

**Step 3: Verify the shell exposes Zig**

Run: `nix develop -c zig version`
Expected: PASS and prints a Zig version string.

**Step 4: Commit**

```bash
git add flake.nix
git commit -m "build: add nix development shell"
```

### Task 5: Verify End-To-End Build Flow

**Files:**
- Verify: `flake.nix`
- Verify: `build.zig`
- Verify: `src/main.cpp`
- Verify: `tests/smoke.cpp`
- Verify: `.gitignore`

**Step 1: Build the executable through the Nix shell**

Run: `nix develop -c zig build`
Expected: PASS and produce `zig-out/` artifacts.

**Step 2: Run the smoke test through the Nix shell**

Run: `nix develop -c zig build test`
Expected: PASS and exit successfully.

**Step 3: Review the final working tree**

Run: `git status --short`
Expected: Only the intended environment and starter files appear as tracked changes if commits were skipped during execution.

**Step 4: Commit**

```bash
git add .gitignore flake.nix build.zig src/main.cpp tests/smoke.cpp
git commit -m "build: bootstrap zig and nix toolchain"
```
