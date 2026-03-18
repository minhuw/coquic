# CI + Pre-Commit Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Nix-backed GitHub Actions CI and Nix-managed pre-commit hooks for format, lint, build, and test.

**Architecture:** `flake.nix` remains the source of truth for the development shell and now also defines the generated pre-commit configuration through `git-hooks.nix`. GitHub Actions installs Nix once, reuses the Nix cache, and runs the same format, lint, build, and test commands through `nix develop`.

**Tech Stack:** Nix flakes, git-hooks.nix, pre-commit, clang-format, clang-tidy, Zig build, GitHub Actions

---

### Task 1: Add Nix-Managed Pre-Commit Integration

**Files:**
- Modify: `flake.nix`
- Modify: `flake.lock`

**Step 1: Confirm pre-commit is not currently available from the project shell**

Run: `nix develop -c pre-commit --version`
Expected: FAIL because the current shell does not expose `pre-commit`.

**Step 2: Extend the flake inputs and outputs**

Update `flake.nix` to:
- add the `git-hooks.nix` input
- define a `pre-commit-check` with `git-hooks.nix`
- keep `zig`, `clang-tools`, `lldb`, and `pkg-config` in the shell
- add the hook packages and shell hook from `pre-commit-check`

**Step 3: Refresh the lock file**

Run: `nix flake lock`
Expected: PASS and record the new `git-hooks.nix` input in `flake.lock`.

**Step 4: Verify the shell now exposes pre-commit**

Run: `nix develop -c pre-commit --version`
Expected: PASS and print a pre-commit version.

**Step 5: Commit**

```bash
git add flake.nix flake.lock
git commit -m "build: add nix-managed pre-commit hooks"
```

### Task 2: Add Clang Format And Lint Configuration

**Files:**
- Create: `.clang-format`
- Create: `.clang-tidy`
- Create: `scripts/run-clang-tidy.sh`
- Modify: `flake.nix`

**Step 1: Add the formatting policy**

Create `.clang-format` with the chosen C++ style settings for the repository.

**Step 2: Add the lint policy**

Create `.clang-tidy` with the enabled check families, warning policy, and repository file scope.

**Step 3: Add the clang-tidy wrapper**

Create `scripts/run-clang-tidy.sh` to:
- exit cleanly when no filenames are passed
- run `clang-tidy` for each incoming file
- pass the repository's current compile flags, including `-std=c++20`

**Step 4: Wire the hooks into `flake.nix`**

Configure the generated pre-commit setup to:
- run `clang-format` on C++ sources
- run the custom `clang-tidy` wrapper on C++ sources

**Step 5: Verify the format hook runs**

Run: `nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure`
Expected: PASS with no formatting diffs.

**Step 6: Verify the lint hook runs**

Run: `nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure`
Expected: PASS with no lint errors.

**Step 7: Commit**

```bash
git add .clang-format .clang-tidy scripts/run-clang-tidy.sh flake.nix
git commit -m "build: add clang format and tidy hooks"
```

### Task 3: Add GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

**Step 1: Confirm there is no existing CI workflow**

Run: `find .github -maxdepth 3 -type f`
Expected: Either no output or no existing CI workflow file.

**Step 2: Create the CI workflow**

Create `.github/workflows/ci.yml` to:
- trigger on `push` and `pull_request`
- grant only `contents: read` and `id-token: write`
- run on `ubuntu-latest`
- install Nix with `DeterminateSystems/nix-installer-action`
- enable cache reuse with `DeterminateSystems/magic-nix-cache-action`
- run four steps in order:
  - format check
  - lint
  - build
  - test

**Step 3: Validate the workflow syntax locally**

Run: `python - <<'PY'\nimport yaml, pathlib\npath = pathlib.Path('.github/workflows/ci.yml')\nprint(yaml.safe_load(path.read_text())['jobs'].keys())\nPY`
Expected: PASS and print the workflow job key.

**Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add nix-backed github actions workflow"
```

### Task 4: Document The Local Workflow

**Files:**
- Modify: `README.md`
- Modify: `.gitignore`

**Step 1: Ignore generated pre-commit output if needed**

Update `.gitignore` to ignore the generated `.pre-commit-config.yaml` if the hook integration writes it into the repository root.

**Step 2: Update the README**

Document:
- `nix develop`
- automatic hook installation
- `pre-commit run clang-format --all-files`
- `pre-commit run coquic-clang-tidy --all-files`
- `zig build`
- `zig build test`

**Step 3: Verify the README commands are accurate**

Run: `sed -n '1,220p' README.md`
Expected: The documented commands match the implemented workflow.

**Step 4: Commit**

```bash
git add README.md .gitignore
git commit -m "docs: document ci and pre-commit workflow"
```

### Task 5: Verify End-To-End Behavior

**Files:**
- Verify: `flake.nix`
- Verify: `flake.lock`
- Verify: `.clang-format`
- Verify: `.clang-tidy`
- Verify: `scripts/run-clang-tidy.sh`
- Verify: `.github/workflows/ci.yml`
- Verify: `README.md`
- Verify: `.gitignore`

**Step 1: Run the format check**

Run: `nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure`
Expected: PASS.

**Step 2: Run the lint check**

Run: `nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure`
Expected: PASS.

**Step 3: Build the project**

Run: `nix develop -c zig build`
Expected: PASS.

**Step 4: Run the smoke test**

Run: `nix develop -c zig build test`
Expected: PASS.

**Step 5: Review the final working tree**

Run: `git status --short`
Expected: Only the intended CI, hook, and documentation files appear as tracked changes if commits were skipped.

**Step 6: Commit**

```bash
git add .github/workflows/ci.yml .clang-format .clang-tidy scripts/run-clang-tidy.sh flake.nix flake.lock README.md .gitignore
git commit -m "ci: add nix-backed checks and pre-commit hooks"
```
