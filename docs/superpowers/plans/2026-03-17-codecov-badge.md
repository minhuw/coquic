# Codecov Badge Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upload CI coverage to Codecov via OIDC and add a README badge that shows default-branch coverage.

**Architecture:** The existing `zig build coverage` step continues to generate `coverage/lcov.info`, GitHub Actions uploads that report with `codecov/codecov-action@v5`, and `README.md` links to Codecov's hosted coverage badge for the repository. No new secrets are introduced; GitHub's OIDC token is used instead.

**Tech Stack:** GitHub Actions, Codecov GitHub Action v5, OIDC, LLVM LCOV output

---

### Task 1: Update The CI Workflow For Codecov Uploads

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Adjust checkout depth for Codecov**

Update the checkout step to:

```yaml
- name: Checkout
  uses: actions/checkout@v6
  with:
    fetch-depth: 0
```

**Step 2: Add the Codecov upload step**

Add a new step after the test run:

```yaml
- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v5
  with:
    files: coverage/lcov.info
    disable_search: true
    fail_ci_if_error: true
    use_oidc: true
```

**Step 3: Keep artifact upload in place**

Retain the existing artifact upload step so local HTML and LCOV outputs are
still available from GitHub Actions.

**Step 4: Validate the workflow file**

Run: `nix shell nixpkgs#actionlint -c actionlint .github/workflows/ci.yml`
Expected: PASS.

**Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: upload coverage to codecov"
```

### Task 2: Add The README Coverage Badge

**Files:**
- Modify: `README.md`

**Step 1: Add the Codecov badge near the top**

Insert:

```md
[![codecov](https://codecov.io/github/minhuw/coquic/graph/badge.svg?branch=main)](https://app.codecov.io/github/minhuw/coquic)
```

directly below the `# coquic` heading.

**Step 2: Document the CI upload**

Adjust the CI section so it states that the workflow now uploads the coverage
report to Codecov in addition to exporting local artifacts.

**Step 3: Verify the docs remain consistent**

Run: `sed -n '1,80p' README.md`
Expected: PASS and show the badge plus updated CI description.

**Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add codecov badge"
```

### Task 3: Re-Run Local Verification

**Files:**
- Modify: none

**Step 1: Re-run the local coverage pipeline**

Run: `nix develop -c zig build coverage`
Expected: PASS.

**Step 2: Re-run formatting and lint hooks**

Run: `nix develop -c pre-commit run clang-format --all-files --show-diff-on-failure`
Expected: PASS.

Run: `nix develop -c pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure`
Expected: PASS.

**Step 3: Confirm the branch is ready**

Run: `git status --short`
Expected: clean working tree after commits.
