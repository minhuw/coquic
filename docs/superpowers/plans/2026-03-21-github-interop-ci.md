# GitHub Interop CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a separate GitHub Actions workflow for the current `quic-go` interop smoke matrix and back it with a reusable local shell script.

**Architecture:** Keep the main CI workflow unchanged. Add a repo-owned shell runner under `tests/nix/` that builds on the existing mixed-image manual interop procedure, then call that script from a new `.github/workflows/interop.yml` workflow triggered by `pull_request`, `push`, and `workflow_dispatch`.

**Tech Stack:** GitHub Actions, Nix, Docker, shell scripting

---

### Task 1: Add a failing workflow contract test

**Files:**
- Create: `tests/nix/github_interop_workflow_test.sh`
- Create: `.github/workflows/interop.yml`

- [ ] **Step 1: Write the failing test**

Create `tests/nix/github_interop_workflow_test.sh` to assert that
`.github/workflows/interop.yml`:

- exists
- includes `pull_request`, `push`, and `workflow_dispatch`
- invokes `bash tests/nix/quicgo_interop_smoke_test.sh`

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/nix/github_interop_workflow_test.sh`
Expected: FAIL because the workflow file does not exist yet.

- [ ] **Step 3: Add the minimal workflow**

Create `.github/workflows/interop.yml` with one Ubuntu job that installs Nix,
enables the Determinate cache, builds `.#interop-image-boringssl-musl`, pulls
`martenseemann/quic-go-interop:latest`, and runs the smoke script.

- [ ] **Step 4: Re-run the workflow contract test**

Run: `bash tests/nix/github_interop_workflow_test.sh`
Expected: PASS.

### Task 2: Add the reusable quic-go smoke runner

**Files:**
- Create: `tests/nix/quicgo_interop_smoke_test.sh`
- Modify: `docs/quic-interop-runner.md`

- [ ] **Step 1: Write the smoke runner**

Create a shell script that:

- builds and loads `.#interop-image-boringssl-musl`
- pulls `martenseemann/quic-go-interop:latest`
- runs the four mixed interop cases over temporary Docker bridge networks
- prints logs and exits non-zero on any failure

- [ ] **Step 2: Run the smoke runner**

Run: `bash tests/nix/quicgo_interop_smoke_test.sh`
Expected: PASS with all four `quic-go` smoke cases succeeding.

- [ ] **Step 3: Document the local entrypoint**

Add a short section to `docs/quic-interop-runner.md` showing the local smoke
command and noting that GitHub interop CI calls the same script.

- [ ] **Step 4: Verify the final contract**

Run:

```bash
bash tests/nix/github_interop_workflow_test.sh
bash tests/nix/quicgo_interop_smoke_test.sh
```

Expected: both commands pass.
