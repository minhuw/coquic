# Musl Interop Image Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the two musl interop image variants into one official-endpoint-based image exposed as `coquic-interop:boringssl-musl`.

**Architecture:** Keep the musl package output unchanged, but repoint the exported musl interop image attribute to the official endpoint layered image. Remove the extra `official-endpoint` naming from the Nix output, Docker tag, docs, and the Nix image verification script.

**Tech Stack:** Nix flakes, Docker layered images, shell verification scripts

---

### Task 1: Rename the verification target first

**Files:**
- Create: `tests/nix/boringssl_musl_image_test.sh`
- Modify: `docs/quic-interop-runner.md`
- Modify: `flake.nix`

- [ ] **Step 1: Write the failing test**

Update the musl image verification script to build `.#interop-image-boringssl-musl` and inspect the Docker tag `coquic-interop:boringssl-musl`.

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/nix/boringssl_musl_image_test.sh`
Expected: FAIL because `flake.nix` still exports the old musl image/tag shape.

- [ ] **Step 3: Write minimal implementation**

Repoint the exported musl interop image to the official endpoint layered image and remove the extra `official-endpoint` output name.

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/nix/boringssl_musl_image_test.sh`
Expected: PASS with the official endpoint base layers preserved and entrypoint set to `/run_endpoint.sh`.

- [ ] **Step 5: Update docs**

Update the interop doc examples to use the single musl image attr and tag.

- [ ] **Step 6: Verify docs/build references**

Run a reference sweep across `flake.nix`, `docs`, and `tests` for the removed musl
official-endpoint export names.
Expected: no remaining repository-facing references after the cleanup.
