# README And AGENTS Split Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split the root project documentation into a very small human-facing `README.md` and a repo-specific agent-facing `AGENTS.md`.

**Architecture:** Keep the root `README.md` as a tiny entry point for people, move workflow and repository conventions into `AGENTS.md`, and leave subsystem docs such as `tools/rag/README.md` as the detailed references. No source code or runtime behavior changes are needed.

**Tech Stack:** Markdown, Git

---

### Task 1: Record The Documentation Split

**Files:**
- Create: `docs/plans/2026-03-17-readme-agents-split-design.md`
- Create: `docs/plans/2026-03-17-readme-agents-split.md`

**Step 1: Write the approved design**

Document:
- the goal of the split
- the minimal `README.md` scope
- the `AGENTS.md` responsibilities

**Step 2: Save the implementation plan**

Document:
- exact files to touch
- intended content boundaries
- verification steps

### Task 2: Simplify The Root README

**Files:**
- Modify: `README.md`

**Step 1: Replace the current root README content**

Keep only:
- project name
- one-line summary
- minimal quickstart commands
- pointer to `tools/rag/README.md`

**Step 2: Verify the README is clearly human-facing**

Check:
- no agent-specific instructions remain
- no large workflow or CI sections remain

### Task 3: Add The Root AGENTS File

**Files:**
- Create: `AGENTS.md`

**Step 1: Write the repo instructions agents need**

Include:
- repo overview
- canonical build and test commands
- RAG workflow and source-of-truth notes
- generated state and worktree conventions

**Step 2: Keep the file focused**

Check:
- instructions are repo-specific
- content moved out of `README.md` now lives here

### Task 4: Verify The Doc Split

**Files:**
- Verify: `README.md`
- Verify: `AGENTS.md`

**Step 1: Run patch verification**

Run: `git diff --check`
Expected: PASS.

**Step 2: Review the final diff**

Run: `git diff -- README.md AGENTS.md docs/plans/2026-03-17-readme-agents-split-design.md docs/plans/2026-03-17-readme-agents-split.md`
Expected: README is minimal and AGENTS carries the agent workflow.

