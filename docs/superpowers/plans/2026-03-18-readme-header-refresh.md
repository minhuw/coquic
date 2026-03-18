# README Header Refresh Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refresh `README.md` with a cleaner badge-led header, move setup details into a `Development` section, and add a root MIT license file.

**Architecture:** Keep the README minimal and human-facing. The header carries the title, three badges, and one concise implementation-focused pitch, while the existing setup details remain in a single `Development` section. The MIT license lives in the repository root and is referenced directly from the README.

**Tech Stack:** Markdown, GitHub Actions badges, Codecov badge, MIT license text

---

## File Map

- Modify: `README.md`
  - Add the `CI`, `Codecov`, and `MIT` badges, polish the project pitch, and
    reorganize the operational content into `## Development`.
- Create: `LICENSE`
  - Add the standard MIT license text for the repository.

### Task 1: Add The MIT License File

**Files:**
- Create: `LICENSE`

- [ ] **Step 1: Add the standard MIT text**

Create `LICENSE` with the canonical MIT license body and a `2026 minhuw`
copyright line.

- [ ] **Step 2: Verify the file is present and readable**

Run: `sed -n '1,40p' LICENSE`
Expected: the MIT license header and copyright line render as plain text.

### Task 2: Refresh The README Header And Development Section

**Files:**
- Modify: `README.md`
- Test: `README.md`

- [ ] **Step 1: Restore and add badges**

Add these badges directly under `# coquic`:

- `CI` linked to `.github/workflows/ci.yml`
- `Codecov` linked to the repository's Codecov dashboard
- `License: MIT` linked to `LICENSE`

- [ ] **Step 2: Replace the short description**

Update the project pitch so it reads as a polished single sentence focused only
on the QUIC implementation, not on the RFC knowledge base.

- [ ] **Step 3: Introduce a Development section**

Place the quick-start shell commands and the existing QUIC RFC knowledge base
setup notes under `## Development`.

- [ ] **Step 4: Verify Markdown hygiene**

Run: `git diff --check -- README.md LICENSE`
Expected: no whitespace or merge-marker errors.

- [ ] **Step 5: Review the rendered content in plain text**

Run: `sed -n '1,120p' README.md`
Expected: title, badge row, polished pitch, and `## Development` section appear
in that order.
