# README And AGENTS Split Design

## Status

Approved on 2026-03-17.

## Context

The repository currently has a single root `README.md` that mixes human-facing
project information with workflow details that are more useful to coding
agents. The user wants a cleaner split:

- `README.md` for humans
- `AGENTS.md` for Codex and other agents

The user also asked to keep `README.md` "deadly simple".

## Goal

Make the root `README.md` minimal and human-oriented while moving repo-specific
agent workflow guidance into a new root `AGENTS.md`.

## Decisions

### README.md

- Keep only:
  - project name
  - one-sentence description
  - a tiny quickstart with the most important commands
  - one pointer to `tools/rag/README.md` for QUIC knowledge base details
- Remove badges, CI detail, and long development instructions.

### AGENTS.md

- Add a new root `AGENTS.md` with:
  - repo overview
  - canonical build and test commands
  - QUIC RFC source-of-truth guidance
  - QUIC RAG location and health-check commands
  - reminder that `.rag/` is generated state and must not be committed
  - user preference that repo worktrees live under `.worktrees/`

### Scope

- Only update the root documentation split in this change.
- Do not rewrite `tools/rag/README.md`.
- Do not change source code or build behavior.

## Verification

The change is complete when:

- `README.md` is short and clearly human-facing
- `AGENTS.md` exists and contains the repo instructions agents need
- `git diff --check` reports no patch formatting errors

