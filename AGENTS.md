# AGENTS

Last updated: 2026-06-04

## Identity And Boundaries

- MUST: respect existing user changes in the working tree.
- MUST: keep generated local state, downloaded CI state, and build outputs out of
  tracked source.
- MUST: keep agent workflow details in this file instead of the root `README.md`.
- SHOULD: act as a pragmatic coding agent working in the `coquic` repository.

## Repo Overview

- SHOULD: `coquic` is an experimental QUIC (Quick UDP (User Datagram Protocol)
  Internet Connections) implementation plus a local QUIC RFC (Request for
  Comments) knowledge base.
- SHOULD: RAG (retrieval-augmented generation) means using a search index as
  grounded context for answers.
- MUST: keep the root `README.md` human-facing and minimal.

## Tools

- MUST: use `rg` or `rg --files` for repository searches when available.
- MUST: use `nix develop -c ...` for local build, test, format, and lint
  commands that need the reproducible toolchain.
- MUST: use `gh` for GitHub Actions inspection when debugging remote CI.
- MUST: use `uv run --project rag ...` for Python RAG project commands.
- MUST: use `rag/scripts/query-rag` for local QUIC specification lookups.
- MUST: keep downloaded CI files under `.remote-ci/`.
- MUST: keep generated RAG state under `.rag/`.

## Build And Test

- MUST: enter the reproducible development environment with `nix develop`.
- MUST: build the project with `zig build`.
- MUST: run the main test suite with `zig build test`.
- SHOULD: for daily interop validation, skip the long-running measurement cases
  `goodput` and `crosstraffic`; reserve them for full verification runs and CI.
- MAY: generate coverage with `zig build coverage`.
- MUST: before broad C++ commits, run `pre-commit run clang-format --all-files
  --show-diff-on-failure` and `pre-commit run coquic-clang-tidy --all-files
  --show-diff-on-failure`.

## Remote CI Debugging

- MUST: use the GitHub CLI (`gh`) to inspect remote GitHub Actions failures instead
  of guessing from the web UI.
- MUST: store all downloaded remote CI material under `.remote-ci/` in the repo root.
  Do not download logs, artifacts, traces, or temporary CI state into tracked
  source directories.
- MUST: start from the GitHub Actions URL provided by the user.
- MUST: extract the run ID from `/actions/runs/<run-id>`.
- MUST: extract the job ID from `/job/<job-id>` when a job URL is present.
- MUST: use `-R <owner>/<repo>` if the URL points at a fork or another
  repository.
- MUST: write failed run logs to `.remote-ci/<run-id>-failed.log`.
- MUST: fetch failed run logs with `gh run view`.
- MUST: write failed job logs to `.remote-ci/<run-id>-job-<job-id>-failed.log`.
- MUST: fetch failed job logs with `gh run view --job`.
- MUST: create `.remote-ci/<run-id>` before downloading artifacts.
- MUST: put artifacts under `.remote-ci/<run-id>/artifacts` with
  `gh run download`.
- SHOULD: inspect interop logs, coverage output, benchmark results, and
  packaged binaries in place under `.remote-ci/<run-id>/`.
- MUST: keep local reproduction outputs for remote CI under `.remote-ci/<run-id>/`.
- MUST: after identifying the failing job or step, reproduce locally with the closest
  documented command, usually through `nix develop -c ...`.
- MUST: summarize the failing workflow and run ID in the final debugging notes.
- MUST: include the job, step, relevant log excerpt, and local reproduction
  command in the final debugging notes.

## QUIC Sources And RAG

- MUST: use the configured RAG/Qdrant index as the source of truth for QUIC
  specification questions.
- SHOULD: the local RAG project lives under `rag/`.
- SHOULD: the repo-local Codex skill for QUIC questions lives under
  `.agents/skills/quic-rag/`.
- MUST: do not commit generated RAG state.
- SHOULD: build or rebuild the RAG index with
  `rag/scripts/build-index --source <source-dir> --state-dir .rag`.
- SHOULD: check index readiness with
  `rag/scripts/query-rag doctor --state-dir .rag`.
- SHOULD: query the local QUIC specification knowledge base with
  `rag/scripts/query-rag search-sections`, `get-section`, or `trace-term`.
- MUST: for QUIC protocol questions, use the repo-local `quic-rag` skill and the
  query wrapper above instead of the old MCP (Model Context Protocol) flow.
- MUST: when changing `rag/`, run `uv run --project rag pytest rag/tests`.

## Repo Conventions

- MUST: if worktrees are needed, keep them under `.worktrees/` inside the repo.
- MUST: use the Conventional Commits guideline when writing git commit messages.
- MUST: do not commit generated local state such as `.rag/`.
- MUST: do not commit downloaded remote CI state such as `.remote-ci/`.
- MUST: when answering QUIC protocol questions, prefer grounded citations from the
  specification corpus or the local QUIC RAG.
