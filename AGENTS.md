# AGENTS

Last updated: 2026-06-04

## Identity And Boundaries

- Required: respect existing user changes in the working tree.
- Required: keep generated local state, downloaded CI state, and build outputs out of
  tracked source.
- Required: keep agent workflow details in this file instead of the root `README.md`.
- Default: act as a pragmatic coding agent working in the `coquic` repository.

## Repo Overview

- Default: `coquic` is an experimental QUIC (Quick UDP (User Datagram Protocol)
  Internet Connections) implementation plus a local QUIC RFC (Request for
  Comments) knowledge base.
- Default: RAG (retrieval-augmented generation) means using a search index as
  grounded context for answers.
- Required: keep the root `README.md` human-facing and minimal.

## Tools

- Required: use `rg` or `rg --files` for repository searches when available.
- Required: use `nix develop -c ...` for local build, test, format, and lint
  commands that need the reproducible toolchain.
- Required: use `gh` for GitHub Actions inspection when debugging remote CI.
- Required: use `uv run --project rag ...` for Python RAG project commands.
- Required: use `rag/scripts/query-rag` for local QUIC specification lookups.
- Required: keep downloaded CI files under `.remote-ci/`.
- Required: keep generated RAG state under `.rag/`.

## Build And Test

- Required: enter the reproducible development environment with `nix develop`.
- Required: build the project with `zig build`.
- Required: run the main test suite with `zig build test`.
- Default: for daily interop validation, skip the long-running measurement cases
  `goodput` and `crosstraffic`; reserve them for full verification runs and CI.
- Optional: generate coverage with `zig build coverage`.
- Required: before broad C++ commits, run `pre-commit run clang-format --all-files
  --show-diff-on-failure` and `pre-commit run coquic-clang-tidy --all-files
  --show-diff-on-failure`.

## Remote CI Debugging

- Required: use the GitHub CLI (`gh`) to inspect remote GitHub Actions failures instead
  of guessing from the web UI.
- Required: store all downloaded remote CI material under `.remote-ci/` in the repo root.
  Do not download logs, artifacts, traces, or temporary CI state into tracked
  source directories.
- Required: start from the GitHub Actions URL provided by the user.
- Required: extract the run ID from `/actions/runs/<run-id>`.
- Required: extract the job ID from `/job/<job-id>` when a job URL is present.
- Required: use `-R <owner>/<repo>` if the URL points at a fork or another
  repository.
- Required: save failed run logs under `.remote-ci/<run-id>-failed.log`.
- Required: use `gh run view` for failed run logs.
- Required: save failed job logs under
  `.remote-ci/<run-id>-job-<job-id>-failed.log`.
- Required: use `gh run view --job` for failed job logs.
- Required: create `.remote-ci/<run-id>` before downloading artifacts.
- Required: put artifacts under `.remote-ci/<run-id>/artifacts` with
  `gh run download`.
- Default: inspect interop logs, coverage output, benchmark results, and
  packaged binaries in place under `.remote-ci/<run-id>/`.
- Required: keep local reproduction outputs for remote CI under `.remote-ci/<run-id>/`.
- Required: after identifying the failing job or step, reproduce locally with the closest
  documented command, usually through `nix develop -c ...`.
- Required: summarize the failing workflow and run ID in the final debugging notes.
- Required: include the job, step, relevant log excerpt, and local reproduction
  command in the final debugging notes.

## QUIC Sources And RAG

- Required: use the configured RAG/Qdrant index as the source of truth for QUIC
  specification questions.
- Default: the local RAG project lives under `rag/`.
- Default: the repo-local Codex skill for QUIC questions lives under
  `.agents/skills/quic-rag/`.
- Required: do not commit generated RAG state.
- Default: build or rebuild the RAG index with
  `rag/scripts/build-index --source <source-dir> --state-dir .rag`.
- Default: check index readiness with
  `rag/scripts/query-rag doctor --state-dir .rag`.
- Default: query the local QUIC specification knowledge base with
  `rag/scripts/query-rag search-sections`, `get-section`, or `trace-term`.
- Required: for QUIC protocol questions, use the repo-local `quic-rag` skill and the
  query wrapper above instead of the old MCP (Model Context Protocol) flow.
- Required: when changing `rag/`, run `uv run --project rag pytest rag/tests`.

## Repo Conventions

- Required: if worktrees are needed, keep them under `.worktrees/` inside the repo.
- Required: use the Conventional Commits guideline when writing git commit messages.
- Required: do not commit generated local state such as `.rag/`.
- Required: do not commit downloaded remote CI state such as `.remote-ci/`.
- Required: when answering QUIC protocol questions, prefer grounded citations from the
  specification corpus or the local QUIC RAG.
