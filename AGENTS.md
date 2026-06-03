# AGENTS

Last updated: 2026-06-03

## Identity And Boundaries

- Required: respect existing user changes in the working tree.
- Required: keep generated local state, downloaded CI state, and build outputs out of
  tracked source.
- Required: keep agent workflow details in this file instead of the root `README.md`.
- Default: act as a pragmatic coding agent working in the `coquic` repository.

## Repo Overview

- `coquic` is an experimental QUIC (Quick UDP Internet Connections)
  implementation plus a local QUIC RFC (Request for Comments) knowledge base.
- UDP means User Datagram Protocol.
- RAG means retrieval-augmented generation.
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
- Required before broad C++ commits: run formatting and lint checks with:
  - `pre-commit run clang-format --all-files --show-diff-on-failure`
  - `pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure`

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
- Required: download failed run logs with:
  - `gh run view <run-id> --log-failed > .remote-ci/<run-id>-failed.log`
- Required: download failed job logs with:
  - `gh run view --job <job-id> --log-failed > .remote-ci/<run-id>-job-<job-id>-failed.log`
- Required: create an artifact directory with:
  - `mkdir -p .remote-ci/<run-id>`
- Required: put artifacts under `.remote-ci/<run-id>/artifacts` with:
  - `gh run download <run-id> --dir .remote-ci/<run-id>/artifacts`
- Default: inspect interop logs, coverage output, benchmark results, and
  packaged binaries in place under `.remote-ci/<run-id>/`.
- Required: keep local reproduction outputs for remote CI under `.remote-ci/<run-id>/`.
- Required: after identifying the failing job or step, reproduce locally with the closest
  documented command, usually through `nix develop -c ...`.
- Required: summarize the failing workflow and run ID in the final debugging notes.
- Required: include the job, step, relevant log excerpt, and local reproduction
  command in the final debugging notes.

## QUIC Sources And RAG

- Required: prefer `docs/rfc/` as the source of truth for QUIC specification questions.
- Default: the local RAG project lives under `rag/`.
- The repo-local Codex skill for QUIC questions lives under
  `.agents/skills/quic-rag/`.
- Required: do not commit generated RAG state.
- Build or rebuild the RAG index with:
  - `rag/scripts/build-index --source docs/rfc --state-dir .rag`
- Check index readiness with:
  - `rag/scripts/query-rag doctor --source docs/rfc --state-dir .rag`
- Query the local QUIC specification knowledge base with:
  - `rag/scripts/query-rag search-sections "ACK (Acknowledgement) frame behavior" --top-k 5`
  - `rag/scripts/query-rag get-section --doc rfc9000 --section-id 18.2`
  - `rag/scripts/query-rag get-section --doc draft-ietf-quic-qlog-main-schema-13 --section-id 1`
  - `rag/scripts/query-rag trace-term max_udp_payload_size`
- For QUIC protocol questions, use the repo-local `quic-rag` skill and the
  query wrapper above instead of the old MCP (Model Context Protocol) flow.
- If you change `rag/`, run:
  - `uv run --project rag pytest rag/tests`

## Repo Conventions

- If worktrees are needed, keep them under `.worktrees/` inside the repo.
- Use the Conventional Commits guideline when writing git commit messages.
- Do not commit generated local state such as `.rag/`.
- Do not commit downloaded remote CI state such as `.remote-ci/`.
- When answering QUIC protocol questions, prefer grounded citations from the
  specification corpus or the local QUIC RAG.
