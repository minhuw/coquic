# AGENTS

Last updated: 2026-06-04

These repository instructions apply unless a newer user or developer instruction
conflicts, or the required tool is unavailable in the current environment. When a
constraint blocks an instruction, state the constraint and use the closest safe
alternative.

## Critical

- Respect existing user changes in the working tree.
- Keep generated local state out of tracked source.
- Keep downloaded CI state out of tracked source.
- Keep build outputs out of tracked source.
- Keep agent workflow details in this file.
- Keep the root `README.md` human-facing and minimal.
- Use `nix develop -c ...` for local build, test, format, and lint commands that
  need the reproducible toolchain.
- Use `gh` for GitHub Actions inspection when debugging remote CI.
- Store downloaded CI files under `.remote-ci/`.
- Store generated RAG state under `.rag/`.
- Use the configured RAG/Qdrant index as the source of truth for QUIC
  specification questions.
- For QUIC protocol questions, use `.agents/skills/quic-rag/`.
- For QUIC protocol questions, query with `rag/scripts/query-rag`.
- Do not commit generated RAG state such as `.rag/`.
- Do not commit downloaded remote CI state such as `.remote-ci/`.
- Use Conventional Commits for git commit messages.

## Standard

- `coquic` is an experimental QUIC (Quick UDP (User Datagram Protocol) Internet
  Connections) implementation plus a local QUIC RFC (Request for Comments)
  knowledge base.
- RAG (retrieval-augmented generation) means using a search index as grounded
  context for answers.
- Prefer `rg` or `rg --files` for repository searches.
- Build the project with `zig build`.
- Run the main test suite with `zig build test`.
- Skip the long-running interop measurement cases `goodput` and `crosstraffic`
  during daily validation.
- Reserve `goodput` and `crosstraffic` for full verification runs and CI.
- Before broad C++ commits, run `pre-commit run clang-format --all-files
  --show-diff-on-failure`.
- Before broad C++ commits, run `pre-commit run coquic-clang-tidy --all-files
  --show-diff-on-failure`.
- Use `uv run --project rag ...` for Python RAG project commands.
- Use `rag/scripts/query-rag` for local QUIC specification lookups.
- The local RAG project lives under `rag/`.
- The repo-local Codex skill for QUIC questions lives under
  `.agents/skills/quic-rag/`.
- Keep worktrees under `.worktrees/` inside the repo.
- Prefer grounded citations from the specification corpus or local QUIC RAG when
  answering QUIC protocol questions.

## Remote CI

- Start from the GitHub Actions URL provided by the user.
- Use `-R <owner>/<repo>` when the URL points at a fork or another repository.

| Material | Destination | Command |
| --- | --- | --- |
| Failed run log | `.remote-ci/<run-id>-failed.log` | `gh run view <run-id> --log-failed` |
| Failed job log | `.remote-ci/<run-id>-job-<job-id>-failed.log` | `gh run view --job <job-id> --log-failed` |
| Run artifacts | `.remote-ci/<run-id>/artifacts` | `gh run download <run-id>` |

- Extract the run ID from `/actions/runs/<run-id>`.
- Extract the job ID from `/job/<job-id>` when the URL includes a job.
- Inspect interop logs in place under `.remote-ci/`.
- Inspect coverage output in place under `.remote-ci/`.
- Inspect benchmark results in place under `.remote-ci/`.
- Inspect packaged binaries in place under `.remote-ci/`.
- Keep local reproduction outputs for remote CI under `.remote-ci/<run-id>/`.
- After identifying the failing job or step, reproduce locally with the closest
  documented command, usually through `nix develop -c ...`.
- Include the workflow in final debugging notes.
- Include the run ID in final debugging notes.
- Include the job in final debugging notes.
- Include the step in final debugging notes.
- Include the relevant log excerpt in final debugging notes.
- Include the local reproduction command in final debugging notes.

## Optional

- Generate coverage with `zig build coverage`.
- Build or rebuild the RAG index with
  `rag/scripts/build-index --source <source-dir> --state-dir .rag`.
- Check index readiness with `rag/scripts/query-rag doctor --state-dir .rag`.
- Query the local QUIC specification knowledge base with
  `rag/scripts/query-rag search-sections`, `get-section`, or `trace-term`.
- When changing `rag/`, run `uv run --project rag pytest rag/tests`.
