# AGENTS

Last updated: 2026-06-12

These repository instructions apply unless a newer user or developer instruction
conflicts, or the required tool is unavailable in the current environment. When a
constraint blocks an instruction, state the constraint and use the closest safe
alternative.

## Glossary

- Quick UDP (User Datagram Protocol) Internet Connections (QUIC).
- Retrieval-augmented generation (RAG).

## Identity

Act as a pragmatic coding agent for the `coquic` repository. Preserve user work,
make focused source changes, validate with the repository toolchain, and report
constraints clearly.

## Tools

| Tool | Purpose |
| --- | --- |
| `nix develop -c ...` | Reproducible build, test, format, and lint |
| `rg` or `rg --files` | Repository searches |
| `gh` | GitHub Actions and remote CI inspection |
| `uv run --project rag ...` | Python RAG project commands |
| `rag/scripts/query-rag` | Local QUIC specification lookups |

## Critical

- Respect existing user changes in the working tree.
- Keep generated local state out of tracked source.
- Keep downloaded CI state out of tracked source.
- Keep build outputs out of tracked source.
- Keep agent workflow details in this file.
- Keep the root `README.md` human-facing and minimal.
- Use `nix develop -c ...` for commands that need the reproducible toolchain.
- Use `gh` for GitHub Actions inspection when debugging remote CI.
- Store downloaded CI files under `.remote-ci/`.
- Store generated RAG state under `.rag/`.
- Use the configured RAG/Qdrant index as the source of truth for QUIC
  specification questions.
- For QUIC protocol questions, use `.agents/skills/quic-rag/`.
- For QUIC protocol questions, query with `rag/scripts/query-rag`.
- Do not commit generated RAG state such as `.rag/`.
- Do not commit downloaded remote CI state such as `.remote-ci/`.
- Keep `main` as the only remote branch; merge all local branch work back into
  `main` before syncing or pushing to the remote.
- Use Conventional Commits for git commit messages.

## Standard

- `coquic` is an experimental QUIC implementation plus a local RFC knowledge
  base.
- Prefer `rg` or `rg --files` for repository searches.
- Build the project with `zig build`.
- Run the main test suite with `zig build test`.
- Skip `goodput` and `crosstraffic` during daily validation.
- Reserve `goodput` and `crosstraffic` for full verification.
- Use `uv run --project rag ...` for Python RAG project commands.
- Use `rag/scripts/query-rag` for local QUIC specification lookups.
- The local RAG project lives under `rag/`.
- The repo-local Codex skill for QUIC questions lives under
  `.agents/skills/quic-rag/`.
- Keep worktrees under `.worktrees/` inside the repo.
- Prefer grounded citations for QUIC protocol questions.

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
- Inspect interop logs under `.remote-ci/`.
- Inspect coverage output under `.remote-ci/`.
- Inspect benchmark results under `.remote-ci/`.
- Keep local reproduction outputs for remote CI under `.remote-ci/<run-id>/`.
- Reproduce failures with the closest documented local command.
- Include the workflow in final debugging notes.
- Include the run ID in final debugging notes.
- Include the job in final debugging notes.
- Include the step in final debugging notes.
- Include the relevant log excerpt in final debugging notes.
- Include the local reproduction command in final debugging notes.

## Optional

- Generate coverage with `zig build coverage`.
- Build the RAG index with `rag/scripts/build-index`.
- Check index readiness with `rag/scripts/query-rag doctor --state-dir .rag`.
- Query the local QUIC knowledge base with `rag/scripts/query-rag`.
- When changing `rag/`, run `uv run --project rag pytest rag/tests`.
