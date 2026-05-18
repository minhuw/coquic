# AGENTS

## Repo Overview

- `coquic` is an experimental QUIC implementation plus a local QUIC RFC
  knowledge base.
- Keep the root `README.md` human-facing and minimal.
- Put agent workflow and repo conventions here instead of expanding the root
  `README.md`.

## Build And Test

- Enter the reproducible development environment with `nix develop`.
- Build the project with `zig build`.
- Run the main test suite with `zig build test`.
- For daily interop validation, skip the long-running measurement cases
  `goodput` and `crosstraffic`; reserve them for full verification runs and CI.
- Generate coverage with `zig build coverage`.
- Run formatting and lint checks with:
  - `pre-commit run clang-format --all-files --show-diff-on-failure`
  - `pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure`

## Remote CI Debugging

- Use the GitHub CLI (`gh`) to inspect remote GitHub Actions failures instead
  of guessing from the web UI.
- Store all downloaded remote CI material under `.remote-ci/` in the repo root.
  Do not download logs, artifacts, traces, or temporary CI state into tracked
  source directories.
- Start from the GitHub Actions URL provided by the user. Extract the run ID
  from `/actions/runs/<run-id>` and, when present, the job ID from
  `/job/<job-id>`. Use `-R <owner>/<repo>` if the URL points at a fork or
  another repository.
- Download the failed logs for the provided run or job:
  - `gh run view <run-id> --log-failed > .remote-ci/<run-id>-failed.log`
  - `gh run view --job <job-id> --log-failed > .remote-ci/<run-id>-job-<job-id>-failed.log`
- Download run artifacts directly into `.remote-ci/`:
  - `mkdir -p .remote-ci/<run-id>`
  - `gh run download <run-id> --dir .remote-ci/<run-id>/artifacts`
- When artifacts include interop logs, coverage output, benchmark results, or
  packaged binaries, inspect them in place under `.remote-ci/<run-id>/` and
  keep any local reproduction outputs there as well.
- After identifying the failing job or step, reproduce locally with the closest
  documented command, usually through `nix develop -c ...`.
- Summarize the failing workflow, run ID, job, step, relevant log excerpt, and
  local reproduction command in the final debugging notes.

## QUIC Sources And RAG

- Prefer `docs/rfc/` as the source of truth for QUIC specification questions.
- The local RAG project lives under `tools/rag/`.
- The repo-local Codex skill for QUIC questions lives under
  `.agents/skills/quic-rag/`.
- Generated RAG state lives under `.rag/` and must not be committed.
- Build or rebuild the RAG index with:
  - `tools/rag/scripts/build-index --source docs/rfc --state-dir .rag`
- Check index readiness with:
  - `tools/rag/scripts/query-rag doctor --source docs/rfc --state-dir .rag`
- Query the local QUIC specification knowledge base with:
  - `tools/rag/scripts/query-rag search-sections "ACK frame behavior" --top-k 5`
  - `tools/rag/scripts/query-rag get-section --doc rfc9000 --section-id 18.2`
  - `tools/rag/scripts/query-rag get-section --doc draft-ietf-quic-qlog-main-schema-13 --section-id 1`
  - `tools/rag/scripts/query-rag trace-term max_udp_payload_size`
- For QUIC protocol questions, use the repo-local `quic-rag` skill and the
  query wrapper above instead of the old MCP flow.
- If you change `tools/rag/`, run:
  - `uv run --project tools/rag pytest tools/rag/tests`

## Repo Conventions

- If worktrees are needed, keep them under `.worktrees/` inside the repo.
- Do not commit generated local state such as `.rag/`.
- Do not commit downloaded remote CI state such as `.remote-ci/`.
- When answering QUIC protocol questions, prefer grounded citations from the
  specification corpus or the local QUIC RAG.
