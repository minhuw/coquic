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
- Query the local RFC knowledge base with:
  - `tools/rag/scripts/query-rag search-sections "ACK frame behavior" --top-k 5`
  - `tools/rag/scripts/query-rag get-section --rfc 9000 --section-id 18.2`
  - `tools/rag/scripts/query-rag trace-term max_udp_payload_size`
- For QUIC protocol questions, use the repo-local `quic-rag` skill and the
  query wrapper above instead of the old MCP flow.
- If you change `tools/rag/`, run:
  - `uv run --project tools/rag pytest tools/rag/tests`

## Repo Conventions

- If worktrees are needed, keep them under `.worktrees/` inside the repo.
- Do not commit generated local state such as `.rag/`.
- When answering QUIC protocol questions, prefer grounded citations from the
  RFC corpus or the local QUIC RAG.
