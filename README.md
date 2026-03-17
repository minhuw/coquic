# coquic

coquic is an experimental project to see how far a feature-complete QUIC implementation can be built using only GPT-5.4 + Codex, documenting the progress, limits, and lessons from that effort.

## QUIC Knowledge Base

The repository now includes a local QUIC RFC knowledge base under `tools/rag/`.

- Source corpus: `docs/rfc/`
- Generated local state: `.rag/`
- Index build: `tools/rag/scripts/build-index --source docs/rfc --state-dir .rag`
- MCP server: `tools/rag/scripts/run-mcp`

After `uv sync --project tools/rag`, you can rebuild the local index with:

```bash
uv run --project tools/rag python -m coquic_rag.cli.main build-index --source docs/rfc --state-dir .rag
uv run --project tools/rag python -m coquic_rag.cli.main doctor --source docs/rfc --state-dir .rag
```

## Development

Enter the reproducible development shell with:

```bash
nix develop
```

The shell installs the project's pre-commit hooks automatically. You can also run the checks manually:

```bash
pre-commit run clang-format --all-files --show-diff-on-failure
pre-commit run coquic-clang-tidy --all-files --show-diff-on-failure
zig build
zig build test
```

## CI

GitHub Actions runs the same four checks through `nix develop`:

- format check
- lint
- build
- test
