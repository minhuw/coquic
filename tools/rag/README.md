# QUIC RAG Tools

This directory contains the local Python tooling for the QUIC RFC knowledge base.

Current scope:
- index RFC text from `docs/rfc`
- store generated local state under `.rag`
- expose query tooling through a local FastMCP server

Setup:

```bash
uv sync --project tools/rag
uv run --project tools/rag pytest
```

Build or rebuild the local index from the RFC corpus:

```bash
uv run --project tools/rag python -m coquic_rag.cli.main build-index --source docs/rfc --state-dir .rag
uv run --project tools/rag python -m coquic_rag.cli.main doctor --source docs/rfc --state-dir .rag
```

The default embedding model is `mixedbread-ai/mxbai-embed-large-v1`, stored under `.rag/cache/models`.

Start the MCP server for Codex:

```bash
uv run --project tools/rag python -m coquic_rag.mcp_server.server
```

Repo-root convenience wrappers are also available:

```bash
tools/rag/scripts/build-index --source docs/rfc --state-dir .rag
tools/rag/scripts/run-mcp
```
