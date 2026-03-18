# QUIC RAG Tools

This directory contains the local Python tooling for the QUIC RFC knowledge base.

Current scope:
- index RFC text from `docs/rfc`
- store generated local state under `.rag`
- expose query tooling through a local FastMCP server
- share one localhost-only Qdrant dev backend across multiple Codex sessions

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

The default embedding model is `sentence-transformers/all-MiniLM-L6-v2`, stored under `.rag/cache/models`.
`build-index` now shows parse and embedding progress, and the MCP server exits early with a clear error if `.rag` is incomplete.

Shared Qdrant dev backend:

```bash
nix run .#qdrant-dev -- start
nix run .#qdrant-dev -- status
```

The dev daemon listens on `127.0.0.1:6333` only, so it is reachable from the
local machine but not exposed on the network. One daemon can serve multiple
Codex sessions at the same time.

The repo-root wrappers default `COQUIC_QDRANT_URL` to
`http://127.0.0.1:6333`, while still honoring a manual override when you set
that environment variable yourself:

```bash
tools/rag/scripts/build-index --source docs/rfc --state-dir .rag
tools/rag/scripts/run-mcp
```

Start the MCP server for Codex:

```bash
uv run --project tools/rag python -m coquic_rag.mcp_server.server
```

Recommended Codex MCP config:

```toml
[mcp_servers.quic-rag]
command = "bash"
args = ["-lc", "cd /home/minhu/projects/coquic && tools/rag/scripts/run-mcp"]
startup_timeout_sec = 30

[mcp_servers.quic-rag.env]
UV_CACHE_DIR = "/tmp/uv-cache"
```

When you are done with the shared backend:

```bash
nix run .#qdrant-dev -- stop
```
