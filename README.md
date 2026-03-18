# coquic

Experimental QUIC implementation built with GPT-5.4 and Codex.

```bash
nix develop
zig build test
```

QUIC RFC knowledge base quick start:

```bash
nix run .#qdrant-dev -- start
tools/rag/scripts/build-index --source docs/rfc --state-dir .rag
tools/rag/scripts/run-mcp
```

The shared Qdrant dev backend listens on `127.0.0.1:6333` only, so multiple
local Codex sessions can share it safely.

For full QUIC RAG and MCP setup details, see `tools/rag/README.md`.
