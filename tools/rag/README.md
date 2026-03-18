# QUIC RAG Tools

This directory contains the local Python tooling for the QUIC RFC knowledge base.

Current scope:
- index RFC text from `docs/rfc`
- store generated local state under `.rag`
- expose query tooling through a repo-local Codex skill and CLI
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
`build-index` now shows parse and embedding progress, and query commands exit early with a clear error if `.rag` is incomplete.

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
tools/rag/scripts/query-rag doctor --source docs/rfc --state-dir .rag
```

Common query commands:

```bash
tools/rag/scripts/query-rag search-sections "ACK frame behavior" --top-k 5
tools/rag/scripts/query-rag get-section --rfc 9000 --section-id 18.2
tools/rag/scripts/query-rag trace-term max_udp_payload_size
tools/rag/scripts/query-rag lookup-term --term-type transport_parameter --name max_udp_payload_size
tools/rag/scripts/query-rag related-sections --rfc 9369 --section-id 5
```

Codex integration is repo-local through `.agents/skills/quic-rag`. Codex can
discover repo skills automatically when launched from this repository or a
subdirectory inside it. If the new skill does not appear in an existing Codex
session, restart Codex.

When you are done with the shared backend:

```bash
nix run .#qdrant-dev -- stop
```
