# coquic

[![CI](https://github.com/minhuw/coquic/actions/workflows/ci.yml/badge.svg)](https://github.com/minhuw/coquic/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/minhuw/coquic/graph/badge.svg?branch=main)](https://app.codecov.io/github/minhuw/coquic)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An experimental project exploring how far Codex, paired with GPT-5.4 and later
models, can go in building a full-featured QUIC implementation.

## Development

```bash
nix develop
zig build
zig build test
zig build coverage
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
