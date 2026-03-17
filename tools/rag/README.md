# QUIC RAG Tools

This directory contains the local Python tooling for the QUIC knowledge base.

Current scope:
- index RFC text from `docs/rfc`
- store generated local state under `.rag`
- expose query tooling through an MCP server in later tasks

Bootstrap:

```bash
uv sync --project tools/rag
uv run --project tools/rag pytest tools/rag/tests/test_project_smoke.py -q
```
