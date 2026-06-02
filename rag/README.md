# QUIC RAG Tools

This directory contains the local Python tooling for the QUIC specification
knowledge base.

Current scope:
- index mixed RFC and Internet-Draft text from `docs/rfc`
- store generated local state under `.rag`
- expose query tooling through a repo-local Codex skill and CLI
- share one localhost-only Qdrant dev backend across multiple Codex sessions
- expose a public-demo QA API that uses hosted embeddings, Qdrant, and OpenRouter free chat models

Setup:

```bash
uv sync --project rag
uv run --project rag pytest
```

Generic document ingestion uses LlamaIndex readers, and source code ingestion
uses CocoIndex. Embeddings are hosted through OpenRouter by default using
`nvidia/llama-nemotron-embed-vl-1b-v2:free`.

Build or rebuild the local index from the mixed specification corpus:

```bash
export OPENROUTER_API_KEY=...

uv run --project rag python -m coquic_rag.cli.main build-index --source docs/rfc --state-dir .rag
uv run --project rag python -m coquic_rag.cli.main doctor --source docs/rfc --state-dir .rag
```

`build-index` now shows parse and embedding progress, and query commands exit early with a clear error if `.rag` is incomplete.

For the low-memory public demo path, build the index with hosted OpenRouter
embeddings and Qdrant Cloud:

```bash
export OPENROUTER_API_KEY=...
export COQUIC_QDRANT_URL=https://<cluster>.<region>.cloud.qdrant.io
export COQUIC_QDRANT_API_KEY=...

rag/scripts/build-index \
  --source docs/rfc \
  --state-dir .rag
```

The same embedding model must be used for indexing and query-time retrieval.

To add or refresh a smaller corpus without resetting the whole Qdrant
collection, use `index-corpus`. It embeds parsed chunks, upserts them into
Qdrant, and merges the local graph artifacts under `--state-dir`.

Loader choices:

| Loader | Use for | Dependency |
| --- | --- | --- |
| `rfc` | RFC and Internet-Draft `.txt` files with section IDs/citations | built in |
| `llamaindex` | Generic documents such as Markdown, text, HTML, PDF, DOCX | LlamaIndex |
| `cocoindex` | Source code chunking with CocoIndex language detection/splitting | CocoIndex |
| `auto` | RFC text, source code, or generic docs based on file extensions | built in |

RFC corpus:

```bash
rag/scripts/index-corpus \
  --loader rfc \
  --source docs/rfc \
  --state-dir .rag
```

Generic documents through LlamaIndex:

```bash
rag/scripts/index-corpus \
  --loader llamaindex \
  --source docs \
  --include "**/*.md" \
  --include "**/*.pdf" \
  --state-dir .rag
```

Source code through CocoIndex:

```bash
rag/scripts/index-corpus \
  --loader cocoindex \
  --source src \
  --include "**/*.cpp" \
  --include "**/*.h" \
  --state-dir .rag
```

Use `--replace` only when you intentionally want to wipe the target collection
and rebuild it from the provided source directory:

```bash
rag/scripts/index-corpus \
  --replace \
  --loader rfc \
  --source docs/rfc \
  --state-dir .rag
```

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
rag/scripts/build-index --source docs/rfc --state-dir .rag
rag/scripts/query-rag doctor --source docs/rfc --state-dir .rag
```

Common query commands:

```bash
rag/scripts/query-rag search-sections "ACK frame behavior" --top-k 5
rag/scripts/query-rag get-section --doc rfc9000 --section-id 18.2
rag/scripts/query-rag get-section --doc draft-ietf-quic-qlog-main-schema-13 --section-id 1
rag/scripts/query-rag trace-term max_udp_payload_size
rag/scripts/query-rag lookup-term --term-type transport_parameter --name max_udp_payload_size
rag/scripts/query-rag related-sections --doc rfc9369 --section-id 5
```

Public QA API:

```bash
export OPENROUTER_API_KEY=...
export COQUIC_QDRANT_URL=https://<cluster>.<region>.cloud.qdrant.io
export COQUIC_QDRANT_API_KEY=...

rag/scripts/run-qa-api
```

The API listens on `127.0.0.1:8787` by default and exposes:

- `GET /api/health`
- `POST /api/qa` with `{ "question": "...", "model": "openai/gpt-oss-120b:free" }`

Cost controls are applied before generation: request size validation,
per-session/IP rate limiting, OpenRouter relevance classification, retrieval
confidence gating, a free-model allowlist, capped context, and capped output tokens.

Useful environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `COQUIC_QA_RATE_LIMIT` | `12` | Requests per window |
| `COQUIC_QA_RATE_WINDOW_SECONDS` | `60` | Rate-limit window |
| `COQUIC_QA_TOP_K` | `10` | Retrieved sections sent to the LLM |
| `COQUIC_QA_MAX_CONTEXT_CHARS` | `6500` | Context cap before generation |
| `COQUIC_QA_MAX_OUTPUT_TOKENS` | `650` | Generation cap |
| `COQUIC_QA_ALLOWED_ORIGINS` | local Next origins | CORS origin allowlist |

The demo page is available at `/qa` in `site/next`. Browser code calls
same-origin `/rag-api/*`; the Next.js server forwards that path to this FastAPI
service on `127.0.0.1:8787` in local development and in production. Do not
expose FastAPI directly to browsers.

Codex integration is repo-local through `.agents/skills/quic-rag`. Codex can
discover repo skills automatically when launched from this repository or a
subdirectory inside it. If the new skill does not appear in an existing Codex
session, restart Codex.

When you are done with the shared backend:

```bash
nix run .#qdrant-dev -- stop
```
