# QUIC RAG Design

## Status

Approved on 2026-03-17.

## Context

`coquic` currently stores a local mirror of QUIC-related RFCs in `docs/rfc/`.
The repository does not yet have a queryable knowledge layer for those specs.
The goal is to let Codex query QUIC protocol details through a local, repo-owned
knowledge system without depending on a remote vector database or a committed
binary index.

## Goal

Build a local QUIC knowledge base that indexes `docs/rfc/`, supports grounded
semantic retrieval plus graph-style traversal, and exposes that functionality
through a FastMCP server for later Codex use.

## Decisions

### Scope

- Index only `docs/rfc/` in v1.
- Do not index repository source files, plans, or README content yet.
- Keep the design extensible so other QUIC-related sources can be added later.

### Runtime And Layout

- Implement the pipeline as a dedicated Python project in `tools/rag/`.
- Manage the Python environment with `uv`.
- Keep generated local state outside the code directory in a repo-local,
  gitignored path such as `.rag/`.

Proposed structure:

```text
tools/rag/
  pyproject.toml
  README.md
  src/coquic_rag/
    ingest/
    embed/
    graph/
    store/
    query/
    mcp_server/
    cli/
  tests/

.rag/
  qdrant/
  cache/
  artifacts/
```

### Storage

- Use `QdrantLocal` for vector storage.
- Do not commit the vector index to Git.
- Keep the index rebuildable from the RFC text sources and deterministic
  artifacts.

### Embeddings

- Use a local embedding model, not an API.
- Default to `mixedbread-ai/mxbai-embed-large-v1`.
- Keep an embedding provider abstraction so the model can be swapped later.

### Canonical Retrieval Unit

- Treat RFC sections and subsections as the primary indexed records.
- Preserve RFC number, section id, section title, and category metadata.
- Generate secondary paragraph-window chunks only as a fallback semantic view;
  sections remain the canonical unit.

### Graph Model

- Build a lightweight graph artifact without introducing a graph database.
- Model nodes such as:
  - `RFC`
  - `Section`
  - `Term`
  - `Frame`
  - `TransportParameter`
  - `ErrorCode`
- Model edges such as:
  - `contains`
  - `defines`
  - `mentions`
  - `cites`
  - `updates`

### Query Flow

1. If the caller requests an exact RFC or section, perform deterministic lookup
   first.
2. Otherwise run vector retrieval over section records in QdrantLocal.
3. Expand the best hits through the graph when the query concerns a protocol
   object such as a frame, parameter, or error code.
4. Return compact grounded results with explicit RFC and section citations.

### MCP Surface

- Expose a small domain-specific FastMCP interface instead of raw storage
  operations.
- Initial tools:
  - `search_sections(query, rfc?, category?, top_k?)`
  - `get_section(rfc, section_id)`
  - `trace_term(term, rfc?)`
  - `related_sections(rfc, section_id, edge_types?)`
  - `lookup_term(term_type, name)`
- Expose canonical RFC section text as MCP resources for direct source access.

### Error Handling

- Return a clear `index not built` error if the local index is missing.
- Return structured `not found` responses for exact section lookup misses.
- Degrade graph lookups to metadata and text search when a term is not present
  in the extracted graph.

### Testing

- Add parser tests for RFC section extraction and citation detection.
- Add ingestion tests for graph artifacts and Qdrant payload shape.
- Add MCP integration tests against a small fixture corpus.
- Add one end-to-end smoke test that builds a tiny local index and verifies
  representative QUIC lookups.

## Verification

The implementation is complete when a fresh local setup can:

```bash
uv run pytest
uv run python -m coquic_rag.cli build-index --source ../../docs/rfc --state-dir ../../.rag
uv run python -m coquic_rag.cli doctor --source ../../docs/rfc --state-dir ../../.rag
uv run python -m coquic_rag.mcp_server.server
```

And the MCP query surface can answer representative questions such as:

- where `max_udp_payload_size` is defined
- which sections describe ACK frame behavior
- which sections are related to QUIC v2 version negotiation

## Non-Goals

- No remote vector database in v1
- No committed binary vector index
- No graph database in v1
- No indexing of repository code or non-RFC sources yet
- No dependence on external embedding APIs

## Rationale

This design keeps the first knowledge system small, local, and reproducible.
QdrantLocal provides better retrieval ergonomics than a SQLite-only vector
approach once Git versioning is removed from the requirements, while FastMCP
provides a clean Codex-facing query surface. Using RFC sections as the canonical
record and augmenting them with a small deterministic graph avoids the weakness
of pure vector retrieval on specification-heavy queries.

## References

- https://python-client.qdrant.tech/qdrant_client.local.qdrant_local
- https://qdrant.tech/documentation/concepts/hybrid-queries/
- https://qdrant.tech/documentation/concepts/filtering/
- https://py.sdk.modelcontextprotocol.io/
- https://huggingface.co/mixedbread-ai/mxbai-embed-large-v1
