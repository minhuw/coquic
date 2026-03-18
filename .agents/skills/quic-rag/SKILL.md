---
name: quic-rag
description: Use when answering QUIC protocol or RFC questions in this repository, especially section lookups, frames, transport parameters, ACK behavior, version negotiation, packet formats, error codes, or when grounded RFC citations are needed.
---

# QUIC RAG

Use the repo-local QUIC RFC knowledge base before answering protocol questions in `coquic`.

## When to Use

- QUIC RFC questions grounded in `docs/rfc/`
- Requests for exact section lookups or RFC citations
- Questions about frames, transport parameters, packet formats, recovery, congestion control, version negotiation, or error codes

## Workflow

1. Check readiness:
   - `nix run .#qdrant-dev -- status`
   - `tools/rag/scripts/query-rag doctor --source docs/rfc --state-dir .rag`
2. If the shared backend is unavailable, run `nix run .#qdrant-dev -- start` and retry once.
3. Use the smallest fitting query:
   - `tools/rag/scripts/query-rag get-section --rfc 9000 --section-id 18.2`
   - `tools/rag/scripts/query-rag trace-term max_udp_payload_size`
   - `tools/rag/scripts/query-rag lookup-term --term-type transport_parameter --name max_udp_payload_size`
   - `tools/rag/scripts/query-rag related-sections --rfc 9369 --section-id 5`
   - `tools/rag/scripts/query-rag search-sections "ACK frame behavior" --top-k 5`
4. Cite the RFC and section IDs from command output in the final answer.
5. If the index is not ready, rebuild it with `tools/rag/scripts/query-rag build-index --source docs/rfc --state-dir .rag`.

## Don't Use

- Source-code implementation questions that are not asking about QUIC protocol behavior
- Non-QUIC repo workflow questions
