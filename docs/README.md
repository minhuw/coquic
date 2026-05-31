# CoQUIC Documentation

These documents describe the CoQUIC project API and integration model.

Reference material that is not project documentation lives under
`references/`. That includes RFC text, Internet-Drafts, papers, audits, and
older research notes used by tooling or implementation work.

## API Hierarchy

The public API is the compatibility boundary exported from `include/coquic/`.
Inside that boundary, callers choose the lowest layer that matches how much
control they need.

```text
include/coquic/ public API
+-- coquic::core
|   Lowest layer: sans-I/O endpoint, typed inputs, typed effects.
+-- coquic::quic
|   Transport facade: endpoint, connection, and stream handles over core.
`-- coquic::http3
   Application protocol layer: HTTP/3 state that emits QUIC connection inputs.
```

`coquic::quic` wraps `coquic::core`. `coquic::http3` composes with either
`core` or `quic`: it does not own sockets or endpoints, and it feeds work back
to the matching QUIC connection.

## Contents

- [Public API](api/public-api.md): API overview and compatibility boundary.
- [Core API](api/core.md): sans-I/O endpoint, inputs, effects, and timers.
- [QUIC Facade API](api/quic.md): transport facade over the core endpoint.
- [HTTP/3 API](api/http3.md): request/response layer and QUIC input handoff.
- [Runtime Integration](api/integration.md): event-loop checklist for callers.

## Reference Corpus

- QUIC RFC and Internet-Draft text: `references/rfc/`
- Research papers: `references/papers/`
- Historical notes and audits: `references/*.md`

Use `references/rfc/` as the source path for RAG indexing and protocol
citations.
